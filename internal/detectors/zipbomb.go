package detectors

import (
	"archive/zip"
	"context"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"protection/internal/config"
	"protection/internal/core"
	"protection/internal/system"
)

// ZipBombDetector inspects archives for decompression-bomb characteristics
// WITHOUT extracting them: it reads the archive's own size metadata (central
// directory for zip, ISIZE trailer for gzip) and flags absurd compression
// ratios or uncompressed totals.
//
// It works two ways:
//   - Hot trigger (event-driven): when a process spikes CPU *and* disk writes
//     — the fingerprint of an active extraction — we immediately inspect the
//     archive(s) that process has open, plus its working directory. This
//     catches a bomb mid-unzip in seconds instead of after a fixed delay.
//   - Full sweep (backstop): a slow periodic walk of every scan path catches
//     bombs that were uploaded but not yet extracted.
type ZipBombDetector struct {
	cfg config.ZipBombConfig

	lastFull time.Time
	cleared  map[string]int64 // path → modtime we've already cleared
	prev     map[int]extractSample
}

type extractSample struct {
	jiffies    uint64
	writeBytes uint64
	at         time.Time
}

// NewZipBombDetector builds a zip-bomb detector from config.
func NewZipBombDetector(cfg config.ZipBombConfig) *ZipBombDetector {
	return &ZipBombDetector{
		cfg:     cfg,
		cleared: map[string]int64{},
		prev:    map[int]extractSample{},
	}
}

func (d *ZipBombDetector) Name() string { return "zipbomb" }

func (d *ZipBombDetector) Run(ctx context.Context, snap *system.Snapshot) ([]core.Event, error) {
	var events []core.Event

	if d.cfg.HotTrigger != nil && *d.cfg.HotTrigger {
		events = append(events, d.hotScan(ctx, snap)...)
	}

	// Slow backstop sweep of every scan path.
	if time.Since(d.lastFull) >= d.cfg.FullScanInterval {
		d.lastFull = time.Now()
		events = append(events, d.fullSweep(ctx)...)
	}
	return events, nil
}

// hotScan finds processes that look like they are actively extracting an
// archive (high CPU + high disk write rate) and inspects exactly what they have
// open. This is the "why wait 5 minutes?" path.
func (d *ZipBombDetector) hotScan(ctx context.Context, snap *system.Snapshot) []core.Event {
	writeThreshold := d.cfg.HotWriteMBps * 1024 * 1024
	seen := make(map[int]bool, len(snap.Processes))
	var events []core.Event
	reported := map[string]bool{}

	for _, p := range snap.Processes {
		seen[p.PID] = true
		cpuPct, writeRate, ok := d.rates(p, snap.Time)
		if !ok || cpuPct < d.cfg.HotCPUPercent || writeRate < writeThreshold {
			continue
		}
		// This process is hammering CPU and disk — likely decompressing.
		// Inspect the archives it has open, then its working directory.
		candidates := archivesAmong(system.ProcessOpenFiles(p.PID))
		if cwd := system.ProcessCwd(p.PID); cwd != "" {
			candidates = append(candidates, archivesIn(cwd)...)
		}
		for _, path := range candidates {
			if reported[path] {
				continue
			}
			reported[path] = true
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			if ev := d.inspect(path, info); ev != nil {
				ev.ContainerID = p.ContainerID
				ev.PID = p.PID
				ev.Process = procDisplay(p)
				ev.AddEvidence("trigger", fmt.Sprintf("active extraction: %.0f%% CPU, %s/s disk write", cpuPct, humanBytes(uint64(writeRate))))
				events = append(events, *ev)
			}
		}
	}
	// GC samples for exited pids.
	for pid := range d.prev {
		if !seen[pid] {
			delete(d.prev, pid)
		}
	}
	return events
}

// rates computes per-core CPU% and disk write bytes/sec for a process from two
// samples. Returns ok=false until a baseline exists.
func (d *ZipBombDetector) rates(p system.Process, now time.Time) (cpuPct, writeRate float64, ok bool) {
	cur := extractSample{jiffies: p.CPUJiffies(), writeBytes: p.WriteBytes, at: now}
	prev, had := d.prev[p.PID]
	d.prev[p.PID] = cur
	if !had || !now.After(prev.at) {
		return 0, 0, false
	}
	elapsed := now.Sub(prev.at).Seconds()
	if elapsed <= 0 {
		return 0, 0, false
	}
	if cur.jiffies >= prev.jiffies {
		cpuPct = float64(cur.jiffies-prev.jiffies) / (elapsed * system.ClockTicks) * 100
	}
	if cur.writeBytes >= prev.writeBytes {
		writeRate = float64(cur.writeBytes-prev.writeBytes) / elapsed
	}
	return cpuPct, writeRate, true
}

// fullSweep walks every configured scan path looking for archive bombs.
func (d *ZipBombDetector) fullSweep(ctx context.Context) []core.Event {
	var events []core.Event
	for _, root := range d.cfg.ScanPaths {
		_ = filepath.WalkDir(root, func(path string, dirent fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			select {
			case <-ctx.Done():
				return filepath.SkipAll
			default:
			}
			if dirent.IsDir() || !isArchive(path) {
				return nil
			}
			info, err := dirent.Info()
			if err != nil {
				return nil
			}
			if mt, ok := d.cleared[path]; ok && mt == info.ModTime().UnixNano() {
				return nil
			}
			if ev := d.inspect(path, info); ev != nil {
				events = append(events, *ev)
			} else {
				d.cleared[path] = info.ModTime().UnixNano()
			}
			return nil
		})
	}
	return events
}

func isArchive(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range []string{".zip", ".jar", ".gz", ".tgz", ".gzip"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// archivesAmong filters a list of paths down to archives.
func archivesAmong(paths []string) []string {
	var out []string
	for _, p := range paths {
		if isArchive(p) {
			out = append(out, p)
		}
	}
	return out
}

// archivesIn returns archives directly inside dir (non-recursive, fast).
func archivesIn(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && isArchive(e.Name()) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

func (d *ZipBombDetector) inspect(path string, info fs.FileInfo) *core.Event {
	compressed := uint64(info.Size())
	if compressed == 0 {
		return nil
	}

	var uncompressed uint64
	var entries int
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".zip"), strings.HasSuffix(lower, ".jar"):
		uncompressed, entries = zipUncompressed(path)
	case strings.HasSuffix(lower, ".gz"), strings.HasSuffix(lower, ".tgz"), strings.HasSuffix(lower, ".gzip"):
		uncompressed = gzipUncompressed(path)
		entries = 1
	}
	if uncompressed == 0 {
		return nil
	}

	ratio := float64(uncompressed) / float64(compressed)
	bombByRatio := ratio >= d.cfg.RatioThreshold
	bombBySize := uncompressed >= d.cfg.MaxUncompressed
	if !bombByRatio && !bombBySize {
		return nil
	}

	sev := core.SeverityMedium
	if ratio >= d.cfg.RatioThreshold*10 || bombBySize {
		sev = core.SeverityHigh
	}

	ev := &core.Event{
		Time:     time.Now(),
		Detector: d.Name(),
		Category: core.CategoryZipBomb,
		Severity: sev,
		Title:    "Decompression bomb detected",
		Path:     path,
		Server:   pteroUUIDFromPath(path),
		Description: fmt.Sprintf("Archive %s expands to %s from %s (%.0f:1 ratio) across %d entries.",
			filepath.Base(path), humanBytes(uncompressed), humanBytes(compressed), ratio, entries),
	}
	ev.AddEvidence("compressed_bytes", fmt.Sprintf("%d", compressed))
	ev.AddEvidence("uncompressed_bytes", fmt.Sprintf("%d", uncompressed))
	ev.AddEvidence("ratio", fmt.Sprintf("%.1f", ratio))
	return ev
}

// zipUncompressed sums declared uncompressed sizes from the central directory.
func zipUncompressed(path string) (uint64, int) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return 0, 0
	}
	defer r.Close()
	var total uint64
	for _, f := range r.File {
		total += f.UncompressedSize64
	}
	return total, len(r.File)
}

// gzipUncompressed reads the 4-byte ISIZE trailer (uncompressed size mod 2^32).
func gzipUncompressed(path string) uint64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	if _, err := f.Seek(-4, os.SEEK_END); err != nil {
		return 0
	}
	var buf [4]byte
	if _, err := f.Read(buf[:]); err != nil {
		return 0
	}
	return uint64(binary.LittleEndian.Uint32(buf[:]))
}

// pteroUUIDFromPath maps a pterodactyl volume path back to its server uuid.
// Volumes live at /var/lib/pterodactyl/volumes/<server-uuid>/...
func pteroUUIDFromPath(path string) string {
	const marker = "/volumes/"
	idx := strings.Index(path, marker)
	if idx < 0 {
		return ""
	}
	rest := path[idx+len(marker):]
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		return rest[:slash]
	}
	return rest
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
