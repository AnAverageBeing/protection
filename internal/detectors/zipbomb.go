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
)

// ZipBombDetector inspects archives for decompression-bomb characteristics
// WITHOUT extracting them: it reads the archive's own size metadata (central
// directory for zip, ISIZE trailer for gzip) and flags absurd compression
// ratios or uncompressed totals. This catches both classic nested bombs and
// modern overlapping/quine bombs, all from header data alone.
type ZipBombDetector struct {
	cfg config.ZipBombConfig

	lastScan time.Time
	// remember (path → modtime) we have already cleared so re-scans are cheap
	// and we don't re-alert on the same untouched file every interval.
	cleared map[string]int64
}

// NewZipBombDetector builds a zip-bomb detector from config.
func NewZipBombDetector(cfg config.ZipBombConfig) *ZipBombDetector {
	return &ZipBombDetector{cfg: cfg, cleared: map[string]int64{}}
}

func (d *ZipBombDetector) Name() string { return "zipbomb" }

func (d *ZipBombDetector) Run(ctx context.Context) ([]core.Event, error) {
	// This is filesystem-heavy, so honour an independent, slower cadence.
	if time.Since(d.lastScan) < d.cfg.ScanInterval {
		return nil, nil
	}
	d.lastScan = time.Now()

	var events []core.Event
	for _, root := range d.cfg.ScanPaths {
		_ = filepath.WalkDir(root, func(path string, dirent fs.DirEntry, err error) error {
			if err != nil {
				return nil // unreadable dir; skip
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
				return nil // unchanged since last clean scan
			}
			if ev := d.inspect(path, info); ev != nil {
				events = append(events, *ev)
			} else {
				d.cleared[path] = info.ModTime().UnixNano()
			}
			return nil
		})
	}
	return events, nil
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
