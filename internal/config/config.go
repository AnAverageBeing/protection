// Package config loads and validates the protection daemon configuration from
// YAML. It supplies sane, security-first defaults so the tool is useful even
// with a near-empty config file.
package config

import (
	"fmt"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultPath is where the daemon looks for its config when none is given.
const DefaultPath = "/etc/protection/config.yaml"

// Config is the root configuration object.
type Config struct {
	General   General         `yaml:"general"`
	Detectors DetectorConfigs `yaml:"detectors"`
	Alerts    AlertConfigs    `yaml:"alerts"`
	Actions   ActionConfigs   `yaml:"actions"`
	Rules     []Rule          `yaml:"rules"`
}

// General holds daemon-wide settings.
type General struct {
	// Name is the human label for this installation, shown in every alert.
	// Defaults to the hostname, then the primary IP, then "Protection".
	Name string `yaml:"name"`
	// Mode selects what to protect: "server" (host processes only),
	// "docker" (containerised threats only) or "both".
	Mode         string        `yaml:"mode"`
	ScanInterval time.Duration `yaml:"scan_interval"`
	Cooldown     time.Duration `yaml:"cooldown"`
	LogLevel     string        `yaml:"log_level"`
	LogFile      string        `yaml:"log_file"`
	// DryRun disables all destructive actions; alerts still fire. Perfect for
	// tuning thresholds on a live node before arming enforcement.
	DryRun   bool   `yaml:"dry_run"`
	Hostname string `yaml:"hostname"`
}

// Protection modes.
const (
	ModeServer = "server"
	ModeDocker = "docker"
	ModeBoth   = "both"
)

// DetectorConfigs groups every detector's settings.
type DetectorConfigs struct {
	Miner    MinerConfig    `yaml:"miner"`
	PortScan PortScanConfig `yaml:"portscan"`
	DDoS     DDoSConfig     `yaml:"ddos"`
	ZipBomb  ZipBombConfig  `yaml:"zipbomb"`
	Exploit  ExploitConfig  `yaml:"exploit"`
}

// MinerConfig tunes cryptocurrency-miner detection.
type MinerConfig struct {
	Enabled          bool     `yaml:"enabled"`
	CPUThreshold     float64  `yaml:"cpu_threshold"`     // percent of one core
	SustainedSeconds int      `yaml:"sustained_seconds"` // how long high CPU must persist
	KnownProcesses   []string `yaml:"known_processes"`
	PoolPorts        []int    `yaml:"pool_ports"`
	PoolDomains      []string `yaml:"pool_domains"`
}

// PortScanConfig tunes port-scan detection.
type PortScanConfig struct {
	Enabled           bool          `yaml:"enabled"`
	DistinctPorts     int           `yaml:"distinct_ports"`
	DistinctHosts     int           `yaml:"distinct_hosts"`
	Window            time.Duration `yaml:"window"`
	KnownScannerProcs []string      `yaml:"known_scanner_processes"`
}

// DDoSConfig tunes outbound flood detection.
type DDoSConfig struct {
	Enabled       bool     `yaml:"enabled"`
	PPSThreshold  uint64   `yaml:"pps_threshold"`  // packets/sec per container
	BPSThreshold  uint64   `yaml:"bps_threshold"`  // bytes/sec per container
	ConnThreshold int      `yaml:"conn_threshold"` // simultaneous outbound conns
	KnownTools    []string `yaml:"known_tools"`
}

// ZipBombConfig tunes archive-bomb detection.
type ZipBombConfig struct {
	Enabled         bool     `yaml:"enabled"`
	ScanPaths       []string `yaml:"scan_paths"`
	RatioThreshold  float64  `yaml:"ratio_threshold"`  // uncompressed/compressed
	MaxUncompressed uint64   `yaml:"max_uncompressed"` // absolute byte ceiling
	MaxNesting      int      `yaml:"max_nesting"`
	// FullScanInterval is the slow backstop sweep of every scan path.
	FullScanInterval time.Duration `yaml:"full_scan_interval"`
	// HotTrigger enables event-driven scanning: when a process spikes CPU and
	// disk writes (the signature of an active extraction) we immediately scan
	// its container/volume instead of waiting for the next full sweep.
	HotTrigger    *bool   `yaml:"hot_trigger"`     // nil = enabled
	HotCPUPercent float64 `yaml:"hot_cpu_percent"` // per-core CPU to consider "extracting"
	HotWriteMBps  float64 `yaml:"hot_write_mbps"`  // disk write rate to consider "extracting"
}

// ExploitConfig tunes exploit / container-escape detection.
type ExploitConfig struct {
	Enabled          bool     `yaml:"enabled"`
	WatchPaths       []string `yaml:"watch_paths"`
	SuspiciousProcs  []string `yaml:"suspicious_processes"`
	FlagReverseShell bool     `yaml:"flag_reverse_shell"`
	FlagPrivEsc      bool     `yaml:"flag_privilege_escalation"`
}

// AlertConfigs groups alert channels.
type AlertConfigs struct {
	Discord DiscordConfig `yaml:"discord"`
	SMTP    SMTPConfig    `yaml:"smtp"`
	Webhook WebhookConfig `yaml:"webhook"`
}

// DiscordConfig configures Discord webhook alerts.
type DiscordConfig struct {
	Enabled     bool   `yaml:"enabled"`
	WebhookURL  string `yaml:"webhook_url"`
	Username    string `yaml:"username"`
	MinSeverity string `yaml:"min_severity"`
}

// SMTPConfig configures email alerts.
type SMTPConfig struct {
	Enabled     bool     `yaml:"enabled"`
	Host        string   `yaml:"host"`
	Port        int      `yaml:"port"`
	Username    string   `yaml:"username"`
	Password    string   `yaml:"password"`
	From        string   `yaml:"from"`
	To          []string `yaml:"to"`
	TLS         bool     `yaml:"tls"`
	MinSeverity string   `yaml:"min_severity"`
}

// WebhookConfig configures a generic JSON webhook.
type WebhookConfig struct {
	Enabled     bool              `yaml:"enabled"`
	URL         string            `yaml:"url"`
	Method      string            `yaml:"method"`
	Headers     map[string]string `yaml:"headers"`
	MinSeverity string            `yaml:"min_severity"`
}

// ActionConfigs groups action backends.
type ActionConfigs struct {
	Docker      DockerConfig      `yaml:"docker"`
	Pterodactyl PterodactylConfig `yaml:"pterodactyl"`
	File        FileConfig        `yaml:"file"`
}

// DockerConfig configures the Docker action backend.
type DockerConfig struct {
	Enabled bool   `yaml:"enabled"`
	Socket  string `yaml:"socket"`
}

// PterodactylConfig configures suspension via the Pterodactyl application API.
type PterodactylConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
	APIKey  string `yaml:"api_key"`
}

// FileConfig configures file actions (quarantine/delete).
type FileConfig struct {
	Enabled       bool   `yaml:"enabled"`
	QuarantineDir string `yaml:"quarantine_dir"`
}

// Rule maps a class of events to a set of actions. Rules are evaluated top to
// bottom; every matching rule contributes its actions.
type Rule struct {
	Name        string   `yaml:"name"`
	Categories  []string `yaml:"categories"`
	MinSeverity string   `yaml:"min_severity"`
	Actions     []string `yaml:"actions"`
}

// Load reads, parses and validates the config at path, applying defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.General.ScanInterval <= 0 {
		// 5s gives responsive CPU/disk sampling without hammering /proc.
		c.General.ScanInterval = 5 * time.Second
	}
	if c.General.Mode == "" {
		c.General.Mode = ModeBoth
	}
	if c.General.Cooldown <= 0 {
		c.General.Cooldown = 5 * time.Minute
	}
	if c.General.LogLevel == "" {
		c.General.LogLevel = "info"
	}
	if c.General.Hostname == "" {
		if h, err := os.Hostname(); err == nil {
			c.General.Hostname = h
		}
	}
	if c.General.Name == "" {
		c.General.Name = DisplayName()
	}

	if len(c.Detectors.Miner.KnownProcesses) == 0 {
		c.Detectors.Miner.KnownProcesses = DefaultMinerProcesses
	}
	if len(c.Detectors.Miner.PoolPorts) == 0 {
		c.Detectors.Miner.PoolPorts = DefaultPoolPorts
	}
	if len(c.Detectors.Miner.PoolDomains) == 0 {
		c.Detectors.Miner.PoolDomains = DefaultPoolDomains
	}
	if c.Detectors.Miner.CPUThreshold == 0 {
		c.Detectors.Miner.CPUThreshold = 85
	}
	if c.Detectors.Miner.SustainedSeconds == 0 {
		c.Detectors.Miner.SustainedSeconds = 45
	}

	if c.Detectors.PortScan.DistinctPorts == 0 {
		c.Detectors.PortScan.DistinctPorts = 100
	}
	if c.Detectors.PortScan.DistinctHosts == 0 {
		c.Detectors.PortScan.DistinctHosts = 50
	}
	if c.Detectors.PortScan.Window <= 0 {
		c.Detectors.PortScan.Window = 15 * time.Second
	}
	if len(c.Detectors.PortScan.KnownScannerProcs) == 0 {
		c.Detectors.PortScan.KnownScannerProcs = DefaultScannerProcesses
	}

	if c.Detectors.DDoS.PPSThreshold == 0 {
		c.Detectors.DDoS.PPSThreshold = 60000
	}
	if c.Detectors.DDoS.BPSThreshold == 0 {
		c.Detectors.DDoS.BPSThreshold = 125_000_000 // ~1 Gbit/s
	}
	if c.Detectors.DDoS.ConnThreshold == 0 {
		c.Detectors.DDoS.ConnThreshold = 1500
	}
	if len(c.Detectors.DDoS.KnownTools) == 0 {
		c.Detectors.DDoS.KnownTools = DefaultDDoSTools
	}

	if len(c.Detectors.ZipBomb.ScanPaths) == 0 {
		c.Detectors.ZipBomb.ScanPaths = []string{"/var/lib/pterodactyl/volumes"}
	}
	if c.Detectors.ZipBomb.RatioThreshold == 0 {
		c.Detectors.ZipBomb.RatioThreshold = 150
	}
	if c.Detectors.ZipBomb.MaxUncompressed == 0 {
		c.Detectors.ZipBomb.MaxUncompressed = 50 << 30 // 50 GiB
	}
	if c.Detectors.ZipBomb.MaxNesting == 0 {
		c.Detectors.ZipBomb.MaxNesting = 3
	}
	if c.Detectors.ZipBomb.FullScanInterval <= 0 {
		c.Detectors.ZipBomb.FullScanInterval = 30 * time.Minute
	}
	if c.Detectors.ZipBomb.HotCPUPercent == 0 {
		c.Detectors.ZipBomb.HotCPUPercent = 80
	}
	if c.Detectors.ZipBomb.HotWriteMBps == 0 {
		c.Detectors.ZipBomb.HotWriteMBps = 25
	}
	if c.Detectors.ZipBomb.HotTrigger == nil {
		enabled := true
		c.Detectors.ZipBomb.HotTrigger = &enabled
	}

	if len(c.Detectors.Exploit.SuspiciousProcs) == 0 {
		c.Detectors.Exploit.SuspiciousProcs = DefaultExploitProcesses
	}
	if len(c.Detectors.Exploit.WatchPaths) == 0 {
		c.Detectors.Exploit.WatchPaths = []string{"/tmp", "/dev/shm", "/var/tmp"}
	}

	if c.Actions.Docker.Socket == "" {
		c.Actions.Docker.Socket = "/var/run/docker.sock"
	}
	if c.Actions.File.QuarantineDir == "" {
		c.Actions.File.QuarantineDir = "/var/lib/protection/quarantine"
	}
	if c.Alerts.Discord.Username == "" {
		c.Alerts.Discord.Username = "Protection"
	}

	if len(c.Rules) == 0 {
		c.Rules = DefaultRules()
	}
}

func (c *Config) validate() error {
	switch c.General.Mode {
	case ModeServer, ModeDocker, ModeBoth:
	default:
		return fmt.Errorf("general.mode must be one of server|docker|both, got %q", c.General.Mode)
	}
	if c.Alerts.SMTP.Enabled {
		if c.Alerts.SMTP.Host == "" || len(c.Alerts.SMTP.To) == 0 {
			return fmt.Errorf("smtp alert enabled but host/to not set")
		}
	}
	if c.Alerts.Discord.Enabled && c.Alerts.Discord.WebhookURL == "" {
		return fmt.Errorf("discord alert enabled but webhook_url not set")
	}
	if c.Alerts.Webhook.Enabled && c.Alerts.Webhook.URL == "" {
		return fmt.Errorf("webhook alert enabled but url not set")
	}
	if c.Actions.Pterodactyl.Enabled {
		if c.Actions.Pterodactyl.URL == "" || c.Actions.Pterodactyl.APIKey == "" {
			return fmt.Errorf("pterodactyl action enabled but url/api_key not set")
		}
	}
	return nil
}

// DefaultRules returns the built-in enforcement policy: aggressive on the
// unambiguous threats, alert-only on the noisier heuristics. The `neutralize`
// action auto-selects container-kill or process-kill based on the threat, so a
// single rule works on both Pterodactyl/Docker nodes and bare VPS hosts.
func DefaultRules() []Rule {
	return []Rule{
		{Name: "miners", Categories: []string{"miner"}, MinSeverity: "high", Actions: []string{"neutralize", "suspend_server", "alert"}},
		{Name: "ddos", Categories: []string{"ddos"}, MinSeverity: "high", Actions: []string{"neutralize", "suspend_server", "alert"}},
		{Name: "exploits", Categories: []string{"exploit"}, MinSeverity: "high", Actions: []string{"neutralize", "alert"}},
		{Name: "zipbombs", Categories: []string{"zipbomb"}, MinSeverity: "medium", Actions: []string{"quarantine_file", "alert"}},
		{Name: "portscans", Categories: []string{"portscan"}, MinSeverity: "medium", Actions: []string{"alert"}},
		{Name: "catch-all", Categories: []string{"*"}, MinSeverity: "low", Actions: []string{"alert"}},
	}
}

// DisplayName picks the best default installation label: hostname, else the
// primary outbound IP, else "Protection".
func DisplayName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	if ip := primaryIP(); ip != "" {
		return ip
	}
	return "Protection"
}

func primaryIP() string {
	// No traffic is sent; this just selects the kernel's preferred source IP.
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}

// ModeAllows reports whether an event is in scope for the configured mode.
// Container-related events (have a container id or pterodactyl server) belong
// to "docker"; everything else is host/"server" scope.
func ModeAllows(mode string, containerRelated bool) bool {
	switch mode {
	case ModeDocker:
		return containerRelated
	case ModeServer:
		return !containerRelated
	default:
		return true
	}
}

// Curated default signature lists. These are deliberately conservative; operators
// extend them via config.
var (
	DefaultMinerProcesses = []string{
		"xmrig", "minerd", "cpuminer", "ccminer", "ethminer", "cgminer",
		"bfgminer", "nbminer", "t-rex", "trex", "phoenixminer", "lolminer",
		"gminer", "nanominer", "xmr-stak", "xmrig-cuda", "teamredminer",
		"srbminer", "wildrig", "verusminer", "kawpowminer", "miniz", "rigel",
	}
	DefaultPoolPorts = []int{
		3333, 4444, 5555, 7777, 8888, 9999, 14444, 14433, 45700, 45560,
		3032, 5730, 8008, 8080, 1080, 12345, 20580,
	}
	DefaultPoolDomains = []string{
		"pool.minexmr.com", "xmrpool", "supportxmr.com", "nanopool.org",
		"ethermine.org", "f2pool.com", "2miners.com", "hashvault.pro",
		"nicehash.com", "minexmr", "moneroocean.stream", "c3pool.com",
		"unmineable.com", "herominers.com", "zergpool.com",
	}
	DefaultScannerProcesses = []string{
		"nmap", "masscan", "zmap", "unicornscan", "hping3", "naabu", "rustscan",
	}
	// Distinctive tool names only — short/generic tokens ("byte", "hammer",
	// "loris", "hulk") are deliberately excluded to avoid false positives;
	// they are matched on word boundaries even so.
	DefaultDDoSTools = []string{
		"hping3", "t50", "mhddos", "ufonet", "slowloris", "goldeneye",
		"torshammer", "xerxes", "ipstresser", "raven-storm", "pyflood",
		"hoic", "loic", "xoic", "hulkattack",
	}
	DefaultExploitProcesses = []string{
		"dirtycow", "dirtypipe", "pwnkit", "linpeas", "linenum", "les.sh",
		"unix-privesc-check", "exploit", "nsenter", "runc", "deepce",
	}
)
