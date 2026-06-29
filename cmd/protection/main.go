// Command protection is a kernel-level abuse-protection daemon for container
// hosts (Pterodactyl/Wings, generic Docker, bare VPS). It detects miners,
// outbound DDoS, port scans, decompression bombs and exploit/escape attempts,
// then alerts and enforces automatically.
//
// Usage:
//
//	protection run                 # start the daemon (reads /etc/protection/config.yaml)
//	protection scan                # one-off scan, print findings, take no action
//	protection status              # show config + docker connectivity
//	protection config init [path]  # write a starter config
//	protection config check [path] # validate a config
//	protection test-alert          # send a synthetic alert to all channels
//	protection version
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"protection/internal/actions"
	"protection/internal/alerts"
	"protection/internal/config"
	"protection/internal/core"
	"protection/internal/detectors"
	"protection/internal/docker"
	"protection/internal/engine"
	"protection/internal/logging"
)

// Version is overridden at build time via -ldflags "-X main.Version=...".
var Version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "run", "start", "daemon":
		err = cmdRun(args)
	case "scan":
		err = cmdScan(args)
	case "status":
		err = cmdStatus(args)
	case "config":
		err = cmdConfig(args)
	case "test-alert":
		err = cmdTestAlert(args)
	case "version", "-v", "--version":
		fmt.Printf("protection %s\n", Version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}

	if err != nil {
		logging.Error("%v", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `protection — container-host abuse protection

USAGE:
  protection <command> [flags]

COMMANDS:
  run                  Start the protection daemon
  scan                 Run all detectors once and print findings (no enforcement)
  status               Show configuration and Docker connectivity
  config init [path]   Write a starter configuration file
  config check [path]  Validate a configuration file
  test-alert           Send a synthetic alert through every configured channel
  version              Print version

FLAGS:
  --config <path>      Path to config (default: `+config.DefaultPath+`)
`)
}

// configPath extracts a --config flag from args (default path otherwise).
func configPath(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return config.DefaultPath
}

func cmdRun(args []string) error {
	cfg, err := config.Load(configPath(args))
	if err != nil {
		return err
	}
	if err := logging.Configure(cfg.General.LogLevel, cfg.General.LogFile); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		logging.Warn("not running as root: process/network introspection and enforcement may be limited")
	}

	eng, _, err := build(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	eng.Run(ctx)
	return nil
}

func cmdScan(args []string) error {
	cfg, err := config.Load(configPath(args))
	if err != nil {
		return err
	}
	_ = logging.Configure(cfg.General.LogLevel, "")

	eng, _, err := build(cfg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	events := eng.ScanOnce(ctx)

	if len(events) == 0 {
		fmt.Println("✓ no threats detected")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "SEVERITY\tCATEGORY\tTARGET\tTITLE")
	for _, ev := range events {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", ev.Severity, ev.Category, ev.Target(), ev.Title)
	}
	w.Flush()
	fmt.Printf("\n%d finding(s)\n", len(events))
	return nil
}

func cmdStatus(args []string) error {
	path := configPath(args)
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	fmt.Printf("config:        %s (ok)\n", path)
	fmt.Printf("hostname:      %s\n", cfg.General.Hostname)
	fmt.Printf("scan interval: %s\n", cfg.General.ScanInterval)
	fmt.Printf("dry run:       %v\n", cfg.General.DryRun)

	fmt.Print("detectors:     ")
	fmt.Println(enabledDetectors(cfg))

	fmt.Print("alerts:        ")
	fmt.Println(enabledAlerts(cfg))

	if cfg.Actions.Docker.Enabled {
		d := docker.New(cfg.Actions.Docker.Socket)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := d.Ping(ctx); err != nil {
			fmt.Printf("docker:        UNREACHABLE (%v)\n", err)
		} else {
			fmt.Printf("docker:        connected via %s\n", cfg.Actions.Docker.Socket)
		}
	} else {
		fmt.Println("docker:        disabled")
	}
	return nil
}

func cmdConfig(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: protection config <init|check> [path]")
	}
	sub := args[0]
	path := config.DefaultPath
	if len(args) > 1 {
		path = args[1]
	}
	switch sub {
	case "init":
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("refusing to overwrite existing file %s", path)
		}
		if err := os.MkdirAll(dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(exampleConfig), 0o640); err != nil {
			return err
		}
		fmt.Printf("wrote starter config to %s\n", path)
		return nil
	case "check":
		if _, err := config.Load(path); err != nil {
			return err
		}
		fmt.Printf("✓ %s is valid\n", path)
		return nil
	default:
		return fmt.Errorf("unknown config subcommand %q", sub)
	}
}

func cmdTestAlert(args []string) error {
	cfg, err := config.Load(configPath(args))
	if err != nil {
		return err
	}
	_ = logging.Configure(cfg.General.LogLevel, "")
	alerters := buildAlerters(cfg)
	if len(alerters) == 0 {
		return fmt.Errorf("no alert channels are enabled in config")
	}

	ev := core.Event{
		Time:        time.Now(),
		Detector:    "test",
		Category:    core.CategorySystem,
		Severity:    core.SeverityCritical,
		Title:       "Test alert",
		Description: "This is a synthetic alert from `protection test-alert`. If you can read this, your channel works.",
		Process:     "protection",
	}
	ev.AddEvidence("note", "synthetic")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, a := range alerters {
		if err := a.Send(ctx, ev); err != nil {
			fmt.Printf("✗ %s: %v\n", a.Name(), err)
		} else {
			fmt.Printf("✓ %s: delivered\n", a.Name())
		}
	}
	return nil
}

// build wires detectors, alerters, actions and the engine from config.
func build(cfg *config.Config) (*engine.Engine, *docker.Client, error) {
	var dockerClient *docker.Client
	if needsDocker(cfg) {
		dockerClient = docker.New(cfg.Actions.Docker.Socket)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := dockerClient.Ping(ctx); err != nil {
			logging.Warn("docker unreachable at %s (%v): container detection/enforcement disabled", cfg.Actions.Docker.Socket, err)
			dockerClient = nil
		}
	}

	dets := buildDetectors(cfg, dockerClient)
	alerters := buildAlerters(cfg)
	registry := actions.NewRegistry(cfg, dockerClient)

	return engine.New(cfg, dets, alerters, registry), dockerClient, nil
}

func buildDetectors(cfg *config.Config, d *docker.Client) []detectors.Detector {
	var dets []detectors.Detector
	if cfg.Detectors.Miner.Enabled {
		dets = append(dets, detectors.NewMinerDetector(cfg.Detectors.Miner, d))
	}
	if cfg.Detectors.PortScan.Enabled {
		dets = append(dets, detectors.NewPortScanDetector(cfg.Detectors.PortScan, d))
	}
	if cfg.Detectors.DDoS.Enabled {
		dets = append(dets, detectors.NewDDoSDetector(cfg.Detectors.DDoS, d))
	}
	if cfg.Detectors.ZipBomb.Enabled {
		dets = append(dets, detectors.NewZipBombDetector(cfg.Detectors.ZipBomb))
	}
	if cfg.Detectors.Exploit.Enabled {
		dets = append(dets, detectors.NewExploitDetector(cfg.Detectors.Exploit, d))
	}
	return dets
}

func buildAlerters(cfg *config.Config) []alerts.Alerter {
	var as []alerts.Alerter
	if cfg.Alerts.Discord.Enabled {
		as = append(as, alerts.NewDiscord(cfg.Alerts.Discord, cfg.General.Hostname))
	}
	if cfg.Alerts.SMTP.Enabled {
		as = append(as, alerts.NewSMTP(cfg.Alerts.SMTP, cfg.General.Hostname))
	}
	if cfg.Alerts.Webhook.Enabled {
		as = append(as, alerts.NewWebhook(cfg.Alerts.Webhook, cfg.General.Hostname))
	}
	return as
}

func needsDocker(cfg *config.Config) bool {
	return cfg.Actions.Docker.Enabled || cfg.Detectors.DDoS.Enabled ||
		cfg.Detectors.Miner.Enabled || cfg.Detectors.Exploit.Enabled ||
		cfg.Detectors.PortScan.Enabled
}

func enabledDetectors(cfg *config.Config) string {
	var out []string
	if cfg.Detectors.Miner.Enabled {
		out = append(out, "miner")
	}
	if cfg.Detectors.PortScan.Enabled {
		out = append(out, "portscan")
	}
	if cfg.Detectors.DDoS.Enabled {
		out = append(out, "ddos")
	}
	if cfg.Detectors.ZipBomb.Enabled {
		out = append(out, "zipbomb")
	}
	if cfg.Detectors.Exploit.Enabled {
		out = append(out, "exploit")
	}
	return join(out)
}

func enabledAlerts(cfg *config.Config) string {
	var out []string
	if cfg.Alerts.Discord.Enabled {
		out = append(out, "discord")
	}
	if cfg.Alerts.SMTP.Enabled {
		out = append(out, "smtp")
	}
	if cfg.Alerts.Webhook.Enabled {
		out = append(out, "webhook")
	}
	return join(out)
}

func join(s []string) string {
	if len(s) == 0 {
		return "(none)"
	}
	out := s[0]
	for _, x := range s[1:] {
		out += ", " + x
	}
	return out
}

func dir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
