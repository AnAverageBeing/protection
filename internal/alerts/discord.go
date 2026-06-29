package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"protection/internal/config"
	"protection/internal/core"
)

// Discord posts rich, markdown-formatted embeds to a Discord webhook.
type Discord struct {
	cfg    config.DiscordConfig
	source string // installation name
	min    core.Severity
	client *http.Client
}

// NewDiscord builds a Discord alerter. `source` is the installation name.
func NewDiscord(cfg config.DiscordConfig, source string) *Discord {
	return &Discord{
		cfg:    cfg,
		source: source,
		min:    core.ParseSeverity(cfg.MinSeverity),
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (d *Discord) Name() string               { return "discord" }
func (d *Discord) MinSeverity() core.Severity { return d.min }

type discordPayload struct {
	Username string         `json:"username,omitempty"`
	Embeds   []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Author      *discordAuthor `json:"author,omitempty"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Color       int            `json:"color"`
	Fields      []discordField `json:"fields"`
	Footer      discordFooter  `json:"footer"`
	Timestamp   string         `json:"timestamp"`
}

type discordAuthor struct {
	Name string `json:"name"`
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type discordFooter struct {
	Text string `json:"text"`
}

// severityBadge returns an emoji + label used in the embed title.
func severityBadge(s core.Severity) string {
	switch s {
	case core.SeverityCritical:
		return "🚨 CRITICAL"
	case core.SeverityHigh:
		return "🔴 HIGH"
	case core.SeverityMedium:
		return "🟠 MEDIUM"
	case core.SeverityLow:
		return "🟡 LOW"
	default:
		return "🔵 INFO"
	}
}

func categoryEmoji(c core.Category) string {
	switch c {
	case core.CategoryMiner:
		return "⛏️"
	case core.CategoryDDoS:
		return "🌊"
	case core.CategoryPortScan:
		return "🔭"
	case core.CategoryZipBomb:
		return "💣"
	case core.CategoryExploit:
		return "🐚"
	default:
		return "🛡️"
	}
}

func (d *Discord) Send(ctx context.Context, ev core.Event) error {
	embed := discordEmbed{
		Author:      &discordAuthor{Name: d.source},
		Title:       fmt.Sprintf("%s %s — %s", categoryEmoji(ev.Category), severityBadge(ev.Severity), ev.Title),
		Description: d.description(ev),
		Color:       ev.Severity.Color(),
		Fields:      d.fields(ev),
		Footer:      discordFooter{Text: "protection • " + d.source},
		Timestamp:   ev.Time.UTC().Format(time.RFC3339),
	}

	payload := discordPayload{Username: d.cfg.Username, Embeds: []discordEmbed{embed}}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("discord webhook returned %d", resp.StatusCode)
	}
	return nil
}

// description builds a markdown body: the human sentence, the target in bold,
// and (in dry-run-friendly fashion) the evidence as a fenced block.
func (d *Discord) description(ev core.Event) string {
	var b strings.Builder
	b.WriteString("> " + ev.Description + "\n")
	b.WriteString(fmt.Sprintf("\n**Target:** `%s`", ev.Target()))

	if len(ev.Evidence) > 0 {
		keys := make([]string, 0, len(ev.Evidence))
		for k := range ev.Evidence {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("\n\n**Evidence**\n```yaml\n")
		for _, k := range keys {
			v := ev.Evidence[k]
			if len(v) > 300 {
				v = v[:300] + "…"
			}
			b.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
		b.WriteString("```")
	}
	return b.String()
}

// fields renders the compact inline metadata grid.
func (d *Discord) fields(ev core.Event) []discordField {
	var fields []discordField
	add := func(name, value string, inline bool) {
		if value == "" {
			return
		}
		fields = append(fields, discordField{Name: name, Value: value, Inline: inline})
	}
	add("Installation", "`"+d.source+"`", true)
	add("Severity", severityBadge(ev.Severity), true)
	add("Category", fmt.Sprintf("%s `%s`", categoryEmoji(ev.Category), ev.Category), true)
	add("Detector", "`"+ev.Detector+"`", true)
	if ev.Container != "" {
		add("Container", "`"+ev.Container+"`", true)
	}
	if ev.Server != "" {
		add("Server", "`"+ev.Server+"`", true)
	}
	if ev.Process != "" {
		proc := ev.Process
		if ev.PID > 0 {
			proc = fmt.Sprintf("%s (pid %d)", ev.Process, ev.PID)
		}
		add("Process", "`"+proc+"`", true)
	}
	if ev.Path != "" {
		add("Path", "`"+ev.Path+"`", false)
	}
	return fields
}
