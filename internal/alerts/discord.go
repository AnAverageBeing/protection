package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"protection/internal/config"
	"protection/internal/core"
)

// Discord posts rich embeds to a Discord webhook.
type Discord struct {
	cfg      config.DiscordConfig
	hostname string
	min      core.Severity
	client   *http.Client
}

// NewDiscord builds a Discord alerter.
func NewDiscord(cfg config.DiscordConfig, hostname string) *Discord {
	return &Discord{
		cfg:      cfg,
		hostname: hostname,
		min:      core.ParseSeverity(cfg.MinSeverity),
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (d *Discord) Name() string               { return "discord" }
func (d *Discord) MinSeverity() core.Severity { return d.min }

type discordPayload struct {
	Username string         `json:"username,omitempty"`
	Embeds   []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Color       int            `json:"color"`
	Fields      []discordField `json:"fields"`
	Footer      discordFooter  `json:"footer"`
	Timestamp   string         `json:"timestamp"`
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type discordFooter struct {
	Text string `json:"text"`
}

func (d *Discord) Send(ctx context.Context, ev core.Event) error {
	var fields []discordField
	for _, kv := range fieldsFor(ev, d.hostname) {
		fields = append(fields, discordField{Name: kv[0], Value: codeOrText(kv[1]), Inline: true})
	}

	payload := discordPayload{
		Username: d.cfg.Username,
		Embeds: []discordEmbed{{
			Title:       fmt.Sprintf("🛡️ %s", ev.Title),
			Description: ev.Description,
			Color:       ev.Severity.Color(),
			Fields:      fields,
			Footer:      discordFooter{Text: "protection"},
			Timestamp:   ev.Time.UTC().Format(time.RFC3339),
		}},
	}

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

func codeOrText(s string) string {
	if s == "" {
		return "—"
	}
	return "`" + s + "`"
}
