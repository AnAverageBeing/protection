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

// Webhook POSTs the raw event as JSON to an arbitrary endpoint, letting
// operators wire protection into their own automation (SIEM, PagerDuty, n8n...).
type Webhook struct {
	cfg    config.WebhookConfig
	source string // installation name
	min    core.Severity
	client *http.Client
}

// NewWebhook builds a generic webhook alerter. `source` is the installation name.
func NewWebhook(cfg config.WebhookConfig, source string) *Webhook {
	return &Webhook{
		cfg:    cfg,
		source: source,
		min:    core.ParseSeverity(cfg.MinSeverity),
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (w *Webhook) Name() string               { return "webhook" }
func (w *Webhook) MinSeverity() core.Severity { return w.min }

func (w *Webhook) Send(ctx context.Context, ev core.Event) error {
	payload := map[string]any{
		"installation": w.source,
		"event":        ev,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	method := w.cfg.Method
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, w.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}
