package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"protection/internal/config"
	"protection/internal/core"
)

// SuspendServer suspends the offending server via the Pterodactyl application
// API. It resolves the internal server id from the event's server uuid/identifier
// (which we derive from the container name/labels) and issues a suspend.
type SuspendServer struct {
	cfg    config.PterodactylConfig
	client *http.Client
}

// NewSuspendServer builds the Pterodactyl suspend action.
func NewSuspendServer(cfg config.PterodactylConfig) *SuspendServer {
	return &SuspendServer{
		cfg:    cfg,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (a *SuspendServer) Name() string { return "suspend_server" }

func (a *SuspendServer) Execute(ctx context.Context, ev core.Event) error {
	key := ev.Server
	if key == "" {
		key = ev.Container
	}
	if key == "" {
		// Host/VPS threat with no associated server — nothing to suspend.
		// Skip quietly so this can sit harmlessly in a shared rule.
		return nil
	}
	id, err := a.resolveServerID(ctx, key)
	if err != nil {
		return err
	}
	return a.suspend(ctx, id)
}

// pteroServer is the slice of the application API response we care about.
type pteroServer struct {
	Attributes struct {
		ID         int    `json:"id"`
		UUID       string `json:"uuid"`
		Identifier string `json:"identifier"`
		Name       string `json:"name"`
	} `json:"attributes"`
}

type pteroList struct {
	Data []pteroServer `json:"data"`
	Meta struct {
		Pagination struct {
			CurrentPage int `json:"current_page"`
			TotalPages  int `json:"total_pages"`
		} `json:"pagination"`
	} `json:"meta"`
}

// resolveServerID matches the event key against each server's uuid or short
// identifier. Wings names containers by the uuid; pterodactyl's "identifier" is
// the 8-char short form — we accept either, including prefix matches.
func (a *SuspendServer) resolveServerID(ctx context.Context, key string) (int, error) {
	key = strings.ToLower(strings.TrimPrefix(key, "/"))
	base := strings.TrimRight(a.cfg.URL, "/")

	for page := 1; ; page++ {
		url := fmt.Sprintf("%s/api/application/servers?per_page=100&page=%d", base, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return 0, err
		}
		a.auth(req)
		resp, err := a.client.Do(req)
		if err != nil {
			return 0, err
		}
		var list pteroList
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&list)
		resp.Body.Close()
		if err != nil {
			return 0, fmt.Errorf("decode pterodactyl servers: %w", err)
		}

		for _, s := range list.Data {
			uuid := strings.ToLower(s.Attributes.UUID)
			ident := strings.ToLower(s.Attributes.Identifier)
			if uuid == key || ident == key || strings.HasPrefix(uuid, key) || strings.HasPrefix(key, ident) {
				return s.Attributes.ID, nil
			}
		}
		if page >= list.Meta.Pagination.TotalPages || list.Meta.Pagination.TotalPages == 0 {
			break
		}
	}
	return 0, fmt.Errorf("suspend_server: no pterodactyl server matched %q", key)
}

func (a *SuspendServer) suspend(ctx context.Context, id int) error {
	base := strings.TrimRight(a.cfg.URL, "/")
	url := fmt.Sprintf("%s/api/application/servers/%d/suspend", base, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	a.auth(req)
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("suspend_server: pterodactyl returned %d", resp.StatusCode)
	}
	return nil
}

func (a *SuspendServer) auth(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+a.cfg.APIKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
}
