// Package docker is a tiny Docker Engine API client speaking HTTP over the unix
// socket. We deliberately avoid the official SDK (and its large dependency
// tree) since we only need a handful of endpoints.
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Client talks to the Docker daemon over its unix socket.
type Client struct {
	http   *http.Client
	socket string
}

// New returns a Docker client bound to the given socket path.
func New(socket string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &Client{
		http:   &http.Client{Transport: transport, Timeout: 15 * time.Second},
		socket: socket,
	}
}

// Container is a trimmed view of the /containers/json response.
type Container struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	State  string            `json:"State"`
	Labels map[string]string `json:"Labels"`
}

// Name returns the primary human name without the leading slash.
func (c Container) Name() string {
	if len(c.Names) == 0 {
		return c.ID
	}
	return strings.TrimPrefix(c.Names[0], "/")
}

func (c *Client) do(ctx context.Context, method, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("docker %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("docker %s %s: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

// Ping verifies connectivity to the daemon.
func (c *Client) Ping(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/_ping", nil)
}

// ListContainers returns all running containers.
func (c *Client) ListContainers(ctx context.Context) ([]Container, error) {
	var out []Container
	if err := c.do(ctx, http.MethodGet, "/containers/json", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Inspect returns the full inspect JSON as a generic map (we only dip into a
// few labels/fields, so avoid a giant typed struct).
func (c *Client) Inspect(ctx context.Context, id string) (map[string]any, error) {
	var out map[string]any
	if err := c.do(ctx, http.MethodGet, "/containers/"+id+"/json", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Kill sends SIGKILL to a container, stopping abuse immediately.
func (c *Client) Kill(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/containers/"+id+"/kill", nil)
}

// Stop gracefully stops a container (10s grace).
func (c *Client) Stop(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/containers/"+id+"/stop?t=10", nil)
}

// Stats holds the subset of docker stats we use for DDoS detection.
type Stats struct {
	Networks map[string]struct {
		RxBytes   uint64 `json:"rx_bytes"`
		RxPackets uint64 `json:"rx_packets"`
		TxBytes   uint64 `json:"tx_bytes"`
		TxPackets uint64 `json:"tx_packets"`
	} `json:"networks"`
}

// StatsOnce fetches a single (non-streaming) stats sample for a container.
func (c *Client) StatsOnce(ctx context.Context, id string) (*Stats, error) {
	var s Stats
	if err := c.do(ctx, http.MethodGet, "/containers/"+id+"/stats?stream=false", &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ContainerByID resolves a (possibly short) id or name to a Container.
func (c *Client) ContainerByID(ctx context.Context, idOrName string) (*Container, error) {
	list, err := c.ListContainers(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == idOrName || strings.HasPrefix(list[i].ID, idOrName) || list[i].Name() == idOrName {
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("container %q not found", idOrName)
}
