package actions

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"protection/internal/core"
)

// QuarantineFile moves an offending file into a locked-down quarantine
// directory rather than deleting it outright, preserving evidence.
type QuarantineFile struct {
	dir string
}

func (a *QuarantineFile) Name() string { return "quarantine_file" }

func (a *QuarantineFile) Execute(ctx context.Context, ev core.Event) error {
	if ev.Path == "" {
		return fmt.Errorf("quarantine_file: event has no path")
	}
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		return err
	}
	dest := filepath.Join(a.dir, fmt.Sprintf("%d_%s", time.Now().Unix(), filepath.Base(ev.Path)))
	if err := os.Rename(ev.Path, dest); err != nil {
		// Rename fails across filesystems; fall back to copy+remove.
		if err := copyThenRemove(ev.Path, dest); err != nil {
			return err
		}
	}
	// Strip all permissions so a quarantined payload cannot be executed.
	_ = os.Chmod(dest, 0o000)
	return nil
}

// DeleteFile permanently removes an offending file.
type DeleteFile struct{}

func (a *DeleteFile) Name() string { return "delete_file" }

func (a *DeleteFile) Execute(ctx context.Context, ev core.Event) error {
	if ev.Path == "" {
		return fmt.Errorf("delete_file: event has no path")
	}
	return os.Remove(ev.Path)
}

// KillProcess sends SIGKILL to the offending pid. Used when the threat is a
// host process rather than a container.
type KillProcess struct{}

func (a *KillProcess) Name() string { return "kill_process" }

func (a *KillProcess) Execute(ctx context.Context, ev core.Event) error {
	if ev.PID <= 1 {
		return fmt.Errorf("kill_process: refusing to kill pid %d", ev.PID)
	}
	return syscall.Kill(ev.PID, syscall.SIGKILL)
}

func copyThenRemove(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		in.Close()
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		in.Close()
		out.Close()
		return err
	}
	in.Close()
	out.Close()
	return os.Remove(src)
}
