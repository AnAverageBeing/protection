// Package logging provides a tiny levelled logger that writes structured-ish
// lines to stderr and, optionally, a file. We avoid external logging deps to
// keep the binary lean and dependency-light.
package logging

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func parseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// Logger is a minimal, concurrency-safe levelled logger.
type Logger struct {
	mu    sync.Mutex
	out   io.Writer
	level Level
}

var std = &Logger{out: os.Stderr, level: LevelInfo}

// Configure sets the global logger's level and optional log file. If logFile is
// non-empty, output is tee'd to both stderr and the file.
func Configure(level, logFile string) error {
	std.mu.Lock()
	defer std.mu.Unlock()
	std.level = parseLevel(level)
	std.out = os.Stderr
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return fmt.Errorf("open log file: %w", err)
		}
		std.out = io.MultiWriter(os.Stderr, f)
	}
	return nil
}

func (l *Logger) log(level Level, format string, args ...any) {
	if level < l.level {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.out, "%s [%-5s] %s\n", ts, level.String(), msg)
}

func Debug(format string, args ...any) { std.log(LevelDebug, format, args...) }
func Info(format string, args ...any)  { std.log(LevelInfo, format, args...) }
func Warn(format string, args ...any)  { std.log(LevelWarn, format, args...) }
func Error(format string, args ...any) { std.log(LevelError, format, args...) }
