package main

import (
	"bytes"
	"io"
	"log"
	"os"
	"strings"
	"sync"
)

var (
	currentLogLevel = "error"
	logMu           sync.RWMutex
)

type filteringLogWriter struct {
	underlying io.Writer
}

func (w *filteringLogWriter) Write(p []byte) (n int, err error) {
	logMu.RLock()
	lvl := currentLogLevel
	logMu.RUnlock()

	if lvl == "none" || lvl == "silent" || lvl == "off" {
		return len(p), nil
	}

	// Zero allocations: check byte tags directly
	isDebug := bytes.Contains(p, []byte("[DEBUG]")) || bytes.Contains(p, []byte("[debug]")) || bytes.Contains(p, []byte("[auth-debug]")) || bytes.Contains(p, []byte("[quic-auth-debug]"))
	isWarn := bytes.Contains(p, []byte("[WARN]")) || bytes.Contains(p, []byte("[warn]")) || bytes.Contains(p, []byte("[WARNING]"))
	isError := bytes.Contains(p, []byte("[ERROR]")) || bytes.Contains(p, []byte("[error]")) || bytes.Contains(p, []byte("[FATAL]")) || bytes.Contains(p, []byte("[PANIC]"))

	switch lvl {
	case "error":
		if !isError {
			return len(p), nil
		}
	case "warn", "warning":
		if !isError && !isWarn {
			return len(p), nil
		}
	case "info":
		if isDebug && !isError && !isWarn {
			return len(p), nil
		}
	case "debug":
		// Allow all
	default:
		if isDebug && !isError && !isWarn {
			return len(p), nil
		}
	}

	return w.underlying.Write(p)
}

// InitServerLogger initializes level-based logger like VLESS/Xray: debug, info, warn, error, none.
func InitServerLogger(level string) {
	if level == "" {
		level = "error"
	}
	logMu.Lock()
	currentLogLevel = strings.ToLower(strings.TrimSpace(level))
	logMu.Unlock()

	log.SetFlags(log.Ldate | log.Ltime)
	log.SetOutput(&filteringLogWriter{underlying: os.Stderr})
}

// SetServerLogLevel changes the server log level dynamically.
func SetServerLogLevel(level string) {
	logMu.Lock()
	defer logMu.Unlock()
	currentLogLevel = strings.ToLower(strings.TrimSpace(level))
}
