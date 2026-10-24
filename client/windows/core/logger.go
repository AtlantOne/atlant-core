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
	coreLogLevel = "info"
	coreLogMu    sync.RWMutex
)

type coreLogFilterWriter struct {
	underlying io.Writer
}

func (w *coreLogFilterWriter) Write(p []byte) (n int, err error) {
	coreLogMu.RLock()
	lvl := coreLogLevel
	coreLogMu.RUnlock()

	if lvl == "none" || lvl == "silent" || lvl == "off" {
		return len(p), nil
	}

	// Zero allocations: check byte tags directly
	isDebug := bytes.Contains(p, []byte("[DEBUG]")) || bytes.Contains(p, []byte("[debug]")) || bytes.Contains(p, []byte("[auth-debug]"))
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
		// all allowed
	default:
		if isDebug && !isError && !isWarn {
			return len(p), nil
		}
	}

	return w.underlying.Write(p)
}

func InitCoreLogger(level string) {
	if level == "" {
		level = "info"
	}
	coreLogMu.Lock()
	coreLogLevel = strings.ToLower(strings.TrimSpace(level))
	coreLogMu.Unlock()

	log.SetFlags(log.Ldate | log.Ltime)
	log.SetOutput(&coreLogFilterWriter{underlying: os.Stderr})
}
