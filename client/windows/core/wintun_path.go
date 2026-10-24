package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func wintunDLLPath(executable string) (string, error) {
	dll := filepath.Join(filepath.Dir(executable), "wintun.dll")
	info, err := os.Stat(dll)
	if err != nil {
		return "", fmt.Errorf("place wintun.dll beside the core executable (%s): %w", dll, err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return "", fmt.Errorf("wintun.dll beside the core must be a non-empty regular file: %s", dll)
	}
	return dll, nil
}
