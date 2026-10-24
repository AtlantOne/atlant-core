package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
)

// Existing identity is never silently replaced because of corruption or I/O
// failure. A newly generated key must be durable before the listener can start.
func loadOrCreateStaticKey(path string) (*ecdh.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Size() != 32 {
			return nil, errors.New("invalid static key file; identity retained, startup refused")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read static key: %w", err)
		}
		defer clear(data)
		if len(data) != 32 {
			return nil, errors.New("invalid static key length")
		}
		return ecdh.X25519().NewPrivateKey(data)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat static key: %w", err)
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("create static key: %w", err)
	}
	data := priv.Bytes()
	defer clear(data)
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return nil, fmt.Errorf("persist static key: %w", writeErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return priv, nil
}
