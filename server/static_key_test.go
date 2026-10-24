package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStaticIdentityPersistsAndNeverReplacesCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.bin")
	a, err := loadOrCreateStaticKey(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadOrCreateStaticKey(path)
	if err != nil || !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("identity changed", err)
	}
	for _, bad := range [][]byte{nil, []byte("broken"), make([]byte, 33)} {
		if err := os.WriteFile(path, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadOrCreateStaticKey(path); err == nil {
			t.Fatal("corrupt identity accepted")
		}
		got, _ := os.ReadFile(path)
		if !bytes.Equal(got, bad) {
			t.Fatal("identity silently regenerated")
		}
	}
	if _, err := loadOrCreateStaticKey(filepath.Dir(path)); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err := loadOrCreateStaticKey(filepath.Join(path, "missing", "key")); err == nil {
		t.Fatal("unpersisted key accepted")
	}
}
