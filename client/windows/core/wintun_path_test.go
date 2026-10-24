package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWintunDLLBesideExecutable(t *testing.T) {
	for _, test := range []string{"missing", "directory", "empty", "present"} {
		t.Run(test, func(t *testing.T) {
			dir := t.TempDir()
			dll := filepath.Join(dir, "wintun.dll")
			switch test {
			case "directory":
				if err := os.Mkdir(dll, 0700); err != nil {
					t.Fatal(err)
				}
			case "empty", "present":
				var data []byte
				if test == "present" {
					data = []byte("test fixture; not loaded as a DLL")
				}
				if err := os.WriteFile(dll, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := wintunDLLPath(filepath.Join(dir, "atlant-win-fixed.exe"))
			if test == "present" {
				if err != nil || got != dll {
					t.Fatalf("got %q, %v", got, err)
				}
			} else if err == nil {
				t.Fatal("expected an error, not a fallback to the working directory")
			}
		})
	}
}
