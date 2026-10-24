//go:build atlantprofile

// Package perfprobe is compiled only into explicitly tagged diagnostic builds.
// It writes local profiles, never opens a management or profiling listener.
package perfprobe

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"time"
)

func init() {
	dir := os.Getenv("ATLANT_PROFILE_DIR")
	if dir == "" {
		return
	}
	seconds := 8
	if value := os.Getenv("ATLANT_PROFILE_SECONDS"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 120 {
			log.Print("[PROFILE] invalid duration")
			return
		}
		seconds = n
	}
	if !filepath.IsAbs(dir) {
		log.Print("[PROFILE] output directory must be absolute")
		return
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Printf("[PROFILE] %v", err)
		return
	}
	f, err := os.CreateTemp(dir, filepath.Base(os.Args[0])+"-*.cpu.pprof")
	if err != nil {
		log.Printf("[PROFILE] %v", err)
		return
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		_ = f.Close()
		log.Printf("[PROFILE] %v", err)
		return
	}
	runtime.SetMutexProfileFraction(10)
	runtime.SetBlockProfileRate(1000000)
	go func() {
		time.Sleep(time.Duration(seconds) * time.Second)
		pprof.StopCPUProfile()
		_ = f.Close()
		for _, name := range []string{"heap", "allocs", "mutex", "block"} {
			out, err := os.OpenFile(f.Name()+"."+name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err == nil {
				_ = pprof.Lookup(name).WriteTo(out, 0)
				_ = out.Close()
			}
		}
		runtime.SetMutexProfileFraction(0)
		runtime.SetBlockProfileRate(0)
	}()
}
