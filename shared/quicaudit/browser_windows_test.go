package quicaudit

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The child uses a fresh profile and a loopback-only target. A private Job
// Object owns this process tree; cleanup never kills the user's browser.
func startCaptureBrowser(t *testing.T, executable string, args []string) {
	t.Helper()
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		windows.CloseHandle(job)
		t.Fatal(err)
	}
	command := syscall.EscapeArg(executable)
	for _, arg := range args {
		command += " " + syscall.EscapeArg(arg)
	}
	line, err := windows.UTF16PtrFromString(command)
	if err != nil {
		windows.CloseHandle(job)
		t.Fatal(err)
	}
	var startup windows.StartupInfo
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Flags = windows.STARTF_USESHOWWINDOW
	startup.ShowWindow = windows.SW_HIDE
	var process windows.ProcessInformation
	if err = windows.CreateProcess(nil, line, nil, nil, false, windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW, nil, nil, &startup, &process); err != nil {
		windows.CloseHandle(job)
		t.Fatal(err)
	}
	if err = windows.AssignProcessToJobObject(job, process.Process); err != nil {
		windows.TerminateProcess(process.Process, 1)
		windows.CloseHandle(process.Thread)
		windows.CloseHandle(process.Process)
		windows.CloseHandle(job)
		t.Fatal(err)
	}
	if _, err = windows.ResumeThread(process.Thread); err != nil {
		windows.CloseHandle(process.Thread)
		windows.CloseHandle(job)
		windows.CloseHandle(process.Process)
		t.Fatal(err)
	}
	windows.CloseHandle(process.Thread)
	t.Cleanup(func() {
		// Waiting for the browser parent alone is insufficient: Crashpad can
		// still hold the temporary profile after that process has exited.
		if err := windows.TerminateJobObject(job, 0); err != nil {
			t.Error("terminate capture job", err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			var accounting struct {
				UserTime, KernelTime, PeriodUserTime, PeriodKernelTime           int64
				PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses uint32
			}
			if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil); err != nil {
				t.Error("query capture job", err)
				break
			}
			if accounting.ActiveProcesses == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Error("capture job children did not exit")
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		windows.CloseHandle(job)
		windows.WaitForSingleObject(process.Process, 3000)
		windows.CloseHandle(process.Process)
	})
}

func TestChromeClientInitialBaseline(t *testing.T) {
	executable := os.Getenv("ATLANT_TEST_CHROME")
	if executable == "" {
		t.Skip("set ATLANT_TEST_CHROME to an installed Chrome/Edge executable")
	}
	if !filepath.IsAbs(executable) || (strings.ToLower(filepath.Base(executable)) != "chrome.exe" && strings.ToLower(filepath.Base(executable)) != "msedge.exe") {
		t.Fatal("expected an absolute installed browser path")
	}
	if _, err := os.Stat(executable); err != nil {
		t.Fatal(err)
	}
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	_, port, _ := net.SplitHostPort(sink.LocalAddr().String())
	origin := "atlant-audit.test:" + port
	profile := t.TempDir()
	startCaptureBrowser(t, executable, []string{
		"--headless=new", "--no-first-run", "--no-default-browser-check",
		"--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-extensions", "--disable-default-apps", "--disable-breakpad",
		"--no-proxy-server", "--enable-quic", "--origin-to-force-quic-on=" + origin,
		"--host-resolver-rules=MAP atlant-audit.test 127.0.0.1, MAP * ~NOTFOUND",
		"--user-data-dir=" + profile, "--dump-dom", "https://" + origin + "/",
	})
	_ = sink.SetReadDeadline(time.Now().Add(12 * time.Second))
	var observer Observer
	for i := 0; i < 32; i++ {
		packet := make([]byte, 65535)
		n, _, err := sink.ReadFrom(packet)
		if err != nil {
			t.Fatal("no complete local browser QUIC Initial", err)
		}
		summary, err := observer.Observe(packet[:n])
		if errors.Is(err, ErrIncomplete) {
			continue
		}
		if err != nil {
			t.Fatal("observer rejected real browser Initial", err)
		}
		encoded, err := json.Marshal(summary)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(string(encoded))
		if output := os.Getenv("ATLANT_BROWSER_BASELINE_OUTPUT"); output != "" {
			if !filepath.IsAbs(output) || filepath.Base(output) != "chrome-initial.json" {
				t.Fatal("expected an absolute chrome-initial.json artifact path")
			}
			if err := os.WriteFile(output, append(encoded, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if summary.ClientHello.SessionIDSize != 0 || len(summary.ClientHello.TransportParameters) == 0 {
			t.Fatal("incomplete browser baseline")
		}
		return
	}
	t.Fatal("browser Initial did not complete within capture bounds")
}
