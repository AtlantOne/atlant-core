package main

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	modIphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetExtendedTcpTable       = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable       = modIphlpapi.NewProc("GetExtendedUdpTable")
	procOpenProcess               = modKernel32.NewProc("OpenProcess")
	procCloseHandle               = modKernel32.NewProc("CloseHandle")
	procQueryFullProcessImageName = modKernel32.NewProc("QueryFullProcessImageNameW")
)

const (
	TCP_TABLE_OWNER_PID_ALL           = 5
	UDP_TABLE_OWNER_PID               = 1
	AF_INET                           = 2
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
)

type mibTcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

type mibUdpRowOwnerPid struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

type portCacheEntry struct {
	procName  string
	expiresAt time.Time
}

type pidCacheEntry struct {
	procName  string
	expiresAt time.Time
}

var (
	portCacheMu sync.RWMutex
	portCache   = make(map[uint16]portCacheEntry)

	pidCacheMu sync.RWMutex
	pidCache   = make(map[uint32]pidCacheEntry)
)

func getProcessNameByPID(pid uint32) string {
	if pid == 0 {
		return ""
	}

	pidCacheMu.RLock()
	entry, found := pidCache[pid]
	pidCacheMu.RUnlock()
	if found && time.Now().Before(entry.expiresAt) {
		return entry.procName
	}

	h, _, _ := procOpenProcess.Call(PROCESS_QUERY_LIMITED_INFORMATION, 0, uintptr(pid))
	if h == 0 {
		return ""
	}
	defer procCloseHandle.Call(h)

	var buf [512]uint16
	size := uint32(len(buf))
	r, _, _ := procQueryFullProcessImageName.Call(h, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return ""
	}

	fullPath := syscall.UTF16ToString(buf[:size])
	name := filepath.Base(fullPath)

	pidCacheMu.Lock()
	pidCache[pid] = pidCacheEntry{
		procName:  name,
		expiresAt: time.Now().Add(30 * time.Second),
	}
	pidCacheMu.Unlock()

	return name
}

// GetProcessNameForPort resolves the executable name belonging to a local port.
func GetProcessNameForPort(port uint16, isUDP bool) string {
	if port == 0 {
		return ""
	}

	portCacheMu.RLock()
	entry, found := portCache[port]
	portCacheMu.RUnlock()
	if found && time.Now().Before(entry.expiresAt) {
		return entry.procName
	}

	var pid uint32

	if !isUDP {
		var size uint32
		procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
		if size > 0 {
			buf := make([]byte, size)
			r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
			if r == 0 && len(buf) >= 4 {
				numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
				rowSize := unsafe.Sizeof(mibTcpRowOwnerPid{})
				for i := uint32(0); i < numEntries; i++ {
					offset := 4 + uintptr(i)*rowSize
					if offset+rowSize > uintptr(len(buf)) {
						break
					}
					row := (*mibTcpRowOwnerPid)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + offset))
					portBytes := (*[2]byte)(unsafe.Pointer(&row.LocalPort))[:]
					rowPort := binary.BigEndian.Uint16(portBytes)
					if rowPort == port {
						pid = row.OwningPid
						break
					}
				}
			}
		}
	} else {
		var size uint32
		procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, AF_INET, UDP_TABLE_OWNER_PID, 0)
		if size > 0 {
			buf := make([]byte, size)
			r, _, _ := procGetExtendedUdpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, AF_INET, UDP_TABLE_OWNER_PID, 0)
			if r == 0 && len(buf) >= 4 {
				numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
				rowSize := unsafe.Sizeof(mibUdpRowOwnerPid{})
				for i := uint32(0); i < numEntries; i++ {
					offset := 4 + uintptr(i)*rowSize
					if offset+rowSize > uintptr(len(buf)) {
						break
					}
					row := (*mibUdpRowOwnerPid)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + offset))
					portBytes := (*[2]byte)(unsafe.Pointer(&row.LocalPort))[:]
					rowPort := binary.BigEndian.Uint16(portBytes)
					if rowPort == port {
						pid = row.OwningPid
						break
					}
				}
			}
		}
	}

	if pid == 0 {
		return ""
	}

	procName := getProcessNameByPID(pid)
	if procName != "" {
		portCacheMu.Lock()
		portCache[port] = portCacheEntry{
			procName:  procName,
			expiresAt: time.Now().Add(3 * time.Second),
		}
		portCacheMu.Unlock()
	}

	return procName
}

func matchProcess(procName string, targets []string) bool {
	if procName == "" || len(targets) == 0 {
		return false
	}
	base := strings.ToLower(filepath.Base(procName))
	for _, target := range targets {
		t := strings.ToLower(strings.TrimSpace(filepath.Base(target)))
		if t == "" {
			continue
		}
		if base == t {
			return true
		}
		// Also match without .exe extension if target lacks it
		tNoExt := strings.TrimSuffix(t, ".exe")
		baseNoExt := strings.TrimSuffix(base, ".exe")
		if baseNoExt == tNoExt {
			return true
		}
	}
	return false
}

// ShouldRouteProcessViaVPN determines if connection from a local port should go through VPN.
func ShouldRouteProcessViaVPN(port uint16, isUDP bool, cfg *Config) bool {
	mode := strings.ToLower(strings.TrimSpace(cfg.RouteMode))
	if mode == "" || mode == "all" {
		return true
	}

	procName := GetProcessNameForPort(port, isUDP)

	// Mode 2: Only proxy selected apps
	if mode == "proxy_apps" || mode == "rules" {
		if len(cfg.ProxyApps) == 0 {
			// No apps configured -> don't proxy
			return false
		}
		return matchProcess(procName, cfg.ProxyApps)
	}

	// Mode 3: Exclude selected apps (bypass VPN for them)
	if mode == "bypass_apps" || mode == "bypass" {
		if len(cfg.BypassApps) == 0 {
			return true
		}
		if matchProcess(procName, cfg.BypassApps) {
			return false // Bypass VPN
		}
		return true
	}

	return true
}
