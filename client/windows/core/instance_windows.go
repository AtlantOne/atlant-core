package main

import (
	"fmt"
	"golang.org/x/sys/windows"
)

func acquireTUNInstance(name string) (func(), error) {
	value, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateMutex(nil, false, value)
	if err != nil {
		if handle != 0 {
			windows.CloseHandle(handle)
		}
		return nil, fmt.Errorf("another Atlant TUN instance is running or its lock is unavailable: %w", err)
	}
	return func() { windows.CloseHandle(handle) }, nil
}
