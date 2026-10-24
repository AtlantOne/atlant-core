package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

// Hard crashes can still lose the last periodic statistics flush interval.
func checkpointUsersOnShutdown(path string) error {
	usersMu.Lock()
	defer usersMu.Unlock()
	if err := saveUsersLocked(path, usersDB); err != nil {
		return err
	}
	usersDirty.Store(false)
	if currentUsersStore != nil {
		err := currentUsersStore.Close()
		currentUsersStore = nil
		return err
	}
	return nil
}

func installUsersShutdownHandler(path string) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		stopQuotaWorker()
		if err := checkpointUsersOnShutdown(path); err != nil {
			log.Printf("[USERS] Final database checkpoint failed: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}()
}
