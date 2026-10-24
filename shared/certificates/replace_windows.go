package certificates

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func replacePrivateFile(source, destination string) error {
	deadline := time.Now().Add(time.Second)
	for {
		err := os.Rename(source, destination)
		// Readers and antivirus software can briefly open the old file without
		// FILE_SHARE_DELETE. Keep the old file intact while waiting for them.
		if err == nil || (!errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED)) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}
