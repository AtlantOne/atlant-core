//go:build !windows

package certificates

import "os"

func replacePrivateFile(source, destination string) error {
	return os.Rename(source, destination)
}
