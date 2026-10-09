//go:build !windows

package platform

import "os"

func Restrict(path string, dir bool) error {
	mode := os.FileMode(0600)
	if dir {
		mode = 0700
	}
	return os.Chmod(path, mode)
}
func PrepareDriver(string) error { return nil }
