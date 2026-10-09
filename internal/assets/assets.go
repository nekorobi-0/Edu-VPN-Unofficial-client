package assets

import (
	"errors"
	"os"
	"path/filepath"
)

// Extract removes obsolete files created by the old DLL-based builds, then
// prepares only the platform TUN driver. SIM files are never touched.
func Extract(dir string) (driver string, err error) {
	dir = filepath.Join(dir, "runtime")
	for _, name := range []string{"loip-client.dll", "ynu-auth-helper.exe"} {
		if e := os.Remove(filepath.Join(dir, name)); e != nil && !errors.Is(e, os.ErrNotExist) {
			return "", e
		}
	}
	return extractDriver(dir)
}
