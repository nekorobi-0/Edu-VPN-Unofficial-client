package platform

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
)

func AcquireLock(path string) (func(), error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return func() {}, e
	}
	var o windows.Overlapped
	if e = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &o); e != nil {
		f.Close()
		return func() {}, errors.New("another ynu-wg process is using this data directory")
	}
	return func() { windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &o); f.Close() }, nil
}
