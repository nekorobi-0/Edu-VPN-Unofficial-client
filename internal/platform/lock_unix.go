//go:build !windows

package platform

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func AcquireLock(path string) (func(), error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return func() {}, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return func() {}, errors.New("another ynu-wg process is using this data directory")
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
