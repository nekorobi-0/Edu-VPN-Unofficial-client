package platform

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

func DataDir(portable bool) (string, error) {
	p, e := os.Executable()
	if e == nil {
		if dir, ok := portableDataDir(p, portable); ok {
			return dir, nil
		}
	} else if portable {
		return "", e
	}
	if runtime.GOOS == "windows" {
		p := os.Getenv("LOCALAPPDATA")
		if p == "" {
			return "", errors.New("LOCALAPPDATA is unset")
		}
		return filepath.Join(p, "YNU-WG"), nil
	}
	h, e := os.UserHomeDir()
	if e != nil {
		return "", e
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(h, "Library", "Application Support", "YNU-WG"), nil
	}
	if p := os.Getenv("XDG_DATA_HOME"); p != "" {
		return filepath.Join(p, "ynu-wg"), nil
	}
	return filepath.Join(h, ".local", "share", "ynu-wg"), nil
}
func portableDataDir(executable string, forced bool) (string, bool) {
	dir := filepath.Join(filepath.Dir(executable), "data")
	if forced {
		return dir, true
	}
	for _, name := range []string{"config.json", filepath.Join("auth", "sim.kkm")} {
		if st, e := os.Stat(filepath.Join(dir, name)); e == nil && st.Mode().IsRegular() {
			return dir, true
		}
	}
	return "", false
}
func PrivateDir(path string) error {
	if e := os.MkdirAll(path, 0700); e != nil {
		return e
	}
	return Restrict(path, true)
}
func WritePrivate(path string, b []byte) error {
	if e := PrivateDir(filepath.Dir(path)); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".ynu-private-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = Restrict(name, false); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(name, path)
}
