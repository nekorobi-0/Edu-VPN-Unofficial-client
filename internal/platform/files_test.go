package platform

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrivateFileAndExclusiveProcessLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	file := filepath.Join(dir, "sim.kkm")
	if e := WritePrivate(file, []byte("test credential")); e != nil {
		t.Fatal(e)
	}
	if runtime.GOOS != "windows" {
		for p, mode := range map[string]os.FileMode{dir: 0700, file: 0600} {
			st, e := os.Stat(p)
			if e != nil || st.Mode().Perm() != mode {
				t.Fatalf("bad private permissions: %s", p)
			}
		}
	}
	path := filepath.Join(dir, "run.lock")
	release, e := AcquireLock(path)
	if e != nil {
		t.Fatal(e)
	}
	if release2, e := AcquireLock(path); e == nil {
		release2()
		t.Fatal("duplicate process lock permitted")
	}
	release()
	release, e = AcquireLock(path)
	if e != nil {
		t.Fatal(e)
	}
	release()
}
func TestPortableDataIsDetectedBesideExecutable(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "ynu-wg.exe")
	if _, ok := portableDataDir(exe, false); ok {
		t.Fatal("missing portable files should use user data directory")
	}
	want := filepath.Join(dir, "data")
	if got, ok := portableDataDir(exe, true); !ok || got != want {
		t.Fatal("explicit portable path incorrect")
	}
	if e := WritePrivate(filepath.Join(want, "auth", "sim.kkm"), []byte("test")); e != nil {
		t.Fatal(e)
	}
	if got, ok := portableDataDir(exe, false); !ok || got != want {
		t.Fatal("adjacent authentication file was not automatically detected")
	}
}
