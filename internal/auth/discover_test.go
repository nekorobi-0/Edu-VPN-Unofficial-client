package auth

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func simFixture(imsi string) []byte {
	return []byte(base64.StdEncoding.EncodeToString([]byte("imsi-" + imsi + "," + strings.Repeat("ab", 16) + "," + strings.Repeat("cd", 16))))
}
func placeSIM(t *testing.T, path, imsi string) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, simFixture(imsi), 0600); e != nil {
		t.Fatal(e)
	}
}
func TestDiscoveryDepthAndOriginalPath(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c", "d", "too-deep.kkm")
	placeSIM(t, deep, "123456789012345")
	if _, e := FindSIM(root); !errors.Is(e, ErrNoSIM) {
		t.Fatal("depth-four authentication file was searched")
	}
	want := filepath.Join(root, "a", "b", "c", "original.KKM")
	placeSIM(t, want, "123456789012345")
	got, e := FindSIM(root)
	if e != nil || got != want {
		t.Fatalf("depth-three discovery failed: %v", e)
	}
	if _, e = os.Stat(want); e != nil {
		t.Fatal("original file was moved")
	}
	if e = os.WriteFile(filepath.Join(root, "invalid.kkm"), []byte("not a SIM"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = FindSIM(root); e != nil {
		t.Fatal("invalid unrelated candidate blocks valid file")
	}
}
func TestDifferentSIMsRequireSelectionButCopiesDoNot(t *testing.T) {
	root := t.TempDir()
	placeSIM(t, filepath.Join(root, "one.kkm"), "123456789012345")
	placeSIM(t, filepath.Join(root, "copy", "two.kkm"), "123456789012345")
	if _, e := FindSIM(root); e != nil {
		t.Fatal("identical copied SIM should not be ambiguous")
	}
	placeSIM(t, filepath.Join(root, "other.kkm"), "987654321098765")
	if _, e := FindSIM(root); e == nil || !strings.Contains(e.Error(), "--auth PATH") || strings.Contains(e.Error(), strings.Repeat("ab", 16)) {
		t.Fatal("different SIMs not detected or secret disclosed")
	}
}
func TestDiscoveryDoesNotFollowDirectorySymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	placeSIM(t, filepath.Join(outside, "secret.kkm"), "123456789012345")
	if e := os.Symlink(outside, filepath.Join(root, "link")); e != nil {
		t.Skip("symlink unavailable")
	}
	if _, e := FindSIM(root); !errors.Is(e, ErrNoSIM) {
		t.Fatal("authentication search escaped through symlink")
	}
}
