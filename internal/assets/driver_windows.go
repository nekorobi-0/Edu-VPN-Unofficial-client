package assets

import (
	"bytes"
	_ "embed"
	"os"
	"path/filepath"
	"runtime"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/platform"
)

//go:embed wintun-amd64.dll
var wintunAMD []byte

//go:embed wintun-arm64.dll
var wintunARM []byte

func extractDriver(dir string) (string, error) {
	if e := platform.PrivateDir(dir); e != nil {
		return "", e
	}
	p := filepath.Join(dir, "wintun.dll")
	b := wintunAMD
	if runtime.GOARCH == "arm64" {
		b = wintunARM
	}
	if old, e := os.ReadFile(p); e == nil && bytes.Equal(old, b) {
		return p, platform.Restrict(p, false)
	}
	return p, platform.WritePrivate(p, b)
}
