package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideCommandWindow(cmd)
	b, e := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return "", fmt.Errorf("%s timed out after 30s: %w", name, ctx.Err())
	}
	if e != nil {
		return "", fmt.Errorf("%s failed: %s", name, strings.TrimSpace(CommandOutput(b)))
	}
	return strings.TrimSpace(CommandOutput(b)), nil
}
func ps(script string) (string, error) {
	return run("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; "+script)
}
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func ConfigureInterface(name, address, prefix string) (func(), error) {
	cleanup := func() {}
	switch runtime.GOOS {
	case "linux":
		if _, e := run("ip", "-6", "addr", "add", address+"/128", "dev", name, "nodad"); e != nil {
			return cleanup, e
		}
		if _, e := run("ip", "link", "set", "dev", name, "up"); e != nil {
			return cleanup, e
		}
		if _, e := run("ip", "-6", "route", "add", prefix, "dev", name); e != nil {
			return cleanup, e
		}
		cleanup = func() { run("ip", "-6", "route", "del", prefix, "dev", name) }
	case "darwin":
		if _, e := run("ifconfig", name, "inet6", address, "prefixlen", "128", "up"); e != nil {
			return cleanup, e
		}
		if _, e := run("route", "-n", "add", "-inet6", prefix, "-interface", name); e != nil {
			return cleanup, e
		}
		cleanup = func() { run("route", "-n", "delete", "-inet6", prefix, "-interface", name) }
	case "windows":
		a := quote(name)
		if _, e := ps("New-NetIPAddress -InterfaceAlias " + a + " -IPAddress " + quote(address) + " -PrefixLength 128 -AddressFamily IPv6 | Out-Null; New-NetRoute -InterfaceAlias " + a + " -DestinationPrefix " + quote(prefix) + " -NextHop '::' -PolicyStore ActiveStore | Out-Null"); e != nil {
			return cleanup, e
		}
		cleanup = func() {
			ps("Get-NetRoute -InterfaceAlias " + a + " -DestinationPrefix " + quote(prefix) + " -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false; Get-NetIPAddress -InterfaceAlias " + a + " -IPAddress " + quote(address) + " -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false")
		}
	default:
		return cleanup, errors.New("unsupported interface platform")
	}
	return cleanup, nil
}

// ConfigureDNS changes only the selected suffixes and restores them on exit.
func ConfigureDNS(name, listen string, domains []string) (func(), error) {
	ap, e := netip.ParseAddrPort(listen)
	if e != nil {
		return func() {}, e
	}
	var undo []func()
	cleanup := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
	for _, domain := range domains {
		var f func()
		switch runtime.GOOS {
		case "windows":
			if ap.Port() != 53 {
				cleanup()
				return func() {}, errors.New("Windows NRPT requires DNS port 53")
			}
			id, err := ps("(Add-DnsClientNrptRule -Namespace " + quote("."+domain) + " -NameServers " + quote(ap.Addr().String()) + " -Comment 'ynu-wg temporary DNS64 rule' -PassThru).Name")
			if err != nil {
				cleanup()
				return func() {}, err
			}
			f = func() { ps("Remove-DnsClientNrptRule -Name " + quote(id) + " -Force") }
		case "linux":
			if ap.Port() != 53 {
				cleanup()
				return func() {}, errors.New("automatic Linux DNS setup requires DNS port 53")
			}
			if _, err := run("resolvectl", "dns", name, ap.Addr().String()); err != nil {
				cleanup()
				return func() {}, err
			}
			// Set all domains in a single call below.
			f = func() { run("resolvectl", "revert", name) }
		case "darwin":
			path := filepath.Join("/etc/resolver", domain)
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				cleanup()
				return func() {}, fmt.Errorf("resolver file already exists: %s", path)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				cleanup()
				return func() {}, err
			}
			b := []byte(fmt.Sprintf("# ynu-wg temporary DNS64 resolver\nnameserver %s\nport %d\n", ap.Addr(), ap.Port()))
			if err := os.WriteFile(path, b, 0644); err != nil {
				cleanup()
				return func() {}, err
			}
			f = func() {
				current, _ := os.ReadFile(path)
				if bytes.Equal(current, b) {
					os.Remove(path)
				}
			}
		}
		if f != nil {
			undo = append(undo, f)
		}
	}
	if runtime.GOOS == "linux" {
		args := []string{"domain", name}
		for _, d := range domains {
			args = append(args, "~"+d)
		}
		if _, e = run("resolvectl", args...); e != nil {
			cleanup()
			return func() {}, e
		}
	}
	return cleanup, nil
}
