package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"sync"
)

// IPv4Bypass keeps control-plane sockets out of the newly installed TUN routes.
// The original default path is captured before the forwarding routes are added.
type IPv4Bypass struct {
	mu                        sync.Mutex
	name, dev, gateway, index string
	ranges                    []netip.Prefix
	installed                 map[netip.Addr]func()
	execute                   func(string, ...string) (string, error)
}

func PrepareIPv4Bypass(name string, ranges []netip.Prefix) (*IPv4Bypass, error) {
	b := &IPv4Bypass{name: name, ranges: ranges, installed: make(map[netip.Addr]func())}
	switch runtime.GOOS {
	case "linux":
		out, e := run("ip", "-j", "-4", "route", "show", "default")
		if e != nil {
			return nil, e
		}
		var rows []struct {
			Dev     string `json:"dev"`
			Gateway string `json:"gateway"`
			Metric  int    `json:"metric"`
		}
		if e = json.Unmarshal([]byte(out), &rows); e != nil {
			return nil, e
		}
		best := -1
		for i, r := range rows {
			if r.Dev != "" && r.Dev != name && (best < 0 || r.Metric < rows[best].Metric) {
				best = i
			}
		}
		if best < 0 {
			return nil, errors.New("no ordinary IPv4 default route for control-plane bypass")
		}
		b.dev, b.gateway = rows[best].Dev, rows[best].Gateway
	case "windows":
		script := "$r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object {$_.InterfaceAlias -ne " + quote(name) + "} | Sort-Object @{Expression={$_.RouteMetric+(Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).InterfaceMetric}} | Select-Object -First 1; if(!$r){throw 'No IPv4 default route'}; @{index=[string]$r.InterfaceIndex;gateway=[string]$r.NextHop} | ConvertTo-Json -Compress"
		out, e := ps(script)
		if e != nil {
			return nil, e
		}
		var r struct {
			Index   string `json:"index"`
			Gateway string `json:"gateway"`
		}
		if e = json.Unmarshal([]byte(out), &r); e != nil {
			return nil, e
		}
		b.index, b.gateway = r.Index, r.Gateway
	case "darwin":
		out, e := run("route", "-n", "get", "-inet", "default")
		if e != nil {
			return nil, e
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) == 2 {
				switch f[0] {
				case "interface:":
					b.dev = f[1]
				case "gateway:":
					b.gateway = f[1]
				}
			}
		}
		if b.dev == "" || b.dev == name {
			return nil, errors.New("no ordinary IPv4 default interface")
		}
		if a, e := netip.ParseAddr(b.gateway); e != nil || !a.Is4() {
			b.gateway = ""
		}
	default:
		return nil, errors.New("unsupported IPv4 route platform")
	}
	return b, nil
}
func (b *IPv4Bypass) Ensure(ip netip.Addr) error {
	if !ip.IsValid() {
		return errors.New("valid bypass endpoint required")
	}
	if !ip.Is4() {
		return nil
	} // IPv4 routes cannot capture an IPv6 control socket.
	captured := false
	for _, p := range b.ranges {
		if p.Contains(ip) {
			captured = true
			break
		}
	}
	if !captured {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.installed[ip]; ok {
		return nil
	}
	prefix := ip.String() + "/32"
	var e error
	var undo func()
	switch runtime.GOOS {
	case "linux":
		args := []string{"-4", "route", "add", prefix}
		if b.gateway != "" {
			args = append(args, "via", b.gateway)
		}
		args = append(args, "dev", b.dev)
		_, e = b.command("ip", args...)
		undo = func() { del := append([]string{}, args...); del[2] = "del"; b.command("ip", del...) }
		if e != nil {
			out, queryError := b.command("ip", "-j", "-4", "route", "get", ip.String())
			var rows []struct {
				Dev string `json:"dev"`
			}
			if queryError == nil && json.Unmarshal([]byte(out), &rows) == nil && len(rows) > 0 && rows[0].Dev != "" && rows[0].Dev != b.name {
				return nil
			}
		}
	case "windows":
		_, e = b.powershell("New-NetRoute -AddressFamily IPv4 -DestinationPrefix " + quote(prefix) + " -InterfaceIndex " + b.index + " -NextHop " + quote(b.gateway) + " -PolicyStore ActiveStore | Out-Null")
		undo = func() {
			b.powershell("Get-NetRoute -AddressFamily IPv4 -DestinationPrefix " + quote(prefix) + " -InterfaceIndex " + b.index + " -NextHop " + quote(b.gateway) + " -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false")
		}
	case "darwin":
		args := []string{"-n", "add", "-inet", "-host", ip.String()}
		if b.gateway != "" {
			args = append(args, b.gateway)
		} else {
			args = append(args, "-interface", b.dev)
		}
		_, e = b.command("route", args...)
		undo = func() { del := append([]string{}, args...); del[1] = "delete"; b.command("route", del...) }
	}
	if e != nil {
		return fmt.Errorf("cannot bypass control-plane endpoint %s: %w", ip, e)
	}
	b.installed[ip] = undo
	return nil
}
func (b *IPv4Bypass) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ip, undo := range b.installed {
		undo()
		delete(b.installed, ip)
	}
}

func ConfigureIPv4(name, address string, ranges []netip.Prefix) (func(), error) {
	var undo []func()
	cleanup := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
	fail := func(e error) (func(), error) { cleanup(); return func() {}, e }
	switch runtime.GOOS {
	case "linux":
		if _, e := run("ip", "-4", "addr", "add", address+"/32", "dev", name); e != nil {
			return fail(e)
		}
		undo = append(undo, func() { run("ip", "-4", "addr", "del", address+"/32", "dev", name) })
		if _, e := run("ip", "link", "set", "dev", name, "up"); e != nil {
			return fail(e)
		}
	case "windows":
		if _, e := ps("New-NetIPAddress -InterfaceAlias " + quote(name) + " -IPAddress " + quote(address) + " -PrefixLength 32 -AddressFamily IPv4 | Out-Null"); e != nil {
			return fail(e)
		}
		undo = append(undo, func() {
			ps("Get-NetIPAddress -InterfaceAlias " + quote(name) + " -IPAddress " + quote(address) + " -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false")
		})
	case "darwin":
		if _, e := run("ifconfig", name, "inet", address, address, "netmask", "255.255.255.255", "up"); e != nil {
			return fail(e)
		}
		undo = append(undo, func() { run("ifconfig", name, "inet", address, "-alias") })
	}
	for _, p := range ranges {
		prefix := p.String()
		switch runtime.GOOS {
		case "linux":
			if _, e := run("ip", "-4", "route", "add", prefix, "dev", name, "src", address); e != nil {
				return fail(e)
			}
			undo = append(undo, func() { run("ip", "-4", "route", "del", prefix, "dev", name) })
		case "windows":
			if _, e := ps("New-NetRoute -InterfaceAlias " + quote(name) + " -DestinationPrefix " + quote(prefix) + " -NextHop '0.0.0.0' -PolicyStore ActiveStore | Out-Null"); e != nil {
				return fail(e)
			}
			undo = append(undo, func() {
				ps("Get-NetRoute -InterfaceAlias " + quote(name) + " -DestinationPrefix " + quote(prefix) + " -NextHop '0.0.0.0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false")
			})
		case "darwin":
			if _, e := run("route", "-n", "add", "-inet", "-net", prefix, "-interface", name); e != nil {
				return fail(e)
			}
			undo = append(undo, func() { run("route", "-n", "delete", "-inet", "-net", prefix, "-interface", name) })
		}
	}
	return cleanup, nil
}

func (b *IPv4Bypass) command(name string, args ...string) (string, error) {
	if b.execute != nil {
		return b.execute(name, args...)
	}
	return run(name, args...)
}
func (b *IPv4Bypass) powershell(script string) (string, error) {
	return b.command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; "+script)
}
