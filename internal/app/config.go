package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"time"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/platform"
)

// Verified YNUNET allocation. Compiled into each platform executable.
const DefaultUniversityIPv4CIDR = "133.34.0.0/16"

type Config struct {
	IPv4Routes         []string `json:"ipv4_routes"`
	IPv4Address        string   `json:"ipv4_address,omitempty"`
	BypassIPv4         []string `json:"bypass_ipv4,omitempty"`
	DNSListen          string   `json:"dns_listen"`
	AllowRemoteDNS     bool     `json:"allow_remote_dns,omitempty"`
	PublicDNS          string   `json:"public_dns"`
	CampusDNS          []string `json:"campus_dns"`
	Domains            []string `json:"domains"`
	CampusDomains      []string `json:"campus_domains"`
	Prefix             string   `json:"nat64_prefix"`
	Interface          string   `json:"interface"`
	ClientAddress      string   `json:"client_address"`
	MTU                int      `json:"mtu"`
	AuthHost           string   `json:"auth_host"`
	IdleSeconds        int      `json:"idle_seconds"`
	AuthTimeoutSeconds int      `json:"auth_timeout_seconds"`
	RetrySeconds       int      `json:"retry_seconds"`
	AuthCommand        []string `json:"auth_command,omitempty"`
	ProfileFile        string   `json:"profile_file,omitempty"`
}

func DefaultConfig() Config {
	name := "auto"
	return Config{IPv4Routes: []string{DefaultUniversityIPv4CIDR}, DNSListen: "127.0.0.1:53", PublicDNS: "1.1.1.1:53", CampusDNS: []string{"133.34.4.251:53", "133.34.4.58:53"}, Domains: []string{"ac.jp"}, CampusDomains: []string{"ynu.ac.jp"}, Prefix: "fd00:596e:7500::/96", Interface: name, ClientAddress: "fd00:596e:7501::2", MTU: 1280, AuthHost: "vpn-stu.ynu.ac.jp:10000", IdleSeconds: 5, AuthTimeoutSeconds: 60, RetrySeconds: 5}
}
func (c Config) Validate() error {
	p, e := netip.ParsePrefix(c.Prefix)
	if e != nil || !p.Addr().Is6() || p.Bits() != 96 || p != p.Masked() || p.Addr().Is4In6() {
		return errors.New("nat64_prefix must be canonical IPv6 /96")
	}
	a, e := netip.ParseAddr(c.ClientAddress)
	if e != nil || !a.Is6() || a.Is4In6() || p.Contains(a) {
		return errors.New("client_address must be IPv6 outside NAT64 prefix")
	}
	if !regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,14}$`).MatchString(c.Interface) {
		return errors.New("invalid interface name")
	}
	if c.MTU < 1280 || c.MTU > 9000 {
		return errors.New("local IPv6 MTU must be 1280..9000")
	}
	if c.IdleSeconds < 1 || c.AuthTimeoutSeconds < 1 || c.RetrySeconds < 1 {
		return errors.New("timeouts must be positive")
	}
	for _, s := range append([]string{c.DNSListen, c.PublicDNS}, c.CampusDNS...) {
		if ap, e := netip.ParseAddrPort(s); e != nil || ap.Port() == 0 {
			return fmt.Errorf("invalid numeric DNS address: %s", s)
		}
	}
	listen, _ := netip.ParseAddrPort(c.DNSListen)
	if !listen.Addr().IsLoopback() && !c.AllowRemoteDNS {
		return errors.New("local DNS listener must be loopback")
	}
	domain := regexp.MustCompile(`^[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$`)
	for _, d := range append(append([]string{}, c.Domains...), c.CampusDomains...) {
		if !domain.MatchString(d) {
			return errors.New("invalid DNS suffix")
		}
	}
	if len(c.Domains) == 0 || len(c.CampusDNS) == 0 {
		return errors.New("DNS suffixes and campus DNS servers are required")
	}
	for _, s := range c.IPv4Routes {
		p, e := netip.ParsePrefix(s)
		if e != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() == 0 {
			return errors.New("ipv4_routes requires canonical IPv4 CIDRs; default route /0 is not supported")
		}
	}
	for _, s := range c.BypassIPv4 {
		a, e := netip.ParseAddr(s)
		if e != nil || !a.Is4() {
			return errors.New("bypass_ipv4 requires numeric IPv4 addresses")
		}
	}
	if len(c.IPv4Routes) > 0 {
		a, e := netip.ParseAddr(c.LocalIPv4())
		if e != nil || !a.Is4() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() {
			return errors.New("invalid ipv4_address")
		}
		for _, s := range c.IPv4Routes {
			if netip.MustParsePrefix(s).Contains(a) {
				return errors.New("ipv4_address must be outside ipv4_routes")
			}
		}
	}
	if _, port, e := net.SplitHostPort(c.AuthHost); e != nil || port != "10000" {
		return errors.New("auth_host must be host:10000")
	}
	return nil
}
func (c Config) LocalIPv4() string {
	if c.IPv4Address != "" {
		return c.IPv4Address
	}
	return "198.18.0.1"
}
func (c Config) DirectRoutes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(c.IPv4Routes))
	seen := make(map[netip.Prefix]bool)
	for _, s := range c.IPv4Routes {
		p := netip.MustParsePrefix(s)
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}
func Load(dir string) (Config, error) {
	var c Config
	b, e := os.ReadFile(filepath.Join(dir, "config.json"))
	if e != nil {
		return c, e
	}
	if e = json.Unmarshal(b, &c); e != nil {
		return c, e
	}
	// Older configs omitted ipv4_routes. Preserve an explicit [] as an opt-out.
	if c.IPv4Routes == nil {
		c.IPv4Routes = []string{DefaultUniversityIPv4CIDR}
	}
	return c, c.Validate()
}
func Save(dir string, c Config) error {
	if e := c.Validate(); e != nil {
		return e
	}
	b, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	return platform.WritePrivate(filepath.Join(dir, "config.json"), append(b, '\n'))
}
func (c Config) Idle() time.Duration { return time.Duration(c.IdleSeconds) * time.Second }
