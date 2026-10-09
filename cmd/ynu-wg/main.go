package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"golang.zx2c4.com/wireguard/tun"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/app"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/assets"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/auth"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/desktop"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/dns64"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/platform"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/translate"
)

func main() {
	if desktop.Launch(mainErr) {
		return
	}
	if e := mainErr(context.Background()); e != nil {
		fmt.Fprintln(os.Stderr, "ynu-wg:", e)
		os.Exit(1)
	}
}

type routeFlags []string

func (r *routeFlags) String() string { return strings.Join(*r, ",") }
func (r *routeFlags) Set(s string) error {
	if a, e := netip.ParseAddr(s); e == nil && a.Is4() {
		s = a.String() + "/32"
	}
	*r = append(*r, s)
	return nil
}
func mainErr(parent context.Context) error {
	global := flag.NewFlagSet("ynu-wg", flag.ContinueOnError)
	portable := global.Bool("portable", false, "store config/auth beside executable in data/")
	dir := global.String("data-dir", "", "explicit private data directory")
	authFile := global.String("auth", "", "use a specific .kkm file instead of recursive discovery")
	if e := global.Parse(os.Args[1:]); e != nil {
		return e
	}
	args := global.Args()
	if len(args) == 0 {
		args = []string{"run"}
		if runtime.GOOS == "windows" {
			args = append(args, "--configure-dns")
		}
	}
	if *dir == "" {
		p, e := platform.DataDir(*portable)
		if e != nil {
			return e
		}
		*dir = p
	}
	absolute, e := filepath.Abs(*dir)
	if e != nil {
		return e
	}
	*dir = absolute
	switch args[0] {
	case "init":
		f := flag.NewFlagSet("init", flag.ContinueOnError)
		sim := f.String("auth", *authFile, "import .kkm authentication file")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if e := platform.PrivateDir(*dir); e != nil {
			return e
		}
		if _, e := os.Stat(filepath.Join(*dir, "config.json")); os.IsNotExist(e) {
			if e = app.Save(*dir, app.DefaultConfig()); e != nil {
				return e
			}
		}
		if *sim != "" {
			b, e := os.ReadFile(*sim)
			if e != nil {
				return errors.New("cannot read authentication file")
			}
			if _, e = auth.ParseSIM(b); e != nil {
				return e
			}
			dest := filepath.Join(*dir, "auth", "sim.kkm")
			if e = platform.WritePrivate(dest, b); e != nil {
				return e
			}
		}
		if _, e := assets.Extract(*dir); e != nil {
			return e
		}
		fmt.Println("configuration:", filepath.Join(*dir, "config.json"))
		fmt.Println("authentication:", filepath.Join(*dir, "auth", "sim.kkm"))
		return nil
	case "decode":
		if len(args) != 2 {
			return errors.New("usage: decode IPv6")
		}
		c, e := app.Load(*dir)
		if e != nil {
			return e
		}
		ip, e := netip.ParseAddr(args[1])
		if e != nil {
			return e
		}
		v, e := dns64.Extract(netip.MustParsePrefix(c.Prefix), ip)
		if e != nil {
			return e
		}
		fmt.Println(v)
		return nil
	case "doctor", "run", "dns":
	default:
		return errors.New("unknown command")
	}
	if _, e := os.Stat(filepath.Join(*dir, "config.json")); os.IsNotExist(e) {
		if e = app.Save(*dir, app.DefaultConfig()); e != nil {
			return e
		}
	}
	c, e := app.Load(*dir)
	if e != nil {
		return e
	}
	if e = platform.PrivateDir(*dir); e != nil {
		return e
	}
	if args[0] != "doctor" {
		release, e := platform.AcquireLock(filepath.Join(*dir, "run.lock"))
		if e != nil {
			return e
		}
		defer release()
	}
	simPath := *authFile
	if simPath == "" {
		simPath = desktop.AuthFile()
	}
	var discoveryError error
	if simPath != "" {
		simPath, discoveryError = filepath.Abs(simPath)
		if discoveryError == nil {
			var raw []byte
			raw, discoveryError = auth.ReadSIMFile(simPath)
			if discoveryError == nil {
				_, discoveryError = auth.ParseSIM(raw)
			}
		}
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		simPath, discoveryError = auth.FindSIM(cwd)
		// Continue supporting files explicitly imported by earlier versions.
		if errors.Is(discoveryError, auth.ErrNoSIM) {
			legacy := filepath.Join(*dir, "auth", "sim.kkm")
			if raw, err := auth.ReadSIMFile(legacy); err == nil {
				if _, err = auth.ParseSIM(raw); err == nil {
					simPath = legacy
					discoveryError = nil
				}
			}
		}
	}
	if discoveryError != nil && args[0] != "doctor" && len(c.AuthCommand) == 0 && c.ProfileFile == "" {
		return discoveryError
	}
	driver, e := assets.Extract(*dir)
	if e != nil {
		return e
	}
	session := app.NewSession(c, *dir)
	session.SIMPath = simPath
	if args[0] == "doctor" {
		simOK := false
		if b, e := auth.ReadSIMFile(simPath); e == nil {
			_, e = auth.ParseSIM(b)
			simOK = e == nil
		}
		result := map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH, "config_valid": true, "sim_valid": simOK, "auth_backend": "go-lte-5g", "auth_protocol_complete": false, "dns_listen": c.DNSListen, "data_dir": *dir, "session_mode": "on-demand", "idle_seconds": c.IdleSeconds, "ipv4_routes": c.IPv4Routes}
		if simPath != "" {
			result["auth_file"] = simPath
		}
		if discoveryError != nil {
			result["auth_discovery_error"] = discoveryError.Error()
		}
		e = session.CheckDependencies()
		result["auth_dependencies_present"] = e == nil
		if e != nil {
			result["dependency_error"] = e.Error()
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	dnsSetup := f.Bool("configure-dns", false, "install temporary domain-specific system DNS rules")
	ipOnly := f.Bool("ip-only", args[0] == "run", "forward configured IPv4 CIDRs without DNS64 (default)")
	useDNS64 := f.Bool("dns64", false, "enable domain DNS64 in addition to direct IPv4 forwarding")
	var extraRoutes routeFlags
	f.Var(&extraRoutes, "route", "additional direct IPv4 CIDR (repeatable)")
	if e = f.Parse(args[1:]); e != nil {
		return e
	}
	if *useDNS64 || *dnsSetup {
		explicitIPOnly := false
		f.Visit(func(v *flag.Flag) {
			if v.Name == "ip-only" {
				explicitIPOnly = *ipOnly
			}
		})
		if explicitIPOnly {
			return errors.New("--ip-only cannot combine with --dns64 or --configure-dns")
		}
		*ipOnly = false
	}
	c.IPv4Routes = append(c.IPv4Routes, extraRoutes...)
	if e = c.Validate(); e != nil {
		return e
	}
	if *ipOnly && (args[0] != "run" || *dnsSetup || len(c.IPv4Routes) == 0) {
		return errors.New("--ip-only requires run with IPv4 routes and cannot combine with --configure-dns")
	}
	if args[0] == "dns" && len(extraRoutes) > 0 {
		return errors.New("--route requires run")
	}
	if e = session.CheckDependencies(); e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	sessionDone := make(chan struct{})
	startedSession := false
	startSession := func() { startedSession = true; go func() { session.Run(ctx); close(sessionDone) }() }
	defer func() {
		cancel()
		if startedSession {
			<-sessionDone
		}
	}()
	resolver := &dns64.Resolver{Prefix: netip.MustParsePrefix(c.Prefix), Domains: c.Domains, PublicUpstream: c.PublicDNS, CampusUpstreams: c.CampusDNS, CampusDomains: c.CampusDomains, Tunnel: session, Activity: session.Activity, Timeout: time.Duration(c.AuthTimeoutSeconds+5) * time.Second}
	if args[0] == "dns" {
		startSession()
		log.Printf("DNS64 listening on %s; on-demand authentication", c.DNSListen)
		return resolver.Serve(ctx, c.DNSListen)
	}
	if driver != "" {
		if e = platform.PrepareDriver(driver); e != nil {
			return e
		}
	}
	interfaceName := c.Interface
	if interfaceName == "auto" {
		interfaceName = "ynu64"
		if runtime.GOOS == "darwin" {
			interfaceName = "utun"
		}
		if runtime.GOOS == "windows" {
			interfaceName = "YNU64"
		}
	}
	desktop.SetStatus("仮想IFを作成中")
	log.Printf("startup: creating interface %s", interfaceName)
	t, e := tun.CreateTUN(interfaceName, c.MTU)
	if e != nil {
		return fmt.Errorf("create TUN interface: %w", e)
	}
	defer t.Close()
	name, e := t.Name()
	if e != nil {
		return e
	}
	if !*ipOnly {
		log.Printf("startup: configuring IPv6 interface %s", name)
		cleanup, e := platform.ConfigureInterface(name, c.ClientAddress, c.Prefix)
		if e != nil {
			return fmt.Errorf("configure IPv6 interface: %w", e)
		}
		defer cleanup()
	}
	if len(c.IPv4Routes) > 0 {
		desktop.SetStatus("経路を設定中")
		log.Printf("startup: finding ordinary IPv4 default route")
		bypass, e := platform.PrepareIPv4Bypass(name, c.DirectRoutes())
		if e != nil {
			return fmt.Errorf("find IPv4 default route: %w", e)
		}
		log.Printf("startup: assigning IPv4 %s and routes %v to %s", c.LocalIPv4(), c.IPv4Routes, name)
		cleanup, e := platform.ConfigureIPv4(name, c.LocalIPv4(), c.DirectRoutes())
		if e != nil {
			return fmt.Errorf("configure IPv4 address/routes: %w", e)
		}
		defer cleanup()
		defer bypass.Close()
		// Stop authentication before removing bypass routes during shutdown.
		defer func() {
			cancel()
			if startedSession {
				<-sessionDone
			}
		}()
		public, _ := netip.ParseAddrPort(c.PublicDNS)
		if public.Addr().Is4() {
			if e = bypass.Ensure(public.Addr()); e != nil {
				return e
			}
		}
		for _, s := range c.BypassIPv4 {
			if e = bypass.Ensure(netip.MustParseAddr(s)); e != nil {
				return e
			}
		}
		session.BeforeEndpoint = bypass.Ensure
	}
	log.Printf("startup: creating TCP/UDP forwarding stack")
	gateway, e := translate.NewWithRoutes(resolver.Prefix, session, c.MTU, c.DirectRoutes(), *ipOnly)
	if e != nil {
		return e
	}
	defer gateway.Close()
	gateway.Activity = session.Activity
	startSession()
	// Bind DNS before installing system rules; a port conflict never redirects DNS.
	var dnsErrors chan error
	if !*ipOnly {
		log.Printf("startup: binding DNS TCP/UDP listener %s", c.DNSListen)
		dnsErrors = make(chan error, 1)
		readySignal := make(chan struct{})
		resolver.Ready = func(string) { close(readySignal) }
		go func() { dnsErrors <- resolver.Serve(ctx, c.DNSListen) }()
		select {
		case <-readySignal:
		case e := <-dnsErrors:
			return fmt.Errorf("start DNS listener %s: %w", c.DNSListen, e)
		case <-time.After(10 * time.Second):
			return errors.New("DNS listener failed to start")
		}
		if *dnsSetup {
			desktop.SetStatus("DNSを設定中")
			log.Printf("startup: configuring DNS rules for %v via %s", c.Domains, c.DNSListen)
			undo, e := platform.ConfigureDNS(name, c.DNSListen, c.Domains)
			if e != nil {
				return fmt.Errorf("configure system DNS: %w", e)
			}
			defer undo()
		}
	}
	desktop.SetStatus("DNS有効")
	desktop.SetDetail(fmt.Sprintf("仮想IF：%s\nDNS：%s\n大学レンジ：%v\n無通信終了：%d秒", name, c.DNSListen, c.IPv4Routes, c.IdleSeconds))
	log.Printf("ready: interface=%s ip_only=%t IPv4_routes=%v idle=%ds", name, *ipOnly, c.IPv4Routes, c.IdleSeconds)
	packetErrors := make(chan error, 1)
	go func() { packetErrors <- gateway.Pump(ctx, t) }()
	select {
	case <-ctx.Done():
		return nil
	case e := <-dnsErrors:
		return e
	case e := <-packetErrors:
		return e
	}
}
