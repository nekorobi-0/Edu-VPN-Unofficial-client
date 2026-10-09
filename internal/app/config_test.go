package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDirectRouteValidation(t *testing.T) {
	for _, route := range []string{"0.0.0.0/0", "133.34.1.0/16", "2001:db8::/32", "not-an-ip"} {
		c := DefaultConfig()
		c.IPv4Routes = []string{route}
		if c.Validate() == nil {
			t.Fatalf("invalid direct IPv4 route accepted: %s", route)
		}
	}
	c := DefaultConfig()
	c.IPv4Routes = []string{"133.34.0.0/16", "133.34.0.0/16", "203.0.113.7/32"}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	if len(c.DirectRoutes()) != 2 {
		t.Fatal("route deduplication failed")
	}
	c.IPv4Address = "133.34.5.6"
	if c.Validate() == nil {
		t.Fatal("TUN address inside forwarding range accepted")
	}
}

func TestBuiltInUniversityRangeAndLegacyConfig(t *testing.T) {
	dir := t.TempDir()
	c := DefaultConfig()
	if len(c.IPv4Routes) != 1 || c.IPv4Routes[0] != "133.34.0.0/16" {
		t.Fatal("missing compiled university default")
	}
	b, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	var legacy map[string]json.RawMessage
	if e = json.Unmarshal(b, &legacy); e != nil {
		t.Fatal(e)
	}
	delete(legacy, "ipv4_routes")
	b, e = json.Marshal(legacy)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "config.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	loaded, e := Load(dir)
	if e != nil {
		t.Fatal(e)
	}
	if len(loaded.IPv4Routes) != 1 || loaded.IPv4Routes[0] != DefaultUniversityIPv4CIDR {
		t.Fatal("legacy config did not receive compiled range")
	}
	c.IPv4Routes = []string{}
	if e = Save(dir, c); e != nil {
		t.Fatal(e)
	}
	loaded, e = Load(dir)
	if e != nil {
		t.Fatal(e)
	}
	if loaded.IPv4Routes == nil || len(loaded.IPv4Routes) != 0 {
		t.Fatal("explicit empty route list did not survive save/load")
	}
	c.IPv4Routes = []string{"203.0.113.7/32"}
	if e = Save(dir, c); e != nil {
		t.Fatal(e)
	}
	loaded, e = Load(dir)
	if e != nil || len(loaded.IPv4Routes) != 1 || loaded.IPv4Routes[0] != c.IPv4Routes[0] {
		t.Fatal("explicit route override was lost")
	}
}
