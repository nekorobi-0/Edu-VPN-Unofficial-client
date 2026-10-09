// Generate Windows COFF resources and verify the manifest in the final EXE.
package main

import (
	"debug/pe"
	_ "embed"
	"encoding/xml"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tc-hib/winres"
)

//go:embed ynu-wg.manifest
var manifest []byte

func main() {
	out := flag.String("out", "", "directory for generated Windows resource objects")
	verify := flag.String("verify", "", "verify requireAdministrator in a compiled Windows EXE")
	flag.Parse()
	if err := run(*out, *verify); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(out, verify string) error {
	if verify != "" {
		return verifyEXE(verify)
	}
	if out == "" {
		return fmt.Errorf("specify -out or -verify")
	}
	rs := winres.ResourceSet{}
	if err := rs.Set(winres.RT_MANIFEST, winres.ID(1), 0x409, manifest); err != nil {
		return err
	}
	for _, target := range []struct {
		name string
		arch winres.Arch
	}{{"amd64", winres.ArchAMD64}, {"arm64", winres.ArchARM64}} {
		path := filepath.Join(out, "manifest_windows_"+target.name+".syso")
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		err = rs.WriteObject(f, target.arch)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func verifyEXE(path string) error {
	p, err := pe.Open(path)
	if err != nil {
		return err
	}
	if p.Section(".rsrc") == nil {
		p.Close()
		return fmt.Errorf("%s: no PE resource section", path)
	}
	header, ok := p.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || header.Subsystem != pe.IMAGE_SUBSYSTEM_WINDOWS_GUI {
		p.Close()
		return fmt.Errorf("%s: expected 64-bit GUI executable", path)
	}
	p.Close()
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	rs, err := winres.LoadFromEXESingleType(f, winres.RT_MANIFEST)
	if err != nil {
		return err
	}
	data := rs.Get(winres.RT_MANIFEST, winres.ID(1), 0x409)
	var document struct {
		XMLName   xml.Name `xml:"urn:schemas-microsoft-com:asm.v1 assembly"`
		TrustInfo struct {
			Security struct {
				RequestedPrivileges struct {
					ExecutionLevel struct {
						Level    string `xml:"level,attr"`
						UIAccess string `xml:"uiAccess,attr"`
					} `xml:"requestedExecutionLevel"`
				} `xml:"requestedPrivileges"`
			} `xml:"security"`
		} `xml:"trustInfo"`
	}
	if err := xml.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("%s: manifest parse: %w", path, err)
	}
	level := document.TrustInfo.Security.RequestedPrivileges.ExecutionLevel
	if level.Level != "requireAdministrator" || level.UIAccess != "false" {
		return fmt.Errorf("%s: missing requireAdministrator manifest", path)
	}
	fmt.Printf("Verified %s: embedded manifest requires administrator; GUI subsystem.\n", path)
	return nil
}
