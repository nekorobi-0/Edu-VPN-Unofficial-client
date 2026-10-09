package desktop

import (
	"encoding/binary"
	"encoding/xml"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"
)

func TestScheduledTaskPreservesPathsAndInteractiveElevation(t *testing.T) {
	exe := `C:\Users\日本語 😀 & Test\App\ynu-wg.exe`
	cwd := `C:\Users\日本語 😀 & Test\Downloads`
	b := taskXML(exe, cwd, "S-1-5-21-123")
	if len(b) < 4 || b[0] != 0xff || b[1] != 0xfe || len(b)%2 != 0 {
		t.Fatal("schtasks XML must be UTF-16LE with a BOM")
	}
	units := make([]uint16, (len(b)-2)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(b[2+2*i:])
	}
	document := string(utf16.Decode(units))
	if !strings.HasPrefix(document, `<?xml version="1.0" encoding="UTF-16"?>`) {
		t.Fatal("XML declaration does not match the file encoding")
	}
	// encoding/xml consumes UTF-8; decode the file before checking task semantics.
	decoded := strings.Replace(document, `encoding="UTF-16"`, `encoding="UTF-8"`, 1)
	var task struct {
		Principals struct {
			Principal struct {
				UserID    string `xml:"UserId"`
				LogonType string
				RunLevel  string
			}
		}
		Actions struct {
			Exec struct{ Command, WorkingDirectory string }
		}
		Settings struct{ MultipleInstancesPolicy, ExecutionTimeLimit, DisallowStartIfOnBatteries string }
	}
	if err := xml.Unmarshal([]byte(decoded), &task); err != nil {
		t.Fatal(err)
	}
	if task.Actions.Exec.Command != exe || task.Actions.Exec.WorkingDirectory != cwd {
		t.Fatal("task paths were corrupted")
	}
	p := task.Principals.Principal
	if p.UserID != "S-1-5-21-123" || p.LogonType != "InteractiveToken" || p.RunLevel != "HighestAvailable" {
		t.Fatal("task would launch outside the user's elevated interactive session")
	}
	if task.Settings.ExecutionTimeLimit != "PT0S" || task.Settings.MultipleInstancesPolicy != "IgnoreNew" || task.Settings.DisallowStartIfOnBatteries != "false" {
		t.Fatal("task must keep running and avoid duplicate instances")
	}
	if strings.Contains(document, "<Triggers>") {
		t.Fatal("startup shortcut owns the trigger; avoid a second login trigger")
	}
}
func TestStatusUpdatesAreSafeDuringTrayReads(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				SetStatus("DNS有効")
				SetSession("active")
				SetDetail("state")
				SetAuthFile("test.kkm")
				_ = Status()
				_ = Detail()
				_ = AuthFile()
			}
		}()
	}
	wg.Wait()
	SetSession("idle")
	if !strings.Contains(Status(), "待機中") {
		t.Fatal("idle session shown as disconnected error")
	}
}
