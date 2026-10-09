package desktop

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/platform"
)

func desktopDataDir() (string, error) {
	p := os.Getenv("LOCALAPPDATA")
	if p == "" {
		return "", errors.New("LOCALAPPDATA is unset")
	}
	return filepath.Join(p, "YNU-WG"), nil
}
func inDownloads(path string) bool {
	root, e := windows.KnownFolderPath(windows.FOLDERID_Downloads, 0)
	if e != nil {
		return false
	}
	rel, e := filepath.Rel(strings.ToLower(root), strings.ToLower(path))
	return e == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
func relocateFromDownloads(exe, cwd string) (bool, error) {
	if !inDownloads(exe) {
		return false, nil
	}
	dir, e := desktopDataDir()
	if e != nil {
		return false, e
	}
	dest := filepath.Join(dir, "bin", "ynu-wg.exe")
	b, e := os.ReadFile(exe)
	if e != nil {
		return false, e
	}
	if e = platform.WritePrivate(dest, b); e != nil {
		return false, e
	}
	args := "--desktop-source " + syscall.EscapeArg(exe)
	if e = windows.ShellExecute(0, utf("open"), utf(dest), utf(args), utf(cwd), 1); e != nil {
		return false, e
	}
	return true, nil
}
func removeOriginalDownload(source, exe string) {
	if !inDownloads(source) || !strings.EqualFold(filepath.Ext(source), ".exe") {
		return
	}
	// Remove only the exact binary just copied, after its original process exits.
	a, e := os.ReadFile(source)
	if e != nil {
		return
	}
	b, e := os.ReadFile(exe)
	if e != nil || sha256.Sum256(a) != sha256.Sum256(b) {
		return
	}
	for i := 0; i < 30; i++ {
		time.Sleep(200 * time.Millisecond)
		if e = os.Remove(source); e == nil || errors.Is(e, os.ErrNotExist) {
			return
		}
	}
}
func (t *tray) startupShortcut(enable bool) error {
	dir, e := windows.KnownFolderPath(windows.FOLDERID_Startup, 0)
	if e != nil {
		return e
	}
	path := filepath.Join(dir, "YNU-WG.lnk")
	if !enable {
		if e := os.Remove(path); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		return nil
	}
	// The shortcut invokes the per-user interactive elevated task. No password,
	// helper script, or console window is needed at subsequent logins.
	psQuote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	programDir, e := windows.KnownFolderPath(windows.FOLDERID_Programs, 0)
	if e != nil {
		return e
	}
	programPath := filepath.Join(programDir, "YNU-WG.lnk")
	script := "$w=New-Object -ComObject WScript.Shell; $s=$w.CreateShortcut(" + psQuote(path) + "); $s.TargetPath=" + psQuote(t.exe) + "; $s.Arguments='--desktop-startup'; $s.WorkingDirectory=" + psQuote(filepath.Dir(t.exe)) + "; $s.IconLocation=" + psQuote(t.exe+",0") + "; $s.Description='YNU-WG'; $s.Save(); $m=$w.CreateShortcut(" + psQuote(programPath) + "); $m.TargetPath=" + psQuote(t.exe) + "; $m.WorkingDirectory=" + psQuote(filepath.Dir(t.exe)) + "; $m.IconLocation=" + psQuote(t.exe+",0") + "; $m.Description='YNU-WG'; $m.Save()"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; "+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, e := cmd.CombinedOutput(); e != nil {
		return fmt.Errorf("ショートカット登録: %s (%v)", platform.CommandOutput(out), e)
	}
	return nil
}

type openFileName struct {
	Size                         uint32
	Owner, Instance              uintptr
	Filter, CustomFilter         *uint16
	MaxCustomFilter, FilterIndex uint32
	File                         *uint16
	MaxFile                      uint32
	FileTitle                    *uint16
	MaxFileTitle                 uint32
	InitialDir, Title            *uint16
	Flags                        uint32
	FileOffset, FileExtension    uint16
	DefaultExtension             *uint16
	CustomData, Hook             uintptr
	TemplateName                 *uint16
	Reserved                     uintptr
	ReservedDWORD, FlagsEx       uint32
}

func pickSIM(owner uintptr, dir string) (string, error) {
	dll := windows.NewLazySystemDLL("comdlg32.dll")
	choose := dll.NewProc("GetOpenFileNameW")
	extendedError := dll.NewProc("CommDlgExtendedError")
	filter := utf16.Encode([]rune("SIM認証ファイル (*.kkm)\x00*.kkm\x00すべてのファイル\x00*.*\x00\x00"))
	buffer := make([]uint16, 32768)
	of := openFileName{Size: uint32(unsafe.Sizeof(openFileName{})), Owner: owner, Filter: &filter[0], FilterIndex: 1, File: &buffer[0], MaxFile: uint32(len(buffer)), InitialDir: utf(dir), Title: utf("SIM認証ファイル（.kkm）を選択"), Flags: 0x80000 | 0x1000 | 0x800 | 8, DefaultExtension: utf("kkm")}
	r, _, _ := choose.Call(uintptr(unsafe.Pointer(&of)))
	if r == 0 {
		n, _, _ := extendedError.Call()
		if n != 0 {
			return "", fmt.Errorf("ファイル選択ダイアログ: 0x%x", n)
		}
		return "", nil
	}
	return windows.UTF16ToString(buffer), nil
}

func startScheduledTask() {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		box(0, e.Error(), "YNU-WG", 0x10)
		return
	}
	sum := sha256.Sum256([]byte(user.User.Sid.String()))
	name := fmt.Sprintf("YNU-WG-%x", sum[:6])
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "schtasks.exe", "/Run", "/TN", name)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, e := cmd.CombinedOutput(); e != nil {
		box(0, fmt.Sprintf("スタートアップ起動に失敗しました。EXEを直接開いて登録し直してください。\n%s (%v)", platform.CommandOutput(out), e), "YNU-WG", 0x10)
	}
}
