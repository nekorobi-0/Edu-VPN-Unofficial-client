package desktop

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/auth"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/platform"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

//go:embed licenses.txt
var licenseText []byte

const portalURL = "https://vpn-stu.ynu.ac.jp:8443/"
const trayMessage = 0x8001
const workerMessage = 0x8002

var user32 = windows.NewLazySystemDLL("user32.dll")
var shell32 = windows.NewLazySystemDLL("shell32.dll")
var registerClass = user32.NewProc("RegisterClassExW")
var createWindow = user32.NewProc("CreateWindowExW")
var defWindow = user32.NewProc("DefWindowProcW")
var getMessage = user32.NewProc("GetMessageW")
var translateMessage = user32.NewProc("TranslateMessage")
var dispatchMessage = user32.NewProc("DispatchMessageW")
var destroyWindow = user32.NewProc("DestroyWindow")
var quitMessage = user32.NewProc("PostQuitMessage")
var postMessage = user32.NewProc("PostMessageW")
var setTimer = user32.NewProc("SetTimer")
var loadIcon = user32.NewProc("LoadIconW")
var notifyIcon = shell32.NewProc("Shell_NotifyIconW")
var registerMessage = user32.NewProc("RegisterWindowMessageW")
var createMenu = user32.NewProc("CreatePopupMenu")
var appendMenu = user32.NewProc("AppendMenuW")
var destroyMenu = user32.NewProc("DestroyMenu")
var cursorPos = user32.NewProc("GetCursorPos")
var foreground = user32.NewProc("SetForegroundWindow")
var trackMenu = user32.NewProc("TrackPopupMenu")
var getModule = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleHandleW")

type windowClass struct {
	Size, Style                        uint32
	Proc                               uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background uintptr
	MenuName, ClassName                *uint16
	SmallIcon                          uintptr
}
type point struct{ X, Y int32 }
type winMessage struct {
	Window         uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	Point          point
	Private        uint32
}
type iconData struct {
	Size                uint32
	Window              uintptr
	ID, Flags, Callback uint32
	Icon                uintptr
	Tip                 [128]uint16
	State, StateMask    uint32
	Info                [256]uint16
	Timeout             uint32
	InfoTitle           [64]uint16
	InfoFlags           uint32
	GUID                [16]byte
	BalloonIcon         uintptr
}
type preferences struct {
	StartupConfigured bool   `json:"startup_configured"`
	StartupVersion    int    `json:"startup_version,omitempty"`
	AuthFile          string `json:"auth_file,omitempty"`
	AutoStart         bool   `json:"auto_start"`
	Executable        string `json:"executable,omitempty"`
	WorkingDirectory  string `json:"working_directory,omitempty"`
}
type tray struct {
	hwnd                                      uintptr
	icon                                      iconData
	cancel                                    context.CancelFunc
	run                                       func(context.Context) error
	ctx                                       context.Context
	closing, finished                         bool
	resultMu                                  sync.Mutex
	result                                    error
	dataDir, logPath, exe, cwd, sid, taskName string
	prefs                                     preferences
	taskbarMessage                            uintptr
}

var current *tray
var wndProc = syscall.NewCallback(windowProc)

func utf(s string) *uint16 { p, _ := windows.UTF16PtrFromString(s); return p }
func box(hwnd uintptr, text, title string, flags uint32) int32 {
	r, _ := windows.MessageBox(windows.HWND(hwnd), utf(text), utf(title), flags)
	return r
}
func open(hwnd uintptr, path, args string) error {
	var a *uint16
	if args != "" {
		a = utf(args)
	}
	return windows.ShellExecute(windows.Handle(hwnd), utf("open"), utf(path), a, nil, 1)
}

// Launch owns the UI only for a no-argument Windows launch. CLI subcommands
// remain available for scripts, including doctor and explicit IP-only mode.
func Launch(run func(context.Context) error) bool {
	source := ""
	if len(os.Args) == 3 && os.Args[1] == "--desktop-source" {
		source = os.Args[2]
		os.Args = os.Args[:1]
	} else if len(os.Args) != 1 {
		return false
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	exe, e := os.Executable()
	if e != nil {
		box(0, e.Error(), "YNU-WG", 0x10)
		return true
	}
	cwd, e := os.Getwd()
	if e != nil {
		box(0, e.Error(), "YNU-WG", 0x10)
		return true
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		box(0, "管理者権限が必要です。管理者権限を要求するマニフェストを含む配布版EXEを使用してください。", "YNU-WG", 0x10)
		return true
	}
	if source == "" {
		moved, e := relocateFromDownloads(exe, cwd)
		if e != nil {
			box(0, e.Error(), "YNU-WG 保存先への移動に失敗", 0x10)
			return true
		}
		if moved {
			return true
		}
	} else {
		go removeOriginalDownload(source, exe)
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		box(0, e.Error(), "YNU-WG", 0x10)
		return true
	}
	sid := user.User.Sid.String()
	mutex, e := windows.CreateMutex(nil, false, utf("Local\\YNU-WG-Tray-"+sid))
	if mutex != 0 {
		defer windows.CloseHandle(mutex)
	}
	if errors.Is(e, windows.ERROR_ALREADY_EXISTS) {
		box(0, "YNU-WGは起動済みです。タスクトレイを確認してください。", "YNU-WG", 0x40)
		return true
	}
	if e != nil {
		box(0, e.Error(), "YNU-WG", 0x10)
		return true
	}
	dir, e := desktopDataDir()
	if e != nil {
		box(0, e.Error(), "YNU-WG", 0x10)
		return true
	}
	if e = platform.PrivateDir(dir); e != nil {
		box(0, e.Error(), "YNU-WG", 0x10)
		return true
	}
	logPath := filepath.Join(dir, "ynu-wg.log")
	if st, e := os.Stat(logPath); e == nil && st.Size() > 2<<20 {
		_ = os.Remove(logPath + ".1")
		_ = os.Rename(logPath, logPath+".1")
	}
	f, e := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		box(0, e.Error(), "YNU-WG", 0x10)
		return true
	}
	defer f.Close()
	if e = platform.Restrict(logPath, false); e != nil {
		box(0, e.Error(), "YNU-WG", 0x10)
		return true
	}
	oldOutput := log.Writer()
	log.SetOutput(f)
	defer log.SetOutput(oldOutput)
	log.Printf("desktop: startup; working_directory=%s", cwd)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sum := sha256.Sum256([]byte(sid))
	t := &tray{cancel: cancel, ctx: ctx, run: run, dataDir: dir, logPath: logPath, exe: exe, cwd: cwd, sid: sid, taskName: fmt.Sprintf("YNU-WG-%x", sum[:6])}
	if b, e := os.ReadFile(filepath.Join(dir, "desktop.json")); e == nil {
		_ = json.Unmarshal(b, &t.prefs)
	}
	current = t
	defer func() { current = nil }()
	if e = t.create(); e != nil {
		box(0, e.Error(), "YNU-WG", 0x10)
		return true
	}
	defer notifyIcon.Call(2, uintptr(unsafe.Pointer(&t.icon)))
	postMessage.Call(t.hwnd, 0x8003, 0, 0)
	var m winMessage
	for {
		r, _, e := getMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) == -1 {
			log.Printf("desktop message loop: %v", e)
			cancel()
			break
		}
		if r == 0 {
			break
		}
		translateMessage.Call(uintptr(unsafe.Pointer(&m)))
		dispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
	return true
}
func (t *tray) create() error {
	instance, _, _ := getModule.Call(0)
	icon, _, _ := loadIcon.Call(0, 32516)
	class := windowClass{Size: uint32(unsafe.Sizeof(windowClass{})), Proc: wndProc, Instance: instance, ClassName: utf("YNUWGTrayWindow")}
	if r, _, e := registerClass.Call(uintptr(unsafe.Pointer(&class))); r == 0 {
		return fmt.Errorf("register tray window: %w", e)
	}
	hwnd, _, e := createWindow.Call(0, uintptr(unsafe.Pointer(class.ClassName)), uintptr(unsafe.Pointer(utf("YNU-WG"))), 0, 0, 0, 0, 0, 0, 0, instance, 0)
	if hwnd == 0 {
		return fmt.Errorf("create tray window: %w", e)
	}
	t.hwnd = hwnd
	t.icon = iconData{Size: uint32(unsafe.Sizeof(iconData{})), Window: hwnd, ID: 1, Flags: 7, Callback: trayMessage, Icon: icon}
	if r, _, e := notifyIcon.Call(0, uintptr(unsafe.Pointer(&t.icon))); r == 0 {
		destroyWindow.Call(hwnd)
		return fmt.Errorf("create tray icon: %w", e)
	}
	t.taskbarMessage, _, _ = registerMessage.Call(uintptr(unsafe.Pointer(utf("TaskbarCreated"))))
	setTimer.Call(hwnd, 1, 1000, 0)
	t.updateIcon()
	return nil
}
func (t *tray) updateIcon() {
	tip, _ := windows.UTF16FromString("YNU-WG: " + Status())
	clear(t.icon.Tip[:])
	copy(t.icon.Tip[:127], tip)
	notifyIcon.Call(1, uintptr(unsafe.Pointer(&t.icon)))
}
func windowProc(hwnd uintptr, msg uint32, wparam, lparam uintptr) uintptr {
	t := current
	if t != nil {
		if uintptr(msg) == t.taskbarMessage && t.taskbarMessage != 0 {
			notifyIcon.Call(0, uintptr(unsafe.Pointer(&t.icon)))
			return 0
		}
		switch msg {
		case 0x8003:
			t.begin()
			return 0
		case trayMessage:
			switch uint32(lparam) {
			case 0x205, 0x7b:
				t.menu()
			case 0x203:
				t.showStatus()
			}
			return 0
		case 0x113:
			t.updateIcon()
			return 0
		case workerMessage:
			t.finished = true
			t.resultMu.Lock()
			e := t.result
			t.resultMu.Unlock()
			if t.closing {
				destroyWindow.Call(hwnd)
				return 0
			}
			SetSession("")
			if e != nil {
				SetStatus("停止（エラー）")
				SetDetail(e.Error())
				log.Printf("application stopped: %v", e)
				box(hwnd, e.Error()+"\n\n右クリックメニューからログを開けます。", "YNU-WG 起動エラー", 0x10)
			} else {
				SetStatus("停止")
			}
			t.updateIcon()
			return 0
		case 0x10:
			t.stop()
			return 0
		case 0x11:
			return 1
		case 0x16:
			if wparam != 0 {
				t.stop()
			}
			return 0
		case 2:
			quitMessage.Call(0)
			return 0
		}
	}
	r, _, _ := defWindow.Call(hwnd, uintptr(msg), wparam, lparam)
	return r
}
func (t *tray) begin() {

	if !t.prefs.StartupConfigured || (t.prefs.AutoStart && (t.prefs.StartupVersion != 2 || t.prefs.Executable != t.exe || t.prefs.WorkingDirectory != filepath.Dir(t.exe))) {
		if e := t.setStartup(true); e != nil {
			log.Printf("startup registration failed: %v", e)
			box(t.hwnd, e.Error(), "スタートアップ登録失敗", 0x10)
		}
	}

	if !t.findSIM() {
		t.finished = true
		t.stop()
		return
	}
	go func() {
		e := t.run(t.ctx)
		t.resultMu.Lock()
		t.result = e
		t.resultMu.Unlock()
		postMessage.Call(t.hwnd, workerMessage, 0, 0)
	}()
}
func (t *tray) findSIM() bool {
	if path, e := auth.FindSIM(t.cwd); e == nil {
		return t.useSIM(path)
	} else if !errors.Is(e, auth.ErrNoSIM) {
		log.Printf("SIM discovery: %v", e)
	}
	if t.prefs.AuthFile != "" {
		if validSIM(t.prefs.AuthFile) {
			SetAuthFile(t.prefs.AuthFile)
			return true
		}
	}
	legacy := filepath.Join(t.dataDir, "auth", "sim.kkm")
	if validSIM(legacy) {
		return t.useSIM(legacy)
	}
	for {
		r := box(t.hwnd, "SIM認証ファイル（.kkm）が見つかりません。\n\n"+portalURL+"\nからSIMファイルをダウンロードしてきてください。\n\n「はい」：ダウンロードページを開いてファイルを選択\n「いいえ」：ダウンロード済みのファイルを選択\n「キャンセル」：終了", "YNU-WG SIMファイルのダウンロード", 0x23)
		if r == 2 {
			return false
		}
		if r == 6 {
			if e := open(t.hwnd, portalURL, ""); e != nil {
				box(t.hwnd, e.Error(), "ページを開けません", 0x10)
			}
		}
		path, e := pickSIM(t.hwnd, t.cwd)
		if e != nil {
			box(t.hwnd, e.Error(), "認証ファイル選択エラー", 0x10)
			continue
		}
		if path == "" {
			return false
		}
		if validSIM(path) {
			return t.useSIM(path)
		}
		box(t.hwnd, "有効なSIM認証ファイルではありません。.kkmファイルを選択してください。", "YNU-WG 認証ファイル", 0x10)
	}
}
func validSIM(path string) bool {
	b, e := auth.ReadSIMFile(path)
	if e != nil {
		return false
	}
	_, e = auth.ParseSIM(b)
	return e == nil
}
func (t *tray) useSIM(path string) bool {
	SetAuthFile(path)
	t.prefs.AuthFile = path
	t.savePrefs()
	return true
}
func (t *tray) savePrefs() {
	b, _ := json.MarshalIndent(t.prefs, "", "  ")
	if e := platform.WritePrivate(filepath.Join(t.dataDir, "desktop.json"), append(b, '\n')); e != nil {
		log.Printf("save desktop preferences: %v", e)
		box(t.hwnd, e.Error(), "設定保存エラー", 0x10)
	}
}
func (t *tray) setStartup(enable bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if enable {
		path := filepath.Join(t.dataDir, "startup-task.xml")
		if e := platform.WritePrivate(path, taskXML(t.exe, filepath.Dir(t.exe), t.sid)); e != nil {
			return e
		}
		defer os.Remove(path)
		cmd = exec.CommandContext(ctx, "schtasks.exe", "/Create", "/TN", t.taskName, "/XML", path, "/F")
	} else {
		cmd = exec.CommandContext(ctx, "schtasks.exe", "/Delete", "/TN", t.taskName, "/F")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, e := cmd.CombinedOutput()
	if e != nil {
		return fmt.Errorf("スタートアップ設定: %s (%v)", platform.CommandOutput(out), e)
	}
	if e := t.updateShortcuts(enable); e != nil {
		return e
	}
	t.prefs.StartupConfigured = true
	t.prefs.StartupVersion = 2
	t.prefs.AutoStart = enable
	t.prefs.Executable = t.exe
	t.prefs.WorkingDirectory = filepath.Dir(t.exe)
	t.savePrefs()
	return nil
}
func (t *tray) showStatus() {
	auto := "無効"
	if t.prefs.AutoStart {
		auto = "有効"
	}
	box(t.hwnd, Status()+"\n\n"+Detail()+"\n\nスタートアップ："+auto+"\nログ："+t.logPath, "YNU-WG ステータス", 0x40)
}
func (t *tray) stop() {
	if t.closing {
		return
	}
	t.closing = true
	SetStatus("終了処理中")
	SetSession("")
	t.cancel()
	if t.finished {
		destroyWindow.Call(t.hwnd)
	}
}
func (t *tray) menu() {
	menu, _, _ := createMenu.Call()
	if menu == 0 {
		return
	}
	defer destroyMenu.Call(menu)
	add := func(flags, id uintptr, label string) {
		appendMenu.Call(menu, flags, id, uintptr(unsafe.Pointer(utf(label))))
	}
	add(3, 0, Status())
	add(0x800, 0, "")
	add(0, 1, "ステータスを表示")
	add(0, 2, "ログを開く")
	add(0, 3, "SIMダウンロードページを開く")
	add(0, 6, "ライセンスを表示")
	label := "スタートアップを有効にする"
	if t.prefs.AutoStart {
		label = "スタートアップを無効にする"
	}
	add(0, 4, label)
	add(0x800, 0, "")
	add(0, 5, "終了")
	var p point
	cursorPos.Call(uintptr(unsafe.Pointer(&p)))
	foreground.Call(t.hwnd)
	selected, _, _ := trackMenu.Call(menu, 0x182, uintptr(p.X), uintptr(p.Y), 0, t.hwnd, 0)
	postMessage.Call(t.hwnd, 0, 0, 0)
	switch selected {
	case 1:
		t.showStatus()
	case 2:
		if e := open(t.hwnd, "notepad.exe", syscall.EscapeArg(t.logPath)); e != nil {
			box(t.hwnd, e.Error(), "ログを開けません", 0x10)
		}
	case 3:
		_ = open(t.hwnd, portalURL, "")
	case 4:
		if e := t.setStartup(!t.prefs.AutoStart); e != nil {
			box(t.hwnd, e.Error(), "スタートアップ設定エラー", 0x10)
		}
	case 6:
		path := filepath.Join(t.dataDir, "licenses.txt")
		if e := platform.WritePrivate(path, licenseText); e == nil {
			_ = open(t.hwnd, "notepad.exe", syscall.EscapeArg(path))
		}
	case 5:
		t.stop()
	}
}
