package platform

import (
	"golang.org/x/sys/windows"
	"os/exec"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
)

func hideCommandWindow(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} }

// CommandOutput converts localized Windows console output into UTF-8 for logs
// and Unicode dialogs. Modern UTF-8 output is already in the correct encoding.
func CommandOutput(data []byte) string {
	if utf8.Valid(data) {
		return string(data)
	}
	// CP_OEMCP (1) follows the system console code page (e.g. 932 on Japanese Windows).
	n, err := windows.MultiByteToWideChar(1, 0, &data[0], int32(len(data)), nil, 0)
	if err != nil {
		return string(data)
	}
	units := make([]uint16, n)
	n, err = windows.MultiByteToWideChar(1, 0, &data[0], int32(len(data)), &units[0], n)
	if err != nil {
		return string(data)
	}
	return string(utf16.Decode(units[:n]))
}
