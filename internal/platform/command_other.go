//go:build !windows

package platform

import "os/exec"

func hideCommandWindow(*exec.Cmd) {}

func CommandOutput(data []byte) string { return string(data) }
