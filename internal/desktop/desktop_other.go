//go:build !windows

package desktop

import "context"

func Launch(func(context.Context) error) bool { return false }
