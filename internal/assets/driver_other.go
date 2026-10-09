//go:build !windows

package assets

func extractDriver(string) (string, error) { return "", nil }
