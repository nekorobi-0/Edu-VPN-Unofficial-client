package auth

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const SearchDepth = 3

var ErrNoSIM = errors.New("no valid .kkm file found in current directory or its first 3 directory levels")

// FindSIM reads candidates without moving, renaming, or changing their permissions.
// Symbolic links are not followed. Identical SIM copies count as one identity.
func FindSIM(root string) (string, error) {
	root, e := filepath.Abs(root)
	if e != nil {
		return "", e
	}
	identities := make(map[[32]byte]string)
	var candidates []string
	entries := 0
	e = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkError error) error {
		if walkError != nil {
			if path == root {
				return walkError
			}
			return nil
		}
		entries++
		if entries > 20000 {
			return errors.New("authentication search exceeded 20000 entries; use --auth PATH")
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		if entry.IsDir() {
			if path == root {
				return nil
			}
			depth := len(strings.Split(rel, string(filepath.Separator)))
			if depth > SearchDepth {
				return filepath.SkipDir
			}
			switch entry.Name() {
			case ".git", "node_modules", "runtime":
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !strings.EqualFold(filepath.Ext(path), ".kkm") {
			return nil
		}
		depth := len(strings.Split(rel, string(filepath.Separator))) - 1
		if depth > SearchDepth {
			return nil
		}
		st, e := entry.Info()
		if e != nil || !st.Mode().IsRegular() || st.Size() > 4096 {
			return nil
		}
		raw, e := ReadSIMFile(path)
		if e != nil {
			return nil
		}
		sim, e := ParseSIM(raw)
		if e != nil {
			return nil
		}
		material := append([]byte(sim.IMSI), sim.K[:]...)
		material = append(material, sim.OPc[:]...)
		id := sha256.Sum256(material)
		if _, ok := identities[id]; !ok {
			identities[id] = path
			candidates = append(candidates, path)
		}
		return nil
	})
	if e != nil {
		return "", e
	}
	if len(candidates) == 0 {
		return "", ErrNoSIM
	}
	if len(candidates) > 1 {
		return "", fmt.Errorf("multiple different .kkm authentication files found; select one with --auth PATH:\n%s", strings.Join(candidates, "\n"))
	}
	return candidates[0], nil
}
func ReadSIMFile(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("authentication path must be a regular file")
	}
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil {
		return nil, e
	}
	if len(b) > 4096 {
		return nil, errors.New("authentication file is too large")
	}
	return b, nil
}
