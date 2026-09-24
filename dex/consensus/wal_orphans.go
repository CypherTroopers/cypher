package consensus

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	walPendingName         = "state.pending.tmp"
	maxWALDirectoryEntries = 64
	maxWALOrphans          = 32
	maxWALOrphanBytes      = 4 * maxWALBytes
)

// cleanupTemporary runs once after the canonical records, local safety state
// and external recovery callbacks succeeded, with the exclusive WAL lock held.
// Pending bytes are never parsed or promoted to canonical state.
func (w *walStore) cleanupTemporary() error {
	if !w.recoveryVerified || w.lock == nil {
		return errors.New("DEX temporary cleanup requires authenticated locked recovery")
	}
	info, err := os.Lstat(w.dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode() != os.ModeDir|0700 || !ownedWALDirectory(info) {
		return errors.New("unsafe DEX WAL cleanup directory")
	}
	d, err := os.Open(w.dir)
	if err != nil {
		return err
	}
	names, readErr := d.Readdirnames(maxWALDirectoryEntries + 1)
	closeErr := d.Close()
	if readErr != nil && readErr != io.EOF {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if len(names) > maxWALDirectoryEntries {
		return errors.New("DEX WAL directory entry bound")
	}
	var paths []string
	var total int64
	for _, name := range names {
		oldGeneration := false
		if w.generational && w.currentPresent && len(name) == len(generationStateName(0)) && strings.HasPrefix(name, "state-") && strings.HasSuffix(name, ".json") {
			g, e := strconv.ParseUint(name[6:26], 10, 64)
			oldGeneration = e == nil && generationStateName(g) == name && g < w.generation
		}
		if !oldGeneration && name != walPendingName && name != "archive.pending.tmp" && name != "CURRENT.pending" && !(strings.HasPrefix(name, "state-") && strings.HasSuffix(name, ".tmp")) {
			continue
		}
		if len(paths) >= maxWALOrphans {
			return errors.New("DEX WAL orphan count bound")
		}
		path := filepath.Join(w.dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode() != 0600 || !info.Mode().IsRegular() || !ownedWALTemporary(info) || info.Size() < 0 || info.Size() > maxWALBytes {
			return errors.New("unsafe DEX WAL temporary generation")
		}
		total += info.Size()
		if total > maxWALOrphanBytes {
			return errors.New("DEX WAL orphan byte bound")
		}
		paths = append(paths, path)
	}
	if len(paths) != 0 && !w.canonicalPresent {
		return errors.New("DEX canonical WAL missing while temporary generations remain")
	}
	// Validate the whole candidate set before removing any file. Unknown names
	// are intentionally preserved even inside the owned directory.
	for _, path := range paths {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	if len(paths) == 0 {
		return nil
	}
	d, err = os.Open(w.dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}
