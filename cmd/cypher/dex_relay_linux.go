//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

const relayCLIMarker = "COMMON_DEX_RELAY_CLI_DEVNET_V1\n"

func relayOwned(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid())
}
func relayNoFollow(path string, flags int, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flags|syscall.O_NOFOLLOW, mode)
}
func relaySyncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
func prepareRelayCLIRoot(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("absolute dedicated relay parent required")
	}
	info, err := os.Lstat(path)
	created := os.IsNotExist(err)
	if created {
		if err = os.Mkdir(path, 0700); err != nil {
			return nil, err
		}
		f, err := relayNoFollow(filepath.Join(path, "RELAY_CLI"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		_, w := f.WriteString(relayCLIMarker)
		if err = errors.Join(w, f.Sync(), f.Close(), relaySyncDir(path), relaySyncDir(filepath.Dir(path))); err != nil {
			return nil, err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || !relayOwned(info) {
		return nil, errors.New("unsafe relay parent directory")
	}
	marker, err := relayRegularRead(filepath.Join(path, "RELAY_CLI"), len(relayCLIMarker), true)
	if err != nil || string(marker) != relayCLIMarker {
		return nil, errors.New("refuse unowned relay parent")
	}
	f, err := relayNoFollow(filepath.Join(path, "LOCK"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	lockInfo, err := f.Stat()
	if err != nil || !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0600 || !relayOwned(lockInfo) {
		f.Close()
		return nil, errors.New("unsafe relay parent lock")
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	if err = cleanupRelayStatusTemporaries(path); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func relayTemporaryOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}
