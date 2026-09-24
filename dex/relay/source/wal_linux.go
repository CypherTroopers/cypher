//go:build linux
// +build linux

package source

import (
	"errors"
	"os"
	"syscall"
)

func checkPlatform() error { return nil }
func openNoFollow(path string, flags int, mode os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, mode)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("source file must be regular")
	}
	return f, nil
}
func lockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }
func ownedSingleLink(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1
}
