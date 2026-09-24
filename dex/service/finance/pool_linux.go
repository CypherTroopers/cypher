//go:build linux

package finance

import (
	"os"
	"syscall"
)

func poolPlatform() error { return nil }
func poolNoFollow(path string, flags int, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flags|syscall.O_NOFOLLOW, mode)
}
func poolLock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }
