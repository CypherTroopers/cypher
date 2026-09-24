//go:build linux
// +build linux

package rewards

import (
	"os"
	"syscall"
)

func checkCollectorWALPlatform() error { return nil }
func collectorOpenNoFollow(path string, flags int, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flags|syscall.O_NOFOLLOW, mode)
}
func collectorLockExclusive(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
