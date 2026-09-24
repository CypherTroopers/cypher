//go:build linux

package testnet

import (
	"os"
	"syscall"
)

func platform() error { return nil }
func noFollow(p string, f int, m os.FileMode) (*os.File, error) {
	return os.OpenFile(p, f|syscall.O_NOFOLLOW, m)
}
func lockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }
