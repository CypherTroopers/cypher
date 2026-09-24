//go:build !linux
// +build !linux

package rewards

import (
	"errors"
	"os"
)

func checkCollectorWALPlatform() error {
	return errors.New("isolated participation WAL requires Linux")
}
func collectorOpenNoFollow(string, int, os.FileMode) (*os.File, error) {
	return nil, checkCollectorWALPlatform()
}
func collectorLockExclusive(*os.File) error { return checkCollectorWALPlatform() }
