//go:build !linux

package finance

import (
	"errors"
	"os"
)

func poolPlatform() error                                     { return errors.New("financial pool requires Linux") }
func poolNoFollow(string, int, os.FileMode) (*os.File, error) { return nil, poolPlatform() }
func poolLock(*os.File) error                                 { return poolPlatform() }
