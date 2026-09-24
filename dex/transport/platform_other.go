//go:build !linux

package transport

import (
	"errors"
	"os"
)

func platform() error                                     { return errors.New("DEX socket outbox requires Linux") }
func noFollow(string, int, os.FileMode) (*os.File, error) { return nil, platform() }
func lockFile(*os.File) error                             { return platform() }
