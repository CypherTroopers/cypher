//go:build !linux

package testnet

import (
	"errors"
	"os"
)

func platform() error                                     { return errors.New("financial process test requires Linux isolation") }
func noFollow(string, int, os.FileMode) (*os.File, error) { return nil, platform() }
func lockFile(*os.File) error                             { return platform() }
