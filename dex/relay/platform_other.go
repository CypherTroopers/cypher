//go:build !linux

package relay

import (
	"errors"
	"os"
)

func platform() error                                     { return errors.New("durable devnet relay requires Linux") }
func noFollow(string, int, os.FileMode) (*os.File, error) { return nil, platform() }
func lockFile(*os.File) error                             { return platform() }

func ownedTemporary(os.FileInfo) bool { return false }
