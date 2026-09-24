//go:build !linux
// +build !linux

package source

import (
	"errors"
	"os"
)

func checkPlatform() error                                    { return errors.New("source durable lock unsupported on this platform") }
func openNoFollow(string, int, os.FileMode) (*os.File, error) { return nil, checkPlatform() }
func lockFile(*os.File) error                                 { return checkPlatform() }
func ownedSingleLink(os.FileInfo) bool                        { return false }
