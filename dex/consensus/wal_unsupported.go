//go:build !linux
// +build !linux

package consensus

import (
	"errors"
	"os"
)

// The isolated fixture's lock and fsync behavior has only been implemented for
// Linux. Other platforms compile, but opening the DEX fails before file writes.
func checkWALPlatform() error                                 { return errors.New("isolated DEX devnet WAL requires Linux") }
func openNoFollow(string, int, os.FileMode) (*os.File, error) { return nil, checkWALPlatform() }
func lockExclusive(*os.File) error                            { return checkWALPlatform() }
