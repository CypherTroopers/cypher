//go:build !linux

package main

import (
	"errors"
	"os"
)

func relayOwned(os.FileInfo) bool { return false }
func relayNoFollow(string, int, os.FileMode) (*os.File, error) {
	return nil, errors.New("isolated relay CLI requires Linux")
}
func relaySyncDir(string) error { return errors.New("isolated relay CLI requires Linux") }
func prepareRelayCLIRoot(string) (*os.File, error) {
	return nil, errors.New("isolated relay CLI requires Linux")
}

func relayTemporaryOwned(os.FileInfo) bool { return false }
