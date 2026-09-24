//go:build !linux

package consensus

import "os"

func ownedWALDirectory(os.FileInfo) bool { return false }
func ownedWALTemporary(os.FileInfo) bool { return false }
