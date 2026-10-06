//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows

package main

import (
	"errors"
	"net"
)

var errPublicRelayPlatform = errors.New("browser relay local transport is unsupported on this platform")

func resolvePublicRelaySocketPath(string, string) (string, error) { return "", errPublicRelayPlatform }

func validatePublicRelaySocketPath(string) error           { return errPublicRelayPlatform }
func listenPublicRelaySocket(string) (net.Listener, error) { return nil, errPublicRelayPlatform }
func readPublicRelayFile(string, bool) ([]byte, error)     { return nil, errPublicRelayPlatform }
