// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !linux || !cypher_native_http3_hook

package main

import (
	"errors"
	"github.com/cypherium/cypher/cmd/cypher/browserstartup"
)

func newNativeBrowserGatewayStartup(browserstartup.Options, *gethConfig) (*browserGatewayStartup, error) {
	return nil, errors.New("browser gateway requires a Linux build with cypher_native_http3_hook; default builds remain disabled")
}

func resolveBrowserDirectory(string) (string, error) {
	return "", errors.New("browser gateway metadata resolver is unavailable in a disabled build")
}
