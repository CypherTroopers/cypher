// SPDX-License-Identifier: GPL-3.0-or-later
//go:build linux && cypher_native_http3_hook

package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/CypherTroopers/cypher-services/proof/browsernode/gateway"
	"github.com/CypherTroopers/cypher-services/proof/browsernode/gateway/discovery"
	"github.com/CypherTroopers/cypher-services/proof/browsernode/gateway/tlsowner"
	nativehttp3 "github.com/CypherTroopers/cypher-services/proof/browsernode/native-node"
	"github.com/cypherium/cypher/cmd/cypher/browserstartup"
	"github.com/cypherium/cypher/node"
)

func resolveBrowserDirectory(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(real)
	if err != nil || !info.IsDir() {
		return "", errors.New("existing directory metadata required")
	}
	return real, nil
}

func readBrowserPublicFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("public proof file must be a bounded regular nonsymlink file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("public proof file byte budget")
	}
	return raw, nil
}

func newNativeBrowserGatewayStartup(o browserstartup.Options, cfg *gethConfig) (*browserGatewayStartup, error) {
	raw, err := readBrowserPublicFile(o.ConfigPath, 1<<20)
	if err != nil {
		return nil, errors.New("public browser gateway configuration unavailable")
	}
	config, err := gateway.Decode(raw)
	if err != nil {
		return nil, errors.New("public browser gateway configuration rejected")
	}
	trust, err := readBrowserPublicFile(config.Trust.Path, 1<<20)
	if err != nil {
		return nil, errors.New("public proof trust anchor unavailable")
	}
	genesis, err := readBrowserPublicFile(config.Genesis.Path, 32<<20)
	if err != nil {
		return nil, errors.New("public proof genesis unavailable")
	}
	if err = config.ValidateAnchors(trust, genesis); err != nil {
		return nil, errors.New("public proof anchors rejected")
	}
	controller, err := browserstartup.New(o)
	if err != nil {
		return nil, err
	}
	g := &browserGatewayStartup{controller: controller, stateRoot: o.StateRoot}
	g.factory = func() (browserstartup.Resource, error) {
		owned, err := gateway.New(config, o.StateRoot, trust, genesis)
		if err != nil {
			return browserstartup.Resource{}, errors.New("browser gateway owned resource initialization failed")
		}
		return browserstartup.Resource{Handler: owned.Handler, Close: owned.Close}, nil
	}
	if config.SourceMode == gateway.SourceSyncedChain {
		codec, err := gateway.NewNativeSyncedChainCodec(gateway.DefaultNativeSyncedChainCodecLimits())
		if err == nil {
			err = configureSyncedBrowserGateway(g, config, o.StateRoot, trust, genesis, codec, gateway.DefaultSyncedChainLimits())
		}
		if err != nil {
			_ = g.Close()
			return nil, errors.New("explicit synced-chain source preparation rejected")
		}
	}
	g.checkMount = func(final *gethConfig) error {
		q := final.Eth.TxQUIC
		// Reuse only the explicitly configured existing native TLS selection.
		// Do not read credentials, create certificates or install trust here.
		if q.HTTP3CertFile == "" || q.HTTP3KeyFile == "" || q.HTTP3CertFile != config.TLSCert || q.HTTP3KeyFile != config.TLSKey {
			return errors.New("proof config must reference the existing explicit HTTP/3 certificate and key")
		}
		u, _ := url.Parse(config.PublicOrigin)
		port := u.Port()
		if port == "" {
			port = "443"
		}
		if port != strconv.Itoa(q.HTTP3Port) {
			return errors.New("proof public origin must use the existing HTTP/3 port")
		}
		_, listenPort, err := net.SplitHostPort(config.Listen)
		if err != nil || listenPort != port {
			return errors.New("proof metadata listen port must match the existing HTTP/3 port")
		}
		// Proof origins remain exact: do not add a wildcard or silently add a
		// browser origin to the configured provider CORS allowlist.
		if o.TLS {
			nativeOrigin := false
			for _, origin := range config.AllowedOrigins {
				if origin == "chrome://cypher-node" {
					nativeOrigin = true
				}
			}
			if !nativeOrigin {
				return errors.New("explicit TLS frontdoor requires configured chrome://cypher-node origin")
			}
			if g.tls != nil {
				return errors.New("TLS lifecycle already prepared")
			}
			frontdoor := tlsowner.Config{
				Enabled: true, Listen: config.Listen, Identity: config.Peer.ID,
				TLS: tlsowner.TLSReferences{Certificate: config.TLSCert, Key: config.TLSKey},
				Discovery: discovery.Config{Enabled: true, PublicOrigin: config.PublicOrigin,
					AllowedOrigins: append([]string(nil), config.AllowedOrigins...),
					HTTP3Port:      q.HTTP3Port, MaxAgeSeconds: 60},
			}
			var err error
			g.tls, err = browserstartup.NewTLS(true, func(handler http.Handler) (browserstartup.TLSOwner, error) {
				// Adapter selection/New are pure. Real TCP/TLS execution occurs
				// only in explicit node lifecycle Start after source initialization.
				return tlsowner.New(&frontdoor, handler, tlsowner.StandardDependencies())
			})
			if err != nil {
				return err
			}
		}
		return nil
	}
	// Proof routes retain the existing vhost/compression stack but use their
	// strict provider CORS gate. RPC routes keep the unchanged legacy CORS stack.
	// If shared authentication is introduced, it must wrap this proof stack too.
	proofStack := func(handler http.Handler) http.Handler {
		vhosts := cfg.Node.HTTPVirtualHosts
		if len(vhosts) == 0 {
			vhosts = []string{"*"}
		}
		return node.NewHTTPHandlerStack(handler, nil, vhosts)
	}
	if err = nativehttp3.InstallWithProofStack(&cfg.Node, true, controller, proofStack); err != nil {
		_ = g.Close()
		return nil, errors.New("optional native HTTP/3 mount unavailable")
	}
	return g, nil
}
