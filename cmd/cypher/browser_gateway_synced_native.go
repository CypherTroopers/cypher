// SPDX-License-Identifier: GPL-3.0-or-later
//go:build linux && cypher_native_http3_hook

package main

import (
	"errors"
	"sync"

	"github.com/CypherTroopers/cypher-services/proof/browsernode/gateway"
	native "github.com/CypherTroopers/cypher-services/proof/browsernode/native-node"
	"github.com/cypherium/cypher/cmd/cypher/browserstartup"
	"github.com/cypherium/cypher/eth"
	"github.com/cypherium/cypher/ethdb"
)

var _ gateway.OwnedRawChainBackend = (*native.OwnedStore)(nil)

// The optional CLI binding uses only a capability-bearing owned HOT KV source.
// The codec argument remains for source compatibility with the original
// preparation hook; native cached typed getters are never selected here.
// Construction and capability validation perform no DB payload read, opening
// a snapshot, RPC/IPC, listener or shared backend lifecycle operation.
func configureSyncedBrowserGateway(g *browserGatewayStartup, config gateway.Config, stateRoot string, trust, genesis []byte, _ gateway.BoundedSyncedChainCodec, limits gateway.SyncedChainLimits) error {
	if g == nil || config.SourceMode != gateway.SourceSyncedChain || config.Role == "relay" {
		return errors.New("explicit dormant owned synced-chain source startup required")
	}
	if err := config.Validate(); err != nil {
		return err
	}
	if err := config.ValidateAnchors(trust, genesis); err != nil {
		return err
	}
	caps := ethdb.DefaultBrowserSnapshotLimits()
	if limits.MaxOutputBytes < caps.MaxValueBytes {
		caps.MaxValueBytes = limits.MaxOutputBytes
	}
	if limits.MaxTotalBytes < caps.MaxReturnedBytes {
		caps.MaxReturnedBytes = limits.MaxTotalBytes
	}
	if err := caps.Validate(); err != nil {
		return errors.New("owned synced-chain payload limits invalid")
	}
	var mu sync.Mutex
	bound := false
	g.factory = func() (browserstartup.Resource, error) {
		return browserstartup.Resource{}, errors.New("owned synced-chain storage not bound")
	}
	g.bindBackend = func(backend *eth.EthAPIBackend) error {
		mu.Lock()
		defer mu.Unlock()
		if bound {
			return errors.New("owned synced-chain storage already bound")
		}
		if backend == nil {
			return errors.New("native backend required")
		}
		// ChainDb returns the existing DB reference; only a dormant owned view
		// is created below. Stock/untagged drivers fail before their first Get.
		db := backend.ChainDb()
		check, err := native.NewOwnedStore(db, caps)
		if err != nil {
			return errors.New("strict owned synced-chain storage unavailable")
		}
		if err = check.Close(); err != nil {
			return errors.New("owned storage capability cleanup failed")
		}
		create := func() (any, func() error, error) {
			lease, err := native.NewOwnedStore(db, caps)
			if err != nil {
				return nil, nil, err
			}
			return lease, lease.Close, nil
		}
		g.factory = func() (browserstartup.Resource, error) {
			owned, err := gateway.NewFromOwnedSyncedChain(config, stateRoot, trust, genesis, create, limits)
			if err != nil {
				return browserstartup.Resource{}, errors.New("owned synced-chain resource initialization failed")
			}
			return browserstartup.Resource{Handler: owned.Handler, Close: owned.Close}, nil
		}
		bound = true
		return nil
	}
	return nil
}
