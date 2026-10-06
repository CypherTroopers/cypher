// SPDX-License-Identifier: LGPL-3.0-or-later
package lightnode

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/rlp"
)

const NativeMaxHeaderBytes = 8 << 10
const nativeMaxConfigBytes = 128 << 10
const nativeMaxSafeInteger uint64 = 9007199254740991

// NativeFactory borrows the node's already owned ChainDb. Construction does no
// IO. An explicitly enabled startup readiness check or an admitted pull/forward
// creates a fresh owned HOT KV snapshot. A
// stock driver, missing frozen genesis/config, or unsupported recent metadata
// fails closed; no second DB, Get, Ancient, cached chain pointer or RPC fallback.
func NativeFactory(db ethdb.Database) Factory {
	return func(ctx context.Context) (View, error) {
		lease, err := rawdb.OpenBrowserRecentStoreLease(ctx, db, nativeSnapshotLimits())
		if err != nil {
			return nil, err
		}
		config, err := lease.ReadChainConfigRaw(ctx)
		if err != nil {
			_ = lease.Close()
			return nil, err
		}
		chainID, err := nativeChainID(config.JSON)
		if err != nil {
			_ = lease.Close()
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			_ = lease.Close()
			return nil, err
		}
		return &nativeView{lease: lease, network: Network{ChainID: chainID, GenesisHash: config.GenesisHash.Hex()}}, nil
	}
}

func nativeSnapshotLimits() ethdb.BrowserSnapshotLimits {
	return ethdb.BrowserSnapshotLimits{
		MaxStoredBytes: 8 << 20, MaxDecodedBytes: 8 << 20,
		MaxValueBytes: nativeMaxConfigBytes, MaxReturnedBytes: 512 << 10,
		MaxAllocationBytes: 16 << 20, MaxKeyBytes: 512,
		MaxWork: 65536, MaxRecordReads: 128,
	}
}

type nativeView struct {
	lease     *rawdb.BrowserStoreLease
	network   Network
	mu        sync.Mutex
	headKnown bool
	head      uint64
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

func (v *nativeView) Network() Network { return v.network }
func (v *nativeView) Close() error {
	v.closeOnce.Do(func() { v.closed.Store(true); v.closeErr = v.lease.Close() })
	return v.closeErr
}
func (v *nativeView) check(ctx context.Context) error {
	if ctx == nil {
		return ethdb.ErrBrowserSnapshotMalformed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.closed.Load() {
		return ethdb.ErrBrowserSnapshotClosed
	}
	return nil
}
func (v *nativeView) headLocked(ctx context.Context) (uint64, error) {
	if err := v.check(ctx); err != nil {
		return 0, err
	}
	if !v.headKnown {
		head, err := v.lease.ReadRecentHead(ctx)
		if err != nil {
			_ = v.Close()
			return 0, err
		}
		if head.Number > nativeMaxSafeInteger {
			_ = v.Close()
			return 0, ethdb.ErrBrowserSnapshotLimit
		}
		if err := v.check(ctx); err != nil {
			return 0, err
		}
		v.head, v.headKnown = head.Number, true
	}
	return v.head, nil
}
func (v *nativeView) LatestHeight(ctx context.Context) (uint64, error) {
	if err := v.check(ctx); err != nil {
		return 0, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.headLocked(ctx)
}
func (v *nativeView) HeaderRLP(ctx context.Context, height uint64, maxBytes int) ([]byte, error) {
	if err := v.check(ctx); err != nil {
		return nil, err
	}
	if maxBytes <= 0 || maxBytes > NativeMaxHeaderBytes {
		return nil, ethdb.ErrBrowserSnapshotLimit
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	head, err := v.headLocked(ctx)
	if err != nil {
		return nil, err
	}
	// Genesis is metadata only, never a relay packet. Subtraction follows the
	// <= comparison, so max-uint64 and a short initial chain cannot underflow.
	if height == 0 || height > head || head-height >= 32 {
		return nil, ethdb.ErrBrowserSnapshotMissing
	}
	header, err := v.lease.ReadHeaderRawBounded(ctx, height, int64(maxBytes))
	if err != nil {
		_ = v.Close()
		return nil, err
	}
	// Decoding is separately bounded by the complete <=8KiB input. Driver
	// allocation accounting does not claim to charge this Go Header object.
	var decoded types.Header
	if err := rlp.DecodeBytes(header.HeaderRLP, &decoded); err != nil {
		_ = v.Close()
		return nil, ethdb.ErrBrowserSnapshotMalformed
	}
	if decoded.Number == nil || decoded.Number.Sign() < 0 || decoded.Number.BitLen() > 53 || decoded.Number.Uint64() != height || decoded.Hash() != header.CanonicalHash {
		_ = v.Close()
		return nil, ethdb.ErrBrowserSnapshotInconsistent
	}
	if err := v.check(ctx); err != nil {
		return nil, err
	}
	// These are the driver-owned complete stored bytes, including SignInfo/QC.
	// Header.Hash deliberately omits that metadata; do not strip or re-encode.
	return header.HeaderRLP, nil
}

// Decode only the bounded chainId scalar from the owned config. Other native
// configuration fields remain opaque. Duplicate keys, exponent/string/negative
// IDs, trailing data and IDs outside uint64 fail closed instead of coercing.
func nativeChainID(raw []byte) (uint64, error) {
	if len(raw) == 0 || len(raw) > nativeMaxConfigBytes {
		return 0, ethdb.ErrBrowserSnapshotLimit
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return 0, ethdb.ErrBrowserSnapshotMalformed
	}
	seen := make(map[string]bool)
	var chainID uint64
	found := false
	for d.More() {
		if len(seen) >= 512 {
			return 0, ethdb.ErrBrowserSnapshotLimit
		}
		keyToken, err := d.Token()
		if err != nil {
			return 0, ethdb.ErrBrowserSnapshotMalformed
		}
		key, ok := keyToken.(string)
		if !ok || seen[key] {
			return 0, ethdb.ErrBrowserSnapshotMalformed
		}
		seen[key] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return 0, ethdb.ErrBrowserSnapshotMalformed
		}
		if key == "chainId" {
			text := string(bytes.TrimSpace(value))
			if text == "" || text[0] < '0' || text[0] > '9' {
				return 0, ethdb.ErrBrowserSnapshotMalformed
			}
			chainID, err = strconv.ParseUint(text, 10, 64)
			if err != nil || chainID == 0 || chainID > nativeMaxSafeInteger {
				return 0, ethdb.ErrBrowserSnapshotMalformed
			}
			found = true
		}
	}
	if tok, err := d.Token(); err != nil || tok != json.Delim('}') {
		return 0, ethdb.ErrBrowserSnapshotMalformed
	}
	var extra json.RawMessage
	if err := d.Decode(&extra); err != io.EOF || !found {
		return 0, ethdb.ErrBrowserSnapshotMalformed
	}
	return chainID, nil
}
