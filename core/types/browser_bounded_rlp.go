// Copyright 2026 Cypher browser contributors.
// SPDX-License-Identifier: LGPL-3.0-or-later

package types

import (
	"context"
	"errors"
	"io"
	"math/big"

	"github.com/cypherium/cypher/common"
	kzg4844 "github.com/cypherium/cypher/crypto/kzg4844"
	"github.com/cypherium/cypher/params"
)

var (
	ErrBrowserBlockLimit       = errors.New("browser block encoding budget exceeded")
	ErrBrowserBlockShape       = errors.New("malformed browser block encoding input")
	ErrBrowserBlockUnsupported = errors.New("unsupported browser block encoding schema")
)

// BrowserBlockEncodingLimits are reader admission limits, not consensus rules.
// Zero selects the defaults. Nonzero limits may only tighten the defaults.
// MaxElements counts every RLP node, including fixed fields and typed-envelope
// payload nodes. The payload of a byte string is never traversed as RLP.
type BrowserBlockEncodingLimits struct {
	MaxEncodedBytes uint64
	MaxFieldBytes   uint64
	MaxElements     uint64
}

func DefaultBrowserBlockEncodingLimits() BrowserBlockEncodingLimits {
	return BrowserBlockEncodingLimits{32 << 20, 32 << 20, 65536}
}

func browserEncodingLimits(l BrowserBlockEncodingLimits) (BrowserBlockEncodingLimits, error) {
	d := DefaultBrowserBlockEncodingLimits()
	if l.MaxEncodedBytes == 0 {
		l.MaxEncodedBytes = d.MaxEncodedBytes
	}
	if l.MaxFieldBytes == 0 {
		l.MaxFieldBytes = d.MaxFieldBytes
	}
	if l.MaxElements == 0 {
		l.MaxElements = d.MaxElements
	}
	if l.MaxEncodedBytes > d.MaxEncodedBytes || l.MaxFieldBytes > d.MaxFieldBytes || l.MaxElements > d.MaxElements {
		return l, ErrBrowserBlockLimit
	}
	return l, nil
}

// BrowserBlockRLPSize validates the complete known block shape and returns its
// exact canonical encoding size without copying payloads or using cached hashes.
// All backing values must remain immutable until EncodeBrowserRLP returns.
// The shape pass precedes commitment hashing and any output write. This does not
// authenticate committee/QC/finality, execute transactions, or validate rewards.
func (b *Block) BrowserBlockRLPSize(ctx context.Context, limits BrowserBlockEncodingLimits) (uint64, error) {
	if ctx == nil {
		return 0, ErrBrowserBlockShape
	}
	l, err := browserEncodingLimits(limits)
	if err != nil {
		return 0, err
	}
	m := browserRLP{ctx: ctx, limits: l}
	m.block(b)
	if m.err != nil {
		return 0, m.err
	}
	if err := b.browserBlobBindings(ctx); err != nil {
		return 0, err
	}
	return m.size, nil
}

// EncodeBrowserRLP streams the exact external Block.EncodeRLP schema only after
// a complete admission pass. It deliberately does not call generic rlp.Encode,
// MarshalBinary, defensive-copy accessors, or allocate a full encoding buffer.
// Lists are measured synchronously before their prefix is written. At the fixed
// schema depth (at most 9), that costs O(depth * nodes), not unbounded recursion.
// Bytes are written in <=32KiB chunks with context checks; integers use a fixed
// 32-byte scratch area. The writer's own storage is outside this helper's bound.
// A failed/cancelled write may leave a partial encoding; callers must discard it.
func (b *Block) EncodeBrowserRLP(ctx context.Context, w io.Writer, limits BrowserBlockEncodingLimits) error {
	if w == nil {
		return ErrBrowserBlockShape
	}
	expected, err := b.BrowserBlockRLPSize(ctx, limits)
	if err != nil {
		return err
	}
	l, _ := browserEncodingLimits(limits)
	m := browserRLP{ctx: ctx, limits: l, w: w}
	m.block(b)
	if m.err != nil {
		return m.err
	}
	if m.size != expected {
		return ErrBrowserBlockShape
	}
	return ctx.Err()
}

// Only fixed schema nesting is supported. No reflection, unsafe, interface
// serializer dispatch, shared pool, or per-element metadata tree is used.
const browserRLPMaxDepth = 9
const browserRLPWriteChunk = 32768

type browserRLP struct {
	ctx         context.Context
	limits      BrowserBlockEncodingLimits
	w           io.Writer
	size, nodes uint64
	depth       uint8
	err         error
}

func (m *browserRLP) check() bool {
	if m.err == nil {
		m.err = m.ctx.Err()
	}
	return m.err == nil
}

func (m *browserRLP) add(size, nodes uint64) bool {
	if !m.check() {
		return false
	}
	if size > m.limits.MaxEncodedBytes-m.size || nodes > m.limits.MaxElements-m.nodes {
		m.err = ErrBrowserBlockLimit
		return false
	}
	m.size += size
	m.nodes += nodes
	return true
}

func (m *browserRLP) count(n int) bool {
	if !m.check() {
		return false
	}
	if uint64(n) > m.limits.MaxElements {
		m.err = ErrBrowserBlockLimit
		return false
	}
	return true
}

func browserRLPPrefix(buf *[9]byte, n uint64, list bool) []byte {
	small, large := byte(0x80), byte(0xb7)
	if list {
		small, large = 0xc0, 0xf7
	}
	if n < 56 {
		buf[0] = small + byte(n)
		return buf[:1]
	}
	width := 0
	for v := n; v > 0; v >>= 8 {
		width++
	}
	buf[0] = large + byte(width)
	for i := width; i > 0; i-- {
		buf[i] = byte(n)
		n >>= 8
	}
	return buf[:width+1]
}

func (m *browserRLP) write(data []byte) {
	if m.w == nil || !m.check() {
		return
	}
	for len(data) > 0 && m.check() {
		chunk := data
		if len(chunk) > browserRLPWriteChunk {
			chunk = chunk[:browserRLPWriteChunk]
		}
		n, err := m.w.Write(chunk)
		if err != nil {
			m.err = err
			return
		}
		if n != len(chunk) {
			m.err = io.ErrShortWrite
			return
		}
		data = data[n:]
	}
}

func (m *browserRLP) bytes(data []byte) {
	if !m.check() {
		return
	}
	n := uint64(len(data))
	if n > m.limits.MaxFieldBytes {
		m.err = ErrBrowserBlockLimit
		return
	}
	if len(data) == 1 && data[0] < 0x80 {
		if m.add(1, 1) {
			m.write(data)
		}
		return
	}
	var prefix [9]byte
	p := browserRLPPrefix(&prefix, n, false)
	if m.add(n+uint64(len(p)), 1) {
		m.write(p)
		m.write(data)
	}
}

func (m *browserRLP) text(data string) {
	if !m.check() {
		return
	}
	n := uint64(len(data))
	if n > m.limits.MaxFieldBytes {
		m.err = ErrBrowserBlockLimit
		return
	}
	var prefix [9]byte
	p := browserRLPPrefix(&prefix, n, false)
	if len(data) == 1 && data[0] < 0x80 {
		p = nil
	}
	if !m.add(n+uint64(len(p)), 1) {
		return
	}
	m.write(p)
	if m.w == nil {
		return
	}
	// A string-to-byte conversion of the whole untrusted leader ID is avoided.
	var scratch [256]byte
	for len(data) > 0 && m.check() {
		n := len(data)
		if n > len(scratch) {
			n = len(scratch)
		}
		copy(scratch[:n], data[:n])
		m.write(scratch[:n])
		data = data[n:]
	}
}

func (m *browserRLP) uint(v uint64) {
	if !m.check() {
		return
	}
	if m.w == nil {
		payload := uint64(0)
		for x := v; x > 0; x >>= 8 {
			payload++
		}
		if payload > m.limits.MaxFieldBytes {
			m.err = ErrBrowserBlockLimit
			return
		}
		encoded := uint64(1)
		if v >= 128 {
			encoded = payload + 1
		}
		m.add(encoded, 1)
		return
	}
	if v == 0 {
		m.bytes(nil)
		return
	}
	var buf [8]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte(v)
		v >>= 8
	}
	m.bytes(buf[i:])
}

func (m *browserRLP) integer(v *big.Int, maxBits int) {
	if !m.check() {
		return
	}
	if v == nil {
		m.bytes(nil)
		return
	}
	if v.Sign() < 0 || v.BitLen() > maxBits {
		m.err = ErrBrowserBlockShape
		return
	}
	if m.w == nil {
		n := uint64((v.BitLen() + 7) / 8)
		if n > m.limits.MaxFieldBytes {
			m.err = ErrBrowserBlockLimit
			return
		}
		if v.BitLen() <= 7 {
			m.add(1, 1)
			return
		}
		var prefix [9]byte
		m.add(n+uint64(len(browserRLPPrefix(&prefix, n, false))), 1)
		return
	}
	var buf [32]byte
	n := (v.BitLen() + 7) / 8
	v.FillBytes(buf[:n])
	m.bytes(buf[:n])
}

func (m *browserRLP) address(v *common.Address) {
	if v == nil {
		m.bytes(nil)
		return
	}
	m.bytes(v[:])
}

func (m *browserRLP) list(f func(*browserRLP)) {
	if !m.check() {
		return
	}
	if m.depth >= browserRLPMaxDepth {
		m.err = ErrBrowserBlockUnsupported
		return
	}
	measured := browserRLP{ctx: m.ctx, limits: m.limits, depth: m.depth + 1}
	f(&measured)
	if measured.err != nil {
		m.err = measured.err
		return
	}
	var prefix [9]byte
	p := browserRLPPrefix(&prefix, measured.size, true)
	if !m.add(measured.size+uint64(len(p)), measured.nodes+1) {
		return
	}
	if m.w == nil {
		return
	}
	m.write(p)
	if m.err != nil {
		return
	}
	emitted := browserRLP{ctx: m.ctx, limits: m.limits, depth: m.depth + 1, w: m.w}
	f(&emitted)
	if emitted.err != nil {
		m.err = emitted.err
		return
	}
	if emitted.size != measured.size || emitted.nodes != measured.nodes {
		m.err = ErrBrowserBlockShape
	}
}

func (m *browserRLP) hashes(hashes []common.Hash) {
	if !m.count(len(hashes)) {
		return
	}
	m.list(func(c *browserRLP) {
		for i := range hashes {
			if !c.check() {
				return
			}
			c.bytes(hashes[i][:])
		}
	})
}

func (m *browserRLP) accessList(access AccessList) {
	if !m.count(len(access)) {
		return
	}
	m.list(func(c *browserRLP) {
		for i := range access {
			if !c.check() {
				return
			}
			a := &access[i]
			c.list(func(v *browserRLP) { v.bytes(a.Address[:]); v.hashes(a.StorageKeys) })
		}
	})
}

func (m *browserRLP) authorizations(auth []SetCodeAuthorization) {
	if !m.count(len(auth)) {
		return
	}
	m.list(func(c *browserRLP) {
		for i := range auth {
			if !c.check() {
				return
			}
			a := &auth[i]
			c.list(func(v *browserRLP) {
				v.integer(a.ChainID, 256)
				v.bytes(a.Address[:])
				v.uint(a.Nonce)
				v.integer(a.V, 8)
				v.integer(a.R, 256)
				v.integer(a.S, 256)
			})
		}
	})
}

func (m *browserRLP) signature(s *SignInfo) {
	m.list(func(c *browserRLP) {
		c.bytes(s.Signature)
		c.bytes(s.Exceptions)
		c.bytes(s.ViewID[:])
		c.text(s.LeaderID)
		c.uint(s.ViewNumber)
		c.bytes(s.ExtraHash[:])
		c.bytes(s.ParentQCID[:])
		c.bytes(s.FHSFinalityProof)
	})
}

func (m *browserRLP) header(h *Header) {
	if !m.check() {
		return
	}
	if h == nil {
		m.err = ErrBrowserBlockShape
		return
	}
	m.list(func(c *browserRLP) {
		c.bytes(h.ParentHash[:])
		c.bytes(h.UncleHash[:])
		c.bytes(h.Coinbase[:])
		c.bytes(h.Root[:])
		c.bytes(h.TxHash[:])
		c.bytes(h.ReceiptHash[:])
		c.bytes(h.Bloom[:])
		c.integer(h.Difficulty, 256)
		c.integer(h.Number, 256)
		c.uint(h.GasLimit)
		c.uint(h.GasUsed)
		c.uint(h.Time)
		c.bytes(h.Extra)
		c.bytes(h.MixDigest[:])
		c.bytes(h.Nonce[:])
		c.integer(h.BaseFee, 256)
		c.bytes(h.WithdrawalsHash[:])
		c.uint(h.BlobGasUsed)
		c.uint(h.ExcessBlobGas)
		c.bytes(h.ParentBeaconRoot[:])
		c.bytes(h.RequestsHash[:])
		c.bytes(h.CommonTxAdmissionRoot[:])
		c.bytes(h.CommonTxRewardRoot[:])
		c.uint(uint64(h.BlockType))
		c.bytes(h.KeyHash[:])
		c.bytes(h.KeyInfo)
		c.signature(&h.SignInfo)
	})
}

// A typed envelope is one RLP byte string containing type||rlp(inner), NOT a
// pooled blob wrapper. Sidecar data is encoded in the separate body component.
func (m *browserRLP) typed(typ byte, f func(*browserRLP)) {
	if !m.check() {
		return
	}
	inner := browserRLP{ctx: m.ctx, limits: m.limits, depth: m.depth + 1}
	inner.list(f)
	if inner.err != nil {
		m.err = inner.err
		return
	}
	n := inner.size + 1
	if n > m.limits.MaxFieldBytes {
		m.err = ErrBrowserBlockLimit
		return
	}
	var prefix [9]byte
	p := browserRLPPrefix(&prefix, n, false)
	// Charge the otherwise opaque inner nodes to bound encoder work.
	if !m.add(n+uint64(len(p)), inner.nodes+1) {
		return
	}
	if m.w == nil {
		return
	}
	m.write(p)
	m.write([]byte{typ})
	if m.err != nil {
		return
	}
	encoded := browserRLP{ctx: m.ctx, limits: m.limits, depth: m.depth + 1, w: m.w}
	encoded.list(f)
	if encoded.err != nil {
		m.err = encoded.err
		return
	}
	if encoded.size != inner.size || encoded.nodes != inner.nodes {
		m.err = ErrBrowserBlockShape
	}
}

func (m *browserRLP) transaction(tx *Transaction) {
	if !m.check() {
		return
	}
	if tx == nil || tx.data == nil {
		m.err = ErrBrowserBlockShape
		return
	}
	switch t := tx.data.(type) {
	case *txdata:
		if t == nil {
			m.err = ErrBrowserBlockShape
			return
		}
		m.list(func(c *browserRLP) {
			c.uint(t.AccountNonce)
			c.integer(t.Price, 256)
			c.uint(t.GasLimit)
			c.address(t.Recipient)
			c.integer(t.Amount, 256)
			c.bytes(t.Payload)
			c.integer(t.V, 256)
			c.integer(t.R, 256)
			c.integer(t.S, 256)
		})
	case *AccessListTx:
		if t == nil {
			m.err = ErrBrowserBlockShape
			return
		}
		m.typed(AccessListTxType, func(c *browserRLP) {
			c.integer(t.ChainID, 256)
			c.uint(t.Nonce)
			c.integer(t.GasPrice, 256)
			c.uint(t.Gas)
			c.address(t.To)
			c.integer(t.Value, 256)
			c.bytes(t.Data)
			c.accessList(t.AccessList)
			c.integer(t.V, 256)
			c.integer(t.R, 256)
			c.integer(t.S, 256)
		})
	case *DynamicFeeTx:
		if t == nil {
			m.err = ErrBrowserBlockShape
			return
		}
		m.typed(DynamicFeeTxType, func(c *browserRLP) {
			c.integer(t.ChainID, 256)
			c.uint(t.Nonce)
			c.integer(t.GasTipCap, 256)
			c.integer(t.GasFeeCap, 256)
			c.uint(t.Gas)
			c.address(t.To)
			c.integer(t.Value, 256)
			c.bytes(t.Data)
			c.accessList(t.AccessList)
			c.integer(t.V, 256)
			c.integer(t.R, 256)
			c.integer(t.S, 256)
		})
	case *BlobTx:
		if t == nil {
			m.err = ErrBrowserBlockShape
			return
		}
		m.typed(BlobTxType, func(c *browserRLP) {
			c.integer(t.ChainID, 256)
			c.uint(t.Nonce)
			c.integer(t.GasTipCap, 256)
			c.integer(t.GasFeeCap, 256)
			c.uint(t.Gas)
			c.bytes(t.To[:])
			c.integer(t.Value, 256)
			c.bytes(t.Data)
			c.accessList(t.AccessList)
			c.integer(t.BlobFeeCap, 256)
			c.hashes(t.BlobHashes)
			c.integer(t.V, 256)
			c.integer(t.R, 256)
			c.integer(t.S, 256)
		})
	case *SetCodeTx:
		if t == nil {
			m.err = ErrBrowserBlockShape
			return
		}
		m.typed(SetCodeTxType, func(c *browserRLP) {
			c.integer(t.ChainID, 256)
			c.uint(t.Nonce)
			c.integer(t.GasTipCap, 256)
			c.integer(t.GasFeeCap, 256)
			c.uint(t.Gas)
			c.bytes(t.To[:])
			c.integer(t.Value, 256)
			c.bytes(t.Data)
			c.accessList(t.AccessList)
			c.authorizations(t.AuthList)
			c.integer(t.V, 256)
			c.integer(t.R, 256)
			c.integer(t.S, 256)
		})
	default:
		// NativeTxV1/type-5 is retired by the pinned public decoder. This is a
		// reader capability limit, not proof that a historical chain is invalid.
		m.err = ErrBrowserBlockUnsupported
	}
}

func (m *browserRLP) sidecar(s *BlobTxSidecar) {
	if !m.check() {
		return
	}
	if s == nil {
		m.err = ErrBrowserBlockShape
		return
	}
	if s.Version != BlobSidecarVersion0 && s.Version != BlobSidecarVersion1 {
		m.err = ErrBrowserBlockUnsupported
		return
	}
	if !m.count(len(s.Blobs)) || !m.count(len(s.Commitments)) || !m.count(len(s.Proofs)) {
		return
	}
	if len(s.Blobs) != len(s.Commitments) {
		m.err = ErrBrowserBlockShape
		return
	}
	proofs := uint64(len(s.Blobs))
	if s.Version == BlobSidecarVersion1 {
		if len(s.Blobs) > params.BlobTxMaxBlobs {
			m.err = ErrBrowserBlockShape
			return
		}
		proofs *= BlobCellProofsPerBlob
	}
	if uint64(len(s.Proofs)) != proofs {
		m.err = ErrBrowserBlockShape
		return
	}
	m.list(func(c *browserRLP) {
		c.uint(uint64(s.Version))
		c.list(func(v *browserRLP) {
			for _, b := range s.Blobs {
				if !v.check() {
					return
				}
				if len(b) != len(kzg4844.Blob{}) {
					v.err = ErrBrowserBlockShape
					return
				}
				v.bytes(b)
			}
		})
		c.list(func(v *browserRLP) {
			for i := range s.Commitments {
				if !v.check() {
					return
				}
				v.bytes(s.Commitments[i][:])
			}
		})
		c.list(func(v *browserRLP) {
			for i := range s.Proofs {
				if !v.check() {
					return
				}
				v.bytes(s.Proofs[i][:])
			}
		})
	})
}

func (m *browserRLP) admission(a *CommonTxAdmissionBatch) {
	if !m.check() {
		return
	}
	if a == nil {
		m.err = ErrBrowserBlockShape
		return
	}
	if a.Version != CommonRPCVersionV2 {
		m.err = ErrBrowserBlockUnsupported
		return
	}
	if a.ValidateVersion() != nil {
		m.err = ErrBrowserBlockShape
		return
	}
	m.list(func(c *browserRLP) {
		c.uint(uint64(a.Version))
		c.integer(a.ChainID, 256)
		c.bytes(a.GenesisHash[:])
		c.bytes(a.TxRoot[:])
		c.bytes(a.AdmissionID[:])
		c.bytes(a.Miner[:])
		c.bytes(a.RewardRecipient[:])
		c.uint(a.KeyBlockNumber)
		c.uint(a.Timestamp)
		c.hashes(a.TxHashes)
		c.bytes(a.Signature)
	})
}

func (m *browserRLP) reward(r *CommonTxReward) {
	if !m.check() {
		return
	}
	if r == nil {
		m.err = ErrBrowserBlockShape
		return
	}
	if r.Version != CommonRPCVersionV2 {
		m.err = ErrBrowserBlockUnsupported
		return
	}
	if r.ValidateVersion() != nil {
		m.err = ErrBrowserBlockShape
		return
	}
	m.list(func(c *browserRLP) {
		c.uint(uint64(r.Version))
		c.bytes(r.TxHash[:])
		c.bytes(r.Approver[:])
		c.bytes(r.RewardRecipient[:])
		c.integer(r.ApproverReward, 256)
		c.integer(r.Burn, 256)
	})
}

func (m *browserRLP) block(b *Block) {
	if !m.check() {
		return
	}
	if b == nil {
		m.err = ErrBrowserBlockShape
		return
	}
	if !m.count(len(b.transactions)) || !m.count(len(b.blobSidecars)) || !m.count(len(b.uncles)) ||
		!m.count(len(b.commonTxAdmissionBatches)) || !m.count(len(b.commonTxAdmissionRefs)) || !m.count(len(b.commonTxRewards)) {
		return
	}
	m.list(func(c *browserRLP) {
		c.header(b.header)
		c.list(func(v *browserRLP) {
			for _, tx := range b.transactions {
				if !v.check() {
					return
				}
				v.transaction(tx)
			}
		})
		c.list(func(v *browserRLP) {
			for _, s := range b.blobSidecars {
				if !v.check() {
					return
				}
				v.sidecar(s)
			}
		})
		c.list(func(v *browserRLP) {
			for _, h := range b.uncles {
				if !v.check() {
					return
				}
				v.header(h)
			}
		})
		c.list(func(v *browserRLP) {
			for _, a := range b.commonTxAdmissionBatches {
				if !v.check() {
					return
				}
				v.admission(a)
			}
		})
		c.list(func(v *browserRLP) {
			for i := range b.commonTxAdmissionRefs {
				if !v.check() {
					return
				}
				r := &b.commonTxAdmissionRefs[i]
				v.list(func(e *browserRLP) { e.uint(uint64(r.Batch)); e.uint(uint64(r.Item)) })
			}
		})
		c.list(func(v *browserRLP) {
			for _, r := range b.commonTxRewards {
				if !v.check() {
					return
				}
				v.reward(r)
			}
		})
	})
}

// Called only after the entire byte/count/shape pass has completed. Matching
// each 48-byte commitment uses fixed scratch; no BlobHashes/Copy accessor.
func (b *Block) browserBlobBindings(ctx context.Context) error {
	index := 0
	for _, tx := range b.transactions {
		if err := ctx.Err(); err != nil {
			return err
		}
		inner, ok := tx.data.(*BlobTx)
		if !ok {
			continue
		}
		if index >= len(b.blobSidecars) {
			return ErrBrowserBlockShape
		}
		s := b.blobSidecars[index]
		if len(inner.BlobHashes) != len(s.Commitments) {
			return ErrBrowserBlockShape
		}
		for i := range inner.BlobHashes {
			if err := ctx.Err(); err != nil {
				return err
			}
			if KZGToVersionedHash(s.Commitments[i]) != inner.BlobHashes[i] {
				return ErrBrowserBlockShape
			}
		}
		index++
	}
	if index != len(b.blobSidecars) {
		return ErrBrowserBlockShape
	}
	return nil
}
