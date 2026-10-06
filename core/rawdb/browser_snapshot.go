// SPDX-License-Identifier: LGPL-3.0-or-later
package rawdb

import (
	"context"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/ethdb"
	"reflect"
	"sync"
)

func browserNil(v interface{}) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return r.IsNil()
	}
	return false
}
func browserCapability(db interface{}) (ethdb.BrowserSnapshotter, error) {
	if browserNil(db) {
		return nil, ethdb.ErrBrowserSnapshotUnsupported
	}
	p, ok := db.(ethdb.BrowserSnapshotter)
	if !ok || browserNil(p) || p.BrowserSnapshotCapabilityVersion() != ethdb.BrowserSnapshotCapabilityV1 {
		return nil, ethdb.ErrBrowserSnapshotUnsupported
	}
	return p, nil
}

// BrowserStoreLease borrows a DB only to create an explicitly capable owned
// view. The finite-proof path opens inside a durable-reserved provider run,
// not ON/ctor. The optional recent path additionally permits an explicitly
// enabled bounded startup readiness check or an admitted source operation.
// There is no cache/native pointer/Get/Ancient/decode fallback. This guard does
// not supply the missing driver preallocation or whole-view guarantees.
type BrowserStoreLease struct {
	view                     ethdb.BrowserSnapshot
	id                       [32]byte
	limits                   ethdb.BrowserSnapshotLimits
	mu                       sync.Mutex
	closed, active, released bool
	cancel                   context.CancelFunc
	reads                    int
	retained                 bool
	returned                 int64
	closeErr                 error
	recent                   bool
}

func OpenBrowserStoreLease(ctx context.Context, db interface{}, limits ethdb.BrowserSnapshotLimits) (*BrowserStoreLease, error) {
	if browserNil(ctx) {
		return nil, ethdb.ErrBrowserSnapshotMalformed
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := limits.Validate(); e != nil {
		return nil, e
	}
	p, e := browserCapability(db)
	if e != nil {
		return nil, e
	}
	view, e := p.NewBrowserSnapshot(ctx, limits)
	if e != nil {
		if !browserNil(view) {
			_ = view.Close()
		}
		return nil, e
	}
	if browserNil(view) {
		return nil, ethdb.ErrBrowserSnapshotUnsupported
	}
	if e = ctx.Err(); e != nil {
		_ = view.Close()
		return nil, e
	}
	id := view.BrowserViewID()
	if id == ([32]byte{}) {
		_ = view.Close()
		return nil, ethdb.ErrBrowserSnapshotUnsupported
	}
	return &BrowserStoreLease{view: view, id: id, limits: limits}, nil
}
func (s *BrowserStoreLease) BrowserViewID() [32]byte { return s.id }
func (s *BrowserStoreLease) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	release := !s.active && !s.retained && !s.released
	if release {
		s.released = true
	}
	previous := s.closeErr
	s.mu.Unlock()
	if release {
		e := s.view.Close()
		s.mu.Lock()
		s.closeErr = e
		s.mu.Unlock()
		return e
	}
	return previous
}

// retain/unretain extend physical view ownership across the whole writer,
// including gaps between record reads and streaming of caller-owned bytes.
func (s *BrowserStoreLease) retain() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ethdb.ErrBrowserSnapshotClosed
	}
	if s.retained {
		return ethdb.ErrBrowserSnapshotLimit
	}
	s.retained = true
	return nil
}
func (s *BrowserStoreLease) unretain() {
	s.mu.Lock()
	s.retained = false
	release := s.closed && !s.active && !s.released
	if release {
		s.released = true
	}
	s.mu.Unlock()
	if release {
		e := s.view.Close()
		s.mu.Lock()
		s.closeErr = e
		s.mu.Unlock()
	}
}
func (s *BrowserStoreLease) finish(bad bool) {
	s.mu.Lock()
	s.active = false
	s.cancel = nil
	if bad {
		s.closed = true
	}
	release := s.closed && !s.retained && !s.released
	if release {
		s.released = true
	}
	s.mu.Unlock()
	if release {
		e := s.view.Close()
		s.mu.Lock()
		s.closeErr = e
		s.mu.Unlock()
	}
}
func (s *BrowserStoreLease) record(ctx context.Context, key []byte, kind string, height uint64, max int64) (value []byte, err error) {
	return s.recordWithNamespace(ctx, key, kind, height, max, false)
}

func (s *BrowserStoreLease) recordWithNamespace(ctx context.Context, key []byte, kind string, height uint64, max int64, recent bool) (value []byte, err error) {
	if s == nil || browserNil(ctx) {
		return nil, ethdb.ErrBrowserSnapshotMalformed
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if recent && !s.recent {
		return nil, ethdb.ErrBrowserSnapshotUnsupported
	}
	if len(key) == 0 || int64(len(key)) > s.limits.MaxKeyBytes || max <= 0 {
		_ = s.Close()
		return nil, ethdb.ErrBrowserSnapshotLimit
	}
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ethdb.ErrBrowserSnapshotClosed
	}
	if s.active {
		s.mu.Unlock()
		return nil, ethdb.ErrBrowserSnapshotLimit
	}
	if s.reads >= s.limits.MaxRecordReads || s.returned >= s.limits.MaxReturnedBytes {
		s.mu.Unlock()
		_ = s.Close()
		return nil, ethdb.ErrBrowserSnapshotLimit
	}
	if max > s.limits.MaxValueBytes {
		max = s.limits.MaxValueBytes
	}
	if remaining := s.limits.MaxReturnedBytes - s.returned; max > remaining {
		max = remaining
	}
	s.reads++
	s.active = true
	s.cancel = cancel
	s.mu.Unlock()
	ok := false
	defer func() { s.finish(!ok) }()
	if e := call.Err(); e != nil {
		return nil, e
	}
	if s.view.BrowserViewID() != s.id {
		return nil, ethdb.ErrBrowserSnapshotInconsistent
	}
	if recent {
		view, supported := s.view.(ethdb.BrowserRecentSnapshot)
		if !supported || browserNil(view) {
			return nil, ethdb.ErrBrowserSnapshotUnsupported
		}
		value, err = view.ReadBrowserRecentRecord(call, key, kind, max)
	} else {
		value, err = s.view.ReadBrowserRecord(call, key, kind, height, max)
	}
	if e := call.Err(); e != nil {
		return nil, e
	}
	if s.view.BrowserViewID() != s.id {
		return nil, ethdb.ErrBrowserSnapshotInconsistent
	}
	if err != nil {
		return nil, err
	}
	if int64(len(value)) > max {
		return nil, ethdb.ErrBrowserSnapshotLimit
	}
	if len(value) == 0 {
		return nil, ethdb.ErrBrowserSnapshotMissing
	}
	s.mu.Lock()
	closed := s.closed
	if !closed {
		s.returned += int64(len(value))
	}
	s.mu.Unlock()
	if closed {
		return nil, ethdb.ErrBrowserSnapshotClosed
	}
	ok = true
	return value, nil
}

type BrowserRawHeader struct {
	Number        uint64
	CanonicalHash common.Hash
	HeaderRLP     []byte
	ViewID        [32]byte
}
type BrowserRawBlock struct {
	BrowserRawHeader
	BodyRLP []byte
}
type BrowserRawChainConfig struct {
	GenesisHash common.Hash
	JSON        []byte
	ViewID      [32]byte
}

func (s *BrowserStoreLease) ReadCanonical(ctx context.Context, height uint64) (common.Hash, error) {
	raw, e := s.record(ctx, headerHashKey(height), freezerHashTable, height, common.HashLength)
	if e != nil {
		return common.Hash{}, e
	}
	if len(raw) != common.HashLength {
		_ = s.Close()
		return common.Hash{}, ethdb.ErrBrowserSnapshotMalformed
	}
	h := common.BytesToHash(raw)
	if h == (common.Hash{}) {
		_ = s.Close()
		return common.Hash{}, ethdb.ErrBrowserSnapshotMalformed
	}
	return h, nil
}
func (s *BrowserStoreLease) ReadHeaderRaw(ctx context.Context, height uint64) (BrowserRawHeader, error) {
	if s == nil {
		return BrowserRawHeader{}, ethdb.ErrBrowserSnapshotMalformed
	}
	return s.ReadHeaderRawBounded(ctx, height, s.limits.MaxValueBytes)
}

// ReadHeaderRawBounded tightens the input value cap before the strict driver
// allocates/copies the same header bytes ultimately sent to the writer.
func (s *BrowserStoreLease) ReadHeaderRawBounded(ctx context.Context, height uint64, max int64) (BrowserRawHeader, error) {
	h, e := s.ReadCanonical(ctx, height)
	if e != nil {
		return BrowserRawHeader{}, e
	}
	raw, e := s.record(ctx, headerKey(height, h), freezerHeaderTable, height, max)
	if e != nil {
		return BrowserRawHeader{}, e
	}
	return BrowserRawHeader{height, h, raw, s.id}, nil
}
func (s *BrowserStoreLease) ReadBlockRaw(ctx context.Context, height uint64) (BrowserRawBlock, error) {
	if s == nil {
		return BrowserRawBlock{}, ethdb.ErrBrowserSnapshotMalformed
	}
	return s.ReadBlockRawBounded(ctx, height, s.limits.MaxValueBytes)
}

// Every valid extblock has one outer-list prefix and at least six one-byte
// list components. Reserve that minimum BEFORE header copying. Body input is
// bounded by output remainder: its prefix is never longer than the new outer
// prefix (the latter payload includes the header). Final exact framing is
// checked before output; no ordinary Get/decode fallback is used.
func (s *BrowserStoreLease) ReadBlockRawBounded(ctx context.Context, height uint64, max int64) (BrowserRawBlock, error) {
	if max < 8 {
		_ = s.Close()
		return BrowserRawBlock{}, ethdb.ErrBrowserSnapshotLimit
	}
	header, e := s.ReadHeaderRawBounded(ctx, height, max-7)
	if e != nil {
		return BrowserRawBlock{}, e
	}
	body, e := s.record(ctx, blockBodyKey(height, header.CanonicalHash), freezerBodiesTable, height, max-int64(len(header.HeaderRLP)))
	if e != nil {
		return BrowserRawBlock{}, e
	}
	return BrowserRawBlock{header, body}, nil
}
func (s *BrowserStoreLease) ReadChainConfigRaw(ctx context.Context) (BrowserRawChainConfig, error) {
	h, e := s.ReadCanonical(ctx, 0)
	if e != nil {
		return BrowserRawChainConfig{}, e
	}
	// Storage JSON cap is independent of the writer's eight-byte ChainID output.
	raw, e := s.record(ctx, configKey(h), "", 0, 1<<20)
	if e != nil {
		return BrowserRawChainConfig{}, e
	}
	return BrowserRawChainConfig{h, raw, s.id}, nil
}

// Raw parts deliberately preserve the complete storage header/body bytes.
// A structural writer must preflight/split six Body children and assemble the
// pinned extblock schema before streaming. These accessors do no semantic
// decode or buffering EncodeRLP and do not certify authentication.
