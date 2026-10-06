//go:build !js && cypher_bounded_storage

// SPDX-License-Identifier: LGPL-3.0-or-later
package leveldb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"github.com/cypherium/cypher/ethdb"
	goleveldb "github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/readbudget"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

// This file is explicitly opt-in and requires the reviewed additive public
// goleveldb fork. A stock module must not be built with this tag. No ordinary
// Get/Ancient/iterator fallback or shared cache mutation is used.
type browserKVSnapshot interface {
	GetBounded(context.Context, []byte, *opt.ReadOptions, *readbudget.Budget) ([]byte, error)
	Release()
}

var _ browserKVSnapshot = (*goleveldb.Snapshot)(nil)
var browserOwnedViewSequence atomic.Uint64

func browserAdapterNil(v interface{}) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return r.IsNil()
	}
	return false
}
func (db *Database) BrowserSnapshotCapabilityVersion() uint32 {
	if db == nil || db.db == nil {
		return 0
	}
	return ethdb.BrowserSnapshotCapabilityV1
}
func (db *Database) NewBrowserSnapshot(ctx context.Context, l ethdb.BrowserSnapshotLimits) (ethdb.BrowserSnapshot, error) {
	if db == nil || db.db == nil {
		return nil, ethdb.ErrBrowserSnapshotUnsupported
	}
	return newBrowserBoundedSnapshot(ctx, l, func() (browserKVSnapshot, error) { return db.db.GetSnapshot() })
}

// createCtx governs acquisition only. Budget lifetime owns an independent
// twenty-minute context, canceled only by this owned snapshot's Close. It must
// not capture first ChainID/ON HTTP request context. Snapshot acquisition is
// fixed sequence/reference metadata, not iterator/Get or payload decoding.
func newBrowserBoundedSnapshot(createCtx context.Context, l ethdb.BrowserSnapshotLimits, create func() (browserKVSnapshot, error)) (ethdb.BrowserSnapshot, error) {
	if browserAdapterNil(createCtx) || create == nil {
		return nil, ethdb.ErrBrowserSnapshotMalformed
	}
	if e := createCtx.Err(); e != nil {
		return nil, e
	}
	if e := l.Validate(); e != nil {
		return nil, e
	}
	lifeCtx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	budget, e := readbudget.New(lifeCtx, readbudget.Limits{MaxStoredBytes: uint64(l.MaxStoredBytes), MaxDecodedBytes: uint64(l.MaxDecodedBytes), MaxValueBytes: uint64(l.MaxValueBytes), MaxKeyBytes: uint64(l.MaxKeyBytes), MaxAllocationBytes: uint64(l.MaxAllocationBytes), MaxWork: uint64(l.MaxWork)})
	if e != nil {
		cancel()
		return nil, browserStorageError(e)
	}
	snap, e := create()
	if e != nil {
		cancel()
		if !browserAdapterNil(snap) {
			snap.Release()
		}
		return nil, browserStorageError(e)
	}
	if browserAdapterNil(snap) {
		cancel()
		return nil, ethdb.ErrBrowserSnapshotUnsupported
	}
	if e = createCtx.Err(); e != nil {
		cancel()
		snap.Release()
		return nil, e
	}
	seq := browserOwnedViewSequence.Add(1)
	if seq == 0 {
		cancel()
		snap.Release()
		return nil, ethdb.ErrBrowserSnapshotUnsupported
	}
	var id [32]byte
	binary.BigEndian.PutUint64(id[24:], seq)
	return &browserBoundedSnapshot{snap: snap, budget: budget, limits: l, id: id, cancelLife: cancel}, nil
}

type browserBoundedSnapshot struct {
	snap                     browserKVSnapshot
	budget                   *readbudget.Budget
	limits                   ethdb.BrowserSnapshotLimits
	id                       [32]byte
	mu                       sync.Mutex
	closed, active, released bool
	cancelLife               context.CancelFunc
	cancelRead               context.CancelFunc
	reads                    int
	returned                 uint64
}

func (s *browserBoundedSnapshot) BrowserViewID() [32]byte { return s.id }
func (s *browserBoundedSnapshot) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.closed = true
	s.cancelLife()
	if s.cancelRead != nil {
		s.cancelRead()
	}
	release := !s.active && !s.released
	if release {
		s.released = true
	}
	s.mu.Unlock()
	if release {
		s.snap.Release()
	}
	return nil
}
func (s *browserBoundedSnapshot) finish(bad bool) {
	s.mu.Lock()
	s.active = false
	s.cancelRead = nil
	if bad {
		s.closed = true
		s.cancelLife()
	}
	release := s.closed && !s.released
	if release {
		s.released = true
	}
	s.mu.Unlock()
	if release {
		s.snap.Release()
	}
}
func (s *browserBoundedSnapshot) ReadBrowserRecord(ctx context.Context, key []byte, kind string, height uint64, max int64) (value []byte, err error) {
	if s == nil || browserAdapterNil(ctx) {
		return nil, ethdb.ErrBrowserSnapshotMalformed
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if len(key) == 0 || int64(len(key)) > s.limits.MaxKeyBytes || max <= 0 {
		return nil, ethdb.ErrBrowserSnapshotLimit
	}
	if !browserRawKeyHint(key, kind, height) {
		return nil, ethdb.ErrBrowserSnapshotUnsupported
	}
	return s.readBrowserKey(ctx, key, max)
}

// Both explicitly versioned namespaces share this same owned-view ledger.
// Callers must validate their namespace before entering this function.
func (s *browserBoundedSnapshot) readBrowserKey(ctx context.Context, key []byte, max int64) (value []byte, err error) {
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
	if s.reads >= s.limits.MaxRecordReads || s.returned >= uint64(s.limits.MaxReturnedBytes) {
		s.mu.Unlock()
		_ = s.Close()
		return nil, ethdb.ErrBrowserSnapshotLimit
	}
	if max > s.limits.MaxValueBytes {
		max = s.limits.MaxValueBytes
	}
	if remainder := uint64(s.limits.MaxReturnedBytes) - s.returned; uint64(max) > remainder {
		max = int64(remainder)
	}
	s.reads++
	s.active = true
	s.cancelRead = cancel
	s.mu.Unlock()
	ok := false
	defer func() { s.finish(!ok) }()
	if e := s.budget.Check(call); e != nil {
		return nil, browserStorageError(e)
	}
	scoped, e := s.budget.WithValueLimit(uint64(max))
	if e != nil {
		return nil, browserStorageError(e)
	}
	value, e = s.snap.GetBounded(call, key, nil, scoped)
	if ce := s.budget.Check(call); ce != nil {
		return nil, browserStorageError(ce)
	}
	if e != nil {
		return nil, browserStorageError(e)
	}
	if len(value) == 0 {
		return nil, ethdb.ErrBrowserSnapshotMissing
	}
	if int64(len(value)) > max {
		return nil, ethdb.ErrBrowserSnapshotLimit
	}
	s.mu.Lock()
	closed := s.closed
	if !closed {
		s.returned += uint64(len(value))
	}
	s.mu.Unlock()
	if closed {
		return nil, ethdb.ErrBrowserSnapshotClosed
	}
	ok = true
	return value, nil
}

// V1 reads the KV key only. Hints validate the pinned rawdb key suffix/height;
// a bounded owner-selected table prefix is opaque, never cold routing. Future
// schema/cold namespaces require a reviewed different capability version.
func browserRawKeyHint(key []byte, kind string, height uint64) bool {
	var tail []byte
	switch kind {
	case "hashes":
		if len(key) < 10 {
			return false
		}
		tail = key[len(key)-10:]
		return tail[0] == 'h' && tail[9] == 'n' && binary.BigEndian.Uint64(tail[1:9]) == height
	case "headers", "bodies":
		if len(key) < 41 {
			return false
		}
		tail = key[len(key)-41:]
		prefix := byte('h')
		if kind == "bodies" {
			prefix = 'b'
		}
		return tail[0] == prefix && binary.BigEndian.Uint64(tail[1:9]) == height && !bytes.Equal(tail[9:], make([]byte, 32))
	case "":
		if height != 0 || len(key) < len("ethereum-config-")+32 {
			return false
		}
		tail = key[len(key)-len("ethereum-config-")-32:]
		return bytes.Equal(tail[:len("ethereum-config-")], []byte("ethereum-config-")) && !bytes.Equal(tail[len("ethereum-config-"):], make([]byte, 32))
	default:
		return false
	}
}
func browserStorageError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, readbudget.ErrLimit), errors.Is(err, readbudget.ErrInvalid):
		return ethdb.ErrBrowserSnapshotLimit
	case errors.Is(err, goleveldb.ErrNotFound):
		return ethdb.ErrBrowserSnapshotMissing
	case errors.Is(err, goleveldb.ErrSnapshotReleased):
		return ethdb.ErrBrowserSnapshotClosed
	default:
		return ethdb.ErrBrowserSnapshotUnsupported
	}
}
