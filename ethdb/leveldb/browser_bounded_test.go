//go:build !js && cypher_bounded_storage

// SPDX-License-Identifier: LGPL-3.0-or-later
package leveldb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/cypherium/cypher/ethdb"
	goleveldb "github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/readbudget"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type browserSnapshotFake struct {
	value            []byte
	reads, releases  atomic.Int32
	entered, release chan struct{}
	failure          error
	lastCap          atomic.Uint64
}

func (s *browserSnapshotFake) GetBounded(ctx context.Context, key []byte, _ *opt.ReadOptions, b *readbudget.Budget) ([]byte, error) {
	s.reads.Add(1)
	s.lastCap.Store(b.Limits().MaxValueBytes)
	if s.entered != nil {
		close(s.entered)
		<-s.release
	}
	if s.failure != nil {
		return nil, s.failure
	}
	return b.CopyValue(ctx, s.value)
}
func (s *browserSnapshotFake) Release() { s.releases.Add(1) }
func browserHashKey(height byte) []byte { return []byte{'h', 0, 0, 0, 0, 0, 0, 0, height, 'n'} }
func TestBrowserStorageTagNilDatabaseUnsupportedNoOpen(t *testing.T) {
	db := &Database{}
	if db.BrowserSnapshotCapabilityVersion() != 0 {
		t.Fatal("nil native DB capability")
	}
	if _, e := db.NewBrowserSnapshot(context.Background(), ethdb.DefaultBrowserSnapshotLimits()); !errors.Is(e, ethdb.ErrBrowserSnapshotUnsupported) {
		t.Fatal(e)
	}
}
func TestBrowserStoragePrimitiveContextAndValueCapBeforeCopy(t *testing.T) {
	mock := &browserSnapshotFake{value: bytes.Repeat([]byte{1}, 32)}
	ctx, cancel := context.WithCancel(context.Background())
	s, e := newBrowserBoundedSnapshot(ctx, ethdb.DefaultBrowserSnapshotLimits(), func() (browserKVSnapshot, error) { return mock, nil })
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	cancel()
	first, e := s.ReadBrowserRecord(context.Background(), browserHashKey(1), "hashes", 1, 32)
	if e != nil {
		t.Fatal("creation context persisted", e)
	}
	first[0] = 9
	next, e := s.ReadBrowserRecord(context.Background(), browserHashKey(1), "hashes", 1, 32)
	if e != nil || next[0] != 1 {
		t.Fatal("owned value alias", e)
	}
	if _, e = s.ReadBrowserRecord(context.Background(), browserHashKey(1), "hashes", 1, 31); !errors.Is(e, ethdb.ErrBrowserSnapshotLimit) || mock.lastCap.Load() != 31 {
		t.Fatal("cap is after copy", e)
	}
	if mock.releases.Load() != 1 {
		t.Fatal("failure did not release owned view")
	}
}
func TestBrowserStorageNamespaceAndReturnedLifetimeBudget(t *testing.T) {
	mock := &browserSnapshotFake{value: bytes.Repeat([]byte{1}, 32)}
	caps := ethdb.DefaultBrowserSnapshotLimits()
	caps.MaxReturnedBytes = 40
	s, e := newBrowserBoundedSnapshot(context.Background(), caps, func() (browserKVSnapshot, error) { return mock, nil })
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.ReadBrowserRecord(context.Background(), []byte("private-other-key"), "unknown", 1, 32); !errors.Is(e, ethdb.ErrBrowserSnapshotUnsupported) || mock.reads.Load() != 0 {
		t.Fatal("namespace fallback", e)
	}
	if _, e = s.ReadBrowserRecord(context.Background(), browserHashKey(1), "hashes", 2, 32); !errors.Is(e, ethdb.ErrBrowserSnapshotUnsupported) || mock.reads.Load() != 0 {
		t.Fatal("height/key mismatch", e)
	}
	if _, e = s.ReadBrowserRecord(context.Background(), browserHashKey(1), "hashes", 1, 32); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ReadBrowserRecord(context.Background(), browserHashKey(1), "hashes", 1, 32); !errors.Is(e, ethdb.ErrBrowserSnapshotLimit) || mock.lastCap.Load() != 8 {
		t.Fatal("remaining cap after copy", e)
	}
}
func TestBrowserStorageCloseRetainsActualInFlightAndNoLateResult(t *testing.T) {
	mock := &browserSnapshotFake{value: []byte{1}, entered: make(chan struct{}), release: make(chan struct{})}
	s, e := newBrowserBoundedSnapshot(context.Background(), ethdb.DefaultBrowserSnapshotLimits(), func() (browserKVSnapshot, error) { return mock, nil })
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		_, e := s.ReadBrowserRecord(context.Background(), browserHashKey(1), "hashes", 1, 32)
		done <- e
	}()
	select {
	case <-mock.entered:
	case <-time.After(time.Second):
		t.Fatal("mock not entered")
	}
	s.Close()
	s.Close()
	if mock.releases.Load() != 0 {
		t.Fatal("inflight snapshot released")
	}
	close(mock.release)
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal("late result accepted", e)
		}
	case <-time.After(time.Second):
		t.Fatal("late read not returned")
	}
	if mock.releases.Load() != 1 {
		t.Fatal("owned snapshot release count")
	}
}
func TestBrowserStoragePartialAcquisitionAndMissingAreFailClosed(t *testing.T) {
	mock := &browserSnapshotFake{}
	if _, e := newBrowserBoundedSnapshot(context.Background(), ethdb.DefaultBrowserSnapshotLimits(), func() (browserKVSnapshot, error) { return mock, errors.New("private path IO") }); !errors.Is(e, ethdb.ErrBrowserSnapshotUnsupported) || mock.releases.Load() != 1 {
		t.Fatal("partial lease/error leaked", e)
	}
	mock = &browserSnapshotFake{failure: goleveldb.ErrNotFound}
	s, e := newBrowserBoundedSnapshot(context.Background(), ethdb.DefaultBrowserSnapshotLimits(), func() (browserKVSnapshot, error) { return mock, nil })
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.ReadBrowserRecord(context.Background(), browserHashKey(1), "hashes", 1, 32); !errors.Is(e, ethdb.ErrBrowserSnapshotMissing) {
		t.Fatal("missing not preserved", e)
	}
	if _, e = s.ReadBrowserRecord(context.Background(), browserHashKey(1), "hashes", 1, 32); !errors.Is(e, ethdb.ErrBrowserSnapshotClosed) || mock.reads.Load() != 1 {
		t.Fatal("missing retried", e)
	}
}

func TestBrowserStorageCancellationDoesNotEchoWrappedPrivateIO(t *testing.T) {
	for _, want := range []error{context.Canceled, context.DeadlineExceeded} {
		got := browserStorageError(fmt.Errorf("synthetic-private-key /private/path: %w", want))
		if got != want || strings.Contains(got.Error(), "private") {
			t.Fatal("wrapped IO escaped", got)
		}
	}
}
