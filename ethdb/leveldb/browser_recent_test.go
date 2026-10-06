//go:build !js && cypher_bounded_storage

// SPDX-License-Identifier: LGPL-3.0-or-later
package leveldb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/ethdb"
	goleveldb "github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/readbudget"
)

type browserRecentReadCall struct {
	key string
	cap uint64
}

// This synthetic storage seam uses the real budget.CopyValue operation. It
// deliberately does not simulate physical storage, decompression or native IO.
// A held call ignores cancellation until resumed so Close must retain ownership
// until that actual call returns, rather than merely until its context expires.
type browserRecentKVFake struct {
	values   map[string][]byte
	mu       sync.Mutex
	calls    []browserRecentReadCall
	copies   atomic.Int32
	releases atomic.Int32
	entered  chan context.Context
	resume   chan struct{}
}

func newBrowserRecentKVFake(values map[string][]byte) *browserRecentKVFake {
	f := &browserRecentKVFake{values: make(map[string][]byte, len(values))}
	for key, value := range values {
		f.values[key] = append([]byte(nil), value...)
	}
	return f
}

func (f *browserRecentKVFake) GetBounded(ctx context.Context, key []byte, _ *opt.ReadOptions, budget *readbudget.Budget) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, browserRecentReadCall{string(key), budget.Limits().MaxValueBytes})
	f.mu.Unlock()
	if err := budget.Check(ctx); err != nil {
		return nil, err
	}
	if f.entered != nil {
		f.entered <- ctx
		<-f.resume
	}
	value, ok := f.values[string(key)]
	if !ok {
		return nil, goleveldb.ErrNotFound
	}
	owned, err := budget.CopyValue(ctx, value)
	if err == nil {
		f.copies.Add(1)
	}
	return owned, err
}

func (f *browserRecentKVFake) Release() { f.releases.Add(1) }

func (f *browserRecentKVFake) readCalls() []browserRecentReadCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]browserRecentReadCall(nil), f.calls...)
}

func browserRecentNumberKey() []byte {
	// This non-aliasing hash does not end in any accepted original V1 suffix.
	return append([]byte{'H'}, bytes.Repeat([]byte{7}, 32)...)
}

func browserRecentCanonicalKey() []byte {
	key := make([]byte, 10)
	key[0], key[9] = 'h', 'n'
	binary.BigEndian.PutUint64(key[1:9], 7)
	return key
}

func browserRecentValues() map[string][]byte {
	number := make([]byte, 8)
	binary.BigEndian.PutUint64(number, 7)
	return map[string][]byte{
		"LastBlock":                         bytes.Repeat([]byte{7}, 32),
		string(browserRecentNumberKey()):    number,
		string(browserRecentCanonicalKey()): bytes.Repeat([]byte{7}, 32),
	}
}

func openBrowserRecentTestSnapshot(t *testing.T, createCtx context.Context, limits ethdb.BrowserSnapshotLimits, fake *browserRecentKVFake) *browserBoundedSnapshot {
	t.Helper()
	view, err := newBrowserBoundedSnapshot(createCtx, limits, func() (browserKVSnapshot, error) { return fake, nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := view.(ethdb.BrowserRecentSnapshot); !ok {
		view.Close()
		t.Fatal("owned view lost the optional recent metadata interface")
	}
	snapshot, ok := view.(*browserBoundedSnapshot)
	if !ok {
		view.Close()
		t.Fatal("unexpected bounded snapshot type")
	}
	t.Cleanup(func() { snapshot.Close() })
	return snapshot
}

func TestBrowserRecentStoragePinnedNamespaceAndOriginalV1Unchanged(t *testing.T) {
	fake := newBrowserRecentKVFake(browserRecentValues())
	snapshot := openBrowserRecentTestSnapshot(t, context.Background(), ethdb.DefaultBrowserSnapshotLimits(), fake)
	bad := []struct {
		key  []byte
		kind string
	}{
		{[]byte("LastHeader"), "head-block"},
		{[]byte("LastFast"), "head-block"},
		{[]byte("LastBlock/"), "head-block"},
		{[]byte("other-private-key"), "head-block"},
		{browserRecentCanonicalKey(), "head-block"},
		{browserRecentNumberKey(), "head-block"},
		{[]byte("LastBlock"), "header-number"},
		{append([]byte{'H'}, make([]byte, 32)...), "header-number"},
		{append([]byte{'h'}, bytes.Repeat([]byte{7}, 32)...), "header-number"},
		{browserRecentNumberKey()[:32], "header-number"},
		{browserRecentNumberKey(), "headers"},
		{[]byte("LastBlock"), ""},
	}
	for _, test := range bad {
		if _, err := snapshot.ReadBrowserRecentRecord(context.Background(), test.key, test.kind, 1024); !errors.Is(err, ethdb.ErrBrowserSnapshotUnsupported) {
			t.Fatalf("unexpected namespace admission for kind %q: %v", test.kind, err)
		}
	}
	// V1 continues to validate its original suffixes with opaque table prefixes.
	// These ordinary metadata fixtures must not acquire a new V1 route or kind.
	for _, key := range [][]byte{[]byte("LastBlock"), browserRecentNumberKey()} {
		for _, kind := range []string{"head-block", "header-number", "hashes", "headers", "bodies", ""} {
			if _, err := snapshot.ReadBrowserRecord(context.Background(), key, kind, 7, 1024); !errors.Is(err, ethdb.ErrBrowserSnapshotUnsupported) {
				t.Fatalf("recent metadata widened original V1 kind %q: %v", kind, err)
			}
		}
	}
	if len(fake.readCalls()) != 0 || snapshot.reads != 0 || fake.releases.Load() != 0 {
		t.Fatal("unsupported namespace touched or retired storage")
	}
	if _, err := snapshot.ReadBrowserRecentRecord(context.Background(), []byte("LastBlock"), "head-block", 1024); err != nil {
		t.Fatal("valid recent head rejected after unsupported inputs", err)
	}
	if _, err := snapshot.ReadBrowserRecentRecord(context.Background(), browserRecentNumberKey(), "header-number", 1024); err != nil {
		t.Fatal("valid recent number rejected", err)
	}
	if _, err := snapshot.ReadBrowserRecord(context.Background(), browserRecentCanonicalKey(), "hashes", 7, 32); err != nil {
		t.Fatal("original canonical namespace changed", err)
	}
	calls := fake.readCalls()
	if len(calls) != 3 || calls[0].cap != 32 || calls[1].cap != 8 || calls[2].cap != 32 {
		t.Fatal("metadata or original cap was not present at the storage boundary", calls)
	}
}

func TestBrowserRecentStorageInputAndPrefixedKeyBoundsBeforeIO(t *testing.T) {
	limits := ethdb.DefaultBrowserSnapshotLimits()
	limits.MaxKeyBytes = 40
	values := browserRecentValues()
	validNumber := append([]byte("outer/"), browserRecentNumberKey()...)
	validNumber = append([]byte("p"), validNumber...) // Seven-byte owner prefix, 40-byte physical key.
	validHead := append(bytes.Repeat([]byte{'p'}, 31), []byte("LastBlock")...)
	values[string(validNumber)] = values[string(browserRecentNumberKey())]
	values[string(validHead)] = values["LastBlock"]
	fake := newBrowserRecentKVFake(values)
	snapshot := openBrowserRecentTestSnapshot(t, context.Background(), limits, fake)
	for _, test := range []struct {
		key  []byte
		kind string
		max  int64
	}{
		{nil, "head-block", 32},
		{[]byte("LastBlock"), "head-block", 0},
		{[]byte("LastBlock"), "head-block", -1},
		{append([]byte{'p'}, validNumber...), "header-number", 8},
		{append([]byte{'p'}, validHead...), "head-block", 32},
	} {
		if _, err := snapshot.ReadBrowserRecentRecord(context.Background(), test.key, test.kind, test.max); !errors.Is(err, ethdb.ErrBrowserSnapshotLimit) {
			t.Fatal("unbounded key/value input reached storage", err)
		}
	}
	if _, err := snapshot.ReadBrowserRecentRecord(nil, []byte("LastBlock"), "head-block", 32); !errors.Is(err, ethdb.ErrBrowserSnapshotMalformed) {
		t.Fatal("nil context accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := snapshot.ReadBrowserRecentRecord(ctx, []byte("LastBlock"), "head-block", 32); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled context reached storage", err)
	}
	if len(fake.readCalls()) != 0 {
		t.Fatal("invalid inputs performed payload IO")
	}
	for _, test := range []struct {
		key  []byte
		kind string
		max  int64
	}{{validNumber, "header-number", 8}, {validHead, "head-block", 32}} {
		if _, err := snapshot.ReadBrowserRecentRecord(context.Background(), test.key, test.kind, test.max); err != nil {
			t.Fatal("bounded owner prefix rejected", err)
		}
	}
	calls := fake.readCalls()
	if len(calls) != 2 || calls[0].key != string(validNumber) || calls[1].key != string(validHead) {
		t.Fatal("physical owner prefix was normalized or dropped", calls)
	}
	var absent *browserBoundedSnapshot
	if _, err := absent.ReadBrowserRecentRecord(context.Background(), []byte("LastBlock"), "head-block", 32); !errors.Is(err, ethdb.ErrBrowserSnapshotMalformed) {
		t.Fatal("nil snapshot accepted", err)
	}
	if (&Database{}).BrowserRecentSnapshotCapabilityVersion() != 0 || (*Database)(nil).BrowserRecentSnapshotCapabilityVersion() != 0 {
		t.Fatal("missing native database advertised recent capability")
	}
}

func TestBrowserRecentStorageTightensCapsBeforeStorageCopy(t *testing.T) {
	for _, test := range []struct {
		name      string
		key       []byte
		kind      string
		requested int64
		valueSize int
		globalCap int64
		wantCap   uint64
	}{
		{"head-hard-ceiling", []byte("LastBlock"), "head-block", 1 << 20, 33, 0, 32},
		{"number-hard-ceiling", browserRecentNumberKey(), "header-number", 1 << 20, 9, 0, 8},
		{"head-caller-tightening", []byte("LastBlock"), "head-block", 7, 8, 0, 7},
		{"number-caller-tightening", browserRecentNumberKey(), "header-number", 3, 4, 0, 3},
		{"head-lifetime-value-cap", []byte("LastBlock"), "head-block", 32, 6, 5, 5},
		{"number-lifetime-value-cap", browserRecentNumberKey(), "header-number", 8, 6, 5, 5},
	} {
		t.Run(test.name, func(t *testing.T) {
			limits := ethdb.DefaultBrowserSnapshotLimits()
			if test.globalCap != 0 {
				limits.MaxValueBytes = test.globalCap
			}
			fake := newBrowserRecentKVFake(map[string][]byte{string(test.key): bytes.Repeat([]byte{7}, test.valueSize)})
			snapshot := openBrowserRecentTestSnapshot(t, context.Background(), limits, fake)
			if value, err := snapshot.ReadBrowserRecentRecord(context.Background(), test.key, test.kind, test.requested); !errors.Is(err, ethdb.ErrBrowserSnapshotLimit) || value != nil {
				t.Fatal("oversized storage value escaped the pre-copy cap", err)
			}
			calls := fake.readCalls()
			if len(calls) != 1 || calls[0].cap != test.wantCap || fake.copies.Load() != 0 || snapshot.budget.Usage().AllocationBytes != 0 {
				t.Fatal("cap applied after storage allocation/copy", calls, snapshot.budget.Usage())
			}
			if fake.releases.Load() != 1 {
				t.Fatal("failed metadata read did not retire its owned view")
			}
		})
	}
}

func TestBrowserRecentStorageSharesRecordReadBudgetWithOriginalV1(t *testing.T) {
	limits := ethdb.DefaultBrowserSnapshotLimits()
	limits.MaxRecordReads = 2
	fake := newBrowserRecentKVFake(browserRecentValues())
	snapshot := openBrowserRecentTestSnapshot(t, context.Background(), limits, fake)
	if _, err := snapshot.ReadBrowserRecord(context.Background(), browserRecentCanonicalKey(), "hashes", 7, 32); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.ReadBrowserRecentRecord(context.Background(), []byte("LastBlock"), "head-block", 32); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.ReadBrowserRecentRecord(context.Background(), browserRecentNumberKey(), "header-number", 8); !errors.Is(err, ethdb.ErrBrowserSnapshotLimit) {
		t.Fatal("recent records acquired a fresh read ledger", err)
	}
	if len(fake.readCalls()) != 2 || snapshot.reads != 2 || snapshot.returned != 64 || fake.releases.Load() != 1 {
		t.Fatal("shared lifetime ledger or release count changed")
	}
	if _, err := snapshot.ReadBrowserRecord(context.Background(), browserRecentCanonicalKey(), "hashes", 7, 32); !errors.Is(err, ethdb.ErrBrowserSnapshotClosed) || len(fake.readCalls()) != 2 {
		t.Fatal("retired metadata view remained readable through V1", err)
	}
}

func TestBrowserRecentStorageSharesReturnedAllocationAndWorkBudgets(t *testing.T) {
	for _, recentFirst := range []bool{false, true} {
		name := "original-then-recent"
		if recentFirst {
			name = "recent-then-original"
		}
		t.Run(name, func(t *testing.T) {
			limits := ethdb.DefaultBrowserSnapshotLimits()
			limits.MaxReturnedBytes = 36
			fake := newBrowserRecentKVFake(browserRecentValues())
			snapshot := openBrowserRecentTestSnapshot(t, context.Background(), limits, fake)
			var err error
			if recentFirst {
				_, err = snapshot.ReadBrowserRecentRecord(context.Background(), []byte("LastBlock"), "head-block", 32)
			} else {
				_, err = snapshot.ReadBrowserRecord(context.Background(), browserRecentCanonicalKey(), "hashes", 7, 32)
			}
			if err != nil {
				t.Fatal(err)
			}
			if recentFirst {
				_, err = snapshot.ReadBrowserRecord(context.Background(), browserRecentCanonicalKey(), "hashes", 7, 32)
			} else {
				_, err = snapshot.ReadBrowserRecentRecord(context.Background(), browserRecentNumberKey(), "header-number", 8)
			}
			calls := fake.readCalls()
			if !errors.Is(err, ethdb.ErrBrowserSnapshotLimit) || len(calls) != 2 || calls[1].cap != 4 || fake.copies.Load() != 1 || snapshot.returned != 32 || snapshot.budget.Usage().AllocationBytes != 32 || fake.releases.Load() != 1 {
				t.Fatal("remaining returned budget was applied after copying or reset", err, calls, snapshot.budget.Usage())
			}
		})
	}
	t.Run("aggregate-allocation", func(t *testing.T) {
		limits := ethdb.DefaultBrowserSnapshotLimits()
		limits.MaxAllocationBytes = 39
		fake := newBrowserRecentKVFake(browserRecentValues())
		snapshot := openBrowserRecentTestSnapshot(t, context.Background(), limits, fake)
		if _, err := snapshot.ReadBrowserRecord(context.Background(), browserRecentCanonicalKey(), "hashes", 7, 32); err != nil {
			t.Fatal(err)
		}
		if _, err := snapshot.ReadBrowserRecentRecord(context.Background(), browserRecentNumberKey(), "header-number", 8); !errors.Is(err, ethdb.ErrBrowserSnapshotLimit) {
			t.Fatal("metadata copy bypassed aggregate allocation budget", err)
		}
		if fake.copies.Load() != 1 || snapshot.budget.Usage().AllocationBytes != 32 || snapshot.returned != 32 || snapshot.reads != 2 || fake.releases.Load() != 1 {
			t.Fatal("failed allocation was copied, refunded or left the view open")
		}
	})
	t.Run("work-failure-keeps-allocation-charged", func(t *testing.T) {
		limits := ethdb.DefaultBrowserSnapshotLimits()
		limits.MaxWork = 1
		fake := newBrowserRecentKVFake(browserRecentValues())
		snapshot := openBrowserRecentTestSnapshot(t, context.Background(), limits, fake)
		if _, err := snapshot.ReadBrowserRecentRecord(context.Background(), []byte("LastBlock"), "head-block", 32); err != nil {
			t.Fatal(err)
		}
		if _, err := snapshot.ReadBrowserRecentRecord(context.Background(), browserRecentNumberKey(), "header-number", 8); !errors.Is(err, ethdb.ErrBrowserSnapshotLimit) {
			t.Fatal("metadata copy obtained a fresh work budget", err)
		}
		usage := snapshot.budget.Usage()
		if usage.Work != 1 || usage.AllocationBytes != 40 || snapshot.returned != 32 || snapshot.reads != 2 || fake.releases.Load() != 1 {
			t.Fatal("failed bounded copy refunded its lifetime allocation", usage)
		}
	})
}

func TestBrowserRecentStorageOwnedBytesAndIndependentCreationContext(t *testing.T) {
	values := browserRecentValues()
	fake := newBrowserRecentKVFake(values)
	ctx, cancel := context.WithCancel(context.Background())
	snapshot := openBrowserRecentTestSnapshot(t, ctx, ethdb.DefaultBrowserSnapshotLimits(), fake)
	cancel()
	values["LastBlock"][0] = 99 // The fake captured an immutable view at construction.
	first, err := snapshot.ReadBrowserRecentRecord(context.Background(), []byte("LastBlock"), "head-block", 32)
	if err != nil || first[0] != 7 || snapshot.BrowserViewID() == ([32]byte{}) {
		t.Fatal("creation request context or mutable input leaked into the owned view", err)
	}
	first[0] = 9
	next, err := snapshot.ReadBrowserRecentRecord(context.Background(), []byte("LastBlock"), "head-block", 32)
	if err != nil || next[0] != 7 {
		t.Fatal("returned metadata aliased retained storage", err)
	}
	retained := append([]byte(nil), next...)
	snapshot.Close()
	snapshot.Close()
	if !bytes.Equal(next, retained) || first[0] != 9 || fake.releases.Load() != 1 {
		t.Fatal("Close mutated caller-owned bytes or released the view repeatedly")
	}
	if _, err = snapshot.ReadBrowserRecentRecord(context.Background(), browserRecentNumberKey(), "header-number", 8); !errors.Is(err, ethdb.ErrBrowserSnapshotClosed) || len(fake.readCalls()) != 2 {
		t.Fatal("closed recent view read payload", err)
	}
}

func TestBrowserRecentStorageCloseRetainsHeldMetadataAndRejectsOverlap(t *testing.T) {
	fake := newBrowserRecentKVFake(browserRecentValues())
	fake.entered, fake.resume = make(chan context.Context, 1), make(chan struct{})
	snapshot := openBrowserRecentTestSnapshot(t, context.Background(), ethdb.DefaultBrowserSnapshotLimits(), fake)
	var once sync.Once
	resume := func() { once.Do(func() { close(fake.resume) }) }
	defer resume()
	type result struct {
		value []byte
		err   error
	}
	done := make(chan result, 1)
	go func() {
		value, err := snapshot.ReadBrowserRecentRecord(context.Background(), []byte("LastBlock"), "head-block", 32)
		done <- result{value, err}
	}()
	var held context.Context
	select {
	case held = <-fake.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("metadata call did not enter the synthetic storage seam")
	}
	if _, err := snapshot.ReadBrowserRecord(context.Background(), browserRecentCanonicalKey(), "hashes", 7, 32); !errors.Is(err, ethdb.ErrBrowserSnapshotLimit) || len(fake.readCalls()) != 1 {
		t.Fatal("original V1 overlapped the held metadata call", err)
	}
	snapshot.Close()
	snapshot.Close()
	if !errors.Is(held.Err(), context.Canceled) || fake.releases.Load() != 0 {
		t.Fatal("Close failed to cancel or released the still-active physical view")
	}
	if _, err := snapshot.ReadBrowserRecentRecord(context.Background(), browserRecentNumberKey(), "header-number", 8); !errors.Is(err, ethdb.ErrBrowserSnapshotClosed) || len(fake.readCalls()) != 1 {
		t.Fatal("Close admitted another metadata read", err)
	}
	resume()
	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) || got.value != nil {
			t.Fatal("late metadata result accepted after Close", got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resumed metadata call did not return")
	}
	snapshot.Close()
	if fake.releases.Load() != 1 || fake.copies.Load() != 0 {
		t.Fatal("held owned view release count or late copy changed")
	}
}

func TestBrowserRecentStorageCanceledRequestWaitsForActualMetadataReturn(t *testing.T) {
	fake := newBrowserRecentKVFake(browserRecentValues())
	fake.entered, fake.resume = make(chan context.Context, 1), make(chan struct{})
	snapshot := openBrowserRecentTestSnapshot(t, context.Background(), ethdb.DefaultBrowserSnapshotLimits(), fake)
	var once sync.Once
	resume := func() { once.Do(func() { close(fake.resume) }) }
	defer resume()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		value, err := snapshot.ReadBrowserRecentRecord(ctx, []byte("LastBlock"), "head-block", 32)
		if value != nil {
			err = errors.New("canceled metadata returned bytes")
		}
		done <- err
	}()
	var held context.Context
	select {
	case held = <-fake.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("metadata call did not enter storage")
	}
	cancel()
	if !errors.Is(held.Err(), context.Canceled) || fake.releases.Load() != 0 {
		t.Fatal("request cancellation released an actual active storage call")
	}
	resume()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("request cancellation or no-late-result contract lost", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resumed canceled metadata call did not return")
	}
	if fake.releases.Load() != 1 || snapshot.reads != 1 || snapshot.returned != 0 {
		t.Fatal("canceled call refunded its read reservation or leaked its owned view")
	}
	if _, err := snapshot.ReadBrowserRecord(context.Background(), browserRecentCanonicalKey(), "hashes", 7, 32); !errors.Is(err, ethdb.ErrBrowserSnapshotClosed) || len(fake.readCalls()) != 1 {
		t.Fatal("failed recent view remained readable through original V1", err)
	}
}
