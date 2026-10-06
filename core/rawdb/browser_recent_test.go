// SPDX-License-Identifier: LGPL-3.0-or-later
package rawdb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/ethdb"
	"sync/atomic"
	"testing"
	"time"
)

// Synthetic owned-view fixture tests rawdb keys, lease accounting and lifetime.
// It does not replace the real bounded-driver tests or verify live chain data.
type recentLeaseFixture struct {
	ethdb.KeyValueStore
	view    *recentViewFixture
	version uint32
	opens   int
	gets    int
}

func (d *recentLeaseFixture) BrowserSnapshotCapabilityVersion() uint32 {
	return ethdb.BrowserSnapshotCapabilityV1
}
func (d *recentLeaseFixture) BrowserRecentSnapshotCapabilityVersion() uint32 { return d.version }
func (d *recentLeaseFixture) NewBrowserSnapshot(context.Context, ethdb.BrowserSnapshotLimits) (ethdb.BrowserSnapshot, error) {
	d.opens++
	return d.view, nil
}
func (d *recentLeaseFixture) Get([]byte) ([]byte, error) {
	d.gets++
	return nil, errors.New("ordinary Get forbidden")
}

type recentViewFixture struct {
	id       [32]byte
	data     map[string][]byte
	keys     []string
	caps     []int64
	closed   atomic.Int32
	entered  chan struct{}
	resume   chan struct{}
	changeID bool
}

func (v *recentViewFixture) BrowserViewID() [32]byte { return v.id }
func (v *recentViewFixture) Close() error            { v.closed.Add(1); return nil }
func (v *recentViewFixture) read(ctx context.Context, key []byte, max int64) ([]byte, error) {
	v.keys = append(v.keys, string(key))
	v.caps = append(v.caps, max)
	if v.entered != nil {
		close(v.entered)
		v.entered = nil
		<-v.resume
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if v.changeID {
		v.id[0]++
	}
	raw, ok := v.data[string(key)]
	if !ok {
		return nil, ethdb.ErrBrowserSnapshotMissing
	}
	if int64(len(raw)) > max {
		return nil, ethdb.ErrBrowserSnapshotLimit
	}
	return append([]byte(nil), raw...), nil
}
func (v *recentViewFixture) ReadBrowserRecord(ctx context.Context, key []byte, _ string, _ uint64, max int64) ([]byte, error) {
	return v.read(ctx, key, max)
}
func (v *recentViewFixture) ReadBrowserRecentRecord(ctx context.Context, key []byte, _ string, max int64) ([]byte, error) {
	return v.read(ctx, key, max)
}
func recentFixture(height uint64, prefix string) (*recentLeaseFixture, common.Hash) {
	hash := common.HexToHash("0x123456789abcdef")
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], height)
	v := &recentViewFixture{id: [32]byte{1}, data: map[string][]byte{
		prefix + string(headBlockKey):          hash.Bytes(),
		prefix + string(headerNumberKey(hash)): append([]byte(nil), number[:]...),
		prefix + string(headerHashKey(height)): hash.Bytes(),
	}}
	return &recentLeaseFixture{view: v, version: ethdb.BrowserRecentSnapshotCapabilityV1}, hash
}
func openRecentFixture(t *testing.T, d interface{}, l ethdb.BrowserSnapshotLimits) *BrowserStoreLease {
	t.Helper()
	lease, err := OpenBrowserRecentStoreLease(context.Background(), d, l)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lease.Close() })
	return lease
}
func TestRecentHeadKeysCapsAndMaximumHeight(t *testing.T) {
	d, hash := recentFixture(^uint64(0), "")
	s := openRecentFixture(t, d, ethdb.DefaultBrowserSnapshotLimits())
	head, err := s.ReadRecentHead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if head.Number != ^uint64(0) || head.CanonicalHash != hash || head.ViewID != d.view.id {
		t.Fatalf("wrong head: %+v", head)
	}
	wantKeys := []string{string(headBlockKey), string(headerNumberKey(hash)), string(headerHashKey(^uint64(0)))}
	for i, want := range wantKeys {
		if d.view.keys[i] != want {
			t.Errorf("key %d differs", i)
		}
	}
	if !bytes.Equal([]byte{byte(d.view.caps[0]), byte(d.view.caps[1]), byte(d.view.caps[2])}, []byte{32, 8, 32}) {
		t.Fatalf("metadata caps %v", d.view.caps)
	}
	if s.reads != 3 || s.returned != 72 || d.gets != 0 {
		t.Fatalf("ledger reads=%d bytes=%d ordinary=%d", s.reads, s.returned, d.gets)
	}
}
func TestRecentUnsupportedVersionBeforeAnyOpen(t *testing.T) {
	for _, version := range []uint32{0, 2} {
		d, _ := recentFixture(7, "")
		d.version = version
		_, err := OpenBrowserRecentStoreLease(context.Background(), d, ethdb.DefaultBrowserSnapshotLimits())
		if !errors.Is(err, ethdb.ErrBrowserSnapshotUnsupported) || d.opens != 0 || d.gets != 0 {
			t.Fatalf("version %d: %v opens=%d", version, err, d.opens)
		}
	}
	var typedNil *recentLeaseFixture
	if _, err := OpenBrowserRecentStoreLease(context.Background(), typedNil, ethdb.DefaultBrowserSnapshotLimits()); !errors.Is(err, ethdb.ErrBrowserSnapshotUnsupported) {
		t.Fatal(err)
	}
	d, _ := recentFixture(7, "")
	ordinary, err := OpenBrowserStoreLease(context.Background(), d, ethdb.DefaultBrowserSnapshotLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	if _, err := ordinary.ReadRecentHead(context.Background()); !errors.Is(err, ethdb.ErrBrowserSnapshotUnsupported) || len(d.view.keys) != 0 {
		t.Fatal("ordinary V1 lease silently acquired recent namespace", err)
	}
}
func TestRecentMalformedAndInconsistentClose(t *testing.T) {
	for _, name := range []string{"missing", "short-head", "oversized-head", "zero-head", "short-number", "oversized-number", "canonical-mismatch", "view-change"} {
		t.Run(name, func(t *testing.T) {
			d, hash := recentFixture(7, "")
			switch name {
			case "missing":
				delete(d.view.data, string(headBlockKey))
			case "short-head":
				d.view.data[string(headBlockKey)] = hash.Bytes()[:31]
			case "oversized-head":
				d.view.data[string(headBlockKey)] = append(hash.Bytes(), 1)
			case "zero-head":
				d.view.data[string(headBlockKey)] = make([]byte, 32)
			case "short-number":
				d.view.data[string(headerNumberKey(hash))] = make([]byte, 7)
			case "oversized-number":
				d.view.data[string(headerNumberKey(hash))] = make([]byte, 9)
			case "canonical-mismatch":
				d.view.data[string(headerHashKey(7))] = common.HexToHash("0x42").Bytes()
			case "view-change":
				d.view.changeID = true
			}
			s := openRecentFixture(t, d, ethdb.DefaultBrowserSnapshotLimits())
			if _, err := s.ReadRecentHead(context.Background()); err == nil {
				t.Fatal("malformed metadata accepted")
			}
			if d.view.closed.Load() != 1 || d.gets != 0 {
				t.Fatalf("close=%d ordinary=%d", d.view.closed.Load(), d.gets)
			}
		})
	}
}
func TestRecentSharedRecordAndReturnedBudgets(t *testing.T) {
	for _, which := range []string{"reads", "bytes"} {
		t.Run(which, func(t *testing.T) {
			d, _ := recentFixture(7, "")
			l := ethdb.DefaultBrowserSnapshotLimits()
			if which == "reads" {
				l.MaxRecordReads = 2
			} else {
				l.MaxReturnedBytes = 71
			}
			s := openRecentFixture(t, d, l)
			if _, err := s.ReadRecentHead(context.Background()); !errors.Is(err, ethdb.ErrBrowserSnapshotLimit) {
				t.Fatal(err)
			}
			if s.returned != 40 || d.view.closed.Load() != 1 {
				t.Fatalf("ledger %d close %d", s.returned, d.view.closed.Load())
			}
		})
	}
}
func TestRecentNestedTablePrefixesAndLimit(t *testing.T) {
	d, hash := recentFixture(7, "one/two/")
	db := NewTable(NewTable(NewDatabase(d), "one/"), "two/")
	s := openRecentFixture(t, db, ethdb.DefaultBrowserSnapshotLimits())
	if head, err := s.ReadRecentHead(context.Background()); err != nil || head.CanonicalHash != hash {
		t.Fatalf("%+v %v", head, err)
	}
	if d.view.keys[0] != "one/two/LastBlock" {
		t.Fatalf("physical key %q", d.view.keys[0])
	}
	// Prefix 480 + header-number 33 must be rejected before that physical read.
	d, _ = recentFixture(7, string(bytes.Repeat([]byte{'p'}, 480)))
	db = NewTable(NewDatabase(d), string(bytes.Repeat([]byte{'p'}, 480)))
	s = openRecentFixture(t, db, ethdb.DefaultBrowserSnapshotLimits())
	if _, err := s.ReadRecentHead(context.Background()); !errors.Is(err, ethdb.ErrBrowserSnapshotLimit) {
		t.Fatal(err)
	}
	if len(d.view.keys) != 1 {
		t.Fatalf("oversized prefixed key reached driver: %d reads", len(d.view.keys))
	}
}
func TestRecentCloseHeldReadRejectsLateResult(t *testing.T) {
	d, _ := recentFixture(7, "")
	entered := make(chan struct{})
	resume := make(chan struct{})
	d.view.entered, d.view.resume = entered, resume
	s := openRecentFixture(t, d, ethdb.DefaultBrowserSnapshotLimits())
	done := make(chan error, 1)
	go func() { _, err := s.ReadRecentHead(context.Background()); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("read did not enter")
	}
	_ = s.Close()
	if d.view.closed.Load() != 0 {
		t.Fatal("owned physical view released during active read")
	}
	close(resume)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("late read held")
	}
	if d.view.closed.Load() != 1 {
		t.Fatal("view not released exactly once")
	}
}
