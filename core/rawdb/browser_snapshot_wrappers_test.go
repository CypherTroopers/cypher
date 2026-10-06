// SPDX-License-Identifier: LGPL-3.0-or-later
package rawdb

import (
	"context"
	"errors"
	"github.com/cypherium/cypher/ethdb"
	"strings"
	"sync/atomic"
	"testing"
)

type browserCapKV struct {
	ethdb.KeyValueStore
	*browserFakeProvider
}

func (p *browserCapKV) Close() error { return p.browserFakeProvider.Close() }

type browserForbiddenAncient struct {
	ethdb.AncientStore
	calls atomic.Int32
}

func (a *browserForbiddenAncient) Ancient(string, uint64) ([]byte, error) {
	a.calls.Add(1)
	panic("version-one hot view touched Ancient")
}
func TestBrowserDatabaseWrappersExplicitCapabilities(t *testing.T) {
	p, _ := browserMock()
	kv := &browserCapKV{browserFakeProvider: p}
	db := NewDatabase(kv)
	s, e := OpenBrowserStoreLease(context.Background(), db, ethdb.DefaultBrowserSnapshotLimits())
	if e != nil {
		t.Fatal("nofreeze capability lost", e)
	}
	if _, e = s.ReadCanonical(context.Background(), 1); e != nil {
		t.Fatal(e)
	}
	s.Close()
	if p.dbClose.Load() != 0 {
		t.Fatal("borrowed DB closed")
	}
	p, _ = browserMock()
	cold := &browserForbiddenAncient{}
	fr := &freezerdb{KeyValueStore: &browserCapKV{browserFakeProvider: p}, AncientStore: cold}
	s, e = OpenBrowserStoreLease(context.Background(), fr, ethdb.DefaultBrowserSnapshotLimits())
	if e != nil {
		t.Fatal("explicit hot-only freezer forward lost", e)
	}
	if _, e = s.ReadBlockRaw(context.Background(), 1); e != nil {
		t.Fatal(e)
	}
	s.Close()
	if cold.calls.Load() != 0 || p.dbClose.Load() != 0 {
		t.Fatal("hot-only scope touched freezer/shared DB")
	}
	p, _ = browserMock()
	delete(p.view.values, string(headerHashKey(1)))
	fr = &freezerdb{KeyValueStore: &browserCapKV{browserFakeProvider: p}, AncientStore: cold}
	s, e = OpenBrowserStoreLease(context.Background(), fr, ethdb.DefaultBrowserSnapshotLimits())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.ReadBlockRaw(context.Background(), 1); !errors.Is(e, ethdb.ErrBrowserSnapshotMissing) || cold.calls.Load() != 0 {
		t.Fatal("missing hot record used cold fallback", e)
	}
}
func TestBrowserPrefixWrapperBoundedAndOwnedLeaseOnly(t *testing.T) {
	p, _ := browserMock()
	v := p.view
	prefixed := make(map[string]browserFakeRecord, len(v.values))
	for k, value := range v.values {
		prefixed["p/"+k] = value
	}
	v.values = prefixed
	db := NewTable(NewDatabase(&browserCapKV{browserFakeProvider: p}), "p/")
	s, e := OpenBrowserStoreLease(context.Background(), db, ethdb.DefaultBrowserSnapshotLimits())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ReadBlockRaw(context.Background(), 1); e != nil {
		t.Fatal("prefix/schema forward lost", e)
	}
	s.Close()
	s.Close()
	if v.closed.Load() != 1 || p.dbClose.Load() != 0 {
		t.Fatal("prefix lease/shared DB ownership changed")
	}
	p, _ = browserMock()
	oversized := NewTable(NewDatabase(&browserCapKV{browserFakeProvider: p}), strings.Repeat("p", ethdb.MaxBrowserRecordKeyBytes+1))
	if _, e = OpenBrowserStoreLease(context.Background(), oversized, ethdb.DefaultBrowserSnapshotLimits()); !errors.Is(e, ethdb.ErrBrowserSnapshotUnsupported) || p.opens.Load() != 0 {
		t.Fatal("oversized prefix read storage", e)
	}
}
func TestBrowserFreezerDeletionAfterCapturedHotSnapshot(t *testing.T) {
	p, _ := browserMock()
	p.capture = true
	cold := &browserForbiddenAncient{}
	fr := &freezerdb{KeyValueStore: &browserCapKV{browserFakeProvider: p}, AncientStore: cold}
	s, e := OpenBrowserStoreLease(context.Background(), fr, ethdb.DefaultBrowserSnapshotLimits())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	// Model deletion by a freezer after snapshot sequence capture. The owned
	// snapshot retains its independent immutable values; no writer pin needed.
	for k := range p.view.values {
		delete(p.view.values, k)
	}
	if _, e = s.ReadBlockRaw(context.Background(), 1); e != nil || cold.calls.Load() != 0 {
		t.Fatal("captured hot sequence lost/used Ancient", e)
	}
	next, e := OpenBrowserStoreLease(context.Background(), fr, ethdb.DefaultBrowserSnapshotLimits())
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	if _, e = next.ReadBlockRaw(context.Background(), 1); !errors.Is(e, ethdb.ErrBrowserSnapshotMissing) || cold.calls.Load() != 0 {
		t.Fatal("new missing hot snapshot fell back", e)
	}
}
