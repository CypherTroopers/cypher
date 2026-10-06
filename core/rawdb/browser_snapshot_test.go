// SPDX-License-Identifier: LGPL-3.0-or-later
package rawdb

import (
	"bytes"
	"context"
	"errors"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/ethdb"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type browserFakeRecord struct {
	kind   string
	height uint64
	value  []byte
}
type browserFakeView struct {
	mu                                       sync.Mutex
	id                                       [32]byte
	values                                   map[string]browserFakeRecord
	reads, closed                            atomic.Int32
	entered, release                         chan struct{}
	change                                   bool
	limits                                   ethdb.BrowserSnapshotLimits
	charged, stored, decoded, returned, work int64
}

func (v *browserFakeView) BrowserViewID() [32]byte { v.mu.Lock(); defer v.mu.Unlock(); return v.id }
func (v *browserFakeView) ReadBrowserRecord(ctx context.Context, key []byte, kind string, height uint64, max int64) ([]byte, error) {
	v.reads.Add(1)
	if v.entered != nil {
		close(v.entered)
		<-v.release
	} // deliberate late native return
	v.mu.Lock()
	defer v.mu.Unlock()
	r, ok := v.values[string(key)]
	if !ok {
		return nil, ethdb.ErrBrowserSnapshotMissing
	}
	if r.kind != kind || r.height != height {
		return nil, ethdb.ErrBrowserSnapshotInconsistent
	}
	// Mock strict seam: charge BEFORE allocation, never refunded.
	cost := int64(len(r.value))
	keyCost := int64(len(key))
	if cost > max || cost > v.limits.MaxValueBytes || keyCost > v.limits.MaxKeyBytes || v.charged+cost+keyCost > v.limits.MaxAllocationBytes || v.stored+cost > v.limits.MaxStoredBytes || v.decoded+cost > v.limits.MaxDecodedBytes || v.returned+cost > v.limits.MaxReturnedBytes || v.work+1 > v.limits.MaxWork {
		return nil, ethdb.ErrBrowserSnapshotLimit
	}
	v.charged += cost + keyCost
	v.stored += cost
	v.decoded += cost
	v.returned += cost
	v.work++
	raw := make([]byte, len(r.value))
	copy(raw, r.value)
	if v.change {
		v.id[0]++
	}
	return raw, nil
}
func (v *browserFakeView) Close() error { v.closed.Add(1); return nil }

type browserFakeProvider struct {
	view           *browserFakeView
	version        uint32
	opens, dbClose atomic.Int32
	err            error
	capture        bool
	last           *browserFakeView
}

func (p *browserFakeProvider) BrowserSnapshotCapabilityVersion() uint32 { return p.version }
func (p *browserFakeProvider) NewBrowserSnapshot(_ context.Context, l ethdb.BrowserSnapshotLimits) (ethdb.BrowserSnapshot, error) {
	p.opens.Add(1)
	if p.capture && p.view != nil {
		v := &browserFakeView{id: p.view.id, values: map[string]browserFakeRecord{}, limits: l}
		for k, r := range p.view.values {
			r.value = append([]byte(nil), r.value...)
			v.values[k] = r
		}
		p.last = v
		return v, p.err
	}
	if p.view != nil {
		p.view.limits = l
	}
	return p.view, p.err
}
func (p *browserFakeProvider) Close() error { p.dbClose.Add(1); return nil }
func browserMock() (*browserFakeProvider, common.Hash) {
	h := common.Hash{1}
	v := &browserFakeView{id: [32]byte{1}, values: map[string]browserFakeRecord{
		string(headerHashKey(0)): {freezerHashTable, 0, h.Bytes()}, string(headerHashKey(1)): {freezerHashTable, 1, h.Bytes()},
		string(headerKey(1, h)): {freezerHeaderTable, 1, []byte{0xc1, 0x01}}, string(blockBodyKey(1, h)): {freezerBodiesTable, 1, []byte{0xc6, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0}}, string(configKey(h)): {"", 0, []byte(`{"chainId":31}`)},
	}}
	return &browserFakeProvider{view: v, version: 1}, h
}
func TestBrowserStrictUnsupportedBeforeOpenReadDecode(t *testing.T) {
	p, _ := browserMock()
	p.version = 0
	for _, db := range []interface{}{nil, struct{}{}, p, (*browserFakeProvider)(nil)} {
		if _, e := OpenBrowserStoreLease(context.Background(), db, ethdb.DefaultBrowserSnapshotLimits()); !errors.Is(e, ethdb.ErrBrowserSnapshotUnsupported) {
			t.Fatal(e)
		}
	}
	if p.opens.Load() != 0 || p.view.reads.Load() != 0 {
		t.Fatal("unsupported path touched storage")
	}
	nilView := &browserFakeProvider{version: 1}
	if _, e := OpenBrowserStoreLease(context.Background(), nilView, ethdb.DefaultBrowserSnapshotLimits()); !errors.Is(e, ethdb.ErrBrowserSnapshotUnsupported) {
		t.Fatal("typed nil view accepted", e)
	}
}
func TestBrowserRawRecordsSingleViewOwnedBytesAndNoDBClose(t *testing.T) {
	p, h := browserMock()
	s, e := OpenBrowserStoreLease(context.Background(), p, ethdb.DefaultBrowserSnapshotLimits())
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.ReadBlockRaw(context.Background(), 1)
	if e != nil || b.CanonicalHash != h || b.ViewID != ([32]byte{1}) {
		t.Fatal(b, e)
	}
	config, e := s.ReadChainConfigRaw(context.Background())
	if e != nil || config.GenesisHash != h || !bytes.Equal(config.JSON, []byte(`{"chainId":31}`)) {
		t.Fatal(config, e)
	}
	b.HeaderRLP[1] = 9
	again, e := s.ReadHeaderRaw(context.Background(), 1)
	if e != nil || again.HeaderRLP[1] != 1 {
		t.Fatal("caller bytes alias retained storage", e)
	}
	retained := append([]byte(nil), again.HeaderRLP...)
	s.Close()
	s.Close()
	if p.view.closed.Load() != 1 || p.dbClose.Load() != 0 || !bytes.Equal(again.HeaderRLP, retained) {
		t.Fatal("Close changed owned bytes or borrowed DB ownership")
	}
	if _, e = s.ReadCanonical(context.Background(), 1); !errors.Is(e, ethdb.ErrBrowserSnapshotClosed) {
		t.Fatal("closed lease reread", e)
	}
}
func TestBrowserPartialLeaseAndChangedViewFailClosed(t *testing.T) {
	p, _ := browserMock()
	p.err = errors.New("mock partial open")
	if _, e := OpenBrowserStoreLease(context.Background(), p, ethdb.DefaultBrowserSnapshotLimits()); !errors.Is(e, p.err) || p.view.closed.Load() != 1 || p.dbClose.Load() != 0 {
		t.Fatal("partial owned view leaked", e)
	}
	p, _ = browserMock()
	p.view.change = true
	s, e := OpenBrowserStoreLease(context.Background(), p, ethdb.DefaultBrowserSnapshotLimits())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ReadCanonical(context.Background(), 1); !errors.Is(e, ethdb.ErrBrowserSnapshotInconsistent) {
		t.Fatal("changed view accepted", e)
	}
	if p.view.closed.Load() != 1 {
		t.Fatal("failed view not closed")
	}
	if _, e = s.ReadCanonical(context.Background(), 1); !errors.Is(e, ethdb.ErrBrowserSnapshotClosed) || p.view.reads.Load() != 1 {
		t.Fatal("failed view retried", e)
	}
}
func TestBrowserCloseRetainsInFlightOwnedViewUntilActualReturn(t *testing.T) {
	p, _ := browserMock()
	p.view.entered = make(chan struct{})
	p.view.release = make(chan struct{})
	defer func() {
		select {
		case <-p.view.release:
		default:
			close(p.view.release)
		}
	}()
	s, e := OpenBrowserStoreLease(context.Background(), p, ethdb.DefaultBrowserSnapshotLimits())
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := s.ReadCanonical(context.Background(), 1); done <- e }()
	select {
	case <-p.view.entered:
	case <-time.After(time.Second):
		t.Fatal("owned read not entered")
	}
	s.Close()
	if p.view.closed.Load() != 0 || p.dbClose.Load() != 0 {
		t.Fatal("inflight view/shared DB closed early")
	}
	if _, e = s.ReadCanonical(context.Background(), 1); !errors.Is(e, ethdb.ErrBrowserSnapshotClosed) {
		t.Fatal("read after Close", e)
	}
	close(p.view.release)
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal("late read accepted", e)
		}
	case <-time.After(time.Second):
		t.Fatal("owned read not returned")
	}
	if p.view.closed.Load() != 1 || p.dbClose.Load() != 0 {
		t.Fatal("owned view not released exactly once")
	}
}
func TestBrowserStorageBudgetAndCanonicalShape(t *testing.T) {
	p, _ := browserMock()
	l := ethdb.DefaultBrowserSnapshotLimits()
	l.MaxRecordReads = 1
	s, e := OpenBrowserStoreLease(context.Background(), p, l)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.ReadHeaderRaw(context.Background(), 1); !errors.Is(e, ethdb.ErrBrowserSnapshotLimit) || p.view.reads.Load() != 1 {
		t.Fatal("record budget escaped", e)
	}
	p, _ = browserMock()
	p.view.values[string(headerHashKey(1))] = browserFakeRecord{freezerHashTable, 1, []byte{1}}
	s, e = OpenBrowserStoreLease(context.Background(), p, ethdb.DefaultBrowserSnapshotLimits())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.ReadCanonical(context.Background(), 1); !errors.Is(e, ethdb.ErrBrowserSnapshotMalformed) {
		t.Fatal("canonical length not exact32", e)
	}
	if p.view.closed.Load() != 1 {
		t.Fatal("malformed canonical left lease open")
	}
}

func TestBrowserRawNilLeaseFailsWithoutPanic(t *testing.T) {
	var s *BrowserStoreLease
	if _, e := s.ReadHeaderRaw(context.Background(), 1); !errors.Is(e, ethdb.ErrBrowserSnapshotMalformed) {
		t.Fatal(e)
	}
	if _, e := s.ReadBlockRaw(context.Background(), 1); !errors.Is(e, ethdb.ErrBrowserSnapshotMalformed) {
		t.Fatal(e)
	}
}
