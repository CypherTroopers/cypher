// SPDX-License-Identifier: LGPL-3.0-or-later
package rawdb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"github.com/cypherium/cypher/ethdb"
	"io"
	"testing"
)

func browserBackend(t *testing.T) (*BrowserOwnedBackend, *browserFakeProvider) {
	t.Helper()
	p, _ := browserMock()
	b, e := NewBrowserOwnedBackend(p, ethdb.DefaultBrowserSnapshotLimits())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { b.Close() })
	return b, p
}
func TestBrowserOwnedWriterLazyAndPinnedSevenFields(t *testing.T) {
	b, p := browserBackend(t)
	if p.opens.Load() != 0 || p.view.reads.Load() != 0 || b.BrowserOwnedSnapshotCapabilityVersion() != 1 {
		t.Fatal("constructor touched DB")
	}
	var chain bytes.Buffer
	if e := b.WriteBrowserChainID(context.Background(), &chain, 8); e != nil || chain.Len() != 8 || binary.BigEndian.Uint64(chain.Bytes()) != 31 {
		t.Fatal("chainID", e)
	}
	var header, block bytes.Buffer
	if e := b.WriteBrowserHeaderRLP(context.Background(), 1, &header, 1024); e != nil {
		t.Fatal(e)
	}
	if e := b.WriteBrowserBlockRLP(context.Background(), 1, &block, 1024); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(block.Bytes(), []byte{0xc8, 0xc1, 0x01, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0}) {
		t.Fatal("Body framing/order wrong", block.Bytes())
	}
	if p.opens.Load() != 1 || p.dbClose.Load() != 0 {
		t.Fatal("job changed view/shared ownership")
	}
	b.Close()
	if p.view.closed.Load() != 1 {
		t.Fatal("view leak")
	}
}
func TestBrowserOwnedWriterJSONRejectsAmbiguityAndOverflow(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want error
	}{{`{"chainId":31,"chainId":32}`, ethdb.ErrBrowserSnapshotMalformed}, {`{"chainId":31,"x":{"a":1,"a":2}}`, ethdb.ErrBrowserSnapshotMalformed}, {`{"chain\u0049d":31,"chainId":31}`, ethdb.ErrBrowserSnapshotMalformed}, {`{"chainId":18446744073709551616}`, ethdb.ErrBrowserSnapshotUnsupported}, {`{"chainId":-1}`, ethdb.ErrBrowserSnapshotUnsupported}, {`{"chainId":3.1e1}`, ethdb.ErrBrowserSnapshotUnsupported}, {`{"chainId":"31"}`, ethdb.ErrBrowserSnapshotUnsupported}, {`{"x":31}`, ethdb.ErrBrowserSnapshotMissing}} {
		b, p := browserBackend(t)
		for k, r := range p.view.values {
			if r.kind == "" {
				r.value = []byte(tc.raw)
				p.view.values[k] = r
			}
		}
		var out bytes.Buffer
		if e := b.WriteBrowserChainID(context.Background(), &out, 8); !errors.Is(e, tc.want) || out.Len() != 0 || p.view.closed.Load() != 1 {
			t.Fatal(tc.raw, e, out.Len())
		}
	}
}
func TestBrowserOwnedWriterPreflightRejectsBodyAndOutputBeforeWrite(t *testing.T) {
	for _, body := range [][]byte{{0xc0}, {0xc5, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0}, {0xc7, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0}, {0xc6, 0x80, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0}, {0xf8, 0x01, 0xc0}} {
		b, p := browserBackend(t)
		for k, r := range p.view.values {
			if r.kind == freezerBodiesTable {
				r.value = body
				p.view.values[k] = r
			}
		}
		var out bytes.Buffer
		if e := b.WriteBrowserBlockRLP(context.Background(), 1, &out, 1024); !errors.Is(e, ethdb.ErrBrowserSnapshotMalformed) || out.Len() != 0 {
			t.Fatal(body, e, out.Bytes())
		}
	}
	b, p := browserBackend(t)
	var out bytes.Buffer
	if e := b.WriteBrowserBlockRLP(context.Background(), 1, &out, 8); !errors.Is(e, ethdb.ErrBrowserSnapshotLimit) || out.Len() != 0 || p.view.closed.Load() != 1 {
		t.Fatal("output cap", e)
	}
	b, p = browserBackend(t)
	if e := b.WriteBrowserChainID(context.Background(), &out, 7); !errors.Is(e, ethdb.ErrBrowserSnapshotLimit) || p.opens.Load() != 0 {
		t.Fatal("8-byte bound opened DB", e)
	}
}

type browserCancelWriter struct {
	cancel context.CancelFunc
	writes int
}

func (w *browserCancelWriter) Write(p []byte) (int, error) {
	w.writes++
	w.cancel()
	return len(p), nil
}

type browserShortWriter struct{}

func (browserShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestBrowserOwnedWriterLateCancellationAndShortWriterAreTerminal(t *testing.T) {
	b, p := browserBackend(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &browserCancelWriter{cancel: cancel}
	if e := b.WriteBrowserBlockRLP(ctx, 1, out, 1024); !errors.Is(e, context.Canceled) || out.writes != 1 || p.view.closed.Load() != 1 {
		t.Fatal("late write accepted", e)
	}
	if e := b.WriteBrowserBlockRLP(context.Background(), 1, io.Discard, 1024); !errors.Is(e, ethdb.ErrBrowserSnapshotClosed) {
		t.Fatal("cancelled job reused", e)
	}
	b, p = browserBackend(t)
	if e := b.WriteBrowserHeaderRLP(context.Background(), 1, browserShortWriter{}, 1024); !errors.Is(e, io.ErrShortWrite) || p.view.closed.Load() != 1 {
		t.Fatal("short writer", e)
	}
}
func TestBrowserOwnedWriterStructuralWorkMonotonicNoRetry(t *testing.T) {
	p, _ := browserMock()
	limits := ethdb.DefaultBrowserSnapshotLimits()
	limits.MaxWork = 4
	b, e := NewBrowserOwnedBackend(p, limits)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	var out bytes.Buffer
	if e = b.WriteBrowserBlockRLP(context.Background(), 1, &out, 1024); !errors.Is(e, ethdb.ErrBrowserSnapshotLimit) || out.Len() != 0 {
		t.Fatal("unbounded structural nodes", e)
	}
	reads := p.view.reads.Load()
	if e = b.WriteBrowserBlockRLP(context.Background(), 1, io.Discard, 1024); !errors.Is(e, ethdb.ErrBrowserSnapshotClosed) || reads != p.view.reads.Load() {
		t.Fatal("budget refunded/retried", e)
	}
}

func TestBrowserOwnedWriterPrimitiveContextDoesNotOwnLeaseLifetime(t *testing.T) {
	b, p := browserBackend(t)
	ctx, cancel := context.WithCancel(context.Background())
	var id bytes.Buffer
	if e := b.WriteBrowserChainID(ctx, &id, 8); e != nil {
		t.Fatal(e)
	}
	cancel()
	var header bytes.Buffer
	if e := b.WriteBrowserHeaderRLP(context.Background(), 1, &header, 1024); e != nil || p.opens.Load() != 1 {
		t.Fatal("first primitive ctx canceled lifetime", e)
	}
	fresh, other := browserBackend(t)
	b.Close()
	if e := fresh.WriteBrowserHeaderRLP(context.Background(), 1, io.Discard, 1024); e != nil || other.view.closed.Load() != 0 {
		t.Fatal("old Close canceled independent job", e)
	}
}
func TestBrowserOwnedWriterHeaderCapBeforeDriverCopy(t *testing.T) {
	b, p := browserBackend(t)
	var out bytes.Buffer
	if e := b.WriteBrowserHeaderRLP(context.Background(), 1, &out, 1); !errors.Is(e, ethdb.ErrBrowserSnapshotLimit) || out.Len() != 0 {
		t.Fatal("low cap copied header", e)
	}
	// Only the preceding exact canonical value was returned; no header copy.
	if p.view.returned != 32 || p.view.closed.Load() != 1 {
		t.Fatal("header input cap was post-copy", p.view.returned)
	}
}

type browserHeldWriter struct{ entered, release chan struct{} }

func (w *browserHeldWriter) Write(p []byte) (int, error) {
	close(w.entered)
	<-w.release
	return len(p), nil
}
func TestBrowserOwnedWriterCloseRetainsViewThroughActualWriteReturn(t *testing.T) {
	b, p := browserBackend(t)
	out := &browserHeldWriter{make(chan struct{}), make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- b.WriteBrowserBlockRLP(context.Background(), 1, out, 1024) }()
	<-out.entered
	b.Close()
	if p.view.closed.Load() != 0 {
		t.Fatal("whole writer view released early")
	}
	close(out.release)
	if e := <-done; !errors.Is(e, context.Canceled) {
		t.Fatal("late writer accepted", e)
	}
	if p.view.closed.Load() != 1 || p.dbClose.Load() != 0 {
		t.Fatal("whole writer owned view not released exactly once")
	}
}
func TestBrowserOwnedWriterBlockCapBeforeDriverCopies(t *testing.T) {
	b, p := browserBackend(t)
	var out bytes.Buffer
	if e := b.WriteBrowserBlockRLP(context.Background(), 1, &out, 8); !errors.Is(e, ethdb.ErrBrowserSnapshotLimit) || out.Len() != 0 {
		t.Fatal("small block cap escaped", e)
	}
	// Reserve six mandatory one-byte body lists plus outer prefix. Only the
	// canonical record may be copied; even this two-byte header exceeds cap.
	if p.view.returned != 32 || p.view.reads.Load() != 2 {
		t.Fatal("block header copied before limit", p.view.returned)
	}
	b, p = browserBackend(t)
	for k, r := range p.view.values {
		if r.kind == freezerBodiesTable {
			r.value = []byte{0xc7, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0}
			p.view.values[k] = r
		}
	}
	if e := b.WriteBrowserBlockRLP(context.Background(), 1, &out, 9); !errors.Is(e, ethdb.ErrBrowserSnapshotLimit) || p.view.returned != 34 {
		t.Fatal("body input cap was post-copy", e, p.view.returned)
	}
}
