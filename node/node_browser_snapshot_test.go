// SPDX-License-Identifier: LGPL-3.0-or-later
package node

import (
	"context"
	"errors"
	"testing"

	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/ethdb"
)

type trackingSnapshotFixture struct{ closes int }

func (*trackingSnapshotFixture) BrowserViewID() [32]byte { return [32]byte{1} }
func (*trackingSnapshotFixture) ReadBrowserRecord(context.Context, []byte, string, uint64, int64) ([]byte, error) {
	return nil, ethdb.ErrBrowserSnapshotMissing
}
func (*trackingSnapshotFixture) ReadBrowserRecentRecord(context.Context, []byte, string, int64) ([]byte, error) {
	return nil, ethdb.ErrBrowserSnapshotMissing
}
func (v *trackingSnapshotFixture) Close() error { v.closes++; return nil }

type trackingSnapshotDatabase struct {
	ethdb.Database
	baseVersion, recentVersion uint32
	opens, closes, ordinary    int
	view                       *trackingSnapshotFixture
	ctx                        context.Context
	limits                     ethdb.BrowserSnapshotLimits
}

func (d *trackingSnapshotDatabase) BrowserSnapshotCapabilityVersion() uint32 { return d.baseVersion }
func (d *trackingSnapshotDatabase) BrowserRecentSnapshotCapabilityVersion() uint32 {
	return d.recentVersion
}
func (d *trackingSnapshotDatabase) NewBrowserSnapshot(ctx context.Context, limits ethdb.BrowserSnapshotLimits) (ethdb.BrowserSnapshot, error) {
	d.opens++
	d.ctx, d.limits = ctx, limits
	return d.view, nil
}
func (d *trackingSnapshotDatabase) Get([]byte) ([]byte, error) {
	d.ordinary++
	return nil, errors.New("ordinary database read forbidden")
}
func (d *trackingSnapshotDatabase) Ancient(string, uint64) ([]byte, error) {
	d.ordinary++
	return nil, errors.New("ancient database read forbidden")
}
func (d *trackingSnapshotDatabase) Close() error { d.closes++; return nil }

func TestCloseTrackingDatabasePreservesOwnedBrowserSnapshots(t *testing.T) {
	d := &trackingSnapshotDatabase{baseVersion: 1, recentVersion: 1, view: new(trackingSnapshotFixture)}
	n := &Node{databases: make(map[*closeTrackingDB]struct{})}
	wrapped := n.wrapDatabase(d)
	capability, ok := wrapped.(ethdb.BrowserRecentSnapshotter)
	if !ok || capability.BrowserSnapshotCapabilityVersion() != 1 || capability.BrowserRecentSnapshotCapabilityVersion() != 1 || d.opens != 0 {
		t.Fatal("node wrapper lost the driver capability or queried it with I/O")
	}
	limits := ethdb.DefaultBrowserSnapshotLimits()
	limits.MaxValueBytes, limits.MaxRecordReads = 8192, 128
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lease, err := rawdb.OpenBrowserRecentStoreLease(ctx, wrapped, limits)
	if err != nil {
		t.Fatal("actual rawdb recent source cannot cross the node wrapper", err)
	}
	if d.opens != 1 || d.ctx != ctx || d.limits != limits || lease.BrowserViewID() != d.view.BrowserViewID() || d.ordinary != 0 {
		t.Fatal("wrapper changed the owned view, context, budgets or read path")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	_ = lease.Close()
	if d.view.closes != 1 || d.closes != 0 || len(n.databases) != 1 {
		t.Fatal("closing the owned view closed or detached the shared database")
	}
	if err := wrapped.Close(); err != nil || d.closes != 1 || len(n.databases) != 0 {
		t.Fatal("ordinary database ownership changed", err)
	}
}

func TestCloseTrackingDatabaseRejectsUnsupportedBrowserSnapshots(t *testing.T) {
	for _, d := range []ethdb.Database{nil, (*trackingSnapshotDatabase)(nil), rawdb.NewMemoryDatabase(),
		&trackingSnapshotDatabase{baseVersion: 0, recentVersion: 1},
		&trackingSnapshotDatabase{baseVersion: 2, recentVersion: 1},
	} {
		wrapped := &closeTrackingDB{Database: d}
		if wrapped.BrowserSnapshotCapabilityVersion() != 0 || wrapped.BrowserRecentSnapshotCapabilityVersion() != 0 {
			t.Fatal("unsupported driver was advertised")
		}
		if _, err := wrapped.NewBrowserSnapshot(context.Background(), ethdb.DefaultBrowserSnapshotLimits()); !errors.Is(err, ethdb.ErrBrowserSnapshotUnsupported) {
			t.Fatal("unsupported driver was opened", err)
		}
		if fixture, ok := d.(*trackingSnapshotDatabase); ok && fixture != nil && (fixture.opens != 0 || fixture.ordinary != 0) {
			t.Fatal("unsupported path touched storage")
		}
		if d != nil && !nilBrowserSnapshotValue(d) {
			_ = d.Close()
		}
	}
	var nilWrapper *closeTrackingDB
	if nilWrapper.BrowserSnapshotCapabilityVersion() != 0 || nilWrapper.BrowserRecentSnapshotCapabilityVersion() != 0 {
		t.Fatal("nil wrapper advertises a source")
	}
	if _, err := nilWrapper.NewBrowserSnapshot(context.Background(), ethdb.DefaultBrowserSnapshotLimits()); !errors.Is(err, ethdb.ErrBrowserSnapshotUnsupported) {
		t.Fatal("nil wrapper opened a source", err)
	}
	for _, version := range []uint32{0, 2} {
		d := &trackingSnapshotDatabase{baseVersion: 1, recentVersion: version}
		wrapped := &closeTrackingDB{Database: d}
		if wrapped.BrowserSnapshotCapabilityVersion() != 1 || wrapped.BrowserRecentSnapshotCapabilityVersion() != 0 {
			t.Fatal("base and recent capabilities were conflated")
		}
		if _, err := rawdb.OpenBrowserRecentStoreLease(context.Background(), wrapped, ethdb.DefaultBrowserSnapshotLimits()); !errors.Is(err, ethdb.ErrBrowserSnapshotUnsupported) || d.opens != 0 {
			t.Fatal("unsupported recent view was acquired", err)
		}
	}
}

type trackingNilContext struct{ context.Context }

func TestCloseTrackingDatabaseValidatesSnapshotContextAndLimits(t *testing.T) {
	d := &trackingSnapshotDatabase{baseVersion: 1, recentVersion: 1, view: new(trackingSnapshotFixture)}
	wrapped := &closeTrackingDB{Database: d}
	limits := ethdb.DefaultBrowserSnapshotLimits()
	for _, ctx := range []context.Context{nil, (*trackingNilContext)(nil)} {
		if _, err := wrapped.NewBrowserSnapshot(ctx, limits); !errors.Is(err, ethdb.ErrBrowserSnapshotMalformed) {
			t.Fatal("nil context reached source", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := wrapped.NewBrowserSnapshot(ctx, limits); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled context reached source", err)
	}
	limits.MaxRecordReads = 0
	if _, err := wrapped.NewBrowserSnapshot(context.Background(), limits); !errors.Is(err, ethdb.ErrBrowserSnapshotLimit) {
		t.Fatal("invalid limit reached source", err)
	}
	if d.opens != 0 || d.ordinary != 0 || d.closes != 0 {
		t.Fatal("invalid requests changed source ownership")
	}
}
