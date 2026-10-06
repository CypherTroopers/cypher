// SPDX-License-Identifier: LGPL-3.0-or-later
package rawdb

import (
	"context"
	"github.com/cypherium/cypher/ethdb"
	"sync"
)

func (db *nofreezedb) BrowserSnapshotCapabilityVersion() uint32 {
	if db == nil {
		return 0
	}
	p, e := browserCapability(db.KeyValueStore)
	if e != nil {
		return 0
	}
	return p.BrowserSnapshotCapabilityVersion()
}
func (db *nofreezedb) NewBrowserSnapshot(ctx context.Context, l ethdb.BrowserSnapshotLimits) (ethdb.BrowserSnapshot, error) {
	if db == nil {
		return nil, ethdb.ErrBrowserSnapshotUnsupported
	}
	p, e := browserCapability(db.KeyValueStore)
	if e != nil {
		return nil, e
	}
	return p.NewBrowserSnapshot(ctx, l)
}

// Version one explicitly captures HOT KV ONLY. Never touch Ancient/freezer or
// pin its writers. A previously moved/missing hot record is rejected. A later
// hot deletion does not mutate a strict snapshot's already captured sequence.
func (db *freezerdb) BrowserSnapshotCapabilityVersion() uint32 {
	if db == nil {
		return 0
	}
	p, e := browserCapability(db.KeyValueStore)
	if e != nil {
		return 0
	}
	return p.BrowserSnapshotCapabilityVersion()
}
func (db *freezerdb) NewBrowserSnapshot(ctx context.Context, l ethdb.BrowserSnapshotLimits) (ethdb.BrowserSnapshot, error) {
	if db == nil {
		return nil, ethdb.ErrBrowserSnapshotUnsupported
	}
	p, e := browserCapability(db.KeyValueStore)
	if e != nil {
		return nil, e
	}
	return p.NewBrowserSnapshot(ctx, l)
}

func (t *table) BrowserSnapshotCapabilityVersion() uint32 {
	if t == nil || len(t.prefix) > ethdb.MaxBrowserRecordKeyBytes {
		return 0
	}
	p, e := browserCapability(t.db)
	if e != nil {
		return 0
	}
	return p.BrowserSnapshotCapabilityVersion()
}
func (t *table) NewBrowserSnapshot(ctx context.Context, l ethdb.BrowserSnapshotLimits) (ethdb.BrowserSnapshot, error) {
	if t == nil || len(t.prefix) > ethdb.MaxBrowserRecordKeyBytes {
		return nil, ethdb.ErrBrowserSnapshotUnsupported
	}
	p, e := browserCapability(t.db)
	if e != nil {
		return nil, e
	}
	s, e := p.NewBrowserSnapshot(ctx, l)
	if e != nil {
		if !browserNil(s) {
			s.Close()
		}
		return nil, e
	}
	if browserNil(s) {
		return nil, ethdb.ErrBrowserSnapshotUnsupported
	}
	return &browserTableSnapshot{view: s, prefix: t.prefix, keyLimit: l.MaxKeyBytes}, nil
}

type browserTableSnapshot struct {
	view     ethdb.BrowserSnapshot
	prefix   string
	keyLimit int64
	once     sync.Once
	closeErr error
}

func (t *browserTableSnapshot) BrowserViewID() [32]byte { return t.view.BrowserViewID() }
func (t *browserTableSnapshot) ReadBrowserRecord(ctx context.Context, key []byte, kind string, height uint64, max int64) ([]byte, error) {
	if browserNil(ctx) {
		return nil, ethdb.ErrBrowserSnapshotMalformed
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if len(key) == 0 || int64(len(key)+len(t.prefix)) > t.keyLimit {
		return nil, ethdb.ErrBrowserSnapshotLimit
	}
	// The strict driver validates this hot KV namespace and rawdb record hints.
	// Version one must never route any hint to an Ancient/cold read.
	prefixed := make([]byte, len(t.prefix)+len(key))
	copy(prefixed, t.prefix)
	copy(prefixed[len(t.prefix):], key)
	return t.view.ReadBrowserRecord(ctx, prefixed, kind, height, max)
}
func (t *browserTableSnapshot) Close() error {
	t.once.Do(func() { t.closeErr = t.view.Close() })
	return t.closeErr
}
