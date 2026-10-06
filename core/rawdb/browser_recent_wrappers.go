// SPDX-License-Identifier: LGPL-3.0-or-later
package rawdb

import (
	"context"
	"github.com/cypherium/cypher/ethdb"
)

func (db *nofreezedb) BrowserRecentSnapshotCapabilityVersion() uint32 {
	if db == nil {
		return 0
	}
	p, err := browserRecentCapability(db.KeyValueStore)
	if err != nil {
		return 0
	}
	return p.BrowserRecentSnapshotCapabilityVersion()
}
func (db *freezerdb) BrowserRecentSnapshotCapabilityVersion() uint32 {
	if db == nil {
		return 0
	}
	p, err := browserRecentCapability(db.KeyValueStore)
	if err != nil {
		return 0
	}
	return p.BrowserRecentSnapshotCapabilityVersion()
}
func (t *table) BrowserRecentSnapshotCapabilityVersion() uint32 {
	if t == nil || len(t.prefix) > ethdb.MaxBrowserRecordKeyBytes {
		return 0
	}
	p, err := browserRecentCapability(t.db)
	if err != nil {
		return 0
	}
	return p.BrowserRecentSnapshotCapabilityVersion()
}
func (t *browserTableSnapshot) ReadBrowserRecentRecord(ctx context.Context, key []byte, kind string, max int64) ([]byte, error) {
	if t == nil || browserNil(ctx) {
		return nil, ethdb.ErrBrowserSnapshotMalformed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(key) == 0 || int64(len(key)) > t.keyLimit || int64(len(t.prefix)) > t.keyLimit-int64(len(key)) {
		return nil, ethdb.ErrBrowserSnapshotLimit
	}
	r, ok := t.view.(ethdb.BrowserRecentSnapshot)
	if !ok || browserNil(r) {
		return nil, ethdb.ErrBrowserSnapshotUnsupported
	}
	prefixed := make([]byte, len(t.prefix)+len(key))
	copy(prefixed, t.prefix)
	copy(prefixed[len(t.prefix):], key)
	return r.ReadBrowserRecentRecord(ctx, prefixed, kind, max)
}
