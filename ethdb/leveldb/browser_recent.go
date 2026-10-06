//go:build !js && cypher_bounded_storage

// SPDX-License-Identifier: LGPL-3.0-or-later
package leveldb

import (
	"bytes"
	"context"
	"github.com/cypherium/cypher/ethdb"
)

func (db *Database) BrowserRecentSnapshotCapabilityVersion() uint32 {
	if db == nil || db.db == nil {
		return 0
	}
	return ethdb.BrowserRecentSnapshotCapabilityV1
}

func (s *browserBoundedSnapshot) ReadBrowserRecentRecord(ctx context.Context, key []byte, kind string, max int64) ([]byte, error) {
	if s == nil || browserAdapterNil(ctx) {
		return nil, ethdb.ErrBrowserSnapshotMalformed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(key) == 0 || int64(len(key)) > s.limits.MaxKeyBytes || max <= 0 {
		return nil, ethdb.ErrBrowserSnapshotLimit
	}
	cap := browserRecentKeyCap(key, kind)
	if cap == 0 {
		return nil, ethdb.ErrBrowserSnapshotUnsupported
	}
	if max > cap {
		max = cap
	}
	return s.readBrowserKey(ctx, key, max)
}

func browserRecentKeyCap(key []byte, kind string) int64 {
	switch kind {
	case "head-block":
		if bytes.HasSuffix(key, []byte("LastBlock")) {
			return 32
		}
	case "header-number":
		if len(key) >= 33 {
			tail := key[len(key)-33:]
			if tail[0] == 'H' && !bytes.Equal(tail[1:], make([]byte, 32)) {
				return 8
			}
		}
	}
	return 0
}
