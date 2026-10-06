// SPDX-License-Identifier: LGPL-3.0-or-later
package rawdb

import (
	"context"
	"encoding/binary"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/ethdb"
)

func browserRecentCapability(db interface{}) (ethdb.BrowserRecentSnapshotter, error) {
	p, err := browserCapability(db)
	if err != nil {
		return nil, err
	}
	r, ok := p.(ethdb.BrowserRecentSnapshotter)
	if !ok || browserNil(r) || r.BrowserRecentSnapshotCapabilityVersion() != ethdb.BrowserRecentSnapshotCapabilityV1 {
		return nil, ethdb.ErrBrowserSnapshotUnsupported
	}
	return r, nil
}

// OpenBrowserRecentStoreLease rejects unsupported drivers before opening any
// view. Acquisition is for an admitted source request or an explicitly enabled
// bounded startup readiness check. It owns
// that view alone and never opens a second DB or calls ordinary Get/Ancient.
func OpenBrowserRecentStoreLease(ctx context.Context, db interface{}, limits ethdb.BrowserSnapshotLimits) (*BrowserStoreLease, error) {
	if _, err := browserRecentCapability(db); err != nil {
		return nil, err
	}
	s, err := OpenBrowserStoreLease(ctx, db, limits)
	if err != nil {
		return nil, err
	}
	if view, ok := s.view.(ethdb.BrowserRecentSnapshot); !ok || browserNil(view) {
		_ = s.Close()
		return nil, ethdb.ErrBrowserSnapshotUnsupported
	}
	s.recent = true
	return s, nil
}

type BrowserRecentHead struct {
	Number        uint64
	CanonicalHash common.Hash
	ViewID        [32]byte
}

// ReadRecentHead discovers LastBlock, its number and its canonical mapping in
// this one immutable HOT KV view. LastHeader/LastFast, caches, iterators and
// Ancient records are intentionally excluded. A missing/inconsistent view
// fails closed; it is not presented as an empty or connected chain.
func (s *BrowserStoreLease) ReadRecentHead(ctx context.Context) (BrowserRecentHead, error) {
	raw, err := s.recordWithNamespace(ctx, headBlockKey, "head-block", 0, 32, true)
	if err != nil {
		return BrowserRecentHead{}, err
	}
	if len(raw) != 32 || common.BytesToHash(raw) == (common.Hash{}) {
		_ = s.Close()
		return BrowserRecentHead{}, ethdb.ErrBrowserSnapshotMalformed
	}
	hash := common.BytesToHash(raw)
	raw, err = s.recordWithNamespace(ctx, headerNumberKey(hash), "header-number", 0, 8, true)
	if err != nil {
		return BrowserRecentHead{}, err
	}
	if len(raw) != 8 {
		_ = s.Close()
		return BrowserRecentHead{}, ethdb.ErrBrowserSnapshotMalformed
	}
	height := binary.BigEndian.Uint64(raw)
	canonical, err := s.ReadCanonical(ctx, height)
	if err != nil {
		return BrowserRecentHead{}, err
	}
	if canonical != hash {
		_ = s.Close()
		return BrowserRecentHead{}, ethdb.ErrBrowserSnapshotInconsistent
	}
	return BrowserRecentHead{height, hash, s.id}, nil
}
