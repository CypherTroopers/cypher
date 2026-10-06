// SPDX-License-Identifier: LGPL-3.0-or-later
package ethdb

import "context"

// BrowserRecentSnapshotCapabilityV1 adds only the two HOT KV metadata records
// needed to discover the full canonical head. It does not widen the original
// BrowserSnapshotCapabilityV1 record namespaces or permit a cold-store fallback.
const BrowserRecentSnapshotCapabilityV1 uint32 = 1

// BrowserRecentSnapshotter is optional and its version query must perform no IO.
// A supported NewBrowserSnapshot returns a BrowserRecentSnapshot using the same
// immutable view, lifetime, cancellation and monotonic budgets as ordinary V1.
type BrowserRecentSnapshotter interface {
	BrowserSnapshotter
	BrowserRecentSnapshotCapabilityVersion() uint32
}

// BrowserRecentSnapshot accepts only "head-block" (LastBlock, at most 32 bytes)
// and "header-number" (H + nonzero hash, at most 8 bytes). A bounded table prefix
// may be supplied only by an owner-created rawdb wrapper. Keys/kinds are never
// browser input. Exact value lengths and canonical equality are checked by rawdb.
type BrowserRecentSnapshot interface {
	BrowserSnapshot
	ReadBrowserRecentRecord(context.Context, []byte, string, int64) ([]byte, error)
}
