// SPDX-License-Identifier: LGPL-3.0-or-later
package ethdb

import (
	"context"
	"errors"
)

const BrowserSnapshotCapabilityV1 uint32 = 1
const MaxBrowserRecordKeyBytes = 512

var (
	ErrBrowserSnapshotUnsupported  = errors.New("strict owned browser snapshot unsupported")
	ErrBrowserSnapshotLimit        = errors.New("strict browser snapshot budget exhausted")
	ErrBrowserSnapshotMissing      = errors.New("browser snapshot record unavailable")
	ErrBrowserSnapshotInconsistent = errors.New("browser snapshot view changed")
	ErrBrowserSnapshotClosed       = errors.New("browser snapshot lease closed")
	ErrBrowserSnapshotMalformed    = errors.New("browser snapshot record malformed")
)

// BrowserSnapshotLimits may only tighten these finite payload budgets. The
// strict driver charges storage/payload-dependent allocations before copying,
// reading a proportional compressed buffer or decompressing. AllocationBytes
// is a monotonic lifetime sum of compressed, decoded, returned/copy and driver
// key buffers, not a Get-after-len check. Fixed bookkeeping and wrapper keys
// (at most 512 bytes) are separate. Stored/Decoded are cumulative, Value is
// per-record and must be applied BEFORE copying (WithValueLimit equivalent).
// MaxRecordReads counts ReadBrowserRecord requests, not provider's 98 runs or
// physical disk I/O. Opening the view must also honor AllocationBytes and ctx.
type BrowserSnapshotLimits struct {
	MaxStoredBytes     int64
	MaxDecodedBytes    int64
	MaxValueBytes      int64
	MaxReturnedBytes   int64
	MaxAllocationBytes int64
	MaxKeyBytes        int64
	MaxWork            int64
	MaxRecordReads     int
}

func DefaultBrowserSnapshotLimits() BrowserSnapshotLimits {
	return BrowserSnapshotLimits{128 << 20, 128 << 20, 32 << 20, 128 << 20, 256 << 20, 512, 65536, 256}
}
func (l BrowserSnapshotLimits) Validate() error {
	h := DefaultBrowserSnapshotLimits()
	if l.MaxStoredBytes <= 0 || l.MaxStoredBytes > h.MaxStoredBytes || l.MaxDecodedBytes <= 0 || l.MaxDecodedBytes > h.MaxDecodedBytes || l.MaxValueBytes <= 0 || l.MaxValueBytes > h.MaxValueBytes || l.MaxReturnedBytes <= 0 || l.MaxReturnedBytes > h.MaxReturnedBytes || l.MaxAllocationBytes <= 0 || l.MaxAllocationBytes > h.MaxAllocationBytes || l.MaxKeyBytes <= 0 || l.MaxKeyBytes > h.MaxKeyBytes || l.MaxWork <= 0 || l.MaxWork > h.MaxWork || l.MaxRecordReads <= 0 || l.MaxRecordReads > h.MaxRecordReads {
		return ErrBrowserSnapshotLimit
	}
	return nil
}

// BrowserSnapshotter is OPTIONAL; Database and ordinary Get/Ancient are
// unchanged. Version 1 is an explicit trusted driver contract, not evidence of
// committee/finality authentication. Absent/other version must fail before
// ordinary Get/Ancient/GetSnapshot/iterator/decode. Version querying does no IO.
type BrowserSnapshotter interface {
	BrowserSnapshotCapabilityVersion() uint32
	NewBrowserSnapshot(context.Context, BrowserSnapshotLimits) (BrowserSnapshot, error)
}

// BrowserSnapshot owns one consistent immutable HOT KV store view, including
// canonical mapping and every header byte (SignInfo/QC included), body/config.
// Version one uses ONLY the KV key. Ancient kind/height are validated rawdb
// hints, never routing to Ancient/cold fallback. Records already moved from
// hot KV return Missing. A snapshot retains its captured sequence when later
// freezer writes delete hot keys. All records use the same fixed hot view.
// Unsupported namespaces fail
// before payload IO. ViewID is an immutable nonzero consistency marker only.
// Returned bytes transfer exclusively to the caller and remain unchanged by
// subsequent reads/Close; driver retains no mutable alias. Context is checked
// before/after bounded operations; no force-interruption of OS reads promised.
// Budgets are driver-owned monotonic charges, never refunded on cancellation
// or error. Ordinary Get/Snapshot.Get wrapped by len checks does not qualify.
// The creation context governs creation only; returned view lifetime is Close.
// Close is idempotent, releases this view only, never shared DB/node ownership.
type BrowserSnapshot interface {
	BrowserViewID() [32]byte
	ReadBrowserRecord(context.Context, []byte, string, uint64, int64) ([]byte, error)
	Close() error
}
