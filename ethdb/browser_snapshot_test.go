// SPDX-License-Identifier: LGPL-3.0-or-later
package ethdb

import (
	"errors"
	"testing"
)

func TestBrowserSnapshotLimitsTightenOnly(t *testing.T) {
	h := DefaultBrowserSnapshotLimits()
	if e := h.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*BrowserSnapshotLimits){func(l *BrowserSnapshotLimits) { l.MaxStoredBytes = 0 }, func(l *BrowserSnapshotLimits) { l.MaxDecodedBytes++ }, func(l *BrowserSnapshotLimits) { l.MaxValueBytes++ }, func(l *BrowserSnapshotLimits) { l.MaxReturnedBytes++ }, func(l *BrowserSnapshotLimits) { l.MaxAllocationBytes++ }, func(l *BrowserSnapshotLimits) { l.MaxKeyBytes++ }, func(l *BrowserSnapshotLimits) { l.MaxWork++ }, func(l *BrowserSnapshotLimits) { l.MaxRecordReads++ }} {
		x := h
		change(&x)
		if !errors.Is(x.Validate(), ErrBrowserSnapshotLimit) {
			t.Fatal("loosened/zero budget accepted")
		}
	}
	x := BrowserSnapshotLimits{1, 1, 1, 1, 1, 1, 1, 1}
	if e := x.Validate(); e != nil {
		t.Fatal("valid tight budget", e)
	}
}
