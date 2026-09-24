package reconfig_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cypherium/cypher/dex/engine"
)

// This selector observes finality; a certified source import cannot authorize
// planning its successor. Existing55/57 slots remain bounded and may fail short.
func continuousFlatChoice(certified, finalized, height, lastInbox, cursor, expected uint64) (string, error) {
	if height == 0 || finalized > certified || lastInbox > certified || cursor > expected || certified < height-1 {
		return "", errors.New("flat source observation bound")
	}
	if certified >= height {
		return "existing-CDXA", nil
	}
	if cursor < expected && lastInbox <= finalized {
		return "await-CDXA", nil
	}
	return "signed-descendant", nil
}

func (e *continuousEconomy) flatSourceSlot(t *testing.T, height, lastInbox, expected uint64) uint64 {
	t.Helper()
	if height != 55 && height != 57 {
		t.Fatal("flat extension can only use existing55/57 slots")
	}
	f := e.fixture
	certified, finalized := f.minimumHeight(t)
	_, market := f.financial(t, finalized)
	choice, err := continuousFlatChoice(certified, finalized, height, lastInbox, market.InboxCursor, expected)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("CONTINUOUS_FLAT_SLOT height=%d choice=%s certified=%d finalized=%d previousInbox=%d cursor=%d expected=%d", height, choice, certified, finalized, lastInbox, market.InboxCursor, expected)
	if choice == "signed-descendant" {
		f.admit(t, height, f.sign(t, 2, engine.Noop, nil))
		return lastInbox
	}
	if choice == "await-CDXA" {
		f.waitDEX(t, height, 0)
	}
	record := f.certifiedRecord(t, height)
	if record == nil || !bytes.HasPrefix(record.Actions, []byte("CDXA")) {
		t.Fatal("unexpected action in reserved flat source slot")
	}
	return height
}

func TestContinuousFlatSourceSlotsRespectFinality(t *testing.T) {
	tests := []struct {
		name                         string
		cert, final, h, last, cursor uint64
		want                         string
	}{
		{"unfinalized53_needs55_descendant", 54, 52, 55, 53, 6, "signed-descendant"},
		{"finalized53_can_source55", 54, 53, 55, 53, 6, "await-CDXA"},
		{"real_commit56_finalizes_prior_source", 56, 55, 57, 55, 6, "await-CDXA"},
		{"view_gap_at56_requires57_descendant", 56, 54, 57, 55, 6, "signed-descendant"},
		{"completed_cursor_uses_existing_noop", 54, 53, 55, 53, 8, "signed-descendant"},
		{"already_certified_source_still_needs_record_check", 55, 53, 55, 53, 6, "existing-CDXA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := continuousFlatChoice(tt.cert, tt.final, tt.h, tt.last, tt.cursor, 8)
			if err != nil || got != tt.want {
				t.Fatal(got, err)
			}
		})
	}
	for _, args := range [][5]uint64{{54, 55, 55, 53, 6}, {54, 53, 55, 56, 6}, {54, 53, 55, 53, 9}, {53, 51, 55, 53, 6}} {
		if _, err := continuousFlatChoice(args[0], args[1], args[2], args[3], args[4], 8); err == nil {
			t.Fatal("invalid observation accepted", args)
		}
	}
}

func TestContinuousFlatSlotCapacityDoesNotAssumeFinality(t *testing.T) {
	// Retained trial10 starting shape and a finality gap at54. This simulation
	// is slot arithmetic, not a substitute for authenticating the real entries.
	for _, tt := range []struct {
		name         string
		deposit      uint64
		wantComplete bool
	}{
		{"late_deposit_needs_two_updates_but_only_one_available", 268, false},
		{"earlier_deposit_is_already_covered_by_observed_prefix", 245, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source, cursor, last := uint64(247), uint64(6), uint64(53)
			if source >= tt.deposit {
				cursor = 8
			}
			for _, observation := range [][3]uint64{{54, 52, 55}, {56, 55, 57}} {
				choice, err := continuousFlatChoice(observation[0], observation[1], observation[2], last, cursor, 8)
				if err != nil {
					t.Fatal(err)
				}
				if choice == "await-CDXA" {
					source += 16 // retained proof-sizing case, not an enlarged cap
					last = observation[2]
					if source >= tt.deposit {
						cursor = 8
					}
				}
			}
			if (cursor == 8) != tt.wantComplete {
				t.Fatalf("cursor=%d source=%d wantComplete=%v", cursor, source, tt.wantComplete)
			}
		})
	}
}
