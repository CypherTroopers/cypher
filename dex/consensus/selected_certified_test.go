package consensus

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func TestSelectedCertifiedDataFollowsQCAncestryAcrossHigherViewSibling(t *testing.T) {
	n := generationNetwork(t, 5)
	n.start(t)
	a := n.nodes[0]
	a.config.MaxHeight = 7
	parent := a.HighestCertified()
	older := generationPendingRecord(t, a, parent, 6, 1)
	older.QC = generationFixtureQC(t, n, older)
	newer := generationPendingRecord(t, a, parent, 7, 2)
	newer.QC = generationFixtureQC(t, n, newer)
	for _, r := range []*Record{older, newer} {
		if err := a.storeRecord(r); err != nil {
			t.Fatal(err)
		}
	}
	// Reproduce live height54: the next certified block extends the older
	// sibling QC. Independent highest-view selection at height6 splices forks.
	tip := generationPendingRecord(t, a, older.QC, 8, 1)
	tip.QC = generationFixtureQC(t, n, tip)
	if err := a.storeRecord(tip); err != nil {
		t.Fatal(err)
	}
	a.disk.Safety.HighestQC = hotstuff.CloneSignedState(tip.QC)
	tip = a.recordForQC(tip.QC) // storeRecord owns a clone; mutate that clone below.
	safety := hotstuff.CloneFHSSafetyState(a.disk.Safety)
	beforeFinalized := a.FinalizedHeight()
	for _, test := range []struct {
		name string
		read func(uint64) ([]byte, error)
		want *Record
	}{{"highest-per-height", a.LatestCertifiedData, newer}, {"selected-ancestor", a.SelectedCertifiedData, older}} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := test.read(6)
			var got Record
			if err != nil || json.Unmarshal(raw, &got) != nil || !hotstuff.SignedStateSemanticEqual(got.QC, test.want.QC) {
				t.Fatal("wrong branch selected", err)
			}
		})
	}
	if a.FinalizedHeight() != beforeFinalized || !reflect.DeepEqual(safety, a.disk.Safety) {
		t.Fatal("planning query changed safety or finality")
	}
	ref, err := types.DecodeHotstuffProposalRef(older.Ref)
	if err != nil {
		t.Fatal(err)
	}
	delete(a.disk.Records, ref.ProposalID().Hex())
	if _, err = a.SelectedCertifiedData(6); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing ancestor substituted with higher-view sibling", err)
	}
	a.disk.Records[ref.ProposalID().Hex()] = older
	original := bytes.Clone(tip.Ref)
	broken, err := types.DecodeHotstuffProposalRef(tip.Ref)
	if err != nil {
		t.Fatal(err)
	}
	broken.ParentQCID[0] ^= 1
	tip.Ref = broken.EncodeToBytes()
	if _, err = a.SelectedCertifiedData(6); err == nil {
		t.Fatal("altered parent binding accepted")
	}
	tip.Ref = original
	for _, height := range []uint64{0, 8} {
		if _, err = a.SelectedCertifiedData(height); !errors.Is(err, ErrUnavailable) {
			t.Fatal("out-of-range query accepted", height, err)
		}
	}
	// A corrupt oversized in-memory set cannot cause an unbounded ancestry
	// scan even though this public read does not modify the persistent store.
	for len(a.disk.Records) <= MaxRecords {
		a.disk.Records[fmt.Sprintf("invalid-%d", len(a.disk.Records))] = nil
	}
	if _, err = a.SelectedCertifiedData(6); !errors.Is(err, ErrUnavailable) {
		t.Fatal("oversized hot set was scanned", err)
	}
}

func TestSelectedCertifiedDataUsesAuthenticatedFinalizedArchive(t *testing.T) {
	n := generationNetwork(t, 6)
	for i := range n.nodes {
		n.nodes[i].wal.rotationInterval = 2
	}
	n.start(t)
	a := n.nodes[0]
	if a.disk.BaseHeight < 4 {
		t.Fatal("fixture did not rotate")
	}
	for _, height := range []uint64{1, 4, 5, 6} {
		raw, err := a.SelectedCertifiedData(height)
		var r Record
		if err != nil || json.Unmarshal(raw, &r) != nil || r.Checkpoint.Sequence != height {
			t.Fatal("selected cold/hot history unavailable", height, err)
		}
	}
}
