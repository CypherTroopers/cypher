package consensus

import (
	"testing"

	"github.com/cypherium/cypher/core/types"
)

// A finite workload can end immediately after a skipped-leader view. Its last
// QC is valid progress but cannot finalize a nonconsecutive parent edge. This
// reproduces the financial fault harness's former certified-1 assumption.
func TestFiniteWorkloadNeedsChildAfterSkippedLeaderViews(t *testing.T) {
	n := newNetwork(t, 6)
	n.dropped[n.nodes[5].Self()] = true
	n.dropped[n.nodes[6].Self()] = true
	n.start(t)
	for i, a := range n.nodes[:5] {
		if a.CertifiedHeight() != 5 || a.FinalizedHeight() != 4 {
			t.Fatalf("initial live node%d certified=%d finalized=%d", i, a.CertifiedHeight(), a.FinalizedHeight())
		}
	}
	for missed := 0; missed < 2; missed++ {
		for _, a := range n.nodes[:5] {
			if err := a.Timeout(); !benign(err) {
				t.Fatal(err)
			}
		}
		n.pump(t)
	}
	for i, a := range n.nodes[:5] {
		qc := a.disk.Safety.HighestQC
		ref, err := types.DecodeHotstuffProposalRef(qc.State)
		if err != nil {
			t.Fatal(err)
		}
		parent, err := a.parentQC(ref)
		if err != nil || qc.Number != 8 || parent.Number != 5 || a.CertifiedHeight() != 6 || a.FinalizedHeight() != 4 {
			t.Fatalf("view-gap node%d certified=%d finalized=%d tipView=%d parent=%+v err=%v", i, a.CertifiedHeight(), a.FinalizedHeight(), qc.Number, parent, err)
		}
		if _, _, err := a.FinalizedCheckpoint(5); err == nil {
			t.Fatal("nonconsecutive single child finalized parent")
		}
	}
	// Admit exactly one additional counter action. The finite-workload ceiling
	// is test-only; domain, registered members, threshold and vote rules stay fixed.
	for _, a := range n.nodes[:5] {
		a.config.MaxHeight = 7
		if err := a.NotifyIngress(); !benign(err) {
			t.Fatal(err)
		}
	}
	n.pump(t)
	for i, a := range n.nodes[:5] {
		if a.CertifiedHeight() != 7 || a.FinalizedHeight() != 6 {
			t.Fatalf("child node%d certified=%d finalized=%d", i, a.CertifiedHeight(), a.FinalizedHeight())
		}
		cp, proof, err := a.FinalizedCheckpoint(5)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.epoch.Verify(cp, proof); err != nil {
			t.Fatal("gapped ancestor finality proof", err)
		}
	}
	t.Log("five live: QC heights5/6 at views5/8 keep finalized4; real child height7/view9 finalizes5 and6")
}
