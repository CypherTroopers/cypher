package consensus

import "testing"

func TestReadinessCertifiedVoteAfterRealViewGaps(t *testing.T) {
	n := newNetwork(t, 6)
	n.dropped[n.nodes[5].Self()] = true
	n.dropped[n.nodes[6].Self()] = true
	n.start(t)
	for missed := 0; missed < 2; missed++ {
		for _, a := range n.nodes[:5] {
			if err := a.Timeout(); !benign(err) {
				t.Fatal(err)
			}
		}
		n.pump(t)
	}
	for i, a := range n.nodes[:5] {
		if a.CertifiedHeight() != 6 || a.HighestCertified().Number != 8 {
			t.Fatal("missing real view-gap certificate")
		}
		if a.HasUncertifiedVote() {
			t.Fatal("gap between height and view made certified vote appear pending")
		}
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		restored, err := Open(n.configs[i])
		if err != nil {
			t.Fatal(err)
		}
		n.nodes[i] = restored
		if restored.HasUncertifiedVote() {
			t.Fatal("cold gapped certified vote appears pending")
		}
	}
}

func TestReadinessDistinguishesCertifiedAndPendingOwnVoteAfterRestart(t *testing.T) {
	n := newNetwork(t, 5)
	n.start(t)
	for i, a := range n.nodes {
		if a.HasUncertifiedVote() {
			t.Fatalf("certified own vote node%d: voteview%d qcview%d", i, a.disk.Safety.LastVote.ViewNumber, a.HighestCertified().Number)
		}
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		restored, err := Open(n.configs[i])
		if err != nil {
			t.Fatal(err)
		}
		n.nodes[i] = restored
		if restored.HasUncertifiedVote() {
			t.Fatal("cold certified own vote became pending")
		}
	}
	a := n.nodes[0]
	a.config.MaxHeight = 6
	n.configs[0].MaxHeight = 6
	r := generationPendingRecord(t, a, a.HighestCertified(), 6, 6)
	if err := a.storeRecord(r); err != nil {
		t.Fatal(err)
	}
	v, err := decodeRecordVote(r)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.PersistFHSVote(v); err != nil {
		t.Fatal(err)
	}
	if !a.HasUncertifiedVote() {
		t.Fatal("uncertified own vote treated as idle")
	}
	if err = a.Close(); err != nil {
		t.Fatal(err)
	}
	a, err = Open(n.configs[0])
	if err != nil {
		t.Fatal(err)
	}
	n.nodes[0] = a
	if !a.HasUncertifiedVote() {
		t.Fatal("cold pending own vote lost timeout readiness")
	}
}
