package consensus

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func TestCertifiedDataRepairPreservesVoteAndReexecutes(t *testing.T) {
	n := newConfiguredNetwork(t, 5, func(c *Config) {
		c.Execution = new(fixtureExecution)
		c.Actions = func(uint64) ([]byte, error) { return []byte{1}, nil }
	})
	n.start(t)
	data, err := n.nodes[0].CertifiedData(0, 8)
	if err != nil || len(data) != 5 {
		t.Fatalf("certified data: %d %v", len(data), err)
	}
	c := n.configs[6]
	c.DataDir = filepath.Join(t.TempDir(), "repair")
	c.Execution = new(fixtureExecution)
	a, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	var first Record
	if err = json.Unmarshal(data[0], &first); err != nil {
		t.Fatal(err)
	}
	ref, _ := types.DecodeHotstuffProposalRef(first.Ref)
	extra, _ := encodeExtra(&first)
	if err = a.OnPropose(first.Ref, extra, ref.ViewNumber, nil); err != nil {
		t.Fatal(err)
	}
	v := &hotstuff.PersistedVote{ViewNumber: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID, ProposalID: ref.ProposalID(), ProposalRefHash: hotstuff.StateDigest(first.Ref), ProposalRef: first.Ref}
	if err = a.PersistFHSVote(v); err != nil {
		t.Fatal(err)
	}
	before := hotstuff.ClonePersistedVote(a.disk.Safety.LastVote)
	if err = a.ImportProposalData(data[1]); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing parent not explicit: %v", err)
	}
	for _, raw := range data {
		if err = a.ImportProposalData(raw); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(before, a.disk.Safety.LastVote) || a.FinalizedHeight() != 4 {
		t.Fatal("repair changed own vote or missed finality")
	}
	want, _ := n.nodes[0].FinalizedState(4)
	got, _ := a.FinalizedState(4)
	if !bytes.Equal(got, want) {
		t.Fatal("repair state mismatch")
	}
	for _, raw := range data {
		if err = a.ImportProposalData(raw); err != nil {
			t.Fatalf("repair retry: %v", err)
		}
	}
	if err = a.Close(); err != nil {
		t.Fatal(err)
	}
	a, err = Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if a.FinalizedHeight() != 4 || !reflect.DeepEqual(before, a.disk.Safety.LastVote) {
		t.Fatal("repair restart lost local safety/finality")
	}
	for _, kind := range []string{"state", "action", "signature", "domain", "missing-qc", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			var r Record
			json.Unmarshal(data[4], &r)
			switch kind {
			case "state":
				r.State[0] ^= 1
			case "action":
				r.Actions[0] ^= 1
			case "signature":
				r.QC.Sign[0] ^= 1
			case "domain":
				r.Checkpoint.DEXID[0] ^= 1
			case "missing-qc":
				r.QC = nil
			}
			raw, _ := json.Marshal(r)
			if kind == "oversize" {
				raw = make([]byte, MaxProposalDataBytes+1)
			}
			if err = a.ImportProposalData(raw); err == nil {
				t.Fatal("malformed repair accepted")
			}
			if !reflect.DeepEqual(before, a.disk.Safety.LastVote) || a.FinalizedHeight() != 4 {
				t.Fatal("malformed repair mutated state")
			}
		})
	}
}
