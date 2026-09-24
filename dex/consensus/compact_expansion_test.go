package consensus

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

type expansionExecution struct{}

func (*expansionExecution) ID() string     { return "bounded-expansion-fixture/v1" }
func (*expansionExecution) Schema() uint16 { return RollingExecutionSchema }
func (*expansionExecution) Genesis() ([]byte, protocol.Hash, error) {
	s := []byte{0}
	return s, protocol.Digest("expansion-fixture", s), nil
}
func (*expansionExecution) Execute(parent, action []byte, c ExecutionContext) (ExecutionResult, error) {
	if len(action) != 1 || action[0] != byte(c.Height) || protocol.Digest("expansion-fixture", parent) != c.ParentRoot {
		return ExecutionResult{}, errors.New("bad expansion fixture input")
	}
	s := bytes.Repeat(action, 360*1024)
	return ExecutionResult{State: s, PostRoot: protocol.Digest("expansion-fixture", s), CLXHeight: c.CLXHeight, CLXHash: c.CLXHash}, nil
}
func expansionSnapshot(t *testing.T, n *network, count int) replaySnapshot {
	t.Helper()
	a := n.nodes[0]
	s := replaySnapshot{Version: 2, Domain: a.config.Domain, Records: make(map[string]*Record), ExecutionID: a.disk.ExecutionID, ExecutionSchema: a.disk.ExecutionSchema, GenesisState: a.disk.GenesisState, GenesisRoot: a.disk.GenesisRoot}
	var parent *hotstuff.SignedState
	keys := make([]string, 0, count)
	for h := 1; h <= count; h++ {
		req := &hotstuff.FHSProposalBuildRequest{Key: hotstuff.FHSProposalBuildKey{ViewNumber: uint64(h), ViewID: common.Hash{byte(h), 5}, LeaderID: a.committee.List[(h-1)%7].Address}, ParentQC: parent}
		if parent != nil {
			id, err := hotstuff.SignedStateID(parent)
			if err != nil {
				t.Fatal(err)
			}
			req.Key.ParentQCID = id.Hash()
		}
		r, err := a.buildAction(req, []byte{byte(h)})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := types.DecodeHotstuffProposalRef(r.Ref)
		if err != nil {
			t.Fatal(err)
		}
		var agg *bls.Sign
		for i := 0; i < 5; i++ {
			secret := n.configs[i].Secret
			sig, err := hotstuff.SignFHSSignatureWithContext(secret, secret.GetPublicKey(), r.Ref, ref.ChainID, hotstuff.MsgVotePrepare, ref.ViewID, ref.LeaderID)
			if err != nil {
				t.Fatal(err)
			}
			if agg == nil {
				agg = sig
			} else {
				agg.Add(sig)
			}
		}
		r.QC = &hotstuff.SignedState{State: r.Ref, Sign: agg.Serialize(), Mask: []byte{31}, ViewID: ref.ViewID, LeaderID: ref.LeaderID, Number: ref.ViewNumber}
		if err = a.verifyQC(r.QC); err != nil {
			t.Fatal(err)
		}
		key := ref.ProposalID().Hex()
		keys = append(keys, key)
		a.disk.Records[key] = r
		s.Records[key] = r
		parent = r.QC
	}
	for i := 0; i+1 < len(keys); i++ {
		r := s.Records[keys[i]]
		proof, err := checkpoint.EncodeProof(checkpoint.Proof{Target: r.QC, Descendants: []*hotstuff.SignedState{s.Records[keys[i+1]].QC}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = a.epoch.Verify(r.Checkpoint, proof); err != nil {
			t.Fatal(err)
		}
		h, _ := r.Checkpoint.Hash()
		s.Finalized = append(s.Finalized, finalizedRecord{keys[i], common.Hash(h).Hex(), proof})
	}
	// Construct adversarial wire data without going through the honest writer's
	// aggregate-memory guard; all roots, refs, signatures and descendants are real.
	for i := 0; i+1 < len(s.Finalized); i++ {
		copyR := *s.Records[s.Finalized[i].Key]
		copyR.State = nil
		s.Records[s.Finalized[i].Key] = &copyR
	}
	return s
}
func TestCompactSnapshotBoundsReconstructedAggregate(t *testing.T) {
	for _, count := range []int{5, 6} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			n := newConfiguredNetwork(t, 7, func(c *Config) { c.Execution = new(expansionExecution) })
			s := expansionSnapshot(t, n, count)
			raw, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) > MaxSnapshotBytes {
				t.Fatal("wire must fit existing cap")
			}
			c := n.configs[6]
			c.DataDir = filepath.Join(t.TempDir(), "receiver")
			peer, err := Open(c)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			err = peer.ImportSnapshot(raw)
			if count == 5 {
				if err != nil {
					t.Fatal(err)
				}
				if peer.FinalizedHeight() != 4 {
					t.Fatal("good compact import")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "reconstructed state budget") {
				t.Fatalf("want explicit aggregate refusal: %v", err)
			}
			if len(peer.disk.Records) != 0 || peer.disk.Safety.HighestQC != nil || peer.FinalizedHeight() != 0 {
				t.Fatal("failed snapshot published partial state")
			}
			if err = peer.Close(); err != nil {
				t.Fatal(err)
			}
			d := diskState{Version: 2, Domain: s.Domain, VotePublic: peer.disk.VotePublic, ExecutionID: s.ExecutionID, ExecutionSchema: s.ExecutionSchema, GenesisState: s.GenesisState, GenesisRoot: s.GenesisRoot, Safety: hotstuff.NewFHSSafetyState(), Records: s.Records, Finalized: s.Finalized}
			writeCompact(t, filepath.Join(c.DataDir, "state.json"), d)
			if reopened, e := Open(c); e == nil {
				reopened.Close()
				t.Fatal("oversized reconstruction accepted on cold WAL")
			} else if !strings.Contains(e.Error(), "reconstructed state budget") {
				t.Fatal(e)
			}
		})
	}
}
func TestCompactWALRequiresExplicitCanonicalStateNull(t *testing.T) {
	n := compactNetwork(t)
	n.start(t)
	a := n.nodes[0]
	p := filepath.Join(n.configs[0].DataDir, "state.json")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	// Preserve the existing v2 canonical-null regression after the local writer
	// moves to v3. The new dictionary tests exercise the v3 equivalent.
	writeCompact(t, p, readCompact(t, p))
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var e walEnvelope
	if err = json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(e.Payload, []byte(`,"State":null`), nil, 1)
	if bytes.Equal(changed, e.Payload) {
		t.Fatal("missing old finalized null")
	}
	e.Payload = changed
	e.Checksum = protocol.Digest(walDigestDomain(2), changed)
	bad, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(p, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(n.configs[0]); err == nil {
		reopened.Close()
		t.Fatal("noncanonical omitted field accepted")
	} else if !strings.Contains(err.Error(), "noncanonical compact") {
		t.Fatal(err)
	}
}
