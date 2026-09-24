package consensus

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// A small opaque executor keeps the test about FHS ancestry, not changes to
// financial formulas. Its height/state semantics are identical to schema 2.
type ancestryFixtureExecution struct{ fixtureExecution }

func (*ancestryFixtureExecution) ID() string     { return "fixture-ancestry/v1" }
func (*ancestryFixtureExecution) Schema() uint16 { return AncestryExecutionSchema }
func (e *ancestryFixtureExecution) Execute(parent, action []byte, ctx ExecutionContext) (ExecutionResult, error) {
	result, err := e.fixtureExecution.Execute(parent, action, ctx)
	result.CLXHeight, result.CLXHash = ctx.CLXHeight, ctx.CLXHash
	return result, err
}
func (*ancestryFixtureExecution) ValidateSnapshot(raw []byte, height uint64, root protocol.Hash) error {
	if len(raw) != 8 || binary.BigEndian.Uint64(raw) != height || root != protocol.Digest("fixture-state", raw) {
		return errors.New("fixture snapshot state/root")
	}
	return nil
}
func ancestryNetwork(t *testing.T, height uint64) *network {
	return newConfiguredNetwork(t, height, func(c *Config) {
		c.StorageGenerations = true
		c.Execution = new(ancestryFixtureExecution)
		c.Actions = func(uint64) ([]byte, error) { return []byte{1}, nil }
	})
}
func admitAncestryHeight(t *testing.T, n *network, height uint64, gap bool) {
	t.Helper()
	if gap {
		for _, a := range n.nodes[:5] {
			if err := a.Timeout(); !benign(err) {
				t.Fatal(err)
			}
		}
		pumpFinalityBacklog(t, n, false)
	}
	for i, a := range n.nodes {
		a.config.MaxHeight = height
		n.configs[i].MaxHeight = height
		if err := a.NotifyIngress(); !benign(err) {
			t.Fatal(err)
		}
	}
	pumpFinalityBacklog(t, n, false)
}

func TestHistoryFinalityLongViewGapsBoundedProofAndColdRestart(t *testing.T) {
	n := ancestryNetwork(t, 40)
	for _, a := range n.nodes {
		a.config.MaxHeight = 1
	}
	n.start(t)
	for height := uint64(2); height <= 32; height++ {
		admitAncestryHeight(t, n, height, true)
		for _, a := range n.nodes {
			if a.CertifiedHeight() != height || a.FinalizedHeight() != 0 {
				t.Fatalf("gap did not remain certified-only: %d/%d", a.CertifiedHeight(), a.FinalizedHeight())
			}
		}
	}
	admitAncestryHeight(t, n, 33, false)
	maxBytes, maxChecks := 0, 0
	for i, a := range n.nodes {
		if a.CertifiedHeight() != 33 || a.FinalizedHeight() != 32 {
			t.Fatalf("node%d certified/finalized %d/%d", i, a.CertifiedHeight(), a.FinalizedHeight())
		}
		for height := uint64(1); height <= 32; height++ {
			cp, proof, err := a.FinalizedCheckpoint(height)
			if err != nil {
				t.Fatal(err)
			}
			stats, err := a.epoch.Verify(cp, proof)
			if err != nil || stats.SignatureChecks > 3 || len(proof) > checkpoint.MaxProofBytes {
				t.Fatalf("height%d bounded finality: %+v/%d: %v", height, stats, len(proof), err)
			}
			if len(proof) > maxBytes {
				maxBytes = len(proof)
			}
			if stats.SignatureChecks > maxChecks {
				maxChecks = stats.SignatureChecks
			}
			state, err := a.FinalizedState(height)
			if err != nil || binary.BigEndian.Uint64(state) != height {
				t.Fatal("changed execution result", err)
			}
		}
		before := hotstuff.CloneFHSSafetyState(a.disk.Safety)
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		restarted, err := Open(n.configs[i])
		if err != nil {
			t.Fatalf("restart%d: %v", i, err)
		}
		n.nodes[i] = restarted
		if restarted.FinalizedHeight() != 32 || restarted.CertifiedHeight() != 33 || !reflect.DeepEqual(before, restarted.disk.Safety) {
			t.Fatal("restart changed own vote/lock/QC/timeout safety or finality")
		}
	}
	t.Logf("real7 FHS managers:32 certified view gaps; genuine33rd child finalizesall32; maxproof=%d maxsignatures=%d; 7coldrestarts preserve state/safety; legacy descendant cap=%d unchanged", maxBytes, maxChecks, checkpoint.MaxDescendants)
}

func TestHistoryFrontierReplayRejectsChangedAndForeignParent(t *testing.T) {
	n := ancestryNetwork(t, 4)
	n.start(t)
	a := n.nodes[0]
	for _, record := range a.disk.Records {
		if record.Checkpoint.Sequence != 3 {
			continue
		}
		ref, err := types.DecodeHotstuffProposalRef(record.Ref)
		if err != nil {
			t.Fatal(err)
		}
		parent, err := a.parentQC(ref)
		if err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{"missing", "count", "branch"} {
			copy := *record
			copy.History = cloneHistory(record.History)
			switch kind {
			case "missing":
				copy.History = nil
			case "count":
				copy.History.Count++
			case "branch":
				copy.History.Branch[0][0] ^= 1
			}
			if err := a.validateRecord(&copy, parent); err == nil {
				t.Fatalf("%s ancestry accepted", kind)
			}
		}
		if err := a.validateRecord(record, nil); err == nil {
			t.Fatal("foreign genesis parent accepted")
		}
		return
	}
	t.Fatal("record not found")
}

func TestHistoryFinalityAcrossTwoStorageGenerations(t *testing.T) {
	n := ancestryNetwork(t, 130)
	n.start(t)
	for i, a := range n.nodes {
		if a.disk.Generation != 2 || a.disk.BaseHeight != 128 || a.FinalizedHeight() != 129 {
			t.Fatalf("node%d did not rotate twice: %+v", i, a.StorageStatus())
		}
	}
	for height := uint64(131); height <= 145; height++ {
		admitAncestryHeight(t, n, height, true)
	}
	for _, a := range n.nodes {
		if a.FinalizedHeight() != 129 {
			t.Fatal("gapped QC exposed as finality")
		}
	}
	admitAncestryHeight(t, n, 146, false)
	for i, a := range n.nodes {
		if a.FinalizedHeight() != 145 || a.CertifiedHeight() != 146 {
			t.Fatal("history stalled across archived parent path")
		}
		for _, height := range []uint64{1, 64, 128, 129, 130, 131, 145} {
			cp, proof, err := a.FinalizedCheckpoint(height)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = a.epoch.Verify(cp, proof); err != nil {
				t.Fatal(err)
			}
		}
		before := hotstuff.CloneFHSSafetyState(a.disk.Safety)
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		restarted, err := Open(n.configs[i])
		if err != nil {
			t.Fatalf("archive restart%d: %v", i, err)
		}
		n.nodes[i] = restarted
		if restarted.FinalizedHeight() != 145 || !reflect.DeepEqual(before, restarted.disk.Safety) {
			t.Fatal("archived cold restart state/safety")
		}
	}
	// A valid checksum does not authenticate a changed frontier. Exercise full
	// archive replay, including its comparison with each actual parent.
	a := n.nodes[0]
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(a.config.DataDir, "history", archiveName(64))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var e archiveEntry
	if _, err = decodeEnvelopeBytes(raw, "common-dex/archive-entry/v4", &e); err != nil {
		t.Fatal(err)
	}
	e.Record.History.Branch[0][0] ^= 1
	corrupt, _, err := envelopeBytes(e, "common-dex/archive-entry/v4", maxWALBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(n.configs[0]); err == nil {
		opened.Close()
		t.Fatal("rechecksummed archived frontier accepted")
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(n.configs[0])
	if err != nil {
		t.Fatal(err)
	}
	n.nodes[0] = restarted
	t.Log("two real128-hot storage cuts;16 nonconsecutive certified descendants;finalized145 with bounded ancestry proofs;oldarchive states/proofs retained;7cold restarts;rechecksummed badfrontier rejected")
}

func TestHistoryColdReplayRejectsRechecksummedMissingFrontier(t *testing.T) {
	n := ancestryNetwork(t, 3)
	n.start(t)
	a := n.nodes[0]
	var victim *Record
	for _, record := range a.disk.Records {
		if record.Checkpoint.Sequence == 2 {
			victim = record
			break
		}
	}
	if victim == nil {
		t.Fatal("missing fixture record")
	}
	victim.History = nil
	// Produce a valid local envelope checksum around deliberately bad content.
	// Recovery must reexecute/derive the frontier, not trust this checksum.
	if err := a.wal.save(a.disk); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(n.configs[0]); err == nil {
		opened.Close()
		t.Fatal("cold replay accepted missing schema6 history")
	}
}

// Signed fixture certificates isolate ancestry binding; this is not an alternate
// live vote history. Two views can certify the same checkpoint hash, but their
// semantic QC identities (and therefore the child's ancestry) must differ.
func TestHistoryBindsActualParentQCViewInsteadOfCheckpointHeight(t *testing.T) {
	n := ancestryNetwork(t, 4)
	a := n.nodes[0]
	var parents []*hotstuff.SignedState
	var checkpoints []protocol.Checkpoint
	for _, view := range []uint64{1, 8} {
		req := &hotstuff.FHSProposalBuildRequest{Key: hotstuff.FHSProposalBuildKey{ViewNumber: view, ViewID: common.Hash{byte(view)}, LeaderID: a.committee.List[(view-1)%7].Address}}
		r, err := a.buildAction(req, []byte{1})
		if err != nil {
			t.Fatal(err)
		}
		r.QC = generationFixtureQC(t, n, r)
		if err = a.verifyQC(r.QC); err != nil {
			t.Fatal(err)
		}
		if err = a.storeRecord(r); err != nil {
			t.Fatal(err)
		}
		parents = append(parents, r.QC)
		checkpoints = append(checkpoints, r.Checkpoint)
	}
	if checkpoints[0] != checkpoints[1] {
		t.Fatal("fixture did not reuse checkpoint hash in two views")
	}
	var children []*Record
	for _, parent := range parents {
		id, err := hotstuff.SignedStateID(parent)
		if err != nil {
			t.Fatal(err)
		}
		req := &hotstuff.FHSProposalBuildRequest{ParentQC: parent, Key: hotstuff.FHSProposalBuildKey{ViewNumber: 9, ViewID: common.Hash{9}, LeaderID: a.committee.List[1].Address, ParentQCID: id.Hash()}}
		r, err := a.buildAction(req, []byte{1})
		if err != nil {
			t.Fatal(err)
		}
		children = append(children, r)
	}
	if sameHistory(children[0].History, children[1].History) || children[0].Checkpoint.DataRoot == children[1].Checkpoint.DataRoot {
		t.Fatal("selected parent QC view was erased from signed ancestry")
	}
	if err := a.validateRecord(children[0], parents[1]); err == nil {
		t.Fatal("replay accepted other same-height parent QC")
	}
}
