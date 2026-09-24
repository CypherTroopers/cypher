package consensus

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// A deliberately nonfinancial reference executor exercises opaque state/outputs.
// The independent financial engine has its own arithmetic vectors and tests.
type fixtureExecution struct {
	id        string
	calls     int
	oversized bool
}

func (e *fixtureExecution) ID() string {
	if e.id != "" {
		return e.id
	}
	return "fixture-execution/v1"
}
func (*fixtureExecution) Schema() uint16 { return ExecutionSchema }
func (*fixtureExecution) Genesis() ([]byte, protocol.Hash, error) {
	s := make([]byte, 8)
	return s, protocol.Digest("fixture-state", s), nil
}
func (e *fixtureExecution) Execute(parent, action []byte, c ExecutionContext) (ExecutionResult, error) {
	e.calls++
	if len(parent) != 8 || len(action) != 1 || action[0] == 0 || c.ParentRoot != protocol.Digest("fixture-state", parent) || !c.Domain.Valid() || c.Height == 0 || c.CLXHash == (protocol.Hash{}) {
		return ExecutionResult{}, errors.New("invalid fixture execution input")
	}
	v := binary.BigEndian.Uint64(parent)
	s := make([]byte, 8)
	binary.BigEndian.PutUint64(s, v+uint64(action[0]))
	if e.oversized {
		s = make([]byte, MaxStateBytes+1)
	}
	r := ExecutionResult{State: s, PostRoot: protocol.Digest("fixture-state", s), InboxStart: c.Height - 1, InboxEnd: c.Height, InboxRoot: protocol.Digest("fixture-inbox", action), WithdrawalRoot: protocol.Digest("fixture-withdraw", action), RewardPeriod: c.Height, RewardRoot: protocol.Digest("fixture-reward", action), FundingRef: protocol.Digest("fixture-funding", action)}
	r.WithdrawalTotal[31], r.RewardTotal[31] = action[0], action[0]+1
	// Mutate received buffers to prove the application gives owned copies.
	parent[0], action[0] = 255, 255
	return r, nil
}

func TestGenericExecutionFinalityRestartAndSnapshot(t *testing.T) {
	executors := make([]*fixtureExecution, 7)
	sources := [7]int{}
	n := newConfiguredNetwork(t, 5, func(c *Config) {
		i := c.Index
		executors[i] = new(fixtureExecution)
		c.Execution = executors[i]
		c.Actions = func(h uint64) ([]byte, error) { sources[i]++; return []byte{byte(h)}, nil }
	})
	n.start(t)
	for i, a := range n.nodes {
		if a.FinalizedHeight() != 4 {
			t.Fatalf("node %d did not finalize", i)
		}
		state, err := a.FinalizedState(4)
		if err != nil || binary.BigEndian.Uint64(state) != 10 {
			t.Fatalf("state %x: %v", state, err)
		}
		state[0] = 1
		state, err = a.FinalizedState(4)
		if err != nil || binary.BigEndian.Uint64(state) != 10 {
			t.Fatal("state alias")
		}
		cp, proof, err := a.FinalizedCheckpoint(4)
		if err != nil {
			t.Fatal(err)
		}
		if cp.DataSchema != 2 || cp.RewardPeriod != 4 || cp.WithdrawalTotal[31] != 4 || cp.RewardTotal[31] != 5 || cp.InboxStart != 3 || cp.InboxEnd != 4 {
			t.Fatal("financial outputs not committed")
		}
		if _, err = a.epoch.Verify(cp, proof); err != nil {
			t.Fatal(err)
		}
		before := executors[i].calls
		if err = a.Close(); err != nil {
			t.Fatal(err)
		}
		n.configs[i].Actions = func(uint64) ([]byte, error) {
			t.Error("recovery called action source")
			return nil, errors.New("source unavailable")
		}
		a, err = Open(n.configs[i])
		if err != nil {
			t.Fatal(err)
		}
		n.nodes[i] = a
		if executors[i].calls-before != 5 {
			t.Fatalf("restart executed %d records", executors[i].calls-before)
		}
	}
	for i := 5; i < 7; i++ {
		if sources[i] != 0 {
			t.Fatal("nonleader consumed action source")
		}
	}
	snapshot, err := n.nodes[0].ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	c := n.configs[6]
	c.DataDir = filepath.Join(t.TempDir(), "sync")
	c.Execution = new(fixtureExecution)
	peer, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err = peer.ImportSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	state, err := peer.FinalizedState(4)
	if err != nil || binary.BigEndian.Uint64(state) != 10 {
		t.Fatal("snapshot state", err)
	}
	if peer.disk.Safety.LastVote != nil {
		t.Fatal("snapshot imported voter safety")
	}
	if err = peer.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if restarted.FinalizedHeight() != 4 {
		t.Fatal("snapshot WAL lost execution header")
	}
}

func TestActionSelectionUsesCertifiedParentCopy(t *testing.T) {
	selected := 0
	n := newConfiguredNetwork(t, 5, func(c *Config) {
		c.Execution = new(fixtureExecution)
		c.ActionsWithParent = func(parent []byte, ctx ExecutionContext) ([]byte, error) {
			selected++
			if len(parent) != 8 || ctx.ParentRoot != protocol.Digest("fixture-state", parent) || ctx.Domain != c.Domain || ctx.CLXHash != c.CLXHash || ctx.CLXHeight != c.CLXHeight {
				t.Fatal("selector did not receive execution context")
			}
			// Previous actions add their own height, including certified blocks
			// not yet finalized. Selecting from the finalized head would fail.
			if binary.BigEndian.Uint64(parent) != (ctx.Height-1)*ctx.Height/2 {
				t.Fatal("selector used wrong parent state")
			}
			parent[0] = 255 // cannot mutate the stored certified state
			return []byte{byte(ctx.Height)}, nil
		}
	})
	n.start(t)
	if selected == 0 {
		t.Fatal("parent-aware source not called")
	}
	for _, a := range n.nodes {
		s, err := a.FinalizedState(4)
		if err != nil || binary.BigEndian.Uint64(s) != 10 {
			t.Fatal("selection changed replicated state", err)
		}
	}
	c := n.configs[0]
	c.Actions = func(uint64) ([]byte, error) { return nil, nil }
	if _, err := Open(c); err == nil {
		t.Fatal("ambiguous action sources accepted")
	}
}

func TestGenericReplayRejectsStateActionRootAndIdentity(t *testing.T) {
	n := newConfiguredNetwork(t, 3, func(c *Config) {
		c.Execution = new(fixtureExecution)
		c.Actions = func(uint64) ([]byte, error) { return []byte{2}, nil }
	})
	n.start(t)
	good, err := n.nodes[0].ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"state", "action", "root", "id", "genesis"} {
		t.Run(field, func(t *testing.T) {
			var s replaySnapshot
			if err := json.Unmarshal(good, &s); err != nil {
				t.Fatal(err)
			}
			var r *Record
			for _, v := range s.Records {
				if v.Checkpoint.Sequence == 1 {
					r = v
					break
				}
			}
			switch field {
			case "state":
				r.State[7] ^= 1
			case "action":
				r.Actions[0] ^= 1
			case "root":
				r.Checkpoint.PostRoot[0] ^= 1
			case "id":
				s.ExecutionID += "2"
			case "genesis":
				s.GenesisState[7] ^= 1
			}
			bad, _ := json.Marshal(s)
			c := n.configs[6]
			c.DataDir = filepath.Join(t.TempDir(), "sync")
			a, err := Open(c)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			if err = a.ImportSnapshot(bad); err == nil {
				t.Fatal("altered snapshot accepted")
			}
			if len(a.disk.Records) != 0 {
				t.Fatal("rejected snapshot changed state")
			}
		})
	}
	if err = n.nodes[0].Close(); err != nil {
		t.Fatal(err)
	}
	c := n.configs[0]
	c.Execution = &fixtureExecution{id: "different-engine"}
	if a, err := Open(c); err == nil {
		a.Close()
		t.Fatal("changed engine adopted old WAL")
	}
	c.Execution = nil
	if a, err := Open(c); err == nil {
		a.Close()
		t.Fatal("counter adopted generic WAL")
	}
}

func TestExecutionGoldenAndBounds(t *testing.T) {
	b, err := os.ReadFile("../testdata/execution.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		MaxAction int `json:"max_action_bytes"`
		MaxWire   int `json:"max_wire_bytes"`
		Actions   []struct{ Name, Action, Envelope, Root string }
		Genesis   struct {
			EpochKey    string `json:"epoch_key"`
			Root        string
			ExecutionID string `json:"execution_id"`
			Parent      string
		}
	}
	if err = json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.MaxAction != MaxActionBytes || vectors.MaxWire != MaxWireBytes {
		t.Fatal("execution bound golden mismatch")
	}
	maximum, err := EncodeExecutionAction(make([]byte, MaxActionBytes))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeExecutionAction(maximum); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors.Actions {
		a, _ := hex.DecodeString(v.Action)
		envelope, err := EncodeExecutionAction(a)
		if err != nil || hex.EncodeToString(envelope) != v.Envelope {
			t.Fatal(v.Name, "envelope")
		}
		root, err := ComputeExecutionDataRoot(a)
		if err != nil || hex.EncodeToString(root[:]) != v.Root {
			t.Fatal(v.Name, "root")
		}
		decoded, err := DecodeExecutionAction(envelope)
		if err != nil || !bytes.Equal(decoded, a) {
			t.Fatal("decode", err)
		}
		for _, bad := range [][]byte{envelope[:len(envelope)-1], append(append([]byte(nil), envelope...), 0), {0, 3, 0, 0, 0, 0}} {
			if _, err := DecodeExecutionAction(bad); err == nil {
				t.Fatal("noncanonical envelope accepted")
			}
		}
	}
	var epoch, root protocol.Hash
	e, _ := hex.DecodeString(vectors.Genesis.EpochKey)
	r, _ := hex.DecodeString(vectors.Genesis.Root)
	copy(epoch[:], e)
	copy(root[:], r)
	hash := executionGenesisHash(epoch, vectors.Genesis.ExecutionID, root)
	if hex.EncodeToString(hash[:]) != vectors.Genesis.Parent {
		t.Fatal("genesis golden mismatch")
	}
	if _, err = EncodeExecutionAction(make([]byte, MaxActionBytes+1)); err == nil {
		t.Fatal("oversized action accepted")
	}
	n := newConfiguredNetwork(t, 2, func(c *Config) {
		c.Execution = &fixtureExecution{oversized: true}
		c.Actions = func(uint64) ([]byte, error) { return []byte{1}, nil }
	})
	a := n.nodes[0]
	if _, _, err = a.executeCheckpoint(1, a.genesisHash(), nil, []byte{1}); err == nil {
		t.Fatal("oversized result accepted")
	}
}

func TestVoteHooksValidateBeforeSigningAndProtectCopies(t *testing.T) {
	before, observed := [7]int{}, [7]int{}
	n := newConfiguredNetwork(t, 3, func(c *Config) {
		i := c.Index
		c.BeforeVote = func(v *hotstuff.PersistedVote) error { before[i]++; v.ProposalRef[0] ^= 1; return nil }
		c.ObserveVote = func(ref []byte, v *hotstuff.HotstuffMessage) error {
			observed[i]++
			if before[i] == 0 || len(ref) == 0 || len(v.DataC) == 0 {
				return fmt.Errorf("observer before durable vote")
			}
			ref[0] ^= 1
			v.DataC[0] ^= 1
			return nil
		}
	})
	n.start(t)
	for i, a := range n.nodes {
		if before[i] != 3 || observed[i] < 3 || a.FinalizedHeight() != 2 {
			t.Fatalf("hooks node %d before=%d observed=%d", i, before[i], observed[i])
		}
	}
	blocked := newNetwork(t, 2)
	a := blocked.nodes[0]
	req := &hotstuff.FHSProposalBuildRequest{Key: hotstuff.FHSProposalBuildKey{ViewNumber: 1, ViewID: a.genesisHash(), LeaderID: a.Self()}}
	r, err := a.build(req)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.storeRecord(r); err != nil {
		t.Fatal(err)
	}
	ref, err := decodeRecordVote(r)
	if err != nil {
		t.Fatal(err)
	}
	a.config.BeforeVote = func(*hotstuff.PersistedVote) error { return errors.New("collector fsync failed") }
	if err = a.PersistFHSVote(ref); err == nil || a.disk.Safety.LastVote != nil {
		t.Fatal("collector failure allowed durable vote")
	}
}

func decodeRecordVote(r *Record) (*hotstuff.PersistedVote, error) {
	ref, err := types.DecodeHotstuffProposalRef(r.Ref)
	if err != nil {
		return nil, err
	}
	return &hotstuff.PersistedVote{ViewNumber: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID, ProposalID: ref.ProposalID(), ProposalRef: r.Ref, ProposalRefHash: hotstuff.StateDigest(r.Ref)}, nil
}

func TestRestoreVoteChecksCollectorBeforeManagerAndProtectsCopies(t *testing.T) {
	n := newNetwork(t, 3)
	n.start(t)
	vote := hotstuff.ClonePersistedVote(n.nodes[0].disk.Safety.LastVote)
	if vote == nil {
		t.Fatal("missing durable vote")
	}
	if err := n.nodes[0].Close(); err != nil {
		t.Fatal(err)
	}
	c := n.configs[0]
	c.RestoreVote = func(v *hotstuff.PersistedVote) error {
		if v == nil || !bytes.Equal(v.ProposalRef, vote.ProposalRef) {
			t.Fatal("recovery hook lacked last vote")
		}
		return errors.New("collector WAL lost its corresponding target")
	}
	if a, err := Open(c); err == nil {
		a.Close()
		t.Fatal("signer reopened with absent collector safety")
	}
	called := 0
	c.RestoreVote = func(v *hotstuff.PersistedVote) error { called++; v.ProposalRef[0] ^= 1; return nil }
	a, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if called != 1 || !bytes.Equal(a.disk.Safety.LastVote.ProposalRef, vote.ProposalRef) {
		t.Fatal("restore callback mutated WAL vote")
	}
	c.DataDir = filepath.Join(t.TempDir(), "fresh")
	c.RestoreVote = func(v *hotstuff.PersistedVote) error {
		if v != nil {
			t.Fatal("fresh app has peer safety")
		}
		return nil
	}
	b, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
}

func TestFinalizedExecutionHookDurableOwnedAndReplay(t *testing.T) {
	counts := [7]int{}
	n := newConfiguredNetwork(t, 3, func(c *Config) {
		c.Execution = new(fixtureExecution)
		c.Actions = func(uint64) ([]byte, error) { return []byte{2}, nil }
		i, path := c.Index, filepath.Join(c.DataDir, "state.json")
		c.OnFinalizedExecution = func(height uint64, action, state []byte) error {
			counts[i]++
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var envelope walEnvelope
			if err = json.Unmarshal(raw, &envelope); err != nil {
				return err
			}
			var disk diskState
			if err = json.Unmarshal(envelope.Payload, &disk); err != nil {
				return err
			}
			if uint64(len(disk.Finalized)) < height {
				return errors.New("callback before finality fsync")
			}
			if len(action) != 1 || action[0] != 2 || binary.BigEndian.Uint64(state) != height*2 {
				return errors.New("callback execution payload mismatch")
			}
			action[0], state[0] = 255, 255
			return nil
		}
	})
	n.start(t)
	for i, a := range n.nodes {
		if counts[i] != 2 {
			t.Fatalf("node %d notified %d incl speculative child", i, counts[i])
		}
		state, err := a.FinalizedState(2)
		if err != nil || binary.BigEndian.Uint64(state) != 4 {
			t.Fatal("callback mutated state", err)
		}
	}
	if err := n.nodes[0].Close(); err != nil {
		t.Fatal(err)
	}
	a, err := Open(n.configs[0])
	if err != nil {
		t.Fatal(err)
	}
	n.nodes[0] = a
	if counts[0] != 4 {
		t.Fatal("startup did not reconcile finalized records")
	}
	data, err := a.ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	c := n.configs[6]
	c.DataDir = filepath.Join(t.TempDir(), "snapshot")
	restored := 0
	c.OnFinalizedExecution = func(uint64, []byte, []byte) error { restored++; return nil }
	peer, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err = peer.ImportSnapshot(data); err != nil {
		t.Fatal(err)
	}
	if restored != 2 {
		t.Fatal("snapshot did not reconcile finalized records")
	}
}

func TestFinalizedExecutionHookFailureNeverRollsBackFinality(t *testing.T) {
	n := newConfiguredNetwork(t, 3, func(c *Config) {
		c.Execution = new(fixtureExecution)
		c.Actions = func(uint64) ([]byte, error) { return []byte{1}, nil }
	})
	n.start(t)
	a := n.nodes[0]
	a.notifiedHeight = 0 // Exercise retry through the same certify/persist path.
	a.config.OnFinalizedExecution = func(uint64, []byte, []byte) error { return errors.New("collector close unavailable") }
	if err := a.certify(a.disk.Safety.HighestQC, false); err == nil || !strings.Contains(err.Error(), "collector close unavailable") {
		t.Fatal("callback failure not reported", err)
	}
	if a.FinalizedHeight() != 2 || a.fatal == nil {
		t.Fatal("failure rolled back finality or allowed signing")
	}
	if err := a.Start(); err == nil {
		t.Fatal("signing resumed after failed reconciliation")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	c := n.configs[0]
	c.OnFinalizedExecution = a.config.OnFinalizedExecution
	if reopened, err := Open(c); err == nil {
		reopened.Close()
		t.Fatal("startup ignored unresolved finality callback")
	}
	count := 0
	c.OnFinalizedExecution = func(uint64, []byte, []byte) error { count++; return nil }
	recovered, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	n.nodes[0] = recovered
	if recovered.FinalizedHeight() != 2 || count != 2 {
		t.Fatal("recovery lost durable finality")
	}
}
