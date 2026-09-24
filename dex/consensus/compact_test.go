package consensus

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

type compactExecution struct{ fixtureExecution }

func (*compactExecution) Schema() uint16 { return RollingExecutionSchema }
func (e *compactExecution) Execute(parent, action []byte, c ExecutionContext) (ExecutionResult, error) {
	r, err := e.fixtureExecution.Execute(parent, action, c)
	r.CLXHeight, r.CLXHash = c.CLXHeight, c.CLXHash
	return r, err
}
func compactNetwork(t *testing.T) *network {
	return newConfiguredNetwork(t, 6, func(c *Config) {
		c.Execution = new(compactExecution)
		c.Actions = func(h uint64) ([]byte, error) { return []byte{byte(h)}, nil }
	})
}
func readCompact(t *testing.T, path string) diskState {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var e walEnvelope
	if err = json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	d, err := decodeWALPayload(e)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func writeCompact(t *testing.T, path string, d diskState) {
	t.Helper()
	p, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(walEnvelope{p, protocol.Digest(walDigestDomain(d.Version), p)})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestCompactReplayRestartSnapshotAndLegacy(t *testing.T) {
	n := compactNetwork(t)
	n.start(t)
	a := n.nodes[0]
	p := filepath.Join(n.configs[0].DataDir, "state.json")
	disk := readCompact(t, p)
	if disk.Version != 2 || len(disk.Finalized) != 5 {
		t.Fatal("not compact rolling WAL")
	}
	for i, f := range disk.Finalized {
		if (disk.Records[f.Key].State == nil) != (i < 4) {
			t.Fatal("wrong omission")
		}
		state, err := a.FinalizedState(uint64(i + 1))
		if err != nil || len(state) != 8 {
			t.Fatal("live state mutated", err)
		}
	}
	snapshot, err := a.ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	var s replaySnapshot
	if err = json.Unmarshal(snapshot, &s); err != nil {
		t.Fatal(err)
	}
	if s.Version != 2 || s.Records[s.Finalized[0].Key].State != nil {
		t.Fatal("snapshot not compact")
	}
	vote := hotstuff.ClonePersistedVote(a.disk.Safety.LastVote)
	if err = a.Close(); err != nil {
		t.Fatal(err)
	}
	a, err = Open(n.configs[0])
	if err != nil {
		t.Fatal(err)
	}
	n.nodes[0] = a
	for h := uint64(1); h <= 5; h++ {
		b, e := a.FinalizedState(h)
		if e != nil || binary.BigEndian.Uint64(b) != h*(h+1)/2 {
			t.Fatalf("replay %d %x %v", h, b, e)
		}
	}
	if a.disk.Safety.LastVote.ProposalID != vote.ProposalID {
		t.Fatal("lost own vote")
	}
	bad := hotstuff.ClonePersistedVote(vote)
	bad.ProposalID[0] ^= 1
	if err = a.PersistFHSVote(bad); err == nil {
		t.Fatal("double vote after compact restart")
	}
	// Different registered receiver keeps its own key; no peer safety state imported.
	c := n.configs[6]
	c.DataDir = filepath.Join(t.TempDir(), "peer")
	peer, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err = peer.BootstrapSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	if peer.disk.VotePublic == a.disk.VotePublic || peer.disk.Safety.LastVote != nil {
		t.Fatal("peer identity/safety copied")
	}
	if err = peer.BootstrapSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	for h := uint64(1); h <= 5; h++ {
		x, _ := a.FinalizedState(h)
		y, _ := peer.FinalizedState(h)
		if !bytes.Equal(x, y) {
			t.Fatal("snapshot replay mismatch")
		}
	}
	// A full legacy rolling WAL is authenticated before one-way local codec upgrade.
	legacy := a.disk
	legacy.Version = 1
	if err = a.Close(); err != nil {
		t.Fatal(err)
	}
	writeCompact(t, p, legacy)
	a, err = Open(n.configs[0])
	if err != nil {
		t.Fatal(err)
	}
	n.nodes[0] = a
	if readCompact(t, p).Version != 2 {
		t.Fatal("legacy rolling WAL not upgraded after verification")
	}
}
func TestCompactReplayRejectsChecksumValidCorruption(t *testing.T) {
	n := compactNetwork(t)
	n.start(t)
	if err := n.nodes[0].Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(n.configs[0].DataDir, "state.json")
	original := readCompact(t, p)
	raw, _ := json.Marshal(original)
	cases := map[string]func(*diskState){
		"action":             func(d *diskState) { d.Records[d.Finalized[0].Key].Actions[0] ^= 1 },
		"root":               func(d *diskState) { d.Records[d.Finalized[0].Key].Checkpoint.PostRoot[0] ^= 1 },
		"ref":                func(d *diskState) { d.Records[d.Finalized[0].Key].Ref[0] ^= 1 },
		"old-state-not-null": func(d *diskState) { d.Records[d.Finalized[0].Key].State = []byte{1} },
		"tip-state-omitted":  func(d *diskState) { d.Records[d.Finalized[4].Key].State = nil },
		"tip-state-wrong":    func(d *diskState) { d.Records[d.Finalized[4].Key].State[0] ^= 1 },
		"missing-parent":     func(d *diskState) { delete(d.Records, d.Finalized[0].Key) },
		"schema":             func(d *diskState) { d.ExecutionSchema = NativeExecutionSchema },
		"version":            func(d *diskState) { d.Version = 3 },
		"single-qc-finality": func(d *diskState) { d.Finalized[0].Proof = []byte{1} },
		"qc-signature":       func(d *diskState) { d.Records[d.Finalized[0].Key].QC.Sign[0] ^= 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var d diskState
			json.Unmarshal(raw, &d)
			mutate(&d)
			writeCompact(t, p, d)
			other, err := Open(n.configs[0])
			if err == nil {
				other.Close()
				t.Fatal("corruption accepted")
			}
		})
	}
	writeCompact(t, p, original)
	a, err := Open(n.configs[0])
	if err != nil {
		t.Fatal(err)
	}
	n.nodes[0] = a
}
func TestCompactReplayGoldenAndBounds(t *testing.T) {
	b, err := os.ReadFile("../testdata/compact_replay.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Payload, Checksum string
		Omitted, Retained []string
	}
	if err = json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	payload, err := hex.DecodeString(v.Payload)
	if err != nil {
		t.Fatal(err)
	}
	sum := protocol.Digest(walDigestDomain(2), payload)
	if hex.EncodeToString(sum[:]) != v.Checksum {
		t.Fatal("independent checksum golden")
	}
	records := map[string]*Record{"a": {State: []byte("state-one")}, "b": {State: []byte("state-two")}, "c": {State: []byte("state-three")}, "orphan": {State: []byte("other-branch")}}
	compact, err := compactRecords(records, []finalizedRecord{{Key: "a"}, {Key: "b"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range v.Omitted {
		if compact[k].State != nil || records[k].State == nil {
			t.Fatal("omission mutates live data")
		}
	}
	for _, k := range v.Retained {
		if !bytes.Equal(records[k].State, compact[k].State) {
			t.Fatal("wrong retention")
		}
	}
	records["a"].State = make([]byte, MaxStateBytes)
	records["b"].State = make([]byte, MaxStateBytes)
	if _, err = compactRecords(records, nil); err == nil {
		t.Fatal("aggregate memory budget bypass")
	}
	if maxWALBytes != 2*1024*1024 || MaxSnapshotBytes != maxWALBytes || MaxRecords != 128 {
		t.Fatal("old limits changed")
	}
}
