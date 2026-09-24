package consensus

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func dictionaryFixture() diskState {
	return diskState{Version: 2, ExecutionSchema: RollingExecutionSchema,
		Safety: hotstuff.NewFHSSafetyState(), Records: map[string]*Record{
			"a": {Actions: []byte("same-body")}, "b": {Actions: []byte{0, 255}},
			"c": {Actions: []byte("same-body")}, "empty": {Actions: []byte{}},
			"nil": {}, "orphan": {Actions: []byte{255, 0}},
		}}
}

func dictionaryEnvelope(t *testing.T, packed dictionaryWAL) walEnvelope {
	t.Helper()
	payload, err := json.Marshal(packed)
	if err != nil {
		t.Fatal(err)
	}
	return walEnvelope{payload, protocol.Digest(walDigestDomain(3), payload)}
}

func TestWALDictionaryIndependentGoldenAndOwnedExpansion(t *testing.T) {
	data, err := os.ReadFile("../testdata/wal_dictionary.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Component         actionDictionary
		Payload, Checksum string
		Expanded          int `json:"expanded_action_bytes"`
	}
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	source := dictionaryFixture()
	packed, err := packDictionary(source)
	if err != nil || !reflect.DeepEqual(packed.actionDictionary, golden.Component) {
		t.Fatal("independent dictionary/ref golden", err)
	}
	component, _ := json.Marshal(packed.actionDictionary)
	if hex.EncodeToString(component) != golden.Payload {
		t.Fatal("component canonical bytes differ from independent model")
	}
	sum := protocol.Digest(walDigestDomain(3), component)
	if hex.EncodeToString(sum[:]) != golden.Checksum {
		t.Fatal("independent v3 digest")
	}
	decoded, err := decodeWALPayload(dictionaryEnvelope(t, packed))
	if err != nil || !reflect.DeepEqual(decoded, source) {
		t.Fatal("lossless normalized v2 state", err)
	}
	total := 0
	for _, r := range decoded.Records {
		total += len(r.Actions)
	}
	if total != golden.Expanded || decoded.Records["empty"].Actions == nil || decoded.Records["nil"].Actions != nil {
		t.Fatal("nil/empty or weighted expansion changed")
	}
	decoded.Records["a"].Actions[0] ^= 1
	if !bytes.Equal(decoded.Records["c"].Actions, []byte("same-body")) || !bytes.Equal(source.Records["a"].Actions, []byte("same-body")) || !bytes.Equal(packed.ActionDictionary[packed.ActionRefs["a"]], []byte("same-body")) {
		t.Fatal("expanded records alias each other, dictionary or source")
	}
	if MaxActionBytes != 64*1024 || maxExpandedActionBytes != 2*1024*1024 || maxWALBytes != 2*1024*1024 || MaxRecords != 128 || maxReplayStateBytes != 2*1024*1024 {
		t.Fatal("existing bounds enlarged")
	}
}

func TestWALDictionaryRejectsMalformedCanonicalPayloads(t *testing.T) {
	cases := map[string]func(*dictionaryWAL){
		"unknown-version":    func(p *dictionaryWAL) { p.Version = 4 },
		"schema":             func(p *dictionaryWAL) { p.ExecutionSchema = NativeExecutionSchema },
		"missing-dictionary": func(p *dictionaryWAL) { p.ActionDictionary = nil },
		"missing-ref":        func(p *dictionaryWAL) { delete(p.ActionRefs, "a") },
		"foreign-ref":        func(p *dictionaryWAL) { p.ActionRefs["foreign"] = p.ActionRefs["a"]; delete(p.ActionRefs, "a") },
		"out-of-range":       func(p *dictionaryWAL) { p.ActionRefs["a"] = uint16(len(p.ActionDictionary)) },
		"duplicate-content": func(p *dictionaryWAL) {
			p.ActionDictionary = append(p.ActionDictionary, p.ActionDictionary[len(p.ActionDictionary)-1])
		},
		"reordered": func(p *dictionaryWAL) {
			p.ActionDictionary[0], p.ActionDictionary[1] = p.ActionDictionary[1], p.ActionDictionary[0]
		},
		"unused": func(p *dictionaryWAL) { p.ActionDictionary = append(p.ActionDictionary, []byte{255, 255}) },
		"oversized-action": func(p *dictionaryWAL) {
			p.ActionDictionary[len(p.ActionDictionary)-1] = bytes.Repeat([]byte{255}, MaxActionBytes+1)
		},
		"non-null-actions": func(p *dictionaryWAL) { p.Records["a"].Actions = []byte{} },
		"nil-record":       func(p *dictionaryWAL) { p.Records["a"] = nil },
		"record-count": func(p *dictionaryWAL) {
			for i := 0; i < MaxRecords; i++ {
				k := fmt.Sprint(i)
				p.Records[k] = &Record{}
				p.ActionRefs[k] = 0
			}
		},
		"dictionary-count": func(p *dictionaryWAL) { p.ActionDictionary = make([][]byte, MaxRecords+1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := packDictionary(dictionaryFixture())
			if err != nil {
				t.Fatal(err)
			}
			mutate(&p)
			if _, err = decodeWALPayload(dictionaryEnvelope(t, p)); err == nil {
				t.Fatal("malformed dictionary accepted")
			}
		})
	}
	p, err := packDictionary(dictionaryFixture())
	if err != nil {
		t.Fatal(err)
	}
	e := dictionaryEnvelope(t, p)
	for name, mutate := range map[string]func([]byte) []byte{
		"duplicate-field": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"Version":3`), []byte(`"Version":3,"Version":3`), 1)
		},
		"unknown-field": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"Version":3`), []byte(`"Version":3,"Unknown":0`), 1)
		},
		"missing-actions-field": func(b []byte) []byte { return bytes.Replace(b, []byte(`"Actions":null,`), nil, 1) },
		"missing-state-field":   func(b []byte) []byte { return bytes.Replace(b, []byte(`"State":null,`), nil, 1) },
		"whitespace":            func(b []byte) []byte { return append([]byte(" "), b...) },
	} {
		t.Run(name, func(t *testing.T) {
			b := mutate(append([]byte(nil), e.Payload...))
			if bytes.Equal(b, e.Payload) {
				t.Fatal("mutation did not apply")
			}
			if _, err := decodeWALPayload(walEnvelope{b, protocol.Digest(walDigestDomain(3), b)}); err == nil {
				t.Fatal("noncanonical payload accepted")
			}
		})
	}
	e.Checksum = protocol.Digest(walDigestDomain(2), e.Payload)
	if _, err := decodeWALPayload(e); err == nil {
		t.Fatal("wrong checksum domain accepted")
	}
}

func TestWALDictionaryExpansionAndEmptyBounds(t *testing.T) {
	for _, count := range []int{32, 33} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			p := dictionaryWAL{diskState: diskState{Version: 3, ExecutionSchema: RollingExecutionSchema, Records: map[string]*Record{}},
				actionDictionary: actionDictionary{[][]byte{bytes.Repeat([]byte{1}, MaxActionBytes)}, map[string]uint16{}}}
			for i := 0; i < count; i++ {
				k := fmt.Sprint(i)
				p.Records[k] = &Record{}
				p.ActionRefs[k] = 0
			}
			decoded, err := decodeWALPayload(dictionaryEnvelope(t, p))
			if count == 32 {
				if err != nil || len(decoded.Records["0"].Actions) != MaxActionBytes {
					t.Fatal("exact weighted cap", err)
				}
				decoded.Records["0"].Actions[0] = 2
				if decoded.Records["1"].Actions[0] != 1 {
					t.Fatal("shared expansion")
				}
			} else if err == nil || !strings.Contains(err.Error(), "expanded action budget") {
				t.Fatal("weighted amplification accepted", err)
			}
		})
	}
	// The first disallowed byte is rejected too, not only a full extra action.
	boundary := dictionaryWAL{diskState: diskState{Version: 3, ExecutionSchema: RollingExecutionSchema, Records: map[string]*Record{}},
		actionDictionary: actionDictionary{[][]byte{bytes.Repeat([]byte{1}, MaxActionBytes), {2}}, map[string]uint16{}}}
	for i := 0; i < 32; i++ {
		k := fmt.Sprint(i)
		boundary.Records[k] = &Record{}
		boundary.ActionRefs[k] = 0
	}
	boundary.Records["extra"] = &Record{}
	boundary.ActionRefs["extra"] = 1
	if _, err := decodeWALPayload(dictionaryEnvelope(t, boundary)); err == nil || !strings.Contains(err.Error(), "expanded action budget") {
		t.Fatal("max+1 expanded byte accepted", err)
	}
	s := dictionaryFixture()
	s.Records = map[string]*Record{}
	p, err := packDictionary(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeWALPayload(dictionaryEnvelope(t, p)); err != nil {
		t.Fatal("canonical empty dictionary", err)
	}
	p.ActionDictionary = nil
	if _, err := decodeWALPayload(dictionaryEnvelope(t, p)); err == nil {
		t.Fatal("null empty dictionary accepted")
	}
	p.ActionDictionary = [][]byte{}
	p.ActionRefs = nil
	if _, err := decodeWALPayload(dictionaryEnvelope(t, p)); err == nil {
		t.Fatal("null refs accepted")
	}
}

func TestWALDictionaryRealRecordsReachAuthentication(t *testing.T) {
	n := compactNetwork(t)
	n.start(t)
	a := n.nodes[0]
	path := filepath.Join(n.configs[0].DataDir, "state.json")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	original := readCompact(t, path)
	base, _ := json.Marshal(original)
	for name, mutate := range map[string]func(*diskState){
		"action":        func(d *diskState) { d.Records[d.Finalized[0].Key].Actions[0] ^= 1 },
		"root":          func(d *diskState) { d.Records[d.Finalized[0].Key].Checkpoint.PostRoot[0] ^= 1 },
		"ref":           func(d *diskState) { d.Records[d.Finalized[0].Key].Ref[0] ^= 1 },
		"qc-signature":  func(d *diskState) { d.Records[d.Finalized[0].Key].QC.Sign[0] ^= 1 },
		"finality":      func(d *diskState) { d.Finalized[0].Proof = []byte{1} },
		"present-state": func(d *diskState) { d.Records[d.Finalized[len(d.Finalized)-1].Key].State[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			var d diskState
			if err := json.Unmarshal(base, &d); err != nil {
				t.Fatal(err)
			}
			mutate(&d)
			p, err := packDictionary(d)
			if err != nil {
				t.Fatal(err)
			}
			e := dictionaryEnvelope(t, p)
			if _, err := decodeWALPayload(e); err != nil {
				t.Fatal("must pass structural codec before consensus checks", err)
			}
			raw, _ := json.Marshal(e)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if reopened, err := Open(n.configs[0]); err == nil {
				reopened.Close()
				t.Fatal("checksum-valid v3 consensus corruption accepted")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(raw, after) {
				t.Fatal("invalid v3 input was rewritten")
			}
		})
	}
}

func TestWALDictionaryColdReplayLegacyAndSnapshot(t *testing.T) {
	n := newConfiguredNetwork(t, 6, func(c *Config) {
		c.Execution = new(compactExecution)
		c.Actions = func(uint64) ([]byte, error) { return []byte{1}, nil }
	})
	n.start(t)
	const index = 5 // real QC leader outbox
	a := n.nodes[index]
	expected := a.disk
	expected.Version = 2
	want, _ := json.Marshal(expected)
	path := filepath.Join(n.configs[index].DataDir, "state.json")
	for _, version := range []uint16{3, 1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			if version != 3 {
				d := expected
				d.Version = version
				if version == 2 {
					var err error
					d.Records, err = compactRecords(d.Records, d.Finalized)
					if err != nil {
						t.Fatal(err)
					}
				}
				writeCompact(t, path, d)
			}
			var err error
			a, err = Open(n.configs[index])
			if err != nil {
				t.Fatal(err)
			}
			n.nodes[index] = a
			restored := a.disk
			restored.Version = 2
			got, _ := json.Marshal(restored)
			if !bytes.Equal(got, want) {
				t.Fatal("replay changed record/actions/roots/refs/QCs/finality/safety/outbox")
			}
			raw, _ := os.ReadFile(path)
			var e walEnvelope
			if err = json.Unmarshal(raw, &e); err != nil {
				t.Fatal(err)
			}
			var p dictionaryWAL
			if err = decodeStrict(e.Payload, &p); err != nil || p.Version != 3 || len(p.ActionDictionary) != 1 || len(p.ActionRefs) != 6 {
				t.Fatal("not authenticated v3 migration", err)
			}
			for h := uint64(1); h <= 5; h++ {
				state, err := a.FinalizedState(h)
				if err != nil || binary.BigEndian.Uint64(state) != h {
					t.Fatal("historical finalized state", err)
				}
			}
		})
	}
	snapshot, err := a.ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	var s replaySnapshot
	if err := decodeStrict(snapshot, &s); err != nil || s.Version != 2 || len(s.Records) != 6 {
		t.Fatal("snapshot v2 changed", err)
	}
	for _, r := range s.Records {
		if !bytes.Equal(r.Actions, []byte{1}) {
			t.Fatal("snapshot not expanded")
		}
	}
	c := n.configs[6]
	if err := n.nodes[6].Close(); err != nil {
		t.Fatal(err)
	}
	c.DataDir = filepath.Join(t.TempDir(), "peer")
	peer, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	s.Version = 3
	invalid, _ := json.Marshal(s)
	if err := peer.ImportSnapshot(invalid); err == nil {
		t.Fatal("local v3 accepted as snapshot")
	}
	if err := peer.ImportSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	if peer.FinalizedHeight() != 5 || peer.disk.Safety.LastVote != nil || peer.disk.VotePublic == a.disk.VotePublic {
		t.Fatal("snapshot state/identity boundary changed")
	}
}

func TestWALDictionaryUpgradeWaitsForAuthenticatedRecovery(t *testing.T) {
	n := compactNetwork(t)
	n.start(t)
	a := n.nodes[0]
	p := filepath.Join(n.configs[0].DataDir, "state.json")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	legacy := readCompact(t, p)
	writeCompact(t, p, legacy)
	before, _ := os.ReadFile(p)
	c := n.configs[0]
	c.RestoreVote = func(*hotstuff.PersistedVote) error { return errors.New("fixture recovery refusal") }
	if reopened, err := Open(c); err == nil {
		reopened.Close()
		t.Fatal("failed callback permitted upgrade")
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("legacy rewritten before callback passed")
	}
	legacy.Records[legacy.Finalized[0].Key].Actions[0] ^= 1
	writeCompact(t, p, legacy)
	before, _ = os.ReadFile(p)
	if reopened, err := Open(n.configs[0]); err == nil {
		reopened.Close()
		t.Fatal("invalid legacy execution upgraded")
	}
	after, _ = os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("corrupt legacy was overwritten")
	}
}

func TestWALDictionaryUniqueBodyCapStopsBeforeCanonicalReplacement(t *testing.T) {
	// Codec-size fixture only: these are not authenticated financial proposals.
	// Real FHS replay/safety is covered separately above and by the compact suite.
	w, err := openWAL(filepath.Join(t.TempDir(), "wal"))
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	s := dictionaryFixture()
	if err := w.save(s); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(w.dir, "state.json")
	before, _ := os.ReadFile(path)
	s.Records = make(map[string]*Record)
	for i := 0; i < MaxRecords; i++ {
		s.Records[fmt.Sprint(i)] = &Record{Actions: bytes.Repeat([]byte{byte(i)}, 16*1024)}
	}
	if _, err := packDictionary(s); err != nil {
		t.Fatal("raw expansion must fit exactly", err)
	}
	w.cleanupPending = false // no crash temporary exists in this codec-size fixture
	a := &Application{wal: w, disk: s}
	err = a.persist()
	if err == nil || !strings.Contains(err.Error(), "WAL byte budget exhausted") || a.fatal == nil {
		t.Fatal("unique content cap did not disable signing", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("over-cap save replaced canonical data")
	}
	if _, err := os.Stat(filepath.Join(w.dir, walPendingName)); !os.IsNotExist(err) {
		t.Fatal("over-cap save created a temporary generation")
	}
	if err := a.Start(); err == nil {
		t.Fatal("persistence failure allowed signing restart")
	}
}

func TestWALDictionaryPublicArtifactStructuralComparison(t *testing.T) {
	root, estimatePath := os.Getenv("DEX_WAL_DICTIONARY_PUBLIC_ROOT"), os.Getenv("DEX_WAL_DICTIONARY_ESTIMATE")
	if root == "" || estimatePath == "" {
		t.Skip("optional retained public WAL structural comparison; no node or datadir mutation")
	}
	data, err := os.ReadFile(estimatePath)
	if err != nil {
		t.Fatal(err)
	}
	var estimate struct {
		Rows []struct {
			Node          string
			ProposedBytes int    `json:"proposed_bytes"`
			PayloadSHA    string `json:"proposed_payload_sha256"`
			InputSHA      string `json:"input_sha256"`
		}
	}
	if err := json.Unmarshal(data, &estimate); err != nil {
		t.Fatal(err)
	}
	if len(estimate.Rows) != 7 {
		t.Fatal("expected all seven retained public nodes")
	}
	for _, row := range estimate.Rows {
		t.Run(row.Node, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, row.Node, "dex", "fhs", "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprintf("%x", sha256.Sum256(raw)) != row.InputSHA {
				t.Fatal("retained public source changed")
			}
			var e walEnvelope
			if err := decodeStrict(raw, &e); err != nil {
				t.Fatal(err)
			}
			d, err := decodeWALPayload(e)
			if err != nil {
				t.Fatal(err)
			}
			p, err := packDictionary(d)
			if err != nil {
				t.Fatal(err)
			}
			out := dictionaryEnvelope(t, p)
			if fmt.Sprintf("%x", sha256.Sum256(out.Payload)) != row.PayloadSHA {
				t.Fatal("independent Python payload differs")
			}
			encoded, _ := json.Marshal(out)
			if len(encoded) != row.ProposedBytes {
				t.Fatal("independent encoded size differs")
			}
			expanded, err := decodeWALPayload(out)
			if err != nil || !reflect.DeepEqual(d, expanded) {
				t.Fatal("record/action/state/proof loss in structural round trip", err)
			}
			t.Logf("read-only structural comparison records=%d before=%d after=%d; not consensus recovery", len(d.Records), len(raw), len(encoded))
		})
	}
}
