package consensus

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/dex/protocol"
)

func generationDictionaryFixture() diskState {
	s := dictionaryFixture()
	s.Version, s.ExecutionSchema = StorageGenerationVersion, AncestryExecutionSchema
	s.Records["a"].State, s.Records["c"].State = []byte("same-state"), []byte("same-state")
	s.Records["b"].State, s.Records["empty"].State = []byte{0, 255}, []byte{}
	return s
}

func generationDictionaryEnvelope(t *testing.T, p generationDictionaryWAL) walEnvelope {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return walEnvelope{b, protocol.Digest(walDigestDomain(generationDictionaryVersion), b)}
}

func TestGenerationDictionaryLosslessIndependentEncoding(t *testing.T) {
	s := generationDictionaryFixture()
	p, err := packGenerationDictionary(s)
	if err != nil {
		t.Fatal(err)
	}
	// Independent canonical ordering: nil, empty, 00ff, ASCII, ff00.
	wantActions := [][]byte{nil, {}, {0, 255}, []byte("same-body"), {255, 0}}
	wantStates := [][]byte{nil, {}, {0, 255}, []byte("same-state")}
	if !reflect.DeepEqual(p.ActionDictionary, wantActions) || !reflect.DeepEqual(p.StateDictionary, wantStates) || p.ActionRefs["a"] != 3 || p.StateRefs["a"] != 3 {
		t.Fatal("independent byte ordering/reference mismatch")
	}
	var golden struct{ Payload, Checksum string }
	vector, err := os.ReadFile("../testdata/wal_generation_dictionary.json")
	if err != nil || json.Unmarshal(vector, &golden) != nil {
		t.Fatal("independent golden", err)
	}
	component, err := json.Marshal(struct {
		actionDictionary
		StateDictionary [][]byte
		StateRefs       map[string]uint16
	}{p.actionDictionary, p.StateDictionary, p.StateRefs})
	if err != nil {
		t.Fatal(err)
	}
	digest := protocol.Digest(walDigestDomain(5), component)
	if hex.EncodeToString(component) != golden.Payload || hex.EncodeToString(digest[:]) != golden.Checksum {
		t.Fatal("independent canonical component/domain golden")
	}
	d, err := decodeWALPayload(generationDictionaryEnvelope(t, p))
	if err != nil || !reflect.DeepEqual(s, d) {
		t.Fatal("not a lossless v4 generation state", err)
	}
	d.Records["a"].Actions[0] ^= 1
	d.Records["a"].State[0] ^= 1
	if !bytes.Equal(d.Records["c"].Actions, s.Records["c"].Actions) || !bytes.Equal(d.Records["c"].State, s.Records["c"].State) || !bytes.Equal(p.StateDictionary[3], []byte("same-state")) {
		t.Fatal("dictionary expansion aliases records or source")
	}
	if MaxRecords != 128 || maxWALBytes != 2<<20 || maxExpandedActionBytes != 2<<20 || maxReplayStateBytes != 2<<20 || MaxActionBytes != 64<<10 || MaxStateBytes != 1<<20 {
		t.Fatal("existing storage/expansion limits changed")
	}
}

func TestGenerationDictionaryRejectsMalformedAndExpansion(t *testing.T) {
	mutations := map[string]func(*generationDictionaryWAL){
		"version":         func(p *generationDictionaryWAL) { p.Version++ },
		"missing-actions": func(p *generationDictionaryWAL) { p.ActionDictionary = nil },
		"missing-states":  func(p *generationDictionaryWAL) { p.StateDictionary = nil },
		"missing-ref":     func(p *generationDictionaryWAL) { delete(p.StateRefs, "a") },
		"foreign-ref":     func(p *generationDictionaryWAL) { p.StateRefs["foreign"] = p.StateRefs["a"]; delete(p.StateRefs, "a") },
		"out-of-range":    func(p *generationDictionaryWAL) { p.ActionRefs["a"] = uint16(len(p.ActionDictionary)) },
		"reordered": func(p *generationDictionaryWAL) {
			p.StateDictionary[0], p.StateDictionary[1] = p.StateDictionary[1], p.StateDictionary[0]
		},
		"duplicate": func(p *generationDictionaryWAL) {
			p.StateDictionary = append(p.StateDictionary, p.StateDictionary[len(p.StateDictionary)-1])
		},
		"unused": func(p *generationDictionaryWAL) { p.StateDictionary = append(p.StateDictionary, []byte{255}) },
		"oversized-state": func(p *generationDictionaryWAL) {
			p.StateDictionary[len(p.StateDictionary)-1] = bytes.Repeat([]byte{255}, MaxStateBytes+1)
		},
		"oversized-action": func(p *generationDictionaryWAL) {
			p.ActionDictionary[len(p.ActionDictionary)-1] = bytes.Repeat([]byte{255}, MaxActionBytes+1)
		},
		"inline-state":  func(p *generationDictionaryWAL) { p.Records["a"].State = []byte{} },
		"inline-action": func(p *generationDictionaryWAL) { p.Records["a"].Actions = []byte{} },
		"nil-record":    func(p *generationDictionaryWAL) { p.Records["a"] = nil },
		"too-many-records": func(p *generationDictionaryWAL) {
			for i := 0; i <= MaxRecords; i++ {
				p.Records[fmt.Sprint(i)] = &Record{}
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p, err := packGenerationDictionary(generationDictionaryFixture())
			if err != nil {
				t.Fatal(err)
			}
			mutate(&p)
			if _, err = decodeWALPayload(generationDictionaryEnvelope(t, p)); err == nil {
				t.Fatal("malformed dictionary accepted")
			}
		})
	}
	for _, field := range []string{"actions", "states"} {
		t.Run("weighted-"+field, func(t *testing.T) {
			s := generationDictionaryFixture()
			s.Records = map[string]*Record{}
			count := maxExpandedActionBytes / MaxActionBytes
			if field == "states" {
				count = maxReplayStateBytes / MaxStateBytes
			}
			for i := 0; i < count; i++ {
				r := &Record{}
				if field == "actions" {
					r.Actions = bytes.Repeat([]byte{1}, MaxActionBytes)
				} else {
					r.State = bytes.Repeat([]byte{1}, MaxStateBytes)
				}
				s.Records[fmt.Sprint(i)] = r
			}
			p, err := packGenerationDictionary(s)
			if err != nil {
				t.Fatal("exact weighted bound", err)
			}
			if _, err = decodeWALPayload(generationDictionaryEnvelope(t, p)); err != nil {
				t.Fatal(err)
			}
			p.Records["extra"] = &Record{}
			p.ActionRefs["extra"], p.StateRefs["extra"] = p.ActionRefs["0"], p.StateRefs["0"]
			if _, err = decodeWALPayload(generationDictionaryEnvelope(t, p)); err == nil {
				t.Fatal("weighted expansion amplification accepted")
			}
		})
	}
	p, _ := packGenerationDictionary(generationDictionaryFixture())
	e := generationDictionaryEnvelope(t, p)
	for name, mutate := range map[string]func([]byte) []byte{
		"duplicate-field": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"Version":5`), []byte(`"Version":5,"Version":5`), 1)
		},
		"unknown-field": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"Version":5`), []byte(`"Version":5,"Unknown":1`), 1)
		},
		"missing-inline": func(b []byte) []byte { return bytes.Replace(b, []byte(`"State":null,`), nil, 1) },
		"whitespace":     func(b []byte) []byte { return append([]byte(" "), b...) },
	} {
		t.Run(name, func(t *testing.T) {
			b := mutate(append([]byte(nil), e.Payload...))
			if bytes.Equal(b, e.Payload) {
				t.Fatal("mutation failed")
			}
			if _, err := decodeWALPayload(walEnvelope{b, protocol.Digest(walDigestDomain(5), b)}); err == nil {
				t.Fatal("noncanonical accepted")
			}
		})
	}
	e.Checksum = protocol.Digest(walDigestDomain(4), e.Payload)
	if _, err := decodeWALPayload(e); err == nil {
		t.Fatal("wrong digest domain accepted")
	}
}

func TestGenerationDictionaryAtomicSameGenerationRewrite(t *testing.T) {
	w, err := openWAL(filepath.Join(t.TempDir(), "fhs"))
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	w.generational = true
	s := generationDictionaryFixture()
	// Existing v4 canonical bytes remain readable before the local rewrite.
	b, _, err := envelopeBytes(s, walDigestDomain(4), maxWALBytes)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(w.dir, generationStateName(0))
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err = w.publishCurrent(0); err != nil {
		t.Fatal(err)
	}
	if got, err := w.load(s.Domain, s.VotePublic); err != nil || !reflect.DeepEqual(got, s) {
		t.Fatal("v4 read", err)
	}
	before, _ := os.ReadFile(filepath.Join(w.dir, "CURRENT"))
	crash := errors.New("injected partial v5 write")
	w.afterTemporaryChunk = func() error { return crash }
	if err = w.save(s); !errors.Is(err, crash) {
		t.Fatal("crash did not fire", err)
	}
	if got, err := w.load(s.Domain, s.VotePublic); err != nil || !reflect.DeepEqual(got, s) {
		t.Fatal("partial rewrite replaced durable state", err)
	}
	w.afterTemporaryChunk = nil
	if err = w.save(s); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope walEnvelope
	json.Unmarshal(raw, &envelope)
	var header struct{ Version uint16 }
	json.Unmarshal(envelope.Payload, &header)
	if header.Version != 5 {
		t.Fatal("not v5 local encoding")
	}
	if got, err := w.load(s.Domain, s.VotePublic); err != nil || !reflect.DeepEqual(got, s) {
		t.Fatal("v5 read changed any record/safety/state", err)
	}
	after, _ := os.ReadFile(filepath.Join(w.dir, "CURRENT"))
	if !bytes.Equal(before, after) {
		t.Fatal("same-generation rewrite changed CURRENT")
	}
	if err = os.WriteFile(path, append(raw, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = w.load(s.Domain, s.VotePublic); err == nil {
		t.Fatal("noncanonical outer envelope accepted")
	}
}

func TestGenerationDictionaryChangedBytesStillRequireAuthenticatedReplay(t *testing.T) {
	n := generationNetwork(t, 4)
	n.start(t)
	a := n.nodes[0]
	path := filepath.Join(a.wal.dir, generationStateName(a.disk.Generation))
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"action", "state"} {
		t.Run(field, func(t *testing.T) {
			var envelope walEnvelope
			if err := json.Unmarshal(original, &envelope); err != nil {
				t.Fatal(err)
			}
			s, err := decodeWALPayload(envelope)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range s.Records {
				if field == "action" && len(r.Actions) > 0 {
					r.Actions[0] ^= 1
					break
				}
				if field == "state" && len(r.State) > 0 {
					r.State[len(r.State)-1] ^= 1
					break
				}
			}
			p, err := packGenerationDictionary(s)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(generationDictionaryEnvelope(t, p))
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			if opened, err := Open(n.configs[0]); err == nil {
				opened.Close()
				t.Fatal("recomputed checksum authorized modified execution")
			}
		})
	}
}

func TestGenerationDictionaryUniqueBytesStillFailBeforeReplacement(t *testing.T) {
	w, err := openWAL(filepath.Join(t.TempDir(), "fhs"))
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	w.generational = true
	s := generationDictionaryFixture()
	if err = w.save(s); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(w.dir, generationStateName(0))
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Records = make(map[string]*Record)
	for i := 0; i < maxExpandedActionBytes/MaxActionBytes; i++ {
		s.Records[fmt.Sprint(i)] = &Record{Actions: bytes.Repeat([]byte{byte(i)}, MaxActionBytes)}
	}
	if err = w.save(s); err == nil {
		t.Fatal("unique dictionary bypassed physical 2MiB cap")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("oversized encoding replaced canonical state", err)
	}
}

func FuzzGenerationDictionaryCanonicalRoundTrip(f *testing.F) {
	p, err := packGenerationDictionary(generationDictionaryFixture())
	if err != nil {
		f.Fatal(err)
	}
	payload, err := json.Marshal(p)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(payload)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxWALBytes {
			return
		}
		var header struct{ Version uint16 }
		if json.Unmarshal(raw, &header) != nil || header.Version != generationDictionaryVersion {
			return
		}
		s, err := decodeWALPayload(walEnvelope{raw, protocol.Digest(walDigestDomain(5), raw)})
		if err != nil {
			return
		}
		if s.Version != StorageGenerationVersion {
			t.Fatal("decoded version changed")
		}
		canonical, err := generationWALPayload(s)
		if err != nil || !bytes.Equal(canonical, raw) {
			t.Fatal("accepted noncanonical generation dictionary", err)
		}
	})
}
