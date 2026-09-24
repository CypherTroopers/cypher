package consensus

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"

	"github.com/cypherium/cypher/dex/protocol"
)

// This limit counts every occurrence, not merely unique dictionary entries.
// It is a local decode bound; action/wire/proof limits are unchanged.
const maxExpandedActionBytes = 2 * 1024 * 1024

type actionDictionary struct {
	ActionDictionary [][]byte
	ActionRefs       map[string]uint16
}

type dictionaryWAL struct {
	diskState
	actionDictionary
}

func actionLess(a, b []byte) bool {
	if (a == nil) != (b == nil) {
		return a == nil
	}
	return bytes.Compare(a, b) < 0
}

func sameAction(a, b []byte) bool {
	return (a == nil) == (b == nil) && bytes.Equal(a, b)
}

func cloneAction(a []byte) []byte {
	if a == nil {
		return nil
	}
	b := make([]byte, len(a))
	copy(b, a)
	return b
}

// packDictionary leaves the live records untouched. State compaction is a
// separate, unchanged v2 step performed by the writer before this function.
func packDictionary(state diskState) (dictionaryWAL, error) {
	var out dictionaryWAL
	if state.Version != 2 || state.ExecutionSchema != RollingExecutionSchema || state.Records == nil || len(state.Records) > MaxRecords || len(state.Finalized) > MaxRecords {
		return out, errors.New("invalid action dictionary source")
	}
	dictionary := make([][]byte, 0, len(state.Records))
	total := 0
	for _, r := range state.Records {
		if r == nil || len(r.Actions) > MaxActionBytes {
			return out, errors.New("invalid action dictionary record")
		}
		total += len(r.Actions)
		if total > maxExpandedActionBytes {
			return out, errors.New("DEX expanded action budget exhausted")
		}
		dictionary = append(dictionary, r.Actions)
	}
	sort.Slice(dictionary, func(i, j int) bool { return actionLess(dictionary[i], dictionary[j]) })
	unique := make([][]byte, 0, len(dictionary))
	for _, action := range dictionary {
		if len(unique) == 0 || !sameAction(unique[len(unique)-1], action) {
			unique = append(unique, cloneAction(action))
		}
	}
	out.diskState = state
	out.Version = 3
	out.Records = make(map[string]*Record, len(state.Records))
	out.ActionDictionary = unique
	out.ActionRefs = make(map[string]uint16, len(state.Records))
	for key, r := range state.Records {
		i := sort.Search(len(unique), func(i int) bool { return !actionLess(unique[i], r.Actions) })
		copyRecord := *r
		copyRecord.Actions = nil
		out.Records[key] = &copyRecord
		out.ActionRefs[key] = uint16(i)
	}
	return out, nil
}

// unpackDictionary validates the entire weighted expansion before cloning any
// action. The returned state deliberately uses the unchanged v2 replay rules.
func unpackDictionary(in dictionaryWAL) (diskState, error) {
	var out diskState
	if in.Version != 3 || in.ExecutionSchema != RollingExecutionSchema || in.Records == nil || len(in.Records) > MaxRecords || len(in.Finalized) > MaxRecords || in.ActionDictionary == nil || len(in.ActionDictionary) > MaxRecords || in.ActionRefs == nil || len(in.ActionRefs) != len(in.Records) {
		return out, errors.New("invalid action dictionary bounds/schema")
	}
	for i, action := range in.ActionDictionary {
		if len(action) > MaxActionBytes || i > 0 && !actionLess(in.ActionDictionary[i-1], action) {
			return out, errors.New("invalid action dictionary order/size")
		}
	}
	used := make([]bool, len(in.ActionDictionary))
	total := 0
	for key, r := range in.Records {
		index, ok := in.ActionRefs[key]
		if r == nil || r.Actions != nil || !ok || int(index) >= len(in.ActionDictionary) {
			return out, errors.New("invalid action dictionary reference")
		}
		used[index] = true
		total += len(in.ActionDictionary[index])
		if total > maxExpandedActionBytes {
			return out, errors.New("DEX expanded action budget exhausted")
		}
	}
	for _, used := range used {
		if !used {
			return out, errors.New("unused action dictionary entry")
		}
	}
	out = in.diskState
	out.Version = 2
	out.Records = make(map[string]*Record, len(in.Records))
	for key, r := range in.Records {
		copyRecord := *r
		copyRecord.Actions = cloneAction(in.ActionDictionary[in.ActionRefs[key]])
		out.Records[key] = &copyRecord
	}
	return out, nil
}

// decodeWALPayload checks local checksum integrity and canonical encoding
// before dictionary expansion. Full consensus authentication follows in recover.
func decodeWALPayload(envelope walEnvelope) (diskState, error) {
	var state diskState
	var header struct{ Version uint16 }
	if err := json.Unmarshal(envelope.Payload, &header); err != nil {
		return state, err
	}
	if header.Version == generationDictionaryVersion {
		var packed generationDictionaryWAL
		if err := decodeStrict(envelope.Payload, &packed); err != nil {
			return state, err
		}
		if protocol.Digest(walDigestDomain(header.Version), envelope.Payload) != envelope.Checksum {
			return state, errors.New("DEX WAL checksum mismatch")
		}
		canonical, err := json.Marshal(packed)
		if err != nil || !bytes.Equal(canonical, envelope.Payload) {
			return state, errors.New("noncanonical generation dictionary WAL payload")
		}
		return unpackGenerationDictionary(packed)
	}
	if header.Version == 3 {
		var packed dictionaryWAL
		if err := decodeStrict(envelope.Payload, &packed); err != nil {
			return state, err
		}
		if protocol.Digest(walDigestDomain(header.Version), envelope.Payload) != envelope.Checksum {
			return state, errors.New("DEX WAL checksum mismatch")
		}
		canonical, err := json.Marshal(packed)
		if err != nil || !bytes.Equal(canonical, envelope.Payload) {
			return state, errors.New("noncanonical dictionary WAL payload")
		}
		return unpackDictionary(packed)
	}
	if err := decodeStrict(envelope.Payload, &state); err != nil {
		return state, err
	}
	if protocol.Digest(walDigestDomain(state.Version), envelope.Payload) != envelope.Checksum {
		return state, errors.New("DEX WAL checksum mismatch")
	}
	if state.Version == 2 || state.Version == StorageGenerationVersion {
		canonical, err := json.Marshal(state)
		if err != nil || !bytes.Equal(canonical, envelope.Payload) {
			return state, errors.New("noncanonical compact WAL payload")
		}
	}
	return state, nil
}
