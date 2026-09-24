package consensus

import (
	"encoding/json"
	"errors"
	"sort"
)

// generationDictionaryVersion changes only the local hot-WAL representation.
// Decoding returns the same v4 generation state; CURRENT, archive records,
// financial schema, proposal bytes and consensus state are unchanged.
const generationDictionaryVersion uint16 = 5

type generationDictionaryWAL struct {
	diskState
	actionDictionary
	StateDictionary [][]byte
	StateRefs       map[string]uint16
}

// byteDictionary never aliases the caller's data. nil and an empty byte slice
// remain distinct, as they have distinct canonical JSON representations.
func byteDictionary(values [][]byte) [][]byte {
	sort.Slice(values, func(i, j int) bool { return actionLess(values[i], values[j]) })
	out := make([][]byte, 0, len(values))
	for _, value := range values {
		if len(out) == 0 || !sameAction(out[len(out)-1], value) {
			out = append(out, cloneAction(value))
		}
	}
	return out
}

func dictionaryIndex(dictionary [][]byte, value []byte) uint16 {
	return uint16(sort.Search(len(dictionary), func(i int) bool { return !actionLess(dictionary[i], value) }))
}

func packGenerationDictionary(state diskState) (generationDictionaryWAL, error) {
	var out generationDictionaryWAL
	if state.Version != StorageGenerationVersion || state.Records == nil || len(state.Records) > MaxRecords || len(state.Finalized) > MaxRecords {
		return out, errors.New("invalid generation dictionary source")
	}
	if err := replayStateBudget(state.Records); err != nil {
		return out, err
	}
	actions, states := make([][]byte, 0, len(state.Records)), make([][]byte, 0, len(state.Records))
	var total int
	for _, record := range state.Records {
		if record == nil || len(record.Actions) > MaxActionBytes {
			return out, errors.New("invalid generation dictionary action")
		}
		total += len(record.Actions)
		if total > maxExpandedActionBytes {
			return out, errors.New("DEX expanded action budget exhausted")
		}
		actions, states = append(actions, record.Actions), append(states, record.State)
	}
	out.diskState = state
	out.Version = generationDictionaryVersion
	out.ActionDictionary, out.StateDictionary = byteDictionary(actions), byteDictionary(states)
	out.ActionRefs, out.StateRefs = make(map[string]uint16, len(state.Records)), make(map[string]uint16, len(state.Records))
	out.Records = make(map[string]*Record, len(state.Records))
	for key, record := range state.Records {
		copyRecord := *record
		copyRecord.Actions, copyRecord.State = nil, nil
		out.Records[key] = &copyRecord
		out.ActionRefs[key] = dictionaryIndex(out.ActionDictionary, record.Actions)
		out.StateRefs[key] = dictionaryIndex(out.StateDictionary, record.State)
	}
	return out, nil
}

// Validate weighted expansion, all references and canonical dictionary order
// before allocating any expanded record bytes. Limits count occurrences, not
// unique dictionary entries; compression cannot bypass existing replay budgets.
func validateGenerationDictionary(dictionary [][]byte, refs map[string]uint16, records map[string]*Record, individual, expanded int) error {
	if dictionary == nil || len(dictionary) > MaxRecords || refs == nil || len(refs) != len(records) {
		return errors.New("invalid generation dictionary bounds")
	}
	for i, value := range dictionary {
		if len(value) > individual || i > 0 && !actionLess(dictionary[i-1], value) {
			return errors.New("invalid generation dictionary order/size")
		}
	}
	used, total := make([]bool, len(dictionary)), 0
	for key, record := range records {
		index, ok := refs[key]
		if record == nil || record.Actions != nil || record.State != nil || !ok || int(index) >= len(dictionary) {
			return errors.New("invalid generation dictionary reference")
		}
		used[index] = true
		total += len(dictionary[index])
		if total > expanded {
			return errors.New("generation dictionary expansion budget exhausted")
		}
	}
	for _, present := range used {
		if !present {
			return errors.New("unused generation dictionary entry")
		}
	}
	return nil
}

func unpackGenerationDictionary(in generationDictionaryWAL) (diskState, error) {
	var out diskState
	if in.Version != generationDictionaryVersion || in.Records == nil || len(in.Records) > MaxRecords || len(in.Finalized) > MaxRecords {
		return out, errors.New("invalid generation dictionary schema")
	}
	if err := validateGenerationDictionary(in.ActionDictionary, in.ActionRefs, in.Records, MaxActionBytes, maxExpandedActionBytes); err != nil {
		return out, err
	}
	if err := validateGenerationDictionary(in.StateDictionary, in.StateRefs, in.Records, MaxStateBytes, maxReplayStateBytes); err != nil {
		return out, err
	}
	out = in.diskState
	out.Version = StorageGenerationVersion
	out.Records = make(map[string]*Record, len(in.Records))
	for key, record := range in.Records {
		copyRecord := *record
		copyRecord.Actions = cloneAction(in.ActionDictionary[in.ActionRefs[key]])
		copyRecord.State = cloneAction(in.StateDictionary[in.StateRefs[key]])
		out.Records[key] = &copyRecord
	}
	return out, nil
}

func generationWALPayload(state diskState) ([]byte, error) {
	packed, err := packGenerationDictionary(state)
	if err != nil {
		return nil, err
	}
	return json.Marshal(packed)
}
