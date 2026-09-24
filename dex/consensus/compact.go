package consensus

import "errors"

// Version 2 removes only redundant finalized state copies. Every action and
// certificate remains available for authenticated replay from configured genesis.
const maxReplayStateBytes = 2 * 1024 * 1024

func replayVersion(version, schema uint16) bool {
	return version == 1 || version == 2 && schema == RollingExecutionSchema || version == StorageGenerationVersion
}

func walDigestDomain(version uint16) string {
	if version == generationDictionaryVersion {
		return "common-dex/wal/v5"
	}
	if version == StorageGenerationVersion {
		return "common-dex/wal/v4"
	}
	if version == 3 {
		return "common-dex/wal/v3"
	}
	if version == 2 {
		return "common-dex/wal/v2"
	}
	return "common-dex/wal/v1"
}

func omittedStates(finalized []finalizedRecord) map[string]bool {
	omitted := make(map[string]bool)
	for i := 0; i+1 < len(finalized); i++ {
		omitted[finalized[i].Key] = true
	}
	return omitted
}

func compactRecords(records map[string]*Record, finalized []finalizedRecord) (map[string]*Record, error) {
	if err := replayStateBudget(records); err != nil {
		return nil, err
	}
	omitted := omittedStates(finalized)
	out := make(map[string]*Record, len(records))
	for key, r := range records {
		copyRecord := *r
		if omitted[key] {
			copyRecord.State = nil
		}
		out[key] = &copyRecord
	}
	return out, nil
}

func compactLayout(version uint16, records map[string]*Record, finalized []finalizedRecord) error {
	if version != 2 {
		return nil
	}
	omitted := omittedStates(finalized)
	for key, r := range records {
		if r == nil || (r.State == nil) != omitted[key] {
			return errors.New("invalid compact replay state layout")
		}
	}
	return nil
}

func replayStateBudget(records map[string]*Record) error {
	total := 0
	for _, r := range records {
		if r == nil || len(r.State) > MaxStateBytes {
			return errors.New("invalid replay state size")
		}
		total += len(r.State)
		if total > maxReplayStateBytes {
			return errors.New("DEX reconstructed state budget exhausted")
		}
	}
	return nil
}
