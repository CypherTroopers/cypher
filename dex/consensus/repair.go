package consensus

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

const MaxProposalDataBytes = 128 * 1024

// SelectedCertifiedData returns the ancestor of the authenticated highest QC,
// not the highest-view sibling independently selected at each height. This is
// read-only planning data; a single QC still does not assert finality. The hot
// walk is bounded by MaxRecords and never mutates selection or vote safety.
func (a *Application) SelectedCertifiedData(height uint64) ([]byte, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	if height == 0 || height > a.config.MaxHeight {
		return nil, ErrUnavailable
	}
	var selected *Record
	if height <= a.FinalizedHeight() {
		var err error
		selected, _, err = a.finalizedRecordAt(height)
		if err != nil {
			return nil, err
		}
	} else {
		if len(a.disk.Records) > MaxRecords {
			return nil, ErrUnavailable
		}
		// Index once so each query does O(MaxRecords) metadata work rather
		// than rehashing the whole hot set at every ancestor hop.
		parents := make(map[common.Hash]*hotstuff.SignedState, len(a.disk.Records))
		for _, r := range a.disk.Records {
			if r == nil || r.QC == nil {
				continue
			}
			id, err := hotstuff.SignedStateID(r.QC)
			if err != nil {
				return nil, err
			}
			parents[id.Hash()] = r.QC
		}
		qc := a.disk.Safety.HighestQC
		for work := 0; work < MaxRecords && qc != nil; work++ {
			r := a.recordForQC(qc)
			if r == nil || r.QC == nil || !hotstuff.SignedStateSemanticEqual(qc, r.QC) || !bytes.Equal(r.Ref, qc.State) {
				return nil, ErrUnavailable
			}
			ref, err := types.DecodeHotstuffProposalRef(r.Ref)
			hash, hashErr := r.Checkpoint.Hash()
			if err != nil || hashErr != nil || ref.Number != r.Checkpoint.Sequence || ref.BlockHash != common.Hash(hash) || ref.StateRoot != common.Hash(r.Checkpoint.PostRoot) || ref.ViewNumber != qc.Number {
				return nil, errors.New("selected certified record binding")
			}
			if r.Checkpoint.Sequence < height {
				return nil, ErrUnavailable
			}
			if r.Checkpoint.Sequence == height {
				selected = r
				break
			}
			parent := parents[ref.ParentQCID]
			if parent == nil {
				return nil, ErrUnavailable
			}
			previous := a.recordForQC(parent)
			if previous == nil {
				return nil, ErrUnavailable
			}
			previousHash, err := previous.Checkpoint.Hash()
			if err != nil || previous.Checkpoint.Sequence+1 != r.Checkpoint.Sequence || parent.Number >= qc.Number || ref.ParentHash != common.Hash(previousHash) || r.Checkpoint.Previous != previousHash || r.Checkpoint.PreRoot != previous.Checkpoint.PostRoot || r.Checkpoint.InboxStart != previous.Checkpoint.InboxEnd {
				return nil, errors.New("selected certified parent continuity")
			}
			qc = parent
		}
	}
	if selected == nil {
		return nil, ErrUnavailable
	}
	raw, err := json.Marshal(selected)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxProposalDataBytes {
		return nil, ErrUnavailable
	}
	return raw, nil
}

// LatestCertifiedData is a bounded read used to inspect one certified state.
// Certification is not finality. Historical finalized heights read one entry
// authenticated against the cold-reconstructed digest index.
func (a *Application) LatestCertifiedData(height uint64) ([]byte, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	if height == 0 || height > a.config.MaxHeight {
		return nil, ErrUnavailable
	}
	var selected *Record
	if height <= a.disk.BaseHeight {
		var err error
		selected, _, err = a.archived(height)
		if err != nil {
			return nil, err
		}
	} else {
		for _, r := range a.disk.Records {
			if r.Checkpoint.Sequence != height || r.QC == nil {
				continue
			}
			if selected == nil || r.QC.Number > selected.QC.Number {
				selected = r
			}
		}
		// Determine the highest view before checking its uniqueness. Otherwise
		// a lower-view conflict could make this read depend on map iteration.
		if selected != nil {
			for _, r := range a.disk.Records {
				if r.Checkpoint.Sequence == height && r.QC != nil && r.QC.Number == selected.QC.Number && !hotstuff.SignedStateSemanticEqual(r.QC, selected.QC) {
					return nil, errors.New("conflicting certified records at highest view")
				}
			}
		}
	}
	if selected == nil {
		return nil, ErrUnavailable
	}
	raw, err := json.Marshal(selected)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxProposalDataBytes {
		return nil, ErrUnavailable
	}
	return raw, nil
}

// CertifiedData serves authenticated data only, never a voter's safety WAL.
// A body outside this devnet transfer budget is explicitly unavailable.
func (a *Application) CertifiedData(afterHeight uint64, limit int) ([][]byte, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 8 {
		return nil, errors.New("certified data count bound")
	}
	var records []*Record
	if afterHeight < a.disk.BaseHeight {
		for h := afterHeight + 1; h <= a.disk.BaseHeight && len(records) < limit; h++ {
			r, _, err := a.archived(h)
			if err != nil {
				return nil, err
			}
			records = append(records, r)
		}
	}
	for _, r := range a.disk.Records {
		if r.QC != nil && r.Checkpoint.Sequence > afterHeight && r.Checkpoint.Sequence > a.disk.BaseHeight {
			records = append(records, r)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Checkpoint.Sequence != records[j].Checkpoint.Sequence {
			return records[i].Checkpoint.Sequence < records[j].Checkpoint.Sequence
		}
		return bytes.Compare(records[i].Ref, records[j].Ref) < 0
	})
	if len(records) > limit {
		records = records[:limit]
	}
	out := make([][]byte, 0, len(records))
	for _, r := range records {
		raw, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		if len(raw) > MaxProposalDataBytes {
			return nil, ErrUnavailable
		}
		out = append(out, raw)
	}
	return out, nil
}

// ImportProposalData augments local retained data without importing remote vote
// or timeout state. The caller serializes this with all FHS actor operations.
func (a *Application) ImportProposalData(raw []byte) error {
	if err := a.check(); err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > MaxProposalDataBytes {
		return errors.New("proposal data byte bound")
	}
	var r Record
	if err := decodeStrict(raw, &r); err != nil {
		return err
	}
	canonical, err := json.Marshal(&r)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errors.New("noncanonical proposal data")
	}
	if r.QC == nil || !bytes.Equal(r.Ref, r.QC.State) {
		return errors.New("repair requires matching QC")
	}
	if err = a.verifyQC(r.QC); err != nil {
		return err
	}
	ref, err := types.DecodeHotstuffProposalRef(r.Ref)
	if err != nil {
		return err
	}
	parent, err := a.parentQC(ref)
	if err != nil {
		return err
	}
	if err = a.validateRecord(&r, parent); err != nil {
		return err
	}
	if r.Checkpoint.Sequence <= a.FinalizedHeight() {
		hash, err := r.Checkpoint.Hash()
		if err != nil {
			return err
		}
		known, _, err := a.finalizedRecordAt(r.Checkpoint.Sequence)
		if err != nil {
			return err
		}
		want, err := known.Checkpoint.Hash()
		if err != nil || hash != want {
			return errors.New("repair conflicts with finalized state")
		}
		if r.Checkpoint.Sequence <= a.disk.BaseHeight {
			return nil
		}
	} else if err = a.extendsFinalized(parent); err != nil {
		return err
	}
	if old := a.disk.Safety.HighestQC; old != nil && old.Number == r.QC.Number && !hotstuff.SignedStateSemanticEqual(old, r.QC) {
		return errors.New("repair conflicts with highest QC")
	}
	if err = a.storeRecord(&r); err != nil {
		return err
	}
	return a.OnCertified(r.QC)
}
