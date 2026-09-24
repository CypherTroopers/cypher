package consensus

import (
	"errors"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func cloneHistory(h *protocol.HistoryFrontier) *protocol.HistoryFrontier {
	if h == nil {
		return nil
	}
	copy := *h
	return &copy
}
func sameHistory(a, b *protocol.HistoryFrontier) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

// deriveHistory uses only the actual parent selected by the FHS protocol. A
// timeout, local mempool, highest-head cache or a QC for another proposal cannot
// append a leaf. Every receiver and cold replay recomputes this same frontier.
func (a *Application) deriveHistory(parent *hotstuff.SignedState) (*protocol.HistoryFrontier, error) {
	if parent == nil {
		return new(protocol.HistoryFrontier), nil
	}
	r := a.recordForQC(parent)
	if r == nil || r.History == nil || r.Checkpoint.DataSchema != AncestryExecutionSchema || r.History.Count+1 != r.Checkpoint.LastBlock {
		return nil, errors.New("authenticated parent ancestry unavailable")
	}
	next := cloneHistory(r.History)
	id, err := hotstuff.SignedStateID(parent)
	if err != nil {
		return nil, err
	}
	if err = next.AppendQCID(protocol.Hash(id.Hash())); err != nil {
		return nil, err
	}
	return next, nil
}

// historyLeaves reconstructs one bounded ancestor vector from the actual parent
// links. The vector is temporary, not duplicated in hot WAL records. Archived
// records are read against the digests established by authenticated cold replay.
// This work is on DEX participants; CLX receives only a fixed-depth path.
func (a *Application) historyLeaves(anchor *Record) ([]protocol.Hash, error) {
	if anchor == nil || anchor.History == nil || anchor.History.Count+1 != anchor.Checkpoint.LastBlock || anchor.History.Count > protocol.MaxHistoryCount {
		return nil, errors.New("history proof anchor count")
	}
	leaves := make([]protocol.Hash, anchor.History.Count)
	cursor := anchor
	for height := anchor.History.Count; height > 0; height-- {
		ref, err := types.DecodeHotstuffProposalRef(cursor.Ref)
		if err != nil {
			return nil, err
		}
		parent, err := a.parentQC(ref)
		if err != nil {
			return nil, err
		}
		r := a.recordForQC(parent)
		if r == nil || r.Checkpoint.LastBlock != height || r.Checkpoint.DataSchema != AncestryExecutionSchema {
			return nil, ErrUnavailable
		}
		id, err := hotstuff.SignedStateID(parent)
		if err != nil || ref.ParentQCID != id.Hash() {
			return nil, errors.New("history proof parent identity")
		}
		leaves[height-1] = protocol.Hash(id.Hash())
		cursor = r
	}
	var reconstructed protocol.HistoryFrontier
	for _, leaf := range leaves {
		if err := reconstructed.AppendQCID(leaf); err != nil {
			return nil, err
		}
	}
	if reconstructed != *anchor.History {
		return nil, errors.New("history frontier does not match actual certified ancestry")
	}
	return leaves, nil
}

// commitHistoryAncestors preserves the existing finality trigger: a genuine
// parent/child QC pair in consecutive views. A finalized tip's signed ancestry
// commitment then authenticates older checkpoints without packaging every QC.
// All proofs and the complete financial chain are checked before publication.
func (a *Application) commitHistoryAncestors(anchor, child *Record) error {
	if anchor == nil || child == nil || anchor.QC == nil || child.QC == nil || anchor.History == nil || child.History == nil ||
		anchor.Checkpoint.DataSchema != AncestryExecutionSchema || child.Checkpoint.DataSchema != AncestryExecutionSchema ||
		child.Checkpoint.LastBlock != anchor.Checkpoint.LastBlock+1 || child.QC.Number != anchor.QC.Number+1 {
		return errors.New("history finality requires consecutive authenticated parent/child")
	}
	if anchor.Checkpoint.LastBlock <= a.FinalizedHeight() {
		return nil
	}
	var leaves []protocol.Hash
	var err error
	if anchor.Checkpoint.LastBlock > a.FinalizedHeight()+1 {
		leaves, err = a.historyLeaves(anchor)
		if err != nil {
			return err
		}
	}
	actionRoot, err := ComputeExecutionDataRoot(anchor.Actions)
	if err != nil {
		return err
	}
	var pending []finalizedRecord
	for cursor := anchor; cursor != nil && cursor.Checkpoint.LastBlock > a.FinalizedHeight(); {
		p := checkpoint.Proof{Target: cursor.QC, Descendants: []*hotstuff.SignedState{child.QC}}
		if cursor != anchor {
			path, err := protocol.BuildHistoryProof(leaves, cursor.Checkpoint.LastBlock-1)
			if err != nil {
				return err
			}
			p.Descendants = []*hotstuff.SignedState{anchor.QC, child.QC}
			p.History = &checkpoint.HistoryWitness{Count: anchor.History.Count, ActionRoot: actionRoot, Siblings: path}
		}
		proof, err := checkpoint.EncodeProofV2(p)
		if err != nil {
			return err
		}
		if _, err = a.epoch.Verify(cursor.Checkpoint, proof); err != nil {
			return err
		}
		hash, err := cursor.Checkpoint.Hash()
		if err != nil {
			return err
		}
		ref, err := types.DecodeHotstuffProposalRef(cursor.Ref)
		if err != nil {
			return err
		}
		pending = append(pending, finalizedRecord{Key: ref.ProposalID().Hex(), Hash: common.Hash(hash).Hex(), Proof: proof})
		if len(pending) > MaxRecords {
			return errors.New("unfinalized hot history bound")
		}
		q, err := a.parentQC(ref)
		if err != nil {
			return err
		}
		cursor = a.recordForQC(q)
	}
	height := a.FinalizedHeight()
	var previous protocol.Hash
	if height != 0 {
		_, f, err := a.finalizedRecordAt(height)
		if err != nil {
			return err
		}
		previous = protocol.Hash(common.HexToHash(f.Hash))
	}
	for i := len(pending) - 1; i >= 0; i-- {
		r := a.disk.Records[pending[i].Key]
		if r == nil || r.Checkpoint.LastBlock != height+1 || r.Checkpoint.Previous != previous {
			return errors.New("history finality is not the contiguous accepted branch")
		}
		height++
		previous = protocol.Hash(common.HexToHash(pending[i].Hash))
	}
	for i := len(pending) - 1; i >= 0; i-- {
		a.disk.Finalized = append(a.disk.Finalized, pending[i])
	}
	return nil
}
