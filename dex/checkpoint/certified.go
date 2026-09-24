package checkpoint

import (
	"errors"
	"math"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// VerifyCertified authenticates one checkpoint's QC for speculative submission
// planning only. It does NOT prove finality, computation validity or availability.
// Financial completion and CLX settlement must continue to use Verify and its
// authenticated descendant/finality rules.
func (e *Epoch) VerifyCertified(c protocol.Checkpoint, qc *hotstuff.SignedState) (*types.HotstuffProposalRef, error) {
	if e == nil || c.Domain() != e.domain || c.Sequence < e.first || c.Sequence >= e.end || c.Sequence != c.FirstBlock || c.Sequence != c.LastBlock || qc == nil || qc.Number == 0 || qc.Number == math.MaxUint64 || len(qc.State) == 0 || len(qc.State) > MaxRefBytes || len(qc.Sign) == 0 || len(qc.Sign) > 128 || len(qc.LeaderID) == 0 || len(qc.LeaderID) > 128 {
		return nil, errors.New("certified planning checkpoint/QC bounds")
	}
	if err := hotstuff.ValidateCanonicalSignerMask(qc.Mask, 7, 5); err != nil {
		return nil, err
	}
	if c.InboxEnd < c.InboxStart || c.InboxEnd-c.InboxStart > protocol.MaxDepositsPerCheckpoint || c.DataSchema == 6 && c.Sequence > protocol.MaxHistoryCount+1 {
		return nil, errors.New("certified planning inbox/history bound")
	}
	hash, err := c.Hash()
	if err != nil {
		return nil, err
	}
	r, err := types.DecodeHotstuffProposalRef(qc.State)
	if err != nil {
		return nil, err
	}
	if r.ChainID != e.domain.ChainID || r.KeyHash != common.Hash(e.domain.EpochKey()) || r.ViewNumber != qc.Number || r.ViewID != qc.ViewID || r.LeaderID != qc.LeaderID || r.LeaderID != e.leaders[(r.ViewNumber-1)%7] || r.Number != c.Sequence || r.BlockHash != common.Hash(hash) || r.StateRoot != common.Hash(c.PostRoot) || r.BodyHash != common.Hash(c.DataRoot) {
		return nil, errors.New("certified planning QC/checkpoint binding")
	}
	if r.Time != r.Number || r.BodySize > 1024*1024 || r.TxHash != (common.Hash{}) || r.ReceiptHash != (common.Hash{}) || r.CommonTxAdmissionRoot != (common.Hash{}) || r.CommonTxRewardRoot != (common.Hash{}) || r.BlockType != 0 || r.GasLimit != 0 || r.GasUsed != 0 {
		return nil, errors.New("certified planning noncanonical DEX metadata")
	}
	if !hotstuff.VerifyFHSSignatureWithContext(qc.Sign, qc.Mask, qc.State, e.keys, 5, e.domain.ChainID, hotstuff.MsgVotePrepare, qc.ViewID, qc.LeaderID) {
		return nil, errors.New("certified planning invalid QC signature")
	}
	return r, nil
}
