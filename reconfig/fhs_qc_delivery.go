package reconfig

import (
	"fmt"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// Keep the previous canonical generation reachable during asynchronous sends,
// plus the signing generations still referenced by our durable QC state. This
// changes transport reachability only; each message still proves its committee.
func (s *Service) addFHSQCDeliveryPeers(peers map[string][]byte) error {
	if s == nil || s.kbc == nil {
		return nil
	}
	generations := make(map[common.Hash]struct{})
	if key := s.kbc.CurrentBlock(); key != nil && key.NumberU64() > 0 {
		generations[key.ParentHash()] = struct{}{}
	}
	qcs := []*hotstuff.SignedState{s.HighestCertified()}
	if s.fhsStore != nil {
		pending, err := s.fhsStore.pendingBroadcastSnapshot()
		if err != nil {
			return err
		}
		qcs = append(qcs, pending)
	}
	for _, qc := range qcs {
		if qc == nil {
			continue
		}
		ref, err := types.DecodeHotstuffProposalRef(qc.State)
		if err != nil {
			return fmt.Errorf("decode retained FHS delivery certificate: %w", err)
		}
		generations[ref.KeyHash] = struct{}{}
	}
	for keyHash := range generations {
		if err := s.addFHSCommitteePeers(peers, keyHash); err != nil {
			return err
		}
	}
	return nil
}

// fhsQCBroadcastCommittee preserves the certified proposal's recipients across
// committee changes, including broadcasts rebuilt from the durable outbox.
// DataB/DataC carry the transaction QC signature/mask; DataD carries the exact
// signed proposal reference. An optional DataA key-state signature does not
// change that routing identity. QC cryptographic validation remains at the
// certification and receiving boundaries.
func (s *Service) fhsQCBroadcastCommittee(data *hotstuff.HotstuffMessage) (*bftview.Committee, error) {
	if s == nil || data == nil || data.Code != hotstuff.MsgQCBroadcast ||
		len(data.DataB) == 0 || len(data.DataC) == 0 || len(data.DataD) == 0 {
		return nil, fmt.Errorf("incomplete FHS QC broadcast")
	}
	ref, err := types.DecodeHotstuffProposalRef(data.DataD)
	if err != nil {
		return nil, fmt.Errorf("decode FHS QC broadcast proposal: %w", err)
	}
	if ref.ChainID != s.ChainID() || ref.ViewNumber != data.Number ||
		ref.ViewID != data.ViewId || ref.LeaderID != data.Id {
		return nil, fmt.Errorf("FHS QC broadcast proposal context mismatch")
	}
	_, committee, _, err := s.resolveExactFHSCommittee(ref.KeyHash, true)
	if err != nil {
		return nil, fmt.Errorf("resolve FHS QC broadcast committee %s: %w", ref.KeyHash, err)
	}
	return committee, nil
}
