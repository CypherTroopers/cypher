package eth

import (
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/p2p"
)

// BroadcastCommonTxAdmissions propagates signed common RPC tx admissions to all
// connected peers. The receiving side verifies ECDSA recovery before accepting
// the record into the local admission pool.
func (pm *ProtocolManager) BroadcastCommonTxAdmissions(admissions []*types.CommonTxAdmission) {
	pm.broadcastCommonTxAdmissionsExcept(admissions, "")
}

func (pm *ProtocolManager) broadcastCommonTxAdmissionsExcept(admissions []*types.CommonTxAdmission, exceptPeerID string) {
	if len(admissions) == 0 || pm == nil || pm.peers == nil {
		return
	}
	valid := make([]*types.CommonTxAdmission, 0, len(admissions))
	for _, admission := range admissions {
		if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
			log.Warn("Skip broadcasting invalid common tx admission", "err", err)
			continue
		}
		valid = append(valid, admission)
	}
	if len(valid) == 0 {
		return
	}

	pm.peers.lock.RLock()
	defer pm.peers.lock.RUnlock()
	for id, ethPeer := range pm.peers.peers {
		if id == exceptPeerID || ethPeer == nil {
			continue
		}
		batch := make([]*types.CommonTxAdmission, len(valid))
		for i, admission := range valid {
			copy := *admission
			if len(admission.Signature) > 0 {
				copy.Signature = append([]byte(nil), admission.Signature...)
			}
			batch[i] = &copy
		}
		go func(p *peer, out []*types.CommonTxAdmission) {
			if err := p2p.Send(p.rw, CommonTxAdmissionMsg, out); err != nil {
				log.Debug("Failed to broadcast common tx admissions", "peer", p.id, "count", len(out), "err", err)
			}
		}(ethPeer, batch)
	}
}

func (pm *ProtocolManager) handleCommonTxAdmissionMsg(p *peer, msg p2p.Msg) error {
	var admissions []*types.CommonTxAdmission
	if err := msg.Decode(&admissions); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	accepted := make([]*types.CommonTxAdmission, 0, len(admissions))
	for _, admission := range admissions {
		if admission == nil {
			continue
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
			log.Warn("Received invalid common tx admission", "peer", p.id, "err", err)
			continue
		}
		if core.StoreCommonRPCAdmission(admission) {
			accepted = append(accepted, admission)
		}
	}
	if len(accepted) > 0 {
		log.Trace("Accepted common tx admissions", "peer", p.id, "count", len(accepted))
		pm.broadcastCommonTxAdmissionsExcept(accepted, p.id)
	}
	return nil
}
