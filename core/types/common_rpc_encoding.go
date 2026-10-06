package types

import (
	"fmt"
	"io"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/rlp"
)

// There is one canonical wire format for the restarted network. Legacy
// recipient-less records are not decoded or silently promoted to this format.
type commonAdmissionEncoding struct {
	Version         uint8
	ChainID         *big.Int
	GenesisHash     common.Hash
	TxRoot          common.Hash
	AdmissionID     common.Hash
	Miner           common.Address
	RewardRecipient common.Address
	KeyBlockNumber  uint64
	Timestamp       uint64
	TxHashes        []common.Hash
	Signature       []byte
}
type commonRewardEncoding struct {
	Version         uint8
	TxHash          common.Hash
	Approver        common.Address
	RewardRecipient common.Address
	ApproverReward  *big.Int
	Burn            *big.Int
}

func (a *CommonTxAdmissionBatch) ValidateVersion() error {
	if a == nil {
		return fmt.Errorf("nil common tx admission")
	}
	if a.Version != CommonRPCVersionV2 {
		return fmt.Errorf("unsupported common tx admission version %d: recipient-bearing version 2 required from genesis", a.Version)
	}
	if a.RewardRecipient == (common.Address{}) || a.RewardRecipient == a.Miner {
		return fmt.Errorf("common tx admission requires a nonzero reward recipient distinct from miner")
	}
	return nil
}
func (r *CommonTxReward) ValidateVersion() error {
	if r == nil {
		return fmt.Errorf("nil common tx reward")
	}
	if r.Version != CommonRPCVersionV2 {
		return fmt.Errorf("unsupported common tx reward version %d: recipient-bearing version 2 required from genesis", r.Version)
	}
	if r.RewardRecipient == (common.Address{}) || r.RewardRecipient == r.Approver {
		return fmt.Errorf("common tx reward requires a nonzero reward recipient distinct from approver")
	}
	return nil
}

// EffectiveRewardRecipient never falls back to the signing account.
func (r *CommonTxReward) EffectiveRewardRecipient() common.Address {
	if r.ValidateVersion() != nil {
		return common.Address{}
	}
	return r.RewardRecipient
}
func (a *CommonTxAdmissionBatch) EncodeRLP(w io.Writer) error {
	if err := a.ValidateVersion(); err != nil {
		return err
	}
	return rlp.Encode(w, commonAdmissionEncoding{a.Version, a.ChainID, a.GenesisHash, a.TxRoot, a.AdmissionID, a.Miner, a.RewardRecipient, a.KeyBlockNumber, a.Timestamp, a.TxHashes, a.Signature})
}
func (a *CommonTxAdmissionBatch) DecodeRLP(s *rlp.Stream) error {
	var wire commonAdmissionEncoding
	if err := s.Decode(&wire); err != nil {
		if err == rlp.EOL {
			return err
		}
		return fmt.Errorf("invalid recipient-bearing common tx admission encoding: %w", err)
	}
	decoded := CommonTxAdmissionBatch{Version: wire.Version, ChainID: wire.ChainID, GenesisHash: wire.GenesisHash, TxRoot: wire.TxRoot, AdmissionID: wire.AdmissionID, Miner: wire.Miner, RewardRecipient: wire.RewardRecipient, KeyBlockNumber: wire.KeyBlockNumber, Timestamp: wire.Timestamp, TxHashes: wire.TxHashes, Signature: wire.Signature}
	if err := decoded.ValidateVersion(); err != nil {
		return err
	}
	*a = decoded
	return nil
}
func (r *CommonTxReward) EncodeRLP(w io.Writer) error {
	if err := r.ValidateVersion(); err != nil {
		return err
	}
	return rlp.Encode(w, commonRewardEncoding{r.Version, r.TxHash, r.Approver, r.RewardRecipient, r.ApproverReward, r.Burn})
}
func (r *CommonTxReward) DecodeRLP(s *rlp.Stream) error {
	var wire commonRewardEncoding
	if err := s.Decode(&wire); err != nil {
		if err == rlp.EOL {
			return err
		}
		return fmt.Errorf("invalid recipient-bearing common tx reward encoding: %w", err)
	}
	decoded := CommonTxReward{Version: wire.Version, TxHash: wire.TxHash, Approver: wire.Approver, RewardRecipient: wire.RewardRecipient, ApproverReward: wire.ApproverReward, Burn: wire.Burn}
	if err := decoded.ValidateVersion(); err != nil {
		return err
	}
	*r = decoded
	return nil
}
