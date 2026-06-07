package types

import (
	"fmt"
	"sync/atomic"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/rlp"
)

const commonTxAdmissionSignatureDomain = "CPH_COMMON_TX_ADMISSION_SIGNATURE_V1"

// CommonTxAdmissionSigningPayload returns the canonical payload signed by the
// common RPC miner. Signature is intentionally excluded from the payload.
func CommonTxAdmissionSigningPayload(admission *CommonTxAdmission) []byte {
	if admission == nil {
		return nil
	}
	payload, err := rlp.EncodeToBytes([]interface{}{
		[]byte(commonTxAdmissionSignatureDomain),
		admission.TxHash,
		admission.Miner,
		admission.KeyBlockNumber,
		admission.TxBlockNumber,
		admission.Timestamp,
	})
	if err != nil {
		return nil
	}
	return payload
}

// CommonTxAdmissionSigningHash returns the ECDSA digest for the admission
// signing payload. It matches accounts.Wallet.SignData, which signs
// keccak256(payload).
func CommonTxAdmissionSigningHash(admission *CommonTxAdmission) common.Hash {
	payload := CommonTxAdmissionSigningPayload(admission)
	if len(payload) == 0 {
		return common.Hash{}
	}
	return crypto.Keccak256Hash(payload)
}

// VerifyCommonTxAdmissionSignature recovers the ECDSA signer and verifies that
// it matches admission.Miner.
func VerifyCommonTxAdmissionSignature(admission *CommonTxAdmission) error {
	if admission == nil {
		return fmt.Errorf("nil common tx admission")
	}
	if admission.TxHash == (common.Hash{}) {
		return fmt.Errorf("common tx admission has empty tx hash")
	}
	if admission.Miner == (common.Address{}) {
		return fmt.Errorf("common tx admission for %s has empty miner", admission.TxHash)
	}
	if len(admission.Signature) != crypto.SignatureLength {
		return fmt.Errorf("common tx admission for %s has invalid signature length %d", admission.TxHash, len(admission.Signature))
	}
	hash := CommonTxAdmissionSigningHash(admission)
	if hash == (common.Hash{}) {
		return fmt.Errorf("common tx admission for %s has empty signing hash", admission.TxHash)
	}
	pub, err := crypto.SigToPub(hash.Bytes(), admission.Signature)
	if err != nil {
		return fmt.Errorf("common tx admission for %s signature recover failed: %v", admission.TxHash, err)
	}
	recovered := crypto.PubkeyToAddress(*pub)
	if recovered != admission.Miner {
		return fmt.Errorf("common tx admission for %s signer mismatch: have %s want %s", admission.TxHash, recovered, admission.Miner)
	}
	return nil
}

// AttachCommonTxData attaches common RPC admission/reward data and commits their
// BLAKE3 Merkle roots into the header. It is intended for block construction
// before any hash/size cache is used. If a caller attaches data after a cache was
// populated, the caches are reset safely without atomic.Value.Store(nil).
func (b *Block) AttachCommonTxData(admissions []*CommonTxAdmission, rewards []*CommonTxReward) {
	b.commonTxAdmissions = copyCommonTxAdmissions(admissions)
	b.commonTxRewards = copyCommonTxRewards(rewards)
	b.header.CommonTxAdmissionRoot = DeriveCommonTxAdmissionRoot(b.commonTxAdmissions)
	b.header.CommonTxRewardRoot = DeriveCommonTxRewardRoot(b.commonTxRewards)
	b.hash = atomic.Value{}
	b.size = atomic.Value{}
}
