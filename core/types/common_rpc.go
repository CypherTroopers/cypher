package types

import (
	"bytes"
	"fmt"
	"math/big"
	"sync/atomic"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/rlp"
)

const (
	commonTxAdmissionSignatureDomain = "CPH_COMMON_TX_ADMISSION_SIGNATURE"
	commonTxAdmissionIDDomain        = "CPH_COMMON_TX_ADMISSION_ID"
	commonTxAdmissionWinnerDomain    = "CPH_COMMON_TX_ADMISSION_WINNER"

	// MaxCommonTxAdmissionBatchItems is the consensus maximum number of ordered
	// transaction hashes covered by one common-RPC admission signature.
	MaxCommonTxAdmissionBatchItems = 512
)

// CommonTxAdmissionSigningPayload returns the canonical payload signed by the
// common RPC miner. Signature is intentionally excluded from the payload.
func CommonTxAdmissionSigningPayload(admission *CommonTxAdmissionBatch) []byte {
	if admission == nil {
		return nil
	}
	payload, err := rlp.EncodeToBytes([]interface{}{
		[]byte(commonTxAdmissionSignatureDomain),
		admission.ChainID,
		admission.GenesisHash,
		admission.TxRoot,
		admission.AdmissionID,
		admission.Miner,
		admission.KeyBlockNumber,
		admission.Timestamp,
		uint16(len(admission.TxHashes)),
	})
	if err != nil {
		return nil
	}
	return payload
}

// CommonTxAdmissionSigningHash returns the ECDSA digest for the admission
// signing payload. It matches accounts.Wallet.SignData, which signs
// keccak256(payload).
func CommonTxAdmissionSigningHash(admission *CommonTxAdmissionBatch) common.Hash {
	payload := CommonTxAdmissionSigningPayload(admission)
	if len(payload) == 0 {
		return common.Hash{}
	}
	return crypto.Keccak256Hash(payload)
}

// CommonTxAdmissionID derives the semantic identity of a signed admission
// batch. It deliberately derives TxRoot from TxHashes instead of trusting the
// stored field, allowing callers and verification to compute the canonical ID
// before the batch is signed.
func CommonTxAdmissionID(admission *CommonTxAdmissionBatch) common.Hash {
	if admission == nil {
		return common.Hash{}
	}
	return blake3RLPHash([]interface{}{
		[]byte(commonTxAdmissionIDDomain),
		admission.ChainID,
		admission.GenesisHash,
		DeriveCommonTxAdmissionTxRoot(admission.TxHashes),
		admission.Miner,
		admission.KeyBlockNumber,
		admission.Timestamp,
		uint16(len(admission.TxHashes)),
	})
}

// CommonTxAdmissionWinnerHash returns the deterministic ordering hash used when
// multiple common RPC miners submit valid admissions for the same tx. The lowest
// hash wins, keeping reward selection reproducible across validators.
func CommonTxAdmissionWinnerHash(admission *CommonTxAdmissionBatch, txHash common.Hash) common.Hash {
	if admission == nil {
		return common.Hash{}
	}
	return blake3RLPHash([]interface{}{
		[]byte(commonTxAdmissionWinnerDomain),
		admission.ChainID,
		admission.GenesisHash,
		txHash,
		admission.Miner,
		admission.KeyBlockNumber,
	})
}

func IsBetterCommonTxAdmission(candidate, current *CommonTxAdmissionBatch, txHash common.Hash) bool {
	if candidate == nil {
		return false
	}
	if current == nil {
		return true
	}
	candidateHash := CommonTxAdmissionWinnerHash(candidate, txHash)
	currentHash := CommonTxAdmissionWinnerHash(current, txHash)
	if cmp := bytes.Compare(candidateHash.Bytes(), currentHash.Bytes()); cmp != 0 {
		return cmp < 0
	}
	// The primary winner identity intentionally ignores batch composition and
	// timestamp so an authorized miner cannot change its reward priority by
	// grinding batches. AdmissionID provides a stable total-order tie-break when
	// the same miner admitted the transaction in multiple valid batches.
	return bytes.Compare(candidate.AdmissionID.Bytes(), current.AdmissionID.Bytes()) < 0
}

// VerifyCommonTxAdmissionSignature recovers the ECDSA signer and verifies that
// it matches admission.Miner.
func VerifyCommonTxAdmissionSignature(admission *CommonTxAdmissionBatch) error {
	if admission == nil {
		return fmt.Errorf("nil common tx admission batch")
	}
	if admission.ChainID == nil || admission.ChainID.Sign() <= 0 {
		return fmt.Errorf("common tx admission %s has invalid chain id", admission.AdmissionID)
	}
	if admission.GenesisHash == (common.Hash{}) {
		return fmt.Errorf("common tx admission %s has empty genesis hash", admission.AdmissionID)
	}
	if admission.Miner == (common.Address{}) {
		return fmt.Errorf("common tx admission %s has empty miner", admission.AdmissionID)
	}
	if admission.Timestamp == 0 {
		return fmt.Errorf("common tx admission %s has empty timestamp", admission.AdmissionID)
	}
	if len(admission.TxHashes) == 0 || len(admission.TxHashes) > MaxCommonTxAdmissionBatchItems {
		return fmt.Errorf("common tx admission %s has invalid transaction count %d", admission.AdmissionID, len(admission.TxHashes))
	}
	seen := make(map[common.Hash]struct{}, len(admission.TxHashes))
	for index, txHash := range admission.TxHashes {
		if txHash == (common.Hash{}) {
			return fmt.Errorf("common tx admission %s has empty transaction hash at %d", admission.AdmissionID, index)
		}
		if _, duplicate := seen[txHash]; duplicate {
			return fmt.Errorf("common tx admission %s repeats transaction %s", admission.AdmissionID, txHash)
		}
		seen[txHash] = struct{}{}
	}
	wantTxRoot := DeriveCommonTxAdmissionTxRoot(admission.TxHashes)
	if admission.TxRoot != wantTxRoot {
		return fmt.Errorf("common tx admission %s transaction root mismatch: have %s want %s", admission.AdmissionID, admission.TxRoot, wantTxRoot)
	}
	wantAdmissionID := CommonTxAdmissionID(admission)
	if admission.AdmissionID != wantAdmissionID {
		return fmt.Errorf("common tx admission id mismatch: have %s want %s", admission.AdmissionID, wantAdmissionID)
	}
	if len(admission.Signature) != crypto.SignatureLength {
		return fmt.Errorf("common tx admission %s has invalid signature length %d", admission.AdmissionID, len(admission.Signature))
	}
	recoveryID := admission.Signature[crypto.RecoveryIDOffset]
	r := new(big.Int).SetBytes(admission.Signature[:32])
	s := new(big.Int).SetBytes(admission.Signature[32:crypto.RecoveryIDOffset])
	if recoveryID > 1 || !crypto.ValidateSignatureValues(recoveryID, r, s, true) {
		return fmt.Errorf("common tx admission %s has non-canonical signature values", admission.AdmissionID)
	}
	hash := CommonTxAdmissionSigningHash(admission)
	if hash == (common.Hash{}) {
		return fmt.Errorf("common tx admission %s has empty signing hash", admission.AdmissionID)
	}
	pub, err := crypto.SigToPub(hash.Bytes(), admission.Signature)
	if err != nil {
		return fmt.Errorf("common tx admission %s signature recover failed: %v", admission.AdmissionID, err)
	}
	recovered := crypto.PubkeyToAddress(*pub)
	if recovered != admission.Miner {
		return fmt.Errorf("common tx admission %s signer mismatch: have %s want %s", admission.AdmissionID, recovered, admission.Miner)
	}
	return nil
}

// AttachCommonTxData attaches common RPC admission/reward data and commits their
// BLAKE3 Merkle roots into the header. It is intended for block construction
// before any hash/size cache is used. If a caller attaches data after a cache was
// populated, the caches are reset safely without atomic.Value.Store(nil).
func (b *Block) AttachCommonTxData(batches []*CommonTxAdmissionBatch, refs []CommonTxAdmissionRef, rewards []*CommonTxReward) {
	b.commonTxAdmissionBatches = copyCommonTxAdmissionBatches(batches)
	b.commonTxAdmissionRefs = copyCommonTxAdmissionRefs(refs)
	b.commonTxRewards = copyCommonTxRewards(rewards)
	b.header.CommonTxAdmissionRoot = DeriveCommonTxAdmissionRoot(b.commonTxAdmissionBatches, b.commonTxAdmissionRefs)
	b.header.CommonTxRewardRoot = DeriveCommonTxRewardRoot(b.commonTxRewards)
	b.hash = atomic.Value{}
	b.size = atomic.Value{}
}
