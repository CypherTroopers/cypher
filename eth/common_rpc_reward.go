package eth

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/commonrpcreward"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/reconfig/bftview"
)

func (b *EthAPIBackend) CommonRPCRewardRegistry() *commonrpcreward.Registry {
	return b.eth.commonRPCRewards
}

// This index contains only WAL-owned local intents. The consensus winner index
// may instead name another operator, and must never define this node's retry.
// It is rebuilt from the authoritative WAL, published after its fsync, and
// replaced with each checkpoint so finalized records do not accumulate.
type localRPCAdmissionKey struct {
	signer common.Address
	tx     common.Hash
}

func indexLocalRPCAdmission(index map[localRPCAdmissionKey]core.CommonRPCAdmissionResult, kind txIngressWALEventKind, payload []byte) error {
	if kind != txIngressWALLocalIntent {
		return nil
	}
	batch, _, err := decodeTxQUICBatch(payload)
	if err != nil {
		return fmt.Errorf("decode local admission retry index: %w", err)
	}
	for _, item := range batch.Items {
		key := localRPCAdmissionKey{batch.Certificate.Miner, item.Tx.Hash()}
		old, exists := index[key]
		// Repeated durable operations may reference the same transaction. Retain
		// the first immutable certificate without rewriting any stored proof.
		if exists && (old.Batch.Timestamp < batch.Certificate.Timestamp ||
			(old.Batch.Timestamp == batch.Certificate.Timestamp && bytes.Compare(old.Batch.AdmissionID[:], batch.Certificate.AdmissionID[:]) <= 0)) {
			continue
		}
		index[key] = core.CommonRPCAdmissionResult{Batch: batch.Certificate, Item: item.AdmissionIndex}
	}
	return nil
}

func (w *txIngressWAL) localRPCAdmission(signer common.Address, hash common.Hash) (core.CommonRPCAdmissionResult, bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.runningErrLocked(); err != nil {
		return core.CommonRPCAdmissionResult{}, false, err
	}
	result, found := w.localAdmissions[localRPCAdmissionKey{signer, hash}]
	if found {
		result.Batch = copyCommonTxAdmissionBatchForQUIC(result.Batch)
	}
	return result, found, nil
}

// A is captured once, then that account's B is read atomically from the
// registry. A subsequent etherbase change cannot change this batch's signer.
// Existing proofs need neither the current recipient setting nor an unlock.
func (b *EthAPIBackend) signOrReuseCommonRPCAdmissions(hashes []common.Hash, genesis common.Hash, keyNumber, timestamp uint64) ([]core.CommonRPCAdmissionResult, error) {
	config := b.ChainConfig()
	var signer, recipient common.Address
	var recipientErr error
	bftview.WithServerCoinBase(func(account common.Address) {
		signer = account
		if b.eth.commonRPCRewards == nil {
			recipientErr = commonrpcreward.ErrNotConfigured
		} else {
			recipient, recipientErr = b.eth.commonRPCRewards.Recipient(account)
		}
	})
	results := make([]core.CommonRPCAdmissionResult, len(hashes))
	newHashes := make([]common.Hash, 0, len(hashes))
	positions := make([]int, 0, len(hashes))
	for i, hash := range hashes {
		previous, found, err := b.eth.txQUICIngress.wal.localRPCAdmission(signer, hash)
		if err != nil {
			return nil, err
		}
		if found {
			if err := previous.Batch.ValidateVersion(); err != nil {
				return nil, fmt.Errorf("invalid stored local admission: %w", err)
			}
			if err := types.VerifyCommonTxAdmissionSignature(previous.Batch); err != nil {
				return nil, err
			}
			results[i] = previous
		} else {
			newHashes = append(newHashes, hash)
			positions = append(positions, i)
		}
	}
	if len(newHashes) == 0 {
		return results, nil
	}
	if recipientErr != nil {
		return nil, recipientErr
	}
	signed, err := core.SignCommonRPCAdmissions(newHashes, signer, config.ChainID, genesis, keyNumber, timestamp, recipient)
	if err != nil {
		return nil, err
	}
	for i, position := range positions {
		results[position] = signed[i]
	}
	return results, nil
}

// Mixed retries and new TXs may have different immutable certificates. Store
// each once and align the winning results by hash, not by original batch size.
func materializeCommonRPCAdmissions(admissions []core.CommonRPCAdmissionResult, txs types.Transactions, chainID *big.Int, genesis common.Hash) ([]core.CommonRPCAdmissionResult, error) {
	stored := make(map[common.Hash]struct{})
	byHash := make(map[common.Hash]core.CommonRPCAdmissionResult)
	for _, admission := range admissions {
		if _, ok := stored[admission.Batch.AdmissionID]; ok {
			continue
		}
		materialized, err := core.VerifyAndStoreCommonRPCAdmissionBatch(admission.Batch, chainID, genesis)
		if err != nil {
			return nil, err
		}
		for i, result := range materialized {
			byHash[admission.Batch.TxHashes[i]] = result
		}
		stored[admission.Batch.AdmissionID] = struct{}{}
	}
	results := make([]core.CommonRPCAdmissionResult, len(txs))
	for i, tx := range txs {
		var found bool
		results[i], found = byHash[tx.Hash()]
		if !found {
			return nil, fmt.Errorf("materialized admission missing transaction %s", tx.Hash())
		}
	}
	return results, nil
}
