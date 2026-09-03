package types

import (
	"errors"
	"fmt"
	"io"

	"github.com/cypherium/cypher/rlp"
)

var (
	// ErrBlockBlobSidecarCountMismatch means that the compact sidecar list is
	// not ordered one-for-one with the BlobTxs in the transaction list.
	ErrBlockBlobSidecarCountMismatch = errors.New("block blob sidecar count does not match blob transactions")
	// ErrBlockBlobSidecarEmbedded rejects pooled-transaction wrappers inside a
	// block. Blocks carry canonical execution envelopes and commit sidecars in
	// their own body field.
	ErrBlockBlobSidecarEmbedded = errors.New("pooled blob transaction wrapper embedded in block transaction list")
)

// blockBodyRLP is the genesis-native body schema. BlobSidecars is compact: its
// ith entry belongs to the ith BlobTx, not to the ith transaction.
type blockBodyRLP struct {
	Transactions             []*Transaction
	BlobSidecars             []*BlobTxSidecar
	Uncles                   []*Header
	CommonTxAdmissionBatches []*CommonTxAdmissionBatch
	CommonTxAdmissionRefs    []CommonTxAdmissionRef
	CommonTxRewards          []*CommonTxReward
}

func countBlobTransactions(txs []*Transaction) int {
	count := 0
	for _, tx := range txs {
		if tx != nil && tx.Type() == BlobTxType {
			count++
		}
	}
	return count
}

func copyBlobSidecars(sidecars []*BlobTxSidecar) []*BlobTxSidecar {
	if len(sidecars) == 0 {
		return nil
	}
	cpy := make([]*BlobTxSidecar, len(sidecars))
	for i, sidecar := range sidecars {
		cpy[i] = sidecar.Copy()
	}
	return cpy
}

// cloneTransactionsWithBlobSidecars copies the transaction slice and every
// mutable BlobTx sidecar. Non-blob transactions remain shared because
// Transaction execution payloads are immutable after construction.
func cloneTransactionsWithBlobSidecars(txs []*Transaction) (Transactions, []*BlobTxSidecar) {
	if len(txs) == 0 {
		return nil, nil
	}
	cloned := make(Transactions, len(txs))
	sidecars := make([]*BlobTxSidecar, 0, countBlobTransactions(txs))
	for i, tx := range txs {
		if tx == nil || tx.Type() != BlobTxType {
			cloned[i] = tx
			continue
		}
		cloned[i] = tx.WithBlobSidecar(tx.BlobSidecar())
		sidecars = append(sidecars, cloned[i].BlobSidecar())
	}
	return cloned, sidecars
}

func validateBlockBlobSidecars(txs []*Transaction, sidecars []*BlobTxSidecar, rejectEmbedded bool) error {
	blobCount := countBlobTransactions(txs)
	if blobCount == 0 && len(sidecars) != 0 {
		return ErrBlobTxSidecarOnNonBlobTx
	}
	if len(sidecars) != blobCount {
		return fmt.Errorf("%w: have %d sidecars for %d blob transactions", ErrBlockBlobSidecarCountMismatch, len(sidecars), blobCount)
	}
	index := 0
	for txIndex, tx := range txs {
		if tx == nil || tx.Type() != BlobTxType {
			continue
		}
		if rejectEmbedded && tx.BlobSidecar() != nil {
			return fmt.Errorf("%w at transaction %d", ErrBlockBlobSidecarEmbedded, txIndex)
		}
		sidecar := sidecars[index]
		if err := tx.ValidateBlobSidecar(sidecar); err != nil {
			return fmt.Errorf("blob sidecar %d for transaction %d: %w", index, txIndex, err)
		}
		if err := validateBlobSidecarWireShape(sidecar); err != nil {
			return fmt.Errorf("blob sidecar %d for transaction %d: %w", index, txIndex, err)
		}
		index++
	}
	return nil
}

// ValidateBlobSidecars verifies that the body's compact sidecar list is
// complete, structurally valid and bound to its BlobTx execution envelopes.
// It is safe to call at network and downloader boundaries before the body is
// reconstructed as a Block.
func (body *Body) ValidateBlobSidecars() error {
	if body == nil {
		return errors.New("nil block body")
	}
	return validateBlockBlobSidecars(body.Transactions, body.BlobSidecars, false)
}

func attachBlockBlobSidecars(txs []*Transaction, sidecars []*BlobTxSidecar, rejectEmbedded bool) (Transactions, []*BlobTxSidecar, error) {
	if err := validateBlockBlobSidecars(txs, sidecars, rejectEmbedded); err != nil {
		return nil, nil, err
	}
	attached := make(Transactions, len(txs))
	ownedSidecars := make([]*BlobTxSidecar, 0, len(sidecars))
	sidecarIndex := 0
	for i, tx := range txs {
		if tx == nil || tx.Type() != BlobTxType {
			attached[i] = tx
			continue
		}
		attached[i] = tx.WithBlobSidecar(sidecars[sidecarIndex])
		ownedSidecars = append(ownedSidecars, attached[i].BlobSidecar())
		sidecarIndex++
	}
	return attached, ownedSidecars, nil
}

// EncodeRLP writes the authenticated genesis-native body schema. Blob sidecars
// are never inlined into Transaction.EncodeRLP, so transaction hashes and the
// transaction trie remain canonical EIP-2718 execution envelopes.
func (body *Body) EncodeRLP(w io.Writer) error {
	if body == nil {
		return errors.New("nil block body")
	}
	sidecars := body.BlobSidecars
	if len(sidecars) == 0 && countBlobTransactions(body.Transactions) != 0 {
		_, sidecars = cloneTransactionsWithBlobSidecars(body.Transactions)
	}
	if err := validateBlockBlobSidecars(body.Transactions, sidecars, false); err != nil {
		return err
	}
	return rlp.Encode(w, blockBodyRLP{
		Transactions:             body.Transactions,
		BlobSidecars:             sidecars,
		Uncles:                   body.Uncles,
		CommonTxAdmissionBatches: body.CommonTxAdmissionBatches,
		CommonTxAdmissionRefs:    body.CommonTxAdmissionRefs,
		CommonTxRewards:          body.CommonTxRewards,
	})
}

// DecodeRLP decodes and attaches the authenticated sidecars. Pooled type-3
// wrappers in Transactions are rejected because sidecars have a single
// canonical location in the block body.
func (body *Body) DecodeRLP(stream *rlp.Stream) error {
	var decoded blockBodyRLP
	if err := stream.Decode(&decoded); err != nil {
		return err
	}
	txs, sidecars, err := attachBlockBlobSidecars(decoded.Transactions, decoded.BlobSidecars, true)
	if err != nil {
		return err
	}
	body.Transactions = txs
	body.BlobSidecars = sidecars
	body.Uncles = decoded.Uncles
	body.CommonTxAdmissionBatches = copyCommonTxAdmissionBatches(decoded.CommonTxAdmissionBatches)
	body.CommonTxAdmissionRefs = copyCommonTxAdmissionRefs(decoded.CommonTxAdmissionRefs)
	body.CommonTxRewards = copyCommonTxRewards(decoded.CommonTxRewards)
	return nil
}

// NewBlockWithBlobSidecars is the fallible block constructor for BlobTx
// bodies. The sidecar list is compact and ordered by BlobTx occurrence.
func NewBlockWithBlobSidecars(header *Header, txs []*Transaction, uncles []*Header, receipts []*Receipt, sidecars []*BlobTxSidecar, hasher Hasher) (*Block, error) {
	attached, ownedSidecars, err := attachBlockBlobSidecars(txs, sidecars, false)
	if err != nil {
		return nil, err
	}
	block := NewBlock(header, attached, uncles, receipts, hasher)
	block.transactions = attached
	block.blobSidecars = ownedSidecars
	return block, nil
}

// WithBodyAndBlobSidecars returns a block with an explicitly authenticated
// body. The sidecar list is compact and ordered by BlobTx occurrence.
func (b *Block) WithBodyAndBlobSidecars(transactions []*Transaction, uncles []*Header, sidecars []*BlobTxSidecar) (*Block, error) {
	attached, ownedSidecars, err := attachBlockBlobSidecars(transactions, sidecars, false)
	if err != nil {
		return nil, err
	}
	block := b.WithBody(attached, uncles)
	block.transactions = attached
	block.blobSidecars = ownedSidecars
	return block, nil
}

// WithBlobSidecars attaches sidecars to the existing transaction body and
// returns a deep-copy block, leaving the receiver untouched.
func (b *Block) WithBlobSidecars(sidecars []*BlobTxSidecar) (*Block, error) {
	return b.WithBodyAndBlobSidecars(b.transactions, b.uncles, sidecars)
}
