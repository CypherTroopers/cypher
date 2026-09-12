package core

import (
	"errors"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

func validateBlobTxWithVerifier(w *types.BlobTxWithSidecar, verifier types.BlobVerifier) error {
	if verifier == nil {
		return types.ErrBlobVerifierMissing
	}
	return w.Verify(verifier)
}

func blobTxWithAttachedSidecar(w *types.BlobTxWithSidecar) (*types.Transaction, error) {
	if w == nil || w.Tx == nil || w.Tx.Type() != types.BlobTxType {
		return nil, types.ErrBlobTxSidecarOnNonBlobTx
	}
	sidecar := w.Sidecar
	if sidecar == nil {
		sidecar = w.Tx.BlobSidecar()
	}
	if err := w.Tx.ValidateBlobSidecar(sidecar); err != nil {
		return nil, err
	}
	return w.Tx.WithBlobSidecar(sidecar), nil
}

// AddLocalBlobTx verifies a BlobTx sidecar bundle and then submits the
// transaction through the existing local txpool path.
func (pool *TxPool) AddLocalBlobTx(w *types.BlobTxWithSidecar, verifier types.BlobVerifier) error {
	// AddLocal applies the mandatory real-KZG admission gate and publishes the
	// sidecar only after the transaction itself is inserted successfully.
	return pool.addBlobTx(w, verifier, pool.AddLocal)
}

// AddRemoteBlobTx verifies a BlobTx sidecar bundle and then submits the
// transaction through the existing remote txpool path.
func (pool *TxPool) AddRemoteBlobTx(w *types.BlobTxWithSidecar, verifier types.BlobVerifier) error {
	return pool.addBlobTx(w, verifier, pool.AddRemote)
}

// AddRemoteBlobTxSync verifies a BlobTx sidecar bundle and then submits the
// transaction through the existing synchronous remote txpool path.
func (pool *TxPool) AddRemoteBlobTxSync(w *types.BlobTxWithSidecar, verifier types.BlobVerifier) error {
	return pool.addBlobTx(w, verifier, pool.addRemoteSync)
}

// addBlobTx keeps bundle verification and attachment identical for every
// admission path. The selected add function still performs real-KZG admission.
func (pool *TxPool) addBlobTx(w *types.BlobTxWithSidecar, verifier types.BlobVerifier, add func(*types.Transaction) error) error {
	if err := validateBlobTxWithVerifier(w, verifier); err != nil {
		return err
	}
	tx, err := blobTxWithAttachedSidecar(w)
	if err != nil {
		return err
	}
	return add(tx)
}

var ErrMissingBlobTxSidecar = errors.New("missing blob transaction sidecar")

func (pool *TxPool) ValidateBlobSidecarsForTransactions(txs types.Transactions) error {
	for _, tx := range txs {
		if tx == nil || tx.Type() != types.BlobTxType {
			continue
		}
		if pool.GetBlobSidecar(tx.Hash()) == nil {
			return ErrMissingBlobTxSidecar
		}
	}
	return nil
}

func (pool *TxPool) FilterTransactionsWithBlobSidecars(txs types.Transactions) types.Transactions {
	if len(txs) == 0 {
		return nil
	}
	filtered := make(types.Transactions, 0, len(txs))
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		if tx.Type() == types.BlobTxType && pool.GetBlobSidecar(tx.Hash()) == nil {
			continue
		}
		filtered = append(filtered, tx)
	}
	return filtered
}

// AttachBlobSidecarsToTransactions returns a transaction list where BlobTxs have
// their sidecars attached from the txpool store. Non-blob transactions are kept
// unchanged. Missing BlobTx sidecars return ErrMissingBlobTxSidecar.
func (pool *TxPool) AttachBlobSidecarsToTransactions(txs types.Transactions) (types.Transactions, error) {
	if len(txs) == 0 {
		return nil, nil
	}
	attached := make(types.Transactions, 0, len(txs))
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		if tx.Type() != types.BlobTxType {
			attached = append(attached, tx)
			continue
		}
		sidecar := pool.GetBlobSidecar(tx.Hash())
		if sidecar == nil {
			return nil, ErrMissingBlobTxSidecar
		}
		attached = append(attached, tx.WithBlobSidecar(sidecar))
	}
	if len(attached) == 0 {
		return nil, nil
	}
	return attached, nil
}

// BlobSidecarsForTransactions returns the sidecars required by the supplied transactions.
// Non-blob transactions are ignored. Blob transactions without sidecars return
// ErrMissingBlobTxSidecar so callers can avoid building invalid Cancun blocks.
func (pool *TxPool) BlobSidecarsForTransactions(txs types.Transactions) (map[common.Hash]*types.BlobTxSidecar, error) {
	if len(txs) == 0 {
		return nil, nil
	}
	sidecars := make(map[common.Hash]*types.BlobTxSidecar)
	for _, tx := range txs {
		if tx == nil || tx.Type() != types.BlobTxType {
			continue
		}
		hash := tx.Hash()
		sidecar := pool.GetBlobSidecar(hash)
		if sidecar == nil {
			return nil, ErrMissingBlobTxSidecar
		}
		sidecars[hash] = sidecar
	}
	if len(sidecars) == 0 {
		return nil, nil
	}
	return sidecars, nil
}

// BlobBundlesForTransactions returns tx+sidecar bundles for blob transactions.
// The tx pointer is the original transaction from the supplied list, while the
// sidecar is fetched from the txpool store.
func (pool *TxPool) BlobBundlesForTransactions(txs types.Transactions) ([]*types.BlobTxWithSidecar, error) {
	if len(txs) == 0 {
		return nil, nil
	}
	bundles := make([]*types.BlobTxWithSidecar, 0)
	for _, tx := range txs {
		if tx == nil || tx.Type() != types.BlobTxType {
			continue
		}
		sidecar := pool.GetBlobSidecar(tx.Hash())
		if sidecar == nil {
			return nil, ErrMissingBlobTxSidecar
		}
		bundle, err := types.NewBlobTxWithSidecar(tx, sidecar)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, bundle)
	}
	if len(bundles) == 0 {
		return nil, nil
	}
	return bundles, nil
}

var ErrMissingBlobSidecarForBlock = errors.New("missing blob sidecar for block blob transaction")

// ValidateBlobSidecarsForBlock validates that every BlobTx selected for a block
// has a sidecar available in the txpool sidecar store. If verifier is non-nil,
// it also runs the configured blob verifier before the block is assembled.
func (pool *TxPool) ValidateBlobSidecarsForBlock(txs types.Transactions, verifier types.BlobVerifier) error {
	for _, tx := range txs {
		if tx == nil || tx.Type() != types.BlobTxType {
			continue
		}
		sidecar := pool.GetBlobSidecar(tx.Hash())
		if sidecar == nil {
			return ErrMissingBlobSidecarForBlock
		}
		if verifier != nil {
			if err := tx.VerifyBlobSidecarVersion(sidecar, pool.activeBlobSidecarVersion(), verifier); err != nil {
				return err
			}
		} else if err := tx.ValidateBlobSidecarVersion(sidecar, pool.activeBlobSidecarVersion()); err != nil {
			return err
		}
	}
	return nil
}

// PendingWithBlobSidecars returns pending transactions after dropping BlobTxs
// whose sidecar is not available in the txpool sidecar store.
func (pool *TxPool) PendingWithBlobSidecars() (map[common.Address]types.Transactions, error) {
	pending, err := pool.Pending()
	if err != nil {
		return nil, err
	}
	return pool.filterAccountsWithBlobSidecars(pending), nil
}

// ContentWithBlobSidecars returns pending and queued transactions after dropping
// BlobTxs whose sidecar is not available in the txpool sidecar store.
func (pool *TxPool) ContentWithBlobSidecars() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	pending, queued := pool.Content()
	return pool.filterAccountsWithBlobSidecars(pending), pool.filterAccountsWithBlobSidecars(queued)
}

func (pool *TxPool) filterAccountsWithBlobSidecars(accounts map[common.Address]types.Transactions) map[common.Address]types.Transactions {
	filtered := make(map[common.Address]types.Transactions, len(accounts))
	for addr, txs := range accounts {
		keep := pool.FilterTransactionsWithBlobSidecars(txs)
		if len(keep) > 0 {
			filtered[addr] = keep
		}
	}
	return filtered
}
