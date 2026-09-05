package eth

import (
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	lru "github.com/hashicorp/golang-lru"
)

const (
	txQUICFinalizedSenderCacheSize = 32768
	txQUICFinalizedNonceCacheSize  = 16384
)

type txQUICFinalizedStateReader interface {
	CurrentBlock() *types.Block
	StateAt(common.Hash) (*state.StateDB, error)
}

type txQUICFinalizedNonceKey struct {
	head   common.Hash
	sender common.Address
}

// txQUICFinalizedNonceLookup shares only successful, immutable lookup results.
// The bounded caches are concurrent-safe: maintenance, ingress rejection and
// WAL recovery can all call Lookup. A StateDB always belongs to one call.
type txQUICFinalizedNonceLookup struct {
	chain   txQUICFinalizedStateReader
	signer  types.Signer
	senders *lru.Cache
	nonces  *lru.Cache
}

func newTxQUICFinalizedNonceLookup(chain txQUICFinalizedStateReader, chainID *big.Int) *txQUICFinalizedNonceLookup {
	lookup := &txQUICFinalizedNonceLookup{chain: chain}
	if chainID != nil {
		// The signer and its chain identity are fixed for this lookup's lifetime.
		lookup.signer = types.LatestSignerForChainID(new(big.Int).Set(chainID))
	}
	lookup.senders, _ = lru.New(txQUICFinalizedSenderCacheSize)
	lookup.nonces, _ = lru.New(txQUICFinalizedNonceCacheSize)
	return lookup
}

// txQUICFinalizedNonceObsolete is the uncached form for isolated callers.
// The live FHS service retains one lookup across calls instead.
func txQUICFinalizedNonceObsolete(chain txQUICFinalizedStateReader, chainID *big.Int, txs types.Transactions) []bool {
	lookup := &txQUICFinalizedNonceLookup{chain: chain}
	if chainID != nil {
		lookup.signer = types.LatestSignerForChainID(new(big.Int).Set(chainID))
	}
	return lookup.Lookup(txs)
}

func (lookup *txQUICFinalizedNonceLookup) sender(tx *types.Transaction) (common.Address, error) {
	if lookup.senders != nil {
		if cached, ok := lookup.senders.Get(tx.Hash()); ok {
			return cached.(common.Address), nil
		}
	}
	sender, err := types.Sender(lookup.signer, tx)
	if err == nil && lookup.senders != nil {
		lookup.senders.Add(tx.Hash(), sender)
	}
	return sender, err
}

// Lookup is a terminal delivery predicate only for a finalized state head.
// New wires it exclusively for FHS after its 2-chain commit. Reusing a sender
// does not bypass stored-item commitments, admission checks or pool recovery.
func (lookup *txQUICFinalizedNonceLookup) Lookup(txs types.Transactions) []bool {
	obsolete := make([]bool, len(txs))
	if lookup == nil || lookup.chain == nil || lookup.signer == nil || len(txs) == 0 {
		return obsolete
	}
	head := lookup.chain.CurrentBlock()
	if head == nil {
		return obsolete
	}
	// A height alone cannot distinguish a replaced/reset head. Sender recovery
	// remains reusable, but nonce values belong to this exact finalized block.
	headHash := head.Hash()
	nonces := make(map[common.Address]uint64)
	var fresh []common.Address
	var finalizedState *state.StateDB
	for index, tx := range txs {
		if tx == nil || !tx.IsInitialized() || tx.ValidateIntegerBounds() != nil {
			continue
		}
		sender, err := lookup.sender(tx)
		if err != nil {
			continue
		}
		nonce, found := nonces[sender]
		if !found && lookup.nonces != nil {
			if cached, ok := lookup.nonces.Get(txQUICFinalizedNonceKey{headHash, sender}); ok {
				nonce, found = cached.(uint64), true
			}
		}
		if !found {
			if finalizedState == nil {
				finalizedState, err = lookup.chain.StateAt(head.Root())
				if err != nil || finalizedState == nil {
					log.Warn("Failed to open finalized state for TxQUIC cleanup", "root", head.Root(), "err", err)
					return make([]bool, len(txs))
				}
			}
			nonce = finalizedState.GetNonce(sender)
			fresh = append(fresh, sender)
		}
		nonces[sender] = nonce
		obsolete[index] = nonce > tx.Nonce()
	}
	if finalizedState != nil {
		if err := finalizedState.Error(); err != nil {
			log.Warn("Failed to read finalized state for TxQUIC cleanup", "root", head.Root(), "err", err)
			return make([]bool, len(txs))
		}
	}
	// GetNonce can return zero after a backing-store error. Publish nothing from
	// this snapshot until the entire batch has been checked for read failures.
	if lookup.nonces != nil {
		for _, sender := range fresh {
			lookup.nonces.Add(txQUICFinalizedNonceKey{headHash, sender}, nonces[sender])
		}
	}
	return obsolete
}
