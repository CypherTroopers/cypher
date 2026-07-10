package reconfig

import (
	mapset "github.com/deckarep/golang-set"
	"gopkg.in/oleiade/lane.v1"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
)

const proposedTxTTL = 500 * time.Millisecond

type proposedChain struct {
	head               *types.Block
	unappliedBlocks    *lane.Deque
	invalidBlockHashes mapset.Set // This is thread-safe. This set is referred to as our "guard" below.
	proposedTxes       map[common.Hash]time.Time
}

func newProposedChain() *proposedChain {
	return &proposedChain{
		head:               nil,
		unappliedBlocks:    lane.NewDeque(),
		invalidBlockHashes: mapset.NewSet(),
		proposedTxes:       make(map[common.Hash]time.Time),
	}
}

func (chain *proposedChain) clear(block *types.Block) {
	chain.head = block
	chain.unappliedBlocks = lane.NewDeque()
	chain.invalidBlockHashes.Clear()
	chain.proposedTxes = make(map[common.Hash]time.Time)
}

// Append a new speculative block
func (chain *proposedChain) extend(block *types.Block) {
	chain.head = block
	chain.recordProposedTransactions(block.Transactions(), time.Now())
	chain.unappliedBlocks.Append(block)
}

func (chain *proposedChain) adoptCertified(block *types.Block) {
	if block == nil {
		return
	}
	if chain.head != nil && chain.head.Hash() == block.Hash() {
		return
	}
	chain.extend(block)
}

func (chain *proposedChain) markCommitted(block *types.Block) {
	if block == nil {
		return
	}
	chain.removeProposedTxes(block)
	chain.cleanupExpiredProposedTxes(time.Now())
}

// Set the parent of the speculative chain
//
// Note: This is only called when not minter
func (chain *proposedChain) setHead(block *types.Block) {
	chain.head = block
}

// Accept this block, removing it from the speculative chain
func (chain *proposedChain) accept(acceptedBlock *types.Block) {
	earliestProposedI := chain.unappliedBlocks.Shift()
	var earliestProposed *types.Block
	if nil != earliestProposedI {
		earliestProposed = earliestProposedI.(*types.Block)
	}

	// There are three possible scenarios:
	// 1. We don't have a record of this block (or any proposed blocks), meaning someone else minted it and we should
	//    add it as the new head of our speculative chain. New blocks from the old leader are still coming in.
	// 2. This block was the first outstanding one we proposed.
	// 3. This block is different from the block we proposed, (also) meaning new blocks are still coming in from the old
	//    leader, but unlike the first scenario, we need to clear all of the speculative chain state because the
	//    `acceptedBlock` takes precedence over our speculative state.
	if earliestProposed == nil {
		chain.head = acceptedBlock
		chain.cleanupExpiredProposedTxes(time.Now())
	} else if expectedBlock := earliestProposed.Hash() == acceptedBlock.Hash(); expectedBlock {
		// Remove the txes in this accepted block from our blacklist.
		chain.removeProposedTxes(acceptedBlock)
		chain.cleanupExpiredProposedTxes(time.Now())
	} else {
		log.Info("Another node minted; Clearing speculative state", "block", acceptedBlock.Hash())

		chain.clear(acceptedBlock)
	}
}

// Remove all blocks in the chain from the specified one until the end
func (chain *proposedChain) unwindFrom(invalidHash common.Hash, headBlock *types.Block) {

	// check our "guard" to see if this is a (descendant) block we're
	// expected to be ruled invalid. if we find it, remove from the guard
	if chain.invalidBlockHashes.Contains(invalidHash) {
		log.Info("Removing expected-invalid block from guard.", "block", invalidHash)

		chain.invalidBlockHashes.Remove(invalidHash)

		return
	}

	// pop from the RHS repeatedly, updating minter.parent each time. if not
	// our block, add to guard. in all cases, call removeProposedTxes
	for {
		currBlockI := chain.unappliedBlocks.Pop()

		if nil == currBlockI {
			log.Info("(Popped all blocks from queue.)")

			break
		}

		currBlock := currBlockI.(*types.Block)

		log.Info("Popped block from queue RHS.", "block", currBlock.Hash())

		// Maintain invariant: the parent always points the last speculative block or the head of the blockchain
		// if there are not speculative blocks.
		if parentI := chain.unappliedBlocks.Last(); nil != parentI {
			chain.head = parentI.(*types.Block)
		} else {
			chain.head = headBlock
		}

		chain.removeProposedTxes(currBlock)

		if currBlock.Hash() != invalidHash {
			log.Info("Haven't yet found block; adding descendent to guard.\n", "invalid block", invalidHash, "descendant", currBlock.Hash())

			chain.invalidBlockHashes.Add(currBlock.Hash())
		} else {
			break
		}
	}
}

// We keep track of txes we've put in all newly-mined blocks since the last
// ChainHeadEvent, and filter them out so that we don't try to create blocks
// with the same transactions. This is necessary because the TX pool will keep
// supplying us these transactions until they are in the chain (after having
// flown through raft).
func (chain *proposedChain) recordProposedTransactions(txes types.Transactions, now time.Time) {
	for _, tx := range txes {
		chain.proposedTxes[tx.Hash()] = now
	}
}

// Removes txes in block from our "blacklist" of "proposed tx" hashes. When we
// create a new block and use txes from the tx pool, we ignore those that we
// have already used ("proposed"), but that haven't yet officially made it into
// the chain yet.
//
// It's important to remove hashes from this blacklist (once we know we don't
// need them in there anymore) so that it doesn't grow endlessly.
func (chain *proposedChain) removeProposedTxes(block *types.Block) {
	for _, tx := range block.Transactions() {
		delete(chain.proposedTxes, tx.Hash())
	}
}

func (chain *proposedChain) cleanupExpiredProposedTxes(now time.Time) {
	for hash, ts := range chain.proposedTxes {
		if now.Sub(ts) > proposedTxTTL {
			delete(chain.proposedTxes, hash)
		}
	}
}

func (chain *proposedChain) withoutProposedTxes(addrTxes AddressTxes, now time.Time) AddressTxes {
	chain.cleanupExpiredProposedTxes(now)

	// PendingByLane already returns a fresh map. Reuse that map and compact
	// each tx slice in-place instead of allocating another AddressTxes map and
	// filtered slice for every account.
	for addr, txes := range addrTxes {
		writeIndex := 0
		for _, tx := range txes {
			if _, blocked := chain.proposedTxes[tx.Hash()]; blocked {
				continue
			}
			txes[writeIndex] = tx
			writeIndex++
		}
		if writeIndex == 0 {
			delete(addrTxes, addr)
			continue
		}
		addrTxes[addr] = txes[:writeIndex]
	}

	return addrTxes
}
