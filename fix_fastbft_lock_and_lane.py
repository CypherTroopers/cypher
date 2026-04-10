#!/usr/bin/env python3
'''
Patch the current cypher working tree (targeted at branch:
colossusx_test_-fastbft_patch) to fix:

1) ABBA deadlock risk between txS.mu and txPool.mu
2) PendingByLane(TxLaneSlow) returning all pending txs instead of strict slow-only prefix

Usage:
    python3 fix_fastbft_lock_and_lane.py /path/to/cypher
    python3 fix_fastbft_lock_and_lane.py

The script is intentionally strict:
- it matches exact blocks from the current branch head
- it aborts if the expected source text is not found exactly once
- it is idempotent: if the patch is already applied, it reports success and exits
'''
from __future__ import annotations

import sys
from pathlib import Path


def replace_exact(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    count = text.count(old)
    if count != 1:
        raise RuntimeError(
            f"[{label}] expected exact source block exactly once, found {count}. "
            "The branch content may differ from the reviewed revision."
        )
    return text.replace(old, new, 1)


def patch_txblock(src: str) -> str:
    old_try_proposal = '''func (txS *txService) tryProposalNewBlock(blockType uint8) ([]byte, error) {
	txS.mu.Lock()
	defer txS.mu.Unlock()

	work := txS.createWork(blockType)
	transactions := txS.getTransactions(blockType)

	committedTxes, publicReceipts, logs := work.commitTransactions(transactions, txS.bc)
	txCount := len(committedTxes)

	if txCount == 0 {
		log.Info("Not minting a new block since there are no pending transactions")
		return nil, fmt.Errorf("Not minting a new block since there are no pending transactions")
	}

	//txS.firePendingBlockEvents(logs)

	header := work.header

	// commit state root after all state transitions.
	colossusX.AccumulateRewards(txS.bc.Config(), work.publicState, header, nil)
	header.Root = work.publicState.IntermediateRoot(false)
	header.KeyHash = txS.kbc.CurrentBlock().Hash()
	header.BlockType = blockType

	// update block hash since it is now available, but was not when the
	// receipt/log of individual transactions were created:
	headerHash := header.Hash()
	for _, l := range logs {
		l.BlockHash = headerHash
	}

	block := types.NewBlock(header, committedTxes, nil, publicReceipts, new(trie.Trie))

	log.Info("Generated next block", "block num", block.Number(), "num txes", txCount)

	txS.proposedChain.extend(block)

	elapsed := time.Since(time.Unix(0, int64(header.Time)))
	log.Info("🔨  Mined block", "number", block.Number(), "hash", fmt.Sprintf("%x", block.Hash().Bytes()[:4]), "elapsed", elapsed)
	return block.EncodeToBytes(), nil
}
'''
    new_try_proposal = '''func (txS *txService) tryProposalNewBlock(blockType uint8) ([]byte, error) {
	allAddrTxes, err := txS.loadPendingAddressTxes(blockType)
	if err != nil {
		return nil, err
	}

	var failedTxes types.Transactions
	data, err := func() ([]byte, error) {
		txS.mu.Lock()
		defer txS.mu.Unlock()

		work := txS.createWork(blockType)
		transactions := txS.getTransactions(blockType, allAddrTxes)

		committedTxes, publicReceipts, logs, failed := work.commitTransactions(transactions, txS.bc)
		failedTxes = failed
		txCount := len(committedTxes)

		if txCount == 0 {
			log.Info("Not minting a new block since there are no pending transactions")
			return nil, fmt.Errorf("Not minting a new block since there are no pending transactions")
		}

		//txS.firePendingBlockEvents(logs)

		header := work.header

		// commit state root after all state transitions.
		colossusX.AccumulateRewards(txS.bc.Config(), work.publicState, header, nil)
		header.Root = work.publicState.IntermediateRoot(false)
		header.KeyHash = txS.kbc.CurrentBlock().Hash()
		header.BlockType = blockType

		// update block hash since it is now available, but was not when the
		// receipt/log of individual transactions were created:
		headerHash := header.Hash()
		for _, l := range logs {
			l.BlockHash = headerHash
		}

		block := types.NewBlock(header, committedTxes, nil, publicReceipts, new(trie.Trie))

		log.Info("Generated next block", "block num", block.Number(), "num txes", txCount)

		txS.proposedChain.extend(block)

		elapsed := time.Since(time.Unix(0, int64(header.Time)))
		log.Info("🔨  Mined block", "number", block.Number(), "hash", fmt.Sprintf("%x", block.Hash().Bytes()[:4]), "elapsed", elapsed)
		return block.EncodeToBytes(), nil
	}()

	if len(failedTxes) > 0 {
		txS.txPool.RemoveBatch(failedTxes)
		log.Warn("Removed failed proposal txs from txpool", "count", len(failedTxes))
	}

	return data, err
}
'''
    src = replace_exact(src, old_try_proposal, new_try_proposal, "txblock.tryProposalNewBlock")

    old_get_transactions = '''func (txS *txService) getTransactions(blockType uint8) *types.TransactionsByPriceAndNonce {
	lane := core.TxLaneSlow
	if isFastBlockType(blockType) {
		lane = core.TxLaneFast
	}
	allAddrTxes, err := txS.txPool.PendingByLane(lane)
	if err != nil { // TODO: handle
		panic(err)
	}
	addrTxes := txS.proposedChain.withoutProposedTxes(allAddrTxes, time.Now())
	addrTxes = selectTxsForBlockType(addrTxes, blockType)
	addrTxes = limitAddressTxes(addrTxes, blockProposalLimit(blockType))
	return types.NewTransactionsByPriceAndNonce(txS.config, txS.bc.CurrentBlock().Number(), addrTxes)
}
'''
    new_get_transactions = '''func (txS *txService) loadPendingAddressTxes(blockType uint8) (AddressTxes, error) {
	lane := core.TxLaneSlow
	if isFastBlockType(blockType) {
		lane = core.TxLaneFast
	}
	return txS.txPool.PendingByLane(lane)
}

func (txS *txService) getTransactions(blockType uint8, allAddrTxes AddressTxes) *types.TransactionsByPriceAndNonce {
	addrTxes := txS.proposedChain.withoutProposedTxes(allAddrTxes, time.Now())
	addrTxes = selectTxsForBlockType(addrTxes, blockType)
	addrTxes = limitAddressTxes(addrTxes, blockProposalLimit(blockType))
	return types.NewTransactionsByPriceAndNonce(txS.config, txS.bc.CurrentBlock().Number(), addrTxes)
}
'''
    src = replace_exact(src, old_get_transactions, new_get_transactions, "txblock.getTransactions")

    old_commit_sig = '''func (env *work) commitTransactions(txes *types.TransactionsByPriceAndNonce, bc *core.BlockChain) (types.Transactions, types.Receipts, []*types.Log) {
'''
    new_commit_sig = '''func (env *work) commitTransactions(txes *types.TransactionsByPriceAndNonce, bc *core.BlockChain) (types.Transactions, types.Receipts, []*types.Log, types.Transactions) {
'''
    src = replace_exact(src, old_commit_sig, new_commit_sig, "txblock.commitTransactions.signature")

    old_commit_tail = '''	if len(failedTxes) > 0 {
		env.txPool.RemoveBatch(failedTxes)
		log.Warn("Removed failed proposal txs from txpool", "count", len(failedTxes))
	}
	return committedTxes, publicReceipts, allLogs
}
'''
    new_commit_tail = '''	return committedTxes, publicReceipts, allLogs, failedTxes
}
'''
    src = replace_exact(src, old_commit_tail, new_commit_tail, "txblock.commitTransactions.tail")

    return src


def patch_txpool(src: str) -> str:
    old_pending_by_lane = '''func (pool *TxPool) PendingByLane(lane TxLane) (map[common.Address]types.Transactions, error) {
	// list.Flatten() may update internal caches, so this path requires
	// exclusive access to avoid races between concurrent callers.
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pending := make(map[common.Address]types.Transactions)
	for addr, list := range pool.pending {
		src := list.Flatten()
		if lane == TxLaneSlow {
			if len(src) > 0 {
				pending[addr] = src
			}
			continue
		}
		dst := make(types.Transactions, 0, len(src))
		for _, tx := range src {
			if ClassifyTxLane(tx) != TxLaneFast {
				break
			}
			dst = append(dst, tx)
		}
		if len(dst) > 0 {
			pending[addr] = dst
		}
	}
	return pending, nil
}
'''
    new_pending_by_lane = '''func (pool *TxPool) PendingByLane(lane TxLane) (map[common.Address]types.Transactions, error) {
	// list.Flatten() may update internal caches, so this path requires
	// exclusive access to avoid races between concurrent callers.
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pending := make(map[common.Address]types.Transactions)
	for addr, list := range pool.pending {
		src := list.Flatten()
		dst := make(types.Transactions, 0, len(src))
		for _, tx := range src {
			if ClassifyTxLane(tx) != lane {
				break
			}
			dst = append(dst, tx)
		}
		if len(dst) > 0 {
			pending[addr] = dst
		}
	}
	return pending, nil
}
'''
    src = replace_exact(src, old_pending_by_lane, new_pending_by_lane, "tx_pool.PendingByLane")
    return src


def main() -> int:
    repo = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    txblock_path = repo / "reconfig" / "txblock.go"
    txpool_path = repo / "core" / "tx_pool.go"

    if not txblock_path.exists():
        raise SystemExit(f"not found: {txblock_path}")
    if not txpool_path.exists():
        raise SystemExit(f"not found: {txpool_path}")

    txblock_src = txblock_path.read_text(encoding="utf-8")
    txpool_src = txpool_path.read_text(encoding="utf-8")

    patched_txblock = patch_txblock(txblock_src)
    patched_txpool = patch_txpool(txpool_src)

    if patched_txblock == txblock_src and patched_txpool == txpool_src:
        print("Already patched. No changes made.")
        return 0

    txblock_path.write_text(patched_txblock, encoding="utf-8")
    txpool_path.write_text(patched_txpool, encoding="utf-8")

    print("Patched:")
    print(f"  - {txblock_path}")
    print(f"  - {txpool_path}")
    print()
    print("Recommended next steps:")
    print("  gofmt -w reconfig/txblock.go core/tx_pool.go")
    print("  go test ./...")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
