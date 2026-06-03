// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/consensus/misc"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
)

var commonApprovalSignerReward = mustCommonApprovalSignerReward()

func mustCommonApprovalSignerReward() *big.Int {
	// 1000 native coins with 18 decimals.
	reward, ok := new(big.Int).SetString("1000000000000000000000", 10)
	if !ok {
		panic("invalid common approval signer reward")
	}
	return reward
}

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts types.Receipts
		usedGas  = new(uint64)
		header   = block.Header()
		allLogs  []*types.Log
		gp       = new(GasPool).AddGas(block.GasLimit())
	)
	if err := ValidateBlockBlobGas(p.config, header, block.Transactions()); err != nil {
		return nil, nil, 0, err
	}
	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	var totalGas uint64

	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		receipt, err := ApplyTransaction(p.config, p.bc, nil, gp, statedb, header, tx, usedGas, cfg)
		if err != nil {
			return nil, nil, 0, err
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
		totalGas += receipt.GasUsed * tx.GasPrice().Uint64()

	}

	// Settle CommonApproval signer rewards only at a key-block boundary.
	// KeyBlock itself does not carry EVM state, so the settlement is applied in
	// the first tx block that points to the new KeyHash. The settlement scans only
	// already-finalized tx blocks from the previous KeyHash period, so leader and
	// validator nodes recompute the same state root.
	p.applyCommonApprovalRewardsAtKeySwitch(block, statedb)

	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles(), totalGas)

	return receipts, allLogs, *usedGas, nil
}

func (p *StateProcessor) applyCommonApprovalRewardsAtKeySwitch(block *types.Block, statedb *state.StateDB) {
	if p == nil || p.config == nil || !p.config.CommonApprovalEnabled || p.bc == nil || block == nil || statedb == nil {
		return
	}
	if block.NumberU64() == 0 {
		return
	}
	parent := p.bc.GetBlock(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		return
	}
	settledKeyHash := parent.KeyHash()
	if block.KeyHash() == settledKeyHash {
		return
	}

	nodes := OrderedCommonCommittee(p.config)
	if len(nodes) == 0 {
		return
	}
	committeeHash := CommonApprovalCommitteeHash(p.config)
	counts := make(map[common.Address]uint64)

	for b := parent; b != nil && b.KeyHash() == settledKeyHash; {
		p.collectCommonApprovalRewardCounts(b, nodes, committeeHash, counts)
		if b.NumberU64() == 0 {
			break
		}
		b = p.bc.GetBlock(b.ParentHash(), b.NumberU64()-1)
	}

	for addr, count := range counts {
		if count == 0 {
			continue
		}
		amount := new(big.Int).Mul(new(big.Int).SetUint64(count), commonApprovalSignerReward)
		statedb.AddBalance(addr, amount)
		log.Info("common approval keyblock reward settled", "settledKeyHash", settledKeyHash, "coinbase", addr, "signedTxBlocks", count, "amount", amount)
	}
}

func (p *StateProcessor) collectCommonApprovalRewardCounts(block *types.Block, nodes []*common.Cnode, committeeHash common.Hash, counts map[common.Address]uint64) {
	if block == nil || counts == nil || block.BlockType() == types.Key_Block {
		return
	}
	signInfo := block.SignInfo()
	if signInfo == nil || len(signInfo.CommonApprovalSignature) == 0 || len(signInfo.CommonApprovalExceptions) == 0 {
		return
	}
	if signInfo.CommonApprovalCommitteeHash != committeeHash {
		log.Warn("skip common approval reward: committee hash mismatch", "block", block.NumberU64(), "have", signInfo.CommonApprovalCommitteeHash.Hex(), "want", committeeHash.Hex())
		return
	}
	for i, node := range nodes {
		if node == nil || node.CoinBase == "" {
			continue
		}
		if len(signInfo.CommonApprovalExceptions) <= i/8 {
			continue
		}
		if (signInfo.CommonApprovalExceptions[i/8] & (1 << uint(i%8))) == 0 {
			continue
		}
		counts[common.HexToAddress(node.CoinBase)]++
	}
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	msg, err := tx.AsMessage(types.MakeSignerAutoJudgement(config, header.Number, tx.V()))
	if err != nil {
		return nil, err
	}
	log.Info("ApplyTransaction", "msg.from", msg.From(), "msg.To()", msg.To())
	// Create a new context to be used in the EVM environment
	context := NewEVMContextWithConfig(config, msg, header, bc, author)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := vm.NewEVM(context, statedb, config, cfg)
	// Apply the transaction to the current state (included in the env)
	result, err := ApplyMessage(vmenv, msg, gp)
	if err != nil {
		return nil, err
	}
	// Update the state with pending changes
	var root []byte
	if config.IsByzantium(header.Number) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(header.Number)).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing whether the root touch-delete accounts.
	receipt := types.NewReceipt(root, result.Failed(), *usedGas)
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas
	// if the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(vmenv.Context.Origin, tx.Nonce())
	}
	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = statedb.GetLogs(tx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = statedb.BlockHash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, err
}
