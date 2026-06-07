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
	"fmt"
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

func effectiveTxGasPrice(tx *types.Transaction, baseFee *big.Int) *big.Int {
	if baseFee == nil || baseFee.Sign() == 0 {
		return new(big.Int).Set(tx.GasPrice())
	}
	gasFeeCap := tx.GasFeeCap()
	gasTipCap := tx.GasTipCap()
	if gasFeeCap == nil {
		gasFeeCap = tx.GasPrice()
	}
	if gasTipCap == nil {
		gasTipCap = tx.GasPrice()
	}
	tip := new(big.Int).Sub(gasFeeCap, baseFee)
	if tip.Sign() < 0 {
		tip.SetInt64(0)
	}
	if tip.Cmp(gasTipCap) > 0 {
		tip.Set(gasTipCap)
	}
	return new(big.Int).Add(baseFee, tip)
}

func buildCommonRewardIndex(rewards []*types.CommonTxReward) (map[common.Hash]*types.CommonTxReward, error) {
	indexed := make(map[common.Hash]*types.CommonTxReward, len(rewards))
	for _, reward := range rewards {
		if reward == nil {
			continue
		}
		if reward.Reward == nil || reward.Burn == nil {
			return nil, fmt.Errorf("invalid common tx reward for %s: nil amount", reward.TxHash)
		}
		if reward.Reward.Sign() < 0 || reward.Burn.Sign() < 0 {
			return nil, fmt.Errorf("invalid common tx reward for %s: negative amount", reward.TxHash)
		}
		if _, exists := indexed[reward.TxHash]; exists {
			return nil, fmt.Errorf("duplicate common tx reward for %s", reward.TxHash)
		}
		indexed[reward.TxHash] = reward
	}
	return indexed, nil
}

func settleCommonRPCReward(statedb *state.StateDB, reward *types.CommonTxReward, tx *types.Transaction, gasUsed uint64, baseFee *big.Int) error {
	if reward == nil {
		return nil
	}
	actualFee := new(big.Int).Mul(new(big.Int).SetUint64(gasUsed), effectiveTxGasPrice(tx, baseFee))
	expectedReward := new(big.Int).Div(actualFee, big.NewInt(5))
	expectedBurn := new(big.Int).Sub(actualFee, expectedReward)
	if reward.Reward.Cmp(expectedReward) != 0 {
		return fmt.Errorf("invalid common tx reward for %s: have %s want %s", tx.Hash(), reward.Reward, expectedReward)
	}
	if reward.Burn.Cmp(expectedBurn) != 0 {
		return fmt.Errorf("invalid common tx burn for %s: have %s want %s", tx.Hash(), reward.Burn, expectedBurn)
	}
	if reward.Miner == (common.Address{}) && expectedReward.Sign() > 0 {
		return fmt.Errorf("invalid common tx reward for %s: empty miner", tx.Hash())
	}
	if expectedReward.Sign() > 0 {
		statedb.AddBalance(reward.Miner, expectedReward)
	}
	// Burn is represented by intentionally not crediting the remaining fee to any account.
	return nil
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
	if root := types.DeriveCommonTxRewardRoot(block.CommonTxRewards()); root != header.CommonTxRewardRoot {
		return nil, nil, 0, fmt.Errorf("common tx reward root mismatch: have %s want %s", root, header.CommonTxRewardRoot)
	}
	rewardByTx, err := buildCommonRewardIndex(block.CommonTxRewards())
	if err != nil {
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
		if reward := rewardByTx[tx.Hash()]; reward != nil {
			if err := settleCommonRPCReward(statedb, reward, tx, receipt.GasUsed, header.BaseFee); err != nil {
				return nil, nil, 0, err
			}
			delete(rewardByTx, tx.Hash())
		}
	}
	if len(rewardByTx) > 0 {
		for hash := range rewardByTx {
			return nil, nil, 0, fmt.Errorf("common tx reward references tx not included in block: %s", hash)
		}
	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles(), totalGas)

	return receipts, allLogs, *usedGas, nil
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
