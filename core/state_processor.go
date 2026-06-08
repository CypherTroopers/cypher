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

func buildCommonAdmissionIndex(admissions []*types.CommonTxAdmission, chainID *big.Int) (map[common.Hash]common.Address, error) {
	indexed := make(map[common.Hash]common.Address, len(admissions))
	for _, admission := range admissions {
		if admission == nil {
			continue
		}
		if admission.TxHash == (common.Hash{}) {
			return nil, fmt.Errorf("invalid common tx admission: empty tx hash")
		}
		if admission.Miner == (common.Address{}) {
			return nil, fmt.Errorf("invalid common tx admission for %s: empty miner", admission.TxHash)
		}
		if chainID == nil || admission.ChainID == nil || admission.ChainID.Cmp(chainID) != 0 {
			return nil, fmt.Errorf("invalid common tx admission chain id for %s: have %v want %v", admission.TxHash, admission.ChainID, chainID)
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
			return nil, err
		}
		if _, exists := indexed[admission.TxHash]; exists {
			return nil, fmt.Errorf("duplicate common tx admission for %s", admission.TxHash)
		}
		indexed[admission.TxHash] = admission.Miner
	}
	return indexed, nil
}

func buildCommonRewardIndex(rewards []*types.CommonTxReward) (map[common.Hash]*types.CommonTxReward, error) {
	indexed := make(map[common.Hash]*types.CommonTxReward, len(rewards))
	for _, reward := range rewards {
		if reward == nil {
			continue
		}
		if reward.TxHash == (common.Hash{}) {
			return nil, fmt.Errorf("invalid common tx reward: empty tx hash")
		}
		if reward.ApproverReward == nil || reward.Burn == nil {
			return nil, fmt.Errorf("invalid common tx reward for %s: nil amount", reward.TxHash)
		}
		if reward.ApproverReward.Sign() < 0 || reward.Burn.Sign() < 0 {
			return nil, fmt.Errorf("invalid common tx reward for %s: negative amount", reward.TxHash)
		}
		if _, exists := indexed[reward.TxHash]; exists {
			return nil, fmt.Errorf("duplicate common tx reward for %s", reward.TxHash)
		}
		indexed[reward.TxHash] = reward
	}
	return indexed, nil
}

func settleCommonRPCReward(statedb *state.StateDB, reward *types.CommonTxReward, expectedApprover common.Address, tx *types.Transaction, gasUsed uint64, baseFee *big.Int) error {
	if reward == nil {
		return fmt.Errorf("missing common tx reward for admitted tx %s", tx.Hash())
	}
	if expectedApprover == (common.Address{}) {
		return fmt.Errorf("invalid common tx admission for %s: empty miner", tx.Hash())
	}
	if reward.TxHash != tx.Hash() {
		return fmt.Errorf("invalid common tx reward hash: have %s want %s", reward.TxHash, tx.Hash())
	}
	if reward.Approver != expectedApprover {
		return fmt.Errorf("invalid common tx reward approver for %s: have %s want %s", tx.Hash(), reward.Approver, expectedApprover)
	}
	actualFee := new(big.Int).Mul(new(big.Int).SetUint64(gasUsed), effectiveTxGasPrice(tx, baseFee))
	expectedReward := new(big.Int).Div(actualFee, big.NewInt(5))
	expectedBurn := new(big.Int).Sub(actualFee, expectedReward)
	if reward.ApproverReward.Cmp(expectedReward) != 0 {
		return fmt.Errorf("invalid common tx approver reward for %s: have %s want %s", tx.Hash(), reward.ApproverReward, expectedReward)
	}
	if reward.Burn.Cmp(expectedBurn) != 0 {
		return fmt.Errorf("invalid common tx burn for %s: have %s want %s", tx.Hash(), reward.Burn, expectedBurn)
	}
	if expectedReward.Sign() > 0 {
		statedb.AddBalance(expectedApprover, expectedReward)
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
	if root := types.DeriveCommonTxAdmissionRoot(block.CommonTxAdmissions()); root != header.CommonTxAdmissionRoot {
		return nil, nil, 0, fmt.Errorf("common tx admission root mismatch: have %s want %s", root, header.CommonTxAdmissionRoot)
	}
	if root := types.DeriveCommonTxRewardRoot(block.CommonTxRewards()); root != header.CommonTxRewardRoot {
		return nil, nil, 0, fmt.Errorf("common tx reward root mismatch: have %s want %s", root, header.CommonTxRewardRoot)
	}
	admissionByTx, err := buildCommonAdmissionIndex(block.CommonTxAdmissions(), p.config.ChainID)
	if err != nil {
		return nil, nil, 0, err
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
		totalGas += receipt.GasUsed

		txHash := tx.Hash()
		admissionMiner, hasAdmission := admissionByTx[txHash]
		reward, hasReward := rewardByTx[txHash]
		switch {
		case hasAdmission:
			if !hasReward {
				return nil, nil, 0, fmt.Errorf("common tx admission without reward for included tx: %s", txHash)
			}
			if err := settleCommonRPCReward(statedb, reward, admissionMiner, tx, receipt.GasUsed, header.BaseFee); err != nil {
				return nil, nil, 0, err
			}
			delete(admissionByTx, txHash)
			delete(rewardByTx, txHash)
		case hasReward:
			return nil, nil, 0, fmt.Errorf("common tx reward without admission for included tx: %s", txHash)
		}
	}
	if len(admissionByTx) > 0 {
		for hash := range admissionByTx {
			return nil, nil, 0, fmt.Errorf("common tx admission references tx not included in block: %s", hash)
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
