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
	"errors"
	"fmt"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/trie"
)

// ErrFHSPerTransactionWorkLimit marks a transaction that can never fit an FHS
// block, as opposed to an otherwise-valid transaction deferred by aggregate
// block work already consumed by earlier transactions.
var ErrFHSPerTransactionWorkLimit = errors.New("Fair HotStuff per-transaction work limit exceeded")

const fhsCommonRewardFixedPayloadBytes = uint64(common.HashLength + common.AddressLength)

// BlockValidator is responsible for validating block headers, uncles and
// processed state.
//
// BlockValidator implements Validator.
type BlockValidator struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for validating
}

// NewBlockValidator returns a new block validator which is safe for re-use
func NewBlockValidator(config *params.ChainConfig, blockchain *BlockChain, engine consensus.Engine) *BlockValidator {
	validator := &BlockValidator{
		config: config,
		engine: engine,
		bc:     blockchain,
	}
	return validator
}

// ValidateBody validates the given block's uncles and verifies the block
// header's transaction and uncle roots. The headers are assumed to be already
// validated at this point.
func (v *BlockValidator) ValidateBody(block *types.Block) error {
	return v.validateBody(block, false, false, false)
}

// ValidateBodyWithHotstuffParent validates a proposal whose parent is a
// certified, locally executed HotStuff block that has not been committed yet.
func (v *BlockValidator) ValidateBodyWithHotstuffParent(block *types.Block) error {
	return v.validateBody(block, true, false, false)
}

// ValidateBodyRevalidatingKnown applies the live-proposal invariants while
// bypassing only the known-block shortcut. It must continue rejecting finality
// proof metadata, which is reserved for the passive full-sync importer.
func (v *BlockValidator) ValidateBodyRevalidatingKnown(block *types.Block, hotstuffParentAvailable bool) error {
	return v.validateBody(block, hotstuffParentAvailable, true, false)
}

// ValidateBodyForHotstuffSync revalidates a downloaded FHS block even when a
// crash left the same hash and state root in the database before the canonical
// head marker was advanced. A raw block is not a 2-chain finality proof.
func (v *BlockValidator) ValidateBodyForHotstuffSync(block *types.Block, hotstuffParentAvailable bool) error {
	return v.validateBody(block, hotstuffParentAvailable, true, true)
}

func (v *BlockValidator) validateBody(block *types.Block, hotstuffParentAvailable, revalidateKnown, allowFinalityProof bool) error {
	// Finality metadata is attached only after a direct-child QC has been
	// verified. A live proposal carrying arbitrary bytes here could consume a
	// tiny placeholder during voting and later exceed EIP-7934 when the real
	// bounded proof replaces it. Proof-bearing blocks are accepted exclusively
	// by the passive, proof-aware sync path below.
	if v.config != nil && v.config.FairHotstuff && !allowFinalityProof && len(block.FHSFinalityProof()) != 0 {
		return fmt.Errorf("live Fair HotStuff proposal contains premature finality proof metadata")
	}
	if err := validateOsakaBlockSize(v.config, block); err != nil {
		return err
	}
	// Check whether the block's known, and if not, that it's linkable
	if !revalidateKnown && v.bc.HasBlockAndState(block.Hash(), block.NumberU64()) {
		return ErrKnownBlock
	}
	// Header validity is known at this point, check the uncles and transactions
	header := block.Header()

	// Fixed-fee policy:
	// All London-active tx blocks must carry the canonical fixed baseFeePerGas.
	// This prevents validators from accepting blocks whose actual effectiveGasPrice
	// would differ from the public RPC policy:
	//   baseFeePerGas          = 0.8 gwei
	//   maxPriorityFeePerGas   = 0.2 gwei
	//   effectiveGasPrice      = 1.0 gwei for normal type-2 transfers
	if v.config != nil && v.config.IsLondon(header.Number) {
		wantBaseFee := big.NewInt(params.FixedBaseFeePerGas)
		if header.BaseFee == nil || header.BaseFee.Cmp(wantBaseFee) != 0 {
			return fmt.Errorf("invalid fixed baseFeePerGas: have %v want %v", header.BaseFee, wantBaseFee)
		}
	}
	// Reject count/byte/list/gas bounds and nil entries before deriving body
	// roots or scheduling any public-key recovery. This phase is linear, does
	// not deep-copy transaction lists, and cannot execute EVM code.
	if err := validateFHSBlockWorkEnvelope(v.config, block); err != nil {
		return err
	}
	if err := validateFHSCommonRPCSidecarCoverage(v.config, block); err != nil {
		return err
	}

	/*??
	if err := v.engine.VerifyUncles(v.bc, block); err != nil {
		return err
	}
	if hash := types.CalcUncleHash(block.Uncles()); hash != header.UncleHash {
		return fmt.Errorf("uncle root hash mismatch: have %x, want %x", hash, header.UncleHash)
	}
	*/
	body := block.Body()
	if hash := types.DeriveSha(types.Transactions(body.Transactions), new(trie.Trie)); hash != header.TxHash {
		return fmt.Errorf("transaction root hash mismatch: have %x, want %x", hash, header.TxHash)
	}
	if hash := types.DeriveCommonTxAdmissionRoot(body.CommonTxAdmissionBatches, body.CommonTxAdmissionRefs); hash != header.CommonTxAdmissionRoot {
		return fmt.Errorf("common tx admission root mismatch: have %x, want %x", hash, header.CommonTxAdmissionRoot)
	}
	if hash := types.DeriveCommonTxRewardRoot(body.CommonTxRewards); hash != header.CommonTxRewardRoot {
		return fmt.Errorf("common tx reward root mismatch: have %x, want %x", hash, header.CommonTxRewardRoot)
	}
	if err := ValidateBlockBlobBody(v.config, header, block.Transactions()); err != nil {
		return err
	}
	if !hotstuffParentAvailable && !v.bc.HasBlockAndState(block.ParentHash(), block.NumberU64()-1) {
		if !v.bc.HasBlock(block.ParentHash(), block.NumberU64()-1) {
			return consensus.ErrUnknownAncestor
		}
		return consensus.ErrPrunedAncestor
	}
	// Sender recovery is the first CPU-heavy body check. Keep all cheap body
	// commitments, blob bounds, and ancestry checks ahead of it so a malformed
	// proposal cannot force a maximum block's worth of ECDSA work.
	if err := validateFHSSenderWork(v.config, block); err != nil {
		return err
	}

	return nil
}

// FHSBlockWorkMeter accounts for allocation-free, pre-EVM consensus work. A
// value copy is a snapshot, which lets the proposer test a candidate and only
// publish the updated meter after that transaction executes successfully.
type FHSBlockWorkMeter struct {
	limits                   params.FHSBlockWorkLimits
	transactions             uint64
	declaredGas              uint64
	signatureOperations      uint64
	setCodeAuthorizations    uint64
	accessListAddresses      uint64
	accessListStorageKeys    uint64
	commonTxAdmissionBatches uint64
	commonTxAdmissionRefs    uint64
	commonTxAdmissionBytes   uint64
	commonTxRewards          uint64
	commonTxRewardBytes      uint64
}

func NewFHSBlockWorkMeter() *FHSBlockWorkMeter {
	return &FHSBlockWorkMeter{limits: params.FairHotstuffWorkLimits()}
}

// AddTransaction adds one transaction in block order. It does not mutate the
// meter when any dimension would cross its limit.
func (m *FHSBlockWorkMeter) AddTransaction(index int, tx *types.Transaction) error {
	if m == nil {
		return nil
	}
	if tx == nil || !tx.IsInitialized() {
		return fmt.Errorf("Fair HotStuff transaction %d is nil or uninitialized", index)
	}
	authCount := tx.SetCodeAuthorizationCount()
	addresses, storageKeys, countOverflow := tx.AccessListEntryCounts()
	if countOverflow {
		return fmt.Errorf("%w: transaction %d access-list storage-key count overflows uint64", ErrFHSPerTransactionWorkLimit, index)
	}
	if authCount > m.limits.SetCodeAuthorizationsPerTx {
		return fmt.Errorf("%w: transaction %d EIP-7702 authorization count %d exceeds maximum %d", ErrFHSPerTransactionWorkLimit, index, authCount, m.limits.SetCodeAuthorizationsPerTx)
	}
	if addresses > m.limits.AccessListAddressesPerTx {
		return fmt.Errorf("%w: transaction %d access-list address count %d exceeds maximum %d", ErrFHSPerTransactionWorkLimit, index, addresses, m.limits.AccessListAddressesPerTx)
	}
	if storageKeys > m.limits.AccessListStorageKeysPerTx {
		return fmt.Errorf("%w: transaction %d access-list storage-key count %d exceeds maximum %d", ErrFHSPerTransactionWorkLimit, index, storageKeys, m.limits.AccessListStorageKeysPerTx)
	}

	next := *m
	var ok bool
	if next.transactions, ok = params.AddFHSWork(next.transactions, 1, next.limits.Transactions); !ok {
		return fmt.Errorf("Fair HotStuff transaction %d makes transaction count exceed maximum %d", index, next.limits.Transactions)
	}
	if next.declaredGas, ok = params.AddFHSWork(next.declaredGas, tx.Gas(), next.limits.DeclaredGas); !ok {
		return fmt.Errorf("Fair HotStuff transaction %d makes declared gas exceed maximum %d (current %d, added %d)", index, next.limits.DeclaredGas, m.declaredGas, tx.Gas())
	}
	if next.setCodeAuthorizations, ok = params.AddFHSWork(next.setCodeAuthorizations, authCount, next.limits.SetCodeAuthorizations); !ok {
		return fmt.Errorf("Fair HotStuff transaction %d makes EIP-7702 authorization count exceed maximum %d", index, next.limits.SetCodeAuthorizations)
	}
	if next.accessListAddresses, ok = params.AddFHSWork(next.accessListAddresses, addresses, next.limits.AccessListAddresses); !ok {
		return fmt.Errorf("Fair HotStuff transaction %d makes access-list address count exceed maximum %d", index, next.limits.AccessListAddresses)
	}
	if next.accessListStorageKeys, ok = params.AddFHSWork(next.accessListStorageKeys, storageKeys, next.limits.AccessListStorageKeys); !ok {
		return fmt.Errorf("Fair HotStuff transaction %d makes access-list storage-key count exceed maximum %d", index, next.limits.AccessListStorageKeys)
	}
	signatureOps, ok := params.AddFHSWork(1, authCount, next.limits.SignatureOperations)
	if !ok {
		return fmt.Errorf("Fair HotStuff transaction %d signature-operation count overflows maximum %d", index, next.limits.SignatureOperations)
	}
	if next.signatureOperations, ok = params.AddFHSWork(next.signatureOperations, signatureOps, next.limits.SignatureOperations); !ok {
		return fmt.Errorf("Fair HotStuff transaction %d makes signature-operation count exceed maximum %d", index, next.limits.SignatureOperations)
	}
	*m = next
	return nil
}

// AddAdmissionBatch adds one signed Common RPC admission certificate. Both the
// per-certificate and aggregate byte dimensions use the exact RLP encoding,
// rather than an estimate which can drift when the certificate schema changes.
// One certificate contributes one signature operation irrespective of how many
// transaction hashes it covers.
func (m *FHSBlockWorkMeter) AddAdmissionBatch(index int, batch *types.CommonTxAdmissionBatch) error {
	if m == nil {
		return nil
	}
	if batch == nil {
		return fmt.Errorf("Fair HotStuff common transaction admission batch %d is nil", index)
	}
	encoded, err := rlp.EncodeToBytes(batch)
	if err != nil {
		return fmt.Errorf("encode Fair HotStuff common transaction admission batch %d: %w", index, err)
	}
	batchBytes := uint64(len(encoded))
	if batchBytes > m.limits.CommonTxAdmissionBytesPerBatch {
		return fmt.Errorf("Fair HotStuff common transaction admission batch %d encoded payload %d exceeds per-batch maximum %d", index, batchBytes, m.limits.CommonTxAdmissionBytesPerBatch)
	}
	next := *m
	var ok bool
	if next.commonTxAdmissionBatches, ok = params.AddFHSWork(next.commonTxAdmissionBatches, 1, next.limits.CommonTxAdmissionBatches); !ok {
		return fmt.Errorf("Fair HotStuff common transaction admission batch %d makes batch count exceed maximum %d", index, next.limits.CommonTxAdmissionBatches)
	}
	if next.commonTxAdmissionBytes, ok = params.AddFHSWork(next.commonTxAdmissionBytes, batchBytes, next.limits.CommonTxAdmissionPayloadBytes); !ok {
		return fmt.Errorf("Fair HotStuff common transaction admission batch %d makes admission payload bytes exceed maximum %d", index, next.limits.CommonTxAdmissionPayloadBytes)
	}
	if next.signatureOperations, ok = params.AddFHSWork(next.signatureOperations, 1, next.limits.SignatureOperations); !ok {
		return fmt.Errorf("Fair HotStuff common transaction admission batch %d makes signature-operation count exceed maximum %d", index, next.limits.SignatureOperations)
	}
	*m = next
	return nil
}

func fhsBigIntPayloadBytes(value *big.Int) uint64 {
	if value == nil {
		return 0
	}
	bits := value.BitLen()
	bytes := uint64(bits / 8)
	if bits%8 != 0 {
		bytes++
	}
	return bytes
}

// AddReward adds one deterministic Common RPC reward without serializing or
// copying its big integers. Rewards do not add signature operations, but their
// count cannot exceed the transactions which the admission references cover.
func (m *FHSBlockWorkMeter) AddReward(index int, reward *types.CommonTxReward) error {
	if m == nil {
		return nil
	}
	if reward == nil {
		return fmt.Errorf("Fair HotStuff common transaction reward %d is nil", index)
	}
	if reward.ApproverReward == nil || reward.Burn == nil {
		return fmt.Errorf("Fair HotStuff common transaction reward %d has nil amount", index)
	}
	if reward.ApproverReward.Sign() < 0 || reward.Burn.Sign() < 0 {
		return fmt.Errorf("Fair HotStuff common transaction reward %d has negative amount", index)
	}
	entryBytes, ok := params.AddFHSWork(fhsCommonRewardFixedPayloadBytes, fhsBigIntPayloadBytes(reward.ApproverReward), m.limits.CommonTxRewardBytesPerEntry)
	if !ok {
		return fmt.Errorf("Fair HotStuff common transaction reward %d payload exceeds per-entry maximum %d", index, m.limits.CommonTxRewardBytesPerEntry)
	}
	entryBytes, ok = params.AddFHSWork(entryBytes, fhsBigIntPayloadBytes(reward.Burn), m.limits.CommonTxRewardBytesPerEntry)
	if !ok {
		return fmt.Errorf("Fair HotStuff common transaction reward %d payload exceeds per-entry maximum %d", index, m.limits.CommonTxRewardBytesPerEntry)
	}

	next := *m
	if next.commonTxRewards, ok = params.AddFHSWork(next.commonTxRewards, 1, next.limits.CommonTxRewards); !ok {
		return fmt.Errorf("Fair HotStuff common transaction reward %d makes reward count exceed maximum %d", index, next.limits.CommonTxRewards)
	}
	if next.commonTxRewards > next.transactions {
		return fmt.Errorf("Fair HotStuff common transaction reward %d makes reward count %d exceed transaction count %d", index, next.commonTxRewards, next.transactions)
	}
	if next.commonTxRewardBytes, ok = params.AddFHSWork(next.commonTxRewardBytes, entryBytes, next.limits.CommonTxRewardPayloadBytes); !ok {
		return fmt.Errorf("Fair HotStuff common transaction reward %d makes reward payload bytes exceed maximum %d", index, next.limits.CommonTxRewardPayloadBytes)
	}
	*m = next
	return nil
}

// AddCommonSidecars atomically meters the final certificate/reference/reward
// sidecars. References are transaction-aligned, every certificate must be used,
// and every selected transaction must have exactly one reward paid to the
// certificate signer. Reward ordering remains irrelevant.
func (m *FHSBlockWorkMeter) AddCommonSidecars(batches []*types.CommonTxAdmissionBatch, refs []types.CommonTxAdmissionRef, rewards []*types.CommonTxReward) error {
	if m == nil {
		return nil
	}
	if uint64(len(batches)) > m.limits.CommonTxAdmissionBatches {
		return fmt.Errorf("Fair HotStuff common transaction admission batch count %d exceeds maximum %d", len(batches), m.limits.CommonTxAdmissionBatches)
	}
	if uint64(len(refs)) > m.limits.CommonTxAdmissionRefs {
		return fmt.Errorf("Fair HotStuff common transaction admission reference count %d exceeds maximum %d", len(refs), m.limits.CommonTxAdmissionRefs)
	}
	if uint64(len(rewards)) > m.limits.CommonTxRewards {
		return fmt.Errorf("Fair HotStuff common transaction reward count %d exceeds maximum %d", len(rewards), m.limits.CommonTxRewards)
	}
	if uint64(len(refs)) != m.transactions {
		return fmt.Errorf("Fair HotStuff common transaction admission reference count %d does not match transaction count %d", len(refs), m.transactions)
	}
	if len(rewards) != len(refs) {
		return fmt.Errorf("Fair HotStuff common transaction reward count %d does not match admission reference count %d", len(rewards), len(refs))
	}

	encodedBatches, err := rlp.EncodeToBytes(batches)
	if err != nil {
		return fmt.Errorf("encode Fair HotStuff common transaction admission batches: %w", err)
	}
	encodedRefs, err := rlp.EncodeToBytes(refs)
	if err != nil {
		return fmt.Errorf("encode Fair HotStuff common transaction admission references: %w", err)
	}
	payloadBytes, ok := params.AddFHSWork(uint64(len(encodedBatches)), uint64(len(encodedRefs)), m.limits.CommonTxAdmissionPayloadBytes)
	if !ok {
		return fmt.Errorf("Fair HotStuff common transaction admission encoded payload exceeds maximum %d", m.limits.CommonTxAdmissionPayloadBytes)
	}

	next := *m
	for index, batch := range batches {
		if batch == nil {
			return fmt.Errorf("Fair HotStuff common transaction admission batch %d is nil", index)
		}
		encoded, encodeErr := rlp.EncodeToBytes(batch)
		if encodeErr != nil {
			return fmt.Errorf("encode Fair HotStuff common transaction admission batch %d: %w", index, encodeErr)
		}
		if uint64(len(encoded)) > next.limits.CommonTxAdmissionBytesPerBatch {
			return fmt.Errorf("Fair HotStuff common transaction admission batch %d encoded payload %d exceeds per-batch maximum %d", index, len(encoded), next.limits.CommonTxAdmissionBytesPerBatch)
		}
	}
	if next.commonTxAdmissionBatches, ok = params.AddFHSWork(next.commonTxAdmissionBatches, uint64(len(batches)), next.limits.CommonTxAdmissionBatches); !ok {
		return fmt.Errorf("Fair HotStuff common transaction admission batch count makes total exceed maximum %d", next.limits.CommonTxAdmissionBatches)
	}
	if next.commonTxAdmissionRefs, ok = params.AddFHSWork(next.commonTxAdmissionRefs, uint64(len(refs)), next.limits.CommonTxAdmissionRefs); !ok {
		return fmt.Errorf("Fair HotStuff common transaction admission reference count makes total exceed maximum %d", next.limits.CommonTxAdmissionRefs)
	}
	if next.commonTxAdmissionBytes, ok = params.AddFHSWork(next.commonTxAdmissionBytes, payloadBytes, next.limits.CommonTxAdmissionPayloadBytes); !ok {
		return fmt.Errorf("Fair HotStuff common transaction admission encoded payload makes total exceed maximum %d", next.limits.CommonTxAdmissionPayloadBytes)
	}
	if next.signatureOperations, ok = params.AddFHSWork(next.signatureOperations, uint64(len(batches)), next.limits.SignatureOperations); !ok {
		return fmt.Errorf("Fair HotStuff common transaction admission batches make signature-operation count exceed maximum %d", next.limits.SignatureOperations)
	}

	referenced := make([]bool, len(batches))
	selectedRefs := make(map[uint32]struct{}, len(refs))
	approverByTx := make(map[common.Hash]common.Address, len(refs))
	for index, ref := range refs {
		if int(ref.Batch) >= len(batches) {
			return fmt.Errorf("Fair HotStuff common transaction admission reference %d selects batch %d outside %d batches", index, ref.Batch, len(batches))
		}
		batch := batches[ref.Batch]
		if int(ref.Item) >= len(batch.TxHashes) {
			return fmt.Errorf("Fair HotStuff common transaction admission reference %d selects item %d outside batch %d size %d", index, ref.Item, ref.Batch, len(batch.TxHashes))
		}
		key := uint32(ref.Batch)<<16 | uint32(ref.Item)
		if _, duplicate := selectedRefs[key]; duplicate {
			return fmt.Errorf("Fair HotStuff common transaction admission reference %d duplicates batch %d item %d", index, ref.Batch, ref.Item)
		}
		selectedRefs[key] = struct{}{}
		referenced[ref.Batch] = true
		txHash := batch.TxHashes[ref.Item]
		if txHash == (common.Hash{}) {
			return fmt.Errorf("Fair HotStuff common transaction admission reference %d selects an empty transaction hash", index)
		}
		if _, duplicate := approverByTx[txHash]; duplicate {
			return fmt.Errorf("Fair HotStuff common transaction admission reference %d duplicates transaction %s", index, txHash)
		}
		approverByTx[txHash] = batch.Miner
	}
	for index, used := range referenced {
		if !used {
			return fmt.Errorf("Fair HotStuff common transaction admission batch %d is unreferenced", index)
		}
	}
	for index, reward := range rewards {
		if err := next.AddReward(index, reward); err != nil {
			return err
		}
		if reward.TxHash == (common.Hash{}) {
			return fmt.Errorf("Fair HotStuff common transaction reward %d has empty transaction hash", index)
		}
		approver, exists := approverByTx[reward.TxHash]
		if !exists {
			return fmt.Errorf("Fair HotStuff common transaction reward %d has no matching admission reference for transaction %s", index, reward.TxHash)
		}
		if reward.Approver != approver {
			return fmt.Errorf("Fair HotStuff common transaction reward %d approver %s does not match admission batch miner %s for transaction %s", index, reward.Approver, approver, reward.TxHash)
		}
		delete(approverByTx, reward.TxHash)
	}
	if len(approverByTx) != 0 {
		return fmt.Errorf("Fair HotStuff common transaction sidecars leave %d admission references without rewards", len(approverByTx))
	}
	*m = next
	return nil
}

// validateFHSBlockWork enforces the same bounded work envelope on leaders and
// validators before EVM execution. In particular, transactions from one
// sender form a strict nonce chain and cannot benefit from the disjoint native
// transfer executor. Without this consensus check a Byzantine leader could
// bypass the proposer's per-account window and monopolize a validation worker
// with a 16k-transaction serial chain.
func validateFHSBlockWork(config *params.ChainConfig, block *types.Block) error {
	if err := validateFHSBlockWorkEnvelope(config, block); err != nil {
		return err
	}
	return validateFHSSenderWork(config, block)
}

func validateFHSBlockWorkEnvelope(config *params.ChainConfig, block *types.Block) error {
	if config == nil || !config.FairHotstuff || block == nil {
		return nil
	}
	txs := block.Transactions()
	limits := params.FairHotstuffWorkLimits()
	if uint64(len(txs)) > limits.Transactions {
		return fmt.Errorf("Fair HotStuff transaction count %d exceeds maximum %d", len(txs), limits.Transactions)
	}
	meter := NewFHSBlockWorkMeter()
	for index, tx := range txs {
		if err := meter.AddTransaction(index, tx); err != nil {
			return err
		}
	}
	body := block.Body()
	return meter.AddCommonSidecars(body.CommonTxAdmissionBatches, body.CommonTxAdmissionRefs, body.CommonTxRewards)
}

// validateFHSCommonRPCSidecarCoverage makes common RPC payment authorization a
// consensus property before signature recovery or EVM execution. Transactions
// do not carry a signed ingress marker, so the only deterministic omission-proof
// rule is that every FHS user transaction has exactly one admission and reward.
func validateFHSCommonRPCSidecarCoverage(config *params.ChainConfig, block *types.Block) error {
	if config == nil || !config.FairHotstuff || block == nil {
		return nil
	}
	body := block.Body()
	txCount := len(body.Transactions)
	batchCount := len(body.CommonTxAdmissionBatches)
	refCount := len(body.CommonTxAdmissionRefs)
	rewardCount := len(body.CommonTxRewards)
	switch block.BlockType() {
	case types.Key_Block:
		if txCount != 0 || batchCount != 0 || refCount != 0 || rewardCount != 0 {
			return fmt.Errorf("Fair HotStuff key block must not contain transactions or common RPC sidecars: txs=%d admissionBatches=%d admissionRefs=%d rewards=%d", txCount, batchCount, refCount, rewardCount)
		}
	case types.FastTx_Block, types.SlowTx_Block:
		if refCount != txCount {
			return fmt.Errorf("Fair HotStuff common transaction admission reference count %d does not match transaction count %d", refCount, txCount)
		}
		if rewardCount != txCount {
			return fmt.Errorf("Fair HotStuff common transaction reward count %d does not match transaction count %d", rewardCount, txCount)
		}
		if txCount == 0 && batchCount != 0 {
			return fmt.Errorf("Fair HotStuff empty transaction block contains %d common transaction admission batches", batchCount)
		}
		if _, err := validateCommonTxAdmissionLayout(config, body.CommonTxAdmissionBatches, body.CommonTxAdmissionRefs, body.Transactions, common.Hash{}); err != nil {
			return err
		}
		for index, reward := range body.CommonTxRewards {
			if reward == nil {
				return fmt.Errorf("Fair HotStuff common transaction reward %d is nil", index)
			}
		}
	default:
		return fmt.Errorf("unknown Fair HotStuff block type %d", block.BlockType())
	}
	return nil
}

func validateFHSSenderWork(config *params.ChainConfig, block *types.Block) error {
	if config == nil || !config.FairHotstuff || block == nil {
		return nil
	}
	txs := block.Transactions()
	if len(txs) == 0 {
		return nil
	}
	limits := params.FairHotstuffWorkLimits()
	senders := make([]common.Address, len(txs))
	senderErrors := make([]error, len(txs))
	perSender := make(map[common.Address]uint16)
	for start := 0; start < len(txs); start += parallelValidationMicroBatch {
		end := start + parallelValidationMicroBatch
		if end > len(txs) {
			end = len(txs)
		}
		runBoundedParallelValidation(end-start, func(offset int) {
			index := start + offset
			tx := txs[index]
			if tx == nil {
				senderErrors[index] = fmt.Errorf("Fair HotStuff transaction %d is nil", index)
				return
			}
			// ApplyTransaction uses the same V-aware signer selection. Matching it
			// here makes this bounded precheck the transaction's only ECDSA recovery
			// instead of invalidating the sender cache for protected legacy txs.
			signer := types.MakeSignerAutoJudgement(config, block.Number(), tx.V())
			senders[index], senderErrors[index] = types.Sender(signer, tx)
		})
		for index := start; index < end; index++ {
			if senderErrors[index] != nil {
				return fmt.Errorf("Fair HotStuff transaction %d has invalid sender: %w", index, senderErrors[index])
			}
			sender := senders[index]
			count := perSender[sender] + 1
			if uint64(count) > limits.TransactionsPerSender {
				return fmt.Errorf("Fair HotStuff sender %s transaction count %d exceeds maximum %d", sender, count, limits.TransactionsPerSender)
			}
			perSender[sender] = count
		}
	}
	return nil
}

// validateOsakaBlockSize enforces EIP-7934 before any known-block shortcut.
// This placement matters in Cypherium because consensus metadata is excluded
// from the block hash: an oversized alternate representation of a known hash
// must not bypass the Osaka payload limit.
func validateOsakaBlockSize(config *params.ChainConfig, block *types.Block) error {
	if config == nil || block == nil || block.Header() == nil || block.Number() == nil {
		return nil
	}
	header := block.Header()
	if !config.IsOsaka(header.Number, header.Time) {
		return nil
	}
	limit := uint64(params.MaxBlockSize)
	// Fair HotStuff proposals do not carry their direct-child finality proof
	// until after they have received a QC. Reserve the complete bounded proof
	// envelope before voting, otherwise an almost-full proposal can become an
	// invalid oversized block exactly when the proof is attached at commit.
	if config.FairHotstuff && len(block.FHSFinalityProof()) == 0 {
		const rlpProofOverhead = uint64(16)
		reserve := uint64(types.MaxFHSFinalityProofSize) + rlpProofOverhead
		if reserve >= limit {
			return fmt.Errorf("Fair HotStuff finality-proof reserve %d exceeds Osaka maximum %d", reserve, limit)
		}
		limit -= reserve
	}
	if size := uint64(block.Size()); size > limit {
		return fmt.Errorf("block RLP size %d exceeds Osaka maximum %d", size, limit)
	}
	return nil
}

// ValidateState validates the various changes that happen after a state
// transition, such as amount of used gas, the receipt roots and the state root
// itself. ValidateState returns a database batch if the validation was a success
// otherwise nil and an error is returned.
//
// it also verifies if the canonical hash in the blocks state points to a valid parent hash.
func (v *BlockValidator) ValidateState(block *types.Block, statedb *state.StateDB, receipts types.Receipts, usedGas uint64) error {
	header := block.Header()
	if block.GasUsed() != usedGas {
		return fmt.Errorf("invalid gas used (remote: %d local: %d)", block.GasUsed(), usedGas)
	}
	// Validate the received block's bloom with the one derived from the generated receipts.
	// For valid blocks this should always validate to true.
	rbloom := types.CreateBloom(receipts)
	if rbloom != header.Bloom {
		return fmt.Errorf("invalid bloom (remote: %x  local: %x)", header.Bloom, rbloom)
	}
	// Tre receipt Trie's root (R = (Tr [[H1, R1], ... [Hn, R1]]))
	receiptSha := types.DeriveSha(receipts, new(trie.Trie))
	if receiptSha != header.ReceiptHash {
		return fmt.Errorf("invalid receipt root hash (remote: %x local: %x)", header.ReceiptHash, receiptSha)
	}
	// Validate the state root against the received state root and throw
	// an error if they don't match.
	if root := statedb.IntermediateRoot(v.config.IsEIP158(header.Number)); header.Root != root {
		return fmt.Errorf("invalid merkle root (remote: %x local: %x)", header.Root, root)
	}
	return nil
}

// CalcGasLimit computes the gas limit of the next block after parent. It aims
// to keep the baseline gas above the provided floor, and increase it towards the
// ceil if the blocks are full. If the ceil is exceeded, it will always decrease
// the gas allowance.
func CalcGasLimit(parent *types.Block, gasFloor, gasCeil uint64) uint64 {
	// contrib = (parentGasUsed * 3 / 2) / 1024
	contrib := (parent.GasUsed() + parent.GasUsed()/2) / params.GasLimitBoundDivisor

	// decay = parentGasLimit / 1024 -1
	decay := parent.GasLimit()/params.GasLimitBoundDivisor - 1

	/*
		strategy: gasLimit of block-to-mine is set based on parent's
		gasUsed value.  if parentGasUsed > parentGasLimit * (2/3) then we
		increase it, otherwise lower it (or leave it unchanged if it's right
		at that usage) the amount increased/decreased depends on how far away
		from parentGasLimit * (2/3) parentGasUsed is.
	*/
	limit := parent.GasLimit() - decay + contrib
	if limit < params.MinGasLimit {
		limit = params.MinGasLimit
	}
	// If we're outside our allowed gas range, we try to hone towards them
	if limit < gasFloor {
		limit = parent.GasLimit() + decay
		if limit > gasFloor {
			limit = gasFloor
		}
	} else if limit > gasCeil {
		limit = parent.GasLimit() - decay
		if limit < gasCeil {
			limit = gasCeil
		}
	}
	return limit
}

func (v *BlockValidator) VerifySignature(block *types.Block) error {
	// HotStuff proposal-reference signature verification.
	//
	// Validators now sign the compact HotstuffProposalRef carried in
	// MsgPrepare.DataB, not the full block RLP.
	//
	// Full block RLP is a sidecar body referenced by BodyHash. Therefore normal
	// downloader/import validation must reconstruct the exact ProposalRef from
	// the downloaded unsigned block and verify the aggregated VotePrepare
	// signature against those ProposalRef bytes.
	//
	// Important:
	//   - BodyHash is computed from the unsigned block encoding.
	//   - block.Hash() / header.Hash() already ignores SignInfo.
	//   - CopyOrg() clears SignInfo and gives the same unsigned body that was
	//     used when the leader created the original ProposalRef.
	mycommittee := &bftview.Committee{List: v.bc.keyBlockChain.GetCommitteeByHash(block.KeyHash())}
	if mycommittee == nil || len(mycommittee.List) < 2 {
		return types.ErrInvalidCommittee
	}
	pubs := mycommittee.ToBlsPublicKeys(block.KeyHash())

	si := block.SignInfo()
	if si == nil {
		return types.ErrEmptySignature
	}
	if si.ViewID == (common.Hash{}) || si.LeaderID == "" {
		return types.ErrInvalidSignature
	}

	unsignedBlock := block.CopyOrg()
	encodedUnsignedBlock := unsignedBlock.EncodeToBytes()
	if encodedUnsignedBlock == nil {
		return types.ErrEncodeRLP
	}

	threshold := hotstuff.CalcThreshold(len(pubs))
	chainID := uint64(0)
	if v.config != nil && v.config.ChainID != nil {
		chainID = v.config.ChainID.Uint64()
	}

	var proposalRef *types.HotstuffProposalRef
	var err error
	if v.config != nil && v.config.FairHotstuff {
		proposalRef, err = types.NewHotstuffProposalRefWithCommitments(chainID, si.ViewNumber, si.ViewID, si.LeaderID, unsignedBlock, encodedUnsignedBlock, si.ExtraHash, si.ParentQCID)
	} else {
		proposalRef, err = types.NewHotstuffProposalRef(chainID, si.ViewNumber, si.ViewID, si.LeaderID, unsignedBlock, encodedUnsignedBlock)
	}
	if err != nil {
		return types.ErrInvalidSignature
	}
	proposalBytes := proposalRef.EncodeToBytes()
	if len(proposalBytes) == 0 {
		return types.ErrEncodeRLP
	}

	var validSignature bool
	if v.config != nil && v.config.FairHotstuff {
		validSignature = hotstuff.VerifyFHSSignatureWithContext(si.Signature, si.Exceptions, proposalBytes, pubs, threshold, chainID, hotstuff.MsgVotePrepare, si.ViewID, si.LeaderID)
	} else {
		validSignature = hotstuff.VerifySignatureWithContext(si.Signature, si.Exceptions, proposalBytes, pubs, threshold, chainID, hotstuff.MsgVotePrepare, si.ViewID, si.LeaderID)
	}
	if !validSignature {
		return types.ErrInvalidSignature
	}
	return nil
}

// ReconstructFHSQC verifies a block's own FHS signature and reconstructs the
// exact semantic QC committed in SignInfo. Header.Hash deliberately excludes
// SignInfo, so callers must use this verified representation rather than a
// same-hash block received from an untrusted peer.
func (v *BlockValidator) ReconstructFHSQC(block *types.Block) (*types.HotstuffProposalRef, *hotstuff.SignedState, error) {
	if block == nil || v.config == nil || !v.config.FairHotstuff {
		return nil, nil, types.ErrInvalidSignature
	}
	if err := v.VerifySignature(block); err != nil {
		return nil, nil, err
	}
	si := block.SignInfo()
	unsigned := block.CopyOrg()
	encoded := unsigned.EncodeToBytes()
	chainID := uint64(0)
	if v.config.ChainID != nil {
		chainID = v.config.ChainID.Uint64()
	}
	ref, err := types.NewHotstuffProposalRefWithCommitments(chainID, si.ViewNumber, si.ViewID, si.LeaderID, unsigned, encoded, si.ExtraHash, si.ParentQCID)
	if err != nil {
		return nil, nil, err
	}
	qc := &hotstuff.SignedState{
		State:    ref.EncodeToBytes(),
		Sign:     append([]byte(nil), si.Signature...),
		Mask:     append([]byte(nil), si.Exceptions...),
		ViewID:   si.ViewID,
		LeaderID: si.LeaderID,
		Number:   si.ViewNumber,
	}
	return ref, qc, nil
}

// VerifyFHS2ChainCommitProof verifies that childQC certifies the direct child
// of target and therefore finalizes target under the Fast-HotStuff 2-chain
// rule. Generic block sync must never advance the FHS canonical head from the
// target's own one-chain QC alone.
func (v *BlockValidator) VerifyFHS2ChainCommitProof(target *types.Block, childQC *hotstuff.SignedState) error {
	if target == nil || childQC == nil || v.config == nil || !v.config.FairHotstuff {
		return fmt.Errorf("incomplete Fair HotStuff 2-chain commit proof")
	}
	targetRef, targetQC, err := v.ReconstructFHSQC(target)
	if err != nil {
		return fmt.Errorf("invalid target FHS QC: %w", err)
	}
	childRef, err := types.DecodeHotstuffProposalRef(childQC.State)
	if err != nil {
		return fmt.Errorf("invalid child FHS proposal reference: %w", err)
	}
	chainID := uint64(0)
	if v.config.ChainID != nil {
		chainID = v.config.ChainID.Uint64()
	}
	if childRef.ChainID != chainID || childQC.Number != childRef.ViewNumber || childQC.ViewID != childRef.ViewID || childQC.LeaderID != childRef.LeaderID {
		return fmt.Errorf("child FHS QC context mismatch")
	}
	if childRef.ParentHash != target.Hash() || childRef.Number != target.NumberU64()+1 || childRef.ViewNumber <= targetRef.ViewNumber {
		return fmt.Errorf("child FHS QC does not directly extend target")
	}
	targetID, err := hotstuff.SignedStateID(targetQC)
	if err != nil {
		return fmt.Errorf("invalid target FHS QC identity: %w", err)
	}
	if childRef.ParentQCID != targetID.Hash() {
		return fmt.Errorf("child FHS QC does not bind the target QC")
	}

	committee := &bftview.Committee{List: v.bc.keyBlockChain.GetCommitteeByHash(childRef.KeyHash)}
	if committee == nil || len(committee.List) < 2 {
		return types.ErrInvalidCommittee
	}
	pubs := committee.ToBlsPublicKeys(childRef.KeyHash)
	threshold := hotstuff.CalcThreshold(len(pubs))
	if err := hotstuff.ValidateCanonicalSignerMask(childQC.Mask, len(pubs), threshold); err != nil {
		return fmt.Errorf("invalid child FHS signer mask: %w", err)
	}
	if !hotstuff.VerifyFHSSignatureWithContext(childQC.Sign, childQC.Mask, childQC.State, pubs, threshold, chainID, hotstuff.MsgVotePrepare, childQC.ViewID, childQC.LeaderID) {
		return fmt.Errorf("invalid child FHS QC signature")
	}

	latestKey := v.bc.keyBlockChain.CurrentBlock()
	if target.BlockType() == types.Key_Block {
		latestKey = types.DecodeToKeyBlock(target.KeyInfo())
	}
	if latestKey == nil {
		return fmt.Errorf("missing Fair HotStuff key activation state")
	}
	latestHash := latestKey.Hash()
	if childRef.KeyHash != target.KeyHash() && childRef.KeyHash != latestHash {
		return fmt.Errorf("child FHS QC uses an invalid signing key transition")
	}
	if childRef.KeyHash != latestHash && target.KeyHash() != latestHash &&
		(latestKey.T_Number() > ^uint64(0)-2 || childRef.Number > latestKey.T_Number()+2) {
		return fmt.Errorf("child FHS QC continues an expired signing key")
	}
	return nil
}
