package core

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/params"
)

const systemCallGas = uint64(30_000_000)

type systemMessage struct {
	from common.Address
	to   common.Address
	data []byte
}

func (m systemMessage) From() common.Address { return m.from }
func (m systemMessage) To() *common.Address  { to := m.to; return &to }
func (m systemMessage) GasPrice() *big.Int   { return new(big.Int) }
func (m systemMessage) Gas() uint64          { return systemCallGas }
func (m systemMessage) Value() *big.Int      { return new(big.Int) }
func (m systemMessage) Nonce() uint64        { return 0 }
func (m systemMessage) CheckNonce() bool     { return false }
func (m systemMessage) Data() []byte         { return common.CopyBytes(m.data) }

// ProcessParentBlockHash applies EIP-2935 to st before user transactions. Both
// proposal construction and imported-block execution call this helper, keeping
// the state root deterministic across the two paths.
func ProcessParentBlockHash(config *params.ChainConfig, header *types.Header, st *state.StateDB) error {
	if config == nil || header == nil || header.Number == nil || st == nil || header.Number.Sign() == 0 || !config.IsPrague(header.Number, header.Time) {
		return nil
	}
	if code := st.GetCode(params.HistoryStorageAddress); !bytes.Equal(code, params.HistoryStorageCode) {
		return fmt.Errorf("EIP-2935 history storage code mismatch: have %x", code)
	}
	msg := systemMessage{from: params.SystemAddress, to: params.HistoryStorageAddress, data: header.ParentHash.Bytes()}
	ctx := vm.Context{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		Origin:      params.SystemAddress,
		GasPrice:    new(big.Int),
		Coinbase:    header.Coinbase,
		GasLimit:    header.GasLimit,
		BlockNumber: new(big.Int).Set(header.Number),
		Time:        new(big.Int).SetUint64(header.Time),
		Difficulty:  new(big.Int).Set(header.Difficulty),
		BaseFee:     copyBigOrZero(header.BaseFee),
	}
	evm := vm.NewEVM(ctx, st, config, vm.Config{})
	st.AddAddressToAccessList(params.HistoryStorageAddress)
	if _, _, err := evm.Call(vm.AccountRef(params.SystemAddress), params.HistoryStorageAddress, msg.data, systemCallGas, new(big.Int)); err != nil {
		return fmt.Errorf("EIP-2935 history storage system call failed: %w", err)
	}
	st.Finalise(true)
	return nil
}

// nativeEVMBlockHashWindow is the exact history range exposed by the EVM
// BLOCKHASH opcode. EIP-2935 retains a larger ring, but importing more than the
// opcode can address would add proposal work without changing semantics.
const nativeEVMBlockHashWindow = uint64(256)

// PrepareNativeBlockHashes snapshots the EVM BLOCKHASH window from the
// state-rooted EIP-2935 ring. ProcessParentBlockHash must have run first so the
// immediate proposal parent is present. The resulting immutable view follows
// Copy and RuntimeMVCCSnapshot branches and never depends on whether a certified
// HotStuff parent has reached the node-local canonical header database.
func PrepareNativeBlockHashes(config *params.ChainConfig, header *types.Header, statedb *state.StateDB) error {
	if config == nil || !config.NativeParallelEnabled() {
		return nil
	}
	if header == nil || header.Number == nil || statedb == nil {
		return errors.New("native BLOCKHASH view requires a header and parent-derived state")
	}
	if !header.Number.IsUint64() {
		return fmt.Errorf("native BLOCKHASH proposal number %s exceeds uint64", header.Number)
	}
	number := header.Number.Uint64()
	hashes := make(map[uint64]common.Hash, nativeEVMBlockHashWindow)
	oldest := uint64(0)
	if number > nativeEVMBlockHashWindow {
		oldest = number - nativeEVMBlockHashWindow
	}
	for ancestorNumber := oldest; ancestorNumber < number; ancestorNumber++ {
		historySlot := common.BigToHash(new(big.Int).SetUint64(ancestorNumber % params.NativeReplayHistoryWindow))
		ancestorHash := statedb.GetState(params.HistoryStorageAddress, historySlot)
		if ancestorHash == (common.Hash{}) {
			return fmt.Errorf("native BLOCKHASH history hash for block %d is unavailable", ancestorNumber)
		}
		hashes[ancestorNumber] = ancestorHash
	}
	statedb.SetNativeBlockHashes(hashes)
	return nil
}

func copyBigOrZero(v *big.Int) *big.Int {
	if v == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(v)
}
