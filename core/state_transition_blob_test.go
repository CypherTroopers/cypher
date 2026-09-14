package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/params"
)

func blobTransition(t *testing.T, tx *types.Transaction) (*StateTransition, *types.Message) {
	t.Helper()
	msg, err := tx.AsMessage(types.NewLondonSigner(big.NewInt(1)))
	if err != nil {
		t.Fatal(err)
	}
	statedb := newModernTestState(t)
	statedb.SetBalance(msg.From(), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	evm := vm.NewEVM(vm.Context{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		BlockNumber: big.NewInt(1),
		Time:        big.NewInt(0),
		BaseFee:     big.NewInt(1),
		BlobBaseFee: big.NewInt(1),
		GasLimit:    30_000_000,
		BlobHashes:  tx.BlobHashes(),
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
	}, statedb, modernExecutionTestConfig(true, false), vm.Config{})
	return NewStateTransition(evm, msg, new(GasPool).AddGas(msg.Gas())), &msg
}

func TestStateTransitionExecutesValidatedBlobTransaction(t *testing.T) {
	tx, _ := signedPoolBlobTx(t, 0, false)
	transition, _ := blobTransition(t, tx)
	result, err := transition.TransitionDb()
	if err != nil {
		t.Fatalf("validated type-3 transition failed: %v", err)
	}
	if result.Failed() || result.UsedGas != params.TxGas {
		t.Fatalf("type-3 result = %+v, want successful %d-gas transfer", result, params.TxGas)
	}
}

type malformedBlobMessage struct {
	types.Message
	hashes []common.Hash
	gas    uint64
	cap    *big.Int
}

func (m malformedBlobMessage) BlobHashes() []common.Hash { return m.hashes }
func (m malformedBlobMessage) BlobGas() uint64           { return m.gas }
func (m malformedBlobMessage) BlobGasFeeCap() *big.Int   { return m.cap }
func (m malformedBlobMessage) Type() uint8               { return types.BlobTxType }

func TestStateTransitionRejectsMalformedBlobFields(t *testing.T) {
	tx, _ := signedPoolBlobTx(t, 0, false)
	_, base := blobTransition(t, tx)
	validHash := tx.BlobHashes()[0]
	tests := []struct {
		name    string
		hashes  []common.Hash
		gas     uint64
		cap     *big.Int
		wantErr error
	}{
		{name: "missing hashes", gas: params.BlobTxBlobGasPerBlob, cap: big.NewInt(2), wantErr: types.ErrBlobTxMissingBlobHashes},
		{name: "wrong hash version", hashes: []common.Hash{{0x02}}, gas: params.BlobTxBlobGasPerBlob, cap: big.NewInt(2), wantErr: types.ErrBlobTxInvalidBlobHashVersion},
		{name: "zero fee cap", hashes: []common.Hash{validHash}, gas: params.BlobTxBlobGasPerBlob, cap: new(big.Int), wantErr: types.ErrBlobTxInvalidFeeCap},
		{name: "blob gas mismatch", hashes: []common.Hash{validHash}, gas: 0, cap: big.NewInt(2), wantErr: ErrBlobGasUsedMismatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := malformedBlobMessage{Message: *base, hashes: tc.hashes, gas: tc.gas, cap: tc.cap}
			statedb := newModernTestState(t)
			statedb.SetBalance(msg.From(), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
			evm := vm.NewEVM(vm.Context{
				BlockNumber: big.NewInt(1), Time: big.NewInt(0), BaseFee: big.NewInt(1), BlobBaseFee: big.NewInt(1),
			}, statedb, modernExecutionTestConfig(true, false), vm.Config{})
			transition := NewStateTransition(evm, msg, new(GasPool).AddGas(msg.Gas()))
			if err := transition.preCheck(); !errors.Is(err, tc.wantErr) {
				t.Fatalf("preCheck error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
