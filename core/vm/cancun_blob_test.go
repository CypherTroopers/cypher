package vm

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/holiman/uint256"
)

func TestBlobHashOpcodeUsesContextHashes(t *testing.T) {
	want := common.HexToHash("0x0102030405060708091011121314151617181920212223242526272829303132")
	interpreter := &EVMInterpreter{evm: &EVM{Context: Context{BlobHashes: []common.Hash{want}}}}
	stack := newstack()
	defer returnStack(stack)
	stack.push(uint256.NewInt(0))
	ctx := &callCtx{stack: stack}

	if _, err := opBlobHash(nil, interpreter, ctx); err != nil {
		t.Fatalf("opBlobHash returned error: %v", err)
	}
	if got := common.BytesToHash(stack.peek().Bytes()); got != want {
		t.Fatalf("blob hash mismatch: got %s want %s", got.Hex(), want.Hex())
	}
}

func TestBlobHashOpcodeOutOfRangeReturnsZero(t *testing.T) {
	interpreter := &EVMInterpreter{evm: &EVM{Context: Context{BlobHashes: nil}}}
	stack := newstack()
	defer returnStack(stack)
	stack.push(uint256.NewInt(5))
	ctx := &callCtx{stack: stack}

	if _, err := opBlobHash(nil, interpreter, ctx); err != nil {
		t.Fatalf("opBlobHash returned error: %v", err)
	}
	if !stack.peek().IsZero() {
		t.Fatalf("expected zero for out-of-range blob hash, got %s", stack.peek().Hex())
	}
}

func TestBlobBaseFeeOpcodeUsesContextValue(t *testing.T) {
	interpreter := &EVMInterpreter{evm: &EVM{Context: Context{BlobBaseFee: big.NewInt(12345)}}}
	stack := newstack()
	defer returnStack(stack)
	ctx := &callCtx{stack: stack}

	if _, err := opBlobBaseFee(nil, interpreter, ctx); err != nil {
		t.Fatalf("opBlobBaseFee returned error: %v", err)
	}
	if got := stack.peek().ToBig(); got.Cmp(big.NewInt(12345)) != 0 {
		t.Fatalf("blob base fee mismatch: got %v want 12345", got)
	}
}

func TestBlobBaseFeeOpcodeNilReturnsZero(t *testing.T) {
	interpreter := &EVMInterpreter{evm: &EVM{Context: Context{}}}
	stack := newstack()
	defer returnStack(stack)
	ctx := &callCtx{stack: stack}

	if _, err := opBlobBaseFee(nil, interpreter, ctx); err != nil {
		t.Fatalf("opBlobBaseFee returned error: %v", err)
	}
	if !stack.peek().IsZero() {
		t.Fatalf("expected zero blob base fee, got %s", stack.peek().Hex())
	}
}
