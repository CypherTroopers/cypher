package vm

import (
	"testing"

	"github.com/holiman/uint256"
)

func TestCLZForkBoundary(t *testing.T) {
	if pragueInstructionSet[CLZ] != nil {
		t.Fatal("CLZ must be undefined before Osaka")
	}
	op := osakaInstructionSet[CLZ]
	if op == nil {
		t.Fatal("CLZ missing from Osaka jump table")
	}
	if op.constantGas != 5 {
		t.Fatalf("CLZ gas = %d, want 5", op.constantGas)
	}
	if got := CLZ.String(); got != "CLZ" {
		t.Fatalf("CLZ name = %q, want CLZ", got)
	}
}

func TestCLZ(t *testing.T) {
	tests := []struct {
		name  string
		value *uint256.Int
		want  uint64
	}{
		{name: "zero", value: new(uint256.Int), want: 256},
		{name: "one", value: uint256.NewInt(1), want: 255},
		{name: "low byte high bit", value: uint256.NewInt(0x80), want: 248},
		{name: "bit 255", value: new(uint256.Int).Lsh(uint256.NewInt(1), 255), want: 0},
		{name: "all bits", value: new(uint256.Int).SetAllOne(), want: 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stack := newstack()
			defer returnStack(stack)
			stack.push(test.value)

			if _, err := opCLZ(nil, nil, &callCtx{stack: stack}); err != nil {
				t.Fatalf("opCLZ returned error: %v", err)
			}
			if stack.len() != 1 {
				t.Fatalf("stack length = %d, want 1", stack.len())
			}
			if got := stack.peek().Uint64(); got != test.want {
				t.Fatalf("CLZ result = %d, want %d", got, test.want)
			}
		})
	}
}

func TestStringToOpIncludesOsakaCLZ(t *testing.T) {
	if got := StringToOp("CLZ"); got != CLZ {
		t.Fatalf("StringToOp(CLZ) = %#x, want %#x", got, CLZ)
	}
}
