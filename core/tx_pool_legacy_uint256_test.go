package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

func TestTxPoolRejectsLegacyUint256OverflowBeforeSharedAdmission(t *testing.T) {
	to := common.HexToAddress("0x1234567890123456789012345678901234567890")
	overflow := new(big.Int).Lsh(big.NewInt(1), 256)
	tx := types.NewTx(&types.LegacyTx{
		Price:     overflow,
		GasLimit:  21_000,
		Recipient: &to,
		Amount:    new(big.Int),
		V:         big.NewInt(27),
		R:         big.NewInt(1),
		S:         big.NewInt(2),
	})

	// An otherwise-uninitialized pool is intentional: the integer boundary is
	// a stateless ingress check and must run before hashing, sender recovery,
	// state access, or any shared pool mutation.
	pool := new(TxPool)
	errs := pool.AddRemotes(types.Transactions{tx})
	if len(errs) != 1 || !errors.Is(errs[0], types.ErrTxIntegerOutOfRange) {
		t.Fatalf("AddRemotes errors = %v, want %v", errs, types.ErrTxIntegerOutOfRange)
	}
	errs = pool.ValidateLocals(types.Transactions{tx})
	if len(errs) != 1 || !errors.Is(errs[0], types.ErrTxIntegerOutOfRange) {
		t.Fatalf("ValidateLocals errors = %v, want %v", errs, types.ErrTxIntegerOutOfRange)
	}
}
