package core

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/core/types"
)

func TestValidate1559FeeCapsBounds(t *testing.T) {
	baseFee := big.NewInt(100)

	t.Run("fee cap below base fee", func(t *testing.T) {
		tx := types.NewTx(&types.DynamicFeeTx{GasFeeCap: big.NewInt(99), GasTipCap: big.NewInt(1)})
		if err := validate1559FeeCaps(tx, baseFee); err != ErrGasFeeCapTooLow {
			t.Fatalf("expected %v, got %v", ErrGasFeeCapTooLow, err)
		}
	})

	t.Run("fee cap bit length too high", func(t *testing.T) {
		tx := types.NewTx(&types.DynamicFeeTx{GasFeeCap: new(big.Int).Lsh(big.NewInt(1), 256), GasTipCap: big.NewInt(1)})
		if err := validate1559FeeCaps(tx, baseFee); err != ErrFeeCapVeryHigh {
			t.Fatalf("expected %v, got %v", ErrFeeCapVeryHigh, err)
		}
	})

	t.Run("tip cap bit length too high", func(t *testing.T) {
		tx := types.NewTx(&types.DynamicFeeTx{GasFeeCap: new(big.Int).Lsh(big.NewInt(1), 255), GasTipCap: new(big.Int).Lsh(big.NewInt(1), 256)})
		if err := validate1559FeeCaps(tx, baseFee); err != ErrTipVeryHigh {
			t.Fatalf("expected %v, got %v", ErrTipVeryHigh, err)
		}
	})
}
