package eth

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

func TestReceiptEffectiveGasPriceForModernTransactionTypes(t *testing.T) {
	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	baseFee := big.NewInt(params.FixedBaseFeePerGas)
	tipCap := big.NewInt(params.FixedPriorityFeePerGas)
	effectivePrice := new(big.Int).Add(new(big.Int).Set(baseFee), tipCap)
	feeCap := new(big.Int).Mul(big.NewInt(2), big.NewInt(params.GWei))
	header := &types.Header{BaseFee: new(big.Int).Set(baseFee)}

	txs := []*types.Transaction{
		types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(1), GasTipCap: tipCap, GasFeeCap: feeCap, To: &to, Value: new(big.Int), V: new(big.Int), R: big.NewInt(1), S: big.NewInt(1)}),
		types.NewTx(&types.BlobTx{ChainID: big.NewInt(1), GasTipCap: tipCap, GasFeeCap: feeCap, To: to, Value: new(big.Int), BlobFeeCap: big.NewInt(1), V: new(big.Int), R: big.NewInt(1), S: big.NewInt(1)}),
		types.NewTx(&types.SetCodeTx{ChainID: big.NewInt(1), GasTipCap: tipCap, GasFeeCap: feeCap, To: to, Value: new(big.Int), V: new(big.Int), R: big.NewInt(1), S: big.NewInt(1)}),
	}
	for _, tx := range txs {
		if got := receiptEffectiveGasPrice(tx, header); got.Cmp(effectivePrice) != 0 {
			t.Fatalf("type-%d effectiveGasPrice = %v, want %v (not fee cap %v)", tx.Type(), got, effectivePrice, feeCap)
		}
	}

	legacyPrice := big.NewInt(params.FixedTransferGasPricePerGas)
	legacy := types.NewTransaction(0, to, new(big.Int), params.TxGas, legacyPrice, nil)
	if got := receiptEffectiveGasPrice(legacy, header); got.Cmp(legacyPrice) != 0 {
		t.Fatalf("legacy effectiveGasPrice = %v, want %v", got, legacyPrice)
	}
}

func TestRPCTransactionYParityForStandardTypedTransactions(t *testing.T) {
	to := common.HexToAddress("0x2000000000000000000000000000000000000002")
	tests := []struct {
		name string
		tx   *types.Transaction
		want bool
	}{
		{name: "legacy", tx: types.NewTransaction(0, to, new(big.Int), params.TxGas, big.NewInt(1), nil)},
		{name: "access-list", want: true, tx: types.NewTx(&types.AccessListTx{ChainID: big.NewInt(1), To: &to, Value: new(big.Int), V: big.NewInt(1), R: big.NewInt(1), S: big.NewInt(1)})},
		{name: "dynamic-fee", want: true, tx: types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(1), To: &to, Value: new(big.Int), V: big.NewInt(1), R: big.NewInt(1), S: big.NewInt(1)})},
		{name: "blob", want: true, tx: types.NewTx(&types.BlobTx{ChainID: big.NewInt(1), To: to, Value: new(big.Int), BlobFeeCap: big.NewInt(1), V: big.NewInt(1), R: big.NewInt(1), S: big.NewInt(1)})},
		{name: "set-code", want: true, tx: types.NewTx(&types.SetCodeTx{ChainID: big.NewInt(1), To: to, Value: new(big.Int), V: big.NewInt(1), R: big.NewInt(1), S: big.NewInt(1)})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fields := make(map[string]interface{})
			v, _, _ := test.tx.RawSignatureValues()
			addRPCTransactionYParity(fields, test.tx, v)
			got, ok := fields["yParity"]
			if ok != test.want {
				t.Fatalf("yParity presence = %v, want %v", ok, test.want)
			}
			if test.want && got != hexutil.Uint64(1) {
				t.Fatalf("yParity = %#v, want 0x1", got)
			}
		})
	}
}
