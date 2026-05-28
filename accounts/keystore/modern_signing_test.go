package keystore

import (
	"math/big"
	"os"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

func TestSignDynamicFeeTxWithPassphrase(t *testing.T) {
	dir, ks := tmpKeyStore(t, true)
	defer os.RemoveAll(dir)

	account, err := ks.NewAccount("passphrase")
	if err != nil {
		t.Fatal(err)
	}
	chainID := big.NewInt(1337)
	to := common.HexToAddress("0x3333333333333333333333333333333333333333")
	tx := types.NewDynamicFeeTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     1,
		GasTipCap: big.NewInt(2),
		GasFeeCap: big.NewInt(20),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(1),
	})

	signed, err := ks.SignTxWithPassphrase(account, "passphrase", tx, chainID)
	if err != nil {
		t.Fatalf("SignTxWithPassphrase failed: %v", err)
	}
	v, _, _ := signed.RawSignatureValues()
	if v.Sign() < 0 || v.Uint64() > 1 {
		t.Fatalf("typed transaction V must be 0 or 1, got %v", v)
	}
	from, err := types.Sender(types.LatestSignerForChainID(chainID), signed)
	if err != nil {
		t.Fatalf("sender recovery failed: %v", err)
	}
	if from != account.Address {
		t.Fatalf("sender mismatch: got %s want %s", from.Hex(), account.Address.Hex())
	}

	raw, err := signed.MarshalBinary()
	if err != nil {
		t.Fatalf("typed tx encode failed: %v", err)
	}
	var decoded types.Transaction
	if err := decoded.UnmarshalBinary(raw); err != nil {
		t.Fatalf("typed tx decode failed: %v", err)
	}
	if decoded.Type() != types.DynamicFeeTxType {
		t.Fatalf("decoded tx type mismatch: got %d", decoded.Type())
	}
}
