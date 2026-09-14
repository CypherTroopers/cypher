package ethapi

import (
	"bytes"
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/rpc"
)

func TestSendTxArgsValidatesExplicitChainID(t *testing.T) {
	backend := newLondonAPITestBackend()
	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	gas := hexutil.Uint64(21_000)
	nonce := hexutil.Uint64(0)
	price := (*hexutil.Big)(big.NewInt(1))

	args := SendTxArgs{
		From: to, To: &to, Gas: &gas, GasPrice: price, Nonce: &nonce,
		ChainID: (*hexutil.Big)(new(big.Int).Set(backend.config.ChainID)),
	}
	if err := args.setDefaults(context.Background(), backend); err != nil {
		t.Fatalf("matching chainId rejected: %v", err)
	}
	if got := args.transactionChainID(backend); got == nil || got.Cmp(backend.config.ChainID) != 0 {
		t.Fatalf("signing chainId = %v, want %v", got, backend.config.ChainID)
	}

	args.ChainID = (*hexutil.Big)(big.NewInt(1))
	if err := args.setDefaults(context.Background(), backend); err == nil || !strings.Contains(err.Error(), "chainId does not match") {
		t.Fatalf("mismatched chainId error = %v", err)
	}
}

func TestCallArgsAcceptsInputNonceAndValidatesWalletFields(t *testing.T) {
	backend := newLondonAPITestBackend()
	data := hexutil.Bytes{0xde, 0xad, 0xbe, 0xef}
	nonce := hexutil.Uint64(7)
	args := CallArgs{
		Input:   &data,
		Nonce:   &nonce,
		ChainID: (*hexutil.Big)(new(big.Int).Set(backend.config.ChainID)),
	}
	if err := args.validateCallArgs(backend); err != nil {
		t.Fatalf("standard call fields rejected: %v", err)
	}
	msg := args.ToMessage(100_000)
	if !bytes.Equal(msg.Data(), data) || msg.Nonce() != uint64(nonce) {
		t.Fatalf("call message data/nonce = %x/%d, want %x/%d", msg.Data(), msg.Nonce(), data, nonce)
	}

	conflicting := hexutil.Bytes{0x01}
	args.Data = &conflicting
	if err := args.validateCallArgs(backend); err == nil || !strings.Contains(err.Error(), `both "data" and "input"`) {
		t.Fatalf("conflicting calldata error = %v", err)
	}
	args.Data = nil

	args.ChainID = (*hexutil.Big)(big.NewInt(1))
	if err := args.validateCallArgs(backend); err == nil || !strings.Contains(err.Error(), "chainId does not match") {
		t.Fatalf("mismatched call chainId error = %v", err)
	}
	args.ChainID = (*hexutil.Big)(new(big.Int).Set(backend.config.ChainID))

	price := (*hexutil.Big)(big.NewInt(1))
	feeCap := (*hexutil.Big)(big.NewInt(2))
	args.GasPrice, args.MaxFeePerGas = price, feeCap
	if err := args.validateCallArgs(backend); err == nil || !strings.Contains(err.Error(), "EIP-1559") {
		t.Fatalf("mixed call fee fields error = %v", err)
	}
	args.MaxFeePerGas = nil
	args.AuthorizationList = []types.SetCodeAuthorization{}
	if err := args.validateCallArgs(backend); err == nil || !strings.Contains(err.Error(), "authorizationList") {
		t.Fatalf("legacy fee with authorizationList error = %v", err)
	}
}

func TestCallAndEstimateRejectMismatchedChainIDBeforeStateAccess(t *testing.T) {
	backend := newLondonAPITestBackend()
	wrong := (*hexutil.Big)(big.NewInt(1))
	args := CallArgs{ChainID: wrong}
	block := rpc.BlockNumberOrHashWithNumber(rpc.PendingBlockNumber)
	if _, err := DoCall(context.Background(), backend, args, block, nil, vm.Config{}, 0, 0); err == nil || !strings.Contains(err.Error(), "chainId does not match") {
		t.Fatalf("eth_call mismatch error = %v", err)
	}
	if _, err := DoEstimateGas(context.Background(), backend, args, block, 0); err == nil || !strings.Contains(err.Error(), "chainId does not match") {
		t.Fatalf("eth_estimateGas mismatch error = %v", err)
	}
}
