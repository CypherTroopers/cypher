package ethapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	kzg "github.com/cypherium/cypher/crypto/kzg4844"
	"github.com/cypherium/cypher/params"
)

type nativeRPCAPITestBackend struct {
	*londonAPITestBackend
	nonceCalls int
}

func newNativeRPCAPITestBackend() *nativeRPCAPITestBackend {
	backend := newLondonAPITestBackend()
	backend.config.NativeParallel = params.SolanaScaleNativeParallelConfig()
	backend.config.NativeParallel.RequireNativeTransactions = true
	return &nativeRPCAPITestBackend{londonAPITestBackend: backend}
}

func newEVMOnlyNativeRPCAPITestBackend() *londonAPITestBackend {
	backend := newLondonAPITestBackend()
	backend.config.NativeParallel = params.SolanaScaleNativeParallelConfig()
	backend.config.NativeParallel.RequireNativeTransactions = false
	return backend
}

func (b *nativeRPCAPITestBackend) GetPoolNonce(context.Context, common.Address) (uint64, error) {
	b.nonceCalls++
	return 0, errors.New("native RPC must not request a pool nonce")
}

func nativeRPCUint64(value uint64) *hexutil.Uint64 {
	encoded := hexutil.Uint64(value)
	return &encoded
}

func nativeRPCBig(value int64) *hexutil.Big {
	return (*hexutil.Big)(big.NewInt(value))
}

func nativeRPCPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func validNativeRPCArgs(t *testing.T, backend *nativeRPCAPITestBackend) SendTxArgs {
	t.Helper()
	key := nativeRPCPrivateKey(t)
	payer := crypto.PubkeyToAddress(key.PublicKey)
	to := common.HexToAddress("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	head := backend.latestHeader()
	recentHash := head.Hash()
	accesses := []types.NativeAccess{
		{
			Resource: types.NativeResource{Kind: types.NativeResourceAccount, Address: payer},
			Mode:     types.NativeAccessWrite,
		},
		{
			Resource: types.NativeResource{Kind: types.NativeResourceAccount, Address: to},
			Mode:     types.NativeAccessWrite,
		},
		{
			Resource: types.NativeResource{Kind: types.NativeResourceStorage, Address: to, Slot: common.HexToHash("0x01")},
			Mode:     types.NativeAccessWrite,
		},
	}
	return SendTxArgs{
		From:                     payer,
		Payer:                    &payer,
		ReplaySequence:           nativeRPCUint64(7),
		To:                       &to,
		Value:                    nativeRPCBig(1),
		RecentBlockHash:          &recentHash,
		RecentBlockNumber:        nativeRPCUint64(head.Number.Uint64()),
		ValidUntil:               nativeRPCUint64(head.Number.Uint64() + 10),
		NativeAccesses:           &accesses,
		MaxFeePerCompute:         nativeRPCBig(20),
		MaxPriorityFeePerCompute: nativeRPCBig(2),
		ComputeLimit:             nativeRPCUint64(100_000),
		MemoryLimit:              nativeRPCUint64(1 << 20),
		LogLimit:                 nativeRPCUint64(16 << 10),
		OutputLimit:              nativeRPCUint64(32 << 10),
	}
}

func TestRetiredNativeSendTxArgsCannotBeEnabledByProgrammaticFlag(t *testing.T) {
	backend := newNativeRPCAPITestBackend()
	args := validNativeRPCArgs(t, backend)
	if err := args.setDefaults(context.Background(), backend); !errors.Is(err, errNativeTransactionsDisabled) {
		t.Fatalf("retired NativeTx RPC mode error = %v, want %v", err, errNativeTransactionsDisabled)
	}
	if backend.nonceCalls != 0 {
		t.Fatalf("rejected NativeTx request queried nonce %d times", backend.nonceCalls)
	}
}

func TestNativeSendTxArgsAlwaysRejectAtPublicBoundary(t *testing.T) {
	backend := newNativeRPCAPITestBackend()
	args := validNativeRPCArgs(t, backend)
	args.Blobs = make([]kzg.Blob, 1)
	if err := args.setDefaults(context.Background(), backend); !errors.Is(err, errNativeTransactionsDisabled) {
		t.Fatalf("NativeTx request with standard blob sidecar fields error = %v, want %v", err, errNativeTransactionsDisabled)
	}
	if backend.nonceCalls != 0 {
		t.Fatalf("rejected NativeTx request queried nonce %d times", backend.nonceCalls)
	}
}

func TestNativeFieldsRejectedOnLegacyChain(t *testing.T) {
	nativeBackend := newNativeRPCAPITestBackend()
	args := validNativeRPCArgs(t, nativeBackend)
	legacyBackend := newLondonAPITestBackend()
	if err := args.setDefaults(context.Background(), legacyBackend); err == nil || !strings.Contains(err.Error(), "native transactions disabled") {
		t.Fatalf("legacy chain accepted native fields: %v", err)
	}
}

func TestNativeRPCModeCannotBeReenabledByRetiredFlag(t *testing.T) {
	strict := newNativeRPCAPITestBackend()
	evmOnly := newEVMOnlyNativeRPCAPITestBackend()
	legacy := newLondonAPITestBackend()
	standard := SendTxArgs{}
	if !nativeTransactionsEnabled(strict) || nativeTransactionsRequired(strict) || standard.requestsNativeTransaction(strict) {
		t.Fatal("retired strict flag changed the public EVM transaction mode")
	}
	if !nativeTransactionsEnabled(evmOnly) || nativeTransactionsRequired(evmOnly) || standard.requestsNativeTransaction(evmOnly) {
		t.Fatal("EVM-only mode did not preserve standard EVM defaults")
	}
	if nativeTransactionsEnabled(legacy) || nativeTransactionsRequired(legacy) || standard.requestsNativeTransaction(legacy) {
		t.Fatal("legacy mode advertised native transaction support")
	}
	for _, txType := range []uint64{types.LegacyTxType, types.AccessListTxType, types.DynamicFeeTxType, types.BlobTxType, types.SetCodeTxType} {
		explicitType := nativeRPCUint64(txType)
		if (&SendTxArgs{Type: explicitType}).requestsNativeTransaction(evmOnly) {
			t.Fatalf("standard EVM transaction type %#x selected NativeTxV1", txType)
		}
	}
	nativeType := nativeRPCUint64(types.NativeTxType)
	if !(&SendTxArgs{Type: nativeType}).requestsNativeTransaction(evmOnly) {
		t.Fatal("explicit NativeTxV1 envelope was not classified before rejection")
	}
}

func TestEVMOnlySendTxArgsDefaultsToStandardDynamicFeeTransaction(t *testing.T) {
	backend := newEVMOnlyNativeRPCAPITestBackend()
	from := common.HexToAddress("0x1000000000000000000000000000000000000001")
	gas := nativeRPCUint64(100_000)
	input := hexutil.Bytes{0x60, 0x00}
	args := SendTxArgs{From: from, Gas: gas, Input: &input}

	if !nativeTransactionsEnabled(backend) {
		t.Fatal("EVM-only backend lost its configured parallel execution capability")
	}
	if nativeTransactionsRequired(backend) {
		t.Fatal("EVM-only backend incorrectly requires NativeTxV1")
	}
	if args.requestsNativeTransaction(backend) {
		t.Fatal("standard wallet arguments were classified as NativeTxV1")
	}
	if err := args.setDefaults(context.Background(), backend); err != nil {
		t.Fatalf("EVM-only standard defaults failed: %v", err)
	}
	if args.Nonce == nil || uint64(*args.Nonce) != 0 {
		t.Fatalf("standard nonce default = %v, want 0", args.Nonce)
	}
	if args.MaxFeePerGas == nil || args.MaxPriorityFeePerGas == nil {
		t.Fatalf("standard EIP-1559 fee defaults are missing: fee=%v tip=%v", args.MaxFeePerGas, args.MaxPriorityFeePerGas)
	}
	if args.Payer != nil || args.ReplaySequence != nil || args.ComputeLimit != nil {
		t.Fatal("standard defaults injected native transaction fields")
	}
	tx := args.toTransaction(args.transactionChainID(backend))
	if tx.Type() != types.DynamicFeeTxType || !tx.CheckNonce() || tx.Nonce() != 0 {
		t.Fatalf("EVM-only standard transaction identity: type=%#x nonce=%d checkNonce=%t", tx.Type(), tx.Nonce(), tx.CheckNonce())
	}
	if tx.ChainId().Cmp(backend.config.ChainID) != 0 || tx.To() != nil {
		t.Fatalf("EVM-only standard contract creation changed: chain=%v to=%v", tx.ChainId(), tx.To())
	}
}

func TestEVMOnlySendTxArgsKeepsExplicitSetCodeTransaction(t *testing.T) {
	backend := newEVMOnlyNativeRPCAPITestBackend()
	key := nativeRPCPrivateKey(t)
	from := crypto.PubkeyToAddress(key.PublicKey)
	to := common.HexToAddress("0x2000000000000000000000000000000000000002")
	authorization, err := types.SignSetCode(key, types.SetCodeAuthorization{
		ChainID: backend.config.ChainID,
		Address: to,
		Nonce:   0,
	})
	if err != nil {
		t.Fatal(err)
	}
	txType := nativeRPCUint64(types.SetCodeTxType)
	gas := nativeRPCUint64(100_000)
	args := SendTxArgs{
		From: from, To: &to, Gas: gas, Type: txType,
		AuthorizationList: []types.SetCodeAuthorization{authorization},
	}
	if args.requestsNativeTransaction(backend) {
		t.Fatal("type 0x04 was classified as NativeTxV1")
	}
	if err := args.setDefaults(context.Background(), backend); err != nil {
		t.Fatalf("EVM-only set-code defaults failed: %v", err)
	}
	tx := args.toTransaction(args.transactionChainID(backend))
	got := tx.SetCodeAuthorizations()
	if tx.Type() != types.SetCodeTxType || !tx.CheckNonce() || len(got) != 1 {
		t.Fatalf("EVM-only set-code identity changed: type=%#x checkNonce=%t auth=%d", tx.Type(), tx.CheckNonce(), len(got))
	}
	if got[0].Address != authorization.Address || got[0].Nonce != authorization.Nonce ||
		got[0].ChainID.Cmp(authorization.ChainID) != 0 || got[0].R.Cmp(authorization.R) != 0 ||
		got[0].S.Cmp(authorization.S) != 0 || got[0].V.Cmp(authorization.V) != 0 {
		t.Fatal("EVM-only set-code authorization changed during defaults")
	}
}

func TestEVMOnlySendTxArgsRejectsExplicitNativeTransaction(t *testing.T) {
	strictBackend := newNativeRPCAPITestBackend()
	backend := newEVMOnlyNativeRPCAPITestBackend()
	nativeType := nativeRPCUint64(types.NativeTxType)
	tests := []struct {
		name string
		args SendTxArgs
	}{
		{name: "complete native fields", args: validNativeRPCArgs(t, strictBackend)},
		{name: "type 0x05", args: SendTxArgs{Type: nativeType}},
		{name: "native-only field", args: SendTxArgs{ReplaySequence: nativeRPCUint64(0)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !test.args.requestsNativeTransaction(backend) {
				t.Fatal("explicit NativeTxV1 request was not classified before rejection")
			}
			if err := test.args.setDefaults(context.Background(), backend); !errors.Is(err, errNativeTransactionsDisabled) {
				t.Fatalf("EVM-only mode error = %v, want %v", err, errNativeTransactionsDisabled)
			}
		})
	}
}

func TestEVMOnlyRawTransactionPreservesStandardEnvelope(t *testing.T) {
	key := nativeRPCPrivateKey(t)
	to := common.HexToAddress("0x2000000000000000000000000000000000000002")
	authorization, err := types.SignSetCode(key, types.SetCodeAuthorization{
		ChainID: big.NewInt(1337),
		Address: to,
		Nonce:   0,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		make  func(*params.ChainConfig) (*types.Transaction, types.Signer)
		check func(*testing.T, *types.Transaction)
	}{
		{
			name: "legacy-eip155",
			make: func(config *params.ChainConfig) (*types.Transaction, types.Signer) {
				return types.NewTransaction(2, to, big.NewInt(1), 21_000, big.NewInt(20), nil), types.NewEIP155Signer(config.ChainID)
			},
		},
		{
			name: "access-list",
			make: func(config *params.ChainConfig) (*types.Transaction, types.Signer) {
				return types.NewTx(&types.AccessListTx{
					ChainID: config.ChainID, Nonce: 3, GasPrice: big.NewInt(20), Gas: 21_000,
					To: &to, Value: big.NewInt(1), AccessList: types.AccessList{},
				}), types.NewEIP2930Signer(config.ChainID)
			},
		},
		{
			name: "dynamic-fee",
			make: func(config *params.ChainConfig) (*types.Transaction, types.Signer) {
				return types.NewDynamicFeeTx(&types.DynamicFeeTx{
					ChainID: config.ChainID,
					Nonce:   3, GasTipCap: big.NewInt(2), GasFeeCap: big.NewInt(20), Gas: 21_000,
					To: &to, Value: big.NewInt(1),
				}), types.NewLondonSigner(config.ChainID)
			},
		},
		{
			name: "blob-execution-envelope",
			make: func(config *params.ChainConfig) (*types.Transaction, types.Signer) {
				var commitment types.KZGCommitment
				commitment[47] = 1
				return types.NewTx(&types.BlobTx{
					ChainID: config.ChainID, Nonce: 4, GasTipCap: big.NewInt(2), GasFeeCap: big.NewInt(20), Gas: 100_000,
					To: to, Value: big.NewInt(1), AccessList: types.AccessList{}, BlobFeeCap: big.NewInt(3),
					BlobHashes: []common.Hash{types.KZGToVersionedHash(commitment)},
				}), types.NewCancunSigner(config.ChainID)
			},
			check: func(t *testing.T, tx *types.Transaction) {
				if len(tx.BlobHashes()) != 1 || tx.BlobHashes()[0][0] != types.BlobCommitmentVersionKZG {
					t.Fatalf("blob versioned hashes changed: %v", tx.BlobHashes())
				}
			},
		},
		{
			name: "set-code",
			make: func(config *params.ChainConfig) (*types.Transaction, types.Signer) {
				return types.NewTx(&types.SetCodeTx{
					ChainID: config.ChainID, Nonce: 5, GasTipCap: big.NewInt(2), GasFeeCap: big.NewInt(20), Gas: 100_000,
					To: to, Value: big.NewInt(1), AccessList: types.AccessList{}, AuthList: []types.SetCodeAuthorization{authorization},
				}), types.NewPragueSigner(config.ChainID)
			},
			check: func(t *testing.T, tx *types.Transaction) {
				got := tx.SetCodeAuthorizations()
				if len(got) != 1 || got[0].Address != authorization.Address || got[0].R.Cmp(authorization.R) != 0 {
					t.Fatalf("set-code authorization changed: %#v", got)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := newEVMOnlyNativeRPCAPITestBackend()
			tx, signer := test.make(backend.config)
			signed, err := types.SignTx(tx, signer, key)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := signed.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			var received *types.Transaction
			backend.sendBatchFn = func(txs types.Transactions) []error {
				if len(txs) == 1 {
					received = txs[0]
				}
				return make([]error, len(txs))
			}
			api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
			api.singleRawTxCoalesceDelay = 0
			hash, err := api.SendRawTransaction(context.Background(), raw)
			if err != nil {
				t.Fatalf("EVM-only standard raw submission failed: %v", err)
			}
			if hash != signed.Hash() || received == nil {
				t.Fatalf("EVM-only standard raw result: hash=%s received=%v", hash, received)
			}
			if received.Type() != signed.Type() || received.Hash() != signed.Hash() || received.Nonce() != signed.Nonce() {
				t.Fatalf("raw standard envelope changed: type=%#x hash=%s nonce=%d", received.Type(), received.Hash(), received.Nonce())
			}
			if test.check != nil {
				test.check(t, received)
			}
			reencoded, err := received.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(reencoded, raw) {
				t.Fatal("raw standard transaction bytes changed during RPC admission")
			}
		})
	}
}

func TestEVMOnlyRawTransactionRejectsNativeEnvelopeAtRPC(t *testing.T) {
	strictBackend := newNativeRPCAPITestBackend()
	args := validNativeRPCArgs(t, strictBackend)
	tx := args.toNativeTransaction(strictBackend.config.ChainID, nativeTransactionInput(&args))
	signed, err := types.SignTx(tx, types.NewNativeSigner(strictBackend.config.ChainID), nativeRPCPrivateKey(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		call func(*PublicTransactionPoolAPI) error
	}{
		{
			name: "single",
			call: func(api *PublicTransactionPoolAPI) error {
				_, err := api.SendRawTransaction(context.Background(), raw)
				return err
			},
		},
		{
			name: "batch",
			call: func(api *PublicTransactionPoolAPI) error {
				results, err := api.SendRawTransactions(context.Background(), []hexutil.Bytes{raw})
				if err != nil {
					return err
				}
				if len(results) != 1 || results[0].Hash == nil || *results[0].Hash != signed.Hash() {
					return fmt.Errorf("unexpected native rejection result: %#v", results)
				}
				return errors.New(results[0].Error)
			},
		},
		{
			name: "with opts",
			call: func(api *PublicTransactionPoolAPI) error {
				_, err := api.SendRawTransactionWithOpts(context.Background(), raw, SendTxOpts{})
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := newEVMOnlyNativeRPCAPITestBackend()
			backendCalled := false
			backend.sendBatchFn = func(txs types.Transactions) []error {
				backendCalled = true
				return make([]error, len(txs))
			}
			api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
			api.singleRawTxCoalesceDelay = 0
			if err := test.call(api); err == nil || !strings.Contains(err.Error(), errNativeTransactionsDisabled.Error()) {
				t.Fatalf("raw NativeTxV1 error = %v, want %v", err, errNativeTransactionsDisabled)
			}
			if backendCalled {
				t.Fatal("raw NativeTxV1 reached the backend in EVM-only mode")
			}
		})
	}
}
