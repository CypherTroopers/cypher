package core

import (
	"bytes"
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/accounts/keystore"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	kzg "github.com/cypherium/cypher/crypto/kzg4844"
	"github.com/cypherium/cypher/internal/ethapi"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/signer/storage"
)

func testSignerBig(value int64) *hexutil.Big {
	encoded := hexutil.Big(*big.NewInt(value))
	return &encoded
}

func testSignerType(txType uint64) *hexutil.Uint64 {
	encoded := hexutil.Uint64(txType)
	return &encoded
}

func testSignerArgs() SendTxArgs {
	to := common.NewMixedcaseAddress(common.HexToAddress("0x1234"))
	return SendTxArgs{
		To:       &to,
		Gas:      hexutil.Uint64(100_000),
		GasPrice: hexutil.Big(*big.NewInt(7)),
		Value:    hexutil.Big(*big.NewInt(11)),
		Nonce:    hexutil.Uint64(9),
	}
}

func TestSendTxArgsConvertsStandardEVMTypes(t *testing.T) {
	chainID := big.NewInt(1337)
	accessList := types.AccessList{{Address: common.HexToAddress("0xabcd")}}
	authorityKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := types.SignSetCode(authorityKey, types.SetCodeAuthorization{
		ChainID: chainID,
		Address: common.HexToAddress("0xbeef"),
		Nonce:   3,
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		txType uint8
		make   func() SendTxArgs
		check  func(*testing.T, *types.Transaction)
	}{
		{
			name: "legacy",
			make: func() SendTxArgs {
				args := testSignerArgs()
				args.Type = testSignerType(types.LegacyTxType)
				return args
			},
		},
		{
			name:   "access-list",
			txType: types.AccessListTxType,
			make: func() SendTxArgs {
				args := testSignerArgs()
				args.Type = testSignerType(types.AccessListTxType)
				args.AccessList = &accessList
				return args
			},
			check: func(t *testing.T, tx *types.Transaction) {
				if len(tx.AccessList()) != 1 {
					t.Fatalf("access list length = %d, want 1", len(tx.AccessList()))
				}
			},
		},
		{
			name:   "dynamic-fee",
			txType: types.DynamicFeeTxType,
			make: func() SendTxArgs {
				args := testSignerArgs()
				args.Type = testSignerType(types.DynamicFeeTxType)
				args.GasPrice = hexutil.Big{}
				args.MaxFeePerGas = testSignerBig(20)
				args.MaxPriorityFeePerGas = testSignerBig(2)
				return args
			},
		},
		{
			name:   "set-code",
			txType: types.SetCodeTxType,
			make: func() SendTxArgs {
				args := testSignerArgs()
				args.Type = testSignerType(types.SetCodeTxType)
				args.GasPrice = hexutil.Big{}
				args.MaxFeePerGas = testSignerBig(20)
				args.MaxPriorityFeePerGas = testSignerBig(2)
				args.AuthorizationList = []types.SetCodeAuthorization{authorization}
				return args
			},
			check: func(t *testing.T, tx *types.Transaction) {
				got := tx.SetCodeAuthorizations()
				if len(got) != 1 || got[0].SigHash() != authorization.SigHash() {
					t.Fatalf("set-code authorization was not preserved: %#v", got)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := test.make()
			tx, err := args.toTransaction(context.Background(), chainID)
			if err != nil {
				t.Fatal(err)
			}
			if tx.Type() != test.txType {
				t.Fatalf("transaction type = %d, want %d", tx.Type(), test.txType)
			}
			if test.txType != types.LegacyTxType && tx.ChainId().Cmp(chainID) != 0 {
				t.Fatalf("chain ID = %s, want %s", tx.ChainId(), chainID)
			}
			if test.check != nil {
				test.check(t, tx)
			}
		})
	}
}

func TestSendTxArgsInfersStandardEVMTypes(t *testing.T) {
	accessList := types.AccessList{}
	tests := []struct {
		name string
		args SendTxArgs
		want uint8
	}{
		{"legacy", SendTxArgs{}, types.LegacyTxType},
		{"access-list", SendTxArgs{AccessList: &accessList}, types.AccessListTxType},
		{"dynamic-fee", SendTxArgs{MaxFeePerGas: testSignerBig(2)}, types.DynamicFeeTxType},
		{"blob", SendTxArgs{MaxFeePerBlobGas: testSignerBig(1)}, types.BlobTxType},
		{"set-code", SendTxArgs{AuthorizationList: []types.SetCodeAuthorization{}}, types.SetCodeTxType},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.args.transactionType()
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("inferred type = %d, want %d", got, test.want)
			}
		})
	}
}

func TestSendTxArgsBuildsAndVerifiesBlobSidecar(t *testing.T) {
	chainID := big.NewInt(1337)
	args := testSignerArgs()
	args.Type = testSignerType(types.BlobTxType)
	args.GasPrice = hexutil.Big{}
	args.MaxFeePerGas = testSignerBig(20)
	args.MaxPriorityFeePerGas = testSignerBig(2)
	args.MaxFeePerBlobGas = testSignerBig(3)
	args.BlobVersion = types.BlobSidecarVersion1
	args.Blobs = []kzg.Blob{{}}

	tx, err := args.toTransaction(context.Background(), chainID)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Type() != types.BlobTxType {
		t.Fatalf("transaction type = %d, want %d", tx.Type(), types.BlobTxType)
	}
	if tx.BlobSidecar() == nil || len(tx.BlobHashes()) != 1 {
		t.Fatalf("blob sidecar/hash missing: sidecar=%v hashes=%d", tx.BlobSidecar() != nil, len(tx.BlobHashes()))
	}
	if tx.BlobSidecar().Version != types.BlobSidecarVersion1 {
		t.Fatalf("blob sidecar version = %d, want Osaka version %d", tx.BlobSidecar().Version, types.BlobSidecarVersion1)
	}
	if len(tx.BlobSidecar().Proofs) != types.BlobCellProofsPerBlob {
		t.Fatalf("cell proof count = %d, want %d", len(tx.BlobSidecar().Proofs), types.BlobCellProofsPerBlob)
	}
	if err := tx.VerifyBlobSidecar(tx.BlobSidecar(), types.KZGBlobVerifier{}); err != nil {
		t.Fatalf("generated sidecar failed real KZG verification: %v", err)
	}
	raw, err := tx.MarshalPooledBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decoded types.Transaction
	if err := decoded.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	if decoded.BlobSidecar() == nil {
		t.Fatal("pooled encoding lost blob sidecar")
	}
	if err := decoded.VerifyBlobSidecar(decoded.BlobSidecar(), types.KZGBlobVerifier{}); err != nil {
		t.Fatalf("decoded sidecar failed real KZG verification: %v", err)
	}

	bad := args
	bad.Commitments = []kzg.Commitment{kzg.Commitment(tx.BlobSidecar().Commitments[0])}
	bad.Proofs = make([]kzg.Proof, len(tx.BlobSidecar().Proofs))
	for i, proof := range tx.BlobSidecar().Proofs {
		bad.Proofs[i] = kzg.Proof(proof)
	}
	bad.Proofs[0][0] ^= 0xff
	if _, err := bad.toTransaction(context.Background(), chainID); err == nil {
		t.Fatal("tampered KZG proof was accepted")
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := args.toTransaction(canceled, chainID); err != context.Canceled {
		t.Fatalf("canceled blob build error = %v, want %v", err, context.Canceled)
	}
}

func TestSendTxArgsStringRedactsBlobPayload(t *testing.T) {
	args := testSignerArgs()
	args.Blobs = []kzg.Blob{{1}}
	args.Proofs = []kzg.Proof{{2}}
	encoded := args.String()
	if strings.Contains(encoded, `"blobs"`) {
		t.Fatalf("audit string contains full blob payload (length %d)", len(encoded))
	}
	if strings.Contains(encoded, `"proofs"`) {
		t.Fatalf("audit string contains full cell proofs (length %d)", len(encoded))
	}
	if !strings.Contains(encoded, "[blobs=1 proofs=1 redacted]") {
		t.Fatalf("audit string does not identify redaction: %s", encoded)
	}
}

func TestSendTxArgsRejectsNonStandardOrAmbiguousEnvelopes(t *testing.T) {
	chainID := big.NewInt(1337)
	tests := []struct {
		name string
		edit func(*SendTxArgs)
	}{
		{"custom type 5", func(args *SendTxArgs) { args.Type = testSignerType(5) }},
		{"legacy typed fields", func(args *SendTxArgs) {
			args.Type = testSignerType(types.LegacyTxType)
			args.MaxFeePerGas = testSignerBig(20)
		}},
		{"dynamic missing priority fee", func(args *SendTxArgs) {
			args.Type = testSignerType(types.DynamicFeeTxType)
			args.GasPrice = hexutil.Big{}
			args.MaxFeePerGas = testSignerBig(20)
		}},
		{"blob without sidecar", func(args *SendTxArgs) {
			args.Type = testSignerType(types.BlobTxType)
			args.GasPrice = hexutil.Big{}
			args.MaxFeePerGas = testSignerBig(20)
			args.MaxPriorityFeePerGas = testSignerBig(2)
			args.MaxFeePerBlobGas = testSignerBig(3)
		}},
		{"pre-Osaka blob wrapper", func(args *SendTxArgs) {
			args.Type = testSignerType(types.BlobTxType)
			args.GasPrice = hexutil.Big{}
			args.MaxFeePerGas = testSignerBig(20)
			args.MaxPriorityFeePerGas = testSignerBig(2)
			args.MaxFeePerBlobGas = testSignerBig(3)
			args.Blobs = []kzg.Blob{{}}
			args.Proofs = []kzg.Proof{{}}
		}},
		{"unsupported blob wrapper version", func(args *SendTxArgs) {
			args.Type = testSignerType(types.BlobTxType)
			args.GasPrice = hexutil.Big{}
			args.MaxFeePerGas = testSignerBig(20)
			args.MaxPriorityFeePerGas = testSignerBig(2)
			args.MaxFeePerBlobGas = testSignerBig(3)
			args.BlobVersion = 2
			args.Blobs = []kzg.Blob{{}}
		}},
		{"set-code without authorizations", func(args *SendTxArgs) {
			args.Type = testSignerType(types.SetCodeTxType)
			args.GasPrice = hexutil.Big{}
			args.MaxFeePerGas = testSignerBig(20)
			args.MaxPriorityFeePerGas = testSignerBig(2)
		}},
		{"chain ID mismatch", func(args *SendTxArgs) {
			args.Type = testSignerType(types.AccessListTxType)
			args.ChainID = testSignerBig(1)
		}},
		{"conflicting input aliases", func(args *SendTxArgs) {
			data, input := hexutil.Bytes{1}, hexutil.Bytes{2}
			args.Data, args.Input = &data, &input
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := testSignerArgs()
			test.edit(&args)
			if _, err := args.toTransaction(context.Background(), chainID); err == nil {
				t.Fatal("expected transaction conversion to fail")
			}
		})
	}
}

type signerTestValidator struct{}

func (signerTestValidator) ValidateTransaction(*string, *SendTxArgs) (*ValidationMessages, error) {
	return &ValidationMessages{}, nil
}

type signerTestUI struct {
	approved  *ethapi.SignTransactionResult
	errors    []string
	transform func(SendTxArgs) SendTxArgs
}

func (ui *signerTestUI) ApproveTx(request *SignTxRequest) (SignTxResponse, error) {
	transaction := request.Transaction
	if ui.transform != nil {
		transaction = ui.transform(transaction)
	}
	return SignTxResponse{Transaction: transaction, Approved: true}, nil
}
func (*signerTestUI) ApproveSignData(*SignDataRequest) (SignDataResponse, error) {
	return SignDataResponse{}, nil
}
func (*signerTestUI) ApproveListing(*ListRequest) (ListResponse, error) { return ListResponse{}, nil }
func (*signerTestUI) ApproveNewAccount(*NewAccountRequest) (NewAccountResponse, error) {
	return NewAccountResponse{}, nil
}
func (ui *signerTestUI) ShowError(message string) { ui.errors = append(ui.errors, message) }
func (*signerTestUI) ShowInfo(string)             {}
func (ui *signerTestUI) OnApprovedTx(tx ethapi.SignTransactionResult) {
	ui.approved = &tx
}
func (*signerTestUI) OnSignerStartup(StartupInfo) {}
func (*signerTestUI) OnInputRequired(UserInputRequest) (UserInputResponse, error) {
	return UserInputResponse{}, nil
}
func (*signerTestUI) RegisterUIServer(*UIServerAPI) {}

func TestSignerAPIReturnsSubmitReadyStandardTransactions(t *testing.T) {
	const password = "a_long_password"
	chainID := big.NewInt(1337)
	ks := keystore.NewKeyStore(t.TempDir(), 2, 1)
	account, err := ks.NewAccount(password)
	if err != nil {
		t.Fatal(err)
	}
	am := accounts.NewManager(&accounts.Config{}, ks)
	defer am.Close()
	credentials := storage.NewEphemeralStorage()
	credentials.Put(account.Address.Hex(), password)
	ui := new(signerTestUI)
	api := NewSignerAPI(am, chainID.Int64(), true, ui, signerTestValidator{}, false, credentials)
	signAndDecode := func(name string, args SendTxArgs, wantType uint8) (*ethapi.SignTransactionResult, *types.Transaction) {
		t.Helper()
		args.From = common.NewMixedcaseAddress(account.Address)
		result, err := api.SignTransaction(context.Background(), args, nil)
		if err != nil {
			t.Fatalf("%s signing failed: %v", name, err)
		}
		if result.Tx.Type() != wantType {
			t.Fatalf("%s transaction type = %d, want %d", name, result.Tx.Type(), wantType)
		}
		if ui.approved == nil || ui.approved.Tx.Hash() != result.Tx.Hash() {
			t.Fatalf("UI did not receive signed %s transaction", name)
		}
		var decoded types.Transaction
		if err := decoded.UnmarshalBinary(result.Raw); err != nil {
			t.Fatalf("returned %s raw transaction is not decodable: %v", name, err)
		}
		if decoded.Type() != wantType {
			t.Fatalf("decoded %s transaction type = %d, want %d", name, decoded.Type(), wantType)
		}
		sender, err := types.Sender(types.LatestSignerForChainID(chainID), result.Tx)
		if err != nil {
			t.Fatalf("recover %s sender: %v", name, err)
		}
		if sender != account.Address {
			t.Fatalf("signed %s sender = %s, want %s", name, sender, account.Address)
		}
		return result, &decoded
	}

	legacyArgs := testSignerArgs()
	legacyArgs.Type = testSignerType(types.LegacyTxType)
	legacyResult, _ := signAndDecode("legacy", legacyArgs, types.LegacyTxType)
	legacyRLP, err := rlp.EncodeToBytes(legacyResult.Tx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(legacyResult.Raw, legacyRLP) {
		t.Fatal("legacy raw signing output changed from canonical RLP")
	}

	accessList := types.AccessList{{Address: common.HexToAddress("0xabcd")}}
	accessArgs := testSignerArgs()
	accessArgs.Type = testSignerType(types.AccessListTxType)
	accessArgs.AccessList = &accessList
	signAndDecode("access-list", accessArgs, types.AccessListTxType)

	dynamicArgs := testSignerArgs()
	dynamicArgs.Type = testSignerType(types.DynamicFeeTxType)
	dynamicArgs.GasPrice = hexutil.Big{}
	dynamicArgs.MaxFeePerGas = testSignerBig(20)
	dynamicArgs.MaxPriorityFeePerGas = testSignerBig(2)
	signAndDecode("dynamic-fee", dynamicArgs, types.DynamicFeeTxType)

	authorityKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := types.SignSetCode(authorityKey, types.SetCodeAuthorization{
		ChainID: chainID,
		Address: common.HexToAddress("0xbeef"),
	})
	if err != nil {
		t.Fatal(err)
	}
	setCodeArgs := testSignerArgs()
	setCodeArgs.Type = testSignerType(types.SetCodeTxType)
	setCodeArgs.GasPrice = hexutil.Big{}
	setCodeArgs.MaxFeePerGas = testSignerBig(20)
	setCodeArgs.MaxPriorityFeePerGas = testSignerBig(2)
	setCodeArgs.AuthorizationList = []types.SetCodeAuthorization{authorization}
	setCodeResult, _ := signAndDecode("set-code", setCodeArgs, types.SetCodeTxType)
	if len(setCodeResult.Tx.SetCodeAuthorizations()) != 1 {
		t.Fatal("signed set-code transaction lost authorization list")
	}

	args := testSignerArgs()
	args.Type = testSignerType(types.BlobTxType)
	args.GasPrice = hexutil.Big{}
	args.MaxFeePerGas = testSignerBig(20)
	args.MaxPriorityFeePerGas = testSignerBig(2)
	args.MaxFeePerBlobGas = testSignerBig(3)
	args.BlobVersion = types.BlobSidecarVersion1
	args.Blobs = []kzg.Blob{{}}

	result, decoded := signAndDecode("blob", args, types.BlobTxType)
	if result.Tx.Type() != types.BlobTxType || result.Tx.BlobSidecar() == nil {
		t.Fatalf("signed transaction lost blob envelope: type=%d sidecar=%v", result.Tx.Type(), result.Tx.BlobSidecar() != nil)
	}
	if err := result.Tx.VerifyBlobSidecar(result.Tx.BlobSidecar(), types.KZGBlobVerifier{}); err != nil {
		t.Fatalf("signed sidecar failed real KZG verification: %v", err)
	}
	if decoded.BlobSidecar() == nil || !bytes.Equal(decoded.BlobSidecar().Blobs[0], result.Tx.BlobSidecar().Blobs[0]) {
		t.Fatal("returned raw transaction is not the sidecar-bearing pooled encoding")
	}

	// An external UI may edit the request it approves. The edited response is
	// the trust boundary: a custom type must be rejected before it is signed.
	ui.approved = nil
	ui.errors = nil
	ui.transform = func(transaction SendTxArgs) SendTxArgs {
		transaction.Type = testSignerType(5)
		return transaction
	}
	invalidArgs := legacyArgs
	invalidArgs.From = common.NewMixedcaseAddress(account.Address)
	if result, err := api.SignTransaction(context.Background(), invalidArgs, nil); err == nil || result != nil {
		t.Fatal("UI-modified custom transaction type was not rejected")
	}
	if ui.approved != nil || len(ui.errors) != 1 {
		t.Fatalf("invalid UI response reached approval callback or was not reported: approved=%v errors=%v", ui.approved != nil, ui.errors)
	}
}
