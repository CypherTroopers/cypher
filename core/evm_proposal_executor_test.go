package core

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
)

func TestExecuteEVMProposalTransactionsMatchesValidatorMVCC(t *testing.T) {
	config := evmMVCTestConfig()
	base := newModernTestState(t)
	block, txs := evmMVCCTestBlock(t, config, base, false, 32)
	prepareEVMOnlyHistory(base, block.Header())
	base.Finalise(true)

	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}

	proposalState := base.Copy()
	proposalReceipts, proposalLogs, proposalGas, err := ExecuteEVMProposalTransactions(config, chain, block.Header(), txs, proposalState, vm.Config{})
	if err != nil {
		t.Fatalf("proposal execution: %v", err)
	}

	validatorState := base.Copy()
	if err := PrepareNativeBlockHashes(config, block.Header(), validatorState); err != nil {
		t.Fatal(err)
	}
	validatorGasPool := new(GasPool).AddGas(block.GasLimit())
	var validatorGas uint64
	validatorReceipts := make(types.Receipts, 0, len(txs))
	validatorLogs := make([]*types.Log, 0)
	processor := &StateProcessor{config: config, bc: chain}
	err = processor.processEVMOptimistic(block, validatorState, validatorGasPool, &validatorGas, vm.Config{}, func(index int, tx *types.Transaction, receipt *types.Receipt) error {
		validatorReceipts = append(validatorReceipts, receipt)
		validatorLogs = append(validatorLogs, receipt.Logs...)
		return nil
	})
	if err != nil {
		t.Fatalf("validator execution: %v", err)
	}

	proposalRoot := proposalState.IntermediateRoot(true)
	validatorRoot := validatorState.IntermediateRoot(true)
	if proposalRoot != validatorRoot || proposalGas != validatorGas || !reflect.DeepEqual(proposalReceipts, validatorReceipts) || !reflect.DeepEqual(proposalLogs, validatorLogs) {
		t.Fatalf("proposal/validator mismatch: root=%s/%s gas=%d/%d receipts=%t logs=%t",
			proposalRoot, validatorRoot, proposalGas, validatorGas,
			reflect.DeepEqual(proposalReceipts, validatorReceipts), reflect.DeepEqual(proposalLogs, validatorLogs))
	}
}

func TestExecuteEVMProposalTransactionsUsesSerialOracleForDebugVM(t *testing.T) {
	config := evmMVCTestConfig()
	base := newModernTestState(t)
	block, txs := evmMVCCTestBlock(t, config, base, true, 8)
	prepareEVMOnlyHistory(base, block.Header())
	base.Finalise(true)
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}

	parallelState := base.Copy()
	parallelReceipts, _, parallelGas, err := ExecuteEVMProposalTransactions(config, chain, block.Header(), txs, parallelState, vm.Config{EnablePreimageRecording: true})
	if err != nil {
		t.Fatalf("serial proposal fallback: %v", err)
	}

	referenceState := base.Copy()
	if err := PrepareNativeBlockHashes(config, block.Header(), referenceState); err != nil {
		t.Fatal(err)
	}
	referencePool := new(GasPool).AddGas(block.GasLimit())
	var referenceGas uint64
	referenceReceipts := make(types.Receipts, 0, len(txs))
	for index, tx := range txs {
		referenceState.Prepare(tx.Hash(), block.Hash(), index)
		receipt, err := ApplyTransaction(config, chain, nil, referencePool, referenceState, block.Header(), tx, &referenceGas, vm.Config{EnablePreimageRecording: true})
		if err != nil {
			t.Fatalf("reference transaction %d: %v", index, err)
		}
		referenceReceipts = append(referenceReceipts, receipt)
	}
	if parallelState.IntermediateRoot(true) != referenceState.IntermediateRoot(true) || parallelGas != referenceGas || !reflect.DeepEqual(parallelReceipts, referenceReceipts) {
		t.Fatal("unsupported VM configuration did not match the serial oracle")
	}
}

func TestExecuteEVMProposalTransactionsSupportsTypesZeroThroughFourAndPreservesBlobSidecar(t *testing.T) {
	config := evmMVCTestConfig()
	base := newModernTestState(t)
	to := common.HexToAddress("0x7000000000000000000000000000000000000007")
	signer := types.LatestSignerForChainID(config.ChainID)
	keys := []string{
		"1111111111111111111111111111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222222222222222222222222222",
		"3333333333333333333333333333333333333333333333333333333333333333",
		"4444444444444444444444444444444444444444444444444444444444444444",
	}
	unsigned := []*types.Transaction{
		types.NewTransaction(0, to, new(big.Int), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil),
		types.NewTx(&types.AccessListTx{ChainID: config.ChainID, GasPrice: big.NewInt(params.FixedTransferGasPricePerGas), Gas: params.TxGas, To: &to, Value: new(big.Int)}),
		types.NewTx(&types.DynamicFeeTx{ChainID: config.ChainID, GasTipCap: big.NewInt(1), GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(1)), Gas: params.TxGas, To: &to, Value: new(big.Int)}),
	}
	txs := make(types.Transactions, 0, 5)
	for index, transaction := range unsigned {
		key, err := crypto.HexToECDSA(keys[index])
		if err != nil {
			t.Fatal(err)
		}
		signed, err := types.SignTx(transaction, signer, key)
		if err != nil {
			t.Fatal(err)
		}
		base.SetBalance(crypto.PubkeyToAddress(key.PublicKey), new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil))
		txs = append(txs, signed)
	}
	_, sidecar := signedPoolBlobTx(t, 0, false)
	blobKey, err := crypto.HexToECDSA("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	blobUnsigned := types.NewTx(&types.BlobTx{
		ChainID: config.ChainID, GasTipCap: big.NewInt(1), GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(1)),
		Gas: params.TxGas, To: to, Value: new(big.Int), BlobFeeCap: big.NewInt(2), BlobHashes: sidecar.BlobHashes(),
	})
	blobTx, err := types.SignTx(blobUnsigned, signer, blobKey)
	if err != nil {
		t.Fatal(err)
	}
	blobTx = toOsakaBlobSidecar(t, blobTx.WithBlobSidecar(sidecar))
	sidecar = blobTx.BlobSidecar()
	blobSender, err := types.Sender(signer, blobTx)
	if err != nil {
		t.Fatal(err)
	}
	base.SetBalance(blobSender, new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil))
	txs = append(txs, blobTx)

	authorityKey, err := crypto.HexToECDSA("5555555555555555555555555555555555555555555555555555555555555555")
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := types.SignSetCode(authorityKey, types.SetCodeAuthorization{ChainID: config.ChainID, Address: to})
	if err != nil {
		t.Fatal(err)
	}
	setCodeKey, err := crypto.HexToECDSA(keys[3])
	if err != nil {
		t.Fatal(err)
	}
	setCodeUnsigned := types.NewTx(&types.SetCodeTx{
		ChainID: config.ChainID, GasTipCap: big.NewInt(11), GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(1)),
		Gas: 100_000, To: to, Value: new(big.Int), AuthList: []types.SetCodeAuthorization{authorization},
	})
	setCodeTx, err := types.SignTx(setCodeUnsigned, signer, setCodeKey)
	if err != nil {
		t.Fatal(err)
	}
	base.SetBalance(crypto.PubkeyToAddress(setCodeKey.PublicKey), new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil))
	txs = append(txs, setCodeTx)

	header := &types.Header{
		ParentHash: common.HexToHash("0xa004"), Coinbase: common.HexToAddress("0x9000000000000000000000000000000000000009"),
		Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: 500_000, Time: 1,
		BaseFee: big.NewInt(params.FixedBaseFeePerGas), BlockType: types.SlowTx_Block, BlobGasUsed: blobTx.BlobGas(),
	}
	prepareEVMOnlyHistory(base, header)
	base.Finalise(true)
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}
	receipts, _, _, err := ExecuteEVMProposalTransactions(config, chain, header, txs, base, vm.Config{})
	if err != nil {
		t.Fatalf("mixed standard EVM proposal: %v", err)
	}
	if len(receipts) != 5 {
		t.Fatalf("receipt count = %d, want 5", len(receipts))
	}
	for index, wantType := range []uint8{types.LegacyTxType, types.AccessListTxType, types.DynamicFeeTxType, types.BlobTxType, types.SetCodeTxType} {
		if receipts[index].Type != wantType {
			t.Fatalf("receipt %d type = %#x, want %#x", index, receipts[index].Type, wantType)
		}
	}
	if got := txs[3].BlobSidecar(); got == nil || len(got.Blobs) != len(sidecar.Blobs) || got.Blobs[0][31] != sidecar.Blobs[0][31] {
		t.Fatal("proposal execution detached or mutated the authenticated blob sidecar")
	}
}
