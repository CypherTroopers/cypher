package reconfig

import (
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

func cancunProposalTestConfig() *params.ChainConfig {
	cancunTime, shanghaiTime := uint64(0), uint64(0)
	cfg := &params.ChainConfig{ChainID: big.NewInt(12367)}
	cfg.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock:  big.NewInt(0),
		LondonBlock:  big.NewInt(0),
		ShanghaiTime: &shanghaiTime,
		CancunTime:   &cancunTime,
		BlobSchedule: &params.BlobScheduleConfig{
			Cancun: &params.BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477},
		},
	})
	return cfg
}

func TestDeriveCancunHeaderFieldsFromParent(t *testing.T) {
	cfg := cancunProposalTestConfig()
	blobCfg := cfg.ActiveBlobConfig(1)
	parent := &types.Header{
		Number:        big.NewInt(1),
		Time:          0,
		ExcessBlobGas: params.TargetBlobGasPerBlock(blobCfg),
		BlobGasUsed:   params.BlobTxBlobGasPerBlob,
	}
	header := &types.Header{Number: big.NewInt(2), Time: 1, BlobGasUsed: 99, ExcessBlobGas: 99}

	deriveCancunHeaderFields(cfg, parent, header)

	if header.BlobGasUsed != 0 {
		t.Fatalf("new proposal blobGasUsed = %d, want 0 before body selection", header.BlobGasUsed)
	}
	wantExcess := params.CalcExcessBlobGas(parent.ExcessBlobGas, parent.BlobGasUsed, blobCfg)
	if header.ExcessBlobGas != wantExcess {
		t.Fatalf("new proposal excessBlobGas = %d, want %d", header.ExcessBlobGas, wantExcess)
	}
}

func TestCanIncludeBlobGasHonorsBlockLimit(t *testing.T) {
	cfg := cancunProposalTestConfig()
	header := &types.Header{Number: big.NewInt(1), Time: 0}
	maxBlobGas := params.MaxBlobGasPerBlock(cfg.ActiveBlobConfig(header.Time))
	tx := types.NewTx(&types.BlobTx{
		Gas:        21_000,
		BlobFeeCap: big.NewInt(1),
		BlobHashes: []common.Hash{{types.BlobCommitmentVersionKZG}},
	})

	header.BlobGasUsed = maxBlobGas - params.BlobTxBlobGasPerBlob
	if !canIncludeBlobGas(cfg, header, tx) {
		t.Fatal("expected one final blob to fit")
	}
	header.BlobGasUsed = maxBlobGas
	if canIncludeBlobGas(cfg, header, tx) {
		t.Fatal("expected blob transaction above block limit to be rejected")
	}
}

func TestProposalPrecheckRejectsBlobTxWithoutDA(t *testing.T) {
	zero := uint64(0)
	config := &params.ChainConfig{ChainID: big.NewInt(1)}
	config.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock:  big.NewInt(0),
		LondonBlock:  big.NewInt(0),
		CancunTime:   &zero,
		BlobSchedule: &params.BlobScheduleConfig{Cancun: &params.BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477}},
	})
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	from := common.HexToAddress("0x100")
	to := common.HexToAddress("0x200")
	st.SetBalance(from, new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether)))
	tx := types.NewTx(&types.BlobTx{
		ChainID:    big.NewInt(1),
		GasTipCap:  big.NewInt(1),
		GasFeeCap:  big.NewInt(params.FixedBaseFeePerGas + 1),
		Gas:        params.TxGas,
		To:         to,
		Value:      new(big.Int),
		BlobFeeCap: big.NewInt(1),
		BlobHashes: []common.Hash{{types.BlobCommitmentVersionKZG}},
		V:          new(big.Int),
		R:          big.NewInt(1),
		S:          big.NewInt(1),
	})
	header := &types.Header{Number: big.NewInt(1), Time: 0, GasLimit: 30_000_000, BaseFee: big.NewInt(params.FixedBaseFeePerGas)}
	if err := precheckTxForProposal(config, st, header, tx, from); !errors.Is(err, core.ErrBlobDAUnavailable) {
		t.Fatalf("error = %v, want %v", err, core.ErrBlobDAUnavailable)
	}
}

func TestOsakaProposalReservesBlockEncodingHeadroom(t *testing.T) {
	zero := uint64(0)
	cfg := &params.ChainConfig{}
	cfg.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0), OsakaTime: &zero})
	header := &types.Header{Number: big.NewInt(1), Time: 0}
	tx := types.NewTransaction(0, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(1), nil)
	env := &work{config: cfg, header: header, size: common.StorageSize(params.MaxBlockSize - uint64(osakaBlockSizeBuffer) - uint64(osakaPerTxBodySizeBuffer) - uint64(tx.Size()))}
	if env.txFitsBlockSize(tx) {
		t.Fatal("transaction at the reserved Osaka size boundary was accepted")
	}
	env.size--
	if !env.txFitsBlockSize(tx) {
		t.Fatal("transaction below the reserved Osaka size boundary was rejected")
	}
}

func TestOsakaProposalSizeBudgetAllowsConsensusMaximumNativeTransfers(t *testing.T) {
	zero := uint64(0)
	cfg := &params.ChainConfig{ChainID: big.NewInt(10_101_919)}
	cfg.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0), OsakaTime: &zero})
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), Time: 0}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := types.SignTx(
		types.NewTransaction(0, common.Address{1}, new(big.Int), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil),
		types.LatestSignerForChainID(cfg.ChainID),
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	env := &work{config: cfg, header: header, size: header.Size()}
	for index := 0; index < params.MaxTxCountPerBlock; index++ {
		if !env.txFitsBlockSize(tx) {
			t.Fatalf("signed native transfer %d/%d rejected by proposer size budget (selected=%d tx=%d perTxBuffer=%d blockBuffer=%d)", index+1, params.MaxTxCountPerBlock, uint64(env.size), uint64(tx.Size()), uint64(osakaPerTxBodySizeBuffer), uint64(osakaBlockSizeBuffer))
		}
		env.size += tx.Size() + osakaPerTxBodySizeBuffer
	}
}

func TestOsakaPerTransactionBufferCoversCanonicalCommonSidecars(t *testing.T) {
	approver := common.Address{1}
	txHashes := make([]common.Hash, types.MaxCommonTxAdmissionBatchItems)
	refs := make([]types.CommonTxAdmissionRef, len(txHashes))
	for index := range txHashes {
		txHashes[index] = common.BigToHash(big.NewInt(int64(index + 1)))
		refs[index] = types.CommonTxAdmissionRef{Batch: 0, Item: uint16(index)}
	}
	admission := &types.CommonTxAdmissionBatch{
		ChainID:        big.NewInt(10_101_919),
		GenesisHash:    common.Hash{2},
		Miner:          approver,
		KeyBlockNumber: math.MaxUint64,
		Timestamp:      math.MaxUint64,
		TxHashes:       txHashes,
		Signature:      make([]byte, 65),
	}
	admission.TxRoot = types.DeriveCommonTxAdmissionTxRoot(admission.TxHashes)
	admission.AdmissionID = types.CommonTxAdmissionID(admission)
	// A transaction gas price is at most 256 bits and the FHS declared-gas
	// envelope is below 2^32. Use full 288-bit fee components to bound the RLP
	// generated by the local deterministic reward calculation.
	maxFeeComponent := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 288), big.NewInt(1))
	rewards := make([]*types.CommonTxReward, len(txHashes))
	for index, txHash := range txHashes {
		rewards[index] = &types.CommonTxReward{
			TxHash:         txHash,
			Approver:       approver,
			ApproverReward: new(big.Int).Set(maxFeeComponent),
			Burn:           new(big.Int).Set(maxFeeComponent),
		}
	}
	encodedAdmission, err := rlp.EncodeToBytes([]interface{}{[]*types.CommonTxAdmissionBatch{admission}, refs})
	if err != nil {
		t.Fatal(err)
	}
	encodedReward, err := rlp.EncodeToBytes(rewards)
	if err != nil {
		t.Fatal(err)
	}
	encodedPerTx := (len(encodedAdmission) + len(encodedReward) + len(txHashes) - 1) / len(txHashes)
	if encodedPerTx > int(osakaPerTxBodySizeBuffer) {
		t.Fatalf("canonical admission/reward batch sidecars use %d amortized bytes per tx, exceed proposal buffer %d", encodedPerTx, uint64(osakaPerTxBodySizeBuffer))
	}
}
