package reconfig

import (
	"bytes"
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
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

func TestOsakaProposalFinalizationCanonicalizesPaddedTargetQC(t *testing.T) {
	f := newConvergenceFixture(t)
	target := f.proposal(t, nil, 10, 'a')
	first := f.proposal(t, target, 12, 'b')
	second := f.proposal(t, first, 14, 'c')
	tip := f.proposal(t, second, 15, 'd')
	s := f.replicas[0]
	canonicalSignature := append([]byte(nil), target.qc.Sign...)
	targetID, err := hotstuff.SignedStateID(target.qc)
	if err != nil {
		t.Fatal(err)
	}
	target.qc.Sign = append(target.qc.Sign, make([]byte, 1024)...)
	paddedSignature := append([]byte(nil), target.qc.Sign...)
	if !hotstuff.VerifyFHSSignatureWithContext(target.qc.Sign, target.qc.Mask, target.qc.State, f.public,
		hotstuff.CalcThreshold(len(f.public)), s.ChainID(), hotstuff.MsgVotePrepare, target.qc.ViewID, target.qc.LeaderID) {
		t.Fatal("valid target QC with trailing signature bytes was rejected")
	}
	// Accepted descendant QC representations can fill the separately bounded
	// proof envelope. The target signature is outside that envelope, so storing
	// its padding would exceed the finalized header reserved during selection.
	proof := &core.FHSCommitProof{QCs: []*hotstuff.SignedState{first.qc, second.qc, tip.qc}}
	for _, qc := range proof.QCs {
		qc.Sign = append(qc.Sign, make([]byte, 333333)...)
	}
	encodedProof, err := core.EncodeFHSCommitProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	padding := types.MaxFHSFinalityProofSize - len(encodedProof) - 16
	if padding < 0 {
		t.Fatal("fixture already exceeds the finality proof envelope")
	}
	tip.qc.Sign = append(tip.qc.Sign, make([]byte, padding)...)
	encodedProof, err = core.EncodeFHSCommitProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(encodedProof) != types.MaxFHSFinalityProofSize-16 {
		t.Fatalf("proof bytes = %d, want %d", len(encodedProof), types.MaxFHSFinalityProofSize-16)
	}
	size, err := newProposalBodySize(target.verified.Block.Header(), s.chainConfig, nil, len(target.qc.LeaderID))
	if err != nil {
		t.Fatal(err)
	}
	limit := size.encodedSize(true)
	zero := uint64(0)
	s.chainConfig.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0), OsakaTime: &zero})
	s.chainConfig.NativeParallel = params.SolanaScaleNativeParallelConfig()
	s.chainConfig.NativeParallel.MaxBlockBytes = limit
	for _, invalidSignature := range [][]byte{nil, {1}} {
		invalidQC := hotstuff.CloneSignedState(target.qc)
		invalidQC.Sign = invalidSignature
		if err := s.txService.decideFHSVerifiedProposal(target.ref, target.verified, invalidQC, proof); err == nil {
			t.Fatal("invalid target signature reached canonical commit")
		}
	}
	if err := s.txService.decideFHSVerifiedProposal(target.ref, target.verified, target.qc, proof); err != nil {
		t.Fatalf("finalize proposal within its reserved size %d: %v", limit, err)
	}
	committed := s.bc.CurrentBlock()
	if committed.Hash() != target.ref.BlockHash || !bytes.Equal(committed.SignInfo().Signature, canonicalSignature) {
		t.Fatal("committed header did not preserve the proposal with a canonical target signature")
	}
	if uint64(len(committed.EncodeToBytes())) > limit {
		t.Fatal("canonical target signature exceeded the finalized proposal boundary")
	}
	if !bytes.Equal(target.qc.Sign, paddedSignature) || !bytes.Equal(committed.FHSFinalityProof(), encodedProof) {
		t.Fatal("header normalization changed the accepted QC or descendant proof")
	}
	if err := s.bc.VerifyFHSCommitProof(committed, proof); err != nil {
		t.Fatalf("normalized target signature invalidated the finality proof: %v", err)
	}
	_, reconstructed, err := s.bc.ReconstructFHSQC(committed)
	if err != nil {
		t.Fatal(err)
	}
	reconstructedID, err := hotstuff.SignedStateID(reconstructed)
	if err != nil || reconstructedID != targetID {
		t.Fatal("header normalization changed the semantic QC identity")
	}
	stored := s.bc.GetBlock(committed.Hash(), committed.NumberU64())
	if stored == nil || !bytes.Equal(stored.SignInfo().Signature, canonicalSignature) {
		t.Fatal("canonical target signature was not persisted")
	}
}

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

func TestProposalPrecheckRejectsBlobTxWithoutSidecar(t *testing.T) {
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
	if err := precheckTxForProposal(config, st, header, tx, from); !errors.Is(err, types.ErrBlobSidecarMissing) {
		t.Fatalf("error = %v, want %v", err, types.ErrBlobSidecarMissing)
	}
}

func TestOsakaProposalReservesBlockEncodingHeadroom(t *testing.T) {
	zero := uint64(0)
	cfg := &params.ChainConfig{FairHotstuff: true, NativeParallel: params.SolanaScaleNativeParallelConfig()}
	cfg.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0), OsakaTime: &zero})
	header := &types.Header{Number: big.NewInt(1), Time: 0}
	tx := types.NewTransaction(0, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(1), nil)
	env := &work{config: cfg, header: header}
	if err := env.ensureProposalBodySize(); err != nil {
		t.Fatal(err)
	}
	addition, ok := env.bodySize.nextTransaction(tx, tx.Gas())
	if !ok {
		t.Fatal("failed to measure candidate")
	}
	cfg.NativeParallel.MaxBlockBytes = addition.next.encodedSize(true)
	if !env.txFitsBlockSize(tx) {
		t.Fatal("transaction exactly at the finalized Osaka size boundary was rejected")
	}
	cfg.NativeParallel.MaxBlockBytes--
	if env.txFitsBlockSize(tx) {
		t.Fatal("transaction above the finalized Osaka size boundary was accepted")
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
			t.Fatalf("signed native transfer %d/%d rejected by proposer size budget (selected=%d tx=%d)", index+1, params.MaxTxCountPerBlock, uint64(env.size), uint64(tx.Size()))
		}
		addition, _ := env.bodySize.nextTransaction(tx, tx.Gas())
		env.bodySize.install(addition)
		env.size = common.StorageSize(env.bodySize.encodedSize(false))
	}
}

func TestOsakaProposalCountsCanonicalCommonSidecarLists(t *testing.T) {
	approver := common.Address{1}
	txHashes := make([]common.Hash, types.MaxCommonTxAdmissionBatchItems)
	refs := make([]types.CommonTxAdmissionRef, len(txHashes))
	for index := range txHashes {
		txHashes[index] = common.BigToHash(big.NewInt(int64(index + 1)))
		refs[index] = types.CommonTxAdmissionRef{Batch: 0, Item: uint16(index)}
	}
	admission := &types.CommonTxAdmissionBatch{
		Version:         types.CommonRPCVersionV2,
		RewardRecipient: common.HexToAddress("0x43"),
		ChainID:         big.NewInt(10_101_919),
		GenesisHash:     common.Hash{2},
		Miner:           approver,
		KeyBlockNumber:  math.MaxUint64,
		Timestamp:       math.MaxUint64,
		TxHashes:        txHashes,
		Signature:       make([]byte, 65),
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
			Version:         types.CommonRPCVersionV2,
			RewardRecipient: common.HexToAddress("0x43"),
			TxHash:          txHash,
			Approver:        approver,
			ApproverReward:  new(big.Int).Set(maxFeeComponent),
			Burn:            new(big.Int).Set(maxFeeComponent),
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
	batchBytes, err := proposalRLPSize(admission)
	if err != nil {
		t.Fatal(err)
	}
	var refBytes, rewardBytes uint64
	for index := range refs {
		refBytes += proposalListSize(proposalUintSize(uint64(refs[index].Batch)) + proposalUintSize(uint64(refs[index].Item)))
		encoded, err := proposalRLPSize(rewards[index])
		if err != nil {
			t.Fatal(err)
		}
		rewardBytes += encoded
	}
	if got := proposalListSize(proposalListSize(batchBytes) + proposalListSize(refBytes)); got != uint64(len(encodedAdmission)) {
		t.Fatalf("admission list bytes = %d, canonical bytes = %d", got, len(encodedAdmission))
	}
	if got := proposalListSize(rewardBytes); got != uint64(len(encodedReward)) {
		t.Fatalf("reward list bytes = %d, canonical bytes = %d", got, len(encodedReward))
	}
}
