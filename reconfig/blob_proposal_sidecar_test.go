package reconfig

import (
	"bytes"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	kzg "github.com/cypherium/cypher/crypto/kzg4844"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/trie"
)

func proposalBlobTestConfig(t *testing.T) *params.ChainConfig {
	t.Helper()
	native := params.SolanaScaleNativeParallelConfig()
	native.RequireNativeTransactions = false
	config := &params.ChainConfig{
		ChainID:        big.NewInt(99),
		FairHotstuff:   true,
		NativeParallel: native,
	}
	zero := uint64(0)
	config.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock:  big.NewInt(0),
		LondonBlock:  big.NewInt(0),
		ShanghaiTime: &zero,
		CancunTime:   &zero,
		BlobSchedule: &params.BlobScheduleConfig{
			Cancun: &params.BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477},
		},
	})
	t.Cleanup(func() { config.SetModernForkConfig(nil) })
	return config
}

func proposalValidBlobSidecar(t *testing.T) *types.BlobTxSidecar {
	t.Helper()
	var blob kzg.Blob
	blob[31] = 1
	commitment, err := kzg.BlobToCommitment(&blob)
	if err != nil {
		t.Fatalf("blob commitment: %v", err)
	}
	proof, err := kzg.ComputeBlobProof(&blob, commitment)
	if err != nil {
		t.Fatalf("blob proof: %v", err)
	}
	encodedBlob := make(types.Blob, len(blob))
	copy(encodedBlob, blob[:])
	var encodedCommitment types.KZGCommitment
	copy(encodedCommitment[:], commitment[:])
	var encodedProof types.KZGProof
	copy(encodedProof[:], proof[:])
	return &types.BlobTxSidecar{
		Blobs:       []types.Blob{encodedBlob},
		Commitments: []types.KZGCommitment{encodedCommitment},
		Proofs:      []types.KZGProof{encodedProof},
	}
}

func proposalValidOsakaBlobSidecar(t *testing.T) *types.BlobTxSidecar {
	t.Helper()
	sidecar := proposalValidBlobSidecar(t)
	var blob kzg.Blob
	copy(blob[:], sidecar.Blobs[0])
	proofs, err := kzg.ComputeCellProofs(&blob)
	if err != nil {
		t.Fatalf("cell proofs: %v", err)
	}
	sidecar.Version = types.BlobSidecarVersion1
	sidecar.Proofs = make([]types.KZGProof, len(proofs))
	for i := range proofs {
		sidecar.Proofs[i] = types.KZGProof(proofs[i])
	}
	return sidecar
}

func TestProposalManifestRequiresOsakaCellProofSidecar(t *testing.T) {
	config := proposalBlobTestConfig(t)
	zero := uint64(0)
	modern := config.ModernForkConfig()
	modern.PragueTime = &zero
	modern.OsakaTime = &zero
	modern.BlobSchedule.Osaka = &params.BlobConfig{Target: 6, Max: 9, BaseFeeUpdateFraction: 5007716}
	v0 := proposalValidBlobSidecar(t)
	manifest := &proposalDataManifest{
		Header:            &types.Header{Number: big.NewInt(1), Time: 0, BlobGasUsed: params.BlobTxBlobGasPerBlob},
		TransactionHashes: []common.Hash{{1}},
		BlobSidecars:      []*types.BlobTxSidecar{v0},
	}
	if err := validateProposalManifestBlobSidecars(config, manifest); !errors.Is(err, types.ErrBlobSidecarVersionMismatch) {
		t.Fatalf("proposal accepted Prague sidecar under Osaka rules: %v", err)
	}
	manifest.BlobSidecars[0] = proposalValidOsakaBlobSidecar(t)
	if err := validateProposalManifestBlobSidecars(config, manifest); err != nil {
		t.Fatalf("proposal rejected Osaka cell-proof sidecar: %v", err)
	}
}

func proposalSignedBlobTx(t *testing.T, config *params.ChainConfig, nonce, gas uint64, keyAddress common.Address, sidecar *types.BlobTxSidecar) *types.Transaction {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := types.NewTx(&types.BlobTx{
		ChainID:    config.ChainID,
		Nonce:      nonce,
		GasTipCap:  big.NewInt(1),
		GasFeeCap:  big.NewInt(2),
		Gas:        gas,
		To:         keyAddress,
		Value:      new(big.Int),
		BlobFeeCap: big.NewInt(2),
		BlobHashes: sidecar.BlobHashes(),
	})
	signed, err := types.SignTx(unsigned, types.NewCancunSigner(config.ChainID), key)
	if err != nil {
		t.Fatal(err)
	}
	attached := signed.WithBlobSidecar(sidecar)
	if err := attached.VerifyBlobSidecar(attached.BlobSidecar(), types.KZGBlobVerifier{}); err != nil {
		t.Fatalf("test BlobTx sidecar is not KZG-valid: %v", err)
	}
	return attached
}

func proposalBlobTestBlock(t *testing.T, config *params.ChainConfig, tx *types.Transaction, blockType uint8) *types.Block {
	t.Helper()
	header := &types.Header{
		ParentHash:  common.HexToHash("0x01"),
		Number:      big.NewInt(1),
		Difficulty:  big.NewInt(1),
		GasLimit:    30_000_000,
		BaseFee:     big.NewInt(1),
		BlobGasUsed: tx.BlobGas(),
		KeyHash:     common.HexToHash("0x5151"),
		BlockType:   blockType,
	}
	block := types.NewBlock(header, types.Transactions{tx}, nil, nil, new(trie.Trie))
	admission := &types.CommonTxAdmissionBatch{
		ChainID:     new(big.Int).Set(config.ChainID),
		GenesisHash: common.HexToHash("0x99"),
		Miner:       common.HexToAddress("0x42"),
		Timestamp:   1,
		TxHashes:    []common.Hash{tx.Hash()},
		Signature:   make([]byte, 65),
	}
	admission.TxRoot = types.DeriveCommonTxAdmissionTxRoot(admission.TxHashes)
	admission.AdmissionID = types.CommonTxAdmissionID(admission)
	reward := &types.CommonTxReward{
		TxHash: tx.Hash(), Approver: admission.Miner,
		ApproverReward: new(big.Int), Burn: new(big.Int),
	}
	block.AttachCommonTxData(
		[]*types.CommonTxAdmissionBatch{admission},
		[]types.CommonTxAdmissionRef{{}},
		[]*types.CommonTxReward{reward},
	)
	return block
}

func proposalBlobTestEnvelope(t *testing.T, config *params.ChainConfig, block *types.Block, manifest []byte) *proposalBodyMsg {
	t.Helper()
	encoded := block.EncodeToBytes()
	if len(encoded) == 0 {
		t.Fatal("blob proposal block did not encode")
	}
	ref, err := types.NewHotstuffProposalRefWithProof(
		config.ChainID.Uint64(), 7, common.HexToHash("0x07"), "leader", block, encoded, nil, common.Hash{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return &proposalBodyMsg{
		Type:            proposalBodyMsgManifest,
		ProposalID:      ref.ProposalID(),
		BodyHash:        ref.BodyHash,
		BodySize:        ref.BodySize,
		Number:          ref.Number,
		ViewNumber:      ref.ViewNumber,
		ViewID:          ref.ViewID,
		LeaderID:        ref.LeaderID,
		From:            "leader",
		ProposalKeyHash: ref.KeyHash,
		SenderKeyHash:   ref.KeyHash,
		Manifest:        manifest,
		AuthSig:         []byte{1},
	}
}

func newProposalBlobAssemblyService(config *params.ChainConfig, tx *types.Transaction) *Service {
	return &Service{
		chainConfig:          config,
		proposalBodies:       make(map[common.Hash]*proposalBodyMsg),
		proposalAssemblies:   make(map[common.Hash]*proposalAssemblyState),
		verifiedProposalByID: make(map[common.Hash]*core.VerifiedProposal),
		fhsCertifiedByID:     make(map[common.Hash]*fhsCertifiedProposal),
		resolveTxQUICTransaction: func(hash common.Hash) (*types.Transaction, error) {
			if hash == tx.Hash() {
				// Repair carries only the canonical execution envelope. The signed
				// manifest must restore the independently authenticated sidecar.
				return tx.WithBlobSidecar(nil), nil
			}
			return nil, nil
		},
	}
}

type proposalBlobPoolChain struct {
	head  *types.Block
	state *state.StateDB
}

func (chain *proposalBlobPoolChain) CurrentBlock() *types.Block { return chain.head }

func (chain *proposalBlobPoolChain) GetBlock(hash common.Hash, number uint64) *types.Block {
	if chain.head != nil && chain.head.Hash() == hash && chain.head.NumberU64() == number {
		return chain.head
	}
	return nil
}

func (chain *proposalBlobPoolChain) StateAt(common.Hash) (*state.StateDB, error) {
	return chain.state.Copy(), nil
}

func (chain *proposalBlobPoolChain) SubscribeChainHeadEvent(chan<- core.ChainHeadEvent) event.Subscription {
	return event.NewSubscription(func(quit <-chan struct{}) error {
		<-quit
		return nil
	})
}

func newProposalBlobTxPool(t *testing.T, config *params.ChainConfig, tx *types.Transaction) (*core.TxPool, *proposalBlobPoolChain, common.Address) {
	t.Helper()
	sender, err := types.Sender(types.NewCancunSigner(config.ChainID), tx)
	if err != nil {
		t.Fatal(err)
	}
	statedb, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	statedb.SetBalance(sender, new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil))
	root, err := statedb.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	statedb, err = state.New(root, statedb.Database(), nil)
	if err != nil {
		t.Fatal(err)
	}
	head := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(0), Root: root, GasLimit: 30_000_000, BaseFee: big.NewInt(1),
	})
	chain := &proposalBlobPoolChain{head: head, state: statedb}
	poolConfig := core.DefaultTxPoolConfig
	poolConfig.NoLocals = true
	poolConfig.Journal = ""
	poolConfig.PriceLimit = 1
	pool := core.NewTxPool(poolConfig, config, chain)
	t.Cleanup(pool.Stop)
	return pool, chain, sender
}

func TestProposalBlobSidecarManifestRoundTripAndRepair(t *testing.T) {
	config := proposalBlobTestConfig(t)
	sidecar := proposalValidBlobSidecar(t)
	tx := proposalSignedBlobTx(t, config, 0, 100_000, common.HexToAddress("0xbeef"), sidecar)
	block := proposalBlobTestBlock(t, config, tx, types.FastTx_Block)
	originalEncoded := block.EncodeToBytes()

	manifestBytes, err := encodeProposalDataManifestForConfig(config, block)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := decodeProposalDataManifestForConfig(config, manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.BlobSidecars) != 1 || !bytes.Equal(manifest.BlobSidecars[0].Blobs[0], sidecar.Blobs[0]) {
		t.Fatal("authenticated manifest lost the BlobTx sidecar")
	}
	manifest.BlobSidecars[0].Blobs[0][0] ^= 0xff
	if block.BlobSidecars()[0].Blobs[0][0] != sidecar.Blobs[0][0] {
		t.Fatal("proposal manifest aliased mutable block sidecar storage")
	}

	service := newProposalBlobAssemblyService(config, tx)
	body := proposalBlobTestEnvelope(t, config, block, manifestBytes)
	missing, err := service.storeProposalManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("locally resolved blob proposal still misses %v", missing)
	}
	complete := service.getProposalBody(body.ProposalID)
	if complete == nil || !bytes.Equal(complete.EncodedBlock, originalEncoded) {
		t.Fatal("blob proposal repair did not reconstruct the exact body commitment")
	}
	decoded := types.DecodeToBlock(complete.EncodedBlock)
	if decoded == nil || len(decoded.BlobSidecars()) != 1 || decoded.Transactions()[0].BlobSidecar() == nil {
		t.Fatal("validator reconstruction did not attach the authenticated blob sidecar")
	}
	returned := decoded.BlobSidecars()
	returned[0].Blobs[0][0] ^= 0xff
	if decoded.BlobSidecars()[0].Blobs[0][0] != sidecar.Blobs[0][0] {
		t.Fatal("decoded proposal exposed mutable blob sidecar storage")
	}
}

func TestProposalBlobSidecarManifestRejectsMissingAndCountMismatch(t *testing.T) {
	config := proposalBlobTestConfig(t)
	sidecar := proposalValidBlobSidecar(t)
	tx := proposalSignedBlobTx(t, config, 0, 100_000, common.HexToAddress("0xbeef"), sidecar)
	block := proposalBlobTestBlock(t, config, tx, types.FastTx_Block)
	manifest, err := proposalDataManifestForBlock(block)
	if err != nil {
		t.Fatal(err)
	}

	missing := *manifest
	missing.BlobSidecars = nil
	missingBytes, err := rlp.EncodeToBytes(&missing)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeProposalDataManifestForConfig(config, missingBytes); err == nil || !strings.Contains(err.Error(), "blob gas mismatch") {
		t.Fatalf("manifest without its blob sidecar was not rejected: %v", err)
	}
	if _, err := reconstructProposalBlock(&missing, types.Transactions{tx.WithBlobSidecar(nil)}); !errors.Is(err, types.ErrBlockBlobSidecarCountMismatch) {
		t.Fatalf("reconstruction missing-sidecar error = %v, want %v", err, types.ErrBlockBlobSidecarCountMismatch)
	}

	extra := *manifest
	extra.BlobSidecars = append(block.BlobSidecars(), sidecar.Copy())
	extraBytes, err := rlp.EncodeToBytes(&extra)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeProposalDataManifestForConfig(config, extraBytes); err == nil || !strings.Contains(err.Error(), "sidecar count") {
		t.Fatalf("manifest with an extra blob sidecar was not rejected: %v", err)
	}
	if _, err := reconstructProposalBlock(&extra, types.Transactions{tx.WithBlobSidecar(nil)}); !errors.Is(err, types.ErrBlockBlobSidecarCountMismatch) {
		t.Fatalf("reconstruction extra-sidecar error = %v, want %v", err, types.ErrBlockBlobSidecarCountMismatch)
	}
}

func TestProposalBlobSidecarTamperingFailsBodyCommitment(t *testing.T) {
	config := proposalBlobTestConfig(t)
	sidecar := proposalValidBlobSidecar(t)
	tx := proposalSignedBlobTx(t, config, 0, 100_000, common.HexToAddress("0xbeef"), sidecar)
	block := proposalBlobTestBlock(t, config, tx, types.FastTx_Block)
	manifest, err := proposalDataManifestForBlock(block)
	if err != nil {
		t.Fatal(err)
	}
	manifest.BlobSidecars[0].Blobs[0][0] ^= 0xff
	tamperedManifest, err := rlp.EncodeToBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}

	service := newProposalBlobAssemblyService(config, tx)
	body := proposalBlobTestEnvelope(t, config, block, tamperedManifest)
	if _, err := service.storeProposalManifest(body); err == nil || !strings.Contains(err.Error(), "body hash mismatch") {
		t.Fatalf("tampered blob bytes did not fail the signed body commitment: %v", err)
	}
}

type proposalBlobSidecarMap map[common.Hash]*types.BlobTxSidecar

func (sidecars proposalBlobSidecarMap) GetBlobSidecar(hash common.Hash) *types.BlobTxSidecar {
	return sidecars[hash].Copy()
}

func TestProposalSelectionRetainsVerifiedBlobSidecarsInFastAndSlowLanes(t *testing.T) {
	config := proposalBlobTestConfig(t)
	sidecar := proposalValidBlobSidecar(t)
	tests := []struct {
		name      string
		gas       uint64
		blockType uint8
		lane      core.TxLane
	}{
		{name: "fast", gas: 100_000, blockType: types.FastTx_Block, lane: core.TxLaneFast},
		{name: "slow", gas: 400_000, blockType: types.SlowTx_Block, lane: core.TxLaneSlow},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			to := common.BigToAddress(big.NewInt(int64(index + 1)))
			tx := proposalSignedBlobTx(t, config, 0, test.gas, to, sidecar)
			if got := core.ClassifyTxLane(tx); got != test.lane {
				t.Fatalf("BlobTx lane = %d, want %d", got, test.lane)
			}
			pool, chain, sender := newProposalBlobTxPool(t, config, tx)
			bundle, err := types.NewBlobTxWithSidecar(tx.WithBlobSidecar(nil), tx.BlobSidecar())
			if err != nil {
				t.Fatal(err)
			}
			if err := pool.AddRemoteBlobTxSync(bundle, types.KZGBlobVerifier{}); err != nil {
				t.Fatalf("actual TxPool rejected valid BlobTx sidecar: %v", err)
			}
			pending, err := pool.PendingByLaneAndClassesLimited(test.lane, 10, 10, 0)
			if err != nil {
				t.Fatal(err)
			}
			selected := attachProposalBlobSidecars(pool, pending)
			got := selected[sender]
			if len(got) != 1 || got[0].BlobSidecar() == nil {
				t.Fatal("proposal selection did not attach the TxPool-verified sidecar")
			}

			st := chain.state.Copy()
			header := &types.Header{Number: big.NewInt(1), GasLimit: 30_000_000, BaseFee: big.NewInt(1)}
			if err := precheckTxForProposal(config, st, header, got[0], sender); err != nil {
				t.Fatalf("proposal precheck rejected a valid attached BlobTx: %v", err)
			}

			block := proposalBlobTestBlock(t, config, got[0], test.blockType)
			if len(block.BlobSidecars()) != 1 || block.Transactions()[0].BlobSidecar() == nil {
				t.Fatalf("%s proposal construction lost the BlobTx sidecar", test.name)
			}
			manifest, err := proposalDataManifestForBlock(block)
			if err != nil {
				t.Fatal(err)
			}
			reconstructed, err := reconstructProposalBlock(manifest, types.Transactions{got[0].WithBlobSidecar(nil)})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(reconstructed.EncodeToBytes(), block.EncodeToBytes()) {
				t.Fatalf("%s proposal did not retain the exact blob sidecar body", test.name)
			}
		})
	}
}

func TestProposalSelectionStopsAtBlobTxWithoutVerifiedSidecar(t *testing.T) {
	config := proposalBlobTestConfig(t)
	sidecar := proposalValidBlobSidecar(t)
	addr := common.HexToAddress("0xbeef")
	blob := proposalSignedBlobTx(t, config, 0, 100_000, addr, sidecar).WithBlobSidecar(nil)
	later := types.NewTransaction(1, addr, new(big.Int), params.TxGas, big.NewInt(2), nil)
	selected := attachProposalBlobSidecars(proposalBlobSidecarMap{}, AddressTxes{addr: {blob, later}})
	if len(selected[addr]) != 0 {
		t.Fatal("proposal selected a BlobTx without a verified TxPool sidecar or leaked a later nonce")
	}
}
