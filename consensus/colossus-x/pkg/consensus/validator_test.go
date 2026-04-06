package consensus

import (
	"sync/atomic"
	"testing"
	"time"

	cx "colossusx/colossusx"
	"colossusx/pkg/chain"
	"colossusx/pkg/types"
)

func testConfig(t *testing.T) (types.ChainConfig, types.GenesisConfig) {
	t.Helper()
	spec := cx.ColossusXSpecWithGrowth(1024*1024, 256*1024)
	target, err := cx.ParseTargetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatal(err)
	}
	chainCfg := types.ChainConfig{NetworkID: "test", Spec: spec}
	genesis := types.GenesisConfig{ChainID: "test", Message: "test", Timestamp: time.Now().Unix() - 1, Bits: target, Spec: spec}
	return chainCfg, genesis
}

type namedAlloc struct {
	name      string
	freeCount *int32
	buf       []byte
}

func (a *namedAlloc) Bytes() []byte { return a.buf }
func (a *namedAlloc) Name() string  { return a.name }
func (a *namedAlloc) Free() error {
	if a.freeCount != nil {
		atomic.AddInt32(a.freeCount, 1)
	}
	a.buf = nil
	return nil
}

type namedAllocator struct {
	name      string
	freeCount *int32
}

func (a namedAllocator) Alloc(size uint64) (cx.Allocation, error) {
	return &namedAlloc{name: a.name, freeCount: a.freeCount, buf: make([]byte, size)}, nil
}
func (a namedAllocator) Name() string { return a.name }

type capabilityAllocator struct {
	namedAllocator
	reuse bool
}

func (a capabilityAllocator) ValidationCanReuseDAG() bool { return a.reuse }

func testBlockHeader(chainCfg types.ChainConfig, genesis types.Block) types.BlockHeader {
	return types.BlockHeader{
		Version:          1,
		AlgorithmVersion: chainCfg.Spec.AlgorithmVersion,
		Height:           1,
		ParentHash:       genesis.BlockHash(),
		Timestamp:        genesis.Header.Timestamp + 1,
		Target:           genesis.Header.Target,
		EpochSeed:        types.EpochSeedForHeight(chainCfg.Spec, 1),
		DAGSizeBytes:     chainCfg.Spec.DAGSizeForHeight(1),
	}
}

func TestValidatorInsertBlock(t *testing.T) {
	chainCfg, genesisCfg := testConfig(t)
	v, err := NewValidator(chainCfg, CPUBackend{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	store := chain.NewMemoryStore()
	genesis, _, err := v.SealBlock(types.NewGenesisBlock(genesisCfg), 10)
	if err != nil {
		t.Fatal(err)
	}
	work, becameTip, err := v.InsertBlock(store, genesis)
	if err != nil {
		t.Fatal(err)
	}
	if !becameTip || work.Sign() <= 0 {
		t.Fatalf("expected genesis to become tip")
	}
	next := types.Block{Header: testBlockHeader(chainCfg, genesis)}
	sealed, _, err := v.SealBlock(next, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, becameTip, err := v.InsertBlock(store, sealed); err != nil {
		t.Fatal(err)
	} else if !becameTip {
		t.Fatalf("expected child to become tip")
	}
}

func TestValidationAndMiningReuseSharedDAGForHostVisibleAllocator(t *testing.T) {
	chainCfg, genesisCfg := testConfig(t)
	v, err := NewValidator(chainCfg, CPUBackend{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	genesis := types.NewGenesisBlock(genesisCfg)
	header := testBlockHeader(chainCfg, genesis)

	miningDAG, err := v.sharedMiningDAGForHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	validationDAG, err := v.validationDAGForHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if miningDAG != validationDAG {
		t.Fatalf("expected validation to reuse mining DAG")
	}
	if !v.DAGReuseEnabled() {
		t.Fatalf("expected DAG reuse to be enabled for default host-visible allocator")
	}
	if got := v.SharedCacheSize(); got != 1 {
		t.Fatalf("expected 1 shared DAG, got %d", got)
	}
	if got := v.ValidationCacheSize(); got != 0 {
		t.Fatalf("expected 0 fallback validation DAGs, got %d", got)
	}
}

func TestValidationReusesSharedDAGWhenAllocatorCapabilityAllowsIt(t *testing.T) {
	chainCfg, genesisCfg := testConfig(t)
	v, err := NewValidator(chainCfg, CPUBackend{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	v.SetMiningBackend(CPUBackend{}, capabilityAllocator{namedAllocator: namedAllocator{name: "cuda-managed"}, reuse: true})
	genesis := types.NewGenesisBlock(genesisCfg)
	header := testBlockHeader(chainCfg, genesis)

	miningDAG, err := v.sharedMiningDAGForHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	validationDAG, err := v.validationDAGForHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if miningDAG != validationDAG {
		t.Fatalf("expected validation to reuse mining DAG when allocator capability allows it")
	}
	if !v.DAGReuseEnabled() {
		t.Fatalf("expected DAG reuse to be enabled for capability-backed cuda-managed allocator")
	}
	if got := v.SharedCacheSize(); got != 1 {
		t.Fatalf("expected 1 shared DAG, got %d", got)
	}
	if got := v.ValidationCacheSize(); got != 0 {
		t.Fatalf("expected 0 fallback validation DAGs, got %d", got)
	}
}

func TestValidationFallsBackWhenAllocatorCapabilityDisallowsIt(t *testing.T) {
	chainCfg, genesisCfg := testConfig(t)
	v, err := NewValidator(chainCfg, CPUBackend{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	v.SetMiningBackend(CPUBackend{}, capabilityAllocator{namedAllocator: namedAllocator{name: "cuda-managed"}, reuse: false})
	genesis := types.NewGenesisBlock(genesisCfg)
	header := testBlockHeader(chainCfg, genesis)

	miningDAG, err := v.sharedMiningDAGForHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	validationDAG, err := v.validationDAGForHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if miningDAG == validationDAG {
		t.Fatalf("expected validation fallback DAG when allocator capability rejects reuse")
	}
	if v.DAGReuseEnabled() {
		t.Fatalf("expected DAG reuse to be disabled when capability rejects reuse")
	}
	if got := v.SharedCacheSize(); got != 1 {
		t.Fatalf("expected 1 shared DAG, got %d", got)
	}
	if got := v.ValidationCacheSize(); got != 1 {
		t.Fatalf("expected 1 fallback validation DAG, got %d", got)
	}
}

func TestValidationFallsBackWhenMiningAllocatorIsNotKnownReusable(t *testing.T) {
	chainCfg, genesisCfg := testConfig(t)
	v, err := NewValidator(chainCfg, CPUBackend{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	v.SetMiningBackend(CPUBackend{}, namedAllocator{name: "cuda-managed"})
	genesis := types.NewGenesisBlock(genesisCfg)
	header := testBlockHeader(chainCfg, genesis)

	miningDAG, err := v.sharedMiningDAGForHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	validationDAG, err := v.validationDAGForHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if miningDAG == validationDAG {
		t.Fatalf("expected validation fallback DAG when mining allocator is not safely reusable")
	}
	if v.DAGReuseEnabled() {
		t.Fatalf("expected DAG reuse to be disabled for unknown cuda-managed allocator")
	}
	if got := v.SharedCacheSize(); got != 1 {
		t.Fatalf("expected 1 shared DAG, got %d", got)
	}
	if got := v.ValidationCacheSize(); got != 1 {
		t.Fatalf("expected 1 fallback validation DAG, got %d", got)
	}
}

func TestSealBlockAndValidateBlockShareCommonCaseDAG(t *testing.T) {
	chainCfg, genesisCfg := testConfig(t)
	v, err := NewValidator(chainCfg, CPUBackend{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	store := chain.NewMemoryStore()

	genesis, _, err := v.SealBlock(types.NewGenesisBlock(genesisCfg), 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.InsertBlock(store, genesis); err != nil {
		t.Fatal(err)
	}

	next := types.Block{Header: testBlockHeader(chainCfg, genesis)}
	sealed, _, err := v.SealBlock(next, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.ValidateBlock(store, sealed); err != nil {
		t.Fatal(err)
	}
	if got := v.SharedCacheSize(); got != 1 {
		t.Fatalf("expected 1 shared DAG for the common-case shared epoch, got %d", got)
	}
	if got := v.ValidationCacheSize(); got != 0 {
		t.Fatalf("expected no fallback validation DAGs, got %d", got)
	}
}

func colossusxTestConfig(t *testing.T) (types.ChainConfig, types.GenesisConfig) {
	t.Helper()
	spec := cx.ColossusXSpec()
	spec.InitialDAGSizeBytes = 256 * 16
	spec.DAGSizeBytes = spec.InitialDAGSizeBytes
	spec.DAGGrowthBytesPerEpoch = 256
	target, err := cx.ParseTargetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatal(err)
	}
	chainCfg := types.ChainConfig{NetworkID: "colossusx-test", Spec: spec}
	genesis := types.GenesisConfig{ChainID: "colossusx-test", Message: "colossusx", Timestamp: time.Now().Unix() - 1, Bits: target, Spec: spec}
	return chainCfg, genesis
}

func TestColossusXSealBlockUsesCompactSolutionAndValidates(t *testing.T) {
	chainCfg, genesisCfg := colossusxTestConfig(t)
	v, err := NewValidator(chainCfg, CPUBackend{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	store := chain.NewMemoryStore()

	genesis, _, err := v.SealBlock(types.NewGenesisBlock(genesisCfg), 2000)
	if err != nil {
		t.Fatal(err)
	}
	if genesis.ColossusXSolutionCompact == nil {
		t.Fatal("expected compact colossusx solution to be attached")
	}
	if genesis.ColossusXSolution != nil {
		t.Fatal("expected full colossusx solution to be omitted when compact is present")
	}
	if err := v.ValidateBlock(store, genesis); err != nil {
		t.Fatalf("validate colossusx genesis: %v", err)
	}
}

func TestColossusXEpochGraceWindowAcceptsPreviousEpochSeedAndSize(t *testing.T) {
	chainCfg, _ := colossusxTestConfig(t)
	v, err := NewValidator(chainCfg, CPUBackend{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	h := types.BlockHeader{
		AlgorithmVersion: chainCfg.Spec.AlgorithmVersion,
		Height:           chainCfg.Spec.EpochBlocks + 1, // grace window
		EpochSeed:        types.EpochSeedForHeight(chainCfg.Spec, 0),
		DAGSizeBytes:     chainCfg.Spec.DAGSizeForHeight(0),
	}
	// target isn't checked by validateEpochParameters, so call it directly.
	if err := v.validateEpochParameters(h); err != nil {
		t.Fatalf("expected previous-epoch params to be accepted in grace window: %v", err)
	}
	h.Height = chainCfg.Spec.EpochBlocks + cx.ColossusXEpochGraceBlocks + 1
	if err := v.validateEpochParameters(h); err == nil {
		t.Fatal("expected previous-epoch params to be rejected outside grace window")
	}
}

func TestDAGMerkleRootStreamingMatchesMaterializedRoot(t *testing.T) {
	chainCfg, genesisCfg := colossusxTestConfig(t)
	v, err := NewValidator(chainCfg, CPUBackend{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	genesis := types.NewGenesisBlock(genesisCfg)
	header := testBlockHeader(chainCfg, genesis)
	dag, err := v.sharedMiningDAGForHeader(header)
	if err != nil {
		t.Fatal(err)
	}

	streaming := dagMerkleRootStreaming(dag)
	materialized := cx.BuildMerkleRoot(dagMerkleLeaves(dag))
	if streaming != materialized {
		t.Fatalf("streaming merkle root mismatch")
	}
}

func TestColossusXValidateBlockRejectsTamperedDAGMerkleRoot(t *testing.T) {
	chainCfg, genesisCfg := colossusxTestConfig(t)
	v, err := NewValidator(chainCfg, CPUBackend{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	store := chain.NewMemoryStore()

	genesis, _, err := v.SealBlock(types.NewGenesisBlock(genesisCfg), 2000)
	if err != nil {
		t.Fatal(err)
	}
	genesis.Header.DAGMerkleRoot[0] ^= 0x01
	if err := v.ValidateBlock(store, genesis); err == nil {
		t.Fatal("expected validation error when DAG merkle root is tampered")
	}
}

func TestColossusXValidateHeaderRejectsTamperedDAGMerkleRoot(t *testing.T) {
	chainCfg, genesisCfg := colossusxTestConfig(t)
	v, err := NewValidator(chainCfg, CPUBackend{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	store := chain.NewMemoryStore()

	genesis, _, err := v.SealBlock(types.NewGenesisBlock(genesisCfg), 2000)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.ValidateHeader(store, genesis.Header); err != nil {
		t.Fatalf("expected sealed header to validate: %v", err)
	}
	genesis.Header.DAGMerkleRoot[0] ^= 0x01
	if err := v.ValidateHeader(store, genesis.Header); err == nil {
		t.Fatal("expected header validation error when DAG merkle root is tampered")
	}
}

func TestColossusXValidateBlockRejectsTamperedCompactProof(t *testing.T) {
	chainCfg, genesisCfg := colossusxTestConfig(t)
	v, err := NewValidator(chainCfg, CPUBackend{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	store := chain.NewMemoryStore()

	genesis, _, err := v.SealBlock(types.NewGenesisBlock(genesisCfg), 2000)
	if err != nil {
		t.Fatal(err)
	}
	if genesis.ColossusXSolutionCompact == nil {
		t.Fatal("expected compact colossusx solution to be present")
	}
	if len(genesis.ColossusXSolutionCompact.Siblings) == 0 {
		t.Fatal("expected compact proof siblings to be present")
	}
	genesis.ColossusXSolutionCompact.Siblings[0][0] ^= 0x01
	if err := v.ValidateBlock(store, genesis); err == nil {
		t.Fatal("expected validation error when compact merkle proof is tampered")
	}
}

func TestSharedCacheKeyIgnoresAllocatorName(t *testing.T) {
	chainCfg, genesisCfg := testConfig(t)
	v, err := NewValidator(chainCfg, CPUBackend{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	genesis := types.NewGenesisBlock(genesisCfg)
	header := testBlockHeader(chainCfg, genesis)

	v.SetMiningBackend(CPUBackend{}, namedAllocator{name: "go-heap"})
	dagA, err := v.sharedMiningDAGForHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	v.SetMiningBackend(CPUBackend{}, namedAllocator{name: "pinned-host"})
	dagB, err := v.sharedMiningDAGForHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if dagA == dagB {
		t.Fatalf("expected cache flush on allocator change to rebuild canonical DAG")
	}
	if got := v.SharedCacheSize(); got != 1 {
		t.Fatalf("expected a single logical shared DAG entry after rebuild, got %d", got)
	}
	validationDAG, err := v.validationDAGForHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if dagB != validationDAG {
		t.Fatalf("expected validation to reuse canonical shared DAG regardless of allocator name partitioning")
	}
}

func TestCloseDoesNotDoubleFreeSharedPointers(t *testing.T) {
	chainCfg, genesisCfg := testConfig(t)
	v, err := NewValidator(chainCfg, CPUBackend{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	var frees int32
	v.allocator = namedAllocator{name: "go-heap", freeCount: &frees}
	v.miningAllocator = namedAllocator{name: "go-heap", freeCount: &frees}

	genesis := types.NewGenesisBlock(genesisCfg)
	header := testBlockHeader(chainCfg, genesis)
	shared, err := v.sharedMiningDAGForHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	v.fallbackValidationDAGs[v.fallbackValidationDAGCacheKey(header, v.validationAllocator())] = shared

	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&frees); got != 1 {
		t.Fatalf("expected shared DAG allocation to be freed once, got %d", got)
	}
}

func TestValidateHeaderRejectsIncorrectResolvedDAGSize(t *testing.T) {
	chainCfg, genesisCfg := testConfig(t)
	v, err := NewValidator(chainCfg, CPUBackend{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	store := chain.NewMemoryStore()
	genesis, _, err := v.SealBlock(types.NewGenesisBlock(genesisCfg), 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.InsertBlock(store, genesis); err != nil {
		t.Fatal(err)
	}
	header := testBlockHeader(chainCfg, genesis)
	header.DAGSizeBytes++
	if err := v.ValidateHeader(store, header); err == nil {
		t.Fatal("expected DAG size mismatch")
	}
}

func TestValidateHeaderRejectsIncorrectEpochSeed(t *testing.T) {
	chainCfg, genesisCfg := testConfig(t)
	v, err := NewValidator(chainCfg, CPUBackend{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	store := chain.NewMemoryStore()
	genesis, _, err := v.SealBlock(types.NewGenesisBlock(genesisCfg), 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.InsertBlock(store, genesis); err != nil {
		t.Fatal(err)
	}
	header := testBlockHeader(chainCfg, genesis)
	header.EpochSeed[0] ^= 0xFF
	if err := v.ValidateHeader(store, header); err == nil {
		t.Fatal("expected epoch seed mismatch")
	}
}
