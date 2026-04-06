package consensus

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cx "colossusx/colossusx"
	"colossusx/pkg/chain"
	"colossusx/pkg/types"
	"github.com/zeebo/blake3"
)

var (
	ErrInvalidParent    = errors.New("invalid parent linkage")
	ErrInvalidTimestamp = errors.New("invalid timestamp")
	ErrInvalidTarget    = errors.New("invalid target")
	ErrInvalidPoW       = errors.New("invalid proof of work")
	ErrInvalidEpoch     = errors.New("invalid epoch parameters")
)

type Validator struct {
	config                 types.ChainConfig
	backend                cx.HashBackend
	workers                int
	now                    func() time.Time
	mu                     sync.Mutex
	sharedDAGs             map[string]*cx.DAG
	fallbackValidationDAGs map[string]*cx.DAG
	allocator              cx.Allocator
	miningBackend          cx.HashBackend
	miningAllocator        cx.Allocator
	colossusxMerkleRoots   map[string][32]byte
}

type dagKey struct {
	seed string
	size uint64
}

type sliceAllocation struct{ buf []byte }

func (a *sliceAllocation) Bytes() []byte { return a.buf }
func (a *sliceAllocation) Free() error   { a.buf = nil; return nil }
func (a *sliceAllocation) Name() string  { return "go-slice" }

type validationReusableAllocator interface {
	ValidationCanReuseDAG() bool
}

type sliceAllocator struct{}

func (sliceAllocator) Alloc(size uint64) (cx.Allocation, error) {
	return &sliceAllocation{buf: make([]byte, size)}, nil
}
func (sliceAllocator) Name() string                { return "go-slice" }
func (sliceAllocator) ValidationCanReuseDAG() bool { return true }

type CPUBackend struct{}

func (CPUBackend) Mode() cx.BackendMode  { return cx.BackendCPU }
func (CPUBackend) Description() string   { return "consensus cpu backend" }
func (CPUBackend) Prepare(*cx.DAG) error { return nil }
func (CPUBackend) Hash(header []byte, nonce cx.Nonce, dag *cx.DAG) cx.HashResult {
	if dag.Spec().AlgorithmVersion >= 2 {
		return cx.ColossusXHash(dag.Spec(), header, nonce, dag)
	}
	return cx.LatticeHash(dag.Spec(), header, nonce, dag, nil)
}

func NewValidator(cfg types.ChainConfig, backend cx.HashBackend, workers int) (*Validator, error) {
	if err := cfg.Spec.Validate(); err != nil {
		return nil, err
	}
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if backend == nil {
		backend = CPUBackend{}
	}
	return &Validator{
		config:                 cfg,
		backend:                backend,
		workers:                workers,
		now:                    time.Now,
		sharedDAGs:             make(map[string]*cx.DAG),
		fallbackValidationDAGs: make(map[string]*cx.DAG),
		allocator:              sliceAllocator{},
		miningBackend:          backend,
		miningAllocator:        sliceAllocator{},
		colossusxMerkleRoots:   make(map[string][32]byte),
	}, nil
}

func (v *Validator) SetMiningBackend(backend cx.HashBackend, allocator cx.Allocator) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if backend != nil {
		v.miningBackend = backend
	}
	if allocator != nil {
		v.miningAllocator = allocator
	}
	for key, dag := range v.sharedDAGs {
		_ = dag.Close()
		delete(v.sharedDAGs, key)
	}
	for key := range v.colossusxMerkleRoots {
		delete(v.colossusxMerkleRoots, key)
	}
}

func (v *Validator) MiningBackend() cx.HashBackend {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.miningBackend == nil {
		return v.backend
	}
	return v.miningBackend
}

func (v *Validator) MiningAllocatorName() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.miningAllocator == nil {
		return ""
	}
	return v.miningAllocator.Name()
}

func (v *Validator) ValidateHeader(store chain.Store, header types.BlockHeader) error {
	return v.validateHeader(store, header, true)
}

func (v *Validator) validateHeader(store chain.Store, header types.BlockHeader, verifyDAGMerkle bool) error {
	if header.AlgorithmVersion != v.config.Spec.AlgorithmVersion {
		return fmt.Errorf("%w: algorithm version mismatch", ErrInvalidEpoch)
	}
	if err := v.validateEpochParameters(header); err != nil {
		return err
	}
	if header.Target == (cx.Target{}) {
		return ErrInvalidTarget
	}
	if header.Height == 0 {
		if header.ParentHash != (types.Hash{}) {
			return fmt.Errorf("%w: genesis parent must be zero", ErrInvalidParent)
		}
	} else {
		parent, err := store.GetHeader(header.ParentHash)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidParent, err)
		}
		if parent.Height+1 != header.Height {
			return fmt.Errorf("%w: expected height %d got %d", ErrInvalidParent, parent.Height+1, header.Height)
		}
		if header.Timestamp <= parent.Timestamp {
			return fmt.Errorf("%w: child timestamp %d <= parent %d", ErrInvalidTimestamp, header.Timestamp, parent.Timestamp)
		}
	}
	now := v.now().Unix() + 2*60*60
	if header.Timestamp > now {
		return fmt.Errorf("%w: timestamp %d too far ahead of %d", ErrInvalidTimestamp, header.Timestamp, now)
	}
	if header.AlgorithmVersion >= 2 || v.config.Spec.Mode == cx.ModeColossusX {
		if header.DAGMerkleRoot == (types.Hash{}) {
			return fmt.Errorf("%w: colossusx header missing dag merkle root", ErrInvalidPoW)
		}
		if verifyDAGMerkle {
			if err := v.validateDAGMerkleRoot(header); err != nil {
				return err
			}
		}
		return nil
	}
	return v.validatePoW(types.Block{Header: header})
}

func (v *Validator) ValidateBlock(store chain.Store, block types.Block) error {
	if err := v.validateHeader(store, block.Header, false); err != nil {
		return err
	}
	return v.validatePoW(block)
}

func (v *Validator) validateEpochParameters(header types.BlockHeader) error {
	currentSize := v.config.Spec.DAGSizeForHeight(header.Height)
	currentSeed := types.EpochSeedForHeight(v.config.Spec, header.Height)
	if header.DAGSizeBytes == currentSize && header.EpochSeed == currentSeed {
		return nil
	}
	epochBlocks := v.config.Spec.EpochBlocks
	if epochBlocks == 0 {
		return fmt.Errorf("%w: invalid epoch config", ErrInvalidEpoch)
	}
	if header.Height < epochBlocks {
		return fmt.Errorf("%w: dag size/seed mismatch", ErrInvalidEpoch)
	}
	offset := header.Height % epochBlocks
	if offset >= cx.ColossusXEpochGraceBlocks {
		return fmt.Errorf("%w: dag size/seed mismatch outside grace window", ErrInvalidEpoch)
	}
	prevHeight := header.Height - epochBlocks
	prevSize := v.config.Spec.DAGSizeForHeight(prevHeight)
	prevSeed := types.EpochSeedForHeight(v.config.Spec, prevHeight)
	if header.DAGSizeBytes == prevSize && header.EpochSeed == prevSeed {
		return nil
	}
	return fmt.Errorf("%w: epoch seed/dag size mismatch", ErrInvalidEpoch)
}

func CalcBlockWork(target cx.Target) *big.Int {
	max := new(big.Int).Lsh(big.NewInt(1), 256)
	targetInt := new(big.Int).SetBytes(target[:])
	if targetInt.Sign() == 0 {
		return big.NewInt(0)
	}
	return max.Div(max, targetInt.Add(targetInt, big.NewInt(1)))
}

func SelectBestChainByTotalWork(currentHash types.Hash, currentWork *big.Int, candidateHash types.Hash, candidateWork *big.Int) types.Hash {
	cmp := candidateWork.Cmp(currentWork)
	if cmp > 0 {
		return candidateHash
	}
	if cmp < 0 {
		return currentHash
	}
	if candidateHash.String() < currentHash.String() {
		return candidateHash
	}
	return currentHash
}

func (v *Validator) InsertBlock(store chain.Store, block types.Block) (*big.Int, bool, error) {
	if err := v.ValidateBlock(store, block); err != nil {
		return nil, false, err
	}
	blockHash := block.BlockHash()
	if store.HasBlock(blockHash) {
		work, err := store.TotalWork(blockHash)
		return work, false, err
	}
	blockWork := CalcBlockWork(block.Header.Target)
	totalWork := new(big.Int).Set(blockWork)
	if block.Header.Height > 0 {
		parentWork, err := store.TotalWork(block.Header.ParentHash)
		if err != nil {
			return nil, false, err
		}
		totalWork.Add(totalWork, parentWork)
	}
	if err := store.StoreBlock(block, totalWork); err != nil {
		return nil, false, err
	}
	current, currentWork, err := store.CurrentTip()
	if err != nil {
		if err := store.SetCurrentTip(blockHash); err != nil {
			return nil, false, err
		}
		return totalWork, true, nil
	}
	best := SelectBestChainByTotalWork(current.BlockHash(), currentWork, blockHash, totalWork)
	if best == blockHash {
		if err := store.SetCurrentTip(blockHash); err != nil {
			return nil, false, err
		}
		return totalWork, true, nil
	}
	return totalWork, false, nil
}

func (v *Validator) SealBlock(block types.Block, maxNonces uint64) (types.Block, cx.MineResult, error) {
	backend := v.MiningBackend()
	dag, err := v.sharedMiningDAGForHeader(block.Header)
	if err != nil {
		return types.Block{}, cx.MineResult{}, err
	}
	if err := backend.Prepare(dag); err != nil {
		return types.Block{}, cx.MineResult{}, err
	}
	var merkleRoot [32]byte
	if block.Header.AlgorithmVersion >= 2 || v.config.Spec.Mode == cx.ModeColossusX {
		merkleRoot = v.merkleRootForDAG(block.Header, dag)
		block.Header.DAGMerkleRoot = types.Hash(merkleRoot)
	}
	miner, err := cx.NewMiner(v.config.Spec, dag, v.workers, sealSkipPrepareBackend{backend})
	if err != nil {
		return types.Block{}, cx.MineResult{}, err
	}
	res, ok := miner.Mine(block.Header.EncodeForMining(), block.Header.Target, cx.NewUint64Nonce(0), maxNonces)
	if !ok {
		return types.Block{}, cx.MineResult{}, fmt.Errorf("no solution found in %d nonces", maxNonces)
	}
	nonce, ok := res.Nonce.(cx.Uint64Nonce)
	if !ok {
		return types.Block{}, cx.MineResult{}, errors.New("unexpected nonce type")
	}
	block.Header.Nonce = nonce.Uint64()
	if block.Header.AlgorithmVersion >= 2 || v.config.Spec.Mode == cx.ModeColossusX {
		solution, root, err := cx.BuildColossusXSolutionStreaming(dag.Spec(), block.Header.EncodeForMining(), nonce.Uint64(), dag)
		if err != nil {
			return types.Block{}, cx.MineResult{}, err
		}
		if root != merkleRoot {
			return types.Block{}, cx.MineResult{}, fmt.Errorf("dag merkle root mismatch between cached root and streaming proof root")
		}
		compact := cx.CompactColossusXSolution(solution)
		block.ColossusXSolutionCompact = &compact
		block.ColossusXSolution = nil
	}
	return block, res, nil
}

type sealSkipPrepareBackend struct{ cx.HashBackend }

func (b sealSkipPrepareBackend) Prepare(*cx.DAG) error { return nil }

func (v *Validator) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	seen := make(map[*cx.DAG]struct{}, len(v.sharedDAGs)+len(v.fallbackValidationDAGs))
	for key, dag := range v.fallbackValidationDAGs {
		if _, ok := seen[dag]; !ok {
			_ = dag.Close()
			seen[dag] = struct{}{}
		}
		delete(v.fallbackValidationDAGs, key)
		delete(v.colossusxMerkleRoots, key)
	}
	for key, dag := range v.sharedDAGs {
		if _, ok := seen[dag]; !ok {
			_ = dag.Close()
			seen[dag] = struct{}{}
		}
		delete(v.sharedDAGs, key)
		delete(v.colossusxMerkleRoots, key)
	}
	return nil
}

func (v *Validator) validatePoW(block types.Block) error {
	header := block.Header
	dag, err := v.validationDAGForHeader(header)
	if err != nil {
		return err
	}
	if header.AlgorithmVersion >= 2 || v.config.Spec.Mode == cx.ModeColossusX {
		var solution cx.ColossusXSolution
		switch {
		case block.ColossusXSolution != nil:
			solution = *block.ColossusXSolution
		case block.ColossusXSolutionCompact != nil:
			expanded, err := cx.ExpandCompactColossusXSolution(*block.ColossusXSolutionCompact)
			if err != nil {
				return fmt.Errorf("%w: invalid compact colossusx solution: %v", ErrInvalidPoW, err)
			}
			solution = expanded
		default:
			return fmt.Errorf("%w: colossusx solution is required", ErrInvalidPoW)
		}
		root := v.merkleRootForDAG(header, dag)
		if err := v.validateDAGMerkleRootWithRoot(header, root); err != nil {
			return err
		}
		if err := cx.VerifyColossusXSolution(dag.Spec(), header.EncodeForMining(), header.Target, root, solution); err != nil {
			return fmt.Errorf("%w: colossusx solution verify failed: %v", ErrInvalidPoW, err)
		}
		return nil
	}
	hash := v.backend.Hash(header.EncodeForMining(), cx.NewUint64Nonce(header.Nonce), dag)
	if !cx.LessOrEqualBE(hash.Pow256, header.Target) {
		return fmt.Errorf("%w: pow=%s target=%s", ErrInvalidPoW, hex.EncodeToString(hash.Pow256[:]), header.Target.String())
	}
	return nil
}

func (v *Validator) validateDAGMerkleRoot(header types.BlockHeader) error {
	dag, err := v.validationDAGForHeader(header)
	if err != nil {
		return err
	}
	return v.validateDAGMerkleRootWithRoot(header, v.merkleRootForDAG(header, dag))
}

func (v *Validator) validateDAGMerkleRootWithRoot(header types.BlockHeader, root [32]byte) error {
	if root != [32]byte(header.DAGMerkleRoot) {
		return fmt.Errorf("%w: dag merkle root mismatch", ErrInvalidPoW)
	}
	return nil
}

func dagMerkleLeaves(dag *cx.DAG) [][32]byte {
	if dag == nil {
		return nil
	}
	cells := make([][]byte, dag.NodeCount())
	for i := uint64(0); i < dag.NodeCount(); i++ {
		cells[i] = dag.Node(i)
	}
	return cx.BuildMerkleLeaves(cells)
}

func hashMerklePair(left, right [32]byte) [32]byte {
	var in [64]byte
	copy(in[:32], left[:])
	copy(in[32:], right[:])
	return blake3.Sum256(in[:])
}

func dagMerkleRootStreaming(dag *cx.DAG) [32]byte {
	if dag == nil || dag.NodeCount() == 0 {
		return [32]byte{}
	}
	frontier := make([][32]byte, 0, 64)
	present := make([]bool, 0, 64)
	for i := uint64(0); i < dag.NodeCount(); i++ {
		h := blake3.Sum256(dag.Node(i))
		level := 0
		for {
			if level >= len(frontier) {
				frontier = append(frontier, [32]byte{})
				present = append(present, false)
			}
			if !present[level] {
				frontier[level] = h
				present[level] = true
				break
			}
			h = hashMerklePair(frontier[level], h)
			present[level] = false
			level++
		}
	}
	var acc [32]byte
	accLevel := 0
	hasAcc := false
	for level := 0; level < len(frontier); level++ {
		if !present[level] {
			continue
		}
		node := frontier[level]
		if !hasAcc {
			acc = node
			accLevel = level
			hasAcc = true
			continue
		}
		for accLevel < level {
			acc = hashMerklePair(acc, acc)
			accLevel++
		}
		acc = hashMerklePair(node, acc)
		accLevel = level + 1
	}
	return acc
}

func (v *Validator) merkleRootForDAG(header types.BlockHeader, dag *cx.DAG) [32]byte {
	key := v.sharedDAGCacheKey(header)
	v.mu.Lock()
	if root, ok := v.colossusxMerkleRoots[key]; ok {
		v.mu.Unlock()
		return root
	}
	v.mu.Unlock()
	root := dagMerkleRootStreaming(dag)
	v.cacheMerkleRoot(key, root)
	return root
}

func (v *Validator) cacheMerkleRoot(key string, root [32]byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.colossusxMerkleRoots[key] = root
}

func (v *Validator) validationDAGForHeader(header types.BlockHeader) (*cx.DAG, error) {
	allocator := v.miningAllocatorOrDefault()
	if v.canValidationReuseMiningDAG() {
		log.Printf("validator DAG reuse enabled allocator=%s shared=true", allocatorName(allocator))
		return v.sharedMiningDAGForHeader(header)
	}
	log.Printf("validator DAG reuse fallback allocator=%s shared=false", allocatorName(allocator))
	allocator = v.validationAllocator()
	return v.cachedDAGForHeader(header, allocator, v.fallbackValidationDAGs, v.fallbackValidationDAGCacheKey(header, allocator))
}

func (v *Validator) sharedMiningDAGForHeader(header types.BlockHeader) (*cx.DAG, error) {
	allocator := v.miningAllocatorOrDefault()
	return v.cachedDAGForHeader(header, allocator, v.sharedDAGs, v.sharedDAGCacheKey(header))
}

func (v *Validator) SharedCacheSize() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.sharedDAGs)
}

func (v *Validator) ValidationCacheSize() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.fallbackValidationDAGs)
}

func (v *Validator) DAGReuseEnabled() bool {
	return v.canValidationReuseMiningDAG()
}

func (v *Validator) miningAllocatorOrDefault() cx.Allocator {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.miningAllocator != nil {
		return v.miningAllocator
	}
	return v.allocator
}

func (v *Validator) validationAllocator() cx.Allocator {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.allocator
}

func (v *Validator) canValidationReuseMiningDAG() bool {
	allocator := v.miningAllocatorOrDefault()
	if allocator == nil {
		return false
	}
	if reusable, ok := allocator.(validationReusableAllocator); ok {
		return reusable.ValidationCanReuseDAG()
	}
	name := strings.ToLower(strings.TrimSpace(allocator.Name()))
	switch {
	case name == "", name == "go", name == "go-slice", name == "go-heap", name == "auto", name == "pinned", name == "pinned-host":
		return true
	case strings.Contains(name, "unified"):
		return true
	default:
		return false
	}
}

func (v *Validator) sharedDAGCacheKey(header types.BlockHeader) string {
	key := dagKey{seed: header.EpochSeed.String(), size: header.DAGSizeBytes}
	return fmt.Sprintf("%s/%d", key.seed, key.size)
}

func (v *Validator) fallbackValidationDAGCacheKey(header types.BlockHeader, allocator cx.Allocator) string {
	return fmt.Sprintf("%s/%s/validation", v.sharedDAGCacheKey(header), allocatorName(allocator))
}

func allocatorName(allocator cx.Allocator) string {
	if allocator == nil {
		return ""
	}
	return allocator.Name()
}

func (v *Validator) cachedDAGForHeader(header types.BlockHeader, allocator cx.Allocator, cache map[string]*cx.DAG, key string) (*cx.DAG, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if dag, ok := cache[key]; ok {
		return dag, nil
	}
	spec := v.config.Spec.ResolvedForHeight(header.Height)
	spec.DAGSizeBytes = header.DAGSizeBytes
	dag, err := cx.NewDAGWithAllocator(spec, allocator)
	if err != nil {
		return nil, err
	}
	if err := populateDAGWithLogging(dag, header.EpochSeed[:], v.workers); err != nil {
		_ = dag.Close()
		return nil, err
	}
	cache[key] = dag
	if spec.AlgorithmVersion >= 2 || spec.Mode == cx.ModeColossusX {
		v.colossusxMerkleRoots[key] = dagMerkleRootStreaming(dag)
	}
	return dag, nil
}

func populateDAGWithLogging(dag *cx.DAG, epochSeed []byte, workers int) error {
	if dag == nil {
		return fmt.Errorf("dag cannot be nil")
	}
	total := dag.NodeCount()
	start := time.Now()
	log.Printf("dag generation started nodes=%d workers=%d", total, workers)
	var finalDone atomic.Uint64
	err := cx.PopulateDAGWithProgress(dag, epochSeed, workers, func(done, total uint64) {
		finalDone.Store(done)
		if total == 0 {
			return
		}
		percent := float64(done) * 100 / float64(total)
		log.Printf("dag generation progress: %.1f%% (%d/%d) elapsed=%s", percent, done, total, time.Since(start).Round(time.Second))
	})
	if err != nil {
		return err
	}
	log.Printf("dag generation completed in %s (%d/%d)", time.Since(start).Round(time.Second), finalDone.Load(), total)
	return nil
}
