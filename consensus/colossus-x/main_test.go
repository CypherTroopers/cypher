package miner

import (
	"fmt"
	"testing"

	cx "colossusx/colossusx"
)

type fakeAutoBackend struct{ mode BackendMode }

func (b *fakeAutoBackend) Mode() BackendMode                         { return b.mode }
func (b *fakeAutoBackend) Description() string                       { return string(b.mode) }
func (b *fakeAutoBackend) Prepare(*DAG) error                        { return nil }
func (b *fakeAutoBackend) Hash([]byte, cx.Nonce, *DAG) cx.HashResult { return cx.HashResult{} }

func TestParseBackendMode(t *testing.T) {
	for _, mode := range []string{"unified", "cpu", "gpu", "auto"} {
		if _, err := ParseBackendMode(mode); err != nil {
			t.Fatalf("ParseBackendMode(%q) returned error: %v", mode, err)
		}
	}
	if _, err := ParseBackendMode("bogus"); err == nil {
		t.Fatal("expected invalid backend to fail")
	}
}

func TestParseBackendModeAutoMapsToUnified(t *testing.T) {
	origCUDAProbe := autoBackendCUDAProbe
	origMetalProbe := autoBackendMetalProbe
	origOpenCLProbe := autoBackendOpenCLProbe
	t.Cleanup(func() {
		autoBackendCUDAProbe = origCUDAProbe
		autoBackendMetalProbe = origMetalProbe
		autoBackendOpenCLProbe = origOpenCLProbe
	})

	autoBackendCUDAProbe = func() bool { return false }
	autoBackendMetalProbe = func() bool { return false }
	autoBackendOpenCLProbe = func() bool { return false }

	mode, err := ParseBackendMode("auto")
	if err != nil {
		t.Fatalf("ParseBackendMode(auto): %v", err)
	}
	if mode != BackendUnified {
		t.Fatalf("expected auto to map to unified backend, got %q", mode)
	}
}

func TestParseBackendModeAutoPrefersCUDAThenMetalThenOpenCL(t *testing.T) {
	origCUDAProbe := autoBackendCUDAProbe
	origMetalProbe := autoBackendMetalProbe
	origOpenCLProbe := autoBackendOpenCLProbe
	t.Cleanup(func() {
		autoBackendCUDAProbe = origCUDAProbe
		autoBackendMetalProbe = origMetalProbe
		autoBackendOpenCLProbe = origOpenCLProbe
	})

	autoBackendCUDAProbe = func() bool { return true }
	autoBackendMetalProbe = func() bool { return true }
	autoBackendOpenCLProbe = func() bool { return true }
	mode, err := ParseBackendMode("auto")
	if err != nil {
		t.Fatalf("ParseBackendMode(auto): %v", err)
	}
	if mode != BackendCUDA {
		t.Fatalf("expected auto backend to prefer cuda, got %q", mode)
	}

	autoBackendCUDAProbe = func() bool { return false }
	mode, err = ParseBackendMode("auto")
	if err != nil {
		t.Fatalf("ParseBackendMode(auto): %v", err)
	}
	if mode != BackendMetal {
		t.Fatalf("expected auto backend to prefer metal when cuda unavailable, got %q", mode)
	}

	autoBackendMetalProbe = func() bool { return false }
	mode, err = ParseBackendMode("auto")
	if err != nil {
		t.Fatalf("ParseBackendMode(auto): %v", err)
	}
	if mode != BackendOpenCL {
		t.Fatalf("expected auto backend to prefer opencl when cuda/metal unavailable, got %q", mode)
	}
}

func TestParseCLIConfigMarksAutoBackendRequest(t *testing.T) {
	cfg, err := ParseCLIConfig([]string{"-backend=auto"})
	if err != nil {
		t.Fatalf("ParseCLIConfig: %v", err)
	}
	if !cfg.AutoBackend {
		t.Fatal("expected AutoBackend=true when -backend=auto")
	}
}

func TestAutoTuneBackendSelectsHighestBenchmarkRate(t *testing.T) {
	origFactory := autoBackendCandidateFactory
	origBenchmark := autoBackendBenchmark
	origCUDAProbe := autoBackendCUDAProbe
	origMetalProbe := autoBackendMetalProbe
	origOpenCLProbe := autoBackendOpenCLProbe
	origBenchmarkNonces := autoBackendBenchmarkNonces
	t.Cleanup(func() {
		autoBackendCandidateFactory = origFactory
		autoBackendBenchmark = origBenchmark
		autoBackendCUDAProbe = origCUDAProbe
		autoBackendMetalProbe = origMetalProbe
		autoBackendOpenCLProbe = origOpenCLProbe
		autoBackendBenchmarkNonces = origBenchmarkNonces
	})

	autoBackendCUDAProbe = func() bool { return true }
	autoBackendMetalProbe = func() bool { return true }
	autoBackendOpenCLProbe = func() bool { return true }
	autoBackendBenchmarkNonces = 32

	autoBackendCandidateFactory = func(mode BackendMode) (HashBackend, error) {
		return &fakeAutoBackend{mode: mode}, nil
	}
	autoBackendBenchmark = func(_ CLIConfig, _ *DAG, backend HashBackend, _ uint64) (float64, error) {
		switch backend.Mode() {
		case BackendCUDA:
			return 100, nil
		case BackendMetal:
			return 500, nil
		case BackendOpenCL:
			return 300, nil
		case BackendUnified:
			return 50, nil
		default:
			return 0, fmt.Errorf("unexpected backend %q", backend.Mode())
		}
	}

	best, rate, err := autoTuneBackend(CLIConfig{}, nil)
	if err != nil {
		t.Fatalf("autoTuneBackend: %v", err)
	}
	if best.Mode() != BackendMetal {
		t.Fatalf("expected metal to win benchmark, got %q", best.Mode())
	}
	if rate != 500 {
		t.Fatalf("expected benchmark rate 500, got %f", rate)
	}
}
func TestParseCLIConfigColossusXModeAllowsDynamicDAGProfile(t *testing.T) {
	cfg, err := ParseCLIConfig([]string{"-mode", "colossusx"})
	if err != nil {
		t.Fatalf("ParseCLIConfig: %v", err)
	}
	if cfg.Spec.InitialDAGSizeBytes != 32*1024*1024*1024 {
		t.Fatalf("unexpected colossusx initial DAG size: %d", cfg.Spec.InitialDAGSizeBytes)
	}
	if cfg.Spec.DAGGrowthBytesPerEpoch != 256*1024*1024 {
		t.Fatalf("unexpected colossusx DAG growth: %d", cfg.Spec.DAGGrowthBytesPerEpoch)
	}
}

func TestParseCLIConfigColossusXModeAllowsDagSizeOverrides(t *testing.T) {
	cfg, err := ParseCLIConfig([]string{"-mode", "colossusx", "-initial-dag-mib", "1", "-dag-growth-mib-per-epoch", "2"})
	if err != nil {
		t.Fatalf("ParseCLIConfig: %v", err)
	}
	if cfg.Spec.Mode != cx.ModeColossusX || cfg.Spec.InitialDAGSizeBytes != 1024*1024 || cfg.Spec.DAGGrowthBytesPerEpoch != 2*1024*1024 {
		t.Fatalf("unexpected colossusx spec: %+v", cfg.Spec)
	}
}

func TestCPUAndUnifiedBackendsProduceSameHash(t *testing.T) {
	spec := Spec{Mode: cx.ModeColossusX, DAGSizeBytes: 1024 * 1024, NodeSize: DefaultNodeSize, ReadsPerHash: 8, EpochBlocks: DefaultEpochBlocks}
	dag, err := NewDAG(spec)
	if err != nil {
		t.Fatalf("NewDAG: %v", err)
	}
	defer dag.Close()
	seed := []byte("0123456789abcdef0123456789abcdef")
	if err := GenerateDAG(dag, seed, 2); err != nil {
		t.Fatalf("GenerateDAG: %v", err)
	}
	header := []byte("header")
	nonce := cx.NewUint64Nonce(42)

	cpu := &CPUBackend{}
	unified := &UnifiedBackend{}
	if err := cpu.Prepare(dag); err != nil {
		t.Fatalf("cpu Prepare: %v", err)
	}
	if err := unified.Prepare(dag); err != nil {
		t.Fatalf("unified Prepare: %v", err)
	}

	cpuHash := cpu.Hash(header, nonce, dag)
	unifiedHash := unified.Hash(header, nonce, dag)
	if cpuHash != unifiedHash {
		t.Fatalf("expected cpu and unified backends to match; cpu=%x unified=%x", cpuHash.Pow256, unifiedHash.Pow256)
	}
}

func TestUnifiedBackendUsesDAGAllocationDirectly(t *testing.T) {
	spec := Spec{Mode: cx.ModeColossusX, DAGSizeBytes: 64 * 8, NodeSize: DefaultNodeSize, ReadsPerHash: 4, EpochBlocks: DefaultEpochBlocks}
	dag, err := NewDAG(spec)
	if err != nil {
		t.Fatalf("NewDAG: %v", err)
	}
	defer dag.Close()
	if err := GenerateDAG(dag, []byte("seedseedseedseedseedseedseedseed"), 1); err != nil {
		t.Fatalf("GenerateDAG: %v", err)
	}
	backend := &UnifiedBackend{}
	if err := backend.Prepare(dag); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	original := backend.Hash([]byte("header"), cx.NewUint64Nonce(1), dag)

	copy(dag.Bytes(), make([]byte, len(dag.Bytes())))
	mutated := backend.Hash([]byte("header"), cx.NewUint64Nonce(1), dag)
	if original == mutated {
		t.Fatal("expected unified backend to observe DAG mutations through shared memory")
	}
}

func TestCPUBackendUsesDAGAllocationDirectly(t *testing.T) {
	spec := Spec{Mode: cx.ModeColossusX, DAGSizeBytes: 64 * 8, NodeSize: DefaultNodeSize, ReadsPerHash: 4, EpochBlocks: DefaultEpochBlocks}
	dag, err := NewDAG(spec)
	if err != nil {
		t.Fatalf("NewDAG: %v", err)
	}
	defer dag.Close()
	if err := GenerateDAG(dag, []byte("seedseedseedseedseedseedseedseed"), 1); err != nil {
		t.Fatalf("GenerateDAG: %v", err)
	}
	backend := &CPUBackend{}
	if err := backend.Prepare(dag); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	original := backend.Hash([]byte("header"), cx.NewUint64Nonce(1), dag)

	copy(dag.Bytes(), make([]byte, len(dag.Bytes())))
	mutated := backend.Hash([]byte("header"), cx.NewUint64Nonce(1), dag)
	if original == mutated {
		t.Fatal("expected cpu backend to observe DAG mutations through shared memory")
	}
}

func TestRunInitializesBackendRuntimeBeforeResolvingAllocator(t *testing.T) {
	spec := Spec{Mode: cx.ModeColossusX, DAGSizeBytes: 64 * 64, NodeSize: DefaultNodeSize, ReadsPerHash: 4, EpochBlocks: DefaultEpochBlocks}
	cfg := CLIConfig{Mode: cx.ModeColossusX, Backend: BackendGPU, DAGAlloc: "auto", Spec: spec, Workers: 1, Header: []byte("01"), EpochSeed: []byte("seedseedseedseedseedseedseedseed"), Target: cx.Target{}, MaxNonces: 1, BenchOnly: true}
	backend := &fakeGPUBackend{}
	if err := Run(cfg, backend); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !backend.runtimeCalled {
		t.Fatal("expected run to initialize backend runtime before allocator resolution")
	}
	if !backend.prepared {
		t.Fatal("expected run to prepare backend after dag allocation/population")
	}
}

func TestColossusXSpecLocksSectionTwoConstants(t *testing.T) {
	spec := cx.ColossusXSpec()
	if spec.ReadsPerHash != cx.ColossusXReadsPerHash {
		t.Fatalf("expected colossusx reads/hash %d, got %d", cx.ColossusXReadsPerHash, spec.ReadsPerHash)
	}
	if spec.ReadsPerHash != 128 {
		t.Fatalf("expected colossusx spec to preserve v2 reads/hash target, got %d", spec.ReadsPerHash)
	}
	if spec.EpochBlocks != 7200 {
		t.Fatalf("expected colossusx epoch blocks 7200, got %d", spec.EpochBlocks)
	}
}

func TestColossusXDAGRequiresFullLogicalImage(t *testing.T) {
	spec := cx.ColossusXSpec()
	alloc := &testAllocation{buf: make([]byte, 1024)}
	_, err := NewDAGWithAllocation(spec, alloc, false)
	if err == nil {
		t.Fatal("expected colossusx DAG allocation to require the full logical DAG image")
	}
}

func TestParseCLIConfigColossusXModeDagMibAliasSetsInitialDag(t *testing.T) {
	cfg, err := ParseCLIConfig([]string{"-mode", "colossusx", "-dag-mib", "3"})
	if err != nil {
		t.Fatalf("ParseCLIConfig: %v", err)
	}
	if cfg.Spec.InitialDAGSizeBytes != 3*1024*1024 {
		t.Fatalf("expected dag-mib alias to set initial DAG size, got %d", cfg.Spec.InitialDAGSizeBytes)
	}
}
