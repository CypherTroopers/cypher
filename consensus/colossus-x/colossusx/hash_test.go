package colossusx

import (
	"bytes"
	"testing"
)

type sliceAccessor struct {
	spec Spec
	buf  []byte
}

func (a sliceAccessor) NodeCount() uint64 { return a.spec.NodeCount() }
func (a sliceAccessor) ReadNode(i uint64, out []byte) {
	off := i * a.spec.NodeSize
	copy(out, a.buf[off:off+a.spec.NodeSize])
}

func testSpec() Spec {
	return ColossusXSpecWithGrowth(64*16, DefaultDAGGrowthBytesPerEpoch)
}

func TestGenerateDAGDeterministic(t *testing.T) {
	spec := testSpec()
	seed := []byte("0123456789abcdef0123456789abcdef")
	left := make([]byte, spec.DAGSizeBytes)
	right := make([]byte, spec.DAGSizeBytes)

	if err := GenerateDAG(spec, left, seed, 2); err != nil {
		t.Fatalf("GenerateDAG left: %v", err)
	}
	if err := GenerateDAG(spec, right, seed, 3); err != nil {
		t.Fatalf("GenerateDAG right: %v", err)
	}
	if !bytes.Equal(left, right) {
		t.Fatal("expected identical DAG output for the same seed")
	}
}

func TestGenerateDAGDiffersAcrossSeeds(t *testing.T) {
	spec := testSpec()
	left := make([]byte, spec.DAGSizeBytes)
	right := make([]byte, spec.DAGSizeBytes)
	if err := GenerateDAG(spec, left, []byte("0123456789abcdef0123456789abcdef"), 2); err != nil {
		t.Fatalf("GenerateDAG left: %v", err)
	}
	if err := GenerateDAG(spec, right, []byte("fedcba9876543210fedcba9876543210"), 2); err != nil {
		t.Fatalf("GenerateDAG right: %v", err)
	}
	if bytes.Equal(left, right) {
		t.Fatal("expected different DAG output for different seeds")
	}
}

func TestLatticeHashDeterministic(t *testing.T) {
	spec := testSpec()
	seed := []byte("0123456789abcdef0123456789abcdef")
	dag := make([]byte, spec.DAGSizeBytes)
	if err := GenerateDAG(spec, dag, seed, 2); err != nil {
		t.Fatalf("GenerateDAG: %v", err)
	}
	accessor := sliceAccessor{spec: spec, buf: dag}
	header := []byte("header")
	nonce := NewUint64Nonce(42)

	first := LatticeHash(spec, header, nonce, accessor, nil)
	second := LatticeHash(spec, header, nonce, accessor, nil)
	if first != second {
		t.Fatalf("expected deterministic lattice hash; first=%x second=%x", first.Pow256, second.Pow256)
	}

	thirdNonce, _ := nonce.AddUint64(1)
	third := LatticeHash(spec, header, thirdNonce, accessor, nil)
	if first == third {
		t.Fatal("expected nonce change to alter lattice hash")
	}
}

func TestLessOrEqualBETargetComparison(t *testing.T) {
	target, err := ParseTargetHex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatalf("ParseTargetHex: %v", err)
	}
	var lower [32]byte
	var equal [32]byte
	copy(equal[:], target[:])
	var higher [32]byte
	copy(higher[:], target[:])
	lower[31] = 1
	higher[0] = 0x01

	if !LessOrEqualBE(lower, target) {
		t.Fatal("expected lower digest to satisfy target")
	}
	if !LessOrEqualBE(equal, target) {
		t.Fatal("expected equal digest to satisfy target")
	}
	if LessOrEqualBE(higher, target) {
		t.Fatal("expected higher digest to fail target comparison")
	}
}

func TestColossusXModeDynamicDAGProfile(t *testing.T) {
	colossusx := ColossusXSpec()
	if err := colossusx.Validate(); err != nil {
		t.Fatalf("ColossusXSpec should validate: %v", err)
	}
	if colossusx.InitialDAGSizeBytes != 32*1024*1024*1024 {
		t.Fatalf("expected colossusx initial DAG size 32GiB, got %d", colossusx.InitialDAGSizeBytes)
	}
	if colossusx.DAGGrowthBytesPerEpoch != 256*1024*1024 {
		t.Fatalf("expected colossusx DAG growth 256MiB, got %d", colossusx.DAGGrowthBytesPerEpoch)
	}
	if colossusx.DAGSizeForHeight(colossusx.EpochBlocks) <= colossusx.DAGSizeForHeight(0) {
		t.Fatal("expected colossusx DAG size to grow after an epoch")
	}
}

func TestGenerateDAGUsesColossusXV2NodeGeneration(t *testing.T) {
	spec := testSpec()
	seed := []byte("0123456789abcdef0123456789abcdef")
	dag := make([]byte, spec.DAGSizeBytes)
	if err := GenerateDAG(spec, dag, seed, 1); err != nil {
		t.Fatalf("GenerateDAG: %v", err)
	}
	cache := buildColossusXV2SeedCache(seed, colossusXCacheEntriesForSpec(spec))
	want := colossusXNode(0, spec.NodeSize, cache)
	if got := dag[:spec.NodeSize]; !bytes.Equal(got, want) {
		t.Fatalf("node 0 mismatch: got=%x want=%x", got, want)
	}
}

func TestBlake3RoundInputIncludesMixAndNode(t *testing.T) {
	var mix [32]byte
	node := make([]byte, 96)
	for i := range mix {
		mix[i] = byte(i + 1)
	}
	for i := range node {
		node[i] = byte(255 - i)
	}
	in := blake3RoundInput(mix, node, nil)
	if len(in) != len(mix)+len(node) {
		t.Fatalf("unexpected round input size: %d", len(in))
	}
	for i := 0; i < 32; i++ {
		if in[i] != mix[i] {
			t.Fatalf("mix prefix mismatch at %d", i)
		}
	}
}

func TestColossusXAuditIndicesCountAndBounds(t *testing.T) {
	pow := [32]byte{1, 2, 3, 4}
	indices := ColossusXAuditIndices(pow, 17, ColossusXAuditCellCount)
	if len(indices) != int(ColossusXAuditCellCount) {
		t.Fatalf("unexpected audit index count: %d", len(indices))
	}
	for i, idx := range indices {
		if idx >= 17 {
			t.Fatalf("index out of bounds at %d: %d", i, idx)
		}
	}
}
