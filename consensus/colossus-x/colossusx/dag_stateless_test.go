package colossusx

import "testing"

func TestHashHeaderStatelessDisabledForColossusXV2(t *testing.T) {
	spec := ColossusXSpecWithGrowth(64*16, DefaultDAGGrowthBytesPerEpoch)
	seed := []byte("0123456789abcdef0123456789abcdef")
	if _, err := HashHeaderStateless(spec, []byte("external-verifier-header"), NewUint64Nonce(42), seed); err == nil {
		t.Fatal("expected colossusx v2 stateless hashing to be disabled")
	}
}

func TestStatelessDAGReadNodeDisabledForColossusXV2(t *testing.T) {
	spec := ColossusXSpecWithGrowth(64*4, DefaultDAGGrowthBytesPerEpoch)
	seed := []byte("fedcba9876543210fedcba9876543210")
	if _, err := NewStatelessDAG(spec, seed); err == nil {
		t.Fatal("expected colossusx v2 stateless DAG to be disabled")
	}
}

func TestVerifyHeaderStatelessChecksTarget(t *testing.T) {
	spec := ColossusXSpecWithGrowth(64*16, DefaultDAGGrowthBytesPerEpoch)
	seed := []byte("0123456789abcdef0123456789abcdef")
	if _, _, err := VerifyHeaderStateless(spec, []byte("verify-target"), NewUint64Nonce(7), seed, Target{}); err == nil {
		t.Fatal("expected colossusx v2 stateless verification to be disabled")
	}
}

func TestHashHeaderStatelessSupportsDifferentResolvedSizesAcrossEpochs(t *testing.T) {
	spec := ColossusXSpecWithGrowth(64*16, 256)
	seedEpoch0 := []byte("0123456789abcdef0123456789abcdef")
	seedEpoch1 := []byte("fedcba9876543210fedcba9876543210")
	header := []byte("external-verifier-header")
	nonce := NewUint64Nonce(42)

	resolved0 := spec.ResolvedForHeight(0)
	resolved1 := spec.ResolvedForHeight(spec.EpochBlocks)
	if resolved1.DAGSizeBytes <= resolved0.DAGSizeBytes {
		t.Fatal("expected DAG to grow across epochs")
	}
	if _, err := HashHeaderStateless(resolved0, header, nonce, seedEpoch0); err == nil {
		t.Fatal("expected colossusx v2 stateless hashing to be disabled for epoch0")
	}
	if _, err := HashHeaderStateless(resolved1, header, nonce, seedEpoch1); err == nil {
		t.Fatal("expected colossusx v2 stateless hashing to be disabled for epoch1")
	}
}

func TestColossusXStatelessDAGIsDisabled(t *testing.T) {
	spec := ColossusXSpec()
	seed := []byte("0123456789abcdef0123456789abcdef")
	if _, err := NewStatelessDAG(spec, seed); err == nil {
		t.Fatal("expected colossusx stateless DAG to be disabled")
	}
	if _, err := HashHeaderStateless(spec, []byte("header"), NewUint64Nonce(1), seed); err == nil {
		t.Fatal("expected colossusx stateless hashing to be disabled")
	}
}
