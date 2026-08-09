package core

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

func TestValidateOsakaBlockSize(t *testing.T) {
	osaka := uint64(1)
	config := new(params.ChainConfig)
	config.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0), OsakaTime: &osaka})

	oversized := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(1),
		Time:       osaka,
		Difficulty: big.NewInt(1),
		Extra:      make([]byte, params.MaxBlockSize),
	})
	if err := validateOsakaBlockSize(config, oversized); err == nil {
		t.Fatal("oversized Osaka block accepted")
	}

	preFork := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(1),
		Time:       osaka - 1,
		Difficulty: big.NewInt(1),
		Extra:      make([]byte, params.MaxBlockSize),
	})
	if err := validateOsakaBlockSize(config, preFork); err != nil {
		t.Fatalf("pre-Osaka block rejected: %v", err)
	}
}

func TestValidateOsakaBlockSizeIncludesFinalityProof(t *testing.T) {
	osaka := uint64(0)
	config := new(params.ChainConfig)
	config.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0), OsakaTime: &osaka})

	block := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(1),
		Time:       osaka,
		Difficulty: big.NewInt(1),
		Extra:      make([]byte, params.MaxBlockSize-4096),
	})
	if err := validateOsakaBlockSize(config, block); err != nil {
		t.Fatalf("block without finality proof should fit: %v", err)
	}
	if err := block.SetFHSFinalityProof(make([]byte, 8192)); err != nil {
		t.Fatalf("attach finality proof: %v", err)
	}
	if err := validateOsakaBlockSize(config, block); err == nil {
		t.Fatal("finality proof was not included in Osaka block-size validation")
	}
}

func TestValidateOsakaBlockSizeReservesFHSFinalityProofBeforeVote(t *testing.T) {
	osaka := uint64(0)
	config := &params.ChainConfig{FairHotstuff: true}
	config.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0), OsakaTime: &osaka})

	block := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(1),
		Time:       osaka,
		Difficulty: big.NewInt(1),
		Extra:      make([]byte, params.MaxBlockSize-types.MaxFHSFinalityProofSize),
	})
	if err := validateOsakaBlockSize(config, block); err == nil {
		t.Fatal("proofless Fair HotStuff proposal consumed the finality-proof reserve")
	}
}

func TestValidateBodyRejectsPrematureFHSFinalityProof(t *testing.T) {
	osaka := uint64(0)
	config := &params.ChainConfig{FairHotstuff: true}
	config.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0), OsakaTime: &osaka,
	})
	block := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), Time: osaka, Difficulty: big.NewInt(1),
	})
	if err := block.SetFHSFinalityProof([]byte{1}); err != nil {
		t.Fatal(err)
	}
	validator := &BlockValidator{config: config}
	if err := validator.validateBody(block, true, false); err == nil {
		t.Fatal("live proposal with placeholder finality proof was accepted")
	}
}
