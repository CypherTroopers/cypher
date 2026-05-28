package tests

import (
	"math/big"
	"testing"
)

func TestGetChainConfigCancun(t *testing.T) {
	cfg, extra, err := GetChainConfig("Cancun")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(extra) != 0 {
		t.Fatalf("expected no extra eips, got %v", extra)
	}
	if !cfg.IsCancun(big.NewInt(0), 0) {
		t.Fatalf("expected Cancun to be active at timestamp 0")
	}
	if !cfg.IsLondon(big.NewInt(0)) {
		t.Fatalf("expected London to be active for Cancun config")
	}
	if !cfg.IsBerlin(big.NewInt(0)) {
		t.Fatalf("expected Berlin to be active for Cancun config")
	}
}

func TestGetChainConfigExtraEIPs(t *testing.T) {
	_, extra, err := GetChainConfig("Istanbul+1344+2200")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(extra) != 2 || extra[0] != 1344 || extra[1] != 2200 {
		t.Fatalf("unexpected extra eips: %v", extra)
	}
}

func TestGetChainConfigRejectsUnknownFork(t *testing.T) {
	if _, _, err := GetChainConfig("UnknownFork"); err == nil {
		t.Fatalf("expected unknown fork error")
	}
}
