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

func TestGetChainConfigPrague(t *testing.T) {
	cfg, extra, err := GetChainConfig("Prague")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(extra) != 0 {
		t.Fatalf("expected no extra eips, got %v", extra)
	}
	if !cfg.IsPrague(big.NewInt(0), 0) {
		t.Fatal("expected Prague to be active at timestamp 0")
	}
	if cfg.IsOsaka(big.NewInt(0), 0) {
		t.Fatal("expected Osaka to be inactive for Prague config")
	}
	blobs := cfg.ActiveBlobConfig(0)
	if blobs.Target != 6 || blobs.Max != 9 || blobs.BaseFeeUpdateFraction != 5007716 {
		t.Fatalf("unexpected Prague blob schedule: %+v", blobs)
	}
}

func TestGetChainConfigOsaka(t *testing.T) {
	cfg, extra, err := GetChainConfig("Osaka")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(extra) != 0 {
		t.Fatalf("expected no extra eips, got %v", extra)
	}
	if !cfg.IsOsaka(big.NewInt(0), 0) {
		t.Fatal("expected Osaka to be active at timestamp 0")
	}
	if !cfg.IsPrague(big.NewInt(0), 0) || !cfg.IsCancun(big.NewInt(0), 0) {
		t.Fatal("expected prerequisite timestamp forks to be active for Osaka config")
	}
	blobs := cfg.ActiveBlobConfig(0)
	if blobs.Target != 6 || blobs.Max != 9 || blobs.BaseFeeUpdateFraction != 5007716 {
		t.Fatalf("unexpected Osaka blob schedule: %+v", blobs)
	}
}

func TestAvailableForksIncludesPragueAndOsaka(t *testing.T) {
	forks := AvailableForks()
	want := map[string]bool{"Prague": false, "Osaka": false}
	for _, fork := range forks {
		if _, ok := want[fork]; ok {
			want[fork] = true
		}
	}
	for fork, found := range want {
		if !found {
			t.Fatalf("AvailableForks is missing %s", fork)
		}
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
