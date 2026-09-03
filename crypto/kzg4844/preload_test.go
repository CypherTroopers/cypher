// Copyright 2026 The Cypherium Authors

package kzg4844

import "testing"

func TestPreloadIsIdempotentAndPublishesReadiness(t *testing.T) {
	if err := UseCKZG(false); err != nil {
		t.Fatalf("select Go KZG backend: %v", err)
	}
	Preload()
	Preload()
	if !Preloaded() {
		t.Fatal("selected KZG backend is not marked ready after preload")
	}
	PreloadAndFreeze()
	if err := UseCKZG(false); err != nil {
		t.Fatalf("idempotent frozen backend selection failed: %v", err)
	}
	if err := UseCKZG(true); err == nil {
		t.Fatal("different backend selection succeeded after native startup freeze")
	}
	if useCKZG.Load() || !Preloaded() {
		t.Fatal("rejected backend switch changed the selected ready context")
	}
}
