package clxevidence_test

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/service/finance"
)

func TestRollingInboxDuplicateAdmissionUsesOnlyKnownAuthenticatedBytes(t *testing.T) {
	f, chain := rollingFinancialFixture(t, 32)
	base, err := chain.Verifier.BootstrapAnchor()
	if err != nil {
		t.Fatal(err)
	}
	evidence := chain.Evidence(t, base, 32, 0, true)
	raw, err := devnet.EncodeRollingInboxAction(evidence)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := finance.OpenPool(filepath.Join(t.TempDir(), "pool"), f.execution)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if fresh, err := pool.Admit(raw); err != nil || !fresh {
		t.Fatal("first immutable authentication", err)
	}
	// Deliberately make the immutable authenticator unavailable after first
	// authentication. Only exact known bytes may take the admission cache path;
	// this test fault is never a supported configuration change.
	verifier := f.execution.Native.Verifier
	f.execution.Native.Verifier = nil
	begin := time.Now()
	for i := 0; i < 100; i++ {
		if fresh, err := pool.Admit(raw); err != nil || fresh {
			t.Fatal("known bytes reran unavailable authenticator", err)
		}
	}
	elapsed := time.Since(begin)
	changed := bytes.Clone(raw)
	changed[len(changed)-1] ^= 1
	if _, err = pool.Admit(changed); err == nil {
		t.Fatal("changed payload inherited authentication")
	}
	f.execution.Native.Verifier = verifier
	if len(pool.Pending()) != 1 || !bytes.Equal(pool.Pending()[0], raw) {
		t.Fatal("duplicate altered authenticated pending data")
	}
	t.Logf("duplicate ingress observations only: headers=32 bytes=%d knownRetries=100 elapsed=%s; no consensus/financial execution bypass", len(raw), elapsed)
}
