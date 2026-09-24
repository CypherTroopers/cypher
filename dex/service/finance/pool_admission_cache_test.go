package finance

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/engine"
)

func TestPoolCachedAdmissionKeepsAuthenticationAndParentExecution(t *testing.T) {
	e, key, parent, ctx := poolFixture(t)
	p, err := OpenPool(filepath.Join(t.TempDir(), "one"), e)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	other, err := OpenPool(filepath.Join(t.TempDir(), "two"), e)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	raw := poolAction(t, e, key, 1)
	for _, pool := range []*Pool{p, other} {
		if fresh, err := pool.Admit(raw); err != nil || !fresh {
			t.Fatal(err)
		}
	}
	before := bytes.Clone(p.Pending()[0])
	for i := 0; i < 5; i++ {
		if fresh, err := p.Admit(raw); err != nil || fresh {
			t.Fatal("known duplicate", err)
		}
	}
	if len(p.Pending()) != 1 || !bytes.Equal(p.Pending()[0], before) {
		t.Fatal("duplicate mutated queue")
	}
	bad := bytes.Clone(raw)
	bad[len(bad)-1] ^= 1
	if _, err = p.Admit(bad); err == nil || len(p.Pending()) != 1 {
		t.Fatal("one-byte changed payload inherited cached authentication")
	}
	foreign := e.Market.Domain()
	foreign.DEXID[0] ^= 1
	foreignRaw, err := engine.Sign(engine.Action{Version: 1, Epoch: foreign.EpochKey(), Owner: e.Market.Oracle(), Nonce: 1, Kind: engine.Noop}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Admit(foreignRaw); err == nil || len(p.Pending()) != 1 {
		t.Fatal("foreign-domain signed payload inherited cache")
	}
	for _, oversized := range [][]byte{nil, make([]byte, consensus.MaxActionBytes+1)} {
		if _, err = p.Admit(oversized); err == nil {
			t.Fatal("prehash bound")
		}
	}
	first, err := e.Execute(parent, raw, ctx)
	if err != nil {
		t.Fatal(err)
	}
	advanced := ctx
	advanced.Height++
	advanced.ParentRoot = first.PostRoot
	if _, err = p.Select(first.State, advanced); !errors.Is(err, consensus.ErrUnavailable) {
		t.Fatal(err)
	}
	if stage, _ := p.Status(poolID(raw)); stage != "rejected" {
		t.Fatal("fixture lacks local status divergence")
	}
	if stage, _ := other.Status(poolID(raw)); stage != "ingress_admitted" {
		t.Fatal("second pool changed", stage)
	}
	// Neither a local cached admission nor rejection participates in validity.
	second, err := e.Execute(parent, raw, ctx)
	if err != nil || first.PostRoot != second.PostRoot || !bytes.Equal(first.State, second.State) {
		t.Fatal("local queue status changed proposal execution", err)
	}
	if err = p.Finalized(1, raw); err != nil {
		t.Fatal(err)
	}
	if fresh, err := p.Admit(raw); err != nil || fresh {
		t.Fatal("finalized history duplicate", err)
	}
}
func TestPoolColdPendingReauthenticatesChecksumValidMutation(t *testing.T) {
	e, key, _, _ := poolFixture(t)
	dir := filepath.Join(t.TempDir(), "queue")
	p, err := OpenPool(dir, e)
	if err != nil {
		t.Fatal(err)
	}
	raw := poolAction(t, e, key, 1)
	if _, err = p.Admit(raw); err != nil {
		t.Fatal(err)
	}
	p.Close()
	p, err = OpenPool(dir, e)
	if err != nil {
		t.Fatal("valid cold pending", err)
	}
	if fresh, err := p.Admit(raw); err != nil || fresh {
		t.Fatal("cold duplicate", err)
	}
	// Change only a signature byte, recompute both item identity and the outer
	// durable checksum. Reopen must still authenticate the pending bytes.
	bad := bytes.Clone(raw)
	bad[len(bad)-1] ^= 1
	want := e.AuthenticateAction(bad)
	if want == nil {
		t.Fatal("invalid signature fixture")
	}
	p.disk.Pending[0] = poolItem{ID: poolID(bad), Raw: bad}
	if err = p.save(); err != nil {
		t.Fatal(err)
	}
	p.Close()
	if restored, err := OpenPool(dir, e); err == nil {
		restored.Close()
		t.Fatal("cold pending signature not authenticated")
	} else if err.Error() != want.Error() {
		t.Fatalf("wrong cold rejection got=%v want=%v", err, want)
	}
	// The original owner's key was never modified by either queue operation.
	if crypto.PubkeyToAddress(key.PublicKey) != e.Market.Oracle() {
		t.Fatal("key ownership changed")
	}
}
