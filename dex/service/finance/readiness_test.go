package finance

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/instrumentation"
)

func TestTimeoutReadinessIgnoresCertifiedIngressWithoutMutatingQueue(t *testing.T) {
	e, key, parent, ctx := poolFixture(t)
	dir := filepath.Join(t.TempDir(), "pool")
	p, err := OpenPool(dir, e)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { p.Close() }()
	raw := poolAction(t, e, key, 1)
	if _, err = p.Admit(raw); err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(p.Pending()[0])
	if ready, err := p.readyAgainst(parent, ctx); err != nil || !ready {
		t.Fatal("real ingress not ready", ready, err)
	}
	result, err := e.Execute(parent, raw, ctx)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Height++
	ctx.ParentRoot = result.PostRoot
	for i := 0; i < 3; i++ {
		if ready, err := p.readyAgainst(result.State, ctx); err != nil || ready {
			t.Fatal("certified nonce kept idle view busy", ready, err)
		}
	}
	if len(p.Pending()) != 1 || !bytes.Equal(before, p.Pending()[0]) {
		t.Fatal("readiness consumed pending action")
	}
	if stage, _ := p.Status(poolID(raw)); stage != "ingress_admitted" {
		t.Fatal("readiness altered local status", stage)
	}
	wrong := ctx
	wrong.ParentRoot[0] ^= 1
	if ready, err := p.readyAgainst(result.State, wrong); err == nil || ready {
		t.Fatal("corrupt parent treated as idle success")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	p, err = OpenPool(dir, e)
	if err != nil {
		t.Fatal(err)
	}
	if ready, err := p.readyAgainst(result.State, ctx); err != nil || ready {
		t.Fatal("cold queue retriggered certified action", ready, err)
	}
	if _, err = p.Admit(poolAction(t, e, key, 2)); err != nil {
		t.Fatal(err)
	}
	if ready, err := p.readyAgainst(result.State, ctx); err != nil || !ready {
		t.Fatal("next real action failed to rearm", ready, err)
	}
}

func TestTimeoutReadinessCachesEconomicChecksUntilParentOrIngressChanges(t *testing.T) {
	e, key, _, _ := poolFixture(t)
	p, err := OpenPool(filepath.Join(t.TempDir(), "pool"), e)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var keys [7]bls.SecretKey
	members := make([]*common.Cnode, 7)
	for i := range members {
		if err := keys[i].SetDecString(fmt.Sprint(i + 200)); err != nil {
			t.Fatal(err)
		}
		recipient := [20]byte{19: byte(i + 1)}
		members[i] = &common.Cnode{Address: fmt.Sprintf("127.0.0.1:%d", 35000+i), Public: keys[i].GetPublicKey().SerializeToHexStr(), CoinBase: common.Address(recipient).Hex()}
	}
	a, err := consensus.Open(consensus.Config{Domain: e.Market.Domain(), Members: members, Index: 0, Secret: &keys[0], DataDir: filepath.Join(t.TempDir(), "fhs"), CLXHash: e.Market.Domain().Genesis, MaxHeight: 2, Execution: e, ActionsWithParent: p.Select})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err = p.Admit(poolAction(t, e, key, 1)); err != nil {
		t.Fatal(err)
	}
	policy := p.timeoutPolicy()
	if ready, err := policy(a); err != nil || !ready {
		t.Fatal(ready, err)
	}
	count := instrumentation.Execution().Actions
	for i := 0; i < 100; i++ {
		if ready, err := policy(a); err != nil || !ready {
			t.Fatal(ready, err)
		}
	}
	if got := instrumentation.Execution().Actions; got != count {
		t.Fatalf("unchanged readiness reexecuted engine %d times", got-count)
	}
	if _, err = p.Admit(poolAction(t, e, key, 2)); err != nil {
		t.Fatal(err)
	}
	if ready, err := policy(a); err != nil || !ready {
		t.Fatal(ready, err)
	}
	if instrumentation.Execution().Actions <= count {
		t.Fatal("new ingress did not invalidate readiness cache")
	}
}
