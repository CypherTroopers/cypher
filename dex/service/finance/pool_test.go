package finance

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
	"github.com/cypherium/cypher/reconfig/bftview"
)

func poolFixture(t *testing.T) (*devnet.Execution, *ecdsa.PrivateKey, []byte, consensus.ExecutionContext) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	oracle := [20]byte(crypto.PubkeyToAddress(key.PublicKey))
	members := make([]*common.Cnode, 7)
	recipients := make([][20]byte, 7)
	for i := range members {
		var sk bls.SecretKey
		sk.SetDecString(fmt.Sprint(i + 200))
		recipients[i][19] = byte(i + 1)
		members[i] = &common.Cnode{Address: fmt.Sprintf("127.0.0.1:%d", 35000+i), Public: sk.GetPublicKey().SerializeToHexStr(), CoinBase: common.Address(recipients[i]).Hex()}
	}
	d := protocol.Domain{Version: 1, ChainID: 7788, Genesis: protocol.Digest("pool-genesis", nil), DEXID: protocol.Digest("pool-dex", nil), Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: members}).RlpHash())}
	m, err := engine.New(engine.Config{Domain: d, Oracle: oracle, Custody: [20]byte{19: 240}, Support: "0", Insurance: "0", CLXHash: d.Genesis})
	if err != nil {
		t.Fatal(err)
	}
	r, err := rewards.NewRegistry(d, members, recipients)
	if err != nil {
		t.Fatal(err)
	}
	e := &devnet.Execution{Market: m, Registry: r}
	s, root, err := e.Genesis()
	if err != nil {
		t.Fatal(err)
	}
	return e, key, s, consensus.ExecutionContext{Domain: d, Height: 1, CLXHash: d.Genesis, ParentRoot: root}
}
func poolAction(t *testing.T, e *devnet.Execution, key *ecdsa.PrivateKey, nonce uint64) []byte {
	t.Helper()
	raw, err := engine.Sign(engine.Action{Version: 1, Epoch: e.Market.Domain().EpochKey(), Owner: e.Market.Oracle(), Nonce: nonce, Kind: engine.Noop}, key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestPoolRejectsInvalidCandidateWithoutBlockingNextAndRestarts(t *testing.T) {
	e, key, state, ctx := poolFixture(t)
	dir := filepath.Join(t.TempDir(), "queue")
	p, err := OpenPool(dir, e)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err = OpenPool(dir, e); err == nil {
		t.Fatal("double open")
	}
	bad, good := poolAction(t, e, key, 9), poolAction(t, e, key, 1)
	for _, raw := range [][]byte{bad, good} {
		if fresh, err := p.Admit(raw); err != nil || !fresh {
			t.Fatal("admit", err)
		}
	}
	if fresh, err := p.Admit(good); err != nil || fresh {
		t.Fatal("duplicate", err)
	}
	wrong := ctx
	wrong.ParentRoot[0] ^= 1
	if _, err = p.Select(state, wrong); err == nil || len(p.Pending()) != 2 {
		t.Fatal("bad local parent consumed users' actions")
	}
	got, err := p.Select(state, ctx)
	if err != nil || !bytes.Equal(got, good) {
		t.Fatal("invalid nonce blocked valid next action", err)
	}
	if s, reason := p.Status(poolID(bad)); s != "rejected" || reason == "" {
		t.Fatal(s, reason)
	}
	pending := p.Pending()
	pending[0][0] ^= 1
	if !bytes.Equal(p.Pending()[0], good) {
		t.Fatal("queue alias")
	}
	result, err := e.Execute(state, good, ctx)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Height = 2
	ctx.ParentRoot = result.PostRoot
	if _, err = p.Select(result.State, ctx); !errors.Is(err, consensus.ErrUnavailable) {
		t.Fatal("certified candidate should become locally obsolete", err)
	}
	if err = p.Finalized(1, good); err != nil {
		t.Fatal(err)
	}
	if s, _ := p.Status(poolID(good)); s != "dex_finalized" {
		t.Fatal("finality did not supersede rejection")
	}
	p.Close()
	p, err = OpenPool(dir, e)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if s, _ := p.Status(poolID(good)); s != "dex_finalized" {
		t.Fatal("lost finality")
	}
	if fresh, err := p.Admit(good); err != nil || fresh {
		t.Fatal("restart duplicate", err)
	}
	foreign, _, _, _ := poolFixture(t)
	p.Close()
	if _, err = OpenPool(dir, foreign); err == nil {
		t.Fatal("foreign oracle accepted WAL")
	}
}
func TestPoolBoundsAuthenticationAndPersistenceFailure(t *testing.T) {
	e, key, _, _ := poolFixture(t)
	dir := filepath.Join(t.TempDir(), "queue")
	p, err := OpenPool(dir, e)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	bad := poolAction(t, e, key, 1)
	bad[0] ^= 1
	if _, err = p.Admit(bad); err == nil || len(p.Pending()) != 0 {
		t.Fatal("unauthenticated admission")
	}
	for i := uint64(1); i <= 64; i++ {
		if _, err = p.Admit(poolAction(t, e, key, i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = p.Admit(poolAction(t, e, key, 65)); err == nil {
		t.Fatal("unbounded queue")
	}
	if err = os.Rename(filepath.Join(dir, "pool.json"), filepath.Join(dir, "saved.json")); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(dir, "pool.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = p.Finalized(1, poolAction(t, e, key, 1)); err == nil {
		t.Fatal("persistence failure hidden")
	}
	if _, err = p.Admit(poolAction(t, e, key, 65)); err == nil {
		t.Fatal("continued after uncertain persistence")
	}
	if s, _ := p.Status(poolID(bad)); s != "unavailable" {
		t.Fatal("uncertain status")
	}
	if p.Pending() != nil {
		t.Fatal("gossip after disk failure")
	}
	p.Close()
	if _, err = OpenPool(dir, e); err == nil {
		t.Fatal("invalid WAL recovered")
	}
}
func TestPoolRefusesUnownedAndSymlinkState(t *testing.T) {
	e, _, _, _ := poolFixture(t)
	dir := t.TempDir()
	if _, err := OpenPool(dir, e); err == nil {
		t.Fatal("adopted unrelated directory")
	}
	owned := filepath.Join(dir, "owned")
	p, err := OpenPool(owned, e)
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
	if err = os.Rename(filepath.Join(owned, "pool.json"), filepath.Join(owned, "real.json")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("real.json", filepath.Join(owned, "pool.json")); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenPool(owned, e); err == nil {
		t.Fatal("followed state symlink")
	}
}
