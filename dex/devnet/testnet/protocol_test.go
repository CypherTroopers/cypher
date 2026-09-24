package testnet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/params"
)

func TestProcessEnvelopeIndependentGoldenAndBounds(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/process.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector map[string]string
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	vote, err := encodeVote([]byte("reference-fixture"), []byte("rlp-structural-only"))
	if err != nil {
		t.Fatal(err)
	}
	record, err := extension(extensionRecord, []byte(`{"fixture":1}`))
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][]byte{"vote": vote, "request": requestData(0x0102030405060708), "record": record} {
		want, e := hex.DecodeString(vector[name])
		if e != nil || !bytes.Equal(got, want) {
			t.Fatalf("golden %s: %v", name, e)
		}
		kind, body, e := decodeExtension(got)
		if e != nil {
			t.Fatal(e)
		}
		if name == "vote" {
			ref, v, e := decodeVote(body)
			if kind != extensionVote || e != nil || string(ref) != "reference-fixture" || string(v) != "rlp-structural-only" {
				t.Fatal("vote decode", e)
			}
		}
	}
	for i := 0; i < len(vote); i++ {
		_, body, e := decodeExtension(vote[:i])
		if e == nil {
			_, _, e = decodeVote(body)
		}
		if e == nil {
			t.Fatalf("truncated vote %d accepted", i)
		}
	}
	if _, _, err = decodeVote(append(vote[9:], 0)); err == nil {
		t.Fatal("trailing vote accepted")
	}
	if _, err = encodeVote(make([]byte, 2049), []byte{1}); err == nil {
		t.Fatal("oversized ref")
	}
	if _, err = extension(extensionRecord, make([]byte, 131064)); err == nil {
		t.Fatal("oversized record")
	}
}

func TestNativeRegistrationMatchesAuthenticatedGenesis(t *testing.T) {
	seed := protocol.Hash{1}
	c := Init{Domain: protocol.Domain{Version: 1, Epoch: 1, Genesis: protocol.Hash{2}, DEXID: protocol.Hash{3}}, MaxHeight: 19}
	c.Market.CLXHash, c.Market.Custody = c.Domain.Genesis, [20]byte{4}
	d := &params.DEXDevnetConfig{Version: 2, ActivationBlock: 1, GenesisSeed: common.Hash(seed), DEXID: common.Hash(c.Domain.DEXID), Custody: common.Address(c.Market.Custody), MaxCheckpoints: 20}
	for i := 0; i < 7; i++ {
		m := common.Cnode{Address: string(rune('a' + i))}
		c.Members = append(c.Members, &m)
		d.Committee = append(d.Committee, m)
	}
	c.CLX.ChainConfig = &params.ChainConfig{DEXDevnet: d}
	if err := validateNativeRegistration(c, seed); err != nil {
		t.Fatal(err)
	}
	if err := validateNativeRegistration(c, protocol.Hash{9}); err == nil {
		t.Fatal("arbitrary oracle seed accepted")
	}
	for _, mutate := range []func(*Init){
		func(x *Init) { x.Domain.DEXID[0]++ }, func(x *Init) { x.Market.Custody[0]++ }, func(x *Init) { x.Domain.Epoch++ }, func(x *Init) { x.MaxHeight = 21 }, func(x *Init) { x.Market.CLXHeight = 1 }, func(x *Init) { x.Market.CLXHash[0]++ },
	} {
		changed := c
		mutate(&changed)
		if err := validateNativeRegistration(changed, seed); err == nil {
			t.Fatal("uncommitted config accepted")
		}
	}
	d.Committee[0], d.Committee[1] = d.Committee[1], d.Committee[0]
	if err := validateNativeRegistration(c, seed); err == nil {
		t.Fatal("reordered committee accepted")
	}
}
func TestProcessAuthenticatedQueueConflictAndPersistenceUncertainty(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	domain := protocol.Domain{Version: 1, ChainID: 7, Genesis: protocol.Hash{1}, DEXID: protocol.Hash{2}, Epoch: 1, Committee: protocol.Hash{3}}
	oracle := [20]byte(crypto.PubkeyToAddress(key.PublicKey))
	market, err := engine.New(engine.Config{Domain: domain, Oracle: oracle, Custody: [20]byte{1}, Support: "0", Insurance: "0", CLXHash: domain.Genesis})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "queue")
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	n := &node{dir: dir, config: Init{MaxHeight: 128}, disk: actionDisk{protocol.Hash{1}, map[uint64][]byte{}, map[string][]byte{}}, execution: &devnet.Execution{Market: market}}
	a := engine.Action{Version: 1, Epoch: domain.EpochKey(), Kind: engine.Noop, Owner: oracle, Nonce: 1}
	action, err := engine.Sign(a, key)
	if err != nil {
		t.Fatal(err)
	}
	// Authenticated oracle intent without the required period witnesses is not
	// an admission reservation. Ordinary market work can use the same height.
	closeIntent := a
	closeIntent.Kind = engine.RewardClose
	closeIntent.Target = [20]byte{1}
	missingWitness, err := engine.Sign(closeIntent, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = n.admit(1, missingWitness); err == nil || len(n.disk.Actions) != 0 {
		t.Fatal("missing reward witness reserved market height", err)
	}
	if err = n.admit(1, action); err != nil {
		t.Fatal(err)
	}
	if err = n.admit(1, action); err != nil {
		t.Fatal("same bytes should retry", err)
	}
	bad := bytes.Clone(action)
	bad[len(bad)-1] ^= 1
	if err = n.admit(2, bad); err == nil {
		t.Fatal("bad auth accepted")
	}
	a.Nonce++
	different, _ := engine.Sign(a, key)
	if err = n.admit(1, different); err == nil {
		t.Fatal("conflict replaced queue")
	}
	var restored actionDisk
	if err = loadFile(dir, "actions.json", &restored); err != nil || !bytes.Equal(restored.Actions[1], action) || len(restored.Actions) != 1 {
		t.Fatal("durable queue", err)
	}
	moved := dir + ".moved"
	if err = os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err = n.admit(2, different); err == nil {
		t.Fatal("missing persistence accepted")
	}
	if err = os.Rename(moved, dir); err != nil {
		t.Fatal(err)
	}
	if err = n.admit(2, different); err == nil {
		t.Fatal("uncertain writer silently resumed")
	}
	if len(n.disk.Actions) != 1 {
		t.Fatal("failed commit mutated live queue")
	}
	// The independent engine transition still succeeds without closing rewards.
	s, err := market.Genesis()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = market.Apply(s, action, 1); err != nil {
		t.Fatal("ordinary action waited for unavailable reward period", err)
	}
}
func TestProcessIdentityOwnershipAndRestart(t *testing.T) {
	if os.Getenv("CYPHER_DEX_SOCKET_DEVNET") != "1" {
		t.Skip("opt-in isolated namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Flags&net.FlagLoopback == 0 {
		t.Fatal("loopback-only namespace", err)
	}
	dir := filepath.Join(t.TempDir(), "child")
	d, lock, err := openIdentity(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{d.Public.Peer.Address, d.Public.API} {
		host, _, err := net.SplitHostPort(endpoint)
		if err != nil || host != "127.0.0.2" {
			t.Fatal("financial fixture requires its own loopback IP", endpoint, err)
		}
	}
	if _, unexpected, e := openIdentity(dir, 0); e == nil {
		unexpected.Close()
		t.Fatal("duplicate helper owns same dir")
	}
	lock.Close()
	again, lock, err := openIdentity(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	lock.Close()
	if d.Public.Peer != again.Public.Peer || !bytes.Equal(d.Secret, again.Secret) || !bytes.Equal(d.TLSPrivate, again.TLSPrivate) {
		t.Fatal("restart changed identity")
	}
	if _, unexpected, e := openIdentity(dir, 1); e == nil {
		unexpected.Close()
		t.Fatal("index rebound")
	}
	occupied := t.TempDir()
	if _, unexpected, e := openIdentity(occupied, 0); e == nil {
		unexpected.Close()
		t.Fatal("unmarked path modified")
	}
}
