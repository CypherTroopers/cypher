package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/relay"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
)

func relayCLIFixture(t *testing.T) (relayCLIManifest, string) {
	t.Helper()
	root := t.TempDir()
	cfg := &params.ChainConfig{ChainID: big.NewInt(10101919), FairHotstuff: true, FixedCommittee: true, FairHotstuffSeed: common.Hash{19}, GenCommittee: make(params.GenesisCommittee)}
	var nodes []*common.Cnode
	var dexNodes []common.Cnode
	for i := 0; i < 7; i++ {
		var key bls.SecretKey
		if err := key.SetDecString(fmt.Sprint(i + 330)); err != nil {
			t.Fatal(err)
		}
		n := common.Cnode{Address: fmt.Sprintf("127.0.0.1:%d", 32000+i), Public: key.GetPublicKey().SerializeToHexStr(), CoinBase: common.Address{19: byte(i + 1)}.Hex()}
		cfg.GenCommittee[i] = n
		copy := n
		nodes = append(nodes, &copy)
		dexNodes = append(dexNodes, n)
	}
	cfg.DEXDevnet = &params.DEXDevnetConfig{Version: 3, ActivationBlock: 1, DEXID: common.Hash{22}, GenesisSeed: common.Hash{23}, Custody: params.DEXSettlementAddress, Committee: dexNodes, MaxCheckpoints: 128}
	commit, err := params.FairHotstuffGenesisCommitment(cfg)
	if err != nil {
		t.Fatal(err)
	}
	genesis := &types.Header{Number: new(big.Int), Difficulty: big.NewInt(1), Root: types.EmptyRootHash, TxHash: types.EmptyRootHash, ReceiptHash: types.EmptyRootHash, MixDigest: commit}
	domain := protocol.Domain{Version: 1, ChainID: cfg.ChainID.Uint64(), Genesis: protocol.Hash(genesis.Hash()), DEXID: protocol.Hash(cfg.DEXDevnet.DEXID), Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: nodes}).RlpHash())}
	m := relayCLIManifest{Version: 1, Devnet: true, DataDir: filepath.Join(root, "relay"), Domain: domain, Custody: params.DEXSettlementAddress, CLX: clxevidence.Config{ChainID: cfg.ChainID.Uint64(), Genesis: genesis, ChainConfig: cfg, Seed: cfg.FairHotstuffSeed, DEXID: domain.DEXID, Custody: params.DEXSettlementAddress, Epochs: []clxevidence.CommitteeEpoch{{First: 1, End: ^uint64(0), KeyHash: common.Hash{7}, Members: nodes}}}, SourceURL: "http://127.0.0.1:1", SubmitURL: "http://127.0.0.1:1", DEXURL: "http://127.0.0.1:1", MaxHeight: 128, PollMillis: 250, GasPrice: "1000000000", MaxGasCost: "1000000000000000000"}
	for i, lane := range []string{"anchor", "checkpoint", "claim"} {
		secret := fmt.Sprintf("%064x", i+901)
		key, err := crypto.HexToECDSA(secret)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, lane+"-gas.key")
		if err = os.WriteFile(path, []byte(secret), 0600); err != nil {
			t.Fatal(err)
		}
		m.Payers = append(m.Payers, relayCLIPayer{Lane: lane, Purpose: "relay-gas", Address: crypto.PubkeyToAddress(key.PublicKey), KeyFile: path, GasLimit: 15000000})
	}
	return m, root
}
func writeRelayManifest(t *testing.T, m relayCLIManifest, root string) string {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "relay.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDEXRelayCLIExplicitStrictConfiguration(t *testing.T) {
	m, root := relayCLIFixture(t)
	path := writeRelayManifest(t, m, root)
	if _, err := loadRelayCLIManifest(path); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		name string
		fn   func(*relayCLIManifest)
	}{{"devnet", func(m *relayCLIManifest) { m.Devnet = false }}, {"version", func(m *relayCLIManifest) { m.Version = 2 }}, {"relative", func(m *relayCLIManifest) { m.DataDir = "relative" }}, {"dns", func(m *relayCLIManifest) { m.SourceURL = "http://localhost:1234" }}, {"public", func(m *relayCLIManifest) { m.DEXURL = "http://8.8.8.8:80" }}, {"credentials", func(m *relayCLIManifest) { m.SubmitURL = "http://user:secret@127.0.0.1:1234" }}, {"poll", func(m *relayCLIManifest) { m.PollMillis = 1 }}, {"height", func(m *relayCLIManifest) { m.MaxHeight = 129 }}, {"gasdecimal", func(m *relayCLIManifest) { m.GasPrice = "01" }}, {"payerpurpose", func(m *relayCLIManifest) {
		m.Payers = append([]relayCLIPayer(nil), m.Payers...)
		m.Payers[0].Purpose = "recipient"
	}}, {"duplicatepayerlane", func(m *relayCLIManifest) {
		m.Payers = append([]relayCLIPayer(nil), m.Payers...)
		m.Payers[1].Lane = "anchor"
	}}, {"recipient", func(m *relayCLIManifest) { m.DeferredRecipients = []common.Address{m.Payers[0].Address} }}} {
		t.Run(change.name, func(t *testing.T) {
			changed := m
			change.fn(&changed)
			if _, err := changed.config(); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
	encoded, _ := json.Marshal(m)
	for _, raw := range [][]byte{append(append([]byte(nil), encoded...), []byte(" {}")...), append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(",\"Unknown\":true}")...), append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(",\"version\":1}")...)} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadRelayCLIManifest(path); err == nil {
			t.Fatal("nonstrict JSON accepted")
		}
	}
	var nested map[string]interface{}
	if err := json.Unmarshal(encoded, &nested); err != nil {
		t.Fatal(err)
	}
	nested["CLX"].(map[string]interface{})["ChainConfig"].(map[string]interface{})["ignoredUnknownField"] = true
	badNested, _ := json.Marshal(nested)
	if err := os.WriteFile(path, badNested, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRelayCLIManifest(path); err == nil {
		t.Fatal("custom nested decoder discarded unknown field")
	}
	count := 0
	for _, command := range app.Commands {
		if command.Name == "dex-relay" {
			count++
		}
	}
	if count != 1 {
		t.Fatal("explicit command registration", count)
	}
	for _, flag := range nodeFlags {
		if strings.Contains(flag.GetName(), "relay") {
			t.Fatal("relay enabled by node defaults")
		}
	}
}

func TestDEXRelayCLIPrivateGasKeysAndSigner(t *testing.T) {
	m, _ := relayCLIFixture(t)
	c, err := m.config()
	if err != nil {
		t.Fatal(err)
	}
	s, err := loadRelayLocalSigner(m, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	call, _ := (protocol.NativeCall{Operation: protocol.NativeAnchorUpdate, Body: []byte{1}}).Encode()
	tx := types.NewTransaction(0, c.Custody, new(big.Int), c.GasLimits[relay.Anchor], c.GasPrice, call)
	signed, err := s.Sign(context.Background(), c.Payers[relay.Anchor], tx, new(big.Int).SetUint64(c.Domain.ChainID))
	if err != nil {
		t.Fatal(err)
	}
	sender, err := types.Sender(types.NewEIP155Signer(new(big.Int).SetUint64(c.Domain.ChainID)), signed)
	if err != nil || sender != c.Payers[relay.Anchor] {
		t.Fatal("dedicated signer", err)
	}
	for _, bad := range []*types.Transaction{types.NewTransaction(0, c.Custody, big.NewInt(1), tx.Gas(), tx.GasPrice(), call), types.NewTransaction(0, common.Address{99}, new(big.Int), tx.Gas(), tx.GasPrice(), call), types.NewTransaction(0, c.Custody, new(big.Int), 1, tx.GasPrice(), call)} {
		if _, err = s.Sign(context.Background(), sender, bad, new(big.Int).SetUint64(c.Domain.ChainID)); err == nil {
			t.Fatal("changed template signed")
		}
	}
	funding, _ := (protocol.NativeCall{Operation: protocol.NativeDeposit}).Encode()
	if _, err = s.Sign(context.Background(), sender, types.NewTransaction(0, c.Custody, new(big.Int), tx.Gas(), tx.GasPrice(), funding), new(big.Int).SetUint64(c.Domain.ChainID)); err == nil {
		t.Fatal("funding signed")
	}
	if err = os.Chmod(m.Payers[0].KeyFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = loadRelayLocalSigner(m, c); err == nil {
		t.Fatal("loose key accepted")
	}
	os.Chmod(m.Payers[0].KeyFile, 0600)
	link := m.Payers[0].KeyFile + ".link"
	if err = os.Symlink(m.Payers[0].KeyFile, link); err != nil {
		t.Fatal(err)
	}
	bad := m
	bad.Payers = append([]relayCLIPayer(nil), m.Payers...)
	bad.Payers[0].KeyFile = link
	if _, err = loadRelayLocalSigner(bad, c); err == nil {
		t.Fatal("symlink key accepted")
	}
	bad.Payers[0].KeyFile = m.Payers[0].KeyFile
	bad.Payers[0].Address = common.Address{88}
	if _, err = loadRelayLocalSigner(bad, c); err == nil {
		t.Fatal("mismatched key accepted")
	}
}

type relayLoopProbe struct {
	discover, steps, status int
	stepErr                 error
}

func (p *relayLoopProbe) Discover(context.Context) error {
	p.discover++
	return errors.New("transient discovery unavailable")
}
func (p *relayLoopProbe) Step(context.Context) error     { p.steps++; return p.stepErr }
func (p *relayLoopProbe) WriteStatus(error, error) error { p.status++; return nil }
func TestDEXRelayCLILoopAndPrivatePaths(t *testing.T) {
	p := new(relayLoopProbe)
	if err := relayCLILoop(context.Background(), time.Millisecond, true, p); err == nil || p.steps != 1 || p.status != 1 {
		t.Fatal("discovery failure skipped Step/status", err, p)
	}
	p = &relayLoopProbe{stepErr: relay.ErrStore}
	if err := relayCLILoop(context.Background(), time.Millisecond, false, p); !errors.Is(err, relay.ErrStore) || p.steps != 1 {
		t.Fatal("store fault did not stop loop", err)
	}
	root := filepath.Join(t.TempDir(), "relay")
	lock, err := prepareRelayCLIRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareRelayCLIRoot(root); err == nil {
		t.Fatal("double CLI owner")
	}
	if err = lock.Close(); err != nil {
		t.Fatal(err)
	}
	lock, err = prepareRelayCLIRoot(root)
	if err != nil {
		t.Fatal("lock not released", err)
	}
	lock.Close()
	if _, err = prepareRelayCLIRoot(t.TempDir()); err == nil {
		t.Fatal("unowned directory adopted")
	}
	status := relay.NetworkStatus{DEXSequence: 4, CLXSequence: 3, CLXSequenceVerified: true}
	records := []relay.Record{{Job: relay.Job{ID: protocol.Hash{1}, Lane: relay.Claim}, Phase: "submitted", Attempt: relay.Attempt{Nonce: 5, GasLimit: 100, Hash: common.Hash{2}, ACK: common.Hash{2}}}}
	if err = relayStatus(root, status, records, nil, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"rpc_ack_observed": true`)) || !bytes.Contains(raw, []byte(`"Phase": "submitted"`)) {
		t.Fatal("ACK mislabeled", string(raw))
	}
	if bytes.Contains(raw, []byte("Authorization")) || bytes.Contains(raw, []byte("Private")) {
		t.Fatal("status exposes proof/key")
	}
	many := make([]relay.Record, relay.MaxActive+relay.MaxHistory)
	for i := range many {
		many[i].Phase = "waiting"
		many[i].LastError = strings.Repeat("e", 512)
	}
	if err = relayStatus(root, status, many, nil, nil); err != nil {
		t.Fatal("full retained queue status", err)
	}
	raw, _ = os.ReadFile(filepath.Join(root, "status.json"))
	var full relayCLIStatus
	if err = json.Unmarshal(raw, &full); err != nil || full.TotalJobs != len(many) || !full.JobsTruncated || len(full.Jobs) != 256 || full.Counts["waiting"] != len(many) {
		t.Fatal("bounded status summary", err)
	}
	if err = relayStatus(root, status, make([]relay.Record, relay.MaxActive+relay.MaxHistory+1), nil, nil); err == nil {
		t.Fatal("status record bound")
	}
}

func TestDEXRelayCLIRealCommandFiniteRunAndSignal(t *testing.T) {
	m, root := relayCLIFixture(t)
	path := writeRelayManifest(t, m, root)
	before := map[string][32]byte{}
	for _, p := range m.Payers {
		b, _ := os.ReadFile(p.KeyFile)
		before[p.KeyFile] = sha256.Sum256(b)
	}
	finite := startOwnedCLI(t, root, "dex-relay", "--relay.config", path, "--relay.duration", "150ms")
	finite.wait(t)
	raw, err := os.ReadFile(filepath.Join(m.DataDir, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	var status relayCLIStatus
	if err = json.Unmarshal(raw, &status); err != nil {
		t.Fatal(err)
	}
	if status.Authenticated.SourceAnchor.Height != 0 || status.Authenticated.CLXSequenceVerified || status.Authenticated.DEXSequence != 0 || len(status.Jobs) != 0 || status.DiscoveryError == "" {
		t.Fatal("unavailable endpoints manufactured progress", string(raw))
	}
	// Resume the same owned stores through the real command, then signal only
	// this newly spawned relay. No operational node PID is discovered or killed.
	if err = os.Remove(filepath.Join(m.DataDir, "status.json")); err != nil {
		t.Fatal(err)
	}
	owned := startOwnedCLI(t, root, "dex-relay", "--relay.config", path, "--relay.duration", "10s")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(m.DataDir, "status.json")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("relay child did not write status")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err = owned.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	owned.wait(t)

	lock, err := prepareRelayCLIRoot(m.DataDir)
	if err != nil {
		t.Fatal("SIGINT failed to release owned locks", err)
	}
	lock.Close()
	for path, sum := range before {
		raw, _ := os.ReadFile(path)
		if sha256.Sum256(raw) != sum {
			t.Fatal("gas key file changed")
		}
	}
}

func TestDEXRelayCLIOrphanStatusRecovery(t *testing.T) {
	root := filepath.Join(t.TempDir(), "relay")
	lock, err := prepareRelayCLIRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = relayStatus(root, relay.NetworkStatus{}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	lock.Close()
	canonical, _ := os.ReadFile(filepath.Join(root, "status.json"))
	for i := 0; i < 20; i++ {
		if err = os.WriteFile(filepath.Join(root, "status.next"), []byte("{partial"), 0600); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			os.WriteFile(filepath.Join(root, "status-legacy.tmp"), []byte("legacy partial"), 0600)
			os.WriteFile(filepath.Join(root, "unrelated.tmp"), []byte("protected"), 0600)
		}
		lock, err = prepareRelayCLIRoot(root)
		if err != nil {
			t.Fatal(err)
		}
		lock.Close()
		after, _ := os.ReadFile(filepath.Join(root, "status.json"))
		if !bytes.Equal(after, canonical) {
			t.Fatal("operational canonical summary changed")
		}
		entries, _ := os.ReadDir(root)
		if len(entries) != 4 {
			t.Fatal("orphan status disk accumulation", len(entries))
		}
	}
	if raw, _ := os.ReadFile(filepath.Join(root, "unrelated.tmp")); string(raw) != "protected" {
		t.Fatal("unrelated file changed")
	}
	os.WriteFile(filepath.Join(root, "status.next"), []byte("partial"), 0600)
	os.WriteFile(filepath.Join(root, "status.json"), []byte("bad"), 0600)
	if _, err = prepareRelayCLIRoot(root); err == nil {
		t.Fatal("corrupt canonical summary accepted")
	}
	if _, err = os.Stat(filepath.Join(root, "status.next")); err != nil {
		t.Fatal("orphan removed before canonical parse")
	}
}
