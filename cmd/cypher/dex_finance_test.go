package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/service"
	"github.com/cypherium/cypher/dex/transport"
	"github.com/cypherium/cypher/eth"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	ldb "github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// This smoke proves normal-CLI ownership and authenticated financial admission.
// Actual funded CLX evidence/settlement is the separate21-process network test.
func TestDEXNormalCLINativeFinanceSmoke(t *testing.T) {
	testDEXNormalCLINativeFinance(t, false)
}

func TestDEXNormalCLINativeFinanceRestart(t *testing.T) {
	testDEXNormalCLINativeFinance(t, true)
}

func TestDEXNormalCLILeaderSubmissionLifecycle(t *testing.T) {
	testDEXNormalCLINativeFinance(t, true, true)
}

func testDEXNormalCLINativeFinance(t *testing.T, restart bool, integrated ...bool) {
	t.Helper()
	leaderSubmission := len(integrated) == 1 && integrated[0]
	if os.Getenv("CYPHER_DEX_CLI_DEVNET") != "1" {
		t.Skip("opt-in isolated CLI namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Flags&net.FlagLoopback == 0 {
		t.Fatal("loopback-only namespace required", err)
	}
	root := t.TempDir()
	raw, err := os.ReadFile("../../genesis.json")
	if err != nil {
		t.Fatal(err)
	}
	var genesis core.Genesis
	if err = json.Unmarshal(raw, &genesis); err != nil {
		t.Fatal(err)
	}
	endpoint := freeEndpoint(t)
	_, rnet, _ := net.SplitHostPort(endpoint)
	genesis.Config.RnetPort, genesis.Config.EnabledTPS = rnet, eth.DefaultConfig.EnableTPS
	var clxMembers []*common.Cnode
	for i := 0; i < 7; i++ {
		m := genesis.Config.GenCommittee[i]
		m.Address = fmt.Sprintf("127.0.0.1:%d", 29000+i)
		genesis.Config.GenCommittee[i] = m
		clxMembers = append(clxMembers, &m)
	}
	oracleKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	oracle := [20]byte(crypto.PubkeyToAddress(oracleKey.PublicKey))
	seed, err := protocol.NativeMarketSeed(oracle)
	if err != nil {
		t.Fatal(err)
	}
	manifests := cliManifests(t, root, protocol.Hash{1}, genesis.Config.ChainID.Uint64())
	members := manifests[0].Members
	var registered []common.Cnode
	for i, m := range members {
		m.CoinBase = common.Address(manifests[0].Peers[i].RewardRecipient).Hex()
		registered = append(registered, *m)
	}
	genesis.Config.DEXDevnet = &params.DEXDevnetConfig{Version: 2, ActivationBlock: 1, DEXID: common.Hash(manifests[0].Domain.DEXID), GenesisSeed: common.Hash(seed), Custody: params.DEXSettlementAddress, Committee: registered, MaxCheckpoints: 32}
	if leaderSubmission {
		genesis.Config.DEXDevnet.Version = 5
	}
	genesis.Mixhash, err = params.FairHotstuffGenesisCommitment(genesis.Config)
	if err != nil {
		t.Fatal(err)
	}
	genesisBlock := genesis.ToBlock(nil)
	domain := manifests[0].Domain
	domain.Genesis = protocol.Hash(genesisBlock.Hash())
	domain.Committee = protocol.Hash((&bftview.Committee{List: members}).RlpHash())
	paths := make([]string, 7)
	for i := range manifests {
		m := &manifests[i]
		m.Domain, m.CLXHash, m.Mode, m.MaxHeight = domain, domain.Genesis, "native-finance", 32
		// No CLX block/evidence is served in this startup-only fixture. Its explicit
		// trusted key-hash marker is not represented as a measured network history.
		cfg := clxevidence.Config{ChainID: domain.ChainID, Genesis: genesisBlock.Header(), ChainConfig: genesis.Config, Seed: genesis.Config.FairHotstuffSeed, DEXID: domain.DEXID, Custody: params.DEXSettlementAddress, Epochs: []clxevidence.CommitteeEpoch{{First: 1, End: math.MaxUint64, KeyHash: common.Hash{91}, Members: clxMembers}}}
		m.Finance = &service.NativeConfig{Market: engine.Config{Domain: domain, Oracle: oracle, Custody: [20]byte(params.DEXSettlementAddress), Support: "0", Insurance: "0", CLXHash: domain.Genesis, NativeInbox: true}, CLX: cfg, ReceiptHeights: []uint64{5}}
		if leaderSubmission {
			m.Version, m.StorageGenerations, m.ArchiveBudgetBytes = 2, true, consensus.DefaultArchiveBudgetBytes
			m.Finance.ReceiptHeights = nil
			r, configRoot := relayCLIFixture(t)
			r.Version = 2
			r.Domain, r.CLX, r.MaxHeight = domain, cfg, m.MaxHeight
			r.DataDir, r.DEXURL = filepath.Join(m.DataDir, "submission"), "http://"+m.APIListen
			for j := range r.Payers {
				r.Payers[j].Purpose = "leader-submission-gas"
			}
			m.LeaderSubmission = writeRelayManifest(t, r, configRoot)
		}
		data, e := json.Marshal(m)
		if e != nil {
			t.Fatal(e)
		}
		paths[i] = filepath.Join(root, fmt.Sprintf("native-%d.json", i))
		if e = os.WriteFile(paths[i], data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	genesisFile := filepath.Join(root, "genesis.json")
	raw, err = json.Marshal(genesis)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(genesisFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	datadir := filepath.Join(root, "common")
	init := startOwnedCLI(t, root, "--datadir", datadir, "--nat", "extip:127.0.0.1", "--rnetport", rnet, "init", genesisFile)
	init.wait(t)
	if restart {
		readNativeCLIClosedGenesis(t, datadir, "after-init")
	}
	ipcDir, err := os.MkdirTemp("", "native-cli-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(ipcDir) })
	ipc := filepath.Join(ipcDir, "node.ipc")
	parent := startOwnedCLI(t, root, "--datadir", datadir, "--nat", "extip:127.0.0.1", "--rnetport", rnet, "--port", "0", "--nodiscover", "--maxpeers", "0", "--ipcpath", ipc, "--syncmode", "full", "--cache", "32", "--cache.trie.journal", "", "--dex.validator", "--dex.config", paths[0])
	client := waitIPC(t, ipc, parent)
	defer client.Close()
	var children []*ownedCLI
	for i := 1; i < 7; i++ {
		children = append(children, startOwnedCLI(t, root, "dex-validator", "--dex.config", paths[i]))
	}
	t.Cleanup(func() {
		if t.Failed() {
			for _, p := range append(children, parent) {
				b, _ := os.ReadFile(p.log)
				if len(b) > 5000 {
					b = b[len(b)-5000:]
				}
				t.Logf("owned CLI log %s: %s", p.log, b)
			}
		}
	})
	deadline := time.Now().Add(20 * time.Second)
	for {
		ready := true
		for _, m := range manifests {
			status, e := readDEXStatus(m.APIListen)
			if e != nil || status.State != "active" {
				ready = false
			}
			if leaderSubmission {
				raw, e := os.ReadFile(filepath.Join(m.DataDir, "submission", "status.json"))
				var submission relayCLIStatus
				if e != nil || json.Unmarshal(raw, &submission) != nil || !submission.LeaderIntegrated || submission.Leader == nil {
					ready = false
				}
			}
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native sidecar startup timeout")
		}
		time.Sleep(50 * time.Millisecond)
	}
	var mining bool
	if err = client.Call(&mining, "eth_mining"); err != nil || mining {
		t.Fatal("native DEX changed PoW state", mining, err)
	}
	httpClient := http.Client{Timeout: 3 * time.Second}
	post := func(body []byte) int {
		r, e := httpClient.Post("http://"+manifests[0].APIListen+"/v1/actions", "application/octet-stream", bytes.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		return r.StatusCode
	}
	if status := post([]byte("unauthenticated")); status != 400 {
		t.Fatal("unsigned financial action accepted", status)
	}
	action, err := engine.Sign(engine.Action{Version: 1, Epoch: domain.EpochKey(), Owner: oracle, Kind: engine.Noop, Nonce: 1}, oracleKey)
	if err != nil {
		t.Fatal(err)
	}
	if status := post(action); status != 202 {
		t.Fatal("signed ingress not admitted", status)
	}
	id := protocol.Digest("common-dex/ingress-action/v1", action)
	rejected := false
	deadline = time.Now().Add(15 * time.Second)
	for !rejected && time.Now().Before(deadline) {
		for _, m := range manifests {
			r, e := httpClient.Get("http://" + m.APIListen + "/v1/action-status?id=" + hex.EncodeToString(id[:]))
			if e != nil {
				continue
			}
			var status map[string]string
			json.NewDecoder(r.Body).Decode(&status)
			r.Body.Close()
			if status["stage"] == "rejected" {
				rejected = true
				t.Logf("pre-inbox economic rejection: %s", status["reason"])
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !rejected {
		t.Fatal("pre-inbox action was not rejected by actual parent-state selection")
	}
	r, err := httpClient.Get("http://" + manifests[0].APIListen + "/v1/checkpoint?height=1")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 503 {
		t.Fatal("missing finalized data reported available", r.StatusCode)
	}
	parent.stop(t)
	if _, err = readDEXStatus(manifests[0].APIListen); err == nil {
		t.Fatal("Common shutdown left its financial sidecar running")
	}
	if restart {
		before := readNativeCLIClosedGenesis(t, datadir, "after-parent-stop-before-probe")
		bad := manifests[0]
		bad.Peers = append([]transport.Peer(nil), bad.Peers...)
		bad.Peers[0].RewardRecipient[0] ^= 1
		encoded, e := json.Marshal(bad)
		if e != nil {
			t.Fatal(e)
		}
		badPath := filepath.Join(root, "bad-recipient.json")
		if e = os.WriteFile(badPath, encoded, 0600); e != nil {
			t.Fatal(e)
		}
		probe := startOwnedCLI(t, root, "dex-validator", "--dex.config", badPath)
		select {
		case e = <-probe.done:
			if e == nil {
				t.Fatal("changed recipient reopened financial service")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("changed recipient startup did not fail promptly")
		}
		after := readNativeCLIClosedGenesis(t, datadir, "after-probe")
		if before != after {
			t.Fatal("sidecar recipient probe changed closed Common genesis mappings")
		}
		previous := parent
		t.Logf("RESTART_SAME_ARGS executable=%s args=%q", previous.cmd.Path, previous.cmd.Args[1:])
		parent = startOwnedCLI(t, root, previous.cmd.Args[1:]...)
		reopened := waitIPC(t, ipc, parent)
		defer reopened.Close()
		deadline = time.Now().Add(10 * time.Second)
		for {
			status, e := readDEXStatus(manifests[0].APIListen)
			if e == nil && status.State == "active" && status.Error == "" {
				if !leaderSubmission {
					break
				}
				raw, e := os.ReadFile(filepath.Join(manifests[0].DataDir, "submission", "status.json"))
				var submission relayCLIStatus
				if e == nil && json.Unmarshal(raw, &submission) == nil && submission.LeaderIntegrated && submission.Leader != nil {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatal("same-datadir native sidecar restart unavailable", status, e)
			}
			time.Sleep(50 * time.Millisecond)
		}
		if e = reopened.Call(&mining, "eth_mining"); e != nil || mining {
			t.Fatal("restart changed PoW state", mining, e)
		}
		t.Logf("native Common restarted same datadir=%s without init; oldPID=%d newPID=%d; rejected recipient probe before restart", datadir, previous.cmd.Process.Pid, parent.cmd.Process.Pid)
		parent.stop(t)
	}
	if leaderSubmission {
		t.Log("seven existing validator processes own submission workers; Common stop/restart joins worker and reopens same journals; no extra relay process and no funded settlement claimed")
	}
	t.Log("ordinary Common owns native-finance child; seven real TLS peers; signed HTTP admission and economic rejection; no PoW nonce work, no funded CLX scenario in this smoke")
}

func readNativeCLIClosedGenesis(t *testing.T, datadir, stage string) [2]common.Hash {
	t.Helper()
	path := filepath.Join(datadir, "cypher", "chaindata")
	db, err := ldb.OpenFile(path, &opt.Options{ReadOnly: true})
	if err != nil {
		t.Fatal("read-only closed fixture database", stage, err)
	}
	defer db.Close()
	var hashes [2]common.Hash
	for i, prefix := range []string{"kb", "h"} {
		key := append(append([]byte(prefix), make([]byte, 8)...), 'n')
		value, e := db.Get(key, nil)
		if e != nil && e != ldb.ErrNotFound {
			t.Fatal("closed genesis mapping read", e)
		}
		hashes[i] = common.BytesToHash(value)
	}
	t.Logf("CLOSED_GENESIS stage=%s path=%s key0=%s tx0=%s", stage, path, hashes[0].Hex(), hashes[1].Hex())
	return hashes
}
