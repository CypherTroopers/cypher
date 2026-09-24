package reconfig_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/dex/devnet/testnet"
	"github.com/cypherium/cypher/dex/service"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rpc"
)

// A normal Common process supervises its own ordinary native-finance sidecar.
// The preceding bootstrap helper only generated owned devnet keys; it is killed
// before this process starts and does not execute any financial action.
type financialCLI struct {
	parent       *exec.Cmd
	done         chan error
	sidecar      *os.Process
	api, logPath string
	client       *http.Client
	stopped      bool
	manifest     service.Manifest
	manifestPath string
	ruleChain    string
}

func startFinancialCLI(t *testing.T, binary, root string, identity testnet.Identity, init testnet.Init, genesis *core.Genesis, index int, options ...func(*service.Manifest)) *dexFinancialChild {
	t.Helper()
	if !filepath.IsAbs(binary) {
		t.Fatal("absolute separately built devnet CLI required")
	}
	dir := filepath.Join(root, fmt.Sprintf("common-%d", index))
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	genesisPath := filepath.Join(dir, "genesis.json")
	raw, err := json.Marshal(genesis)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(genesisPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	m := service.Manifest{Version: 1, Devnet: true, Mode: "native-finance", Domain: init.Domain, Index: uint8(index), Members: init.Members, Peers: init.Peers, DataDir: filepath.Join(dir, "dex"), VoteKeyFile: identity.VoteKeyFile, TLSCertFile: identity.TLSCertFile, TLSKeyFile: identity.TLSKeyFile, APIListen: identity.API, CLXHash: init.Domain.Genesis, MaxHeight: init.MaxHeight, TimeoutMillis: init.TimeoutMillis, Finance: &service.NativeConfig{Market: init.Market, CLX: init.CLX, ReceiptHeights: []uint64{init.ParticipationHeight}}}
	for _, option := range options {
		option(&m)
	}
	if err = m.Validate(); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "dex.json")
	raw, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(manifest, raw, 0600); err != nil {
		t.Fatal(err)
	}
	datadir := filepath.Join(dir, "common-data")
	initialize := exec.Command(binary, "--datadir", datadir, "init", genesisPath)
	initialize.Env = append(os.Environ(), "GOMAXPROCS=2")
	if out, err := initialize.CombinedOutput(); err != nil {
		t.Fatalf("ordinary CLI genesis init: %v\n%s", err, out)
	}
	sock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(sock.LocalAddr().String())
	sock.Close()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--datadir", datadir, "--nat", "extip:127.0.0.1", "--rnetport", port, "--port", "0", "--nodiscover", "--maxpeers", "1", "--ipcpath", filepath.Join(dir, "common.ipc"), "--syncmode", "full", "--cache", "32", "--cache.trie.journal", "", "--dex.validator", "--dex.config", manifest, "--verbosity", "2"}
	args = append(args, "--networkid", genesis.Config.ChainID.String())
	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
	logPath := filepath.Join(dir, "common-sidecar.log")
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = log, log
	p := &financialCLI{parent: cmd, done: make(chan error, 1), api: identity.API, logPath: logPath, client: &http.Client{Timeout: 4 * time.Second}, manifest: m, manifestPath: manifest}
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	go func() { err := cmd.Wait(); log.Close(); p.done <- err; close(p.done) }()
	t.Cleanup(func() {
		defer p.stop(t)
		p.clearFirewall(t)
		if t.Failed() {
			raw, _ := os.ReadFile(p.logPath)
			f, e := os.CreateTemp("", "dex-normal-cli-failure-*.log")
			if e == nil {
				f.Write(raw)
				f.Close()
				t.Logf("ordinary CLI full log %s", f.Name())
			}
			if len(raw) > 12000 {
				raw = raw[len(raw)-12000:]
			}
			t.Logf("ordinary Common%d: %s", index, raw)
		}
	})
	deadline := time.Now().Add(45 * time.Second)
	var lastStatus service.Status
	var lastChildren []string
	for time.Now().Before(deadline) {
		select {
		case err := <-p.done:
			raw, _ := os.ReadFile(logPath)
			t.Fatalf("normal Common exit: %v\n%s", err, raw)
		default:
		}
		var s service.Status
		err = p.http("GET", "/v1/status", nil, &s)
		lastStatus = s
		if err == nil && s.Error == "" {
			// os/exec may fork from any Go runtime OS thread. Linux reports
			// children per thread, not just under the thread-group leader.
			paths, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/children", cmd.Process.Pid))
			found := map[string]bool{}
			for _, path := range paths {
				b, e := os.ReadFile(path)
				if e == nil {
					for _, id := range strings.Fields(string(b)) {
						found[id] = true
					}
				}
			}
			lastChildren = nil
			for id := range found {
				lastChildren = append(lastChildren, id)
			}
			if len(lastChildren) == 1 {
				pid, e := strconv.Atoi(lastChildren[0])
				if e != nil {
					t.Fatal(e)
				}
				line, e := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
				if e != nil || !bytes.Contains(line, []byte("dex-validator")) {
					t.Fatal("unexpected supervised process")
				}
				p.sidecar, e = os.FindProcess(pid)
				if e != nil {
					t.Fatal(e)
				}
				t.Logf("NORMAL_FINANCIAL_ROLES index=%d CommonPID=%d DEXSidecarPID=%d api=%s pow=false rpcReward=false", index, cmd.Process.Pid, pid, identity.API)
				return &dexFinancialChild{cmd: cmd, identity: identity, index: index, dir: m.DataDir, logPath: logPath, cli: p}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("normal Common/DEX startup deadline: HTTP=%v status=%+v children=%v", err, lastStatus, lastChildren)
	return nil
}
func (p *financialCLI) http(method, path string, raw []byte, out interface{}) error {
	return p.httpContext(context.Background(), method, path, raw, out)
}

type financialHTTPError struct {
	Path   string
	Status int
	Body   string
}

func (e *financialHTTPError) Error() string {
	return fmt.Sprintf("financial API %s: HTTP%d %s", e.Path, e.Status, e.Body)
}

func (p *financialCLI) httpContext(ctx context.Context, method, path string, raw []byte, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, method, "http://"+p.api+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024+1))
	if err != nil {
		return err
	}
	if len(b) > 2*1024*1024 {
		return fmt.Errorf("financial API response bound")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &financialHTTPError{Path: path, Status: resp.StatusCode, Body: string(b)}
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}
func (p *financialCLI) request(t *testing.T, r testnet.Request) testnet.Response {
	t.Helper()
	var out testnet.Response
	var err error
	switch r.Op {
	case "action":
		err = p.http("POST", "/v1/actions", r.Raw, nil) // no height on wire
	case "status":
		var s service.Status
		err = p.http("GET", "/v1/status", nil, &s)
		out.Status = &s
		if err == nil {
			err = p.http("GET", "/v1/participation?height=5", nil, &out)
		}
	case "checkpoint":
		err = p.http("GET", fmt.Sprintf("/v1/checkpoint?height=%d", r.Height), nil, &out)
	case "partition":
		p.partition(t, r.Allowed)
	case "repair":
		// Normal finance service runs authenticated repair periodically. No
		// privileged HTTP import or remote safety watermark is introduced.
	default:
		err = fmt.Errorf("no fixture control op %s on ordinary CLI", r.Op)
	}
	if err != nil {
		out.Error = err.Error()
	}
	return out
}

func (p *financialCLI) firewall(t *testing.T, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "iptables", append([]string{"-w", "2"}, args...)...)
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated namespace firewall %v: %v %s", args, err, raw)
	}
}
func (p *financialCLI) partition(t *testing.T, allowed []bool) {
	t.Helper()
	if len(allowed) != 7 {
		t.Fatal("partition peer count")
	}
	self, _, err := net.SplitHostPort(p.manifest.Peers[p.manifest.Index].Address)
	if err != nil || net.ParseIP(self) == nil || !net.ParseIP(self).IsLoopback() || self == "127.0.0.1" {
		t.Fatal("dedicated loopback peer IP required")
	}
	if p.ruleChain == "" {
		p.ruleChain = fmt.Sprintf("DXF%d_%d", os.Getpid(), p.manifest.Index)
		p.firewall(t, "-N", p.ruleChain)
		p.firewall(t, "-A", "INPUT", "-p", "tcp", "-d", self, "-j", p.ruleChain)
	}
	p.firewall(t, "-F", p.ruleChain)
	for i, yes := range allowed {
		if !yes {
			ip, _, err := net.SplitHostPort(p.manifest.Peers[i].Address)
			if err != nil || net.ParseIP(ip) == nil || !net.ParseIP(ip).IsLoopback() || ip == "127.0.0.1" {
				t.Fatal("partition foreign address")
			}
			p.firewall(t, "-A", p.ruleChain, "-s", ip, "-j", "DROP")
		}
	}
	t.Logf("DEX_SOCKET_PARTITION receiver=%s allowed=%v ownNamespace=true", self, allowed)
}
func (p *financialCLI) clearFirewall(t *testing.T) {
	if p.ruleChain == "" {
		return
	}
	self, _, _ := net.SplitHostPort(p.manifest.Peers[p.manifest.Index].Address)
	p.firewall(t, "-D", "INPUT", "-p", "tcp", "-d", self, "-j", p.ruleChain)
	p.firewall(t, "-F", p.ruleChain)
	p.firewall(t, "-X", p.ruleChain)
	p.ruleChain = ""
}

// After the DEX sidecars stop, their ordinary Common parents still perform
// CLX ETH full sync. Only the test source's public enode is supplied over IPC;
// no block, StateDB, receipt or finalized marker is injected into these nodes.
func verifyFinancialCommonSync(t *testing.T, children []*dexFinancialChild, source *nativeCommonNode, height uint64) {
	t.Helper()
	if height > 128 || source.Service.BlockChain().CurrentBlock().NumberU64() != height {
		t.Fatal("normal Common sync source bound")
	}
	sourceNode := source.Stack.Server().Self()
	sourceURL, sourceID := sourceNode.URLv4(), sourceNode.ID().String()
	targetHash := source.Service.BlockChain().CurrentBlock().Hash()
	type syncPeer struct {
		ID        string                     `json:"id"`
		Protocols map[string]json.RawMessage `json:"protocols"`
	}
	peerHead := func(client *rpc.Client) (common.Hash, bool) {
		var peers []syncPeer
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := client.CallContext(ctx, &peers, "admin_peers")
		cancel()
		if err != nil {
			t.Fatal("normal Common peer observation", err)
		}
		for _, peer := range peers {
			if peer.ID != sourceID {
				t.Fatal("normal Common has an unexpected peer", peer.ID)
			}
			var info struct {
				Head common.Hash `json:"head"`
			}
			if err := json.Unmarshal(peer.Protocols["eth"], &info); err == nil {
				return info.Head, true
			}
			return common.Hash{}, true // ETH handshake is still pending.
		}
		return common.Hash{}, false
	}
	clients := make([]*rpc.Client, len(children))
	for i, child := range children {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		client, err := rpc.DialIPC(ctx, filepath.Join(filepath.Dir(child.cli.manifestPath), "common.ipc"))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		clients[i] = client
		defer client.Close()
		oldHead, previouslyConnected := peerHead(client)
		// This fixture supplies new canonical blocks to its source via ordinary
		// InsertChain; it does not emit the miner's NewMinedBlockEvent. Common 0
		// may still have the source's height-47 handshake from the combined RPC
		// test. Re-adding an existing static peer cannot refresh that peer's TD.
		// Disconnect only this owned test connection and authenticate a fresh ETH
		// status handshake. All downloaded blocks still use normal validation.
		var removed bool
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		err = client.CallContext(ctx, &removed, "admin_removePeer", sourceURL)
		cancel()
		if err != nil || !removed {
			t.Fatal("normal Common old peer removal", i, err)
		}
		if _, present := peerHead(client); present {
			t.Fatal("normal Common old peer survived removal", i)
		}
		var added bool
		if err = client.Call(&added, "admin_addPeer", sourceURL); err != nil || !added {
			t.Fatal("normal Common peer admission", i, err)
		}
		t.Logf("NORMAL_COMMON_SYNC_PEER_REFRESH index=%d previouslyConnected=%t oldPeerHead=%s expectedPeerHead=%s height=%d", i, previouslyConnected, oldHead.Hex(), targetHash.Hex(), height)
	}
	deadline := time.Now().Add(75 * time.Second)
	heights := make([]uint64, len(clients))
	peerHeads := make([]common.Hash, len(clients))
	for {
		ready := true
		for i, client := range clients {
			var current hexutil.Uint64
			if err := client.Call(&current, "eth_blockNumber"); err != nil {
				t.Fatal(err)
			}
			heights[i] = uint64(current)
			peerHeads[i], _ = peerHead(client)
			if heights[i] > height {
				t.Fatal("normal Common exceeded bounded source height", i, heights[i], height)
			}
			ready = ready && heights[i] == height && peerHeads[i] == targetHash
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("normal Common ETH full sync deadline: wantHeight=%d wantPeerHead=%s heights=%v peerHeads=%v", height, targetHash.Hex(), heights, peerHeads)
		}
		time.Sleep(100 * time.Millisecond)
	}
	for i, client := range clients {
		for h := uint64(0); h <= height; h++ {
			var got struct {
				Hash    common.Hash
				Root    common.Hash    `json:"stateRoot"`
				Receipt common.Hash    `json:"receiptsRoot"`
				Gas     hexutil.Uint64 `json:"gasUsed"`
			}
			if err := client.Call(&got, "eth_getBlockByNumber", hexutil.EncodeUint64(h), false); err != nil {
				t.Fatal(err)
			}
			want := source.Service.BlockChain().GetBlockByNumber(h)
			if got.Hash != want.Hash() || got.Root != want.Root() || got.Receipt != want.ReceiptHash() || uint64(got.Gas) != want.GasUsed() {
				t.Fatal("normal Common sync root/receipt/gas divergence", i, h)
			}
		}
		var balance hexutil.Big
		if err := client.Call(&balance, "eth_getBalance", params.DEXSettlementAddress, hexutil.EncodeUint64(height)); err != nil || (*big.Int)(&balance).Cmp(nativeUnits(214)) != 0 {
			t.Fatal("normal Common synced native custody", i, err)
		}
		t.Logf("NORMAL_COMMON_CLX_SYNC index=%d pid=%d height=%d custody=%s DEXSidecarStopped=true allBlockRootsReceiptsGasMatch=true", i, children[i].cli.parent.Process.Pid, height, (*big.Int)(&balance))
	}
}

func restartFinancialCLI(t *testing.T, c *dexFinancialChild, init testnet.Init, old []byte) *dexFinancialChild {
	t.Helper()
	p := c.cli
	p.stop(t)
	// A forged reward recipient must fail normal CLI registration before it can
	// open or mutate the old safety WAL.
	bad := p.manifest
	bad.Peers = append(bad.Peers[:0:0], bad.Peers...)
	bad.Peers[c.index].RewardRecipient[0] ^= 1
	badPath := filepath.Join(filepath.Dir(p.manifestPath), "bad-restart.json")
	raw, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(badPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	probe := exec.CommandContext(ctx, p.parent.Path, "dex-validator", "--dex.config", badPath)
	probe.Env = p.parent.Env
	if out, err := probe.CombinedOutput(); err == nil || ctx.Err() != nil {
		cancel()
		t.Fatalf("bad CLI restart identity: err=%v output=%s", err, out)
	}
	cancel()
	if !bytes.Equal(readFinancialWAL(t, c), old) {
		t.Fatal("bad CLI identity changed WAL")
	}
	oldPID := p.parent.Process.Pid
	cmd := exec.Command(p.parent.Path, p.parent.Args[1:]...)
	cmd.Env = p.parent.Env
	logPath := filepath.Join(filepath.Dir(p.logPath), fmt.Sprintf("restart-%d.log", time.Now().UnixNano()))
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	p.parent = cmd
	p.done = make(chan error, 1)
	p.stopped = false
	p.sidecar = nil
	p.logPath = logPath
	go func() { err := cmd.Wait(); log.Close(); p.done <- err; close(p.done) }()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-p.done:
			raw, _ := os.ReadFile(logPath)
			t.Fatalf("CLI restart exit %v: %s", err, raw)
		default:
		}
		var status service.Status
		if err = p.http("GET", "/v1/status", nil, &status); err == nil && status.Error == "" {
			paths, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/children", cmd.Process.Pid))
			found := map[int]bool{}
			for _, path := range paths {
				b, _ := os.ReadFile(path)
				for _, id := range strings.Fields(string(b)) {
					pid, e := strconv.Atoi(id)
					if e == nil {
						line, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
						if bytes.Contains(line, []byte("dex-validator")) {
							found[pid] = true
						}
					}
				}
			}
			if len(found) == 1 {
				for pid := range found {
					p.sidecar, _ = os.FindProcess(pid)
				}
				next := *c
				next.cmd = cmd
				next.stopped = false
				next.logPath = logPath
				t.Logf("NORMAL_COMMON_DEX_RESTART index=%d parent=%d->%d sidecar=%d", c.index, oldPID, cmd.Process.Pid, p.sidecar.Pid)
				return &next
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("CLI financial restart deadline")
	return nil
}
func (p *financialCLI) killSidecar(t *testing.T) {
	t.Helper()
	if p.sidecar == nil {
		return
	}
	if err := p.sidecar.Kill(); err != nil && !os.IsNotExist(err) {
		t.Error(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", p.sidecar.Pid)); os.IsNotExist(err) {
			p.sidecar = nil
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("owned DEX sidecar did not exit")
}
func (p *financialCLI) stop(t *testing.T) {
	t.Helper()
	if p.stopped {
		return
	}
	p.stopped = true
	select {
	case <-p.done:
		return
	default:
	}
	_ = p.parent.Process.Signal(os.Interrupt)
	select {
	case <-p.done:
	case <-time.After(8 * time.Second):
		_ = p.parent.Process.Kill()
		<-p.done
		if p.sidecar != nil {
			_ = p.sidecar.Kill()
		}
		t.Error("normal Common shutdown deadline")
	}
}
