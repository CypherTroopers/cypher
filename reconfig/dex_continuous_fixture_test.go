package reconfig_test

// These fixtures exercise the shipped Common, DEX sidecar and relay commands.
// Test control submits user transactions/actions and observes public APIs only;
// the CLX helper RPC is used exclusively by the independent accounting observer.
import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/devnet/testnet"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/relay"
	"github.com/cypherium/cypher/dex/service"
	"github.com/cypherium/cypher/dex/transport"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/p2p/enode"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig"
	"github.com/cypherium/cypher/reconfig/bftview"
)

type continuousFixture struct {
	root, binary  string
	identity      []testnet.Identity
	children      []*dexFinancialChild
	keys, gasKeys []*ecdsa.PrivateKey
	owners        []common.Address
	actionNonce   []uint64
	network       *reconfig.FHSNativeNetwork
	source        *nativeCommonNode
	ledger        *continuousLedger
	init          testnet.Init
	relays        []*continuousRelay
}

func newContinuousFixture(t *testing.T) *continuousFixture {
	t.Helper()
	if os.Getenv("CYPHER_DEX_CONTINUOUS_DEVNET") != "1" || os.Getenv("CYPHER_FHS_PROCESS_RECOVERY") != "1" {
		t.Skip("isolated normal CLI continuous relay opt-in")
	}
	binary := os.Getenv("CYPHER_DEX_CLI_BINARY")
	if !filepath.IsAbs(binary) {
		t.Skip("absolute separately built normal CLI required")
	}
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) != 1 || ifaces[0].Flags&net.FlagLoopback == 0 {
		t.Fatal("continuous fixture requires isolated loopback namespace", err)
	}
	f := &continuousFixture{root: t.TempDir(), binary: binary, identity: make([]testnet.Identity, 7), children: make([]*dexFinancialChild, 7), keys: make([]*ecdsa.PrivateKey, 4), gasKeys: make([]*ecdsa.PrivateKey, 2), owners: make([]common.Address, 4), actionNonce: make([]uint64, 4)}
	t.Cleanup(func() { f.preserveFailure(t) })
	members, nodes, peers := make([]*common.Cnode, 7), make([]common.Cnode, 7), make([]transport.Peer, 7)
	for i := range f.identity {
		child := startDEXFinancialChild(t, filepath.Join(f.root, fmt.Sprintf("identity-%d", i)), i)
		f.identity[i] = child.identity
		members[i], nodes[i], peers[i] = child.identity.Member, *child.identity.Member, child.identity.Peer
		// This helper has never received init and has never voted or executed DEX.
		child.kill(t)
	}
	alloc := core.GenesisAlloc{}
	for i := range f.keys {
		f.keys[i], err = crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		f.owners[i] = crypto.PubkeyToAddress(f.keys[i].PublicKey)
		if i < 3 {
			alloc[f.owners[i]] = core.GenesisAccount{Balance: nativeUnits(1000)}
		}
	}
	for i := range f.gasKeys {
		f.gasKeys[i], err = crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		alloc[crypto.PubkeyToAddress(f.gasKeys[i].PublicKey)] = core.GenesisAccount{Balance: nativeUnits(1000)}
	}
	seed, err := protocol.NativeMarketSeed([20]byte(f.owners[2]))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &params.DEXDevnetConfig{Version: 3, ActivationBlock: 1, DEXID: common.Hash(protocol.Digest("continuous-normal-cli-fixture/v1", []byte(t.Name()))), GenesisSeed: common.Hash(seed), Custody: params.DEXSettlementAddress, Committee: nodes, MaxCheckpoints: 128}
	f.network = reconfig.NewFHSNativeNetwork(t, cfg, alloc)
	f.source = startFHSRewardCommon(t, f.network.Fixture, nativeCommonOptions{P2P: &p2p.Config{NoDiscovery: true, MaxPeers: 16, ListenAddr: "127.0.0.1:0"}})
	peer, err := enode.ParseV4(f.network.ETHPeers()[0])
	if err != nil {
		t.Fatal(err)
	}
	f.source.Stack.Server().AddPeer(peer)
	f.ledger = newContinuousLedger(t, newNativeLedger(t, f.network, f.source))
	chain := f.network.Fixture.Genesis.Config
	genesis := f.network.Fixture.Genesis.ToBlock(nil).Header()
	domain := protocol.Domain{Version: 1, ChainID: chain.ChainID.Uint64(), Genesis: protocol.Hash(genesis.Hash()), DEXID: protocol.Hash(cfg.DEXID), Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: members}).RlpHash())}
	clx := clxevidence.Config{ChainID: domain.ChainID, Genesis: genesis, ChainConfig: chain, Seed: chain.FairHotstuffSeed, DEXID: domain.DEXID, Custody: cfg.Custody, Epochs: []clxevidence.CommitteeEpoch{{First: 1, End: ^uint64(0), KeyHash: f.network.Fixture.KeyBlock.Hash(), Members: f.network.Fixture.Committee}}}
	market := engine.Config{Domain: domain, Oracle: [20]byte(f.owners[2]), Custody: [20]byte(cfg.Custody), Support: "0", Insurance: "0", CLXHash: domain.Genesis, NativeInbox: true}
	f.init = testnet.Init{Domain: domain, Members: members, Peers: peers, Market: market, CLX: clx, MaxHeight: 128, ParticipationHeight: 5, TimeoutMillis: 3000}
	t.Logf("CONTINUOUS_SETUP CLX=%v source=%s network=loopback version=3 DEXRegistered=7 activeInitially=6 relayGasPayers=2 coordinatorStateImports=0", f.network.PIDs(), f.source.Stack.HTTPEndpoint())
	return f
}

func (f *continuousFixture) startDEX(t *testing.T, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		f.children[i] = startFinancialCLI(t, f.binary, f.root, f.identity[i], f.init, f.network.Fixture.Genesis, i, func(m *service.Manifest) { m.Finance.ReceiptHeights = []uint64{5, 15, 25, 35, 45, 55, 65, 75, 85, 95} })
		f.connectParent(t, f.children[i])
	}
}

func (f *continuousFixture) waitSource(t *testing.T, height uint64) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for f.source.Service.BlockChain().CurrentBlock().NumberU64() < height {
		if time.Now().After(deadline) {
			t.Fatalf("ordinary source ETH follow failed current=%d target=%d peers=%+v", f.source.Service.BlockChain().CurrentBlock().NumberU64(), height, f.source.Stack.Server().PeersInfo())
		}
		time.Sleep(50 * time.Millisecond)
	}
	var p nativeProjection
	if err := f.ledger.base.clients[0].Call(&p, "dexfixture_projection", hexutil.Uint64(height)); err != nil {
		t.Fatal(err)
	}
	block := f.source.Service.BlockChain().GetBlockByNumber(height)
	if block == nil || block.Hash() != p.Header.Hash() || block.Root() != p.Header.Root {
		t.Fatal("ordinary source canonical root differs")
	}
	if f.source.Service.IsMining() || f.source.Service.ServiceIsRunning() {
		t.Fatal("ordinary source activated PoW/CLX membership")
	}
	t.Logf("CONTINUOUS_ETH_SOURCE height=%d hash=%s root=%s normalFollow=true", height, block.Hash().Hex(), block.Root().Hex())
}

// send is deliberately independent from nativeLedger.send: the ledger learns
// every effect only by replaying finalized receipts, including relay races.
func (f *continuousFixture) send(t *testing.T, who int, to common.Address, amount *big.Int, data []byte, gas uint64) *types.Transaction {
	t.Helper()
	nonce := f.ledger.base.nonces[f.owners[who]]
	tx, err := types.SignTx(types.NewTransaction(nonce, to, amount, gas, big.NewInt(params.FixedBaseFeePerGas*2), data), types.NewEIP155Signer(f.network.Fixture.Genesis.Config.ChainID), f.keys[who])
	if err != nil {
		t.Fatal(err)
	}
	if err = f.source.Submit(tx); err != nil {
		t.Fatal(err)
	}
	t.Logf("CONTINUOUS_USER_RPC_ACK tx=%s nonce=%d", tx.Hash().Hex(), nonce)
	receipt := nativeWaitReceipt(t, f.ledger.base.clients[0], tx.Hash())
	if uint64(receipt.Status) != types.ReceiptStatusSuccessful {
		t.Fatalf("continuous user TX reverted %s", tx.Hash())
	}
	f.ledger.scan(t, uint64(receipt.BlockNumber))
	f.waitSource(t, uint64(receipt.BlockNumber))
	return tx
}

func (f *continuousFixture) fund(t *testing.T) {
	t.Helper()
	for _, v := range []struct {
		who    int
		op     uint8
		amount int64
	}{{0, protocol.NativeDeposit, 100}, {1, protocol.NativeDeposit, 100}, {2, protocol.NativeSupport, 20}, {2, protocol.NativeInsurance, 5}} {
		raw, err := (protocol.NativeCall{Operation: v.op}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		f.send(t, v.who, params.DEXSettlementAddress, nativeUnits(v.amount), raw, 500000)
	}
	p := f.ledger.base.projection(t)
	if p.Balance.Cmp(nativeUnits(225)) != 0 || p.Status.Deposits != 4 {
		t.Fatal("continuous initial native funding mismatch")
	}
	f.ledger.reconcile(t)
}

func (f *continuousFixture) sign(t *testing.T, who int, kind uint8, change func(*engine.Action)) []byte {
	t.Helper()
	f.actionNonce[who]++
	a := engine.Action{Version: 1, Epoch: f.init.Domain.EpochKey(), Owner: [20]byte(f.owners[who]), Nonce: f.actionNonce[who], Kind: kind}
	if change != nil {
		change(&a)
	}
	raw, err := engine.Sign(a, f.keys[who])
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *continuousFixture) statuses(t *testing.T) []service.Status {
	return f.statusesUntil(t, time.Now().Add(75*time.Second))
}

func (f *continuousFixture) statusesUntil(t *testing.T, deadline time.Time) []service.Status {
	t.Helper()
	var out []service.Status
	for _, c := range f.children {
		if c != nil && !c.stopped {
			out = append(out, continuousCLIStatus(t, c, deadline))
		}
	}
	return out
}

func continuousCLIStatus(t *testing.T, c *dexFinancialChild, deadline time.Time) service.Status {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	s, retries, last, err := continuousObserveStatus(ctx, func(ctx context.Context) (service.Status, error) {
		var s service.Status
		err := c.cli.httpContext(ctx, "GET", "/v1/status", nil, &s)
		return s, err
	}, 100*time.Millisecond)
	if retries > 0 {
		t.Logf("CONTINUOUS_STATUS_RETRY node=%d retries=%d last=%v freshSuccess=%v", c.index, retries, last, err == nil)
	}
	if err != nil {
		t.Fatal("ordinary DEX status observation", err)
	}
	return s
}
func (f *continuousFixture) waitDEX(t *testing.T, certified, finalized uint64) {
	t.Helper()
	deadline := time.Now().Add(75 * time.Second)
	var last []service.Status
	for time.Now().Before(deadline) {
		last = f.statusesUntil(t, deadline)
		all := len(last) >= 5
		for _, s := range last {
			all = all && s.Certified >= certified && s.Finalized >= finalized
		}
		if all {
			t.Logf("CONTINUOUS_DEX certified>=%d finalized>=%d active=%d", certified, finalized, len(last))
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("continuous DEX deadline certified=%d finalized=%d statuses=%+v relay=%+v", certified, finalized, last, f.relayStatuses(t))
}
func (f *continuousFixture) admit(t *testing.T, height uint64, raw []byte) {
	t.Helper()
	if err := f.children[0].cli.http("POST", "/v1/actions", raw, nil); err != nil {
		t.Fatal(err)
	}
	t.Logf("CONTINUOUS_DEX_INGRESS expectedHeight=%d bytes=%d", height, len(raw))
	f.waitDEX(t, height, 0)
	if record := f.certifiedRecord(t, height); record != nil {
		root, err := consensus.ComputeExecutionDataRoot(raw)
		if err != nil || record.Checkpoint.DataRoot != root || !bytes.Equal(record.Actions, raw) {
			t.Fatal("certified action differs from submitted financial schedule", height, err)
		}
	}
}

// Finality must be observed, not inferred as certified-1 across timeout views.
func (f *continuousFixture) finalize(t *testing.T, target, next uint64) uint64 {
	t.Helper()
	for extra := 0; extra <= 7; extra++ {
		all := true
		for _, s := range f.statuses(t) {
			all = all && s.Finalized >= target
		}
		if all {
			return next
		}
		if extra == 7 {
			t.Fatal("seven certified descendants did not finalize requested action")
		}
		f.admit(t, next, f.sign(t, 2, engine.Noop, nil))
		next++
	}
	return next
}

type continuousRelayManifest struct {
	Version                      uint16
	Devnet                       bool
	DataDir                      string
	Domain                       protocol.Domain
	Custody                      common.Address
	CLX                          clxevidence.Config
	SourceURL, SubmitURL, DEXURL string
	MaxHeight                    uint64
	AutoInbox                    bool
	DeferredRecipients           []common.Address
	PollMillis                   uint64
	GasPrice, MaxGasCost         string
	Payers                       []continuousRelayPayer
}
type continuousRelayPayer struct {
	Lane, Purpose string
	Address       common.Address
	KeyFile       string
	GasLimit      uint64
}
type continuousRelayStatus struct {
	Version       uint16
	Devnet        bool
	Authenticated relay.NetworkStatus
	Counts        map[string]int
	TotalJobs     int
	JobsTruncated bool
	Jobs          []struct {
		ID             protocol.Hash
		Lane           relay.Lane
		Phase          string
		Nonce          uint64
		Reserved       bool
		TXHash         common.Hash
		Sends          uint64
		RPCAckObserved bool `json:"rpc_ack_observed"`
		LastError      string
	}
	DiscoveryError, StepError string
}
type continuousRelay struct {
	cmd          *exec.Cmd
	done         chan error
	dir, logPath string
	stopped      bool
}

func (f *continuousFixture) startRelays(t *testing.T, deferred []common.Address) {
	t.Helper()
	for i, key := range f.gasKeys {
		configDir := filepath.Join(f.root, fmt.Sprintf("relay-config-%d", i))
		if err := os.Mkdir(configDir, 0700); err != nil {
			t.Fatal(err)
		}
		keyPath := filepath.Join(configDir, "gas.key")
		if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(crypto.FromECDSA(key))), 0600); err != nil {
			t.Fatal(err)
		}
		m := continuousRelayManifest{Version: 1, Devnet: true, DataDir: filepath.Join(f.root, fmt.Sprintf("relay-%d", i)), Domain: f.init.Domain, Custody: params.DEXSettlementAddress, CLX: f.init.CLX, SourceURL: f.source.Stack.HTTPEndpoint(), SubmitURL: f.source.Stack.HTTPEndpoint(), DEXURL: "http://" + f.identity[i].API, MaxHeight: 128, AutoInbox: true, DeferredRecipients: deferred, PollMillis: 500, GasPrice: fmt.Sprint(params.FixedBaseFeePerGas * 2), MaxGasCost: nativeUnits(1).String()}
		for _, lane := range []string{"anchor", "checkpoint", "claim"} {
			m.Payers = append(m.Payers, continuousRelayPayer{Lane: lane, Purpose: "relay-gas", Address: crypto.PubkeyToAddress(key.PublicKey), KeyFile: keyPath, GasLimit: 16000000})
		}
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		configPath := filepath.Join(configDir, "relay.json")
		if err = os.WriteFile(configPath, raw, 0600); err != nil {
			t.Fatal(err)
		}
		p := &continuousRelay{cmd: exec.Command(f.binary, "dex-relay", "--relay.config", configPath), done: make(chan error, 1), dir: m.DataDir, logPath: filepath.Join(configDir, "relay.log")}
		p.cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
		log, err := os.OpenFile(p.logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		p.cmd.Stdout, p.cmd.Stderr = log, log
		if err = p.cmd.Start(); err != nil {
			log.Close()
			t.Fatal(err)
		}
		go func() { err := p.cmd.Wait(); log.Close(); p.done <- err; close(p.done) }()
		t.Cleanup(func() {
			p.stop(t)
			if t.Failed() {
				raw, _ := os.ReadFile(p.logPath)
				out, e := os.CreateTemp("", "continuous-relay-failure-*.log")
				if e == nil {
					out.Write(raw)
					out.Close()
					t.Logf("continuous relay log %s", out.Name())
				}
				t.Logf("relay status %+v", p.status(t))
			}
		})
		f.relays = append(f.relays, p)
		t.Logf("NORMAL_RELAY index=%d pid=%d store=%s payer=%s", i, p.cmd.Process.Pid, m.DataDir, m.Payers[0].Address.Hex())
	}
}
func (p *continuousRelay) status(t *testing.T) continuousRelayStatus {
	t.Helper()
	var status continuousRelayStatus
	raw, err := os.ReadFile(filepath.Join(p.dir, "status.json"))
	if os.IsNotExist(err) {
		return status
	}
	if err != nil || len(raw) > 1<<20 {
		t.Fatal("relay status bound", err)
	}
	if err = json.Unmarshal(raw, &status); err != nil {
		t.Fatal(err)
	}
	return status
}
func (f *continuousFixture) relayStatuses(t *testing.T) []continuousRelayStatus {
	t.Helper()
	var out []continuousRelayStatus
	for _, p := range f.relays {
		if !p.stopped {
			select {
			case err := <-p.done:
				p.stopped = true
				t.Fatalf("relay exited before completion: %v log=%s", err, p.logPath)
			default:
			}
		}
		out = append(out, p.status(t))
	}
	return out
}
func (p *continuousRelay) stop(t *testing.T) {
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
	_ = p.cmd.Process.Signal(os.Interrupt)
	select {
	case err := <-p.done:
		if err != nil {
			t.Errorf("relay shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
		t.Error("relay shutdown deadline")
	}
}
