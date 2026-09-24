package reconfig

// Test-only orchestration: all transactions enter through the external Common
// RPC callback. No transaction or admission is injected into a validator here.
import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
)

type FHSNativeNetwork struct {
	Fixture        *FHSRewardNetworkFixture
	children       []*fhsRecoveryChild
	t              *testing.T
	initialization fhsProcessCommand
}

func NewFHSNativeNetwork(t *testing.T, dex *params.DEXDevnetConfig, alloc core.GenesisAlloc) *FHSNativeNetwork {
	t.Helper()
	if os.Getenv("CYPHER_FHS_PROCESS_RECOVERY") != "1" {
		t.Skip("isolated real CLX QUIC process test opt-in")
	}
	raw, err := os.ReadFile(filepath.Join("..", "genesis.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g core.Genesis
	if err = json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	operator, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	recipient := common.HexToAddress("0xb123")
	g.Alloc = core.GenesisAlloc{}
	for address, account := range alloc {
		g.Alloc[address] = account
	}
	g.Alloc[crypto.PubkeyToAddress(key.PublicKey)] = core.GenesisAccount{Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(27), nil)}
	g.Alloc[crypto.PubkeyToAddress(operator.PublicKey)] = core.GenesisAccount{Balance: big.NewInt(77)}
	g.Alloc[recipient] = core.GenesisAccount{Balance: big.NewInt(123)}
	g.Timestamp = uint64(time.Now().Unix())
	g.Config.DEXDevnet = dex
	if err = g.Config.ValidateDEXDevnet(); err != nil {
		t.Fatal(err)
	}
	n := &FHSNativeNetwork{t: t, children: make([]*fhsRecoveryChild, 7)}
	members := make([]*common.Cnode, 7)
	g.Config.GenCommittee = make(params.GenesisCommittee)
	for i := range n.children {
		child := startFHSRecoveryChild(t, t.TempDir())
		n.children[i] = child
		members[i] = &common.Cnode{Address: child.info.Address, Public: child.info.Public, CoinBase: common.BigToAddress(big.NewInt(int64(i + 1))).Hex()}
		g.Config.GenCommittee[i] = *members[i]
	}
	g.Mixhash, err = params.FairHotstuffGenesisCommitment(g.Config)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(&g)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &FHSRewardNetworkFixture{Genesis: &g, Committee: members, SenderKey: key, OperatorKey: operator, RewardRecipient: recipient}
	fixture.KeyBlock, err = normalFHSFixtureKeyGenesis(raw, members)
	if err != nil {
		t.Fatal(err)
	}
	for _, child := range n.children {
		n.initialization = fhsProcessCommand{Op: "init", Genesis: raw, Committee: members, SenderKey: hex.EncodeToString(crypto.FromECDSA(key)), OperatorKey: hex.EncodeToString(crypto.FromECDSA(operator)), RewardRecipient: recipient, NetworkIngress: true, PreserveAlloc: true, NormalKeyGenesis: true, Timestamp: g.Timestamp}
		child.info = child.call(t, n.initialization)
		if child.info.Genesis != g.ToBlock(nil).Hash() || child.info.KeyHash != fixture.KeyBlock.Hash() {
			t.Fatal("native child transaction/key genesis differs from normal CLI init")
		}
	}
	for _, child := range n.children {
		child.call(t, fhsProcessCommand{Op: "gate", Gate: fhsProcessGate{Healed: true}})
		child.call(t, fhsProcessCommand{Op: "start"})
	}
	n.Fixture = fixture
	return n
}

// Native fixtures must be sync-compatible with ordinary CLI init. Older FHS
// recovery/reward fixtures deliberately retain their existing synthetic key.
func normalFHSFixtureKeyGenesis(raw []byte, members []*common.Cnode) (*types.KeyBlock, error) {
	var genesis core.GenesisKey
	if err := json.Unmarshal(raw, &genesis); err != nil {
		return nil, err
	}
	if genesis.Config == nil || genesis.Number != 0 || len(members) != 7 || len(genesis.Config.GenCommittee) != len(members) {
		return nil, fmt.Errorf("normal key genesis fixture requires seven registered members")
	}
	for i, member := range members {
		if member == nil || genesis.Config.GenCommittee[i] != *member {
			return nil, fmt.Errorf("normal key genesis committee differs at index %d", i)
		}
	}
	key := genesis.ToBlock()
	key.SetCommitteeHash((&bftview.Committee{List: members}).RlpHash())
	return key, nil
}

// Stop/Restart target only handles created by this fixture. No operational
// process discovery or signals are involved. The canonical database and FHS
// safety WAL are reopened; genesis.Commit is never called on restart.
func (n *FHSNativeNetwork) Stop() {
	for _, c := range n.children {
		if !c.stopped {
			_ = c.cmd.Process.Kill()
			<-c.done
			c.stopped = true
			_ = c.input.Close()
		}
	}
}
func (n *FHSNativeNetwork) Restart() {
	n.Stop()
	for i, old := range n.children {
		dir := filepath.Dir(old.logPath)
		c := startFHSRecoveryChildMode(n.t, dir, true)
		if c.info.Public != old.info.Public || c.info.Address != old.info.Address {
			n.t.Fatal("CLX restart identity changed")
		}
		c.info = c.call(n.t, n.initialization)
		n.children[i] = c
	}
	for _, c := range n.children {
		c.call(n.t, fhsProcessCommand{Op: "gate", Gate: fhsProcessGate{Healed: true}})
		c.call(n.t, fhsProcessCommand{Op: "start"})
	}
}

func (n *FHSNativeNetwork) Endpoints() []string {
	result := make([]string, len(n.children))
	for i, c := range n.children {
		result[i] = c.call(n.t, fhsProcessCommand{Op: "status"}).ReceiptEndpoint
	}
	return result
}

func (n *FHSNativeNetwork) ETHPeers() []string {
	result := make([]string, len(n.children))
	for i, c := range n.children {
		result[i] = c.call(n.t, fhsProcessCommand{Op: "status"}).ETHPeerURL
	}
	return result
}

func (n *FHSNativeNetwork) P2PURLs() []string { return n.ETHPeers() }
func (n *FHSNativeNetwork) WaitFinalized(height uint64) {
	s := waitFHSProcesses(n.t, n.children, 90*time.Second, func(statuses []fhsProcessReport) bool {
		for _, s := range statuses {
			if s.Height < height {
				return false
			}
		}
		return true
	})
	requireFHSCanonicalAgreement(n.t, n.children, s, height)
	for _, report := range s {
		if report.Submitted != 0 {
			n.t.Fatal("native test bypassed RPC ingress")
		}
	}
}
func (n *FHSNativeNetwork) PIDs() []int {
	p := make([]int, len(n.children))
	for i, c := range n.children {
		p[i] = c.info.PID
	}
	return p
}
