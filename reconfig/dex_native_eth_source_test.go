package reconfig_test

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	proofs "github.com/cypherium/cypher/dex/relay/source"
	"github.com/cypherium/cypher/internal/ethapi"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/p2p/enode"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig"
	"github.com/cypherium/cypher/rpc"
)

func TestFHSNativeOrdinaryETHSource(t *testing.T) {
	if os.Getenv("CYPHER_FHS_PROCESS_RECOVERY") != "1" || os.Getenv("CYPHER_DEX_SOURCE_DEVNET") != "1" {
		t.Skip("isolated actual CLX ETH/source opt-in")
	}
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) != 1 || ifaces[0].Flags&net.FlagLoopback == 0 {
		t.Fatal("actual source test requires fresh loopback-only namespace", err)
	}
	before := engine.Metrics()
	payer, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	owner := crypto.PubkeyToAddress(payer.PublicKey)
	nodes := make([]common.Cnode, 7)
	for i := range nodes {
		var key bls.SecretKey
		if err = key.SetDecString(fmt.Sprint(9700 + i)); err != nil {
			t.Fatal(err)
		}
		nodes[i] = common.Cnode{Address: fmt.Sprintf("127.0.0.1:%d", 34000+i), Public: key.GetPublicKey().SerializeToHexStr(), CoinBase: common.Address{19: byte(101 + i)}.Hex()}
	}
	seed, err := protocol.NativeMarketSeed([20]byte(owner))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &params.DEXDevnetConfig{Version: 3, ActivationBlock: 1, DEXID: common.Hash(protocol.Digest("ordinary-eth-source-fixture", []byte(t.Name()))), GenesisSeed: common.Hash(seed), Custody: params.DEXSettlementAddress, Committee: nodes, MaxCheckpoints: 128}
	network := reconfig.NewFHSNativeNetwork(t, cfg, core.GenesisAlloc{owner: {Balance: nativeUnits(1000)}})
	peers := network.ETHPeers()
	for _, url := range peers {
		if url == "" {
			t.Fatal("config3 CLX peer transport absent")
		}
	}
	peer, err := enode.ParseV4(peers[0])
	if err != nil {
		t.Fatal(err)
	}
	// One CLX peer plus the late DEX OFF Common exercised after the six deposits.
	options := nativeCommonOptions{P2P: &p2p.Config{NoDiscovery: true, MaxPeers: 2, ListenAddr: "127.0.0.1:0"}}
	source := startFHSRewardCommon(t, network.Fixture, options)
	if source.Service.BlockChain().CurrentBlock().NumberU64() != 0 {
		t.Fatal("new source did not begin at genesis")
	}
	source.Stack.Server().AddPeer(peer)
	receiptClient, err := rpc.DialHTTP(network.Endpoints()[0])
	if err != nil {
		t.Fatal(err)
	}
	defer receiptClient.Close()
	submit := func(nonce uint64) nativeReceipt {
		tx := nativeSignedTX(t, payer, network.Fixture.Genesis.Config.ChainID, nonce, protocol.NativeDeposit, 1, 500000)
		if err := source.Submit(tx); err != nil {
			t.Fatal(err)
		}
		r := nativeWaitReceipt(t, receiptClient, tx.Hash())
		if uint64(r.Status) != types.ReceiptStatusSuccessful {
			t.Fatalf("deposit failed %+v", r)
		}
		network.WaitFinalized(uint64(r.BlockNumber))
		return r
	}
	wait := func(n *nativeCommonNode, r nativeReceipt, want uint64) {
		deadline := time.Now().Add(60 * time.Second)
		for n.Service.BlockChain().CurrentBlock().NumberU64() < uint64(r.BlockNumber) {
			if time.Now().After(deadline) {
				t.Fatalf("automatic ETH follow timeout current=%d target=%d peers=%+v", n.Service.BlockChain().CurrentBlock().NumberU64(), r.BlockNumber, n.Stack.Server().PeersInfo())
			}
			time.Sleep(50 * time.Millisecond)
		}
		b := n.Service.BlockChain().GetBlockByNumber(uint64(r.BlockNumber))
		if b == nil || b.Hash() != r.BlockHash {
			t.Fatal("automatic source imported wrong branch")
		}
		var balance hexutil.Big
		if err := n.Client.Call(&balance, "eth_getBalance", params.DEXSettlementAddress, rpc.BlockNumberOrHashWithHash(b.Hash(), true)); err != nil || (*big.Int)(&balance).Cmp(nativeUnits(int64(want))) != 0 {
			t.Fatal("source native state mismatch", err)
		}
		if n.Service.IsMining() || n.Service.ServiceIsRunning() || engine.Metrics() != before {
			t.Fatal("source activated independent PoW/FHS/DEX execution role")
		}
		t.Logf("ORDINARY_ETH_SOURCE_PROGRESS deposit=%d height=%d hash=%s root=%s peers=%d engineDelta=0", want, b.NumberU64(), b.Hash().Hex(), b.Root().Hex(), len(n.Stack.Server().Peers()))
	}
	var fifth nativeReceipt
	for nonce := uint64(0); nonce < 5; nonce++ {
		fifth = submit(nonce)
		wait(source, fifth, nonce+1)
	}
	if fifth.BlockNumber < 5 {
		t.Fatal("continuous source did not progress through five blocks")
	}
	dir := source.DataDir
	source.Client.Close()
	if err = source.Stack.Close(); err != nil {
		t.Fatal(err)
	}
	source = startFHSRewardCommon(t, network.Fixture, nativeCommonOptions{DataDir: dir, P2P: options.P2P, Restart: true})
	source.Stack.Server().AddPeer(peer)
	sixth := submit(5)
	wait(source, sixth, 6)
	trusted := clxevidence.Config{ChainID: network.Fixture.Genesis.Config.ChainID.Uint64(), Genesis: network.Fixture.Genesis.ToBlock(nil).Header(), ChainConfig: network.Fixture.Genesis.Config, Seed: network.Fixture.Genesis.Config.FairHotstuffSeed, DEXID: protocol.Hash(cfg.DEXID), Custody: cfg.Custody, Epochs: []clxevidence.CommitteeEpoch{{First: 1, End: math.MaxUint64, KeyHash: network.Fixture.KeyBlock.Hash(), Members: network.Fixture.Committee}}}
	client, err := proofs.Open(proofs.Config{Endpoint: source.Stack.HTTPEndpoint(), Dir: filepath.Join(t.TempDir(), "proof-source"), CLX: trusted})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for client.Current().Height < uint64(sixth.BlockNumber) {
		if _, err = client.Advance(context.Background()); err != nil {
			var head hexutil.Uint64
			headErr := source.Client.Call(&head, "eth_blockNumber")
			for height := uint64(1); height <= 2; height++ {
				b := source.Service.BlockChain().GetBlockByNumber(height)
				var witness ethapi.CLXFinalityWitness
				rpcErr := source.Client.Call(&witness, "eth_getCLXFinalityWitness", hexutil.Uint64(height))
				t.Logf("SOURCE_RPC_DIAGNOSTIC height=%d localSignature=%d localFinality=%d witnessBytes=%d rpcError=%v", height, len(b.SignInfo().Signature), len(b.SignInfo().FHSFinalityProof), len(witness.Header)+len(witness.ProposalRef), rpcErr)
			}
			t.Fatalf("normal Common proof client err=%v rpcHead=%d headErr=%v currentAnchor=%d localHead=%d endpoint=%s", err, head, headErr, client.Current().Height, source.Service.BlockChain().CurrentBlock().NumberU64(), source.Stack.HTTPEndpoint())
		}
	}
	anchor := client.Current()
	entries, err := client.Entries(context.Background(), anchor, 0, 6)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = client.BuildRange(context.Background(), anchor, anchor.Height, 0, entries); err != nil {
		t.Fatal(err)
	}
	account, _, err := client.Account(context.Background(), anchor, anchor.Custody, []protocol.Hash{protocol.InboxCountStorageKey()})
	if err != nil || account.Balance.Cmp(nativeUnits(6)) != 0 || account.Values[0] != (protocol.Hash{31: 6}) {
		t.Fatal("normal Common authenticated proof mismatch", err)
	}
	for _, path := range []string{"dex", "dex-state", "dex-wal"} {
		if _, err = os.Stat(filepath.Join(dir, path)); !os.IsNotExist(err) {
			t.Fatal("DEX OFF source created DEX state", path, err)
		}
	}
	t.Logf("ORDINARY_ETH_SOURCE_RESTART_PROOF sourceHeight=%d inbox=%d balance=%s CLXChildren=7 sourceRPC=true sourcePoW=false sourceDEX=false noCoordinatorInsertChain=true", anchor.Height, anchor.InboxCount, account.Balance)
	// Stop only this fixture's producers. No block/state import or peer-head
	// repair is used to prepare the unchanged late sync/restart gate.
	network.Stop()
	head := source.Service.BlockChain().CurrentBlock()
	checkContinuousRPCBlock(t, source.Client, head)
	continuousSyncOffCommon(t, network.Fixture, source, head.NumberU64())
}
