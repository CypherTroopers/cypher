package reconfig_test

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/accounts/keystore"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/commonrpcreward"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/eth"
	"github.com/cypherium/cypher/eth/downloader"
	"github.com/cypherium/cypher/internal/ethapi"
	"github.com/cypherium/cypher/node"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rpc"
)

var rewardReceiptServers sync.Map
var rewardETHPeers sync.Map

type rewardReceiptBackend struct {
	ethapi.Backend
	backend *reconfig.ReconfigBackend
}

func (b *rewardReceiptBackend) AccountManager() *accounts.Manager { return nil }
func (b *rewardReceiptBackend) ChainConfig() *params.ChainConfig {
	return b.backend.BlockChain().Config()
}
func (b *rewardReceiptBackend) GetTransaction(_ context.Context, hash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
	tx, bh, bn, index := rawdb.ReadTransaction(b.backend.ChainDb(), hash)
	return tx, bh, bn, index, nil
}
func (b *rewardReceiptBackend) GetReceipts(_ context.Context, hash common.Hash) (types.Receipts, error) {
	return b.backend.BlockChain().GetReceiptsByHash(hash), nil
}
func (b *rewardReceiptBackend) BlockByHash(_ context.Context, hash common.Hash) (*types.Block, error) {
	return b.backend.BlockChain().GetBlockByHash(hash), nil
}

type rewardReceiptAPI struct {
	api     *ethapi.PublicTransactionPoolAPI
	backend *rewardReceiptBackend
}

func (a *rewardReceiptAPI) GetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]interface{}, error) {
	return a.api.GetTransactionReceipt(ctx, hash)
}

func rewardNetworkTxQUICConfig() eth.TxQUICConfig {
	return eth.TxQUICConfig{FairHotstuff: true, Addr: "127.0.0.1", PortOffset: 2000, ReplayWindow: 64, MaxClockSkew: time.Minute, MaxPacketAge: time.Hour, NonceReservation: 4, IngressCommitInterval: 5 * time.Millisecond, IngressCommitMaxRequests: 16, IngressCommitMaxBytes: 4 << 20, IngressAckRetention: time.Hour, OutboxMaxRecords: 32, OutboxMaxBytes: 16 << 20, OutboxWorkers: 1, OutboxRetryMin: 100 * time.Millisecond, OutboxRetryMax: time.Second, BridgeQueueSize: 1024, BridgeQueueMaxBytes: 8 << 20, BridgeWorkers: 1, BridgeBatchInterval: 20 * time.Millisecond}
}

func init() {
	reconfig.FHSRewardETHPeerURL = func(b *reconfig.ReconfigBackend) string {
		if value, ok := rewardETHPeers.Load(b); ok {
			return value.(string)
		}
		return ""
	}
	reconfig.FHSRewardReceiptEndpoint = func(b *reconfig.ReconfigBackend) string {
		if value, ok := rewardReceiptServers.Load(b); ok {
			return value.(string)
		}
		return ""
	}
	reconfig.FHSRewardIngressFactory = func(backend *reconfig.ReconfigBackend, dir, address string) (func() error, func(), error) {
		_, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, nil, err
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			return nil, nil, err
		}
		chain := backend.BlockChain()
		config := rewardNetworkTxQUICConfig()
		if chain.Config().DEXDevnet != nil {
			// Native financial integration has funding, 18 relays and 8 claims;
			// the legacy five-TX fixture's 32 WAL events cannot hold that trace.
			config.OutboxMaxRecords = 512
		}
		config.Enabled = true
		config.Port = port + config.PortOffset
		config.ChainID = chain.Config().ChainID.Uint64()
		config.GenesisHash = chain.Genesis().Hash()
		q := eth.NewTxQUICIngress(config, backend.TxPool())
		ingressDB, err := rawdb.NewLevelDBDatabase(filepath.Join(dir, "tx-ingress"), 8, 16, "")
		if err != nil {
			return nil, nil, err
		}
		walDB, err := rawdb.NewLevelDBDatabase(filepath.Join(dir, "tx-wal"), 8, 16, "")
		if err != nil {
			ingressDB.Close()
			return nil, nil, err
		}
		q.SetDurableIngress(eth.NewTxQUICIngressStore(ingressDB, config))
		q.SetIngressWALDatabase(walDB)
		q.SetCanonicalTxLookup(func(hash common.Hash) bool { return chain.GetTransactionLookup(hash) != nil })
		q.SetFinalizedTxLookup(chain.IsFinalizedTransaction)
		q.SetObsoleteTxLookup(func(txs types.Transactions) []bool {
			obsolete := make([]bool, len(txs))
			head := chain.CurrentBlock()
			state, err := chain.StateAt(head.Root())
			if err != nil {
				return obsolete
			}
			for i, tx := range txs {
				if sender, err := types.Sender(types.LatestSignerForChainID(chain.Config().ChainID), tx); err == nil {
					obsolete[i] = tx.Nonce() < state.GetNonce(sender)
				}
			}
			return obsolete
		})
		q.SetFHSRouteProvider(func() (eth.TxQUICFHSRoute, error) {
			route, err := backend.CurrentFHSRoute()
			if err != nil {
				return eth.TxQUICFHSRoute{}, err
			}
			if route == nil || route.Leader == nil {
				return eth.TxQUICFHSRoute{}, fmt.Errorf("FHS route unavailable")
			}
			out := eth.TxQUICFHSRoute{ProposalView: route.ProposalView, KeyNumber: route.KeyNumber, CommitteeHash: route.CommitteeHash, LeaderIndex: route.LeaderIndex, LeaderAddress: route.Leader.Address}
			for _, member := range route.Committee {
				out.CommitteeAddresses = append(out.CommitteeAddresses, member.Address)
				out.CommitteePublicKeys = append(out.CommitteePublicKeys, member.Public)
			}
			return out, nil
		})
		if err := q.SetFHSReceiptSigner(backend.TxQUICReceiptPublicKey, backend.SignTxQUICReceipt); err != nil {
			return nil, nil, err
		}
		reconfig.FHSRewardSetTransactionResolver(backend, q.ResolveTransaction)
		receiptBackend := &rewardReceiptBackend{backend: backend}
		api := ethapi.NewPublicTransactionPoolAPI(receiptBackend, new(ethapi.AddrLocker))
		server := rpc.NewServer()
		if err := server.RegisterName("eth", &rewardReceiptAPI{api: api, backend: receiptBackend}); err != nil {
			return nil, nil, err
		}
		if err := server.RegisterName("dexfixture", &nativeFixtureAPI{backend: receiptBackend}); err != nil {
			return nil, nil, err
		}
		httpServer := httptest.NewServer(server)
		rewardReceiptServers.Store(backend, httpServer.URL)
		var ethStart func() error
		var ethStop func()
		if chain.Config().DEXDevnet != nil && chain.Config().DEXDevnet.Version == 3 {
			ethStart, ethStop, err = nativeETHTransport(backend, dir)
			if err != nil {
				return nil, nil, err
			}
		}
		start := func() error {
			if err := q.Start(); err != nil {
				return err
			}
			if ethStart != nil {
				return ethStart()
			}
			return nil
		}
		return start, func() {
			if ethStop != nil {
				ethStop()
			}
			httpServer.Close()
			server.Stop()
			api.Stop()
			q.Stop()
			walDB.Close()
			ingressDB.Close()
			rewardReceiptServers.Delete(backend)
		}, nil
	}
}

type nativeCommonOptions struct {
	DataDir        string
	P2P            *p2p.Config
	Plain, Restart bool
}

func startFHSRewardCommon(t *testing.T, fixture *reconfig.FHSRewardNetworkFixture, options ...nativeCommonOptions) *nativeCommonNode {
	t.Helper()
	if len(options) > 1 {
		t.Fatal("one Common options record required")
	}
	var opt nativeCommonOptions
	if len(options) == 1 {
		opt = options[0]
	}
	if opt.DataDir == "" {
		if opt.Restart {
			t.Fatal("restart needs the fixture datadir")
		}
		opt.DataDir = t.TempDir()
	}
	peerConfig := p2p.Config{NoDiscovery: true, MaxPeers: 0}
	if opt.P2P != nil {
		peerConfig = *opt.P2P
	}
	ipcDir, err := os.MkdirTemp("", "fhs-rpc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(ipcDir) })
	stack, err := node.New(&node.Config{Name: "reward-network", DataDir: opt.DataDir, IPCPath: filepath.Join(ipcDir, "rpc.ipc"), NoUSB: true, UseLightweightKDF: true, HTTPHost: "127.0.0.1", HTTPModules: []string{"eth", "personal", "miner"}, HTTPVirtualHosts: []string{"localhost"}, P2P: peerConfig})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stack.Close() })
	// Seed only this new temporary node with the exact fixture key block and
	// committee; GenesisKey's normal constructor uses a different body.
	if !opt.Restart {
		db, err := stack.OpenDatabaseWithFreezer("chaindata", 16, 16, "", "")
		if err != nil {
			t.Fatal(err)
		}
		key := fixture.KeyBlock
		rawdb.WriteKeyBlock(db, key)
		rawdb.WriteKeyBlockHash(db, key.Hash(), 0)
		rawdb.WriteHeadKeyBlockHash(db, key.Hash())
		rawdb.WriteHeadKeyHeaderHash(db, key.Hash())
		rawdb.WriteTd(db, key.Hash(), 0, key.Difficulty())
		rawdb.WriteChainConfig(db, key.Hash(), fixture.Genesis.Config)
		bftview.SetCommitteeConfig(db, nil, nil)
		if !bftview.WriteCommittee(0, key.Hash(), &bftview.Committee{List: fixture.Committee}) {
			t.Fatal("seed temporary committee")
		}
		if _, err := fixture.Genesis.Commit(db); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
	config := eth.DefaultConfig
	config.Genesis = nil
	config.GenesisKey = nil
	config.SyncMode = downloader.FullSync
	config.NetworkId = fixture.Genesis.Config.ChainID.Uint64()
	config.ExternalIp = "127.0.0.1"
	reserved, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, config.RnetPort, err = net.SplitHostPort(reserved.LocalAddr().String())
	reserved.Close()
	if err != nil {
		t.Fatal(err)
	}
	config.EnableTPS = fixture.Genesis.Config.EnabledTPS
	config.DatabaseCache, config.DatabaseHandles = 16, 16
	config.TrieCleanCache, config.TrieDirtyCache, config.SnapshotCache = 0, 0, 0
	config.TxQUIC = rewardNetworkTxQUICConfig()
	if fixture.Genesis.Config.DEXDevnet != nil {
		config.TxQUIC.OutboxMaxRecords = 512
	}
	config.TxQUIC.BridgeEnabled = !opt.Plain
	service, err := eth.New(stack, &config)
	if err != nil {
		t.Fatal(err)
	}
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	if opt.Plain {
		client, err := rpc.DialHTTP(stack.HTTPEndpoint())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.Close)
		if service.IsMining() || service.ServiceIsRunning() || len(stack.AccountManager().Accounts()) != 0 {
			t.Fatal("plain Common started an optional signing/mining role")
		}
		return &nativeCommonNode{Service: service, Stack: stack, Client: client, DataDir: opt.DataDir}
	}
	manager := stack.AccountManager()
	store := manager.Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	var account accounts.Account
	if opt.Restart {
		account, err = store.Find(accounts.Account{Address: crypto.PubkeyToAddress(fixture.OperatorKey.PublicKey)})
		if err != nil {
			t.Fatal("restart operator account absent", err)
		}
	} else {
		events := make(chan accounts.WalletEvent, 1)
		sub := manager.Subscribe(events)
		account, err = store.ImportECDSA(fixture.OperatorKey, "fixture password")
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-events:
		case <-time.After(5 * time.Second):
			t.Fatal("operator account manager discovery timed out")
		}
		sub.Unsubscribe()
	}
	ipc, err := rpc.DialIPC(context.Background(), stack.IPCEndpoint())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ipc.Close)
	var ok bool
	if err := ipc.Call(&ok, "miner_setEtherbase", account.Address); err != nil || !ok {
		t.Fatalf("IPC signer: %v", err)
	}
	var registered commonrpcreward.Status
	if err := ipc.Call(&registered, "personal_setCommonRPCRewardAddress", account.Address, fixture.RewardRecipient, "fixture password"); err != nil {
		t.Fatalf("IPC recipient: %v", err)
	}
	if err := ipc.Call(&ok, "personal_unlockAccount", account.Address, "fixture password", uint64(0)); err != nil || !ok {
		t.Fatalf("IPC unlock: %v", err)
	}
	if len(store.Accounts()) != 1 || store.Accounts()[0].Address != crypto.PubkeyToAddress(fixture.OperatorKey.PublicKey) {
		t.Fatal("Common keystore contains an account other than A")
	}
	if service.BlockChain().Genesis().Hash() != fixture.Genesis.ToBlock(nil).Hash() {
		t.Fatal("Common genesis identity differs from validators")
	}
	client, err := rpc.DialHTTP(stack.HTTPEndpoint())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	var balance hexutil.Big
	if err := client.Call(&balance, "eth_getBalance", fixture.RewardRecipient, "latest"); err != nil || (!opt.Restart && (*big.Int)(&balance).Cmp(big.NewInt(123)) != 0) || (opt.Restart && (*big.Int)(&balance).Cmp(big.NewInt(123)) < 0) {
		t.Fatalf("public B balance read: %v", err)
	}
	submit := func(tx *types.Transaction) error {
		wire, err := tx.MarshalBinary()
		if err != nil {
			return err
		}
		var hash common.Hash
		if err := client.Call(&hash, "eth_sendRawTransaction", hexutil.Bytes(wire)); err != nil {
			return err
		}
		if hash != tx.Hash() {
			return fmt.Errorf("raw TX hash mismatch")
		}
		return nil
	}
	return &nativeCommonNode{Submit: submit, Service: service, Stack: stack, Client: client, DataDir: opt.DataDir}
}

type nativeCommonNode struct {
	Submit  func(*types.Transaction) error
	Service *eth.Ethereum
	Stack   *node.Node
	Client  *rpc.Client
	DataDir string
}

func TestFHSRewardHTTPToTxQUICToFinality(t *testing.T) {
	reconfig.RunFHSRewardNetworkTest(t, func(t *testing.T, fixture *reconfig.FHSRewardNetworkFixture) func(*types.Transaction) error {
		return startFHSRewardCommon(t, fixture).Submit
	})
}
