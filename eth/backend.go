// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package eth implements the Ethereum protocol.
package eth

import (
	"errors"
	"fmt"
	"math/big"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/bloombits"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/eth/downloader"
	"github.com/cypherium/cypher/eth/filters"
	"github.com/cypherium/cypher/eth/gasprice"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/internal/ethapi"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/miner"
	"github.com/cypherium/cypher/node"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/p2p/enode"
	"github.com/cypherium/cypher/p2p/enr"
	p2pnat "github.com/cypherium/cypher/p2p/nat"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/rpc"
	"golang.org/x/crypto/ed25519"
)

// Ethereum implements the Ethereum full node service.
type Ethereum struct {
	config *Config

	// Handlers
	txPool          *core.TxPool
	blockchain      *core.BlockChain
	keyBlockChain   *core.KeyBlockChain
	protocolManager *ProtocolManager
	candidatePool   *core.CandidatePool
	dialCandidates  enode.Iterator
	txQUICIngress   *TxQUICIngress

	// DB interfaces
	chainDb     ethdb.Database // Block chain database
	txOutboxDb  ethdb.Database // Dedicated durable TxQUIC outbox database (bridge nodes only)
	txIngressDb ethdb.Database // Dedicated durable TxQUIC ingress database (committee nodes only)

	eventMux       *event.TypeMux
	engine         consensus.Engine
	accountManager *accounts.Manager

	bloomRequests     chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests
	bloomIndexer      *core.ChainIndexer             // Bloom indexer operating during block imports
	closeBloomHandler chan struct{}

	APIBackend *EthAPIBackend

	miner     *miner.Miner
	reconfig  *reconfig.ReconfigBackend
	gasPrice  *big.Int
	etherbase common.Address

	networkID     uint64
	netRPCService *ethapi.PublicNetAPI

	p2pServer *p2p.Server
	extIP     net.IP
	lock      sync.RWMutex // Protects the variadic fields (e.g. gas price and etherbase)

	consensusServicePendingLogsFeed *event.Feed
}

type txQUICFinalizedStateReader interface {
	CurrentBlock() *types.Block
	StateAt(common.Hash) (*state.StateDB, error)
}

// txQUICFinalizedNonceObsolete uses one isolated state snapshot for a whole
// micro-batch. It is safe as a terminal delivery predicate only when CurrentBlock
// is final; New wires it exclusively for Fair HotStuff after its 2-chain commit.
func txQUICFinalizedNonceObsolete(chain txQUICFinalizedStateReader, chainID *big.Int, txs types.Transactions) []bool {
	obsolete := make([]bool, len(txs))
	if chain == nil || chainID == nil || len(txs) == 0 {
		return obsolete
	}
	head := chain.CurrentBlock()
	if head == nil {
		return obsolete
	}
	finalizedState, err := chain.StateAt(head.Root())
	if err != nil {
		log.Warn("Failed to open finalized state for TxQUIC cleanup", "root", head.Root(), "err", err)
		return obsolete
	}
	signer := types.LatestSignerForChainID(chainID)
	nonces := make(map[common.Address]uint64)
	for index, tx := range txs {
		if tx == nil {
			continue
		}
		sender, err := types.Sender(signer, tx)
		if err != nil {
			continue
		}
		nonce, cached := nonces[sender]
		if !cached {
			nonce = finalizedState.GetNonce(sender)
			nonces[sender] = nonce
		}
		obsolete[index] = nonce > tx.Nonce()
	}
	if err := finalizedState.Error(); err != nil {
		log.Warn("Failed to read finalized state for TxQUIC cleanup", "root", head.Root(), "err", err)
		return make([]bool, len(txs))
	}
	return obsolete
}

// New creates a new Ethereum object (including the initialisation of the common Ethereum object).
func New(stack *node.Node, config *Config) (*Ethereum, error) {
	if config.SyncMode == downloader.LightSync {
		return nil, errors.New("can't run eth.Ethereum in light sync mode, use les.LightEthereum")
	}
	if !config.SyncMode.IsValid() {
		return nil, fmt.Errorf("invalid sync mode %d", config.SyncMode)
	}
	if config.Miner.GasPrice == nil || config.Miner.GasPrice.Cmp(common.Big0) <= 0 {
		log.Warn("Sanitizing invalid miner gas price", "provided", config.Miner.GasPrice, "updated", DefaultConfig.Miner.GasPrice)
		config.Miner.GasPrice = new(big.Int).Set(DefaultConfig.Miner.GasPrice)
	}
	if config.NoPruning && config.TrieDirtyCache > 0 {
		if config.SnapshotCache > 0 {
			config.TrieCleanCache += config.TrieDirtyCache * 3 / 5
			config.SnapshotCache += config.TrieDirtyCache * 2 / 5
		} else {
			config.TrieCleanCache += config.TrieDirtyCache
		}
		config.TrieDirtyCache = 0
	}
	log.Info("Allocated trie memory caches", "clean", common.StorageSize(config.TrieCleanCache)*1024*1024, "dirty", common.StorageSize(config.TrieDirtyCache)*1024*1024)

	chainDb, err := stack.OpenDatabaseWithFreezer("chaindata", config.DatabaseCache, config.DatabaseHandles, config.DatabaseFreezer, "eth/db/chaindata/")
	if err != nil {
		return nil, err
	}
	core.SetCommonRPCAdmissionDatabase(chainDb)
	_, _, keyGenesisErr := core.SetupGenesisKeyBlock(chainDb, config.GenesisKey)
	if keyGenesisErr != nil {
		return nil, keyGenesisErr
	}
	chainConfig, genesisHash, blockGenesisErr := core.SetupGenesisBlock(chainDb, config.Genesis)
	if blockGenesisErr != nil {
		return nil, blockGenesisErr
	}
	if chainConfig != nil && chainConfig.ChainID != nil && chainConfig.ChainID.IsUint64() {
		// Bind every TxQUIC packet and acknowledgement to this chain before
		// auto-role selection can enable either side of the transport.
		config.TxQUIC.ChainID = chainConfig.ChainID.Uint64()
		config.TxQUIC.GenesisHash = genesisHash
		config.TxQUIC.FairHotstuff = chainConfig.FairHotstuff
	} else if config.TxQUIC.Enabled || config.TxQUIC.BridgeEnabled {
		return nil, fmt.Errorf("TxQUIC requires a non-negative uint64 chain ID")
	}
	log.Info("Initialised chain configuration", "config", chainConfig)
	chainConfig.RnetPort = config.RnetPort
	chainConfig.EnabledTPS = config.EnableTPS
	if chainConfig.FairHotstuff {
		// Admission authorization is consensus state committed by genesis. Derive
		// the TxQUIC packet allowlist from it so an operator-local TOML value
		// cannot admit a signer whose reward validators must reject.
		config.TxQUIC.AllowedSigners = append([]common.Address(nil), chainConfig.CommonRPCSigners...)
	}
	config.TxQUIC.ApplyFixedCommitteeAutoRole(chainConfig)
	config.TxQUIC.ApplyHTTP3RPCDefaults(stack.Config().HTTPHost, stack.Config().HTTPPort)

	log.Info("Initialised chain configuration", "config id", chainConfig.ChainID)
	extIP := net.ParseIP(config.ExternalIp)
	if extIP == nil {
		extIP = net.ParseIP(p2pnat.GetExternalIp())
	}
	if extIP != nil {
		log.Info("extIP address", "IP", extIP.String())
	} else {
		log.Warn("extIP address is not configured")
	}

	eth := &Ethereum{
		config:                          config,
		chainDb:                         chainDb,
		eventMux:                        stack.EventMux(),
		accountManager:                  stack.AccountManager(),
		engine:                          CreateConsensusEngine(stack, chainConfig, config),
		closeBloomHandler:               make(chan struct{}),
		networkID:                       config.NetworkId,
		gasPrice:                        config.Miner.GasPrice,
		etherbase:                       config.Miner.Etherbase,
		bloomRequests:                   make(chan chan *bloombits.Retrieval),
		bloomIndexer:                    NewBloomIndexer(chainDb, params.BloomBitsBlocks, params.BloomConfirms),
		p2pServer:                       stack.Server(),
		consensusServicePendingLogsFeed: new(event.Feed),
		extIP:                           extIP,
	}

	bcVersion := rawdb.ReadDatabaseVersion(chainDb)
	var dbVer = "<nil>"
	if bcVersion != nil {
		dbVer = fmt.Sprintf("%d", *bcVersion)
	}
	log.Info("Initialising Ethereum protocol", "versions", ProtocolVersions, "network", config.NetworkId, "dbversion", dbVer)

	if !config.SkipBcVersionCheck {
		if bcVersion != nil && *bcVersion > core.BlockChainVersion {
			return nil, fmt.Errorf("database version is v%d, Geth %s only supports v%d", *bcVersion, params.VersionWithMeta, core.BlockChainVersion)
		} else if bcVersion == nil || *bcVersion < core.BlockChainVersion {
			log.Warn("Upgrade blockchain database version", "from", dbVer, "to", core.BlockChainVersion)
			rawdb.WriteDatabaseVersion(chainDb, core.BlockChainVersion)
		}
	}

	vmConfig := vm.Config{
		EnablePreimageRecording: config.EnablePreimageRecording,
		EWASMInterpreter:        config.EWASMInterpreter,
		EVMInterpreter:          config.EVMInterpreter,
	}
	cacheConfig := &core.CacheConfig{
		TrieCleanLimit:      config.TrieCleanCache,
		TrieCleanJournal:    stack.ResolvePath(config.TrieCleanCacheJournal),
		TrieCleanRejournal:  config.TrieCleanCacheRejournal,
		TrieCleanNoPrefetch: config.NoPrefetch,
		TrieDirtyLimit:      config.TrieDirtyCache,
		TrieDirtyDisabled:   config.NoPruning,
		TrieTimeLimit:       config.TrieTimeout,
		SnapshotLimit:       config.SnapshotCache,
	}

	eth.candidatePool = core.NewCandidatePool(eth, eth.EventMux(), chainDb)
	eth.keyBlockChain, err = core.NewKeyBlockChain(eth, chainDb, cacheConfig, chainConfig, eth.engine, eth.EventMux())
	if err != nil {
		return nil, err
	}
	eth.blockchain, err = core.NewBlockChain(chainDb, cacheConfig, chainConfig, eth.engine, vmConfig, eth.shouldPreserve, &config.TxLookupLimit, eth.keyBlockChain)
	if err != nil {
		return nil, err
	}
	if chainConfig != nil && chainConfig.FairHotstuff {
		core.SetCommonRPCAdmissionFinalizedLookup(func(hash common.Hash) bool {
			return eth.blockchain.IsFinalizedTransaction(hash)
		})
	} else {
		core.SetCommonRPCAdmissionFinalizedLookup(nil)
	}
	eth.bloomIndexer.Start(eth.blockchain)

	if config.TxQUIC.BridgeEnabled {
		// Keep common RPC transactions local as an additional recovery path. The
		// bridge's synchronously-written outbox is the RPC durability boundary;
		// the tx journal remains an asynchronous secondary copy.
		if config.TxPool.NoLocals {
			log.Warn("Disabling txpool.nolocals for durable common RPC ingress")
			config.TxPool.NoLocals = false
		}
		if config.TxPool.Journal == "" {
			log.Warn("Restoring transaction journal for durable common RPC ingress", "journal", core.DefaultTxPoolConfig.Journal)
			config.TxPool.Journal = core.DefaultTxPoolConfig.Journal
		}
		outboxCache, outboxHandles := config.DatabaseCache/16, config.DatabaseHandles/16
		if outboxCache < 16 {
			outboxCache = 16
		}
		if outboxCache > 128 {
			outboxCache = 128
		}
		if outboxHandles < 16 {
			outboxHandles = 16
		}
		if outboxHandles > 128 {
			outboxHandles = 128
		}
		eth.txOutboxDb, err = stack.OpenDatabase("txoutbox", outboxCache, outboxHandles, "eth/db/txoutbox/")
		if err != nil {
			return nil, fmt.Errorf("open TxQUIC outbox database: %w", err)
		}
	}
	if config.TxQUIC.Enabled {
		ingressCache, ingressHandles := config.DatabaseCache/16, config.DatabaseHandles/16
		if ingressCache < 16 {
			ingressCache = 16
		}
		if ingressCache > 128 {
			ingressCache = 128
		}
		if ingressHandles < 16 {
			ingressHandles = 16
		}
		if ingressHandles > 128 {
			ingressHandles = 128
		}
		eth.txIngressDb, err = stack.OpenDatabase("txingress", ingressCache, ingressHandles, "eth/db/txingress/")
		if err != nil {
			return nil, fmt.Errorf("open TxQUIC ingress database: %w", err)
		}
	}
	if config.TxPool.Journal != "" {
		config.TxPool.Journal = stack.ResolvePath(config.TxPool.Journal)
	}
	eth.txPool = core.NewTxPool(config.TxPool, chainConfig, eth.blockchain)
	eth.txQUICIngress = NewTxQUICIngress(config.TxQUIC, eth.txPool)
	eth.txQUICIngress.SetCanonicalTxLookup(func(hash common.Hash) bool {
		return eth.blockchain.GetTransactionLookup(hash) != nil
	})
	if chainConfig != nil && chainConfig.FairHotstuff {
		// Receipt sync may publish lookup entries ahead of the FHS state head;
		// require exact canonical membership at or below the finalized head.
		eth.txQUICIngress.SetFinalizedTxLookup(func(hash common.Hash) bool {
			return eth.blockchain.IsFinalizedTransaction(hash)
		})
		eth.txQUICIngress.SetObsoleteTxLookup(func(txs types.Transactions) []bool {
			return txQUICFinalizedNonceObsolete(eth.blockchain, chainConfig.ChainID, txs)
		})
	}
	if eth.txOutboxDb != nil {
		eth.txQUICIngress.SetDurableOutbox(NewTxOutbox(eth.txOutboxDb, config.TxQUIC), eth.accountManager)
	}
	if eth.txIngressDb != nil {
		eth.txQUICIngress.SetDurableIngress(NewTxQUICIngressStore(eth.txIngressDb, config.TxQUIC))
	}

	cacheLimit := cacheConfig.TrieCleanLimit + cacheConfig.TrieDirtyLimit + cacheConfig.SnapshotLimit
	checkpoint := config.Checkpoint
	if checkpoint == nil {
		checkpoint = params.TrustedCheckpoints[genesisHash]
	}
	if eth.protocolManager, err = NewProtocolManager(chainConfig, checkpoint, config.SyncMode, config.NetworkId, eth.eventMux, eth.txPool, eth.engine, eth.blockchain, chainDb, cacheLimit, config.Whitelist, eth.candidatePool); err != nil {
		return nil, err
	}
	if chainConfig != nil && (chainConfig.FixedLeader || chainConfig.FixedCommittee) {
		if err := eth.candidatePool.StartPoWResultUDP(chainConfig.RnetPort); err != nil {
			return nil, err
		}
	}

	eth.miner = miner.New(eth, chainConfig, eth.EventMux(), eth.engine, extIP)
	// Every TxQUIC bridge packet is authenticated with the node etherbase. Resolve
	// and publish that address while constructing the service, before discovery
	// policy and RPC become visible. A bridge without a local signing wallet must
	// fail closed instead of accepting transactions it cannot authenticate.
	if config.TxQUIC.BridgeEnabled {
		etherbase, err := eth.Etherbase()
		if err != nil {
			return nil, fmt.Errorf("resolve TxQUIC bridge signer: %w", err)
		}
		if eth.accountManager == nil {
			return nil, fmt.Errorf("TxQUIC bridge account manager is unavailable")
		}
		if _, err := eth.accountManager.Find(accounts.Account{Address: etherbase}); err != nil {
			return nil, fmt.Errorf("TxQUIC bridge etherbase %s has no local signing wallet: %w", etherbase, err)
		}
		eth.SetEtherbase(etherbase)
	}
	eth.APIBackend = &EthAPIBackend{stack.Config().ExtRPCEnabled(), eth, nil, "hexNodeId", config.EVMCallTimeOut}
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.Miner.GasPrice
	}
	eth.APIBackend.gpo = gasprice.NewOracle(eth.APIBackend, gpoParams)

	eth.dialCandidates, err = eth.setupDiscovery(&stack.Config().P2P)
	if err != nil {
		return nil, err
	}
	eth.netRPCService = ethapi.NewPublicNetAPI(eth.p2pServer, eth.NetVersion())

	stack.RegisterAPIs(eth.APIs())
	stack.RegisterProtocols(eth.Protocols())
	stack.RegisterLifecycle(eth)

	eth.reconfig, err = reconfig.New(stack, chainConfig, eth)
	if err != nil {
		return nil, err
	}
	if eth.txQUICIngress != nil && eth.reconfig != nil && chainConfig != nil && chainConfig.FairHotstuff {
		eth.txQUICIngress.SetFHSRouteProvider(func() (TxQUICFHSRoute, error) {
			route, err := eth.reconfig.CurrentFHSRoute()
			if err != nil {
				return TxQUICFHSRoute{}, err
			}
			if route == nil || route.Leader == nil {
				return TxQUICFHSRoute{}, fmt.Errorf("Fair HotStuff route has no leader")
			}
			committeeAddresses := make([]string, len(route.Committee))
			committeePublicKeys := make([]string, len(route.Committee))
			for index, member := range route.Committee {
				if member == nil || strings.TrimSpace(member.Address) == "" || strings.TrimSpace(member.Public) == "" {
					return TxQUICFHSRoute{}, fmt.Errorf("Fair HotStuff route has invalid committee member %d", index)
				}
				committeeAddresses[index] = member.Address
				committeePublicKeys[index] = member.Public
			}
			return TxQUICFHSRoute{
				ProposalView:        route.ProposalView,
				KeyNumber:           route.KeyNumber,
				CommitteeHash:       route.CommitteeHash,
				LeaderIndex:         route.LeaderIndex,
				LeaderAddress:       route.Leader.Address,
				CommitteeAddresses:  committeeAddresses,
				CommitteePublicKeys: committeePublicKeys,
			}, nil
		})
		if config.TxQUIC.Enabled {
			if err := eth.txQUICIngress.SetFHSReceiptSigner(eth.reconfig.TxQUICReceiptPublicKey, eth.reconfig.SignTxQUICReceipt); err != nil {
				return nil, err
			}
		}
	}
	if eth.txQUICIngress != nil && config.TxQUIC.HTTP3Enabled {
		if rpcHandler, err := stack.RPCHandler(); err == nil {
			vhosts := stack.Config().HTTPVirtualHosts
			if len(vhosts) == 0 {
				vhosts = []string{"*"}
			}
			eth.txQUICIngress.SetHTTP3RPCHandler(node.NewHTTPHandlerStack(rpcHandler, stack.Config().HTTPCors, vhosts))
		} else {
			log.Warn("Failed to attach HTTP/3 JSON-RPC handler", "err", err)
		}
	}
	return eth, nil
}

func makeExtraData(extra []byte, hasPrivate bool) []byte {
	if len(extra) == 0 {
		extra, _ = rlp.EncodeToBytes([]interface{}{
			uint(params.VersionMajor<<16 | params.VersionMinor<<8 | params.VersionPatch),
			"cypher",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	if uint64(len(extra)) > params.GetMaximumExtraDataSize(hasPrivate) {
		log.Warn("Miner extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", params.GetMaximumExtraDataSize(hasPrivate))
		extra = nil
	}
	return extra
}

// ResolveTxQUICTransaction exposes only authenticated, fsync-complete ingress
// data to the consensus proposal data-availability layer.
func (s *Ethereum) ResolveTxQUICTransaction(hash common.Hash) (*types.Transaction, error) {
	if s == nil || s.txQUICIngress == nil {
		return nil, nil
	}
	return s.txQUICIngress.ResolveTransaction(hash)
}

// CreateConsensusEngine creates the required type of consensus engine instance for an Ethereum service.
func CreateConsensusEngine(stack *node.Node, chainConfig *params.ChainConfig, config *Config) consensus.Engine {
	s := config.colossusX
	engine := colossusX.New(colossusX.Config{
		CacheDir:       stack.ResolvePath(s.CacheDir),
		CachesInMem:    s.CachesInMem,
		CachesOnDisk:   s.CachesOnDisk,
		DatasetDir:     s.DatasetDir,
		DatasetsInMem:  s.DatasetsInMem,
		DatasetsOnDisk: s.DatasetsOnDisk,
	})
	engine.SetThreads(-1)
	return engine
}

// APIs return the collection of RPC services the ethereum package offers.
func (s *Ethereum) APIs() []rpc.API {
	apis := ethapi.GetAPIs(s.APIBackend)
	apis = append(apis, s.engine.APIs(s.BlockChain())...)
	apis = append(apis, []rpc.API{
		{Namespace: "eth", Version: "1.0", Service: NewPublicEthereumAPI(s), Public: true},
		{Namespace: "eth", Version: "1.0", Service: NewPublicMinerAPI(s), Public: true},
		{Namespace: "eth", Version: "1.0", Service: downloader.NewPublicDownloaderAPI(s.protocolManager.downloader, s.eventMux), Public: true},
		{Namespace: "miner", Version: "1.0", Service: NewPrivateMinerAPI(s), Public: false},
		{Namespace: "eth", Version: "1.0", Service: filters.NewPublicFilterAPI(s.APIBackend, false), Public: true},
		{Namespace: "admin", Version: "1.0", Service: NewPrivateAdminAPI(s)},
		{Namespace: "debug", Version: "1.0", Service: NewPublicDebugAPI(s), Public: true},
		{Namespace: "debug", Version: "1.0", Service: NewPrivateDebugAPI(s)},
		{Namespace: "net", Version: "1.0", Service: s.netRPCService, Public: true},
	}...)
	return apis
}

func (s *Ethereum) ResetWithGenesisBlock(gb *types.Block) { s.blockchain.ResetWithGenesisBlock(gb) }

func (s *Ethereum) Etherbase() (eb common.Address, err error) {
	s.lock.RLock()
	etherbase := s.etherbase
	s.lock.RUnlock()
	if etherbase != (common.Address{}) {
		return etherbase, nil
	}
	if wallets := s.AccountManager().Wallets(); len(wallets) > 0 {
		if accounts := wallets[0].Accounts(); len(accounts) > 0 {
			etherbase := accounts[0].Address
			s.lock.Lock()
			s.etherbase = etherbase
			s.lock.Unlock()
			log.Info("Etherbase automatically configured", "address", etherbase)
			return etherbase, nil
		}
	}
	return common.Address{}, fmt.Errorf("etherbase must be explicitly specified")
}

func (s *Ethereum) shouldPreserve(block *types.Block) bool { return false }

// SetEtherbase sets the mining reward address.
func (s *Ethereum) SetEtherbase(etherbase common.Address) {
	s.lock.Lock()
	s.etherbase = etherbase
	s.lock.Unlock()
	s.miner.SetCoinbase(etherbase)
	bftview.SetServerCoinBase(etherbase)
}

func (s *Ethereum) ServiceIsRunning() bool { return s.reconfig.ServiceIsRunning() }

func (s *Ethereum) setMiningThreads(threads int) {
	type threaded interface{ SetThreads(threads int) }
	if th, ok := s.engine.(threaded); ok {
		log.Info("Updated mining threads", "threads", threads)
		th.SetThreads(threads)
	}
}

func (s *Ethereum) StartMining(threads int, local bool, eb common.Address, pubKey ed25519.PublicKey) error {
	s.setMiningThreads(threads)
	if !s.IsMining() {
		s.lock.RLock()
		price := s.gasPrice
		s.lock.RUnlock()
		s.txPool.SetGasPrice(price)
		atomic.StoreUint32(&s.protocolManager.acceptTxs, 1)
		go s.miner.Start(pubKey, eb)
	}
	return nil
}

func (s *Ethereum) StopMining()                                      { s.miner.Stop() }
func (s *Ethereum) IsMining() bool                                   { return s.miner.Mining() }
func (s *Ethereum) Miner() *miner.Miner                              { return s.miner }
func (s *Ethereum) AccountManager() *accounts.Manager                { return s.accountManager }
func (s *Ethereum) BlockChain() *core.BlockChain                     { return s.blockchain }
func (s *Ethereum) KeyBlockChain() *core.KeyBlockChain               { return s.keyBlockChain }
func (s *Ethereum) TxPool() *core.TxPool                             { return s.txPool }
func (s *Ethereum) EventMux() *event.TypeMux                         { return s.eventMux }
func (s *Ethereum) Engine() consensus.Engine                         { return s.engine }
func (s *Ethereum) ChainDb() ethdb.Database                          { return s.chainDb }
func (s *Ethereum) IsListening() bool                                { return true }
func (s *Ethereum) EthVersion() int                                  { return int(ProtocolVersions[0]) }
func (s *Ethereum) NetVersion() uint64                               { return s.networkID }
func (s *Ethereum) Downloader() *downloader.Downloader               { return s.protocolManager.downloader }
func (s *Ethereum) Synced() bool                                     { return atomic.LoadUint32(&s.protocolManager.acceptTxs) == 1 }
func (s *Ethereum) ArchiveMode() bool                                { return s.config.NoPruning }
func (s *Ethereum) BloomIndexer() *core.ChainIndexer                 { return s.bloomIndexer }
func (s *Ethereum) CandidatePool() *core.CandidatePool               { return s.candidatePool }
func (s *Ethereum) ExtIP() net.IP                                    { return s.extIP }
func (s *Ethereum) PublicKey() ed25519.PublicKey                     { return s.miner.GetPubKey() }
func (s *Ethereum) GetCalcGasLimit() func(block *types.Block) uint64 { return s.CalcGasLimit }

// Protocols returns all the currently configured network protocols to start.
func (s *Ethereum) Protocols() []p2p.Protocol {
	protos := make([]p2p.Protocol, len(ProtocolVersions))
	for i, vsn := range ProtocolVersions {
		protos[i] = s.protocolManager.makeProtocol(vsn)
		protos[i].Attributes = []enr.Entry{s.currentEthEntry()}
		protos[i].DialCandidates = s.dialCandidates
	}
	return protos
}

// Start implements node.Lifecycle, starting all internal goroutines needed by the Ethereum protocol implementation.
func (s *Ethereum) Start() error {
	s.startEthEntryUpdate(s.p2pServer.LocalNode())
	s.startBloomHandlers(params.BloomBitsBlocks)
	maxPeers := s.p2pServer.MaxPeers
	if s.config.LightServ > 0 {
		if s.config.LightPeers >= s.p2pServer.MaxPeers {
			return fmt.Errorf("invalid peer config: light peer count (%d) >= total peer count (%d)", s.config.LightPeers, s.p2pServer.MaxPeers)
		}
		maxPeers -= s.config.LightPeers
	}
	s.protocolManager.Start(maxPeers)
	if s.txQUICIngress != nil {
		if err := s.txQUICIngress.Start(); err != nil {
			s.protocolManager.Stop()
			return err
		}
	}
	return nil
}

// Stop implements node.Lifecycle, terminating all internal goroutines used by the Ethereum protocol.
func (s *Ethereum) Stop() error {
	if s.txQUICIngress != nil {
		s.txQUICIngress.Stop()
	}
	if s.txOutboxDb != nil {
		if err := s.txOutboxDb.Close(); err != nil {
			log.Warn("Failed to close TxQUIC outbox database", "err", err)
		}
	}
	if s.txIngressDb != nil {
		if err := s.txIngressDb.Close(); err != nil {
			log.Warn("Failed to close TxQUIC ingress database", "err", err)
		}
	}
	s.protocolManager.Stop()
	s.candidatePool.StopPoWResultUDP()
	s.bloomIndexer.Close()
	close(s.closeBloomHandler)
	s.txPool.Stop()
	s.miner.Stop()
	s.blockchain.Stop()
	s.keyBlockChain.Stop()
	s.engine.Close()
	core.SetCommonRPCAdmissionFinalizedLookup(nil)
	core.SetCommonRPCAdmissionDatabase(nil)
	s.chainDb.Close()
	s.eventMux.Stop()
	return nil
}

func (s *Ethereum) CalcGasLimit(block *types.Block) uint64 {
	return core.CalcGasLimit(block, s.config.Miner.GasFloor, s.config.Miner.GasCeil)
}
func (s *Ethereum) ConsensusServicePendingLogsFeed() *event.Feed {
	return s.consensusServicePendingLogsFeed
}
func (s *Ethereum) SubscribePendingLogs(ch chan<- []*types.Log) event.Subscription {
	return s.consensusServicePendingLogsFeed.Subscribe(ch)
}
