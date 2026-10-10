package miner

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"

	"net"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
)

// Backend wraps all methods required for mining.
type Backend interface {
	AccountManager() *accounts.Manager
	BlockChain() *core.BlockChain
	KeyBlockChain() *core.KeyBlockChain
	CandidatePool() *core.CandidatePool
	TxPool() *core.TxPool
	ChainDb() ethdb.Database
	PoWRewardRecipient(signer common.Address) (common.Address, error)
	BroadcastPoWResult(context.Context, string, []*common.Cnode, *types.PoWResult) error
}

// Config is the configuration parameters of mining.
type Config struct {
	Etherbase              common.Address `toml:",omitempty"` // Public address for block mining rewards (default = first account)
	Notify                 []string       `toml:",omitempty"` // HTTP URL list to be notified of new work packages(only useful in colossusX).
	ExtraData              hexutil.Bytes  `toml:",omitempty"` // Block extra data set by the miner
	GasFloor               uint64         // Target gas floor for mined blocks.
	GasCeil                uint64         // Target gas ceiling for mined blocks.
	GasPrice               *big.Int       // Minimum gas price for mining a transaction
	Recommit               time.Duration  // The time interval for miner to re-create mining work.
	Noverify               bool           // Disable remote mining solution verification(only useful in colossusX).
	AllowedFutureBlockTime uint64         // Max time (in seconds) from current time allowed for blocks, before they're considered future blocks
}

// Miner creates candidate from current head keyblock and searches for proof-of-work values.
type Miner struct {
	lifecycleMu sync.Mutex // Serializes worker generations and engine DAG ownership.
	mux         *event.TypeMux
	worker      *worker
	pubKey      ed25519.PublicKey
	coinBase    common.Address
	eth         Backend
	engine      consensus.Engine
	keyHeadSub  *event.TypeMuxSubscription
	fullSyncing int32 // can start indicates whether we can start the mining operation
	isMember    bool
}

func New(eth Backend, config *params.ChainConfig, mux *event.TypeMux, engine consensus.Engine, extIP net.IP) *Miner {
	miner := &Miner{
		eth:         eth,
		mux:         mux,
		engine:      engine,
		worker:      newWorker(config, engine, eth, mux, eth.CandidatePool(), extIP),
		fullSyncing: 0,
		isMember:    false,
	}
	miner.Register(NewCpuAgent(eth.BlockChain(), engine))
	return miner
}

func (self *Miner) Start(pubKey ed25519.PublicKey, eb common.Address) error {
	self.lifecycleMu.Lock()
	defer self.lifecycleMu.Unlock()
	self.SetPubKey(pubKey)
	self.SetCoinbase(eb)
	log.Info("Miner) Start", "coinBase", eb, "pubKey", pubKey)
	self.worker.setShouldStart(true)
	log.Info("Ready to start pow work")
	if err := self.worker.start(); err != nil {
		self.worker.setShouldStart(false)
		return errors.Join(err, self.worker.stopAndRelease())
	}
	if !self.worker.isRunning() {
		self.worker.setShouldStart(false)
		return errors.Join(errors.New("miner worker failed to start"), self.worker.stopAndRelease())
	}
	return nil
}

func (self *Miner) SuspendMiner() {
	self.lifecycleMu.Lock()
	defer self.lifecycleMu.Unlock()
	if self.Mining() {
		if err := self.worker.stopAndRelease(); err != nil {
			log.Warn("Failed to release suspended miner DAG", "err", err)
		}
	}
}

func (self *Miner) Stop() error {
	self.lifecycleMu.Lock()
	defer self.lifecycleMu.Unlock()
	self.worker.setShouldStart(false)
	// Agent.Stop joins readers before the engine unmaps their DAG. The engine
	// also closes its own admission gate and drains direct sealing calls.
	return self.worker.stopAndRelease()
}

func (self *Miner) Quit() {
	if err := self.Stop(); err != nil {
		log.Warn("Failed to release miner DAG", "err", err)
	}
}

func (self *Miner) Register(agent Agent) {
	self.worker.register(agent)
}

func (self *Miner) Unregister(agent Agent) {
	self.worker.unregister(agent)
}

func (self *Miner) Mining() bool {
	return self.worker.isRunning()
}

func (self *Miner) HashRate() uint64 {
	if pow, ok := self.engine.(consensus.PoW); ok {
		return uint64(pow.Hashrate())
	}
	return 0
}

func (self *Miner) GetPubKey() ed25519.PublicKey {
	return self.pubKey
}

func (self *Miner) SetPubKey(pubKey ed25519.PublicKey) {
	self.pubKey = pubKey
	self.worker.SetPubKey(pubKey)
}

func (self *Miner) SetCoinbase(eb common.Address) {
	self.coinBase = eb
	self.worker.SetCoinbase(eb)
}

func (self *Miner) GetCoinbase() common.Address {
	return self.coinBase
}

// Pending returns the currently pending block and associated state.
func (self *Miner) Pending() (*types.Block, *state.StateDB) {
	state, _ := self.eth.BlockChain().State()
	return self.eth.BlockChain().CurrentBlock(), state
}

// PendingBlock returns the currently pending block.
//
// Note, to access both the pending block and the pending state
// simultaneously, please use Pending(), as the pending state can
// change between multiple method calls
func (self *Miner) PendingBlock() *types.Block {
	return self.eth.BlockChain().CurrentBlock()
}
