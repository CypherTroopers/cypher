package reconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"time"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/node"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rpc"
)

// Backend wraps all methods required for mining.
type Backend interface {
	ChainDb() ethdb.Database
	BlockChain() *core.BlockChain
	KeyBlockChain() *core.KeyBlockChain
	TxPool() *core.TxPool
	AccountManager() *accounts.Manager
	GetCalcGasLimit() func(block *types.Block) uint64
	ConsensusServicePendingLogsFeed() *event.Feed
	ResolveTxQUICTransaction(common.Hash) (*types.Transaction, error)

	CandidatePool() *core.CandidatePool
	Engine() consensus.Engine
	ExtIP() net.IP
}

type ReconfigBackend struct {
	blockchain     *core.BlockChain
	keyBlockchain  *core.KeyBlockChain
	chainDb        ethdb.Database // Block chain database
	txPool         *core.TxPool
	accountManager *accounts.Manager

	// we need an event mux to instantiate the blockchain
	eventMux         *event.TypeMux
	calcGasLimitFunc func(block *types.Block) uint64

	pendingLogsFeed          *event.Feed
	candidatePool            *core.CandidatePool
	engine                   consensus.Engine
	resolveTxQUICTransaction func(common.Hash) (*types.Transaction, error)
	//-----------------------------------------------
	service *Service
}

// Public interface of service class
type serviceI interface {
	isRunning() bool
	hasDeferredFHSRecovery() bool
	updateCommittee(keyBlock *types.KeyBlock) bool
	procBlockDone(block *types.Block)
	GetCurrentView() *bftview.View
	getBestCandidate(refresh bool) *types.Candidate
	syncCommittee(mb *bftview.Committee, keyblock *types.KeyBlock)
	setNextLeader()
	sendNewViewMsg(curN uint64)
	LeaderAckTime() time.Time
	HotstuffProgressTime() time.Time
	ResetLeaderAckTime()
}

func signCommonRPCAdmission(am *accounts.Manager, admission *types.CommonTxAdmissionBatch) error {
	if am == nil || admission == nil {
		return accounts.ErrUnknownAccount
	}
	account := accounts.Account{Address: admission.Miner}
	wallet, err := am.Find(account)
	if err != nil {
		return err
	}
	payload := types.CommonTxAdmissionSigningPayload(admission)
	if len(payload) == 0 {
		return accounts.ErrUnknownAccount
	}
	sig, err := wallet.SignData(account, accounts.MimetypeDataWithValidator, payload)
	if err != nil {
		return err
	}
	admission.Signature = sig
	return nil
}

type RescueConfig struct {
	KeyBlockNumber uint64          `json:"keyBlockNumer"`
	Committee      []*common.Cnode `json:"committee"`
}

type RescueCommitteeArgs struct {
	ConfigPath string `json:"configPath"`
}

func New(stack *node.Node, chainConfig *params.ChainConfig, e Backend) (*ReconfigBackend, error) {
	backend := &ReconfigBackend{
		eventMux:                 stack.EventMux(),
		chainDb:                  e.ChainDb(),
		blockchain:               e.BlockChain(),
		keyBlockchain:            e.KeyBlockChain(),
		txPool:                   e.TxPool(),
		accountManager:           e.AccountManager(),
		calcGasLimitFunc:         e.GetCalcGasLimit(),
		pendingLogsFeed:          e.ConsensusServicePendingLogsFeed(),
		candidatePool:            e.CandidatePool(),
		engine:                   e.Engine(),
		resolveTxQUICTransaction: e.ResolveTxQUICTransaction,
	}
	core.SetCommonRPCAdmissionSigner(func(admission *types.CommonTxAdmissionBatch) error {
		return signCommonRPCAdmission(backend.accountManager, admission)
	})
	sIp := net.JoinHostPort(e.ExtIP().String(), chainConfig.RnetPort)
	//backend.minter = newMinter(chainConfig, backend, blockTime)
	backend.service = newService("cypherBFTService", sIp, chainConfig, backend)
	backend.candidatePool.CheckMinerPort = backend.CheckMinerPort

	stack.RegisterAPIs(backend.apis())
	stack.RegisterLifecycle(backend)

	return backend, nil
}

// Utility methods
func (backend *ReconfigBackend) apis() []rpc.API {
	return []rpc.API{
		{
			Namespace: "reconfig",
			Version:   "1.0",
			Service:   NewPublicReconfigAPI(backend),
			Public:    true,
		},
	}
}

// Backend interface methods:

func (backend *ReconfigBackend) AccountManager() *accounts.Manager  { return backend.accountManager }
func (backend *ReconfigBackend) BlockChain() *core.BlockChain       { return backend.blockchain }
func (backend *ReconfigBackend) KeyBlockChain() *core.KeyBlockChain { return backend.keyBlockchain }
func (backend *ReconfigBackend) ChainDb() ethdb.Database            { return backend.chainDb }
func (backend *ReconfigBackend) DappDb() ethdb.Database             { return nil }
func (backend *ReconfigBackend) EventMux() *event.TypeMux           { return backend.eventMux }
func (backend *ReconfigBackend) TxPool() *core.TxPool               { return backend.txPool }
func (backend *ReconfigBackend) CandidatePool() *core.CandidatePool { return backend.candidatePool }
func (backend *ReconfigBackend) Engine() consensus.Engine           { return backend.engine }
func (backend *ReconfigBackend) ConsensusServicePendingLogsFeed() *event.Feed {
	return backend.pendingLogsFeed
}

// node.Lifecycle interface methods:

func (backend *ReconfigBackend) Start() error {
	return nil
}

func (backend *ReconfigBackend) Stop() error {
	backend.service.stop()
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), 10*time.Second)
	if err := backend.service.shutdownFHSContentWriter(drainCtx); err != nil {
		log.Warn("FHS proposal content writer did not drain before shutdown deadline", "err", err)
	}
	cancelDrain()
	// blockchain, eventMux and chainDb are borrowed from eth.Ethereum. Their
	// owner stops them after this lifecycle has quiesced consensus and drained
	// the FHS writer; closing shared state here used to race the later ingress
	// WAL/outbox shutdown because node lifecycles stop in reverse order.
	log.Info("Raft stopped")
	return nil
}

// ------------------------------------------------------------------
func (backend *ReconfigBackend) MinerStart(config *common.NodeConfig) error {
	if err := backend.service.start(config); err != nil {
		return err
	}
	log.Info("reconfig start")
	return nil
}

func (backend *ReconfigBackend) MinerStop() error {
	backend.service.stop()
	log.Info("reconfig stop")
	return nil
}

// ReconfigIsRunning call by api
func (backend *ReconfigBackend) ServiceIsRunning() bool {
	return backend.service.isRunning()
}

func (backend *ReconfigBackend) Exceptions(blockNumber int64) []string {
	return backend.service.Exceptions(blockNumber)
}

func (backend *ReconfigBackend) CheckMinerPort(addr string, blockN uint64, keyblockN uint64) {
	backend.service.netService.CheckMinerPort(addr, blockN, keyblockN, 111)
}

// CurrentFHSRoute exposes the service route to subsystems (notably TxQUIC)
// without exporting the Service field from ReconfigBackend.
func (backend *ReconfigBackend) CurrentFHSRoute() (*FHSRoute, error) {
	if backend == nil || backend.service == nil {
		return nil, fmt.Errorf("reconfig service is unavailable")
	}
	return backend.service.CurrentFHSRoute()
}

// TxQUICReceiptPublicKey returns the validator identity that signs durable
// ingress acknowledgements. It is the same BLS identity committed in the FHS
// committee, not a replaceable TLS certificate key.
func (backend *ReconfigBackend) TxQUICReceiptPublicKey() ([]byte, error) {
	if backend == nil || backend.service == nil {
		return nil, fmt.Errorf("Fair HotStuff receipt identity is unavailable")
	}
	return backend.service.txQUICReceiptPublicKey()
}

// PoWResultTLSPublicKey returns the consensus BLS identity used to authenticate
// the fixed-mode PoW result listener.
func (backend *ReconfigBackend) PoWResultTLSPublicKey() ([]byte, error) {
	if backend == nil || backend.service == nil {
		return nil, fmt.Errorf("PoW result TLS identity is unavailable")
	}
	return backend.service.txQUICReceiptPublicKey()
}

func (s *Service) txQUICReceiptPublicKey() ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("Fair HotStuff receipt identity is unavailable")
	}
	s.muConsensusIdentity.RLock()
	secret, public := s.txQUICReceiptSecret, s.txQUICReceiptPublic
	s.muConsensusIdentity.RUnlock()
	if secret == nil || public == nil {
		return nil, fmt.Errorf("Fair HotStuff receipt identity is unavailable")
	}
	derived := secret.GetPublicKey()
	if derived == nil || !derived.IsEqual(public) {
		return nil, fmt.Errorf("Fair HotStuff receipt key pair is inconsistent")
	}
	return append([]byte(nil), public.Serialize()...), nil
}

// SignTxQUICReceipt signs one domain-separated TxQUIC acknowledgement digest
// only while this node's BLS key is a member of the exact canonical committee
// generation carried by the packet and acknowledgement.
func (backend *ReconfigBackend) SignTxQUICReceipt(keyNumber uint64, committeeHash common.Hash, digest []byte) ([]byte, error) {
	if backend == nil || backend.service == nil {
		return nil, fmt.Errorf("Fair HotStuff receipt signer is unavailable")
	}
	return backend.service.signTxQUICReceiptForGeneration(keyNumber, committeeHash, digest)
}

// SignPoWResultTLS signs a PoW-result transport certificate digest while the
// local consensus identity belongs to the canonical committee. Unlike a
// TxQUIC receipt, the TLS host identity is the validator's long-lived BLS key,
// so this check works for both legacy and Fair HotStuff fixed committees.
func (backend *ReconfigBackend) SignPoWResultTLS(generation common.Hash, digest []byte) ([]byte, error) {
	if backend == nil || backend.service == nil {
		return nil, fmt.Errorf("PoW result TLS signer is unavailable")
	}
	return backend.service.signPoWResultTLS(generation, digest)
}

func (s *Service) signPoWResultTLS(generation common.Hash, digest []byte) ([]byte, error) {
	if s == nil || generation == (common.Hash{}) || s.kbc == nil {
		return nil, fmt.Errorf("PoW result TLS signer is unavailable")
	}
	// The BLS implementation is not safe for concurrent use. Share the receipt
	// signer serialization because both protocols use the isolated receipt key.
	s.txQUICReceiptSignMu.Lock()
	defer s.txQUICReceiptSignMu.Unlock()
	keyBlock := s.kbc.CurrentBlock()
	if keyBlock == nil || keyBlock.Hash() != generation {
		return nil, fmt.Errorf("PoW result TLS keyblock generation changed before signing")
	}
	committee := bftview.GetCurrentMember()
	if committee == nil || len(committee.List) == 0 {
		return nil, fmt.Errorf("canonical PoW result committee is unavailable")
	}
	signature, err := s.signTxQUICReceiptLocked(digest, committee.List)
	if err != nil {
		return nil, err
	}
	keyBlock = s.kbc.CurrentBlock()
	if keyBlock == nil || keyBlock.Hash() != generation {
		return nil, fmt.Errorf("PoW result TLS keyblock generation changed while signing")
	}
	return signature, nil
}

func (s *Service) signTxQUICReceiptForGeneration(keyNumber uint64, committeeHash common.Hash, digest []byte) ([]byte, error) {
	if s == nil || committeeHash == (common.Hash{}) {
		return nil, fmt.Errorf("invalid Fair HotStuff receipt generation")
	}
	// Serialize the non-thread-safe BLS secret before taking the view lock. ACK
	// bursts then wait without blocking HotStuff view/QC transitions.
	s.txQUICReceiptSignMu.Lock()
	defer s.txQUICReceiptSignMu.Unlock()
	// Hold the authoritative view lock through the short membership check and
	// BLS operation. A key-block transition cannot move the committee between
	// validation and signing.
	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()
	if err := s.refreshFHSRouteBaseLocked(); err != nil {
		return nil, err
	}
	view := s.currentView
	if view.KeyNumber != keyNumber || view.CommitteeHash != committeeHash {
		return nil, fmt.Errorf("Fair HotStuff committee changed before TxQUIC receipt signing")
	}
	committee, err := s.loadViewCommittee(&view, true)
	if err != nil {
		return nil, err
	}
	if committee == nil || len(committee.List) == 0 || committee.RlpHash() != committeeHash {
		return nil, fmt.Errorf("Fair HotStuff receipt committee is unavailable")
	}
	return s.signTxQUICReceiptLocked(digest, committee.List)
}

func (s *Service) signTxQUICReceiptLocked(digest []byte, committee []*common.Cnode) ([]byte, error) {
	publicKey, err := s.txQUICReceiptPublicKey()
	if err != nil {
		return nil, err
	}
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("invalid TxQUIC receipt digest length")
	}
	authorized := false
	for _, member := range committee {
		if member == nil {
			continue
		}
		candidate := bls.GetPublicKey(common.FromHex(member.Public))
		if candidate != nil && bytes.Equal(candidate.Serialize(), publicKey) {
			authorized = true
			break
		}
	}
	if !authorized {
		return nil, fmt.Errorf("local TxQUIC receipt signer is outside the active committee")
	}
	s.muConsensusIdentity.RLock()
	secret := s.txQUICReceiptSecret
	s.muConsensusIdentity.RUnlock()
	if secret == nil {
		return nil, fmt.Errorf("Fair HotStuff receipt signing key is unavailable")
	}
	signature := secret.SignHash(digest)
	if signature == nil {
		return nil, fmt.Errorf("failed to sign TxQUIC receipt")
	}
	return append([]byte(nil), signature.Serialize()...), nil
}

func (s *Service) Exceptions(blockNumber int64) []string {
	block := s.bc.GetBlockByNumber(uint64(blockNumber))
	if block == nil {
		return nil
	}
	cm := s.kbc.GetCommitteeByHash(block.KeyHash())
	if cm == nil {
		return nil
	}
	indexs := hotstuff.MaskToExceptionIndexs(block.SignInfo().Exceptions, len(cm))
	if indexs == nil {
		return nil
	}
	var exs []string
	for _, i := range indexs {
		exs = append(exs, cm[i].CoinBase)
	}
	return exs
}
