// Copyright 2017 The cypherBFT Authors
// This file is part of the cypherBFT library.
//
// The cypherBFT library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The cypherBFT library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the cypherBFT library. If not, see <http://www.gnu.org/licenses/>.

package reconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/math"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/rnet"
	"github.com/cypherium/cypher/rnet/network"
	"golang.org/x/crypto/sha3"
)

type serviceCallback interface {
	networkMsgAck(si *network.ServerIdentity, msg *networkMsg)
}

const Gossip_MSG = 8

const (
	peerQueueInputCapacity     = 64
	peerQueueControlMaxEntries = 4096
	peerQueueControlMaxBytes   = 16 * 1024 * 1024
	// Production queues share a global budget. Keep every peer below 1/100 of
	// that budget so even all f Byzantine peers cannot consume the slots that
	// an honest member needs. Fair HotStuff limits committees to 100 members.
	peerQueueFairControlMaxEntries = 8
	peerQueueFairControlMaxBytes   = 640 * 1024
	peerQueueBulkMaxEntries        = 16
	peerQueueBulkMaxBytes          = proposalBodySidecarMaxBytes + 1024*1024
	peerQueueProducerWait          = 100 * time.Millisecond
	peerQueueRetryTTL              = 2 * time.Minute
	peerQueueMessageOverhead       = 512
	peerQueueBulkSendWorkers       = 4

	outboundControlMaxEntries = 1024
	outboundControlMaxBytes   = 64 * 1024 * 1024
	outboundBulkMaxReferences = 256
	outboundBulkMaxBytes      = 2 * peerQueueBulkMaxBytes
)

type heartBeatMsg struct {
	BlockN uint64
}

func (msg *heartBeatMsg) NetworkClass() uint8 {
	return network.NetClassHeartbeat
}

type checkMinerMsg struct {
	BlockN    uint64
	KeyblockN uint64
	AckFlag   uint64
}

func (msg *checkMinerMsg) NetworkClass() uint8 {
	return network.NetClassCandidateMiner
}

type ackInfo struct {
	ackTm     time.Time
	sendTm    time.Time
	isSending *int32 // atomic int
}

type msgHeadInfo struct {
	blockN    uint64
	keyblockN uint64
}

type peerQueues struct {
	input           chan *networkMsg
	priorityInput   chan *networkMsg
	nextHotstuff    chan *networkMsg
	nextMetadata    chan *networkMsg
	nextBulk        chan *networkMsg
	stop            chan struct{}
	once            sync.Once
	lifecycleMu     sync.Mutex
	mu              sync.Mutex
	closed          bool
	controlCount    int
	controlBytes    int
	bulkCount       int
	bulkBytes       int
	budget          *outboundQueueBudget
	controlDigests  map[[32]byte]struct{}
	controlMaxCount int
	controlMaxBytes int
}

type outboundBulkRef struct {
	refs int
	size int
}

// outboundQueueBudget bounds the aggregate memory retained across all peer
// queues. Proposal bodies are immutable after sealing and are shared between
// destinations, so their bytes are charged once while every queued reference
// is still counted.
type outboundQueueBudget struct {
	mu sync.Mutex

	controlCount int
	controlBytes int
	bulkRefs     int
	bulkBytes    int
	bulkPayloads map[*proposalBodyMsg]*outboundBulkRef
}

func newOutboundQueueBudget() *outboundQueueBudget {
	return &outboundQueueBudget{bulkPayloads: make(map[*proposalBodyMsg]*outboundBulkRef)}
}

func (budget *outboundQueueBudget) reserve(msg *networkMsg) bool {
	if budget == nil || msg == nil {
		return budget == nil
	}
	size := peerQueueMessageBytes(msg)
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if isHighPriorityNetworkMsg(msg) {
		if size > outboundControlMaxBytes || budget.controlCount >= outboundControlMaxEntries || budget.controlBytes > outboundControlMaxBytes-size {
			return false
		}
		budget.controlCount++
		budget.controlBytes += size
		return true
	}
	if budget.bulkRefs >= outboundBulkMaxReferences {
		return false
	}
	if msg.Pmsg != nil {
		if ref := budget.bulkPayloads[msg.Pmsg]; ref != nil {
			ref.refs++
			budget.bulkRefs++
			return true
		}
	}
	if size > outboundBulkMaxBytes || budget.bulkBytes > outboundBulkMaxBytes-size {
		return false
	}
	budget.bulkRefs++
	budget.bulkBytes += size
	if msg.Pmsg != nil {
		budget.bulkPayloads[msg.Pmsg] = &outboundBulkRef{refs: 1, size: size}
	}
	return true
}

func (budget *outboundQueueBudget) release(msg *networkMsg) {
	if budget == nil || msg == nil {
		return
	}
	size := peerQueueMessageBytes(msg)
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if isHighPriorityNetworkMsg(msg) {
		if budget.controlCount > 0 {
			budget.controlCount--
		}
		if size >= budget.controlBytes {
			budget.controlBytes = 0
		} else {
			budget.controlBytes -= size
		}
		return
	}
	if budget.bulkRefs > 0 {
		budget.bulkRefs--
	}
	if msg.Pmsg != nil {
		if ref := budget.bulkPayloads[msg.Pmsg]; ref != nil {
			ref.refs--
			if ref.refs > 0 {
				return
			}
			if ref.size >= budget.bulkBytes {
				budget.bulkBytes = 0
			} else {
				budget.bulkBytes -= ref.size
			}
			delete(budget.bulkPayloads, msg.Pmsg)
			return
		}
	}
	if size >= budget.bulkBytes {
		budget.bulkBytes = 0
	} else {
		budget.bulkBytes -= size
	}
}

func newPeerQueues() *peerQueues {
	return newPeerQueuesWithBudget(nil)
}

func newPeerQueuesWithBudget(budget *outboundQueueBudget) *peerQueues {
	maxCount, maxBytes := peerQueueControlMaxEntries, peerQueueControlMaxBytes
	if budget != nil {
		maxCount, maxBytes = peerQueueFairControlMaxEntries, peerQueueFairControlMaxBytes
	}
	q := &peerQueues{
		input:           make(chan *networkMsg, peerQueueInputCapacity),
		priorityInput:   make(chan *networkMsg, peerQueueInputCapacity),
		nextHotstuff:    make(chan *networkMsg),
		nextMetadata:    make(chan *networkMsg),
		nextBulk:        make(chan *networkMsg),
		stop:            make(chan struct{}),
		budget:          budget,
		controlDigests:  make(map[[32]byte]struct{}),
		controlMaxCount: maxCount,
		controlMaxBytes: maxBytes,
	}
	go q.run()
	return q
}

func (q *peerQueues) run() {
	var classes [7][]*networkMsg
	for {
		select {
		case msg := <-q.priorityInput:
			class := peerQueueClass(msg)
			classes[class] = append(classes[class], msg)
			continue
		default:
		}

		var hotstuffNext, metadataNext, bulkNext *networkMsg
		if len(classes[0]) > 0 {
			hotstuffNext = classes[0][0]
		}
		for class := 1; class <= 4; class++ {
			if len(classes[class]) > 0 {
				metadataNext = classes[class][0]
				break
			}
		}
		for class := 5; class <= 6; class++ {
			if len(classes[class]) > 0 {
				bulkNext = classes[class][0]
				break
			}
		}
		var hotstuffOut, metadataOut, bulkOut chan *networkMsg
		if hotstuffNext != nil {
			hotstuffOut = q.nextHotstuff
		}
		if metadataNext != nil {
			metadataOut = q.nextMetadata
		}
		if bulkNext != nil {
			bulkOut = q.nextBulk
		}

		select {
		case msg := <-q.priorityInput:
			class := peerQueueClass(msg)
			classes[class] = append(classes[class], msg)
		case msg := <-q.input:
			class := peerQueueClass(msg)
			classes[class] = append(classes[class], msg)
		case hotstuffOut <- hotstuffNext:
			class := peerQueueClass(hotstuffNext)
			classes[class][0] = nil
			classes[class] = classes[class][1:]
		case metadataOut <- metadataNext:
			class := peerQueueClass(metadataNext)
			classes[class][0] = nil
			classes[class] = classes[class][1:]
		case bulkOut <- bulkNext:
			class := peerQueueClass(bulkNext)
			classes[class][0] = nil
			classes[class] = classes[class][1:]
		case <-q.stop:
			q.releasePending(classes)
			return
		}
	}
}

func (q *peerQueues) releasePending(classes [7][]*networkMsg) {
	for i := range classes {
		for _, msg := range classes[i] {
			q.release(msg)
		}
	}
	for {
		select {
		case msg := <-q.priorityInput:
			q.release(msg)
		default:
			goto drainNormal
		}
	}
drainNormal:
	for {
		select {
		case msg := <-q.input:
			q.release(msg)
		default:
			return
		}
	}
}

func peerQueueClass(msg *networkMsg) int {
	if msg == nil {
		return 6
	}
	switch msg.NetworkClass() {
	case network.NetClassHotstuffControl:
		return 0
	case network.NetClassProposalBodyControl:
		return 1
	case network.NetClassCommitteeControl:
		return 2
	case network.NetClassCandidateMiner:
		return 3
	case network.NetClassHeartbeat:
		return 4
	case network.NetClassProposalBodyBulk:
		return 5
	default:
		return 6
	}
}

func (q *peerQueues) push(msg *networkMsg) bool {
	return q.pushMessage(msg, true)
}

func peerQueueMessageBytes(msg *networkMsg) int {
	if msg == nil {
		return peerQueueMessageOverhead
	}
	if err := validateNetworkMsgShape(msg); err != nil {
		return peerQueueControlMaxBytes + peerQueueBulkMaxBytes + 1
	}
	if msg.Hmsg != nil {
		return queuedHotstuffMessageBytes(&hotstuffMsg{hMsg: msg.Hmsg}) + peerQueueMessageOverhead
	}
	if msg.Pmsg != nil {
		return peerQueueMessageOverhead + proposalBodyMsgPayloadBytes(msg.Pmsg)
	}
	encoded, err := rlp.EncodeToBytes(msg)
	if err != nil {
		return peerQueueControlMaxBytes + 1
	}
	return peerQueueMessageOverhead + len(encoded)
}

func outboundControlDigest(msg *networkMsg) ([32]byte, bool) {
	if msg == nil || !isHighPriorityNetworkMsg(msg) {
		return [32]byte{}, false
	}
	var (
		encoded []byte
		err     error
	)
	if msg.Hmsg != nil {
		canonical := *msg.Hmsg
		canonical.ReceivedAt = time.Time{}
		encoded, err = rlp.EncodeToBytes([]interface{}{msg.MsgFlag, &canonical})
	} else {
		encoded, err = rlp.EncodeToBytes(msg)
	}
	if err != nil {
		return [32]byte{}, false
	}
	return sha256.Sum256(encoded), true
}

func (q *peerQueues) reserve(msg *networkMsg) (bool, bool) {
	if q == nil || msg == nil {
		return false, false
	}
	size := peerQueueMessageBytes(msg)
	priority := isHighPriorityNetworkMsg(msg)
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false, false
	}
	if priority {
		digest, hasDigest := outboundControlDigest(msg)
		if hasDigest {
			if _, duplicate := q.controlDigests[digest]; duplicate {
				return false, true
			}
		}
		if size > q.controlMaxBytes || q.controlCount >= q.controlMaxCount || q.controlBytes > q.controlMaxBytes-size {
			return false, false
		}
		q.controlCount++
		q.controlBytes += size
		if q.budget == nil || q.budget.reserve(msg) {
			if hasDigest {
				q.controlDigests[digest] = struct{}{}
			}
			return true, false
		}
		q.controlCount--
		q.controlBytes -= size
		return false, false
	}
	if size > peerQueueBulkMaxBytes || q.bulkCount >= peerQueueBulkMaxEntries || q.bulkBytes > peerQueueBulkMaxBytes-size {
		return false, false
	}
	q.bulkCount++
	q.bulkBytes += size
	if q.budget == nil || q.budget.reserve(msg) {
		return true, false
	}
	q.bulkCount--
	q.bulkBytes -= size
	return false, false
}

func (q *peerQueues) release(msg *networkMsg) {
	if q == nil || msg == nil {
		return
	}
	size := peerQueueMessageBytes(msg)
	q.mu.Lock()
	if isHighPriorityNetworkMsg(msg) {
		if digest, ok := outboundControlDigest(msg); ok {
			delete(q.controlDigests, digest)
		}
		if q.controlCount > 0 {
			q.controlCount--
		}
		if size >= q.controlBytes {
			q.controlBytes = 0
		} else {
			q.controlBytes -= size
		}
	} else {
		if q.bulkCount > 0 {
			q.bulkCount--
		}
		if size >= q.bulkBytes {
			q.bulkBytes = 0
		} else {
			q.bulkBytes -= size
		}
	}
	if q.budget != nil {
		q.budget.release(msg)
	}
	q.mu.Unlock()
}

func (q *peerQueues) pushMessage(msg *networkMsg, clone bool) bool {
	if q == nil || msg == nil {
		return false
	}
	if err := validateNetworkMsgShape(msg); err != nil {
		return false
	}
	q.lifecycleMu.Lock()
	defer q.lifecycleMu.Unlock()
	reserved, coalesced := q.reserve(msg)
	if coalesced {
		return true
	}
	if !reserved {
		return false
	}
	queued := msg
	if clone {
		queued = cloneNetworkMsgForQueue(msg)
	}
	if queued == nil {
		q.release(msg)
		return false
	}
	if queued.queueSince.IsZero() {
		queued.queueSince = time.Now()
	}
	input := q.input
	if isHighPriorityNetworkMsg(queued) {
		input = q.priorityInput
	}
	timer := time.NewTimer(peerQueueProducerWait)
	defer timer.Stop()
	select {
	case input <- queued:
		return true
	case <-q.stop:
		q.release(queued)
		return false
	case <-timer.C:
		q.release(queued)
		return false
	}
}

func (q *peerQueues) pushFrontClass(msg *networkMsg) bool {
	// Requeue at the tail of the same priority class to preserve FIFO and avoid
	// retrying a failed send in a tight loop.
	if msg == nil || msg.queueSince.IsZero() || time.Since(msg.queueSince) > peerQueueRetryTTL {
		return false
	}
	msg.queueAttempts++
	return q.pushMessage(msg, false)
}

func outboundMessageExpired(msg *networkMsg, now time.Time) bool {
	return msg != nil && !msg.queueSince.IsZero() && now.Sub(msg.queueSince) > peerQueueRetryTTL
}

func (q *peerQueues) close() {
	if q != nil {
		q.once.Do(func() {
			q.lifecycleMu.Lock()
			defer q.lifecycleMu.Unlock()
			q.mu.Lock()
			q.closed = true
			q.mu.Unlock()
			close(q.stop)
		})
	}
}

type netService struct {
	*rnet.ServiceProcessor // We need to embed the ServiceProcessor, so that incoming messages are correctly handled.
	server                 *rnet.Server
	serverAddress          string
	serverID               string
	gossipMsg              map[common.Hash]*msgHeadInfo
	muGossip               sync.Mutex

	goMap    map[string]*int32 // atomic int
	idQueues map[string]*peerQueues
	ackMap   map[string]*ackInfo
	muIdMap  sync.Mutex

	peerAuthMu     sync.RWMutex
	peerAuthKeys   map[string][]byte
	outboundBudget *outboundQueueBudget

	lifecycleMu     sync.Mutex
	workerWG        sync.WaitGroup
	lifecycleActive bool
	networkStarted  bool
	generation      atomic.Uint64

	backend       serviceCallback
	curBlockN     uint64
	curKeyBlockN  uint64
	isStoping     atomic.Bool
	candidatepool *core.CandidatePool
	bc            *core.BlockChain
	kbc           *core.KeyBlockChain
}

func newNetService(sName, sIp string, chainConfig *params.ChainConfig, backend *ReconfigBackend, callback serviceCallback) *netService {
	registerService := func(c *rnet.Context) (rnet.Service, error) {
		s := &netService{ServiceProcessor: rnet.NewServiceProcessor(c)}
		s.RegisterProcessorFunc(network.RegisterMessage(&networkMsg{}), s.handleNetworkMsgAck)
		s.RegisterProcessorFunc(network.RegisterMessage(&heartBeatMsg{}), s.handleHeartBeatMsgAck)
		s.RegisterProcessorFunc(network.RegisterMessage(&checkMinerMsg{}), s.handleCheckMinerMsgAck)

		return s, nil
	}
	rnet.RegisterNewService(sName, registerService)
	transport := "quic"
	fallback := "tcp"
	if chainConfig != nil {
		transport = chainConfig.EffectiveRnetTransport()
		fallback = chainConfig.EffectiveRnetFallbackTransport()
	}
	server := rnet.NewServerWithTransport(sIp, transport, fallback)
	s := server.Service(sName).(*netService)
	s.server = server
	s.serverID = sIp
	s.serverAddress = sIp

	s.gossipMsg = make(map[common.Hash]*msgHeadInfo)
	s.goMap = make(map[string]*int32)
	s.idQueues = make(map[string]*peerQueues)
	s.ackMap = make(map[string]*ackInfo)
	s.peerAuthKeys = make(map[string][]byte)
	s.outboundBudget = newOutboundQueueBudget()
	s.backend = callback
	s.candidatepool = backend.CandidatePool()
	s.bc = backend.BlockChain()
	s.kbc = backend.KeyBlockChain()

	return s
}

func (s *netService) StartStop(isStart bool) {
	if isStart {
		// A restart must not revive workers from the previous generation after
		// isStoping becomes false. Stopping prevents new WaitGroup additions, so
		// waiting here is safe and gives the next generation empty queue maps.
		s.lifecycleMu.Lock()
		if s.lifecycleActive {
			s.lifecycleMu.Unlock()
			return
		}
		wasStopping := s.isStoping.Load()
		s.lifecycleMu.Unlock()
		if wasStopping {
			s.workerWG.Wait()
		}

		s.lifecycleMu.Lock()
		if s.lifecycleActive {
			s.lifecycleMu.Unlock()
			return
		}
		s.isStoping.Store(false)
		generation := s.generation.Add(1)
		s.lifecycleActive = true
		if !s.networkStarted {
			s.server.Start()
			s.networkStarted = true
		}
		s.workerWG.Add(1)
		go func() {
			defer s.workerWG.Done()
			s.heartBeat_Loop(generation)
		}()
		s.lifecycleMu.Unlock()
		return
	}

	s.lifecycleMu.Lock()
	if !s.lifecycleActive {
		s.lifecycleMu.Unlock()
		return
	}
	s.lifecycleActive = false
	s.isStoping.Store(true)
	s.generation.Add(1)
	s.muIdMap.Lock()
	queues := make([]*peerQueues, 0, len(s.idQueues))
	for address, queue := range s.idQueues {
		if running := s.goMap[address]; running != nil {
			atomic.StoreInt32(running, 2)
		}
		queues = append(queues, queue)
	}
	s.muIdMap.Unlock()
	for _, queue := range queues {
		queue.close()
	}
	s.lifecycleMu.Unlock()
}

func (s *netService) serverIdentityFor(address string) *network.ServerIdentity {
	transport := network.PlainKCP
	if s != nil && s.server != nil && s.server.Address().ConnType() != network.InvalidConnType {
		transport = s.server.Address().ConnType()
	}
	identity := network.NewServerIdentityWithTransport(address, transport)
	s.peerAuthMu.RLock()
	if publicKey := s.peerAuthKeys[address]; len(publicKey) > 0 {
		identity.PublicKey = append([]byte(nil), publicKey...)
	}
	s.peerAuthMu.RUnlock()
	if len(identity.PublicKey) > 0 {
		return identity
	}
	if committee := bftview.GetCurrentMember(); committee != nil {
		if node, _ := committee.Get(address, bftview.Address); node != nil {
			if publicKey, err := hex.DecodeString(node.Public); err == nil {
				identity.PublicKey = publicKey
			}
		}
	}
	return identity
}

func (s *netService) setAuthenticatedPeerKeys(peers map[string][]byte) {
	if s == nil {
		return
	}
	copyPeers := make(map[string][]byte, len(peers))
	for address, publicKey := range peers {
		copyPeers[address] = append([]byte(nil), publicKey...)
	}
	s.peerAuthMu.Lock()
	s.peerAuthKeys = copyPeers
	s.peerAuthMu.Unlock()
}

// ----------------------------------------------------------------------------------------------------
func (s *netService) CheckMinerPort(addr string, blockN uint64, keyblockN uint64, ackFlag uint64) {
	msg := &checkMinerMsg{BlockN: blockN, KeyblockN: keyblockN, AckFlag: ackFlag}
	log.Info("CheckMinerPort", "addr", addr, "msg", msg)
	si := s.serverIdentityFor(addr)
	go s.SendRaw(si, msg, true)
}

func (s *netService) handleCheckMinerMsgAck(env *network.Envelope) {
	msg, ok := env.Msg.(*checkMinerMsg)
	if !ok {
		log.Error("handleCheckMinerMsgAck failed to cast to ")
		return
	}
	si := env.ServerIdentity
	address := si.Address.String()
	log.Debug("handleCheckMinerMsgAck Recv", "from address", address, "blockN", msg.BlockN, "keyblockN", msg.KeyblockN, "ackFlag", msg.AckFlag)
	if msg.AckFlag == 111 {
		s.CheckMinerPort(address, s.bc.CurrentBlockN(), s.kbc.CurrentBlockN(), 0)
	} else {
		s.candidatepool.CheckMinerMsgAck(address, msg.BlockN, msg.KeyblockN)
	}
}

// ----------------------------------------------------------------------------------------------------
func (s *netService) AdjustConnect(outAddress string) {
	s.setIsRunning(outAddress, false)
}

func (s *netService) procBlockDone(blockN, keyblockN uint64) {
	atomic.StoreUint64(&s.curBlockN, blockN)
	atomic.StoreUint64(&s.curKeyBlockN, keyblockN)

	// clear old cache of gossipMsg
	s.muGossip.Lock()
	for k, h := range s.gossipMsg {
		if (h.blockN > 0 && h.blockN < blockN) || (h.keyblockN > 0 && h.keyblockN < keyblockN) {
			delete(s.gossipMsg, k)
		}
	}
	s.muGossip.Unlock()
	s.ResetAckTime("")
}

func (s *netService) handleNetworkMsgAck(env *network.Envelope) {
	msg, ok := env.Msg.(*networkMsg)
	if !ok {
		log.Error("handleNetworkMsgReq failed to cast to ")
		return
	}
	if err := validateNetworkMsgShape(msg); err != nil {
		log.Warn("reject malformed network message", "err", err)
		return
	}
	si := env.ServerIdentity
	address := si.Address.String()
	// log.Info("handleNetworkMsgReq Recv", "from address", address)
	s.getAckInfo(address).ackTm = time.Now()

	if s.IgnoreMsg(msg) {
		return
	}

	if (msg.MsgFlag & Gossip_MSG) > 0 {
		hash := rlpHash(msg)
		s.muGossip.Lock()
		m, ok := s.gossipMsg[hash]
		s.muGossip.Unlock()
		if !ok {
			s.broadcast(address, msg)
		} else {
			log.Info("Gossip_MSG Recv Same", "hash", hash, "keyblockN", m.keyblockN, "blockN", m.blockN)
			return
		}
	}
	s.backend.networkMsgAck(si, msg)
}

func (s *netService) broadcast(fromAddr string, msg *networkMsg) {
	if msg == nil {
		log.Error("broadcast", "error", "nil network message")
		return
	}
	if err := validateNetworkMsgShape(msg); err != nil {
		log.Warn("refusing to broadcast malformed network message", "err", err)
		return
	}
	mb := msg.GetCommittee()
	if mb == nil {
		log.Error("broadcast", "error", "can't find current committee")
		return
	}
	if fromAddr != "" {
		p, _ := mb.Get(fromAddr, bftview.Address)
		if p == nil {
			log.Error("broadcast", "can't find current committee address", fromAddr)
			return
		}
	}

	// Production rule: HotStuff control messages must not depend on random gossip
	// fanout. Service.Broadcast and Service.Write deliver them directly. Refuse
	// to gossip them here if a future caller accidentally routes them through this
	// data-plane path.
	if msg.Hmsg != nil {
		switch msg.Hmsg.Code {
		case hotstuff.MsgNewView, hotstuff.MsgPrepare, hotstuff.MsgVotePrepare, hotstuff.MsgQCBroadcast, hotstuff.MsgDecide,
			hotstuff.MsgTimeout, hotstuff.MsgTimeoutQC:
			log.Warn("refusing to gossip hotstuff control message",
				"code", hotstuff.ReadableMsgType(msg.Hmsg.Code),
				"number", msg.Hmsg.Number,
				"viewID", msg.Hmsg.ViewId)
			return
		}
	}

	gossipMsg := cloneNetworkMsg(msg)
	gossipMsg.MsgFlag = Gossip_MSG
	hash := rlpHash(gossipMsg)
	hInfo := s.getMsgHeadInfo(gossipMsg)
	log.Info("Gossip_MSG broadcast", "hash", hash, "keyblockN", hInfo.keyblockN, "blockN", hInfo.blockN)

	s.muGossip.Lock()
	s.gossipMsg[hash] = hInfo
	s.muGossip.Unlock()

	mblist := mb.List
	n := len(mblist)
	seedIndexs := math.GetRandIntArray(n, n/2+3)

	for i, selected := range seedIndexs {
		if !selected {
			continue
		}
		if i >= len(mblist) {
			continue
		}

		node := mblist[i]
		if node == nil || node.Address == "" {
			continue
		}
		if IsSelf(node.Address) {
			continue
		}
		if err := s.SendRawData(node.Address, cloneNetworkMsg(gossipMsg)); err != nil {
			log.Warn("Gossip_MSG send failed", "to", node.Address, "hash", hash, "err", err)
		}
	}
}

func (s *netService) SendRawData(address string, msg *networkMsg) error {
	if msg == nil {
		return network.NewPermanentSendError(network.SendErrorInvalidMessage,
			fmt.Errorf("nil network message"))
	}
	if err := validateNetworkMsgShape(msg); err != nil {
		return network.NewPermanentSendError(network.SendErrorInvalidMessage, err)
	}
	if address == "" {
		return fmt.Errorf("empty destination address")
	}
	if address == s.serverAddress {
		return nil
	}

	s.setIsRunning(address, true)
	s.muIdMap.Lock()
	queues := s.idQueues[address]
	s.muIdMap.Unlock()

	if queues == nil {
		return fmt.Errorf("queue not found for %s", address)
	}
	if !queues.push(msg) {
		return fmt.Errorf("queue closed for %s", address)
	}
	return nil
}

func (s *netService) loop_iddata(address string, queues *peerQueues, isRunning *int32, generation uint64) {
	log.Debug("loop_iddata start", "address", address)

	var lanes sync.WaitGroup
	launch := func(next <-chan *networkMsg, workers int) {
		for worker := 0; worker < workers; worker++ {
			lanes.Add(1)
			go func() {
				defer lanes.Done()
				s.loopPeerSendLane(address, queues, isRunning, generation, next)
			}()
		}
	}
	launch(queues.nextHotstuff, 1)
	launch(queues.nextMetadata, 1)
	launch(queues.nextBulk, peerQueueBulkSendWorkers)

	lifecycleTicker := time.NewTicker(10 * time.Millisecond)
waitForStop:
	for !s.isStoping.Load() && s.generation.Load() == generation && atomic.LoadInt32(isRunning) == 1 {
		select {
		case <-queues.stop:
			break waitForStop
		case <-lifecycleTicker.C:
		}
	}
	lifecycleTicker.Stop()
	queues.close()
	lanes.Wait()

	atomic.StoreInt32(isRunning, 0)

	s.removePeerWorkerIfOwned(address, queues, isRunning)

	log.Debug("loop_iddata exit", "id", address)
}

func (s *netService) loopPeerSendLane(address string, queues *peerQueues, isRunning *int32, generation uint64, next <-chan *networkMsg) {
	for {
		var msg *networkMsg
		select {
		case <-queues.stop:
			return
		case msg = <-next:
		}
		if msg == nil {
			continue
		}
		if s.isStoping.Load() || s.generation.Load() != generation || atomic.LoadInt32(isRunning) != 1 {
			queues.release(msg)
			return
		}
		if outboundMessageExpired(msg, time.Now()) {
			queues.release(msg)
			log.Warn("drop expired outbound network message before send", "to", address, "class", msg.NetworkClass())
			continue
		}
		if s.IgnoreMsg(msg) {
			queues.release(msg)
			continue
		}
		si := s.serverIdentityFor(address)
		if s.GetNetBlocks(si) >= peerQueueBulkSendWorkers && !isHighPriorityNetworkMsg(msg) {
			queues.release(msg)
			if !s.IgnoreMsg(msg) && !queues.pushFrontClass(msg) {
				log.Warn("drop expired or saturated outbound network message", "to", address, "class", msg.NetworkClass())
			}
			time.Sleep(2 * time.Millisecond)
			continue
		}
		sendErr := s.SendRaw(si, msg, false)
		queues.release(msg)
		if sendErr == nil {
			continue
		}
		log.Warn("SendRawData", "couldn't send to", address, "error", sendErr)
		if retryableConsensusSendError(msg, sendErr) && !s.IgnoreMsg(msg) {
			if !queues.pushFrontClass(msg) {
				log.Warn("drop expired or saturated consensus retry", "to", address, "class", msg.NetworkClass())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func (s *netService) removePeerWorkerIfOwned(address string, queues *peerQueues, isRunning *int32) bool {
	s.muIdMap.Lock()
	defer s.muIdMap.Unlock()
	// A send can replace a stopping worker with a fresh queue. An old worker
	// must only remove the exact map entry it owns, never its successor.
	if s.goMap[address] != isRunning || s.idQueues[address] != queues {
		return false
	}
	delete(s.goMap, address)
	delete(s.idQueues, address)
	delete(s.ackMap, address)
	return true
}

func (s *netService) getMsgHeadInfo(msg *networkMsg) *msgHeadInfo {
	hInfo := new(msgHeadInfo)
	if msg.Cmsg != nil {
		hInfo.keyblockN = msg.Cmsg.KeyNumber
		hInfo.blockN = 0
	} else if msg.Bmsg != nil {
		hInfo.keyblockN = msg.Bmsg.KeyNumber
		hInfo.blockN = 0
	} else if msg.Hmsg != nil {
		hInfo.keyblockN = 0
		hInfo.blockN = msg.Hmsg.Number
	} else if msg.Pmsg != nil {
		hInfo.keyblockN = 0
		hInfo.blockN = msg.Pmsg.Number
	}
	return hInfo
}

func (s *netService) IgnoreMsg(m *networkMsg) bool {
	if m.Cmsg != nil {
		if m.Cmsg.KeyNumber < atomic.LoadUint64(&s.curKeyBlockN) {
			return true
		}
	} else if m.Bmsg != nil {
		if m.Bmsg.KeyNumber < atomic.LoadUint64(&s.curKeyBlockN) {
			return true
		}
	} else if m.Hmsg != nil {
		if m.Hmsg.Number < atomic.LoadUint64(&s.curBlockN) {
			return true
		}
	} else if m.Pmsg != nil {
		if m.Pmsg.Number < atomic.LoadUint64(&s.curBlockN) {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------------------------------
func (s *netService) isRunning(id string) int32 {
	s.muIdMap.Lock()
	isRunning, ok := s.goMap[id]
	s.muIdMap.Unlock()
	if ok {
		return atomic.LoadInt32(isRunning)
	}
	return 0
}

func (s *netService) setIsRunning(id string, isStart bool) {
	s.lifecycleMu.Lock()
	if isStart && (!s.lifecycleActive || s.isStoping.Load()) {
		s.lifecycleMu.Unlock()
		return
	}
	generation := s.generation.Load()
	s.muIdMap.Lock()
	isRunning := s.goMap[id]
	if !isStart {
		if isRunning != nil {
			atomic.CompareAndSwapInt32(isRunning, 1, 2)
		}
		s.muIdMap.Unlock()
		s.lifecycleMu.Unlock()
		return
	}
	if isRunning != nil && atomic.LoadInt32(isRunning) == 1 {
		s.muIdMap.Unlock()
		s.lifecycleMu.Unlock()
		return
	}
	// Missing, stopped, or stopping workers are replaced as one map
	// transaction. loop_iddata receives these exact identities so its cleanup
	// cannot delete a later replacement.
	isRunning = new(int32)
	atomic.StoreInt32(isRunning, 1)
	queues := newPeerQueuesWithBudget(s.outboundBudget)
	s.goMap[id] = isRunning
	s.idQueues[id] = queues
	s.muIdMap.Unlock()
	s.workerWG.Add(1)
	go func() {
		defer s.workerWG.Done()
		s.loop_iddata(id, queues, isRunning, generation)
	}()
	s.lifecycleMu.Unlock()
}

// -------------------------------------------------------------------------------------------------------------------------------------------
func (s *netService) handleHeartBeatMsgAck(env *network.Envelope) {
	_, ok := env.Msg.(*heartBeatMsg)
	if !ok {
		log.Error("handleNetworkMsgReq failed to cast to ")
		return
	}
	si := env.ServerIdentity
	address := si.Address.String()
	// log.Info("handleHeartBeatMsgAck Recv", "from address", address, "blockN", msg.blockN)
	s.getAckInfo(address).ackTm = time.Now()
}

func (s *netService) getAckInfo(addr string) *ackInfo {
	s.muIdMap.Lock()
	a := s.ackMap[addr]
	if a == nil {
		a = new(ackInfo)
		a.isSending = new(int32)
		a.ackTm = time.Now()
		s.ackMap[addr] = a
	}
	s.muIdMap.Unlock()
	return a
}

func (s *netService) heartBeat_Loop(generation uint64) {
	heatBeatTimeout := params.HeatBeatTimeout
	for !s.isStoping.Load() && s.generation.Load() == generation {
		mb := bftview.GetCurrentMember()
		if mb == nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		now := time.Now()
		msg := &heartBeatMsg{BlockN: atomic.LoadUint64(&s.curBlockN)}
		for _, node := range mb.List {
			if IsSelf(node.Address) {
				continue
			}
			addr := node.Address
			a := s.getAckInfo(addr)
			if a != nil && now.Sub(a.sendTm) > heatBeatTimeout {
				if atomic.LoadInt32(a.isSending) == 0 {
					si := s.serverIdentityFor(addr)
					if s.GetNetBlocks(si) == 0 {
						a.sendTm = time.Now()
						go func(si *network.ServerIdentity, msg interface{}, isRunning *int32) {
							atomic.StoreInt32(isRunning, 1)
							s.SendRaw(si, msg, false)
							// log.Debug("sendHeartBeatMsg", "address", si.Address, "tm", time.Now(), "error", err)
							atomic.StoreInt32(isRunning, 0)
						}(si, msg, a.isSending)
					}
				}
				continue
			}
		}
		time.Sleep(500 * time.Millisecond)
	} // end for !s.isStoping
}

func (s *netService) GetAckTime(addr string) time.Time {
	return s.getAckInfo(addr).ackTm
}

func (s *netService) ResetAckTime(addr string) {
	now := time.Now()

	s.muIdMap.Lock()
	if addr != "" {
		a, ok := s.ackMap[addr]
		if ok {
			a.ackTm = now
		}
	} else {
		for _, a := range s.ackMap {
			a.ackTm = now
		}
	}
	s.muIdMap.Unlock()
}

func isHighPriorityNetworkMsg(msg *networkMsg) bool {
	if msg == nil {
		return false
	}
	switch msg.NetworkClass() {
	case network.NetClassHotstuffControl,
		network.NetClassProposalBodyControl,
		network.NetClassCommitteeControl,
		network.NetClassCandidateMiner,
		network.NetClassHeartbeat:
		return true
	default:
		return false
	}
}

func retryableConsensusNetworkMsg(msg *networkMsg) bool {
	if isHighPriorityNetworkMsg(msg) {
		return true
	}
	return msg != nil && msg.NetworkClass() == network.NetClassProposalBodyBulk
}

func retryableConsensusSendError(msg *networkMsg, err error) bool {
	return err != nil && !network.IsPermanentSendError(err) && retryableConsensusNetworkMsg(msg)
}

func cloneNetworkMsg(msg *networkMsg) *networkMsg {
	if msg == nil {
		return nil
	}
	cpy := *msg
	cpy.Hmsg = cloneHotstuffMessage(msg.Hmsg)
	if msg.Pmsg != nil {
		cpy.Pmsg = cloneProposalBodyMsg(msg.Pmsg)
	}
	return &cpy
}

// cloneNetworkMsgForQueue gives the queue ownership of its mutable retry
// metadata while sharing already-sealed payloads. Consensus and proposal-body
// messages are immutable after authentication, so duplicating a 256 MiB body
// once per destination would only amplify memory without adding isolation.
func cloneNetworkMsgForQueue(msg *networkMsg) *networkMsg {
	if msg == nil {
		return nil
	}
	cpy := *msg
	cpy.Hmsg = cloneHotstuffMessage(msg.Hmsg)
	return &cpy
}

func cloneHotstuffMessage(msg *hotstuff.HotstuffMessage) *hotstuff.HotstuffMessage {
	if msg == nil {
		return nil
	}
	cpy := *msg
	cpy.PubKey = append([]byte(nil), msg.PubKey...)
	cpy.DataA = append([]byte(nil), msg.DataA...)
	cpy.DataB = append([]byte(nil), msg.DataB...)
	cpy.DataC = append([]byte(nil), msg.DataC...)
	cpy.DataD = append([]byte(nil), msg.DataD...)
	cpy.DataE = append([]byte(nil), msg.DataE...)
	cpy.DataF = append([]byte(nil), msg.DataF...)
	cpy.DataG = append([]byte(nil), msg.DataG...)
	cpy.AuthSig = append([]byte(nil), msg.AuthSig...)
	cpy.ReceivedAt = time.Time{}
	return &cpy
}

// validateNetworkMsgShape enforces networkMsg as an explicit one-of. Without
// this check an attacker can select a cheap control class with Hmsg while
// smuggling a large proposal body in another field that accounting ignores.
func validateNetworkMsgShape(msg *networkMsg) error {
	if msg == nil {
		return fmt.Errorf("nil network message")
	}
	payloads := 0
	for _, present := range []bool{msg.Hmsg != nil, msg.Cmsg != nil, msg.Bmsg != nil, msg.Pmsg != nil} {
		if present {
			payloads++
		}
	}
	if payloads != 1 {
		return fmt.Errorf("network message must contain exactly one payload, got %d", payloads)
	}
	if (msg.Hmsg != nil || msg.Pmsg != nil) && msg.MsgFlag&Gossip_MSG != 0 {
		return fmt.Errorf("authenticated consensus messages cannot use gossip delivery")
	}
	return nil
}

// --------------------------------------------------------------------------------------------------------------------------
func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewLegacyKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}

func IsSelf(addr string) bool {
	return addr == bftview.GetServerAddress()
}
