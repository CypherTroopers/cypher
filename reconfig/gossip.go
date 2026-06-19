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
	input         chan *networkMsg
	priorityInput chan *networkMsg
	next          chan *networkMsg
	stop          chan struct{}
	once          sync.Once
}

func newPeerQueues() *peerQueues {
	q := &peerQueues{
		input:         make(chan *networkMsg, 8192),
		priorityInput: make(chan *networkMsg, 8192),
		next:          make(chan *networkMsg),
		stop:          make(chan struct{}),
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

		var out chan *networkMsg
		var next *networkMsg
		for i := range classes {
			if len(classes[i]) > 0 {
				out = q.next
				next = classes[i][0]
				break
			}
		}

		select {
		case msg := <-q.priorityInput:
			class := peerQueueClass(msg)
			classes[class] = append(classes[class], msg)
		case msg := <-q.input:
			class := peerQueueClass(msg)
			classes[class] = append(classes[class], msg)
		case out <- next:
			class := peerQueueClass(next)
			classes[class][0] = nil
			classes[class] = classes[class][1:]
		case <-q.stop:
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
	if q == nil || msg == nil {
		return false
	}
	input := q.input
	if isHighPriorityNetworkMsg(msg) {
		input = q.priorityInput
	}
	select {
	case input <- cloneNetworkMsg(msg):
		return true
	case <-q.stop:
		return false
	}
}

func (q *peerQueues) pushFrontClass(msg *networkMsg) {
	// Requeue at the tail of the same priority class to preserve FIFO and avoid
	// retrying a failed send in a tight loop.
	q.push(msg)
}

func (q *peerQueues) popNext() interface{} {
	if q == nil {
		return nil
	}
	select {
	case msg := <-q.next:
		return msg
	case <-q.stop:
		return nil
	default:
		return nil
	}
}

func (q *peerQueues) close() {
	if q != nil {
		q.once.Do(func() { close(q.stop) })
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

	backend       serviceCallback
	curBlockN     uint64
	curKeyBlockN  uint64
	isStoping     bool
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
	s.backend = callback
	s.candidatepool = backend.CandidatePool()
	s.bc = backend.BlockChain()
	s.kbc = backend.KeyBlockChain()

	return s
}

func (s *netService) StartStop(isStart bool) {
	if isStart {
		s.server.Start()
		go s.heartBeat_Loop()
	} else { // stop
		s.isStoping = true
		//..............................
	}
}

func (s *netService) serverIdentityFor(address string) *network.ServerIdentity {
	transport := network.PlainKCP
	if s != nil && s.server != nil && s.server.Address().ConnType() != network.InvalidConnType {
		transport = s.server.Address().ConnType()
	}
	return network.NewServerIdentityWithTransport(address, transport)
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
	if msg.Cmsg == nil && msg.Bmsg == nil && msg.Hmsg == nil && msg.Pmsg == nil {
		log.Error("handleNetworkMsgReq nil message")
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
		case hotstuff.MsgNewView, hotstuff.MsgPrepare, hotstuff.MsgVotePrepare, hotstuff.MsgDecide:
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
		return fmt.Errorf("nil network message")
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

func (s *netService) loop_iddata(address string, queues *peerQueues) {
	log.Debug("loop_iddata start", "address", address)
	si := s.serverIdentityFor(address)

	s.muIdMap.Lock()
	isRunning, _ := s.goMap[address]
	s.muIdMap.Unlock()

	for !s.isStoping && atomic.LoadInt32(isRunning) == 1 {
		msg := queues.popNext()
		if msg == nil {
			time.Sleep(2 * time.Millisecond)
			continue
		}

		m, ok := msg.(*networkMsg)
		if ok && s.IgnoreMsg(m) {
			continue
		}
		if s.GetNetBlocks(si) > 1 && (!ok || !isHighPriorityNetworkMsg(m)) {
			if ok && queues != nil && !s.IgnoreMsg(m) {
				queues.pushFrontClass(m)
			}
			time.Sleep(2 * time.Millisecond)
			continue
		}
		if err := s.SendRaw(si, msg, false); err != nil {
			log.Warn("SendRawData", "couldn't send to", address, "error", err)
			if ok && isHighPriorityNetworkMsg(m) && queues != nil && !s.IgnoreMsg(m) {
				// HotStuff and proposal-body control messages are consensus-critical.
				// Do not drop them on a transient QUIC/TCP send failure.
				queues.pushFrontClass(m)
				time.Sleep(5 * time.Millisecond)
			}
		}
	}

	atomic.StoreInt32(isRunning, 0)
	queues.close()

	s.muIdMap.Lock()
	delete(s.goMap, address)
	delete(s.idQueues, address)
	delete(s.ackMap, address)
	s.muIdMap.Unlock()

	log.Debug("loop_iddata exit", "id", address)
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
	s.muIdMap.Lock()
	isRunning, ok := s.goMap[id]
	if !ok {
		if isStart == false {
			s.muIdMap.Unlock()
			return
		}
		isRunning = new(int32)
		s.goMap[id] = isRunning
	}
	s.muIdMap.Unlock()
	i := atomic.LoadInt32(isRunning)
	if isStart {
		atomic.StoreInt32(isRunning, 1)
		if i == 0 {
			s.muIdMap.Lock()
			queues, ok := s.idQueues[id]
			if !ok {
				queues = newPeerQueues()
				s.idQueues[id] = queues
			}
			s.muIdMap.Unlock()
			go s.loop_iddata(id, queues)
		}
	} else {
		if i == 1 {
			atomic.StoreInt32(isRunning, 2)
		}
	}
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

func (s *netService) heartBeat_Loop() {
	heatBeatTimeout := params.HeatBeatTimeout
	for !s.isStoping {
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

func cloneNetworkMsg(msg *networkMsg) *networkMsg {
	if msg == nil {
		return nil
	}
	cpy := *msg
	if msg.Pmsg != nil {
		body := *msg.Pmsg
		if len(msg.Pmsg.EncodedBlock) > 0 {
			body.EncodedBlock = make([]byte, len(msg.Pmsg.EncodedBlock))
			copy(body.EncodedBlock, msg.Pmsg.EncodedBlock)
		}
		cpy.Pmsg = &body
	}
	return &cpy
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
