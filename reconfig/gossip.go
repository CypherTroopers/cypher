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
	"errors"
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
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/rnet"
	"github.com/cypherium/cypher/rnet/network"
	"golang.org/x/crypto/sha3"
)

type serviceCallback interface {
	networkMsgAck(si *network.ServerIdentity, msg *networkMsg)
}

const Gossip_MSG = 8

const defaultSendResultTimeout = 5 * time.Second

var (
	errNetServiceStopped     = errors.New("reconfig network service is stopped")
	errSendQueueNotAvailable = errors.New("reconfig send queue is not available")
	errSendResultTimeout     = errors.New("reconfig send result timed out")
	errSendMessageIgnored    = errors.New("reconfig send message is stale")
)

type heartBeatMsg struct {
	BlockN uint64
}
type checkMinerMsg struct {
	BlockN    uint64
	KeyblockN uint64
	AckFlag   uint64
}

type ackInfo struct {
	mu        sync.RWMutex
	ackTm     time.Time
	sendTm    time.Time
	isSending *int32 //atomic int
}

func (a *ackInfo) ackTime() time.Time {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.ackTm
}

func (a *ackInfo) setAckTime(now time.Time) {
	a.mu.Lock()
	a.ackTm = now
	a.mu.Unlock()
}

func (a *ackInfo) sendTime() time.Time {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.sendTm
}

func (a *ackInfo) setSendTime(now time.Time) {
	a.mu.Lock()
	a.sendTm = now
	a.mu.Unlock()
}

type sendRequest struct {
	msg      *networkMsg
	resultCh chan error
	cancelCh chan struct{}
}

func newSendRequest(msg *networkMsg) *sendRequest {
	return &sendRequest{
		msg:      msg,
		resultCh: make(chan error, 1),
		cancelCh: make(chan struct{}),
	}
}

func (r *sendRequest) complete(err error) {
	select {
	case r.resultCh <- err:
	default:
	}
}

func (r *sendRequest) canceled() bool {
	return channelClosed(r.cancelCh)
}

type msgHeadInfo struct {
	blockN    uint64
	keyblockN uint64
}

type netService struct {
	*rnet.ServiceProcessor // We need to embed the ServiceProcessor, so that incoming messages are correctly handled.
	server                 *rnet.Server
	serverAddress          string
	serverID               string
	gossipMsg              map[common.Hash]*msgHeadInfo
	muGossip               sync.Mutex

	goMap     map[string]*int32 //atomic int
	idDataMap map[string]*common.Queue
	ackMap    map[string]*ackInfo
	muIdMap   sync.Mutex
	lifecycle sync.RWMutex

	backend       serviceCallback
	curBlockN     uint64
	curKeyBlockN  uint64
	isStoping     int32
	running       bool
	serverStarted bool
	stopCh        chan struct{}
	sendTimeout   time.Duration
	sendRawFn     func(*network.ServerIdentity, interface{}, bool) error
	netBlocksFn   func(*network.ServerIdentity) int
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
	server := rnet.NewKcpServer(sIp)
	s := server.Service(sName).(*netService)
	s.server = server
	s.serverID = sIp
	s.serverAddress = sIp

	s.gossipMsg = make(map[common.Hash]*msgHeadInfo)
	s.goMap = make(map[string]*int32)
	s.idDataMap = make(map[string]*common.Queue)
	s.ackMap = make(map[string]*ackInfo)
	s.backend = callback
	s.candidatepool = backend.CandidatePool()
	s.bc = backend.BlockChain()
	s.kbc = backend.KeyBlockChain()
	atomic.StoreInt32(&s.isStoping, 1)

	return s
}

func (s *netService) StartStop(isStart bool) {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()

	if isStart {
		if s.running {
			return
		}
		// Mining stop does not stop the network listener. Start it only once,
		// including when another owner has already made it listen.
		if !s.serverStarted {
			if !s.server.Listening() {
				s.server.Start()
			}
			s.serverStarted = true
		}
		s.stopCh = make(chan struct{})
		s.running = true
		atomic.StoreInt32(&s.isStoping, 0)
		go s.heartBeat_Loop(s.stopCh)
		return
	}

	atomic.StoreInt32(&s.isStoping, 1)
	if !s.running {
		return
	}
	s.running = false
	if s.stopCh != nil {
		close(s.stopCh)
	}
	s.stopCh = nil

	// Mark all workers from this run as stopping. A later SendRawData call
	// creates a fresh worker and queue instead of reviving the old goroutine.
	s.muIdMap.Lock()
	for _, isRunning := range s.goMap {
		if isRunning != nil {
			atomic.StoreInt32(isRunning, 2)
		}
	}
	s.muIdMap.Unlock()
}

// ----------------------------------------------------------------------------------------------------
func (s *netService) CheckMinerPort(addr string, blockN uint64, keyblockN uint64, ackFlag uint64) {
	msg := &checkMinerMsg{BlockN: blockN, KeyblockN: keyblockN, AckFlag: ackFlag}
	log.Info("CheckMinerPort", "addr", addr, "msg", msg)
	si := network.NewServerIdentity(addr)
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

	//clear old cache of gossipMsg
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
	if msg.Cmsg == nil && msg.Bmsg == nil && msg.Hmsg == nil {
		log.Error("handleNetworkMsgReq nil message")
		return
	}
	si := env.ServerIdentity
	address := si.Address.String()
	//	log.Info("handleNetworkMsgReq Recv", "from address", address)
	s.getAckInfo(address).setAckTime(time.Now())

	if s.IgnoreMsg(msg) {
		return
	}

	if (msg.MsgFlag & Gossip_MSG) > 0 {
		hash := rlpHash(msg)
		s.muGossip.Lock()
		m, ok := s.gossipMsg[hash]
		s.muGossip.Unlock()
		if !ok {
			// Forwarding is best-effort for an already received message. Do not
			// delay local HotStuff handling while peer sends wait for their result.
			go func() {
				for _, err := range s.broadcast(address, msg) {
					if err != nil {
						log.Warn("Gossip_MSG broadcast failed", "error", err)
					}
				}
			}()
		} else {
			log.Info("Gossip_MSG Recv Same", "hash", hash, "keyblockN", m.keyblockN, "blockN", m.blockN)
			return
		}
	}
	s.backend.networkMsgAck(si, msg)
}

func (s *netService) broadcast(fromAddr string, msg *networkMsg) []error {
	mb := msg.GetCommittee()
	if mb == nil {
		err := errors.New("can't find current committee")
		log.Error("broadcast", "error", err)
		return []error{err}
	}
	if fromAddr != "" {
		p, _ := mb.Get(fromAddr, bftview.Address)
		if p == nil {
			err := fmt.Errorf("can't find current committee address %s", fromAddr)
			log.Error("broadcast", "error", err)
			return []error{err}
		}
	}
	msg.MsgFlag = Gossip_MSG
	hash := rlpHash(msg)
	hInfo := s.getMsgHeadInfo(msg)
	log.Info("Gossip_MSG broadcast", "hash", hash, "keyblockN", hInfo.keyblockN, "blockN", hInfo.blockN)

	s.muGossip.Lock()
	s.gossipMsg[hash] = hInfo
	s.muGossip.Unlock()

	mblist := mb.List
	n := len(mblist)
	seedIndexs := math.GetRandIntArray(n, n/2+3)
	addresses := make([]string, 0, len(seedIndexs))
	for index := range seedIndexs {
		if mblist[index].Address == "" {
			continue
		}
		if IsSelf(mblist[index].Address) {
			continue
		}
		addresses = append(addresses, mblist[index].Address)
	}
	return s.sendRawDataParallel(addresses, msg)
}

func (s *netService) sendRawDataParallel(addresses []string, msg *networkMsg) []error {
	if len(addresses) == 0 {
		return nil
	}
	results := make([]error, len(addresses))
	var wg sync.WaitGroup
	wg.Add(len(addresses))
	for i, address := range addresses {
		go func(i int, address string) {
			defer wg.Done()
			err := s.SendRawData(address, msg)
			if err != nil {
				err = fmt.Errorf("send gossip to %s: %w", address, err)
			}
			results[i] = err
		}(i, address)
	}
	wg.Wait()
	return results
}

func (s *netService) sendResultTimeout() time.Duration {
	if s.sendTimeout > 0 {
		return s.sendTimeout
	}
	return defaultSendResultTimeout
}

func (s *netService) sendRaw(si *network.ServerIdentity, msg interface{}, beforeConnect bool) error {
	if s.sendRawFn != nil {
		return s.sendRawFn(si, msg, beforeConnect)
	}
	return s.SendRaw(si, msg, beforeConnect)
}

func (s *netService) netBlocks(si *network.ServerIdentity) int {
	if s.netBlocksFn != nil {
		return s.netBlocksFn(si)
	}
	return s.GetNetBlocks(si)
}

func (s *netService) SendRawData(address string, msg *networkMsg) error {
	// Keep the lifecycle lock only while validating and enqueueing. Waiting for
	// the worker while holding it would prevent Stop from closing this run.
	s.lifecycle.RLock()
	if !s.running || atomic.LoadInt32(&s.isStoping) != 0 {
		s.lifecycle.RUnlock()
		return errNetServiceStopped
	}
	if address == s.serverAddress {
		s.lifecycle.RUnlock()
		return nil
	}
	if s.stopCh == nil {
		s.lifecycle.RUnlock()
		return errSendQueueNotAvailable
	}
	stopCh := s.stopCh
	request := newSendRequest(msg)
	if err := s.enqueueSend(address, request, stopCh); err != nil {
		s.lifecycle.RUnlock()
		return err
	}
	timeout := s.sendResultTimeout()
	s.lifecycle.RUnlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	defer close(request.cancelCh)
	select {
	case err := <-request.resultCh:
		return err
	case <-stopCh:
		// Prefer a result that completed concurrently with Stop.
		select {
		case err := <-request.resultCh:
			return err
		default:
			return errNetServiceStopped
		}
	case <-timer.C:
		return errSendResultTimeout
	}
}

// enqueueSend is called with lifecycle held, so a stop cannot race with
// establishing the worker and accepting its message.
func (s *netService) enqueueSend(address string, request *sendRequest, stopCh <-chan struct{}) error {
	if stopCh == nil || channelClosed(stopCh) {
		return errNetServiceStopped
	}
	s.muIdMap.Lock()
	if s.goMap == nil {
		s.goMap = make(map[string]*int32)
	}
	if s.idDataMap == nil {
		s.idDataMap = make(map[string]*common.Queue)
	}
	isRunning := s.goMap[address]
	q := s.idDataMap[address]
	startWorker := isRunning == nil || atomic.LoadInt32(isRunning) != 1
	if startWorker {
		isRunning = new(int32)
		atomic.StoreInt32(isRunning, 1)
		q = common.QueueNew()
		if q == nil {
			s.muIdMap.Unlock()
			return errSendQueueNotAvailable
		}
		s.goMap[address] = isRunning
		s.idDataMap[address] = q
	} else if q == nil {
		s.muIdMap.Unlock()
		return errSendQueueNotAvailable
	}
	q.PushBack(request)
	s.muIdMap.Unlock()

	if startWorker {
		go s.loop_iddata(address, q, isRunning, stopCh)
	}
	return nil
}

func (s *netService) loop_iddata(address string, q *common.Queue, isRunning *int32, stopCh <-chan struct{}) {
	log.Debug("loop_iddata start", "address", address)
	si := network.NewServerIdentity(address)

	for atomic.LoadInt32(isRunning) == 1 && !channelClosed(stopCh) {
		if s.netBlocks(si) > 1 {
			if waitForStop(stopCh, 5*time.Millisecond) {
				break
			}
			continue
		}
		s.muIdMap.Lock()
		currentWorker := s.goMap[address]
		currentQueue := s.idDataMap[address]
		if currentWorker != isRunning || currentQueue != q {
			s.muIdMap.Unlock()
			break
		}
		rawRequest := q.PopFront()
		s.muIdMap.Unlock()
		if rawRequest == nil {
			if waitForStop(stopCh, 5*time.Millisecond) {
				break
			}
			continue
		}
		request, ok := rawRequest.(*sendRequest)
		if !ok || request == nil {
			continue
		}
		if request.canceled() {
			request.complete(errSendResultTimeout)
			continue
		}
		if s.IgnoreMsg(request.msg) {
			request.complete(errSendMessageIgnored)
			continue
		}
		// Stop can happen after the request was popped. Recheck the worker
		// generation immediately before invoking the network send API.
		s.lifecycle.RLock()
		if atomic.LoadInt32(&s.isStoping) != 0 || atomic.LoadInt32(isRunning) != 1 || channelClosed(stopCh) {
			s.lifecycle.RUnlock()
			request.complete(errNetServiceStopped)
			break
		}
		if request.canceled() {
			s.lifecycle.RUnlock()
			request.complete(errSendResultTimeout)
			continue
		}
		err := s.sendRaw(si, request.msg, false)
		request.complete(err)
		s.lifecycle.RUnlock()
		if err != nil {
			log.Warn("SendRawData", "couldn't send to", address, "error", err)
		}
		if waitForStop(stopCh, 5*time.Millisecond) {
			break
		}
	}
	atomic.StoreInt32(isRunning, 0)

	s.muIdMap.Lock()
	// Complete queued requests from this worker generation. On miner Stop the
	// callers also observe stopCh; this completion additionally covers a peer
	// worker stopped by AdjustConnect.
	drainErr := errSendQueueNotAvailable
	if channelClosed(stopCh) {
		drainErr = errNetServiceStopped
	}
	for {
		rawRequest := q.PopFront()
		if rawRequest == nil {
			break
		}
		if request, ok := rawRequest.(*sendRequest); ok && request != nil {
			request.complete(drainErr)
		}
	}
	// A stop/start can install a new worker before this old goroutine exits.
	// Only clean up entries that still belong to this exact worker generation.
	if s.goMap[address] == isRunning && s.idDataMap[address] == q {
		delete(s.goMap, address)
		delete(s.idDataMap, address)
		delete(s.ackMap, address)
	}
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
	if isStart {
		// SendRawData is the only path that starts a worker because it can
		// atomically enqueue the first message and report any failure.
		return
	}
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	s.muIdMap.Lock()
	isRunning, ok := s.goMap[id]
	if ok && isRunning != nil && atomic.LoadInt32(isRunning) == 1 {
		atomic.StoreInt32(isRunning, 2)
	}
	s.muIdMap.Unlock()
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
	//log.Info("handleHeartBeatMsgAck Recv", "from address", address, "blockN", msg.blockN)
	s.getAckInfo(address).setAckTime(time.Now())
}

func (s *netService) getAckInfo(addr string) *ackInfo {
	s.muIdMap.Lock()
	if s.ackMap == nil {
		s.ackMap = make(map[string]*ackInfo)
	}
	a := s.ackMap[addr]
	if a == nil {
		a = new(ackInfo)
		a.isSending = new(int32)
		a.setAckTime(time.Now())
		s.ackMap[addr] = a
	}
	s.muIdMap.Unlock()
	return a
}

func (s *netService) heartBeat_Loop(stopCh <-chan struct{}) {
	heatBeatTimeout := params.HeatBeatTimeout
	for !channelClosed(stopCh) {
		mb := bftview.GetCurrentMember()
		if mb == nil {
			if waitForStop(stopCh, 200*time.Millisecond) {
				return
			}
			continue
		}
		now := time.Now()
		msg := &heartBeatMsg{BlockN: atomic.LoadUint64(&s.curBlockN)}
		for _, node := range mb.List {
			if channelClosed(stopCh) {
				return
			}
			if IsSelf(node.Address) {
				continue
			}
			addr := node.Address
			a := s.getAckInfo(addr)
			if a != nil && now.Sub(a.sendTime()) > heatBeatTimeout {
				if atomic.CompareAndSwapInt32(a.isSending, 0, 1) {
					si := network.NewServerIdentity(addr)
					if s.netBlocks(si) == 0 {
						a.setSendTime(time.Now())
						go func(si *network.ServerIdentity, msg interface{}, isSending *int32, stopCh <-chan struct{}) {
							defer atomic.StoreInt32(isSending, 0)
							s.lifecycle.RLock()
							defer s.lifecycle.RUnlock()
							if atomic.LoadInt32(&s.isStoping) != 0 || channelClosed(stopCh) {
								return
							}
							s.sendRaw(si, msg, false)
							//log.Debug("sendHeartBeatMsg", "address", si.Address, "tm", time.Now(), "error", err)
						}(si, msg, a.isSending, stopCh)
					} else {
						atomic.StoreInt32(a.isSending, 0)
					}
				}
				continue
			}
		}
		if waitForStop(stopCh, 500*time.Millisecond) {
			return
		}
	}
}

func channelClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func waitForStop(stopCh <-chan struct{}, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-stopCh:
		return true
	case <-timer.C:
		return false
	}
}

func (s *netService) GetAckTime(addr string) time.Time {
	return s.getAckInfo(addr).ackTime()
}

func (s *netService) ResetAckTime(addr string) {
	now := time.Now()

	s.muIdMap.Lock()
	if addr != "" {
		a, ok := s.ackMap[addr]
		if ok {
			a.setAckTime(now)
		}
	} else {
		for _, a := range s.ackMap {
			a.setAckTime(now)
		}
	}
	s.muIdMap.Unlock()
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
