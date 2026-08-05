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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/rnet/network"
)

func newRunningTestNetService(timeout time.Duration) *netService {
	s := &netService{
		serverStarted: true,
		serverAddress: "127.0.0.1:1",
		goMap:         make(map[string]*int32),
		idDataMap:     make(map[string]*common.Queue),
		ackMap:        make(map[string]*ackInfo),
		running:       true,
		stopCh:        make(chan struct{}),
		sendTimeout:   timeout,
		netBlocksFn: func(*network.ServerIdentity) int {
			return 0
		},
	}
	atomic.StoreInt32(&s.isStoping, 0)
	return s
}

func TestNetServiceStartStopRestart(t *testing.T) {
	s := &netService{
		// A miner restart reuses the listener started by the node. Leaving
		// server nil makes this test fail if StartStop attempts to start it
		// again while serverStarted is true.
		serverStarted: true,
		goMap:         make(map[string]*int32),
		idDataMap:     make(map[string]*common.Queue),
		ackMap:        make(map[string]*ackInfo),
	}
	atomic.StoreInt32(&s.isStoping, 1)
	defer s.StartStop(false)

	s.StartStop(true)
	firstRun := s.stopCh
	if firstRun == nil || channelClosed(firstRun) {
		t.Fatal("first run did not create a live stop channel")
	}

	s.StartStop(false)
	if !channelClosed(firstRun) {
		t.Fatal("stop did not signal the first run")
	}
	if atomic.LoadInt32(&s.isStoping) != 1 {
		t.Fatal("stop state was not published")
	}

	s.StartStop(true)
	secondRun := s.stopCh
	if secondRun == nil || secondRun == firstRun || channelClosed(secondRun) {
		t.Fatal("restart did not create a fresh live run")
	}

	// A duplicate start must not create another heartbeat generation or call
	// Server.Start again on the listener that is already active.
	s.StartStop(true)
	if s.stopCh != secondRun {
		t.Fatal("duplicate start replaced the active run")
	}
}

func TestSendRawDataReportsUnavailableLifecycle(t *testing.T) {
	s := &netService{serverAddress: "127.0.0.1:1"}
	atomic.StoreInt32(&s.isStoping, 1)
	if err := s.SendRawData(s.serverAddress, &networkMsg{}); err != errNetServiceStopped {
		t.Fatalf("stopped send error = %v, want %v", err, errNetServiceStopped)
	}

	s.running = true
	atomic.StoreInt32(&s.isStoping, 0)
	if err := s.SendRawData("127.0.0.1:2", &networkMsg{}); err != errSendQueueNotAvailable {
		t.Fatalf("send without an active run queue error = %v, want %v", err, errSendQueueNotAvailable)
	}
}

func TestOldSendWorkerDoesNotDeleteRestartedWorker(t *testing.T) {
	const address = "127.0.0.1:2"
	oldState := new(int32)
	newState := new(int32)
	atomic.StoreInt32(oldState, 1)
	atomic.StoreInt32(newState, 1)
	oldQueue := common.QueueNew()
	newQueue := common.QueueNew()
	stopOldRun := make(chan struct{})
	close(stopOldRun)

	s := &netService{
		goMap: map[string]*int32{
			address: newState,
		},
		idDataMap: map[string]*common.Queue{
			address: newQueue,
		},
		ackMap: make(map[string]*ackInfo),
	}
	go s.loop_iddata(address, oldQueue, oldState, stopOldRun)

	deadline := time.After(time.Second)
	for atomic.LoadInt32(oldState) != 0 {
		select {
		case <-deadline:
			t.Fatal("old worker did not exit")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	s.muIdMap.Lock()
	gotState := s.goMap[address]
	gotQueue := s.idDataMap[address]
	s.muIdMap.Unlock()
	if gotState != newState || gotQueue != newQueue {
		t.Fatal("old worker removed the restarted worker state")
	}
}

func TestSendRawDataReturnsWorkerSendError(t *testing.T) {
	want := errors.New("send failed")
	s := newRunningTestNetService(time.Second)
	s.sendRawFn = func(*network.ServerIdentity, interface{}, bool) error {
		return want
	}
	defer s.StartStop(false)

	if err := s.SendRawData("127.0.0.1:2", &networkMsg{}); err != want {
		t.Fatalf("SendRawData error = %v, want worker error %v", err, want)
	}
}

func TestSendRawDataResultTimeout(t *testing.T) {
	const timeout = 50 * time.Millisecond
	started := make(chan struct{})
	release := make(chan struct{})
	s := newRunningTestNetService(timeout)
	s.sendRawFn = func(*network.ServerIdentity, interface{}, bool) error {
		close(started)
		<-release
		return nil
	}
	defer s.StartStop(false)

	begin := time.Now()
	err := s.SendRawData("127.0.0.1:2", &networkMsg{})
	elapsed := time.Since(begin)
	close(release)
	if err != errSendResultTimeout {
		t.Fatalf("SendRawData error = %v, want %v", err, errSendResultTimeout)
	}
	select {
	case <-started:
	default:
		t.Fatal("worker did not invoke the send API")
	}
	if elapsed < timeout || elapsed > 10*timeout {
		t.Fatalf("SendRawData timeout elapsed = %v, want approximately %v", elapsed, timeout)
	}
}

func TestSendRawDataParallelStartsAllPeersTogether(t *testing.T) {
	addresses := []string{"127.0.0.1:2", "127.0.0.1:3", "127.0.0.1:4"}
	started := make(chan struct{}, len(addresses))
	release := make(chan struct{})
	s := newRunningTestNetService(time.Second)
	s.sendRawFn = func(*network.ServerIdentity, interface{}, bool) error {
		started <- struct{}{}
		<-release
		return nil
	}
	defer s.StartStop(false)

	resultCh := make(chan []error, 1)
	go func() {
		resultCh <- s.sendRawDataParallel(addresses, &networkMsg{})
	}()
	deadline := time.After(500 * time.Millisecond)
	for range addresses {
		select {
		case <-started:
		case <-deadline:
			close(release)
			t.Fatal("parallel broadcast did not start every peer before one send completed")
		}
	}
	close(release)
	results := <-resultCh
	if len(results) != len(addresses) {
		t.Fatalf("parallel results length = %d, want %d", len(results), len(addresses))
	}
	for i, err := range results {
		if err != nil {
			t.Fatalf("parallel result[%d] = %v, want nil", i, err)
		}
	}
}

func TestStopAfterWorkerWakePreventsSend(t *testing.T) {
	const address = "127.0.0.1:2"
	checkedBlocks := make(chan struct{})
	releaseBlocks := make(chan struct{})
	var checkOnce sync.Once
	var sendCalls int32
	s := newRunningTestNetService(time.Second)
	s.netBlocksFn = func(*network.ServerIdentity) int {
		checkOnce.Do(func() { close(checkedBlocks) })
		<-releaseBlocks
		return 0
	}
	s.sendRawFn = func(*network.ServerIdentity, interface{}, bool) error {
		atomic.AddInt32(&sendCalls, 1)
		return nil
	}

	resultCh := make(chan error, 1)
	go func() {
		resultCh <- s.SendRawData(address, &networkMsg{})
	}()
	select {
	case <-checkedBlocks:
	case <-time.After(time.Second):
		t.Fatal("worker did not reach the pre-send network check")
	}
	s.muIdMap.Lock()
	workerState := s.goMap[address]
	s.muIdMap.Unlock()
	if workerState == nil {
		t.Fatal("worker state was not installed")
	}

	s.StartStop(false)
	close(releaseBlocks)
	select {
	case err := <-resultCh:
		if err != errNetServiceStopped {
			t.Fatalf("send racing with stop error = %v, want %v", err, errNetServiceStopped)
		}
	case <-time.After(time.Second):
		t.Fatal("send did not return after stop")
	}

	deadline := time.After(time.Second)
	for atomic.LoadInt32(workerState) != 0 {
		select {
		case <-deadline:
			t.Fatal("stopped worker did not exit")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if got := atomic.LoadInt32(&sendCalls); got != 0 {
		t.Fatalf("send API called %d times after stop, want 0", got)
	}
}

func TestAckInfoTimesAreConcurrentSafe(t *testing.T) {
	const address = "127.0.0.1:2"
	s := &netService{ackMap: make(map[string]*ackInfo)}
	a := s.getAckInfo(address)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				now := time.Now()
				switch i % 4 {
				case 0:
					a.setAckTime(now)
				case 1:
					_ = s.GetAckTime(address)
				case 2:
					a.setSendTime(now)
					_ = a.sendTime()
				case 3:
					s.ResetAckTime(address)
				}
			}
		}(i)
	}
	wg.Wait()
	if a.ackTime().IsZero() {
		t.Fatal("ack time was not recorded")
	}
}
