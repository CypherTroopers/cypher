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
	"sync"
	"time"

	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
)

var maxPaceMakerTime time.Time
var paceMakerPollInterval = 1 * time.Millisecond

type paceMakerTimer struct {
	startTime        time.Time
	lastKeyTime      time.Time
	beStop           bool
	beClose          bool
	service          serviceI
	txPool           *core.TxPool
	candidatepool    *core.CandidatePool
	retryNumber      int
	ackMissCount     int
	lastAckMissAt    time.Time
	lastKeyTriggerAt time.Time
	config           *params.ChainConfig
	kbc              *core.KeyBlockChain
	mu               sync.Mutex

	txsCh  chan core.NewTxsEvent
	txsSub event.Subscription
}

func newPaceMakerTimer(config *params.ChainConfig, s serviceI, backend *ReconfigBackend) *paceMakerTimer {
	maxPaceMakerTime = time.Now().AddDate(200, 0, 0) //200 years
	t := &paceMakerTimer{
		service:       s,
		txPool:        backend.TxPool(),
		candidatepool: backend.CandidatePool(),
		startTime:     maxPaceMakerTime,
		lastKeyTime:   time.Now(),
		beStop:        true,
		beClose:       false,
		config:        config,
	}

	t.txsCh = make(chan core.NewTxsEvent, 8192)
	t.txsSub = backend.TxPool().SubscribeNewTxsEvent(t.txsCh)
	go t.txsEventLoop()

	go t.loopTimer()
	return t
}

// Start for time counting of pacemake
func (t *paceMakerTimer) start() error {
	if t.service != nil && t.service.hasDeferredFHSRecovery() {
		return errFHSRecoveryPending
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.beStop { //first
		t.startTime = time.Now()
		/*
			if t.txPool.PendingCount() > 0 && t.service.SwitchOK() {
				t.startTime = time.Now()
			} else {
				now := time.Now()
				diff := now.Sub(t.lastKeyTime)
				if diff > params.KeyBlockTimeout {
					t.startTime = time.Now()
					log.Debug("paceMakerTimer keyblock", "startTime", t.startTime)
				}
			}
		*/
	} else {
		t.startTime = time.Now()
	}
	//log.Info("paceMakerTimer.start", "startTime", t.startTime )

	t.beStop = false

	return nil
}

// Stop for time counting of pacemake
func (t *paceMakerTimer) stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.beStop = true
	t.retryNumber = 0
	t.ackMissCount = 0
	t.lastAckMissAt = time.Time{}
	t.startTime = maxPaceMakerTime
	return nil
}

// Close pacemake loop
func (t *paceMakerTimer) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.beClose = true
	if t.txsSub != nil {
		t.txsSub.Unsubscribe()
	}
}
func (t *paceMakerTimer) get() (time.Time, bool, bool, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.startTime, t.beStop, t.beClose, t.retryNumber
}

func (t *paceMakerTimer) recordAckMiss(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.lastAckMissAt.IsZero() || now.Sub(t.lastAckMissAt) >= params.AckTimeout {
		t.ackMissCount++
		t.lastAckMissAt = now
	}
	return t.ackMissCount
}

func (t *paceMakerTimer) resetAckMissCount() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ackMissCount = 0
	t.lastAckMissAt = time.Time{}
}

// Loop for status action
func (t *paceMakerTimer) loopTimer() {
	for {
		time.Sleep(paceMakerPollInterval)
		startTime, beStop, beClose, retryNumber := t.get()
		if beClose {
			return
		}

		if beStop || startTime == maxPaceMakerTime {
			continue
		}

		now := time.Now()
		fixedMode := t.config != nil && (t.config.FixedLeader || t.config.FixedCommittee) && !t.config.FairHotstuff
		leaderSilentFor := now.Sub(t.service.LeaderAckTime())
		progressSilentFor := now.Sub(t.service.HotstuffProgressTime())

		if fixedMode && bftview.IamMember() >= 0 {
			t.mu.Lock()
			lastKeyTime := t.lastKeyTime
			if now.Sub(lastKeyTime) >= params.KeyBlockMinInterval {
				// Fixed-mode keyblock view selection is owned by Service. Mutating
				// the leader here races with Service fallback selection and causes
				// the active leader to flap between primary and fallback.
				if t.lastKeyTriggerAt.IsZero() || now.Sub(t.lastKeyTriggerAt) >= 2*time.Second {
					t.lastKeyTriggerAt = now
					t.mu.Unlock()
					log.Warn("paceMakerTimer fixed mode keyblock trigger", "elapsed", now.Sub(lastKeyTime))
					continue
				}
				t.mu.Unlock()
				continue
			}
			t.mu.Unlock()

			// FixedLeader/FixedCommittee fallback must not be driven directly by this
			// local AckTimeout path. A local ack miss can differ per node and split
			// the committee into different LeaderIndex views. Keyblock fallback is
			// handled by the fixed-mode keyblock view logic in Service.
			if leaderSilentFor <= params.AckTimeout || progressSilentFor <= params.AckTimeout {
				t.resetAckMissCount()
			}
			continue
		}

		diff := now.Sub(startTime)
		if leaderSilentFor > params.AckTimeout && bftview.IamMember() >= 0 {
			if progressSilentFor <= params.AckTimeout {
				t.resetAckMissCount()
				continue
			}
			log.Warn("paceMakerTimer Viewchange AckTimeout", "ackSilentFor", leaderSilentFor, "progressSilentFor", progressSilentFor)
			t.setNextLeader(false)
			t.service.ResetLeaderAckTime()
			t.resetAckMissCount()
		} else if diff > params.PaceMakerTimeout /**time.Duration(retryNumber+1)*/ && bftview.IamMember() >= 0 { //timeout
			t.resetAckMissCount()
			log.Warn("paceMakerTimer Viewchange PaceMakerTimeout Event is coming", "retryNumber", retryNumber)
			/*
				switchLen := bftview.GetServerCommitteeLen()/2 + 1
				if t.retryNumber > switchLen && t.retryNumber%switchLen == 0 {
					log.Warn("Viewchange Event is coming", "double wait, retryNumber", retryNumber, "committee len", bftview.GetServerCommitteeLen())
					t.start()
					continue
				}
			*/
			t.setNextLeader(false)
			t.retryNumber++
		} else if leaderSilentFor <= params.AckTimeout || progressSilentFor <= params.AckTimeout {
			t.resetAckMissCount()
		}
	}
}

func (t *paceMakerTimer) triggerTryPropose() {
	curView := t.service.GetCurrentView()
	if !bftview.IamLeader(curView.LeaderIndex) {
		return
	}
	pending, _ := t.txPool.Stats()
	if pending == 0 {
		return
	}
	if svc, ok := t.service.(*Service); ok {
		svc.clearProposalNoWork()
		svc.triggerTryPropose(curView.TxNumber)
	}
}

func (t *paceMakerTimer) setNextLeader(isDone bool) {
	if !isDone && t.config != nil && t.config.FairHotstuff {
		if service, ok := t.service.(*Service); ok && service.protocolMng != nil {
			service.enqueueFHSTimeout()
			t.start()
			return
		}
	}
	curView := t.service.GetCurrentView()
	t.service.setNextLeader(isDone)
	t.service.sendNewViewMsg(curView.TxNumber)
	t.start()
}

var m_totalTxs int
var m_tps10StartTm time.Time

// Event for new block done
func (t *paceMakerTimer) procBlockDone(curBlock *types.Block, curKeyBlock *types.KeyBlock, isKeyBlock bool) {
	if isKeyBlock {
		t.mu.Lock()
		t.lastKeyTime = time.Now()
		t.lastKeyTriggerAt = time.Time{}
		lastKeyTime := t.lastKeyTime
		t.mu.Unlock()
		log.Debug("paceMakerTimer keyblock done", "lastKeyTime", lastKeyTime)
	}
	if curBlock != nil {
		if t.config.EnabledTPS {
			txs := len(curBlock.Transactions())
			m_totalTxs += txs
			if txs > 0 {
				now := time.Now()
				if m_tps10StartTm.Equal(time.Time{}) {
					m_tps10StartTm = now
				} else if now.Sub(m_tps10StartTm).Seconds() > 10 {
					tps := float64(m_totalTxs) / now.Sub(m_tps10StartTm).Seconds()
					log.Debug("@TPS10", "txs/s", tps)
					m_totalTxs = 0
					m_tps10StartTm = now
				}
				tps := float64(txs) / now.Sub(t.startTime).Seconds()
				log.Debug("@TPS", "txs/s", tps)
			}
		}

		// 360-TX keyblock trigger removed.
		// KeyBlock generation is controlled by time-based fixed-mode KeyBlockMinInterval.

		//if curBlock.NumberU64()%20 == 0 {
		//log.Info("Goroutine", "num", runtime.NumGoroutine())
		//runtime.GC() //force gc
		//}

	}

	t.stop()
	if bftview.IamMember() >= 0 {
		t.start()
	}

}

func (t *paceMakerTimer) txsEventLoop() {
	for {
		select {
		case <-t.txsCh:
			t.mu.Lock()
			beStop := t.beStop
			beClose := t.beClose
			if !beStop && !beClose {
				t.startTime = time.Now()
			}
			t.mu.Unlock()

			if beClose {
				return
			}
			if beStop || bftview.IamMember() < 0 {
				continue
			}

			t.triggerTryPropose()

		case <-t.txsSub.Err():
			log.Info("txsEventLoop stopped")
			return
		}
	}
}
