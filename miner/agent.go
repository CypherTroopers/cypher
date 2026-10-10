// Copyright 2015 The go-ethereum Authors
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

package miner

import (
	"sync"

	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
)

type CpuAgent struct {
	// Start and Stop serialize complete generations. The update and mining
	// goroutines never acquire mu, so Stop can join them while holding it.
	mu      sync.Mutex
	running *cpuAgentGeneration

	workCh   chan *Work
	returnMu sync.RWMutex
	returnCh chan<- *Result

	chain  types.ChainReader
	engine consensus.Engine
}

type cpuAgentGeneration struct {
	stop chan struct{}
	done chan struct{}
}

func NewCpuAgent(chain types.ChainReader, engine consensus.Engine) *CpuAgent {
	agent := &CpuAgent{
		chain:  chain,
		engine: engine,
		workCh: make(chan *Work, 1),
	}
	return agent
}

func (self *CpuAgent) Work() chan<- *Work { return self.workCh }

func (self *CpuAgent) SetReturnCh(ch chan<- *Result) {
	self.returnMu.Lock()
	defer self.returnMu.Unlock()
	self.returnCh = ch
}

func (self *CpuAgent) Start() {
	self.mu.Lock()
	defer self.mu.Unlock()
	if self.running != nil {
		return // agent already started
	}
	generation := &cpuAgentGeneration{stop: make(chan struct{}), done: make(chan struct{})}
	self.running = generation
	go self.update(generation)
}

func (self *CpuAgent) Stop() {
	self.mu.Lock()
	defer self.mu.Unlock()
	if self.running == nil {
		return // agent already stopped
	}
	close(self.running.stop)
	<-self.running.done
	self.running = nil
	// Empty work channel
	for {
		select {
		case <-self.workCh:
		default:
			return
		}
	}
}

func (self *CpuAgent) update(generation *cpuAgentGeneration) {
	var (
		quitCurrentOp chan struct{}
		mining        sync.WaitGroup
	)
	defer func() {
		if quitCurrentOp != nil {
			close(quitCurrentOp)
		}
		mining.Wait()
		close(generation.done)
	}()
	for {
		select {
		case work := <-self.workCh:
			// A ready work channel must not delay cancellation of this generation.
			select {
			case <-generation.stop:
				return
			default:
			}
			if quitCurrentOp != nil {
				close(quitCurrentOp)
			}
			quitCurrentOp = make(chan struct{})
			operationStop := quitCurrentOp
			log.Info("CpuAgent.update")
			mining.Add(1)
			go func() {
				defer mining.Done()
				self.mine(work, operationStop, generation.stop)
			}()
		case <-generation.stop:
			return
		}
	}
}

func (self *CpuAgent) mine(work *Work, stop, generationStop <-chan struct{}) {
	log.Info("CpuAgent.mine")
	var completed *Result
	if result, err := self.engine.SealCandidate(work.candidate, stop); result != nil {
		log.Info("Successfully sealed new candidate", "nonce", work.candidate.KeyCandidate.Nonce.Uint64(), "mixdigest", work.candidate.KeyCandidate.MixDigest.Hex())
		completed = &Result{work, result}
	} else {
		if err != nil {
			log.Warn("Candidate sealing failed", "err", err)
		}
	}
	self.returnMu.RLock()
	returnCh := self.returnCh
	self.returnMu.RUnlock()
	// A worker may hold its own mutex while stopping us, or its result queue
	// may already be full. Neither can prevent canceled sealing from draining.
	select {
	case returnCh <- completed:
	case <-generationStop:
	}
}
