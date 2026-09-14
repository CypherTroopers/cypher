package reconfig

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

type pacemakerEventTestChain struct {
	block     *types.KeyBlock
	committee []*common.Cnode
}

func (c *pacemakerEventTestChain) CurrentBlock() *types.KeyBlock { return c.block }
func (c *pacemakerEventTestChain) CurrentBlockN() uint64         { return c.block.NumberU64() }
func (c *pacemakerEventTestChain) CurrentCommittee() []*common.Cnode {
	return c.committee
}
func (c *pacemakerEventTestChain) GetBlockByHash(hash common.Hash) *types.KeyBlock {
	if hash == c.block.Hash() {
		return c.block
	}
	return nil
}

// The real TX event loop and Service timeout queue are exercised with the
// deployed genesis limits. Only the committee-chain lookup is a test double;
// aging the initial progress time avoids waiting out the large native lease.
func newFHSPacemakerEventFixture(t *testing.T) (*paceMakerTimer, *event.Feed, <-chan *hotstuffMsg) {
	t.Helper()
	encoded, err := os.ReadFile("../genesis.json")
	if err != nil {
		t.Fatal(err)
	}
	var genesis core.Genesis
	if err := json.Unmarshal(encoded, &genesis); err != nil {
		t.Fatal(err)
	}
	committee := &bftview.Committee{List: make([]*common.Cnode, len(genesis.Config.GenCommittee))}
	for i := range committee.List {
		node := genesis.Config.GenCommittee[i]
		committee.List[i] = &node
	}
	chain := &pacemakerEventTestChain{
		block: types.NewKeyBlock(&types.KeyBlockHeader{
			Number: big.NewInt(0), Difficulty: big.NewInt(1), CommitteeHash: committee.RlpHash(),
		}),
		committee: committee.List,
	}
	db := rawdb.NewMemoryDatabase()
	bftview.SetCommitteeConfig(db, chain, nil)
	if !bftview.WriteCommittee(0, chain.block.Hash(), committee) {
		t.Fatal("store pacemaker committee")
	}
	// A follower observes a healthy leader's heartbeat, but no block progress.
	bftview.SetServerInfo(committee.List[1].Address, committee.List[1].Public)
	if bftview.IamMember() != 1 {
		t.Fatal("pacemaker fixture is not a committee follower")
	}
	deadlineStart := time.Now().Add(-paceMakerTimeoutForConfig(genesis.Config) - time.Second)
	priority := make(chan *hotstuffMsg, 8)
	service := &Service{
		chainConfig:        genesis.Config,
		runningState:       1,
		currentView:        bftview.View{LeaderIndex: 0, ViewNumber: 1},
		hotstuffProgressAt: deadlineStart,
		hotstuffMsgQ:       &hotstuffMessageQueue{priorityInput: priority},
		protocolMng:        new(hotstuff.HotstuffProtocolManager),
		netService: &netService{ackMap: map[string]*ackInfo{
			committee.List[0].Address: {ackTm: time.Now()},
		}},
	}
	timer := &paceMakerTimer{
		service: service, config: genesis.Config, startTime: deadlineStart,
		txsCh: make(chan core.NewTxsEvent),
	}
	service.pacetMakerTimer = timer
	feed := new(event.Feed)
	timer.txsSub = feed.Subscribe(timer.txsCh)
	eventsDone := make(chan struct{})
	go func() {
		defer close(eventsDone)
		timer.txsEventLoop()
	}()
	t.Cleanup(func() {
		timer.close()
		select {
		case <-eventsDone:
		case <-time.After(2 * time.Second):
			t.Error("pacemaker TX event loop did not stop")
		}
		bftview.SetServerInfo("", "")
		bftview.SetCommitteeConfig(nil, nil, nil)
		db.Close()
	})
	return timer, feed, priority
}

func pacemakerTestTxEvent() core.NewTxsEvent {
	return core.NewTxsEvent{Txs: []*types.Transaction{
		types.NewTransaction(0, common.Address{1}, big.NewInt(1), 21000, big.NewInt(1), nil),
	}}
}

func sendPacemakerTxEvents(t *testing.T, feed *event.Feed) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		// The unbuffered subscription makes the second delivery a barrier:
		// the first event has completed its entire handler before we return.
		feed.Send(pacemakerTestTxEvent())
		feed.Send(pacemakerTestTxEvent())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pacemaker did not consume TX events")
	}
}

func TestFHSPacemakerTimesOutWithHealthyHeartbeatAndContinuingTransactions(t *testing.T) {
	timer, feed, priority := newFHSPacemakerEventFixture(t)
	sendPacemakerTxEvents(t, feed)
	stopTXs, txsDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(txsDone)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopTXs:
				return
			case <-ticker.C:
				feed.Send(pacemakerTestTxEvent())
			}
		}
	}()
	defer func() { close(stopTXs); <-txsDone }()
	timerDone := make(chan struct{})
	go func() { defer close(timerDone); timer.loopTimer() }()
	defer func() { timer.close(); <-timerDone }()
	select {
	case msg := <-priority:
		if msg == nil || msg.hMsg == nil || msg.hMsg.Code != hotstuff.MsgLocalTimeout {
			t.Fatalf("no-progress deadline emitted %v, want local FHS timeout", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("continuing TX arrivals suppressed timeout of a stalled, heartbeating leader")
	}
}

func TestFHSPacemakerProgressAndViewStartResetDeadline(t *testing.T) {
	for _, action := range []string{"committed block", "view start"} {
		t.Run(action, func(t *testing.T) {
			timer, feed, _ := newFHSPacemakerEventFixture(t)
			before := time.Now()
			if action == "committed block" {
				timer.procBlockDone(types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1)}), nil, false)
			} else if err := timer.start(); err != nil {
				t.Fatal(err)
			}
			progressStart, stopped, _, _ := timer.get()
			if stopped || progressStart.Before(before) || progressStart.After(time.Now()) {
				t.Fatalf("%s did not establish a fresh active deadline: %s stopped=%t", action, progressStart, stopped)
			}
			sendPacemakerTxEvents(t, feed)
			if after, _, _, _ := timer.get(); !after.Equal(progressStart) {
				t.Fatalf("TX arrival moved the %s deadline from %s to %s", action, progressStart, after)
			}
		})
	}
}

func TestFHSPacemakerTransactionsDoNotRestartStoppedTimer(t *testing.T) {
	timer, feed, _ := newFHSPacemakerEventFixture(t)
	if err := timer.stop(); err != nil {
		t.Fatal(err)
	}
	stoppedStart, _, _, _ := timer.get()
	sendPacemakerTxEvents(t, feed)
	if after, stopped, _, _ := timer.get(); !stopped || !after.Equal(stoppedStart) {
		t.Fatalf("TX arrival restarted stopped pacemaker: start=%s stopped=%t", after, stopped)
	}
}
