package reconfig

import (
	"sync"
	"testing"
	"time"

	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func TestHotstuffMessageQueueConcurrentProducers(t *testing.T) {
	q := newHotstuffMessageQueue()
	const producers = 8
	const perProducer = 250

	var wg sync.WaitGroup
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perProducer; j++ {
				q.push(&hotstuffMsg{hMsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgTimer}})
			}
		}()
	}
	wg.Wait()

	for count := 0; count < producers*perProducer; count++ {
		select {
		case <-q.next:
		case <-time.After(3 * time.Second):
			t.Fatalf("timed out after receiving %d messages", count)
		}
	}
}

func TestHotstuffMessageQueuePriorityBypassesNormalBacklog(t *testing.T) {
	q := newHotstuffMessageQueue()

	for i := 0; i < 64; i++ {
		q.push(&hotstuffMsg{hMsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgNewView}})
	}
	q.pushPriority(&hotstuffMsg{hMsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgStartNewView}})

	select {
	case msg := <-q.next:
		if msg == nil || msg.hMsg == nil || msg.hMsg.Code != hotstuff.MsgStartNewView {
			t.Fatalf("first message code = %v, want priority MsgStartNewView", msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for priority message")
	}
}

func TestPeerQueuesConcurrentProducers(t *testing.T) {
	q := newPeerQueues()
	defer q.close()

	const producers = 8
	const perProducer = 250
	var wg sync.WaitGroup
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perProducer; j++ {
				if !q.push(&networkMsg{Hmsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgPrepare}}) {
					t.Error("queue closed while producers were active")
					return
				}
			}
		}()
	}
	wg.Wait()

	for count := 0; count < producers*perProducer; count++ {
		select {
		case <-q.next:
		case <-time.After(3 * time.Second):
			t.Fatalf("timed out after receiving %d messages", count)
		}
	}
}

func TestPeerQueuesHotstuffControlBypassesBulkBacklog(t *testing.T) {
	q := newPeerQueues()
	defer q.close()

	largeBody := make([]byte, proposalBodyControlMaxBytes+1)
	for i := 0; i < 8; i++ {
		if !q.push(&networkMsg{Pmsg: &proposalBodyMsg{Type: proposalBodyMsgData, Number: 1, EncodedBlock: largeBody}}) {
			t.Fatal("queue closed while adding bulk backlog")
		}
	}
	if !q.push(&networkMsg{Hmsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgPrepare}}) {
		t.Fatal("queue closed while adding hotstuff control")
	}

	select {
	case msg := <-q.next:
		if msg == nil || msg.Hmsg == nil || msg.Hmsg.Code != hotstuff.MsgPrepare {
			t.Fatalf("first peer message = %v, want hotstuff control", msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for hotstuff control")
	}
}

func TestProposalBodyBulkIsNotHighPriorityNetworkMsg(t *testing.T) {
	largeBody := make([]byte, proposalBodyControlMaxBytes+1)
	if isHighPriorityNetworkMsg(&networkMsg{Pmsg: &proposalBodyMsg{Type: proposalBodyMsgData, EncodedBlock: largeBody}}) {
		t.Fatal("proposal body bulk must not be high priority")
	}
	if !isHighPriorityNetworkMsg(&networkMsg{Pmsg: &proposalBodyMsg{Type: proposalBodyMsgData, EncodedBlock: make([]byte, proposalBodyControlMaxBytes)}}) {
		t.Fatal("small proposal body data should be high priority")
	}
	if !isHighPriorityNetworkMsg(&networkMsg{Pmsg: &proposalBodyMsg{Type: proposalBodyMsgRequest}}) {
		t.Fatal("proposal body request should remain high priority")
	}
	if !isHighPriorityNetworkMsg(&networkMsg{Hmsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgPrepare}}) {
		t.Fatal("hotstuff control should remain high priority")
	}
}
