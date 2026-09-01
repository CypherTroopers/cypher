package reconfig

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rnet/network"
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

func TestHotstuffMessageQueueDeduplicatesPendingRemoteWireMessage(t *testing.T) {
	q := newHotstuffMessageQueue()
	sender := &network.ServerIdentity{Address: network.Address("byzantine:7100")}
	msg := &hotstuffMsg{sid: sender, hMsg: &hotstuff.HotstuffMessage{
		Code: hotstuff.MsgPrepare, Number: 7, Id: sender.Address.String(), AuthSig: []byte("signed-wire-message"),
	}}
	if !q.push(msg) {
		t.Fatal("first remote wire message was rejected")
	}
	if q.push(msg) {
		t.Fatal("duplicate pending remote wire message consumed another queue slot")
	}
	select {
	case <-q.next:
	case <-time.After(time.Second):
		t.Fatal("timed out consuming dedupe fixture")
	}
	if q.push(msg) {
		t.Fatal("recently processed remote wire replay was immediately revalidated")
	}
}

func TestHotstuffMessageQueueReservesCapacityForEntireMaximumCommittee(t *testing.T) {
	if params.MaxFairHotstuffCommitteeSize*hotstuffQueuePerSenderEntries > hotstuffQueueMaxEntries {
		t.Fatal("entry budget cannot reserve every maximum-committee sender's quota")
	}
	if params.MaxFairHotstuffCommitteeSize*hotstuffQueuePerSenderBytes > hotstuffQueueMaxBytes {
		t.Fatal("byte budget cannot reserve every maximum-committee sender's quota")
	}
}

func TestHotstuffMessageQueuePreservesCapacityForOtherSenders(t *testing.T) {
	q := newHotstuffMessageQueue()
	byzantine := &network.ServerIdentity{Address: network.Address("byzantine:7100")}
	for i := 0; i < hotstuffQueuePerSenderEntries; i++ {
		msg := &hotstuffMsg{sid: byzantine, hMsg: &hotstuff.HotstuffMessage{
			Code: hotstuff.MsgPrepare, Number: uint64(i + 1), Id: byzantine.Address.String(), AuthSig: []byte{byte(i)},
		}}
		if !q.push(msg) {
			t.Fatalf("sender quota rejected message %d before the documented cap", i)
		}
	}
	if q.push(&hotstuffMsg{sid: byzantine, hMsg: &hotstuff.HotstuffMessage{
		Code: hotstuff.MsgPrepare, Number: 999, Id: byzantine.Address.String(), AuthSig: []byte("over-quota"),
	}}) {
		t.Fatal("one remote sender exceeded its queue quota")
	}

	honest := &network.ServerIdentity{Address: network.Address("honest:7100")}
	if !q.push(&hotstuffMsg{sid: honest, hMsg: &hotstuff.HotstuffMessage{
		Code: hotstuff.MsgPrepare, Number: 1000, Id: honest.Address.String(), AuthSig: []byte("honest"),
	}}) {
		t.Fatal("Byzantine sender quota exhausted another sender's queue capacity")
	}
}

func TestHotstuffMessageQueueAcceptsBoundedCertifiedCatchupBurst(t *testing.T) {
	q := newHotstuffMessageQueue()
	leader := &network.ServerIdentity{Address: network.Address("leader:7100")}
	for i := 0; i < hotstuffQueuePerSenderEntries; i++ {
		msg := &hotstuffMsg{sid: leader, hMsg: &hotstuff.HotstuffMessage{
			Code: hotstuff.MsgQCBroadcast, Number: uint64(i + 1), Id: leader.Address.String(), AuthSig: []byte{byte(i + 1)},
		}}
		if !q.push(msg) {
			t.Fatalf("certified catch-up burst rejected message %d before sender bound", i)
		}
	}
	if q.push(&hotstuffMsg{sid: leader, hMsg: &hotstuff.HotstuffMessage{
		Code: hotstuff.MsgQCBroadcast, Number: 10_000, Id: leader.Address.String(), AuthSig: []byte("over-bound"),
	}}) {
		t.Fatal("certified catch-up burst exceeded sender bound")
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

func TestHotstuffMessageQueueRejectsUnboundedRemoteBacklog(t *testing.T) {
	q := newHotstuffMessageQueue()
	large := &hotstuffMsg{hMsg: &hotstuff.HotstuffMessage{
		Code:  hotstuff.MsgNewView,
		DataA: make([]byte, hotstuff.MaxHotstuffControlBytes),
	}}
	accepted := 0
	for accepted < 1000 && q.push(large) {
		accepted++
	}
	if accepted == 1000 {
		t.Fatal("remote HotStuff queue accepted an unbounded backlog")
	}
	// The queue can overshoot its byte threshold by at most one message and has
	// a fixed-size input channel; this assertion catches accidental removal of
	// both bounds without depending on goroutine scheduling.
	maximumAccepted := hotstuffQueueMaxEntries + hotstuffQueueInputCapacity + 1
	if accepted > maximumAccepted {
		t.Fatalf("accepted %d messages, bounded maximum is %d", accepted, maximumAccepted)
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
		go func(producer int) {
			defer wg.Done()
			for j := 0; j < perProducer; j++ {
				number := uint64(producer*perProducer + j + 1)
				if !q.push(&networkMsg{Hmsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgPrepare, Number: number}}) {
					t.Error("queue closed while producers were active")
					return
				}
			}
		}(i)
	}
	wg.Wait()

	for count := 0; count < producers*perProducer; count++ {
		select {
		case <-q.nextHotstuff:
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
		if !q.push(&networkMsg{Pmsg: &proposalBodyMsg{Type: proposalBodyMsgManifest, Number: 1, Manifest: largeBody}}) {
			t.Fatal("queue closed while adding bulk backlog")
		}
	}
	if !q.push(&networkMsg{Hmsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgPrepare}}) {
		t.Fatal("queue closed while adding hotstuff control")
	}

	select {
	case msg := <-q.nextHotstuff:
		if msg == nil || msg.Hmsg == nil || msg.Hmsg.Code != hotstuff.MsgPrepare {
			t.Fatalf("first peer message = %v, want hotstuff control", msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for hotstuff control")
	}
}

func TestPeerQueuesBoundControlBacklogAndExpireRetries(t *testing.T) {
	q := newPeerQueues()
	defer q.close()
	large := &networkMsg{Hmsg: &hotstuff.HotstuffMessage{
		Code:  hotstuff.MsgPrepare,
		DataA: make([]byte, hotstuff.MaxHotstuffControlBytes),
	}}
	accepted := 0
	for accepted < 1000 {
		large.Hmsg.Number = uint64(accepted + 1)
		if !q.push(large) {
			break
		}
		accepted++
	}
	if accepted == 1000 {
		t.Fatal("per-peer outbound control queue accepted an unbounded backlog")
	}

	q2 := newPeerQueues()
	defer q2.close()
	if !q2.push(&networkMsg{Hmsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgPrepare}}) {
		t.Fatal("failed to enqueue retry fixture")
	}
	var queued *networkMsg
	deadline := time.Now().Add(time.Second)
	for queued == nil && time.Now().Before(deadline) {
		select {
		case queued = <-q2.nextHotstuff:
		default:
		}
		if queued == nil {
			time.Sleep(time.Millisecond)
		}
	}
	if queued == nil {
		t.Fatal("failed to dequeue retry fixture")
	}
	queued.queueSince = time.Now().Add(-peerQueueRetryTTL - time.Second)
	q2.release(queued)
	if q2.pushFrontClass(queued) {
		t.Fatal("expired outbound consensus message was requeued")
	}
}

func TestOutboundBudgetSharesImmutableProposalAcrossPeers(t *testing.T) {
	budget := newOutboundQueueBudget()
	body := &proposalBodyMsg{Type: proposalBodyMsgManifest, Manifest: make([]byte, proposalBodyControlMaxBytes+1)}
	msg := &networkMsg{Pmsg: body}
	q1 := newPeerQueuesWithBudget(budget)
	q2 := newPeerQueuesWithBudget(budget)
	defer q1.close()
	defer q2.close()
	if !q1.push(msg) || !q2.push(msg) {
		t.Fatal("shared proposal body was rejected by aggregate outbound budget")
	}

	budget.mu.Lock()
	if budget.bulkRefs != 2 || len(budget.bulkPayloads) != 1 || budget.bulkBytes != peerQueueMessageBytes(msg) {
		t.Fatalf("shared body accounting refs=%d payloads=%d bytes=%d", budget.bulkRefs, len(budget.bulkPayloads), budget.bulkBytes)
	}
	budget.mu.Unlock()

	for _, q := range []*peerQueues{q1, q2} {
		select {
		case queued := <-q.nextBulk:
			q.release(queued)
		case <-time.After(time.Second):
			t.Fatal("timed out draining shared proposal body")
		}
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.bulkRefs != 0 || budget.bulkBytes != 0 || len(budget.bulkPayloads) != 0 {
		t.Fatalf("outbound budget leaked after delivery: refs=%d bytes=%d payloads=%d", budget.bulkRefs, budget.bulkBytes, len(budget.bulkPayloads))
	}
}

func TestOutboundBudgetGloballyBoundsControlMessages(t *testing.T) {
	budget := newOutboundQueueBudget()
	msg := &networkMsg{Hmsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgPrepare, DataA: make([]byte, hotstuff.MaxHotstuffControlBytes)}}
	accepted := 0
	for accepted <= outboundControlMaxEntries && budget.reserve(msg) {
		accepted++
	}
	if accepted == 0 || accepted > outboundControlMaxEntries {
		t.Fatalf("invalid global control admission count %d", accepted)
	}
	for i := 0; i < accepted; i++ {
		budget.release(msg)
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.controlCount != 0 || budget.controlBytes != 0 {
		t.Fatalf("control budget leaked after release: count=%d bytes=%d", budget.controlCount, budget.controlBytes)
	}
}

func TestPeerQueueCoalescesIdenticalCriticalMessage(t *testing.T) {
	budget := newOutboundQueueBudget()
	q := newPeerQueuesWithBudget(budget)
	defer q.close()
	msg := &networkMsg{Hmsg: &hotstuff.HotstuffMessage{
		Code: hotstuff.MsgQCBroadcast, Number: 17, Id: "leader", AuthSig: []byte("sealed"),
	}}
	if !q.push(msg) || !q.push(cloneNetworkMsg(msg)) {
		t.Fatal("coalesced critical send should be reported as queued")
	}
	q.mu.Lock()
	controlCount, digestCount := q.controlCount, len(q.controlDigests)
	q.mu.Unlock()
	if controlCount != 1 || digestCount != 1 {
		t.Fatalf("identical critical messages were separately queued: count=%d digests=%d", controlCount, digestCount)
	}
	budget.mu.Lock()
	globalCount := budget.controlCount
	budget.mu.Unlock()
	if globalCount != 1 {
		t.Fatalf("coalesced critical message consumed %d global slots", globalCount)
	}
	select {
	case queued := <-q.nextHotstuff:
		q.release(queued)
	case <-time.After(time.Second):
		t.Fatal("timed out draining coalesced critical message")
	}
	if !q.push(msg) {
		t.Fatal("critical message remained permanently coalesced after delivery")
	}
}

func TestOutboundControlBudgetPreservesEveryCommitteePeersHeadroom(t *testing.T) {
	if params.MaxFairHotstuffCommitteeSize*peerQueueFairControlMaxEntries > outboundControlMaxEntries {
		t.Fatal("per-peer entry quotas can exhaust the global budget before every committee peer is admitted")
	}
	if params.MaxFairHotstuffCommitteeSize*peerQueueFairControlMaxBytes > outboundControlMaxBytes {
		t.Fatal("per-peer byte quotas can exhaust the global budget before every committee peer is admitted")
	}

	budget := newOutboundQueueBudget()
	attacker := newPeerQueuesWithBudget(budget)
	honest := newPeerQueuesWithBudget(budget)
	defer attacker.close()
	defer honest.close()
	for index := 0; index < peerQueueFairControlMaxEntries; index++ {
		msg := &networkMsg{Hmsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgQCBroadcast, Number: uint64(index + 1)}}
		if !attacker.push(msg) {
			t.Fatalf("attacker quota rejected entry %d too early", index)
		}
	}
	if attacker.push(&networkMsg{Hmsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgQCBroadcast, Number: 999}}) {
		t.Fatal("one peer exceeded its fair control-message quota")
	}
	if !honest.push(&networkMsg{Hmsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgQCBroadcast, Number: 1}}) {
		t.Fatal("saturated peer consumed another peer's reserved headroom")
	}
}

func TestPeerQueueOwnsHotstuffWireSnapshot(t *testing.T) {
	q := newPeerQueuesWithBudget(newOutboundQueueBudget())
	defer q.close()
	original := &networkMsg{Hmsg: &hotstuff.HotstuffMessage{
		Code: hotstuff.MsgQCBroadcast, Number: 7, DataA: []byte{1, 2, 3}, ReceivedAt: time.Now(),
	}}
	if !q.push(original) {
		t.Fatal("failed to enqueue HotStuff snapshot")
	}
	original.Hmsg.DataA[0] = 9
	original.Hmsg.ReceivedAt = time.Now().Add(time.Hour)
	select {
	case queued := <-q.nextHotstuff:
		defer q.release(queued)
		if queued.Hmsg.DataA[0] != 1 {
			t.Fatal("outbound queue shared mutable HotStuff payload bytes")
		}
		if !queued.Hmsg.ReceivedAt.IsZero() {
			t.Fatal("local receive timestamp leaked into the immutable wire snapshot")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out reading HotStuff snapshot")
	}
}

func TestNetworkMessageRequiresExactlyOnePayload(t *testing.T) {
	hotstuffPayload := &hotstuff.HotstuffMessage{Code: hotstuff.MsgPrepare}
	proposalPayload := &proposalBodyMsg{Type: proposalBodyMsgRepairRequest}
	for name, msg := range map[string]*networkMsg{
		"empty":             {},
		"hotstuff+proposal": {Hmsg: hotstuffPayload, Pmsg: proposalPayload},
		"gossiped-hotstuff": {MsgFlag: Gossip_MSG, Hmsg: hotstuffPayload},
		"gossiped-sidecar":  {MsgFlag: Gossip_MSG, Pmsg: proposalPayload},
	} {
		if err := validateNetworkMsgShape(msg); err == nil {
			t.Fatalf("%s malformed message was accepted", name)
		}
	}
	if err := validateNetworkMsgShape(&networkMsg{Hmsg: hotstuffPayload}); err != nil {
		t.Fatalf("valid one-of HotStuff message rejected: %v", err)
	}
	q := newPeerQueuesWithBudget(newOutboundQueueBudget())
	defer q.close()
	if q.push(&networkMsg{Hmsg: hotstuffPayload, Pmsg: proposalPayload}) {
		t.Fatal("queue admitted a multi-payload message with undercounted bytes")
	}
}

func TestInvalidNetworkMessageShapeIsPermanentAndNotRetryable(t *testing.T) {
	hotstuffPayload := &hotstuff.HotstuffMessage{Code: hotstuff.MsgPrepare}
	malformed := &networkMsg{
		Hmsg: hotstuffPayload,
		Pmsg: &proposalBodyMsg{Type: proposalBodyMsgRepairRequest},
	}
	err := new(netService).SendRawData("peer", malformed)
	if !network.IsPermanentSendError(err) {
		t.Fatalf("invalid message shape was not classified as permanent: %v", err)
	}
	var permanent *network.PermanentSendError
	if !errors.As(err, &permanent) || permanent.Kind != network.SendErrorInvalidMessage {
		t.Fatalf("invalid message shape kind = %v, want %v", permanent, network.SendErrorInvalidMessage)
	}
	validConsensusMessage := &networkMsg{Hmsg: hotstuffPayload}
	if retryableConsensusSendError(validConsensusMessage, err) {
		t.Fatal("permanent local send error would be requeued")
	}
}

func TestTransientConsensusSendErrorRemainsRetryable(t *testing.T) {
	msg := &networkMsg{Hmsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgPrepare}}
	if !retryableConsensusSendError(msg, network.ErrTimeout) {
		t.Fatal("transient consensus stream timeout would not be requeued")
	}
}

func TestStoppingPeerWorkerCannotDeleteReplacement(t *testing.T) {
	oldState, newState := new(int32), new(int32)
	oldQueue, newQueue := newPeerQueues(), newPeerQueues()
	defer oldQueue.close()
	defer newQueue.close()
	service := &netService{
		goMap:    map[string]*int32{"peer": newState},
		idQueues: map[string]*peerQueues{"peer": newQueue},
		ackMap:   map[string]*ackInfo{"peer": {}},
	}
	if service.removePeerWorkerIfOwned("peer", oldQueue, oldState) {
		t.Fatal("superseded worker claimed ownership of its replacement")
	}
	if service.goMap["peer"] != newState || service.idQueues["peer"] != newQueue {
		t.Fatal("superseded worker deleted the replacement queue")
	}
	if !service.removePeerWorkerIfOwned("peer", newQueue, newState) {
		t.Fatal("current worker could not clean up its own queue")
	}
	if _, exists := service.idQueues["peer"]; exists {
		t.Fatal("owned queue remained after cleanup")
	}
}

func TestOutboundMessageExpiresBeforeFirstSend(t *testing.T) {
	now := time.Now()
	msg := &networkMsg{queueSince: now.Add(-peerQueueRetryTTL - time.Nanosecond)}
	if !outboundMessageExpired(msg, now) {
		t.Fatal("message that expired while queued would still be sent once")
	}
	msg.queueSince = now.Add(-peerQueueRetryTTL + time.Second)
	if outboundMessageExpired(msg, now) {
		t.Fatal("fresh outbound message was treated as expired")
	}
}

func TestPeerQueueCloseReleasesAggregateBudget(t *testing.T) {
	budget := newOutboundQueueBudget()
	q := newPeerQueuesWithBudget(budget)
	body := &proposalBodyMsg{Type: proposalBodyMsgManifest, Manifest: make([]byte, proposalBodyControlMaxBytes+1)}
	if !q.push(&networkMsg{Pmsg: body}) {
		t.Fatal("failed to enqueue close fixture")
	}
	q.close()
	deadline := time.Now().Add(time.Second)
	for {
		budget.mu.Lock()
		released := budget.bulkRefs == 0 && budget.bulkBytes == 0 && len(budget.bulkPayloads) == 0
		budget.mu.Unlock()
		if released {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closing peer queue leaked aggregate outbound reservation")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestProposalBodyBulkIsNotHighPriorityNetworkMsg(t *testing.T) {
	largeBody := make([]byte, proposalBodyControlMaxBytes+1)
	if isHighPriorityNetworkMsg(&networkMsg{Pmsg: &proposalBodyMsg{Type: proposalBodyMsgManifest, Manifest: largeBody}}) {
		t.Fatal("proposal body bulk must not be high priority")
	}
	if !isHighPriorityNetworkMsg(&networkMsg{Pmsg: &proposalBodyMsg{Type: proposalBodyMsgManifest, Manifest: make([]byte, proposalBodyControlMaxBytes)}}) {
		t.Fatal("small proposal body data should be high priority")
	}
	if !isHighPriorityNetworkMsg(&networkMsg{Pmsg: &proposalBodyMsg{Type: proposalBodyMsgRepairRequest}}) {
		t.Fatal("proposal body request should remain high priority")
	}
	if !isHighPriorityNetworkMsg(&networkMsg{Hmsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgPrepare}}) {
		t.Fatal("hotstuff control should remain high priority")
	}
}
