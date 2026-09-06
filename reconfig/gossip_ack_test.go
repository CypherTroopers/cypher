package reconfig

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/rnet/network"
)

func TestPeerAckTimeConcurrentReceiveAndPacemaker(t *testing.T) {
	const address = "127.0.0.1:7102"
	service := &netService{ackMap: make(map[string]*ackInfo), curKeyBlockN: 1}
	identity := network.NewServerIdentity(address)
	heartbeat := &network.Envelope{ServerIdentity: identity, Msg: &heartBeatMsg{}}
	// An old committee message still updates liveness through the production
	// receiver, then returns before needing a consensus backend.
	message := &network.Envelope{ServerIdentity: identity, Msg: &networkMsg{Cmsg: &committeeInfo{KeyNumber: 0}}}
	initial := service.GetAckTime(address)
	ack := service.getAckInfo(address)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for _, operation := range []func(){
		func() { service.handleHeartBeatMsgAck(heartbeat) },
		func() { service.handleNetworkMsgAck(message) },
		func() { service.GetAckTime(address) },
		func() { service.ResetAckTime(address) },
		func() { service.ResetAckTime("") },
		func() { service.ackStatusSnapshot() },
		func() {
			ack.setSendTime(time.Now())
			atomic.StoreInt32(ack.isSending, 1)
			ack.sendTime()
			atomic.StoreInt32(ack.isSending, 0)
		},
	} {
		workers.Add(1)
		go func(operation func()) {
			defer workers.Done()
			<-start
			for i := 0; i < 1000; i++ {
				operation()
			}
		}(operation)
	}
	close(start)
	workers.Wait()
	last := service.GetAckTime(address)
	if last.Before(initial) || last.After(time.Now()) {
		t.Fatalf("last receive time outside the observation interval: initial=%s last=%s", initial, last)
	}
}

func TestPeerAckTimeTracksBothReceivePaths(t *testing.T) {
	const address = "127.0.0.1:7102"
	for _, kind := range []string{"heartbeat", "network message"} {
		t.Run(kind, func(t *testing.T) {
			service := &netService{ackMap: make(map[string]*ackInfo), curKeyBlockN: 1}
			service.ackMap[address] = &ackInfo{ackTm: time.Now().Add(-time.Hour)}
			identity := network.NewServerIdentity(address)
			before := time.Now()
			if kind == "heartbeat" {
				service.handleHeartBeatMsgAck(&network.Envelope{ServerIdentity: identity, Msg: &heartBeatMsg{}})
			} else {
				service.handleNetworkMsgAck(&network.Envelope{ServerIdentity: identity, Msg: &networkMsg{Cmsg: &committeeInfo{KeyNumber: 0}}})
			}
			last := service.GetAckTime(address)
			if last.Before(before) || last.After(time.Now()) {
				t.Fatalf("%s did not record a current receive time: %s", kind, last)
			}
		})
	}
}
