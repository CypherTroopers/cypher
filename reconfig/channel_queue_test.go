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
