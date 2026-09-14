package eth

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestTransactionIngressLifecycleStopsExactlyOnce(t *testing.T) {
	var calls atomic.Int32
	lifecycle := &transactionIngressLifecycle{stop: func() { calls.Add(1) }}

	const callers = 32
	var group sync.WaitGroup
	group.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer group.Done()
			if err := lifecycle.Stop(); err != nil {
				t.Errorf("Stop failed: %v", err)
			}
		}()
	}
	group.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("ingress stop calls = %d, want 1", got)
	}
}
