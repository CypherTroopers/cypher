package common

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestQueueZeroValue(t *testing.T) {
	var q Queue
	if got := q.Front(); got != nil {
		t.Fatalf("Front() = %v, want nil", got)
	}
	if got := q.Back(); got != nil {
		t.Fatalf("Back() = %v, want nil", got)
	}
	q.PushBack(1)
	if got := q.PopFront(); got != 1 {
		t.Fatalf("PopFront() = %v, want 1", got)
	}
}

func TestQueueConcurrentPushAndPop(t *testing.T) {
	const (
		producers = 4
		perWorker = 500
	)
	var (
		q  Queue
		wg sync.WaitGroup
	)
	for worker := 0; worker < producers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				q.PushBack(worker*perWorker + i)
			}
		}()
	}

	deadline := time.After(2 * time.Second)
	seen := make(map[int]bool, producers*perWorker)
	for len(seen) < producers*perWorker {
		value := q.PopFront()
		if value == nil {
			select {
			case <-deadline:
				t.Fatalf("popped %d values before timeout", len(seen))
			default:
				runtime.Gosched()
				continue
			}
		}
		n := value.(int)
		if seen[n] {
			t.Fatalf("popped duplicate value %d", n)
		}
		seen[n] = true
	}
	wg.Wait()
	if got := q.Len(); got != 0 {
		t.Fatalf("Len() = %d after consuming all values, want 0", got)
	}
}

func TestQueueConcurrentPush(t *testing.T) {
	const (
		producers = 8
		perWorker = 250
	)
	var (
		q  Queue
		wg sync.WaitGroup
	)
	for worker := 0; worker < producers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				q.PushBack(worker*perWorker + i)
			}
		}()
	}
	wg.Wait()

	want := producers * perWorker
	if got := q.Len(); got != want {
		t.Fatalf("Len() = %d, want %d", got, want)
	}
	seen := make(map[int]bool, want)
	for value := q.PopFront(); value != nil; value = q.PopFront() {
		seen[value.(int)] = true
	}
	if len(seen) != want {
		t.Fatalf("popped %d unique values, want %d", len(seen), want)
	}
}
