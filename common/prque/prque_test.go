package prque

import "testing"

func TestRemoveReturnsStoredValue(t *testing.T) {
	q := New(nil)
	q.Push("low", 1)
	q.Push("high", 10)

	removed := q.Remove(0)
	if removed != "high" {
		t.Fatalf("expected removed value %q, got %#v", "high", removed)
	}
	if q.Size() != 1 {
		t.Fatalf("expected size 1 after remove, got %d", q.Size())
	}
	item, _ := q.Pop()
	if item != "low" {
		t.Fatalf("expected remaining value %q, got %#v", "low", item)
	}
}

func TestRemoveNegativeIndex(t *testing.T) {
	q := New(nil)
	q.Push("x", 1)
	if got := q.Remove(-1); got != nil {
		t.Fatalf("expected nil for negative index, got %#v", got)
	}
	if q.Size() != 1 {
		t.Fatalf("queue size changed after negative remove, got %d", q.Size())
	}
}

func TestRemoveOutOfRangeIndex(t *testing.T) {
	q := New(nil)
	q.Push("x", 1)
	if got := q.Remove(1); got != nil {
		t.Fatalf("expected nil for out-of-range index, got %#v", got)
	}
	if q.Size() != 1 {
		t.Fatalf("queue size changed after out-of-range remove, got %d", q.Size())
	}
}

func TestPeekEmptyQueue(t *testing.T) {
	q := New(nil)
	item, priority := q.Peek()
	if item != nil || priority != 0 {
		t.Fatalf("expected nil/0 from empty Peek, got %#v/%d", item, priority)
	}
}

func TestPopEmptyQueue(t *testing.T) {
	q := New(nil)
	item, priority := q.Pop()
	if item != nil || priority != 0 {
		t.Fatalf("expected nil/0 from empty Pop, got %#v/%d", item, priority)
	}
	if got := q.PopItem(); got != nil {
		t.Fatalf("expected nil from empty PopItem, got %#v", got)
	}
}

func TestZeroValuePrque(t *testing.T) {
	var q Prque
	if !q.Empty() || q.Size() != 0 {
		t.Fatal("zero-value queue should be empty")
	}
	if item, pri := q.Peek(); item != nil || pri != 0 {
		t.Fatalf("unexpected zero-value peek result: %#v/%d", item, pri)
	}
	q.Push("x", 1)
	if q.Size() != 1 {
		t.Fatalf("expected size 1 after push, got %d", q.Size())
	}
	if item, pri := q.Pop(); item != "x" || pri != 1 {
		t.Fatalf("unexpected pop result: %#v/%d", item, pri)
	}
	q.Reset()
	if !q.Empty() || q.Size() != 0 {
		t.Fatal("queue should be empty after reset")
	}
}
