package reconfig_test

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

const continuousSettlementIdle = 120 * time.Second
const continuousCleanupReserve = 30 * time.Second

// These counters come only from continuousLedger.scan, after real FHS finality
// and matching canonical receipts on all seven CLX nodes. ACK/head/proposal and
// local relay phase counts are deliberately not inputs to this clock.
type continuousProgress struct{ Sequence, Claims, Anchor uint64 }
type continuousProgressWatch struct {
	start, hard, last, observed time.Time
	point                       continuousProgress
}

func (w *continuousProgressWatch) observe(now time.Time, p continuousProgress) (bool, error) {
	if now.Before(w.observed) || p.Sequence < w.point.Sequence || p.Claims < w.point.Claims || p.Anchor < w.point.Anchor {
		return false, errors.New("continuous canonical progress regression")
	}
	if !now.Before(w.hard) {
		return false, errors.New("continuous absolute parent deadline")
	}
	if now.Sub(w.last) >= continuousSettlementIdle {
		return false, errors.New("continuous canonical progress idle deadline")
	}
	w.observed = now
	if p == w.point {
		return false, nil
	}
	w.point, w.last = p, now
	return true, nil
}

func continuousParentBound(t *testing.T) time.Time {
	t.Helper()
	deadline, ok := t.Deadline()
	if !ok {
		t.Fatal("continuous network fixture requires a finite parent test deadline")
	}
	return deadline.Add(-continuousCleanupReserve)
}

func (f *continuousFixture) progressPoint() continuousProgress {
	var seq uint64
	for n := range f.ledger.accepted {
		if n > seq {
			seq = n
		}
	}
	return continuousProgress{seq, uint64(len(f.ledger.seenClaims)), f.ledger.anchorProgressHeight}
}

func (f *continuousFixture) progressWatch(t *testing.T, label string) *continuousProgressWatch {
	t.Helper()
	now := time.Now()
	w := &continuousProgressWatch{start: now, hard: continuousParentBound(t), last: now, observed: now, point: f.progressPoint()}
	t.Logf("CONTINUOUS_PROGRESS_START label=%s idle=%s hard=%s canonical=%+v", label, continuousSettlementIdle, w.hard.UTC().Format(time.RFC3339Nano), w.point)
	return w
}

func (f *continuousFixture) observeProgress(t *testing.T, w *continuousProgressWatch, label string) {
	t.Helper()
	now := time.Now()
	last := w.last
	changed, err := w.observe(now, f.progressPoint())
	if err != nil {
		t.Fatalf("%s label=%s elapsed=%s idle=%s canonical=%+v relays=%+v", err, label, now.Sub(w.start), now.Sub(last), f.progressPoint(), f.relayStatuses(t))
	}
	if changed {
		t.Logf("CONTINUOUS_CANONICAL_PROGRESS label=%s elapsed=%s idle=%s sequence=%d uniquePaid=%d nativeAnchor=%d", label, now.Sub(w.start), now.Sub(last), w.point.Sequence, w.point.Claims, w.point.Anchor)
	}
}

func TestContinuousCanonicalProgressWatch(t *testing.T) {
	start := time.Unix(1000, 0)
	newWatch := func() continuousProgressWatch {
		return continuousProgressWatch{start: start, hard: start.Add(45*time.Minute - continuousCleanupReserve), last: start, observed: start}
	}
	t.Run("steady_canonical_progress_beyond_old_phase_cap", func(t *testing.T) {
		w := newWatch()
		for minute := 1; minute <= 12; minute++ {
			p := continuousProgress{uint64(minute), uint64(minute / 2), uint64(minute * 8)}
			if changed, err := w.observe(start.Add(time.Duration(minute)*time.Minute), p); err != nil || !changed {
				t.Fatal(changed, err)
			}
		}
	})
	t.Run("head_ack_replay_and_local_phase_do_not_reset_idle", func(t *testing.T) {
		w := newWatch()
		// Advancing unrelated observations supplies the same canonical counters.
		for i := 1; i < 120; i++ {
			if changed, err := w.observe(start.Add(time.Duration(i)*time.Second), continuousProgress{}); changed || err != nil {
				t.Fatal(changed, err)
			}
		}
		if _, err := w.observe(start.Add(120*time.Second), continuousProgress{}); err == nil {
			t.Fatal("idle expiry ignored")
		}
	})
	t.Run("late_event_cannot_revive_expired_watch", func(t *testing.T) {
		w := newWatch()
		if _, err := w.observe(start.Add(120*time.Second), continuousProgress{Sequence: 1}); err == nil {
			t.Fatal("late event revived watchdog")
		}
	})
	t.Run("absolute_limit_despite_continuous_progress", func(t *testing.T) {
		w := newWatch()
		for minute := 1; minute <= 44; minute++ {
			if _, err := w.observe(start.Add(time.Duration(minute)*time.Minute), continuousProgress{Sequence: uint64(minute)}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := w.observe(w.hard, continuousProgress{Sequence: 45}); err == nil {
			t.Fatal("absolute deadline ignored")
		}
	})
	for _, field := range []string{"sequence", "claims", "anchor", "clock"} {
		t.Run(fmt.Sprintf("regression_%s", field), func(t *testing.T) {
			w := newWatch()
			p := continuousProgress{1, 1, 1}
			w.observe(start.Add(time.Second), p)
			now := start.Add(2 * time.Second)
			switch field {
			case "sequence":
				p.Sequence = 0
			case "claims":
				p.Claims = 0
			case "anchor":
				p.Anchor = 0
			case "clock":
				now = start
			}
			if _, err := w.observe(now, p); err == nil {
				t.Fatal("regression accepted")
			}
		})
	}
}
