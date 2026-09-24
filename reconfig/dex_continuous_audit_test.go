package reconfig_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/cypherium/cypher/dex/protocol"
)

// This clock is only a bounded wait for cold-reopened relay diagnostics. It
// cannot authenticate a native payment or replace the independent ledger gate.
type continuousAuditKey struct {
	relay int
	id    protocol.Hash
}

func continuousAuditFixture(t *testing.T, phases ...string) []continuousRelayStatus {
	t.Helper()
	out := make([]continuousRelayStatus, 2)
	for i := range out {
		counts := map[string]int{}
		jobs := make([]map[string]interface{}, 0, len(phases))
		for n, phase := range phases {
			id := protocol.Hash{byte(n + 1), byte((n + 1) >> 8)}
			jobs = append(jobs, map[string]interface{}{"ID": id, "Phase": phase, "Reserved": true})
			counts[phase]++
		}
		raw, err := json.Marshal(map[string]interface{}{"Version": 1, "Devnet": true, "Authenticated": map[string]interface{}{"DEXSequence": 109, "CLXSequence": 109, "CLXSequenceVerified": true}, "TotalJobs": len(phases), "Counts": counts, "Jobs": jobs})
		if err != nil || json.Unmarshal(raw, &out[i]) != nil {
			t.Fatal("audit fixture encoding", err)
		}
	}
	return out
}

func TestContinuousRelayAuditWatch(t *testing.T) {
	start := time.Unix(1000, 0)
	newWatch := func(s []continuousRelayStatus) *continuousAuditWatch {
		w, err := newContinuousAuditWatch(start, start.Add(45*time.Minute-continuousCleanupReserve), 109, s)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	t.Run("fresh_unique_revalidation_can_outlast_old_phase_cap", func(t *testing.T) {
		phases := make([]string, 12)
		for i := range phases {
			phases[i] = "revalidation_wait"
		}
		w := newWatch(continuousAuditFixture(t, phases...))
		for n := range phases {
			phases[n] = "complete"
			changed, complete, err := w.observe(start.Add(time.Duration(n+1)*time.Minute), continuousAuditFixture(t, phases...))
			if err != nil || !changed || complete != (n == len(phases)-1) {
				t.Fatal(changed, complete, err)
			}
		}
	})
	t.Run("baseline_repeat_ack_height_and_new_ids_do_not_reset", func(t *testing.T) {
		w := newWatch(continuousAuditFixture(t, "complete", "waiting"))
		s := continuousAuditFixture(t, "complete", "waiting", "complete")
		for i := range s {
			s[i].Authenticated.SourceAnchor.Height = 1000
			s[i].Jobs[1].RPCAckObserved = true
		}
		if changed, complete, err := w.observe(start.Add(119*time.Second), s); changed || complete || err != nil {
			t.Fatal(changed, complete, err)
		}
		if _, _, err := w.observe(start.Add(120*time.Second), continuousAuditFixture(t, "complete", "complete", "complete")); err == nil {
			t.Fatal("late completion revived audit clock")
		}
	})
	t.Run("pending_nonce_incomplete_reserved_history_complete_allowed", func(t *testing.T) {
		w := newWatch(continuousAuditFixture(t, "completed_pending_nonce"))
		if changed, complete, err := w.observe(start.Add(time.Second), continuousAuditFixture(t, "completed_pending_nonce")); changed || complete || err != nil {
			t.Fatal(changed, complete, err)
		}
		if changed, complete, err := w.observe(start.Add(2*time.Second), continuousAuditFixture(t, "complete")); !changed || !complete || err != nil {
			t.Fatal(changed, complete, err)
		}
	})
	for _, field := range []string{"truncated", "missing", "duplicate", "counts", "regression", "sequence", "zero", "quarantine", "bound", "clock", "hard"} {
		t.Run(field, func(t *testing.T) {
			w := newWatch(continuousAuditFixture(t, "complete", "waiting"))
			s := continuousAuditFixture(t, "complete", "waiting")
			now := start.Add(time.Second)
			switch field {
			case "truncated":
				s[0].JobsTruncated = true
			case "missing":
				s = continuousAuditFixture(t, "complete")
			case "duplicate":
				s[0].Jobs[1].ID = s[0].Jobs[0].ID
			case "counts":
				s[0].Counts["complete"]++
			case "regression":
				s = continuousAuditFixture(t, "waiting", "waiting")
			case "sequence":
				s[0].Authenticated.CLXSequence = 108
			case "zero":
				s[0].Jobs[0].ID = protocol.Hash{}
			case "quarantine":
				s = continuousAuditFixture(t, "complete", "quarantined")
			case "bound":
				phases := make([]string, 257)
				for i := range phases {
					phases[i] = "waiting"
				}
				s = continuousAuditFixture(t, phases...)
			case "clock":
				now = start.Add(-time.Second)
			case "hard":
				w.hard = now
			}
			if _, _, err := w.observe(now, s); err == nil {
				t.Fatal("invalid audit observation accepted")
			}
		})
	}
	// This phase cannot replace or reset the payment clock when only62 of72
	// claims have been authenticated, as in trial11.
	t.Run("local_audit_progress_does_not_change_payment_watch", func(t *testing.T) {
		p := continuousProgress{109, 62, 321}
		payment := continuousProgressWatch{start: start, hard: start.Add(45 * time.Minute), last: start, observed: start, point: p}
		w := newWatch(continuousAuditFixture(t, "waiting"))
		if _, _, err := w.observe(start.Add(60*time.Second), continuousAuditFixture(t, "complete")); err != nil {
			t.Fatal(err)
		}
		if _, err := payment.observe(start.Add(120*time.Second), p); err == nil {
			t.Fatal("local audit revived incomplete payments")
		}
	})
}

type continuousAuditWatch struct {
	start, hard, last, observed time.Time
	sequence                    uint64
	known                       map[continuousAuditKey]bool
}

func continuousAuditSnapshot(statuses []continuousRelayStatus, sequence uint64) (map[continuousAuditKey]bool, error) {
	if len(statuses) != 2 {
		return nil, errors.New("cold audit requires both independent relays")
	}
	out := make(map[continuousAuditKey]bool)
	for i, s := range statuses {
		if s.Version != 1 || !s.Devnet || s.JobsTruncated || s.TotalJobs < 1 || s.TotalJobs > 256 || s.TotalJobs != len(s.Jobs) || !s.Authenticated.CLXSequenceVerified || s.Authenticated.CLXSequence < sequence || s.Authenticated.DEXSequence < sequence {
			return nil, fmt.Errorf("cold audit incomplete or malformed status relay%d", i)
		}
		counts := make(map[string]int)
		for _, j := range s.Jobs {
			key := continuousAuditKey{i, j.ID}
			if j.ID == (protocol.Hash{}) {
				return nil, errors.New("cold audit zero job ID")
			}
			if _, exists := out[key]; exists {
				return nil, errors.New("cold audit duplicate job ID")
			}
			if j.Phase == "" || j.Phase == "quarantined" {
				return nil, errors.New("cold audit invalid job phase")
			}
			out[key] = j.Phase == "complete"
			counts[j.Phase]++
		}
		for phase, n := range s.Counts {
			if n < 0 || counts[phase] != n {
				return nil, errors.New("cold audit inconsistent phase counts")
			}
		}
		for phase, n := range counts {
			if s.Counts[phase] != n {
				return nil, errors.New("cold audit missing phase count")
			}
		}
	}
	return out, nil
}

func newContinuousAuditWatch(now, hard time.Time, sequence uint64, statuses []continuousRelayStatus) (*continuousAuditWatch, error) {
	known, err := continuousAuditSnapshot(statuses, sequence)
	if err != nil {
		return nil, err
	}
	return &continuousAuditWatch{start: now, hard: hard, last: now, observed: now, sequence: sequence, known: known}, nil
}

func (w *continuousAuditWatch) observe(now time.Time, statuses []continuousRelayStatus) (changed, complete bool, err error) {
	if now.Before(w.observed) || !now.Before(w.hard) || now.Sub(w.last) >= continuousSettlementIdle {
		return false, false, errors.New("cold audit clock/idle/absolute deadline")
	}
	current, err := continuousAuditSnapshot(statuses, w.sequence)
	if err != nil {
		return false, false, err
	}
	for key, done := range w.known {
		next, exists := current[key]
		if !exists || (done && !next) {
			return false, false, errors.New("cold audit job disappearance or completion regression")
		}
		if !done && next {
			changed = true
		}
	}
	// New IDs, including already-complete ones, establish baseline only. Repeated
	// displays of a completed ID cannot extend this clock. Historical Reserved
	// flags are deliberately not used: only phase excludes an unresolved nonce.
	w.known, w.observed = current, now
	if changed {
		w.last = now
	}
	complete = true
	for _, done := range current {
		complete = complete && done
	}
	return changed, complete, nil
}

func (f *continuousFixture) waitRelayAudit(t *testing.T, sequence uint64) {
	t.Helper()
	statuses := f.relayStatuses(t)
	w, err := newContinuousAuditWatch(time.Now(), continuousParentBound(t), sequence, statuses)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("CONTINUOUS_RELAY_AUDIT_START jobs=%d idle=%s hard=%s financialAuthority=false", len(w.known), continuousSettlementIdle, w.hard.UTC().Format(time.RFC3339Nano))
	lastAdvance := time.Now()
	for {
		// Collect native effects of any ordinary exact resend/carrier separately;
		// neither CLX height nor its ACK is an audit progress signal.
		f.observeCLX(t)
		statuses := f.relayStatuses(t)
		changed, complete, err := w.observe(time.Now(), statuses)
		if err != nil {
			t.Fatalf("%v elapsed=%s jobs=%d", err, time.Since(w.start), len(w.known))
		}
		if changed {
			done := 0
			for _, yes := range w.known {
				if yes {
					done++
				}
			}
			t.Logf("CONTINUOUS_RELAY_AUDIT_PROGRESS freshlyComplete=%d total=%d elapsed=%s financialAuthority=false", done, len(w.known), time.Since(w.start))
		}
		if complete {
			return
		}
		if time.Since(lastAdvance) > 5*time.Second {
			f.send(t, 2, f.owners[2], new(big.Int), nil, 21000)
			lastAdvance = time.Now()
		}
		time.Sleep(250 * time.Millisecond)
	}
}
