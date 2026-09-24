package relay

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/dex/protocol"
)

// A durable 204-record workload reproduces ordinary cold relay selection.
// Fake observations isolate work scheduling; elapsed time is not BLS/MPT cost.
func TestRelayColdHistoryDoesNotDelayReservedOwners(t *testing.T) {
	t.Run("late-new-claim", func(t *testing.T) { coldSchedulingWorkload(t, false) })
	t.Run("older-queued-claims", func(t *testing.T) { coldSchedulingWorkload(t, true) })
}

func coldSchedulingWorkload(t *testing.T, olderQueued bool) {
	c, b, signer := fixtureConfig(t)
	dir := filepath.Join(t.TempDir(), "relay")
	r := openFixture(t, c, b, signer, dir)
	history := map[protocol.Hash]bool{}
	b.obs.completed = true
	for id := uint64(1); id <= 200; id++ {
		lane := Checkpoint
		if id%2 == 0 {
			lane = Claim
		}
		j := fixtureJob(lane, id)
		j.Owner = common.Address{19: byte(id % 7)}
		if lane == Checkpoint {
			j.Owner = common.Address{}
		}
		history[j.ID] = true
		if err := r.Enqueue(j); err != nil {
			t.Fatal(err)
		}
		if err := stepNow(r); err != nil {
			t.Fatal(err)
		}
	}
	b.obs.completed = false
	pendingCP, pendingClaim := fixtureJob(Checkpoint, 201), fixtureJob(Claim, 202)
	pendingCP.Owner = common.Address{}
	for _, j := range []Job{pendingCP, pendingClaim} {
		if err := r.Enqueue(j); err != nil {
			t.Fatal(err)
		}
		if err := stepNow(r); err != nil {
			t.Fatal(err)
		}
	}
	newClaim, inbox := fixtureJob(Claim, 203), fixtureJob(Inbox, 204)
	for _, j := range []Job{newClaim, inbox} {
		if err := r.Enqueue(j); err != nil {
			t.Fatal(err)
		}
	}
	older := map[protocol.Hash]bool{}
	if olderQueued {
		// Seed the same valid durable shape as trial11: unsigned claims have
		// earlier local IDs than the latest reserved checkpoint. These local
		// phases are fixture metadata, never accepted financial evidence.
		d := cloneState(r.state)
		for i := range d.Records {
			id := d.Records[i].LocalID
			if id >= 170 && id <= 188 && id%2 == 0 {
				x := &d.Records[i]
				x.Phase, x.Proof = "queued", nil
				delete(history, x.Job.ID)
				older[x.Job.ID] = true
			}
		}
		if err := r.persist(d); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r = openFixture(t, c, b, signer, dir)
	defer r.Close()
	ownerCalls := map[protocol.Hash]int{}
	paidNew := map[protocol.Hash]bool{}
	b.observe = func(j Job, a Attempt) (observation, error) {
		o := b.obs
		if history[j.ID] {
			o.completed = true
			return o, nil
		}
		if j.ID == pendingCP.ID || j.ID == pendingClaim.ID {
			ownerCalls[j.ID]++
			o.completed = ownerCalls[j.ID] >= 2
			if o.completed {
				o.nonce = 1
			}
			return o, nil
		}
		o.completed = a.Sends > 0
		if j.ID == newClaim.ID || older[j.ID] {
			if o.completed {
				paidNew[j.ID] = true
			}
			o.nonce = 1 + uint64(len(paidNew))
		}
		return o, nil
	}
	b.seen = nil
	start := time.Now()
	firstCP, firstClaim, firstInbox, firstNewClaim, firstOlder := 0, 0, 0, 0, 0
	firstWindowHistory := 0
	completeAt := 0
	for step := 1; step <= 450; step++ {
		if err := stepNow(r); err != nil {
			t.Fatal(err)
		}
		id := b.seen[len(b.seen)-1]
		if id == pendingCP.ID && firstCP == 0 {
			firstCP = step
		}
		if id == pendingClaim.ID && firstClaim == 0 {
			firstClaim = step
		}
		if id == inbox.ID && firstInbox == 0 {
			firstInbox = step
		}
		if id == newClaim.ID && firstNewClaim == 0 {
			firstNewClaim = step
		}
		if older[id] && firstOlder == 0 {
			firstOlder = step
		}
		if step <= 8 && history[id] {
			firstWindowHistory++
		}
		done := true
		for _, rec := range r.Status() {
			done = done && rec.Phase == "complete"
		}
		if done {
			completeAt = step
			break
		}
	}
	t.Logf("COLD_SCHEDULER records=204 olderQueued=%v firstCP=%d firstClaim=%d firstInbox=%d firstNewClaim=%d firstOlder=%d first8History=%d completedAt=%d ObserveCalls=%d elapsed=%s fakeBackend=true", olderQueued, firstCP, firstClaim, firstInbox, firstNewClaim, firstOlder, firstWindowHistory, completeAt, len(b.seen), time.Since(start))
	if completeAt == 0 || completeAt > 212+2*len(older) {
		t.Fatal("finite historical revalidation or current work did not converge", completeAt)
	}
	if firstCP == 0 || firstCP > 8 || firstClaim == 0 || firstClaim > 8 || firstInbox == 0 || firstInbox > 8 || firstWindowHistory == 0 {
		t.Fatal("cold historical work delayed reserved owners or independent lane")
	}
	if olderQueued && (firstOlder == 0 || firstOlder > 20) {
		t.Fatal("older unsigned claim delayed behind cold history", firstOlder)
	}
	if signer.calls != 3+len(older) || b.dexSent != 1 {
		t.Fatal("cold replay changed nonce ownership or repeated paid actions", signer.calls, b.dexSent)
	}
}

func TestRelayColdClassesRotateFailuresAndReservationForms(t *testing.T) {
	for _, phase := range []string{"prepared", "signed", "submitted", "completed_pending_nonce"} {
		for _, ownerLast := range []bool{false, true} {
			name := phase + "/history-last"
			if ownerLast {
				name = phase + "/owner-last"
			}
			t.Run(name, func(t *testing.T) {
				c, b, signer := fixtureConfig(t)
				dir := filepath.Join(t.TempDir(), "relay")
				armed := false
				c.Hook = func(stage string) error {
					if armed && ((phase == "prepared" && stage == "after_prepared") || (phase == "signed" && stage == "after_signed")) {
						return errors.New("selected reservation crash")
					}
					return nil
				}
				r := openFixture(t, c, b, signer, dir)
				b.obs.completed = true
				history := map[protocol.Hash]bool{}
				for id := uint64(1); id <= 8; id++ {
					j := fixtureJob(Checkpoint, id)
					j.Owner = common.Address{}
					history[j.ID] = true
					if err := r.Enqueue(j); err != nil {
						t.Fatal(err)
					}
					if err := stepNow(r); err != nil {
						t.Fatal(err)
					}
				}
				owner := fixtureJob(Checkpoint, 9)
				owner.Owner = common.Address{}
				b.obs.completed, armed = false, true
				if err := r.Enqueue(owner); err != nil {
					t.Fatal(err)
				}
				if err := stepNow(r); err != nil && phase != "prepared" && phase != "signed" {
					t.Fatal(err)
				}
				armed = false
				if phase == "completed_pending_nonce" {
					b.obs.completed = true
					if err := stepNow(r); err != nil {
						t.Fatal(err)
					}
				}
				if r.state.Records[8].Phase != phase {
					t.Fatal("reservation fixture phase", r.state.Records[8].Phase)
				}
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
				r = openFixture(t, c, b, signer, dir)
				d := cloneState(r.state)
				d.LastSequence[Checkpoint-1] = 1
				if ownerLast {
					d.LastSequence[Checkpoint-1] = 9
				}
				if err := r.persist(d); err != nil {
					t.Fatal(err)
				}
				independent, inbox, bad := fixtureJob(Claim, 10), fixtureJob(Inbox, 11), fixtureJob(Claim, 12)
				for _, j := range []Job{independent, inbox, bad} {
					if err := r.Enqueue(j); err != nil {
						t.Fatal(err)
					}
				}
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
				r = openFixture(t, c, b, signer, dir)
				defer r.Close()
				baselineSigns := signer.calls
				missing := fixtureJob(Checkpoint, 1).ID
				retry := errors.New("evidence temporarily unavailable")
				b.observe = func(j Job, a Attempt) (observation, error) {
					if j.ID == missing || j.ID == owner.ID {
						return observation{}, retry
					}
					if j.ID == bad.ID {
						return observation{}, ErrInvalidJob
					}
					o := b.obs
					o.completed = history[j.ID] || a.Sends > 0
					if j.ID == independent.ID && o.completed {
						o.nonce = 1
					}
					return o, nil
				}
				b.seen = nil
				for i := 0; i < 48; i++ {
					if err := stepNow(r); err != nil && !errors.Is(err, retry) && !errors.Is(err, ErrInvalidJob) {
						t.Fatal(err)
					}
				}
				seen := map[protocol.Hash]int{}
				for _, id := range b.seen {
					seen[id]++
				}
				for id := range history {
					if seen[id] == 0 {
						t.Fatal("retryable first history or failed owner starved later history")
					}
				}
				status := r.Status()
				if seen[owner.ID] < 4 || status[0].Phase != "revalidation_wait" || r.validated[missing] || status[8].Attempt.GasLimit == 0 || status[9].Phase != "complete" || status[10].Phase != "complete" || status[11].Phase != "quarantined" || signer.calls != baselineSigns+1 {
					t.Fatal("cold class authentication/nonce/independent progress", seen[owner.ID], status[0].Phase, status[9].Phase, status[10].Phase, status[11].Phase)
				}
			})
		}
	}
}

func TestRelayColdClassHintsFollowDurableCursor(t *testing.T) {
	c, b, signer := fixtureConfig(t)
	dir := filepath.Join(t.TempDir(), "relay")
	r := openFixture(t, c, b, signer, dir)
	j := fixtureJob(Checkpoint, 1)
	if err := r.Enqueue(j); err != nil {
		t.Fatal(err)
	}
	r.store.afterTemporaryWrite = func() error { return errors.New("cursor persistence failure") }
	if err := stepNow(r); !errors.Is(err, ErrStore) {
		t.Fatal("missing durable cursor failure", err)
	}
	if len(b.seen) != 0 || signer.calls != 0 || r.activeSequence != [4]uint64{} || r.historySequence != [4]uint64{} || r.historyTurn != [4]bool{} {
		t.Fatal("failed cursor write changed hints or began authentication/signing")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r = openFixture(t, c, b, signer, dir)
	defer r.Close()
	if len(r.validated) != 0 || r.activeSequence != [4]uint64{} || r.historySequence != [4]uint64{} {
		t.Fatal("cold reopen trusted scheduling hints")
	}
	b.observe = func(job Job, _ Attempt) (observation, error) {
		if job.ID != j.ID || r.state.LastSequence[Checkpoint-1] != 1 || r.activeSequence[Checkpoint-1] != 1 || !r.historyTurn[Checkpoint-1] {
			t.Fatal("Observe preceded durable cursor and local class update")
		}
		o := b.obs
		o.completed = true
		return o, nil
	}
	if err := stepNow(r); err != nil || r.Status()[0].Phase != "complete" {
		t.Fatal("recovery failed", err)
	}
}
