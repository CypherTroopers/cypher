package relay

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cypherium/cypher/dex/protocol"
)

func TestAuthenticatedInboxHintBoundsFrontierDelayAndPreservesFairness(t *testing.T) {
	c, b, s := fixtureConfig(t)
	r := openFixture(t, c, b, s, filepath.Join(t.TempDir(), "relay"))
	defer r.Close()
	const oldCount = 48
	for i := uint64(1); i <= oldCount; i++ {
		if err := r.Enqueue(fixtureJob(Inbox, i)); err != nil {
			t.Fatal(err)
		}
	}
	frontier := fixtureJob(Inbox, 100)
	if err := r.Enqueue(frontier); err != nil {
		t.Fatal(err)
	}
	for _, lane := range []Lane{Anchor, Checkpoint, Claim} {
		if err := r.Enqueue(fixtureJob(lane, uint64(lane)+200)); err != nil {
			t.Fatal(err)
		}
	}
	b.observe = func(j Job, _ Attempt) (observation, error) {
		o := b.obs
		o.ready = j.ID == frontier.ID
		return o, nil
	}
	// The test simulates the private planner hint. Production creates it only
	// after authenticating the certified parent and the rolling inbox proof.
	for tick := 0; tick < 24; tick++ {
		r.prioritizeInbox(frontier.ID)
		if err := stepNow(r); err != nil {
			t.Fatal(err)
		}
		if tick == 3 && b.dexSent == 0 {
			t.Fatal("frontier delayed by old pending count")
		}
	}
	seenLanes := map[Lane]int{}
	old := map[protocol.Hash]bool{}
	for _, id := range b.seen {
		for _, record := range r.Status() {
			if record.Job.ID == id {
				seenLanes[record.Job.Lane]++
				if record.Job.Lane == Inbox && id != frontier.ID {
					old[id] = true
				}
			}
		}
	}
	for _, lane := range []Lane{Anchor, Checkpoint, Claim} {
		if seenLanes[lane] < 6 {
			t.Fatal("inbox hint starved another lane", lane, seenLanes)
		}
	}
	if len(old) < 3 {
		t.Fatal("priority reset ordinary cursor or starved old intent reconciliation", len(old))
	}
	for _, record := range r.Status() {
		if record.Phase == "complete" {
			t.Fatal("scheduling hint became economic completion")
		}
	}
	if len(r.Status()) != oldCount+4 {
		t.Fatal("old intents disappeared")
	}
	if len(b.sent) != 0 || s.calls != 0 {
		t.Fatal("waiting native jobs signed or sent")
	}
}

func TestInboxHintCannotBypassObservationLeaseOrColdRecovery(t *testing.T) {
	c, b, s := fixtureConfig(t)
	state := Leadership{View: 1, Active: true}
	dir := filepath.Join(t.TempDir(), "member")
	l := openLeaderFixture(t, c, b, s, dir, func(context.Context) (Leadership, error) { return state, nil })
	defer l.Close()
	job := fixtureJob(Inbox, 99)
	if err := l.Enqueue(job); err != nil {
		t.Fatal(err)
	}
	l.Journal().prioritizeInbox(job.ID)
	b.obs.verified = false
	if err := leaderStepNow(l, false); err == nil || b.dexSent != 0 {
		t.Fatal("hint authorized unverified observation", err)
	}
	b.obs.verified = true
	l.Journal().prioritizeInbox(job.ID)
	b.observe = func(Job, Attempt) (observation, error) {
		state.View++ // demotion after the proof; current-view send guard remains mandatory
		return b.obs, nil
	}
	if err := leaderStepNow(l, false); !errors.Is(err, ErrNotLeader) || b.dexSent != 0 {
		t.Fatal("hint bypassed leadership", err)
	}
	l.Close()
	b.observe = nil
	l = openLeaderFixture(t, c, b, s, dir, func(context.Context) (Leadership, error) { return state, nil })
	defer l.Close()
	if !l.Journal().inboxHintUntil.IsZero() || l.Journal().inboxHint != (protocol.Hash{}) || !l.PendingWork() {
		t.Fatal("ephemeral hint survived cold restart or intent lost")
	}
	l.Journal().prioritizeInbox(job.ID)
	l.Journal().inboxHintUntil = time.Now().Add(-time.Second)
	if err := leaderStepNow(l, false); err != nil || b.dexSent != 1 {
		t.Fatal("normal authenticated scheduling did not recover", err)
	}
}
