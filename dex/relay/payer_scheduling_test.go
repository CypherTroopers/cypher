package relay

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/dex/protocol"
)

// These tests use the package-private fake authenticated backend to measure
// scheduling opportunities, not cryptographic validity or network throughput.
func TestRelayPendingPayerSchedulingProgress(t *testing.T) {
	for _, cold := range []bool{false, true} {
		name := "running"
		if cold {
			name = "cold"
		}
		t.Run(name, func(t *testing.T) {
			c, b, signer := fixtureConfig(t)
			dir := filepath.Join(t.TempDir(), "relay")
			r := openFixture(t, c, b, signer, dir)
			pending := fixtureJob(Checkpoint, 1)
			if err := r.Enqueue(pending); err != nil {
				t.Fatal(err)
			}
			if err := stepNow(r); err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(r.Status()[0].Attempt.Raw)
			blocked := map[protocol.Hash]bool{}
			bad := fixtureJob(Checkpoint, 2)
			for id := uint64(2); id <= 13; id++ {
				j := fixtureJob(Checkpoint, id)
				blocked[j.ID] = true
				if err := r.Enqueue(j); err != nil {
					t.Fatal(err)
				}
			}
			independent := fixtureJob(Claim, 21)
			inbox := fixtureJob(Inbox, 22)
			for _, j := range []Job{independent, inbox} {
				if err := r.Enqueue(j); err != nil {
					t.Fatal(err)
				}
			}
			released := false
			b.observe = func(j Job, a Attempt) (observation, error) {
				o := b.obs
				switch j.ID {
				case pending.ID:
					o.completed = released
					if released {
						o.nonce = 1
					}
				case independent.ID:
					o.completed = a.Sends != 0
					if o.completed {
						o.nonce = 1
					}
				case inbox.ID:
					o.completed = a.Sends != 0
				case bad.ID:
					return observation{}, ErrInvalidJob
				default:
					o.nonce = 1
				}
				return o, nil
			}
			if cold {
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
				r = openFixture(t, c, b, signer, dir)
			}
			defer r.Close()
			b.seen = nil
			for i := 0; i < 8; i++ {
				if err := stepNow(r); err != nil {
					t.Fatal(err)
				}
			}
			seen := map[protocol.Hash]int{}
			for _, id := range b.seen {
				seen[id]++
				if blocked[id] {
					t.Fatal("unsigned same-payer sibling consumed Observe while nonce owner waited")
				}
			}
			if seen[pending.ID] < 2 || seen[independent.ID] == 0 || seen[inbox.ID] == 0 || b.dexSent != 1 || signer.calls != 2 {
				t.Fatal("pending nonce/independent payer/inbox did not progress", seen, b.dexSent, signer.calls)
			}
			if !bytes.Equal(original, r.Status()[0].Attempt.Raw) || r.Status()[0].Attempt.Sends < 2 {
				t.Fatal("pending owner's signed transaction was not retried exactly")
			}
			released = true
			for i := 0; i < 32; i++ {
				if err := stepNow(r); err != nil && !errors.Is(err, ErrInvalidJob) {
					t.Fatal(err)
				}
			}
			status := r.Status()
			if status[0].Phase != "complete" || status[1].Phase != "quarantined" || status[1].Attempt.GasLimit != 0 {
				t.Fatal("release or deferred invalid proof handling", status[0].Phase, status[1].Phase)
			}
			if signer.calls != 3 {
				t.Fatal("eligible sibling was not authenticated then signed", signer.calls)
			}
			for _, rec := range status[2:13] {
				if rec.Attempt.GasLimit != 0 && rec.Attempt.Nonce != 1 {
					t.Fatal("sibling reused pending nonce")
				}
			}
		})
	}
}

func TestRelayPendingPayerPreservesColdCompletionAndDependencies(t *testing.T) {
	c, b, signer := fixtureConfig(t)
	c.Payers[Claim] = c.Payers[Checkpoint]
	dir := filepath.Join(t.TempDir(), "relay")
	r := openFixture(t, c, b, signer, dir)
	old := fixtureJob(Claim, 1)
	b.obs.completed = true // Already completed externally, no local nonce reservation.
	if err := r.Enqueue(old); err != nil {
		t.Fatal(err)
	}
	if err := stepNow(r); err != nil {
		t.Fatal(err)
	}
	b.obs.completed = false
	pending := fixtureJob(Checkpoint, 2)
	if err := r.Enqueue(pending); err != nil {
		t.Fatal(err)
	}
	if err := stepNow(r); err != nil {
		t.Fatal(err)
	}
	sibling := fixtureJob(Checkpoint, 3)
	sibling.Dependencies = []protocol.Hash{old.ID}
	if err := r.Enqueue(sibling); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r = openFixture(t, c, b, signer, dir)
	defer r.Close()
	oldValid, released := false, false
	b.observe = func(j Job, _ Attempt) (observation, error) {
		o := b.obs
		if j.ID == old.ID {
			o.verified, o.completed = oldValid, true
		} else if j.ID == pending.ID {
			o.completed = released
		}
		if released {
			o.nonce = 1
		}
		return o, nil
	}
	b.seen = nil
	for i := 0; i < 6; i++ {
		_ = stepNow(r) // Invalid cold observation must not authorize completion.
	}
	oldSeen := false
	for _, id := range b.seen {
		oldSeen = oldSeen || id == old.ID
		if id == sibling.ID {
			t.Fatal("blocked sibling observed before nonce release")
		}
	}
	if !oldSeen || r.validated[old.ID] || r.dependenciesReady(sibling) || signer.calls != 1 {
		t.Fatal("cold completion was skipped or trusted without authentication")
	}
	released = true
	for i := 0; i < 8; i++ {
		_ = stepNow(r)
	}
	if r.Status()[1].Phase != "complete" || signer.calls != 1 || r.dependenciesReady(sibling) {
		t.Fatal("dependency lost after nonce release")
	}
	oldValid = true
	for i := 0; i < 8; i++ {
		if err := stepNow(r); err != nil {
			t.Fatal(err)
		}
	}
	if !r.validated[old.ID] || !r.dependenciesReady(sibling) || signer.calls != 2 || r.Status()[2].Attempt.Nonce != 1 {
		t.Fatal("authenticated cold dependency did not release eligible work")
	}
}

func TestRelayPendingPayerStillRequiresOwnerAuthentication(t *testing.T) {
	c, b, signer := fixtureConfig(t)
	c.Payers[Claim] = c.Payers[Checkpoint]
	r := openFixture(t, c, b, signer, filepath.Join(t.TempDir(), "relay"))
	defer r.Close()
	pending := fixtureJob(Checkpoint, 1)
	if err := r.Enqueue(pending); err != nil {
		t.Fatal(err)
	}
	if err := stepNow(r); err != nil {
		t.Fatal(err)
	}
	raw := bytes.Clone(r.Status()[0].Attempt.Raw)
	if err := r.Enqueue(fixtureJob(Claim, 2)); err != nil {
		t.Fatal(err)
	}
	for _, invalidJob := range []bool{false, true} {
		b.observe = func(j Job, _ Attempt) (observation, error) {
			if j.ID != pending.ID {
				t.Fatal("unauthenticated pending nonce was released")
			}
			if invalidJob {
				return observation{}, ErrInvalidJob
			}
			o := b.obs
			o.verified, o.completed, o.nonce = false, true, 1
			return o, nil
		}
		if err := stepNow(r); err == nil {
			t.Fatal("invalid pending-owner observation accepted")
		}
		if signer.calls != 1 || len(b.sent) != 1 || !bytes.Equal(raw, r.Status()[0].Attempt.Raw) {
			t.Fatal("authentication failure changed signed nonce or sent another job")
		}
	}
	if r.Status()[0].Phase != "quarantined" {
		t.Fatal("invalid owner proof not quarantined")
	}
	for i := 0; i < 4; i++ {
		if err := stepNow(r); err != nil {
			t.Fatal(err)
		}
	}
	if signer.calls != 1 || len(b.sent) != 1 {
		t.Fatal("quarantined reservation was automatically cancelled")
	}
}
