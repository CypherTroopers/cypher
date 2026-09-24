package relay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/rlp"
)

func openLeaderFixture(t *testing.T, c Config, b *testBackend, s *testSigner, dir string, check LeadershipCheck) *LeaderRelay {
	t.Helper()
	b.dir, s.dir = dir, dir
	l, err := OpenLeader(dir, c, b, s, check)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func leaderStepNow(l *LeaderRelay, reconcile bool) error {
	r := l.Journal()
	r.mu.Lock()
	r.nextTry = map[protocol.Hash]time.Time{}
	r.mu.Unlock()
	if reconcile {
		return l.Reconcile(context.Background())
	}
	return l.Step(context.Background())
}

func TestLeaderStandbyNeverReservesSignsOrSends(t *testing.T) {
	c, b, s := fixtureConfig(t)
	at := Leadership{View: 12}
	dir := filepath.Join(t.TempDir(), "member")
	l := openLeaderFixture(t, c, b, s, dir, func(context.Context) (Leadership, error) { return at, nil })
	defer l.Close()
	for _, lane := range []Lane{Checkpoint, Inbox} {
		if err := l.Enqueue(fixtureJob(lane, uint64(lane))); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.ReadFile(filepath.Join(dir, "state.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := leaderStepNow(l, false); !errors.Is(err, ErrNotLeader) {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "state.bin"))
	if err != nil || !bytes.Equal(before, after) || len(b.seen) != 0 {
		t.Fatal("standby submission touched journal or observed", err)
	}
	for range 4 {
		if err := leaderStepNow(l, true); err != nil {
			t.Fatal(err)
		}
	}
	for _, record := range l.Status() {
		if record.Attempt.GasLimit != 0 || record.Attempt.Sends != 0 {
			t.Fatal("standby reserved nonce or attempted send")
		}
	}
	if s.calls != 0 || len(b.sent) != 0 || b.dexSent != 0 || !l.PendingWork() {
		t.Fatal("standby authorization", s.calls, len(b.sent), b.dexSent)
	}
	b.obs.completed = true
	for range 4 {
		if err := leaderStepNow(l, true); err != nil {
			t.Fatal(err)
		}
	}
	if l.PendingWork() {
		t.Fatal("authenticated external completion left false pending work")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l = openLeaderFixture(t, c, b, s, dir, func(context.Context) (Leadership, error) { return at, nil })
	defer l.Close()
	if !l.PendingWork() {
		t.Fatal("cold completion label trusted without proof")
	}
	for range 4 {
		if err := leaderStepNow(l, true); err != nil {
			t.Fatal(err)
		}
	}
	if l.PendingWork() {
		t.Fatal("cold authenticated reconcile failed")
	}
}

func TestLeaderRechecksRoleAtSigningAndSendingBoundaries(t *testing.T) {
	for _, boundary := range []string{"after_proof", "after_prepared", "after_signed", "before_send"} {
		for _, nextActive := range []bool{false, true} {
			t.Run(boundary+map[bool]string{false: "/demoted", true: "/new-local-view"}[nextActive], func(t *testing.T) {
				c, b, s := fixtureConfig(t)
				at := Leadership{View: 10, Active: true}
				c.Hook = func(stage string) error {
					if stage == boundary {
						at.View++
						at.Active = nextActive
					}
					return nil
				}
				l := openLeaderFixture(t, c, b, s, filepath.Join(t.TempDir(), "member"), func(context.Context) (Leadership, error) { return at, nil })
				defer l.Close()
				if err := l.Enqueue(fixtureJob(Checkpoint, 1)); err != nil {
					t.Fatal(err)
				}
				if err := leaderStepNow(l, false); !errors.Is(err, ErrNotLeader) {
					t.Fatal("missing leadership boundary", err)
				}
				wantSigns := 0
				if boundary == "after_signed" || boundary == "before_send" {
					wantSigns = 1
				}
				if len(b.sent) != 0 || s.calls != wantSigns {
					t.Fatal("stale-view side effect", s.calls, len(b.sent))
				}
			})
		}
	}
}

func TestLeaderJournalCannotBypassGuardAndInboxIsGated(t *testing.T) {
	for _, lane := range []Lane{Checkpoint, Inbox} {
		c, b, s := fixtureConfig(t)
		at := Leadership{View: 1, Active: true}
		l := openLeaderFixture(t, c, b, s, filepath.Join(t.TempDir(), "member"), func(context.Context) (Leadership, error) { return at, nil })
		defer l.Close()
		if err := l.Enqueue(fixtureJob(lane, 1)); err != nil {
			t.Fatal(err)
		}
		if err := stepNow(l.Journal()); !errors.Is(err, ErrNotLeader) {
			t.Fatal("unguarded journal Step authorized send", lane, err)
		}
		if s.calls != 0 || len(b.sent) != 0 || b.dexSent != 0 {
			t.Fatal("unguarded side effect")
		}
		if err := leaderStepNow(l, false); err != nil {
			t.Fatal(err)
		}
		if lane == Inbox && b.dexSent != 1 || lane == Checkpoint && len(b.sent) != 1 {
			t.Fatal("current leader unable to submit")
		}
	}
}

func TestLeaderReconcileDoesNotStarveImmediateSubmission(t *testing.T) {
	c, b, s := fixtureConfig(t)
	l := openLeaderFixture(t, c, b, s, filepath.Join(t.TempDir(), "member"), func(context.Context) (Leadership, error) {
		return Leadership{View: 1, Active: true}, nil
	})
	defer l.Close()
	if err := l.Enqueue(fixtureJob(Checkpoint, 1)); err != nil {
		t.Fatal(err)
	}
	if err := l.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := l.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.calls != 1 || len(b.sent) != 1 {
		t.Fatal("read-only reconciliation starved pending leader submission")
	}
}

type blockedLeaderBackend struct {
	*testBackend
	entered chan struct{}
}

func (b *blockedLeaderBackend) Observe(ctx context.Context, _ Job, _ Attempt) (observation, error) {
	close(b.entered)
	<-ctx.Done()
	return observation{}, ctx.Err()
}

func TestLeaderLeaseLossCancelsInFlightObservation(t *testing.T) {
	c, b, s := fixtureConfig(t)
	dir := filepath.Join(t.TempDir(), "member")
	b.dir, s.dir = dir, dir
	done := make(chan struct{})
	bk := &blockedLeaderBackend{testBackend: b, entered: make(chan struct{})}
	l, err := OpenLeader(dir, c, bk, s, func(context.Context) (Leadership, error) {
		return Leadership{View: 1, Active: true, Done: done}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Enqueue(fixtureJob(Checkpoint, 1)); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- l.Step(context.Background()) }()
	select {
	case <-bk.entered:
	case <-time.After(time.Second):
		t.Fatal("observation did not start")
	}
	close(done)
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("lost leadership did not cancel")
	}
	if s.calls != 0 || len(b.sent) != 0 {
		t.Fatal("canceled worker submitted")
	}
}

func TestLeaderHandoffUsesOwnNonceAndRetainsPredecessorSignedAttempt(t *testing.T) {
	// This package-local ledger is a scheduling fixture, not a LIVE/native-state
	// acceptance claim. The network/settlement suites separately verify proofs
	// and on-chain business idempotence.
	active, view := 0, uint64(1)
	completed, payments := false, 0
	var nodes [2]*LeaderRelay
	var backends [2]*testBackend
	var signers [2]*testSigner
	var configs [2]Config
	var dirs [2]string
	for member := range nodes {
		c, b, s := fixtureConfig(t)
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		payer := crypto.PubkeyToAddress(key.PublicKey)
		s.keys = map[common.Address]*ecdsa.PrivateKey{payer: key}
		for _, lane := range []Lane{Anchor, Checkpoint, Claim} {
			c.Payers[lane] = payer
		}
		b.obs.nonce = uint64(20 + member*30)
		b.observe = func(_ Job, _ Attempt) (observation, error) {
			obs := b.obs
			obs.completed = completed
			return obs, nil
		}
		b.onSend = func() error {
			if !completed {
				completed = true
				payments++
			}
			b.obs.nonce++
			return nil
		}
		if member == 0 {
			c.Hook = func(stage string) error {
				if stage == "after_signed" {
					active, view = 1, 2
				}
				return nil
			}
		}
		dirs[member] = filepath.Join(t.TempDir(), "member")
		configs[member], backends[member], signers[member] = c, b, s
		nodes[member] = openLeaderFixture(t, c, b, s, dirs[member], func(context.Context) (Leadership, error) {
			return Leadership{View: view, Active: active == member}, nil
		})
		defer nodes[member].Close()
		if err := nodes[member].Enqueue(fixtureJob(Claim, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := leaderStepNow(nodes[0], false); !errors.Is(err, ErrNotLeader) {
		t.Fatal(err)
	}
	old := nodes[0].Status()[0].Attempt
	if len(old.Raw) == 0 || old.Nonce != 20 || len(backends[0].sent) != 0 {
		t.Fatal("old signed attempt was not retained")
	}
	if err := leaderStepNow(nodes[1], false); err != nil {
		t.Fatal(err)
	}
	if nodes[1].Status()[0].Attempt.Nonce != 50 || payments != 1 {
		t.Fatal("successor used predecessor nonce or failed business")
	}
	if err := leaderStepNow(nodes[0], true); err != nil {
		t.Fatal(err)
	}
	if nodes[0].PendingWork() || nodes[0].Status()[0].Phase != "completed_pending_nonce" {
		t.Fatal("predecessor incorrectly discarded nonce or kept business pending")
	}
	if err := nodes[0].Close(); err != nil {
		t.Fatal(err)
	}
	configs[0].Hook = nil
	nodes[0] = openLeaderFixture(t, configs[0], backends[0], signers[0], dirs[0], func(context.Context) (Leadership, error) {
		return Leadership{View: view, Active: active == 0}, nil
	})
	defer nodes[0].Close()
	if err := leaderStepNow(nodes[0], false); !errors.Is(err, ErrNotLeader) || len(backends[0].sent) != 0 {
		t.Fatal("cold standby sent old transaction", err)
	}
	active, view = 0, 3
	if err := leaderStepNow(nodes[0], false); err != nil {
		t.Fatal(err)
	}
	if len(backends[0].sent) != 1 || !bytes.Equal(backends[0].sent[0], old.Raw) || payments != 1 {
		t.Fatal("pending own nonce not exact-retried or business duplicated")
	}
	if err := leaderStepNow(nodes[0], true); err != nil {
		t.Fatal(err)
	}
	if nodes[0].Status()[0].Phase != "complete" {
		t.Fatal("authenticated own nonce not completed")
	}
	var first, second types.Transaction
	if rlp.DecodeBytes(old.Raw, &first) != nil || rlp.DecodeBytes(backends[1].sent[0], &second) != nil {
		t.Fatal("signed transaction decode")
	}
	signer := types.NewEIP155Signer(new(big.Int).SetUint64(configs[0].Domain.ChainID))
	a, _ := types.Sender(signer, &first)
	b, _ := types.Sender(signer, &second)
	if a == b || first.Nonce() == second.Nonce() {
		t.Fatal("member gas identities or nonce histories shared")
	}
}
