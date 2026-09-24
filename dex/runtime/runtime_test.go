package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testExecutor struct {
	execute func(context.Context, []byte) error
	closed  atomic.Int64
}

func (e *testExecutor) Execute(ctx context.Context, payload []byte) error {
	if e.execute != nil {
		return e.execute(ctx, payload)
	}
	return nil
}
func (e *testExecutor) Close() error { e.closed.Add(1); return nil }

// Seven registered identities are deterministic metadata, not seven independent
// operators. Authentication below is a closed devnet registry fixture.
func registeredFixture(index byte) (Config, RegistrationVerifier) {
	identity := Identity{ChainID: 9127001, Genesis: [32]byte{1}, DEX: [32]byte{2}, Epoch: 3, Committee: [32]byte{4}, VoteKey: [32]byte{index + 1}, RewardRecipient: [20]byte{index + 11}}
	config := Config{Enabled: true, Identity: identity, QueueItems: 2, QueueBytes: 16, MaxJobBytes: 8}
	verify := func(reg Registration, height uint64) error {
		if height != 100 || reg.ActivationHeight != 90 || reg.Identity != identity || index >= 7 {
			return ErrRegistration
		}
		return nil
	}
	return config, verify
}

// This trusted test adapter models an authenticated fixture manifest and local
// retained data. It is separate from the caller's availability assertion.
func fixtureSnapshotVerifier(identity Identity, snapshot Snapshot) error {
	if identity.ChainID != 9127001 || identity.Epoch != 3 || snapshot.Root != ([32]byte{8}) || snapshot.Height != 7 || !snapshot.DataAvailable {
		return errors.New("fixture manifest/root/height/data mismatch")
	}
	return nil
}

func eligibleRuntime(t *testing.T, executor Executor) *Runtime {
	t.Helper()
	config, verify := registeredFixture(0)
	r, err := New(config, func(Config) (Executor, error) { return executor, nil }, verify, fixtureSnapshotVerifier)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.BeginSync(); err != nil {
		t.Fatal(err)
	}
	if err := r.CompleteSync(Snapshot{Root: [32]byte{8}, Height: 7, DataAvailable: true}, Registration{config.Identity, 90}, 100); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := r.Stop(ctx); err != nil {
			t.Error(err)
		}
	})
	return r
}

func waitResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("worker completion timed out")
		return nil
	}
}

type liveRole struct {
	mu       sync.Mutex
	running  bool
	requests chan chan struct{}
	stop     chan struct{}
	done     chan struct{}
}

func (r *liveRole) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		return nil
	}
	r.running = true
	r.requests, r.stop, r.done = make(chan chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(r.done)
		for {
			select {
			case done := <-r.requests:
				close(done)
			case <-r.stop:
				return
			}
		}
	}()
	return nil
}
func (r *liveRole) Stop(ctx context.Context) error {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return nil
	}
	r.running = false
	close(r.stop)
	done := r.done
	r.mu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (r *liveRole) progressing(t *testing.T, want bool) {
	t.Helper()
	r.mu.Lock()
	running, requests := r.running, r.requests
	r.mu.Unlock()
	if running != want {
		t.Fatalf("role running=%v want %v", running, want)
	}
	if !want {
		return
	}
	ack := make(chan struct{})
	select {
	case requests <- ack:
	case <-time.After(3 * time.Second):
		t.Fatal("role enqueue stalled")
	}
	select {
	case <-ack:
	case <-time.After(3 * time.Second):
		t.Fatal("role execution stalled")
	}
}

func TestAllEightRoleCombinationsWithLiveWorkers(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		t.Run(fmt.Sprintf("pow_%t_rpc_%t_dex_%t", mask&1 != 0, mask&2 != 0, mask&4 != 0), func(t *testing.T) {
			pow, rpc := new(liveRole), new(liveRole)
			executor := new(testExecutor)
			var dex *Runtime
			if mask&4 != 0 {
				dex = eligibleRuntime(t, executor)
			} else {
				var err error
				dex, err = New(Config{}, func(Config) (Executor, error) { t.Fatal("disabled factory called"); return nil, nil }, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			roles := NewCoordinator(pow, rpc, dex)
			ctx := context.Background()
			for role := PoW; role <= DEX; role++ {
				if mask&(1<<role) != 0 {
					if err := roles.Start(ctx, role); err != nil {
						t.Fatal(err)
					}
				}
			}
			check := func(remaining int) {
				pow.progressing(t, remaining&1 != 0)
				rpc.progressing(t, remaining&2 != 0)
				if remaining&4 != 0 {
					done, err := dex.Submit([]byte("action"))
					if err != nil {
						t.Fatal(err)
					}
					if err := waitResult(t, done); err != nil {
						t.Fatal(err)
					}
				} else if dex.Stats().State == Active {
					t.Fatal("DEX unexpectedly active")
				}
			}
			check(mask)
			// Stop DEX, then RPC, then PoW; every remaining worker must progress.
			remaining := mask
			for _, role := range []Role{DEX, RPC, PoW} {
				if err := roles.Stop(ctx, role); err != nil {
					t.Fatal(err)
				}
				remaining &^= 1 << role
				check(remaining)
			}
			if mask&4 == 0 && dex.Stats().QueueCapacity != 0 {
				t.Fatal("disabled DEX allocated queue")
			}
		})
	}
}

func TestDisabledCreatesNoDEXResources(t *testing.T) {
	var calls atomic.Int64
	r, err := New(Config{}, func(Config) (Executor, error) { calls.Add(1); return nil, nil }, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(r.BeginSync(), ErrTransition) || !errors.Is(r.Start(context.Background()), ErrTransition) {
		t.Fatal("disabled runtime started")
	}
	if _, err := r.Submit(nil); !errors.Is(err, ErrInactive) {
		t.Fatal(err)
	}
	if err := r.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || r.Stats().QueueCapacity != 0 || r.Stats().State != Disabled {
		t.Fatal("disabled runtime created resources")
	}
}

func TestRegistrationDataAndImmutableConfiguration(t *testing.T) {
	for index := byte(0); index < 7; index++ {
		config, verify := registeredFixture(index)
		original := config
		r, err := New(config, func(Config) (Executor, error) { return new(testExecutor), nil }, verify, fixtureSnapshotVerifier)
		if err != nil {
			t.Fatal(err)
		}
		config.Identity.RewardRecipient[0]++
		returned := r.Config()
		returned.Identity.VoteKey[0]++
		if r.Config() != original {
			t.Fatal("configuration is not immutable")
		}
		if !errors.Is(r.Start(context.Background()), ErrTransition) {
			t.Fatal("flag granted eligibility")
		}
		if err := r.BeginSync(); err != nil {
			t.Fatal(err)
		}
		good := Registration{original.Identity, 90}
		if !errors.Is(r.CompleteSync(Snapshot{}, good, 100), ErrDataUnavailable) {
			t.Fatal("missing data accepted")
		}
		snapshot := Snapshot{Root: [32]byte{8}, Height: 7, DataAvailable: true}
		wrong := good
		wrong.Identity.Epoch++
		if !errors.Is(r.CompleteSync(snapshot, wrong, 100), ErrRegistration) {
			t.Fatal("foreign epoch accepted")
		}
		wrong = good
		wrong.ActivationHeight = 101
		if !errors.Is(r.CompleteSync(snapshot, wrong, 100), ErrRegistration) {
			t.Fatal("future activation accepted")
		}
		if r.CompleteSync(snapshot, good, 99) == nil {
			t.Fatal("unauthenticated CLX height accepted")
		}
		wrongSnapshot := snapshot
		wrongSnapshot.Root[0]++
		if err := r.CompleteSync(wrongSnapshot, good, 100); !errors.Is(err, ErrSnapshotAuthentication) {
			t.Fatal("self-asserted data availability bypassed authenticated root", err)
		}
		wrongSnapshot = snapshot
		wrongSnapshot.Height++
		if err := r.CompleteSync(wrongSnapshot, good, 100); !errors.Is(err, ErrSnapshotAuthentication) {
			t.Fatal("unauthenticated snapshot height accepted", err)
		}
		if r.Stats().State != Syncing {
			t.Fatal("rejected snapshot made node eligible")
		}
		if err := r.CompleteSync(snapshot, good, 100); err != nil {
			t.Fatal(err)
		}
		if err := r.Stop(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	config, _ := registeredFixture(0)
	if _, err := New(config, func(Config) (Executor, error) { return new(testExecutor), nil }, nil, nil); err == nil {
		t.Fatal("nil verifier accepted")
	}
	config, verify := registeredFixture(0)
	if _, err := New(config, func(Config) (Executor, error) { return new(testExecutor), nil }, verify, nil); err == nil {
		t.Fatal("nil snapshot verifier accepted")
	}
	config.Identity.Epoch = 0
	if _, err := New(config, func(Config) (Executor, error) { return new(testExecutor), nil }, verify, fixtureSnapshotVerifier); err == nil {
		t.Fatal("zero epoch accepted")
	}
}

func TestQueueSaturationAndCrashDoNotStopOtherRoles(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	executor := &testExecutor{execute: func(ctx context.Context, payload []byte) error {
		close(started)
		select {
		case <-release:
			panic("devnet injected DEX failure")
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	dex := eligibleRuntime(t, executor)
	pow, rpc := new(liveRole), new(liveRole)
	roles := NewCoordinator(pow, rpc, dex)
	for _, role := range []Role{PoW, RPC, DEX} {
		if err := roles.Start(context.Background(), role); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = pow.Stop(context.Background()); _ = rpc.Stop(context.Background()) })
	first, err := dex.Submit([]byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("executor did not start")
	}
	second, err := dex.Submit([]byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	third, err := dex.Submit([]byte("third"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dex.Submit([]byte("fourth")); !errors.Is(err, ErrQueueFull) {
		t.Fatal(err)
	}
	pow.progressing(t, true)
	rpc.progressing(t, true)
	close(release)
	if err := waitResult(t, first); !errors.Is(err, ErrWorkerCrashed) {
		t.Fatal(err)
	}
	for _, done := range []<-chan error{second, third} {
		if err := waitResult(t, done); !errors.Is(err, ErrInactive) {
			t.Fatal(err)
		}
	}
	if err := dex.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(dex.Stats().LastError, ErrWorkerCrashed) || executor.closed.Load() != 1 {
		t.Fatal("crash did not close DEX resources exactly once")
	}
	pow.progressing(t, true)
	rpc.progressing(t, true)
}

func TestStopDeadlinePreservesLeavingAndOtherRoles(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	executor := &testExecutor{execute: func(context.Context, []byte) error { close(started); <-release; return nil }}
	dex := eligibleRuntime(t, executor)
	rpc := new(liveRole)
	roles := NewCoordinator(nil, rpc, dex)
	if err := roles.Start(context.Background(), RPC); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rpc.Stop(context.Background()) })
	if err := roles.Start(context.Background(), DEX); err != nil {
		t.Fatal(err)
	}
	done, err := dex.Submit([]byte("action"))
	if err != nil {
		t.Fatal(err)
	}
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := roles.Stop(ctx, DEX); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if dex.Stats().State != Leaving {
		t.Fatal("uncooperative worker considered stopped")
	}
	rpc.progressing(t, true)
	close(release)
	if err := waitResult(t, done); err != nil {
		t.Fatal(err)
	}
	if err := dex.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestStopWhileFactoryOpeningWaitsForCleanup(t *testing.T) {
	config, verify := registeredFixture(0)
	entered, release := make(chan struct{}), make(chan struct{})
	executor := new(testExecutor)
	r, err := New(config, func(Config) (Executor, error) { close(entered); <-release; return executor, nil }, verify, fixtureSnapshotVerifier)
	if err != nil {
		t.Fatal(err)
	}
	opening := make(chan error, 1)
	go func() { opening <- r.BeginSync() }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Stop(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if r.Stats().State != Leaving {
		t.Fatal("open resource was considered closed")
	}
	close(release)
	if err := waitResult(t, opening); !errors.Is(err, ErrTransition) {
		t.Fatal(err)
	}
	if err := r.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if executor.closed.Load() != 1 {
		t.Fatal("late factory resource leaked")
	}
}

func TestAdmissionCopiesPayloadAndBoundsQueuedBytes(t *testing.T) {
	config, verify := registeredFixture(0)
	config.QueueItems, config.QueueBytes, config.MaxJobBytes = 3, 8, 8
	entered, release := make(chan struct{}), make(chan struct{})
	observed := make(chan string, 3)
	executor := &testExecutor{execute: func(ctx context.Context, payload []byte) error {
		if string(payload) == "block" {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		observed <- string(payload)
		return nil
	}}
	r, err := New(config, func(Config) (Executor, error) { return executor, nil }, verify, fixtureSnapshotVerifier)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.BeginSync(); err != nil {
		t.Fatal(err)
	}
	if err := r.CompleteSync(Snapshot{Root: [32]byte{8}, Height: 7, DataAvailable: true}, Registration{config.Identity, 90}, 100); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Stop(context.Background()) })
	first, err := r.Submit([]byte("block"))
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	payload := []byte("original")
	second, err := r.Submit(payload)
	if err != nil {
		t.Fatal(err)
	}
	copy(payload, "tampered")
	if _, err := r.Submit([]byte("x")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("byte saturation: %v", err)
	}
	if _, err := r.Submit(make([]byte, 9)); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("payload bound: %v", err)
	}
	close(release)
	for _, done := range []<-chan error{first, second} {
		if err := waitResult(t, done); err != nil {
			t.Fatal(err)
		}
	}
	if got := <-observed; got != "block" {
		t.Fatal(got)
	}
	if got := <-observed; got != "original" {
		t.Fatalf("request alias changed admitted payload: %q", got)
	}
	if err := r.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.Stats().QueuedBytes != 0 {
		t.Fatal("queue budget leaked")
	}
}
