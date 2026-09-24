// Package runtime owns an optional, isolated DEX worker lifecycle. It does not
// grant consensus authority or change existing CLX, PoW, or RPC lifecycles.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

type State string

const (
	Disabled   State = "disabled"
	Configured State = "configured"
	Syncing    State = "syncing"
	Eligible   State = "eligible"
	Active     State = "active"
	Leaving    State = "leaving"
	Inactive   State = "inactive"
)

var (
	ErrTransition             = errors.New("invalid DEX lifecycle transition")
	ErrRegistration           = errors.New("DEX registration does not match configuration")
	ErrDataUnavailable        = errors.New("DEX snapshot data unavailable")
	ErrSnapshotAuthentication = errors.New("DEX snapshot authentication failed")
	ErrQueueFull              = errors.New("DEX queue capacity exhausted")
	ErrPayloadTooLarge        = errors.New("DEX request exceeds byte limit")
	ErrInactive               = errors.New("DEX worker is not active")
	ErrWorkerCrashed          = errors.New("DEX worker panicked")
)

// Identity deliberately has no CLX membership, PoW coinbase, RPC signer, or
// spending secret. Fixed arrays make configuration snapshots independent values.
type Identity struct {
	ChainID         uint64
	Genesis         [32]byte
	DEX             [32]byte
	Epoch           uint64
	Committee       [32]byte
	VoteKey         [32]byte // Registered fingerprint, not a raw 64-byte BLS public key.
	RewardRecipient [20]byte
}

type Config struct {
	Enabled     bool
	Identity    Identity
	QueueItems  int
	QueueBytes  int
	MaxJobBytes int
}

type Registration struct {
	Identity         Identity
	ActivationHeight uint64
}

type Snapshot struct {
	Root          [32]byte
	Height        uint64
	DataAvailable bool
}

// RegistrationVerifier must authenticate the registry and CLX height against
// trusted state. A caller-controlled "authenticated" flag is not sufficient.
// The runtime is fail-closed when this adapter is absent.
type RegistrationVerifier func(Registration, uint64) error

// SnapshotVerifier must authenticate the root/height against trusted finalized
// DEX state and check that required data has actually been retrieved. An API
// caller's DataAvailable flag alone must never authorize participation.
type SnapshotVerifier func(Identity, Snapshot) error

// Executor owns DEX-only storage. Close must release its resources. Execute must
// honor cancellation for Stop to finish; an uncooperative executor cannot stop
// any other role, and leaves this runtime in Leaving until it returns.
type Executor interface {
	Execute(context.Context, []byte) error
	Close() error
}

type Factory func(Config) (Executor, error)

type job struct {
	payload []byte
	done    chan error
}

type Stats struct {
	State         State
	QueueCapacity int
	QueuedItems   int
	QueuedBytes   int
	Completed     uint64
	LastError     error
}

type Runtime struct {
	mu             sync.Mutex
	config         Config
	state          State
	factory        Factory
	verify         RegistrationVerifier
	verifySnapshot SnapshotVerifier
	executor       Executor
	opening        bool
	queue          chan job
	queuedBytes    int
	completed      uint64
	cancel         context.CancelFunc
	done           chan struct{}
	lastError      error
}

func New(config Config, factory Factory, verify RegistrationVerifier, verifySnapshot SnapshotVerifier) (*Runtime, error) {
	r := &Runtime{config: config, state: Disabled, factory: factory, verify: verify, verifySnapshot: verifySnapshot}
	if !config.Enabled {
		return r, nil
	}
	i := config.Identity
	if i.ChainID == 0 || i.Genesis == ([32]byte{}) || i.DEX == ([32]byte{}) || i.Epoch == 0 || i.Committee == ([32]byte{}) || i.VoteKey == ([32]byte{}) || i.RewardRecipient == ([20]byte{}) {
		return nil, errors.New("incomplete DEX identity")
	}
	if factory == nil || verify == nil || verifySnapshot == nil || config.QueueItems < 1 || config.QueueItems > 65536 || config.MaxJobBytes < 1 || config.MaxJobBytes > 1024*1024 || config.QueueBytes < config.MaxJobBytes || config.QueueBytes > 64*1024*1024 {
		return nil, errors.New("invalid DEX factory, verifier, or queue limits")
	}
	r.state = Configured
	return r, nil
}

func (r *Runtime) Config() Config { return r.config }

// BeginSync is the first operation allowed to open DEX-specific resources.
func (r *Runtime) BeginSync() error {
	r.mu.Lock()
	if r.state != Configured {
		r.mu.Unlock()
		return ErrTransition
	}
	r.state = Syncing
	r.opening = true
	r.done = make(chan struct{})
	r.mu.Unlock()
	executor, err := openExecutor(r.factory, r.config)
	if executor == nil && err == nil {
		err = errors.New("DEX factory returned nil executor")
	}
	r.mu.Lock()
	r.opening = false
	r.executor = executor
	if err != nil {
		r.state = Leaving
		r.mu.Unlock()
		r.finish(err)
		return err
	}
	if r.state != Syncing {
		r.mu.Unlock()
		r.finish(nil)
		return ErrTransition
	}
	r.mu.Unlock()
	return nil
}

func (r *Runtime) CompleteSync(snapshot Snapshot, registration Registration, authenticatedCLXHeight uint64) error {
	r.mu.Lock()
	ready := r.state == Syncing && r.executor != nil
	r.mu.Unlock()
	if !ready {
		return ErrTransition
	}
	if !snapshot.DataAvailable || snapshot.Root == ([32]byte{}) {
		return ErrDataUnavailable
	}
	if registration.Identity != r.config.Identity || registration.ActivationHeight > authenticatedCLXHeight {
		return ErrRegistration
	}
	if err := r.verify(registration, authenticatedCLXHeight); err != nil {
		return fmt.Errorf("authenticate DEX registry: %w", err)
	}
	if err := r.verifySnapshot(r.config.Identity, snapshot); err != nil {
		return fmt.Errorf("%w: %w", ErrSnapshotAuthentication, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != Syncing {
		return ErrTransition
	}
	r.state = Eligible
	return nil
}

func (r *Runtime) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == Active {
		return nil
	}
	if r.state != Eligible {
		return ErrTransition
	}
	workerCtx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.queue = make(chan job, r.config.QueueItems)
	r.state = Active
	go r.run(workerCtx)
	return nil
}

// Submit acknowledges local bounded ingress only. Its completion is an executor
// result, not a claim of DEX finality, CLX settlement, or withdrawal completion.
func (r *Runtime) Submit(payload []byte) (<-chan error, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != Active {
		return nil, ErrInactive
	}
	if len(payload) > r.config.MaxJobBytes {
		return nil, ErrPayloadTooLarge
	}
	if len(r.queue) == cap(r.queue) || len(payload) > r.config.QueueBytes-r.queuedBytes {
		return nil, ErrQueueFull
	}
	j := job{payload: append([]byte(nil), payload...), done: make(chan error, 1)}
	r.queue <- j
	r.queuedBytes += len(payload)
	return j.done, nil
}

func (r *Runtime) run(ctx context.Context) {
	var current *job
	var failure error
	defer func() {
		if recover() != nil {
			failure = ErrWorkerCrashed
			if current != nil {
				current.done <- failure
			}
		}
		r.finish(failure)
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-r.queue:
			r.mu.Lock()
			r.queuedBytes -= len(j.payload)
			r.mu.Unlock()
			current = &j
			if ctx.Err() != nil {
				j.done <- ErrInactive
				current = nil
				return
			}
			err := r.executor.Execute(ctx, j.payload)
			j.done <- err
			current = nil
			r.mu.Lock()
			r.completed++
			r.mu.Unlock()
		}
	}
}

func (r *Runtime) finish(failure error) {
	r.mu.Lock()
	r.state = Leaving
	if r.cancel != nil {
		r.cancel()
	}
	for r.queue != nil && len(r.queue) != 0 {
		j := <-r.queue
		r.queuedBytes -= len(j.payload)
		j.done <- ErrInactive
	}
	executor := r.executor
	r.mu.Unlock()
	if executor != nil {
		if err := closeExecutor(executor); failure == nil {
			failure = err
		}
	}
	r.mu.Lock()
	r.lastError = failure
	r.executor = nil
	r.state = Inactive
	close(r.done)
	r.mu.Unlock()
}

func (r *Runtime) Stop(ctx context.Context) error {
	r.mu.Lock()
	if r.state == Disabled || r.state == Inactive {
		r.mu.Unlock()
		return nil
	}
	if r.state != Leaving {
		wasActive := r.state == Active
		r.state = Leaving
		if r.cancel != nil {
			r.cancel()
		}
		if !wasActive && !r.opening {
			if r.done == nil {
				r.done = make(chan struct{})
			}
			go r.finish(nil)
		}
	}
	done := r.done
	r.mu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func openExecutor(factory Factory, config Config) (executor Executor, err error) {
	defer func() {
		if recover() != nil {
			err = ErrWorkerCrashed
		}
	}()
	return factory(config)
}

func closeExecutor(executor Executor) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrWorkerCrashed
		}
	}()
	return executor.Close()
}

func (r *Runtime) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Stats{r.state, cap(r.queue), len(r.queue), r.queuedBytes, r.completed, r.lastError}
}
