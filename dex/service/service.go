// Package service owns one serialized DEX consensus actor in a separate process.
// Transport goroutines never call BLS, execution, or consensus directly.
package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/cypherium/cypher/dex/instrumentation"
	"net/url"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/transport"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

type Config struct {
	Consensus consensus.Config
	Transport transport.Config
	// OnAction must authenticate and durably admit the exact signed action before
	// returning nil. It runs only on the actor. nil disables all action ingress.
	OnAction     func([]byte) error
	OnPeerAction func(peer uint8, payload []byte) error
	OnExtension  func(peer uint8, payload []byte) error
	ActorInit    func(*consensus.Application) error
	ActorTick    func(*consensus.Application) error
	// TimeoutReady is a local scheduling policy, not a proposal-validity rule.
	// A false result suppresses new timeout votes while authenticated ingress is
	// idle. Existing QCs, TCs and messages are still processed normally. nil
	// retains the unconditional timeout policy used by earlier configurations.
	TimeoutReady func(*consensus.Application) (bool, error)
	Query        func(*consensus.Application, string, url.Values) (interface{}, error)
	IngressStage func(protocol.Hash) (string, string)
	OnClose      func() error
	// DeliveryFilter is an optional isolated-test fault injector. It runs on the
	// actor after TLS/domain checks and before normal proof validation. Returning
	// transport.ErrBusy models a dropped connection/retry, never valid execution.
	DeliveryFilter        func(peer uint8, kind uint8, payload []byte) error
	APIListen             string
	BootstrapSnapshotFile string
	Timeout               time.Duration
	// SubmissionTimeout bounds failover when only CLX submission work remains.
	// It gives sparse market ingress and bounded proof construction time to
	// finish without forcing a TC between otherwise consecutive DEX proposals.
	// Executable ingress still uses Timeout. Neither timer changes validity.
	SubmissionTimeout time.Duration
}
type request struct {
	ctx    context.Context
	call   func(*consensus.Application) error
	result chan error
}
type Status struct {
	State                  string
	Certified, Finalized   uint64
	PendingTransport       int
	PendingTransportByPeer [7]int
	Error                  string
	Execution              instrumentation.ExecutionStats
	Storage                consensus.StorageStatus
	Leadership             consensus.Leadership
	SubmissionPending      bool
}
type Service struct {
	config            Config
	app               *consensus.Application
	net               *transport.Transport
	queue             chan request
	ctx               context.Context
	cancel            context.CancelFunc
	wg                sync.WaitGroup
	mu                sync.Mutex
	started, closed   bool
	failure           error
	api               *apiServer
	submissionPending atomic.Bool
	// Only the consensus actor reads/writes these fields. Workers receive an
	// immutable channel that closes as soon as that actor leaves its view.
	leadershipView uint64
	leadershipDone chan struct{}
}

func Open(c Config) (*Service, error) {
	if len(c.Transport.Peers) != 7 || len(c.Consensus.Members) != 7 || c.Consensus.Index != int(c.Transport.Index) || c.Consensus.Domain != c.Transport.Domain {
		return nil, errors.New("service registration/domain mismatch")
	}
	for i, m := range c.Consensus.Members {
		p := c.Transport.Peers[i]
		if m == nil || m.Address != p.ID || m.Public != p.BLSPublic {
			return nil, errors.New("TLS and FHS registered identity mismatch")
		}
	}
	if c.Timeout == 0 {
		c.Timeout = time.Second
	}
	if c.Timeout < 100*time.Millisecond || c.Timeout > 30*time.Second {
		return nil, errors.New("bounded FHS timeout required")
	}
	if c.SubmissionTimeout == 0 {
		c.SubmissionTimeout = max(c.Timeout, 15*time.Second)
	}
	if c.SubmissionTimeout < c.Timeout || c.SubmissionTimeout > 30*time.Second {
		return nil, errors.New("submission timeout must be between FHS timeout and 30 seconds")
	}
	if c.APIListen != "" {
		if err := transport.ValidateLoopback(c.APIListen, false); err != nil {
			return nil, err
		}
	}
	app, err := consensus.Open(c.Consensus)
	if err != nil {
		return nil, err
	}
	if c.BootstrapSnapshotFile != "" {
		if !filepath.IsAbs(c.BootstrapSnapshotFile) {
			app.Close()
			return nil, errors.New("absolute bootstrap snapshot path required")
		}
		raw, err := regularRead(c.BootstrapSnapshotFile, consensus.MaxSnapshotBytes, false)
		if err == nil {
			err = app.BootstrapSnapshot(raw)
		}
		if err != nil {
			app.Close()
			return nil, fmt.Errorf("DEX bootstrap snapshot rejected before transport/signing: %w", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{config: c, app: app, queue: make(chan request, 128), ctx: ctx, cancel: cancel}
	n, err := transport.Open(c.Transport, s.receive)
	if err != nil {
		app.Close()
		cancel()
		return nil, err
	}
	s.net = n
	app.SetTransport(func(to string, m *hotstuff.HotstuffMessage) error {
		b, err := rlp.EncodeToBytes(m)
		if err != nil {
			return err
		}
		if len(b) > transport.MaxPayload {
			return errors.New("FHS encoded message bound")
		}
		return n.Send(to, transport.KindConsensus, b)
	})
	return s, nil
}
func (s *Service) receive(ctx context.Context, peer, kind uint8, b []byte) error {
	payload := bytes.Clone(b)
	return s.Do(ctx, func(a *consensus.Application) error {
		if s.config.DeliveryFilter != nil {
			if err := s.config.DeliveryFilter(peer, kind, bytes.Clone(payload)); err != nil {
				return err
			}
		}
		switch kind {
		case transport.KindConsensus:
			if len(payload) > consensus.MaxWireBytes {
				return errors.New("FHS encoded ingress bound")
			}
			var m hotstuff.HotstuffMessage
			if err := rlp.DecodeBytes(payload, &m); err != nil {
				return err
			}
			p := s.config.Transport.Peers[peer]
			key, err := hex.DecodeString(p.BLSPublic)
			if err != nil || m.Id != p.ID || !bytes.Equal(m.PubKey, key) {
				return errors.New("FHS sender differs from TLS identity")
			}
			err = a.Handle(&m)
			if errors.Is(err, hotstuff.ErrProposalDataUnavailable) || temporaryTransport(err) {
				return transport.ErrBusy
			}
			if benign(err) {
				return nil
			}
			return err
		case transport.KindAction:
			if s.config.OnPeerAction != nil {
				return s.config.OnPeerAction(peer, payload)
			}
			if s.config.OnAction == nil {
				return errors.New("authenticated action adapter unavailable")
			}
			return s.config.OnAction(payload)
		case transport.KindExtension:
			if s.config.OnExtension == nil {
				return errors.New("extension adapter unavailable")
			}
			return s.config.OnExtension(peer, payload)
		default:
			return errors.New("unknown DEX transport kind")
		}
	})
}
func benign(err error) bool {
	return err == nil || temporaryTransport(err) || errors.Is(err, hotstuff.ErrInsufficientQC) || errors.Is(err, hotstuff.ErrProposalValidationPending) || errors.Is(err, hotstuff.ErrProposalDataUnavailable) || errors.Is(err, hotstuff.ErrUnhandledMsg) || errors.Is(err, hotstuff.ErrOldState) || errors.Is(err, hotstuff.ErrMissingView) || errors.Is(err, hotstuff.ErrViewOldPhase) || errors.Is(err, hotstuff.ErrFutureState)
}

// A broadcast may aggregate multiple destination failures. Do not hide a disk,
// authentication or other failure merely because another destination is busy.
func temporaryTransport(err error) bool {
	if !errors.Is(err, transport.ErrBusy) {
		return false
	}
	var onlyCapacity func(error) bool
	onlyCapacity = func(e error) bool {
		if e == transport.ErrBusy || e == transport.ErrCapacity {
			return true
		}
		if many, ok := e.(interface{ Unwrap() []error }); ok {
			for _, child := range many.Unwrap() {
				if !onlyCapacity(child) {
					return false
				}
			}
			return true
		}
		if child := errors.Unwrap(e); child != nil {
			return onlyCapacity(child)
		}
		return false
	}
	return onlyCapacity(err)
}
func (s *Service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.closed {
		return errors.New("DEX service already started/closed")
	}
	if err := s.net.Start(); err != nil {
		return err
	}
	s.started = true
	ready := make(chan error, 1)
	s.wg.Add(1)
	go s.run(ready)
	if err := <-ready; err != nil {
		s.failure = err
		return err
	}
	if s.config.APIListen != "" {
		api, err := startAPI(s, s.config.APIListen)
		if err != nil {
			s.failure = err
			return err
		}
		s.api = api
	}
	return nil
}
func (s *Service) run(ready chan error) {
	defer s.wg.Done()
	defer s.closeLeadershipLease()
	var err error
	if s.config.ActorInit != nil {
		err = s.config.ActorInit(s.app)
	}
	if err == nil {
		err = s.app.Start()
		if temporaryTransport(err) {
			// Start restored and marked the actor started before rebroadcasting
			// its durable QC/NewView. An absent peer's full share must not keep
			// this healthy node from running authenticated recovery/timeouts.
			if _, check := s.app.Leadership(); check == nil {
				err = nil
			}
		}
	}
	if err == nil {
		_, _, err = s.actorLeadershipLease()
	}
	ready <- err
	if err != nil {
		return
	}
	timer := time.NewTimer(s.config.Timeout)
	defer timer.Stop()
	view := s.app.CurrentN()
	timeoutReady := s.config.TimeoutReady == nil
	timeoutInterval := s.config.Timeout
	advance := time.NewTicker(10 * time.Millisecond)
	defer advance.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case r := <-s.queue:
			if r.ctx.Err() != nil {
				r.result <- r.ctx.Err()
				continue
			}
			r.result <- r.call(s.app)
		case <-timer.C:
			timer.Reset(timeoutInterval)
			if timeoutReady {
				err = s.app.Timeout()
				if !benign(err) {
					s.record(err)
				}
			}
		case <-advance.C:
			if s.config.ActorTick != nil {
				if e := s.config.ActorTick(s.app); e != nil {
					s.record(e)
				}
			}
			for i := 0; i < 8; i++ {
				did, e := s.app.Advance()
				if !benign(e) {
					s.record(e)
					break
				}
				if !did {
					break
				}
			}
		}
		// A newly authenticated QC/TC starts a complete timeout interval. A
		// process-wide periodic tick could time out a just-entered view and
		// create needless gaps in the protocol's consecutive-view finality.
		nextReady := true
		if s.config.TimeoutReady != nil {
			nextReady, err = s.config.TimeoutReady(s.app)
			if err != nil {
				s.record(err)
				nextReady = false
			}
		}
		// Authenticated but unsettled work needs bounded leader replacement
		// even with no executable market action. Use a separate idle grace:
		// applying the market timer here inserts a TC between sparse actions
		// and can prevent consecutive-view finality indefinitely. This hint
		// creates no proposal or signature and changes no validity rule.
		nextInterval := s.config.Timeout
		if !nextReady && s.submissionPending.Load() {
			nextReady = true
			nextInterval = s.config.SubmissionTimeout
		}
		nextView := s.app.CurrentN()
		// New executable ingress must get a full timeout interval even if it
		// arrived immediately before the old idle timer would have fired.
		if nextView != view || nextReady && !timeoutReady || nextInterval != timeoutInterval {
			view = nextView
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(nextInterval)
		}
		timeoutReady = nextReady
		timeoutInterval = nextInterval
		_, _, _ = s.actorLeadershipLease()
	}
}
func (s *Service) record(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	s.failure = err
	s.mu.Unlock()
}

// Do is an in-process trusted adapter boundary, never an arbitrary network call.
func (s *Service) Do(ctx context.Context, f func(*consensus.Application) error) error {
	if f == nil {
		return errors.New("nil actor operation")
	}
	s.mu.Lock()
	ready := s.started && !s.closed
	s.mu.Unlock()
	if !ready {
		return transport.ErrBusy
	}
	r := request{ctx, f, make(chan error, 1)}
	select {
	case s.queue <- r:
	default:
		return transport.ErrBusy
	}
	select {
	case err := <-r.result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return context.Canceled
	}
}
func (s *Service) Submit(ctx context.Context, raw []byte) (protocol.Hash, error) {
	if len(raw) == 0 || len(raw) > consensus.MaxActionBytes {
		return protocol.Hash{}, errors.New("action byte bound")
	}
	b := bytes.Clone(raw)
	err := s.Do(ctx, func(*consensus.Application) error {
		if s.config.OnAction == nil {
			return errors.New("authenticated action adapter unavailable")
		}
		return s.config.OnAction(b)
	})
	if err != nil {
		return protocol.Hash{}, err
	}
	return protocol.Digest("common-dex/ingress-action/v1", b), nil
}

// Relay is called by trusted application adapters on the actor, e.g. receipt
// dissemination. The durable transport bounds remain enforced.
func (s *Service) Relay(to string, kind uint8, payload []byte) error {
	return s.net.Send(to, kind, payload)
}
func (s *Service) Status(ctx context.Context) (Status, error) {
	status := Status{State: "active", Execution: instrumentation.Execution(), SubmissionPending: s.submissionPending.Load()}
	err := s.Do(ctx, func(a *consensus.Application) error {
		status.Certified, status.Finalized = a.CertifiedHeight(), a.FinalizedHeight()
		status.Storage = a.StorageStatus()
		var err error
		status.Leadership, err = a.Leadership()
		return err
	})
	if err != nil {
		return Status{State: "unavailable"}, err
	}
	stats := s.net.Stats()
	status.PendingTransport = stats.Pending
	status.PendingTransportByPeer = stats.PendingByPeer
	s.mu.Lock()
	if s.failure != nil {
		status.Error = s.failure.Error()
	}
	s.mu.Unlock()
	if stats.Failure != "" {
		status.State = "failed"
		status.Error = stats.Failure
	}
	return status, nil
}

// Leadership serializes observation with FHS transitions. Network/signing work
// must happen after this method returns, outside the consensus actor.
func (s *Service) Leadership(ctx context.Context) (consensus.Leadership, error) {
	state, _, err := s.LeadershipLease(ctx)
	return state, err
}

// LeadershipLease cancels background operations when the serialized actor
// leaves this view or shuts down. A transaction already delivered to CLX stays
// subject to ordinary canonical/idempotence rules; cancellation cannot recall it.
func (s *Service) LeadershipLease(ctx context.Context) (consensus.Leadership, <-chan struct{}, error) {
	var state consensus.Leadership
	var done <-chan struct{}
	err := s.Do(ctx, func(a *consensus.Application) error {
		var err error
		state, done, err = s.actorLeadershipLease()
		return err
	})
	if err != nil {
		// Do may return on cancellation while an already-running callback is
		// finishing. Do not read its captured outputs without result handoff.
		return consensus.Leadership{}, nil, err
	}
	return state, done, err
}

func (s *Service) closeLeadershipLease() {
	if s.leadershipDone != nil {
		close(s.leadershipDone)
		s.leadershipDone = nil
	}
}

func (s *Service) actorLeadershipLease() (consensus.Leadership, <-chan struct{}, error) {
	state, err := s.app.Leadership()
	if err != nil {
		s.closeLeadershipLease()
		return state, nil, err
	}
	if s.leadershipDone == nil || s.leadershipView != state.View {
		s.closeLeadershipLease()
		s.leadershipView, s.leadershipDone = state.View, make(chan struct{})
	}
	return state, s.leadershipDone, nil
}

// SetSubmissionPending only arms local timeout scheduling. Callers must derive
// pending work from authenticated finalized records, not an RPC height or ACK.
func (s *Service) SetSubmissionPending(pending bool) { s.submissionPending.Store(pending) }
func (s *Service) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.cancel()
	api := s.api
	s.mu.Unlock()
	if api != nil {
		api.close()
	}
	e := s.net.Close()
	s.wg.Wait()
	e = errors.Join(e, s.app.Close())
	if s.config.OnClose != nil {
		e = errors.Join(e, s.config.OnClose())
	}
	return e
}
func (s *Service) String() string { return fmt.Sprintf("DEX service %d", s.config.Consensus.Index) }
