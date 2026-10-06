// SPDX-License-Identifier: LGPL-3.0-or-later
package browserrelay

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/node/lightnode"
	"github.com/cypherium/cypher/rlp"
)

// ErrUnavailable never implies an empty chain or a successful source observation.
var ErrUnavailable = errors.New("browser relay source unavailable")

// ErrNotInWindow reports a missing object while the current observation is fresh.
var ErrNotInWindow = errors.New("browser relay header is outside the current window")

type Config struct {
	Factory                     lightnode.Factory
	Network                     Network
	SourceID, KeyID             string
	SigningKey                  *ecdsa.PrivateKey
	PollInterval, SourceTimeout time.Duration
	ManifestTTL                 time.Duration
	Now                         func() time.Time
}

// SourceConfiguration is public verification material for trusted owner
// provisioning. A consumer must not automatically trust a peer-supplied key.
type SourceConfiguration struct {
	Network        Network `json:"network"`
	SourceID       string  `json:"sourceId"`
	KeyID          string  `json:"keyId"`
	PublicKey      JWK     `json:"publicKey"`
	MaxHeaders     int     `json:"maxHeaders"`
	MaxHeaderBytes int     `json:"maxHeaderBytes"`
}

// Status describes source observations, not browser delivery or chain finality.
// ErrorCode is a fixed code; source errors never expose paths or credentials.
type Status struct {
	State          string `json:"state"`
	Healthy        bool   `json:"healthy"`
	Running        bool   `json:"running"`
	SourceID       string `json:"sourceId"`
	SourceBootID   string `json:"sourceBootId"`
	Sequence       string `json:"sequence"`
	LastAttemptAt  int64  `json:"lastAttemptAt"`
	LastObservedAt int64  `json:"lastObservedAt"`
	ExpiresAt      int64  `json:"expiresAt"`
	HeadHeight     uint64 `json:"headHeight"`
	Headers        int    `json:"headers"`
	ErrorCode      string `json:"errorCode"`
}

type publication struct {
	envelope Envelope
	manifest Manifest
	packets  map[string]lightnode.Packet
}

// Exporter borrows a Factory, owns each returned View, and exposes only its
// bounded immutable publication. Public readers never perform source I/O.
type Exporter struct {
	config Config
	ctx    context.Context
	cancel context.CancelFunc
	gate   chan struct{}
	wg     sync.WaitGroup
	mu     sync.RWMutex

	starting, started, stopped bool
	bootID                     string
	sequence                   uint64
	lastAttempt                int64
	lastError                  string
	current                    *publication
}

func New(c Config) (*Exporter, error) {
	if c.Factory == nil || ValidateNetwork(c.Network) != nil {
		return nil, errors.New("browser relay requires a source factory and pinned network")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.PollInterval == 0 {
		c.PollInterval = 2 * time.Second
	}
	if c.SourceTimeout == 0 {
		c.SourceTimeout = 2 * time.Second
	}
	if c.ManifestTTL == 0 {
		c.ManifestTTL = 30 * time.Second
	}
	if c.PollInterval < 2*time.Second || c.SourceTimeout <= 0 || c.SourceTimeout > 2*time.Second || c.ManifestTTL < time.Millisecond || c.ManifestTTL > 30*time.Second {
		return nil, errors.New("browser relay source limits are invalid")
	}
	var boot [16]byte
	if _, err := rand.Read(boot[:]); err != nil {
		return nil, errors.New("browser relay entropy unavailable")
	}
	bootID := hex.EncodeToString(boot[:])
	// Reuse the protocol's complete identity/key validation before acquiring a
	// source. This validation envelope is discarded and is never published.
	probe := Manifest{Version: 1, Network: c.Network, SourceID: c.SourceID, SourceBootID: bootID,
		Sequence: "0", ObservedAt: 0, ExpiresAt: 1, HeadHash: c.Network.GenesisHash, Entries: []Entry{}}
	if _, err := SignManifest(probe, c.KeyID, c.SigningKey); err != nil {
		return nil, errors.New("browser relay signing configuration is invalid")
	}
	// Configuration is private after New. Mutating the caller's key must not
	// change a running source's identity or race with signing.
	c.SigningKey = &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c.SigningKey.Curve,
		X: new(big.Int).Set(c.SigningKey.X), Y: new(big.Int).Set(c.SigningKey.Y)}, D: new(big.Int).Set(c.SigningKey.D)}
	ctx, cancel := context.WithCancel(context.Background())
	return &Exporter{config: c, ctx: ctx, cancel: cancel, gate: make(chan struct{}, 1), bootID: bootID}, nil
}

// Start performs a successful initial observation before creating the poller.
// A failed initial observation creates no background work and may be retried.
func (e *Exporter) Start() error {
	e.mu.Lock()
	if e.stopped || e.started || e.starting {
		e.mu.Unlock()
		return ErrUnavailable
	}
	e.starting = true
	e.wg.Add(1)
	e.mu.Unlock()
	defer e.wg.Done()
	if err := e.Refresh(e.ctx); err != nil {
		e.mu.Lock()
		e.starting = false
		e.mu.Unlock()
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.starting = false
	if e.stopped {
		return ErrUnavailable
	}
	e.started = true
	e.wg.Add(1)
	go e.poll()
	return nil
}

func (e *Exporter) poll() {
	defer e.wg.Done()
	ticker := time.NewTicker(e.config.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			_ = e.Refresh(e.ctx)
		}
	}
}

// Stop cancels and joins all owned work, including manually requested Refresh
// operations. A source that violates View's context contract can delay joining;
// no source goroutine is abandoned and no late publication is allowed.
func (e *Exporter) Stop() error {
	e.mu.Lock()
	if !e.stopped {
		e.stopped = true
		e.current = nil
		e.cancel()
	}
	e.mu.Unlock()
	e.wg.Wait()
	return nil
}

type observationError struct {
	code  string
	cause error
}

func (e *observationError) Error() string        { return e.code }
func (e *observationError) Unwrap() error        { return e.cause }
func (e *observationError) Is(target error) bool { return target == ErrUnavailable }

func failObservation(code string, cause error) error {
	return &observationError{code: code, cause: cause}
}

func sourceFailure(err error) error {
	code := "source_unavailable"
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		code = "source_timeout"
	case errors.Is(err, context.Canceled):
		code = "source_canceled"
	case errors.Is(err, ethdb.ErrBrowserSnapshotUnsupported):
		code = "unsupported_source"
	case errors.Is(err, ethdb.ErrBrowserSnapshotLimit):
		// This also covers work/record/allocation budgets, so it must not be
		// mislabeled as a known oversized header without size evidence.
		code = "source_limit"
	case errors.Is(err, ethdb.ErrBrowserSnapshotMalformed), errors.Is(err, ethdb.ErrBrowserSnapshotInconsistent):
		code = "source_inconsistent"
	}
	return failObservation(code, err)
}

// Refresh serializes fresh, full-window observations. Failure preserves the old
// envelope's original expiry and sequence; it never re-signs cached data.
func (e *Exporter) Refresh(ctx context.Context) (err error) {
	if ctx == nil {
		return failObservation("source_canceled", nil)
	}
	e.mu.Lock()
	if e.stopped {
		e.mu.Unlock()
		return ErrUnavailable
	}
	e.wg.Add(1)
	e.mu.Unlock()
	defer e.wg.Done()
	select {
	case e.gate <- struct{}{}:
		defer func() { <-e.gate }()
	case <-ctx.Done():
		return sourceFailure(ctx.Err())
	case <-e.ctx.Done():
		return ErrUnavailable
	}
	call, cancel := context.WithTimeout(ctx, e.config.SourceTimeout)
	stopLife := context.AfterFunc(e.ctx, cancel)
	defer func() { stopLife(); cancel() }()
	defer func() {
		if err != nil {
			code := "source_unavailable"
			var failure *observationError
			if errors.As(err, &failure) {
				code = failure.code
			}
			e.mu.Lock()
			if !e.stopped {
				e.lastError = code
			}
			e.mu.Unlock()
		}
	}()
	if err := call.Err(); err != nil {
		return sourceFailure(err)
	}
	observed := e.config.Now().UnixMilli()
	e.mu.Lock()
	if e.stopped {
		e.mu.Unlock()
		return ErrUnavailable
	}
	if observed < e.lastAttempt || observed < 0 {
		e.mu.Unlock()
		return failObservation("clock_regression", nil)
	}
	if uint64(observed) > MaxSafeInteger-uint64(e.config.ManifestTTL.Milliseconds()) {
		e.mu.Unlock()
		return failObservation("invalid_clock", nil)
	}
	e.lastAttempt = observed
	if e.sequence == math.MaxUint64 {
		e.mu.Unlock()
		return failObservation("sequence_exhausted", nil)
	}
	nextSequence := e.sequence + 1
	e.mu.Unlock()
	pub, err := e.observe(call, observed, nextSequence)
	if err != nil {
		return err
	}
	if err := call.Err(); err != nil {
		return sourceFailure(err)
	}
	// Publication and stop share the lock; an old generation cannot come back.
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped || e.ctx.Err() != nil {
		return ErrUnavailable
	}
	now := e.config.Now().UnixMilli()
	if now < observed {
		return failObservation("clock_regression", nil)
	}
	if now >= pub.manifest.ExpiresAt {
		return failObservation("source_timeout", nil)
	}
	e.current, e.sequence, e.lastError = pub, nextSequence, ""
	return nil
}

func (e *Exporter) observe(ctx context.Context, observed int64, sequence uint64) (*publication, error) {
	view, err := e.config.Factory(ctx)
	if err != nil || view == nil {
		if view != nil {
			_ = view.Close()
		}
		return nil, sourceFailure(err)
	}
	// Close must succeed before signing. Deferred close handles every failure.
	closed := false
	defer func() {
		if !closed {
			_ = view.Close()
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, sourceFailure(err)
	}
	if view.Network() != e.config.Network {
		return nil, failObservation("network_mismatch", nil)
	}
	head, err := view.LatestHeight(ctx)
	if err != nil {
		return nil, sourceFailure(err)
	}
	if head > MaxSafeInteger {
		return nil, failObservation("source_inconsistent", nil)
	}
	m := Manifest{Version: 1, Network: e.config.Network, SourceID: e.config.SourceID, SourceBootID: e.bootID,
		Sequence: strconv.FormatUint(sequence, 10), ObservedAt: observed, ExpiresAt: observed + e.config.ManifestTTL.Milliseconds(),
		HeadHeight: head, HeadHash: e.config.Network.GenesisHash, Entries: make([]Entry, 0, MaxHeaders)}
	packets := make(map[string]lightnode.Packet, MaxHeaders)
	first := uint64(1)
	if head >= MaxHeaders {
		first = head - MaxHeaders + 1
	}
	for height := first; height <= head; height++ {
		if err := ctx.Err(); err != nil {
			return nil, sourceFailure(err)
		}
		raw, err := view.HeaderRLP(ctx, height, MaxHeaderBytes)
		if err != nil {
			return nil, sourceFailure(err)
		}
		if len(raw) > MaxHeaderBytes {
			return nil, failObservation("unsupported_header_size", nil)
		}
		var header types.Header
		if len(raw) == 0 || rlp.DecodeBytes(raw, &header) != nil || header.Number == nil || header.Number.Sign() < 0 || header.Number.BitLen() > 53 || header.Number.Uint64() != height {
			return nil, failObservation("invalid_header", nil)
		}
		blockHash, parentHash := header.Hash().Hex(), header.ParentHash.Hex()
		digest := lightnode.HeaderDigest(e.config.Network, height, raw)
		m.Entries = append(m.Entries, Entry{Height: height, BlockHash: blockHash, ParentHash: parentHash, Digest: digest, RawBytes: len(raw)})
		packets[digest] = lightnode.Packet{Version: 1, Network: e.config.Network, Height: height, HeaderRLP: base64.StdEncoding.EncodeToString(raw), Digest: digest}
		m.HeadHash = blockHash
	}
	if err := ctx.Err(); err != nil {
		return nil, sourceFailure(err)
	}
	if err := ValidateManifest(m); err != nil {
		return nil, failObservation("source_inconsistent", err)
	}
	closed = true
	if err := view.Close(); err != nil {
		return nil, failObservation("source_close_failed", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, sourceFailure(err)
	}
	envelope, err := SignManifest(m, e.config.KeyID, e.config.SigningKey)
	if err != nil {
		return nil, failObservation("signing_failed", err)
	}
	return &publication{envelope: envelope, manifest: m, packets: packets}, nil
}

func (e *Exporter) availableLocked(now int64) bool {
	return !e.stopped && e.current != nil && now >= e.current.manifest.ObservedAt && now < e.current.manifest.ExpiresAt
}

func (e *Exporter) Head() (Envelope, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if !e.availableLocked(e.config.Now().UnixMilli()) {
		return Envelope{}, ErrUnavailable
	}
	return e.current.envelope, nil
}

func (e *Exporter) Header(digest string) (lightnode.Packet, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if !e.availableLocked(e.config.Now().UnixMilli()) {
		return lightnode.Packet{}, ErrUnavailable
	}
	p, found := e.current.packets[digest]
	if !found {
		return lightnode.Packet{}, ErrNotInWindow
	}
	return p, nil
}

func (e *Exporter) SourceConfiguration() SourceConfiguration {
	// New validated and copied this key; it remains immutable. PublicJWK
	// creates a fresh key-operations slice and never returns the private scalar.
	key, _ := PublicJWK(&e.config.SigningKey.PublicKey)
	return SourceConfiguration{Network: e.config.Network, SourceID: e.config.SourceID, KeyID: e.config.KeyID,
		PublicKey: key, MaxHeaders: MaxHeaders, MaxHeaderBytes: MaxHeaderBytes}
}

func (e *Exporter) Status() Status {
	e.mu.RLock()
	defer e.mu.RUnlock()
	now := e.config.Now().UnixMilli()
	s := Status{State: "idle", Running: e.started && !e.stopped, SourceID: e.config.SourceID, SourceBootID: e.bootID,
		Sequence: strconv.FormatUint(e.sequence, 10), LastAttemptAt: e.lastAttempt, ErrorCode: e.lastError}
	if e.current != nil {
		m := e.current.manifest
		s.LastObservedAt, s.ExpiresAt, s.HeadHeight, s.Headers = m.ObservedAt, m.ExpiresAt, m.HeadHeight, len(m.Entries)
		s.State, s.Healthy = "healthy", true
		if now >= m.ExpiresAt {
			s.State, s.Healthy = "expired", false
		}
		if now < m.ObservedAt {
			s.State, s.Healthy, s.ErrorCode = "degraded", false, "clock_regression"
		}
	}
	if e.lastError != "" {
		s.State, s.Healthy = "degraded", false
	}
	if e.starting {
		s.State, s.Healthy = "starting", false
	}
	if e.stopped {
		s.State, s.Healthy = "stopped", false
	}
	return s
}
