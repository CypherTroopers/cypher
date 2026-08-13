// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/cypherium/cypher/aiinfra/ccse"
)

var (
	ErrOutboxPublisherRequired = errors.New("aiinfra postgres: outbox publisher is required")
	ErrOutboxConfiguration     = errors.New("aiinfra postgres: invalid outbox dispatcher configuration")
	ErrOutboxIntentCorrupt     = errors.New("aiinfra postgres: outbox intent is corrupt")
	ErrOutboxLeaseLost         = errors.New("aiinfra postgres: outbox delivery lease was lost")
)

const (
	defaultOutboxBatchSize       = 32
	defaultOutboxLeaseDuration   = 30 * time.Second
	defaultOutboxRetryBackoff    = time.Second
	defaultOutboxRetryBackoffMax = 5 * time.Minute
	maxOutboxBatchSize           = 256
	maxOutboxWorkerIDBytes       = 255
	maxOutboxLeaseDuration       = 10 * time.Minute
	maxOutboxPublishErrorBytes   = 64 << 10
)

// OutboxPublication is an immutable committed intent. Attempt begins at one
// and increases after a failed publication or a lease-expiry recovery.
// Publishers MUST atomically deduplicate Destination+DeduplicationKey (or the
// globally unique EventID). This is what makes crash-after-publish redelivery
// safe; PostgreSQL and an arbitrary remote system cannot provide one atomic
// exactly-once commit.
type OutboxPublication struct {
	EventID          [ccse.MessageIDSize]byte
	Destination      string
	DeduplicationKey string
	ContentType      string
	Payload          []byte
	Attempt          uint64
}

// OutboxPublisher performs the only external operation in the dispatcher.
// Publish is called only after the delivery lease transaction has committed.
type OutboxPublisher interface {
	Publish(context.Context, OutboxPublication) error
}

// OutboxPublishFunc adapts a function to OutboxPublisher.
type OutboxPublishFunc func(context.Context, OutboxPublication) error

func (publish OutboxPublishFunc) Publish(ctx context.Context, publication OutboxPublication) error {
	return publish(ctx, publication)
}

// OutboxDispatcherOption configures immutable dispatcher policy.
type OutboxDispatcherOption func(*outboxDispatcherConfig) error

type outboxDispatcherConfig struct {
	batchSize    int
	lease        time.Duration
	retryBackoff time.Duration
	retryMax     time.Duration
}

// WithOutboxBatchSize limits publications attempted by one DispatchBatch.
func WithOutboxBatchSize(size int) OutboxDispatcherOption {
	return func(config *outboxDispatcherConfig) error {
		if size < 1 || size > maxOutboxBatchSize {
			return ErrOutboxConfiguration
		}
		config.batchSize = size
		return nil
	}
}

// WithOutboxLeaseDuration bounds how long another worker waits after a crash.
func WithOutboxLeaseDuration(duration time.Duration) OutboxDispatcherOption {
	return func(config *outboxDispatcherConfig) error {
		if duration < time.Second || duration > maxOutboxLeaseDuration {
			return ErrOutboxConfiguration
		}
		config.lease = duration
		return nil
	}
}

// WithOutboxRetryBackoff configures bounded exponential retry scheduling.
func WithOutboxRetryBackoff(initial, maximum time.Duration) OutboxDispatcherOption {
	return func(config *outboxDispatcherConfig) error {
		if initial < time.Millisecond || maximum < initial || maximum > 24*time.Hour {
			return ErrOutboxConfiguration
		}
		config.retryBackoff = initial
		config.retryMax = maximum
		return nil
	}
}

// OutboxDispatcher claims committed intents using database-clock leases,
// publishes outside every database transaction, and fences acknowledgements
// with a random lease token. Multiple workers may safely run concurrently.
type OutboxDispatcher struct {
	db           BeginTxer
	publisher    OutboxPublisher
	workerDigest [sha256.Size]byte
	config       outboxDispatcherConfig
}

// NewOutboxDispatcher verifies the complete schema and runtime role before it
// accepts work. workerID is an operator-controlled visible-ASCII identity.
func NewOutboxDispatcher(ctx context.Context, db BeginTxer, workerID string,
	publisher OutboxPublisher, options ...OutboxDispatcherOption) (*OutboxDispatcher, error) {
	if db == nil {
		return nil, ErrDatabaseRequired
	}
	if publisher == nil {
		return nil, ErrOutboxPublisherRequired
	}
	if !validOutboxWorkerID(workerID) {
		return nil, ErrOutboxConfiguration
	}
	config := outboxDispatcherConfig{
		batchSize: defaultOutboxBatchSize, lease: defaultOutboxLeaseDuration,
		retryBackoff: defaultOutboxRetryBackoff, retryMax: defaultOutboxRetryBackoffMax,
	}
	for _, option := range options {
		if option == nil {
			return nil, ErrOutboxConfiguration
		}
		if err := option(&config); err != nil {
			return nil, err
		}
	}
	if err := VerifyReplayStore(ctx, db); err != nil {
		return nil, err
	}
	return &OutboxDispatcher{
		db: db, publisher: publisher,
		workerDigest: outboxWorkerDigest(workerID), config: config,
	}, nil
}

// OutboxDispatchReport describes one bounded scan. Failed publications are
// durably scheduled for retry and included in Failed; their errors are joined
// in the returned error after other ready intents have had a chance to run.
type OutboxDispatchReport struct {
	Claimed   int
	Delivered int
	Failed    int
}

// DispatchBatch performs at most the configured number of publication calls.
func (dispatcher *OutboxDispatcher) DispatchBatch(ctx context.Context) (OutboxDispatchReport, error) {
	if dispatcher == nil || dispatcher.db == nil {
		return OutboxDispatchReport{}, ErrDatabaseRequired
	}
	if dispatcher.publisher == nil {
		return OutboxDispatchReport{}, ErrOutboxPublisherRequired
	}
	if dispatcher.workerDigest == ([sha256.Size]byte{}) || dispatcher.config.batchSize < 1 ||
		dispatcher.config.batchSize > maxOutboxBatchSize || dispatcher.config.lease < time.Second ||
		dispatcher.config.lease > maxOutboxLeaseDuration || dispatcher.config.retryBackoff < time.Millisecond ||
		dispatcher.config.retryMax < dispatcher.config.retryBackoff || dispatcher.config.retryMax > 24*time.Hour {
		return OutboxDispatchReport{}, ErrOutboxConfiguration
	}
	var report OutboxDispatchReport
	var failures []error
	for report.Claimed < dispatcher.config.batchSize {
		claim, found, err := dispatcher.claim(ctx)
		if err != nil {
			return report, errors.Join(append(failures, err)...)
		}
		if !found {
			break
		}
		report.Claimed++
		publishErr := dispatcher.publisher.Publish(ctx, claim.publication())
		if publishErr == nil {
			if err := dispatcher.acknowledge(ctx, claim); err != nil {
				failures = append(failures, err)
				continue
			}
			report.Delivered++
			continue
		}
		report.Failed++
		if err := dispatcher.reject(ctx, claim, publishErr); err != nil {
			failures = append(failures, errors.Join(publishErr, err))
		} else {
			failures = append(failures, publishErr)
		}
	}
	return report, errors.Join(failures...)
}

type outboxClaim struct {
	eventID          [ccse.MessageIDSize]byte
	destination      string
	deduplicationKey string
	contentType      string
	payload          []byte
	attempt          uint64
	leaseToken       [ccse.MessageIDSize]byte
}

func (claim outboxClaim) publication() OutboxPublication {
	return OutboxPublication{
		EventID: claim.eventID, Destination: claim.destination,
		DeduplicationKey: claim.deduplicationKey, ContentType: claim.contentType,
		Payload: bytes.Clone(claim.payload), Attempt: claim.attempt,
	}
}

func (dispatcher *OutboxDispatcher) claim(ctx context.Context) (outboxClaim, bool, error) {
	tx, err := dispatcher.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return outboxClaim{}, false, fmt.Errorf("aiinfra postgres: begin outbox claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SET LOCAL search_path = pg_catalog"); err != nil {
		return outboxClaim{}, false, fmt.Errorf("aiinfra postgres: constrain outbox claim search path: %w", err)
	}
	if err := assertSessionReplicationOrigin(ctx, tx); err != nil {
		return outboxClaim{}, false, err
	}
	var claim outboxClaim
	var eventID, payloadDigest []byte
	var priorAttempts int64
	if _, err := rand.Read(claim.leaseToken[:]); err != nil {
		return outboxClaim{}, false, fmt.Errorf("aiinfra postgres: create outbox lease token: %w", err)
	}
	if claim.leaseToken == ([ccse.MessageIDSize]byte{}) {
		claim.leaseToken[0] = 1
	}
	leaseMicroseconds := dispatcher.config.lease.Microseconds()
	err = tx.QueryRowContext(ctx, `
		SELECT claimed_event_id, claimed_destination, claimed_deduplication_key,
		       claimed_content_type, claimed_payload, claimed_payload_digest,
		       claimed_prior_attempt_count
		FROM cph_aiinfra.claim_outbox_delivery($1, $2, $3, $4)`,
		dispatcher.workerDigest[:], claim.leaseToken[:], leaseMicroseconds,
		dispatcher.config.batchSize).Scan(&eventID, &claim.destination, &claim.deduplicationKey,
		&claim.contentType, &claim.payload, &payloadDigest, &priorAttempts)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return outboxClaim{}, false, fmt.Errorf("aiinfra postgres: commit empty outbox claim: %w", err)
		}
		return outboxClaim{}, false, nil
	}
	if err != nil {
		return outboxClaim{}, false, fmt.Errorf("aiinfra postgres: select outbox delivery: %w", err)
	}
	if err := validateOutboxClaim(eventID, payloadDigest, priorAttempts, &claim); err != nil {
		return outboxClaim{}, false, err
	}
	if err := assertSessionReplicationOrigin(ctx, tx); err != nil {
		return outboxClaim{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return outboxClaim{}, false, fmt.Errorf("aiinfra postgres: commit outbox claim: %w", err)
	}
	claim.attempt = uint64(priorAttempts) + 1
	claim.payload = bytes.Clone(claim.payload)
	return claim, true, nil
}

func (dispatcher *OutboxDispatcher) acknowledge(ctx context.Context, claim outboxClaim) error {
	return dispatcher.finishClaim(ctx, claim, true, [sha256.Size]byte{}, 0)
}

func (dispatcher *OutboxDispatcher) reject(ctx context.Context, claim outboxClaim, publishErr error) error {
	digest := outboxPublishErrorDigest(publishErr)
	return dispatcher.finishClaim(ctx, claim, false, digest,
		outboxRetryDelay(claim.attempt, dispatcher.config.retryBackoff, dispatcher.config.retryMax))
}

func (dispatcher *OutboxDispatcher) finishClaim(ctx context.Context, claim outboxClaim,
	delivered bool, failureDigest [sha256.Size]byte, retryDelay time.Duration) error {
	tx, err := dispatcher.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("aiinfra postgres: begin outbox acknowledgement: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SET LOCAL search_path = pg_catalog"); err != nil {
		return fmt.Errorf("aiinfra postgres: constrain outbox acknowledgement search path: %w", err)
	}
	if err := assertSessionReplicationOrigin(ctx, tx); err != nil {
		return err
	}
	var changedRows int64
	if delivered {
		err = tx.QueryRowContext(ctx, `
			SELECT cph_aiinfra.acknowledge_outbox_delivery($1, $2, $3)`,
			claim.eventID[:], dispatcher.workerDigest[:], claim.leaseToken[:]).Scan(&changedRows)
	} else {
		err = tx.QueryRowContext(ctx, `
			SELECT cph_aiinfra.reject_outbox_delivery($1, $2, $3, $4, $5)`,
			claim.eventID[:], dispatcher.workerDigest[:], claim.leaseToken[:],
			retryDelay.Microseconds(), failureDigest[:]).Scan(&changedRows)
	}
	if err != nil {
		if isOutboxLeaseFailure(err) {
			return fmt.Errorf("%w: %v", ErrOutboxLeaseLost, err)
		}
		return fmt.Errorf("aiinfra postgres: update outbox acknowledgement: %w", err)
	}
	if changedRows != 1 {
		return ErrOutboxLeaseLost
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("aiinfra postgres: commit outbox acknowledgement: %w", err)
	}
	return nil
}

func validateOutboxClaim(eventID, payloadDigest []byte, attempts int64, claim *outboxClaim) error {
	if len(eventID) != ccse.MessageIDSize || len(payloadDigest) != sha256.Size ||
		attempts < 0 || attempts == int64(^uint64(0)>>1) || claim == nil ||
		!validStableOutboxText(claim.destination, maxDestinationBytes) ||
		!validStableOutboxText(claim.deduplicationKey, maxDeduplicationKeyBytes) ||
		!validStableOutboxText(claim.contentType, maxContentTypeBytes) ||
		len(claim.payload) > maxDurablePayloadBytes {
		return ErrOutboxIntentCorrupt
	}
	copy(claim.eventID[:], eventID)
	digest := sha256.Sum256(claim.payload)
	if !bytes.Equal(digest[:], payloadDigest) {
		return ErrOutboxIntentCorrupt
	}
	return nil
}

func outboxPublishErrorDigest(err error) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("CPH-AIIE-OUTBOX-PUBLISH-ERROR-V1\x00"))
	message := err.Error()
	if len(message) > maxOutboxPublishErrorBytes {
		message = message[:maxOutboxPublishErrorBytes]
	}
	_, _ = hash.Write([]byte(message))
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func validStableOutboxText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validOutboxWorkerID(workerID string) bool {
	return validStableOutboxText(workerID, maxOutboxWorkerIDBytes)
}

func outboxWorkerDigest(workerID string) [sha256.Size]byte {
	return sha256.Sum256(append([]byte("CPH-AIIE-OUTBOX-WORKER-V1\x00"), []byte(workerID)...))
}

func isOutboxLeaseFailure(err error) bool {
	var state sqlStateError
	return errors.As(err, &state) && state.SQLState() == "55000"
}

func outboxRetryDelay(attempt uint64, initial, maximum time.Duration) time.Duration {
	delay := initial
	for remaining := attempt; remaining > 1 && delay < maximum; remaining-- {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}
