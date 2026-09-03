package reconfig

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

var errFHSRecoveryPending = errors.New("Fair HotStuff durable recovery is waiting for proposal content")

const (
	fhsMaxCertifiedChainDepth = 128

	// Fair HotStuff finalizes with a certified direct child. Keeping a small
	// canonical suffix is deliberately more conservative than that two-chain
	// requirement, while every certificate above the canonical head is retained
	// regardless of this window for crash recovery.
	fhsPersistenceCanonicalRetention = uint64(8)
	fhsPersistenceViewRetention      = uint64(256)

	// Uncertified proposals are repairable DA cache entries, not safety state.
	// Bound them to the same entry/byte budget as the in-memory proposal cache;
	// certified proposals and the durable vote/QC watermarks are exempt.
	fhsPersistenceUncertifiedLimit = proposalBodyCacheMaxEntries
	fhsPersistenceUncertifiedBytes = proposalBodyCacheMaxBytes

	fhsPersistencePruneWriteInterval = uint64(16)
	fhsPersistenceDeleteBatchSize    = 256

	// Content persistence is intentionally bounded by the same memory budget as
	// the proposal cache. Jobs retain an immutable cache entry rather than taking
	// another multi-megabyte body copy.
	fhsContentQueueMaxEntries = proposalBodyCacheMaxEntries
	fhsContentQueueMaxBytes   = proposalBodyCacheMaxBytes
)

type fhsContentWriteJob struct {
	proposalID common.Hash
	ref        *types.HotstuffProposalRef
	body       *proposalBodyMsg
	bytes      int
}

// fhsContentWriter is a single-writer, best-effort durability lane for
// content-addressed proposal data. Safety WAL publication never waits for this
// queue: a missing body is repaired by its signed ProposalRef after restart.
type fhsContentWriter struct {
	mu          sync.Mutex
	jobs        chan fhsContentWriteJob
	pending     map[common.Hash]struct{}
	queuedBytes int
	maxEntries  int
	maxBytes    int
	accepting   bool
	abort       chan struct{}
	done        chan struct{}
	abortOnce   sync.Once
	persist     func(*types.HotstuffProposalRef, *proposalBodyMsg) error
}

func newFHSContentWriter(persist func(*types.HotstuffProposalRef, *proposalBodyMsg) error) *fhsContentWriter {
	return newFHSContentWriterWithLimits(fhsContentQueueMaxEntries, fhsContentQueueMaxBytes, persist)
}

func newFHSContentWriterForConfig(config *params.ChainConfig, persist func(*types.HotstuffProposalRef, *proposalBodyMsg) error) *fhsContentWriter {
	return newFHSContentWriterWithLimits(fhsContentQueueMaxEntries, proposalBodyCacheLimitForConfig(config), persist)
}

func newFHSContentWriterWithLimits(maxEntries, maxBytes int, persist func(*types.HotstuffProposalRef, *proposalBodyMsg) error) *fhsContentWriter {
	if maxEntries <= 0 || maxBytes <= 0 || persist == nil {
		return nil
	}
	writer := &fhsContentWriter{
		jobs:       make(chan fhsContentWriteJob, maxEntries),
		pending:    make(map[common.Hash]struct{}),
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		accepting:  true,
		abort:      make(chan struct{}),
		done:       make(chan struct{}),
		persist:    persist,
	}
	go writer.run()
	return writer
}

func (writer *fhsContentWriter) enqueue(ref *types.HotstuffProposalRef, body *proposalBodyMsg) bool {
	if writer == nil || ref == nil || body == nil || ref.ProposalID() == (common.Hash{}) {
		return false
	}
	proposalID := ref.ProposalID()
	jobBytes := proposalBodyMsgPayloadBytes(body)
	if jobBytes <= 0 || jobBytes > writer.maxBytes {
		return false
	}
	refCopy := *ref
	job := fhsContentWriteJob{proposalID: proposalID, ref: &refCopy, body: body, bytes: jobBytes}

	writer.mu.Lock()
	defer writer.mu.Unlock()
	if !writer.accepting {
		return false
	}
	if _, duplicate := writer.pending[proposalID]; duplicate {
		return true
	}
	if len(writer.pending) >= writer.maxEntries || writer.queuedBytes > writer.maxBytes-jobBytes {
		return false
	}
	select {
	case writer.jobs <- job:
		writer.pending[proposalID] = struct{}{}
		writer.queuedBytes += jobBytes
		return true
	default:
		return false
	}
}

func (writer *fhsContentWriter) finish(job fhsContentWriteJob) {
	writer.mu.Lock()
	delete(writer.pending, job.proposalID)
	writer.queuedBytes -= job.bytes
	if writer.queuedBytes < 0 {
		writer.queuedBytes = 0
	}
	writer.mu.Unlock()
}

func (writer *fhsContentWriter) run() {
	defer close(writer.done)
	aborting := false
	for job := range writer.jobs {
		if !aborting {
			select {
			case <-writer.abort:
				aborting = true
			default:
			}
		}
		if !aborting {
			if err := writer.persist(job.ref, job.body); err != nil {
				log.Error("Failed to persist recoverable FHS proposal content",
					"proposalID", job.proposalID, "bodyHash", job.body.BodyHash, "bytes", job.bytes, "err", err)
			}
		}
		writer.finish(job)
	}
}

// shutdown stops accepting new jobs and drains until ctx expires. A currently
// executing database batch is always joined before returning so the caller may
// safely close the shared chain database afterwards.
func (writer *fhsContentWriter) shutdown(ctx context.Context) error {
	if writer == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	writer.mu.Lock()
	if writer.accepting {
		writer.accepting = false
		close(writer.jobs)
	}
	writer.mu.Unlock()
	select {
	case <-writer.done:
		return nil
	case <-ctx.Done():
		writer.abortOnce.Do(func() { close(writer.abort) })
		<-writer.done
		return ctx.Err()
	}
}

func (s *Service) shutdownFHSContentWriter(ctx context.Context) error {
	if s == nil || s.fhsContentWriter == nil {
		return nil
	}
	return s.fhsContentWriter.shutdown(ctx)
}

type fhsDiskSafety struct {
	ChainID          uint64
	GenesisHash      common.Hash
	State            *hotstuff.FHSSafetyState
	HighestBlockHash common.Hash
	PendingBroadcast *hotstuff.SignedState `rlp:"nil"`
}

type fhsDiskProposal struct {
	ProposalID  common.Hash
	ProposalRef []byte
	Extra       []byte
	ParentQC    []byte
}

type fhsDiskBody struct {
	BodyHash     common.Hash
	EncodedBlock []byte
}

type fhsDiskCertificate struct {
	ProposalID common.Hash
	QC         *hotstuff.SignedState
}

// fhsDeferredRecovery keeps an already durable safety watermark gated while
// its recoverable proposal content is fetched after networking starts. It is a
// process-local continuation, not another WAL record.
type fhsDeferredRecovery struct {
	HighestQC        *hotstuff.SignedState
	HighestBlockHash common.Hash
	RecoveredView    uint64
	PendingBroadcast *hotstuff.SignedState
}

func cloneFHSDeferredRecovery(recovery *fhsDeferredRecovery) *fhsDeferredRecovery {
	if recovery == nil {
		return nil
	}
	return &fhsDeferredRecovery{
		HighestQC:        hotstuff.CloneSignedState(recovery.HighestQC),
		HighestBlockHash: recovery.HighestBlockHash,
		RecoveredView:    recovery.RecoveredView,
		PendingBroadcast: hotstuff.CloneSignedState(recovery.PendingBroadcast),
	}
}

type fhsSafetyStore struct {
	db                  ethdb.KeyValueStore
	chainID             uint64
	genesisHash         common.Hash
	bodyMaxBytes        int
	uncertifiedMaxBytes int

	// safetyMu serializes the small synchronous anti-equivocation WAL. Proposal
	// bodies are deliberately excluded: an 8 MiB content write must never delay
	// publishing a vote/timeout watermark that is already independent of that
	// recoverable data.
	safetyMu           sync.Mutex
	loaded             bool
	state              *hotstuff.FHSSafetyState
	highestBlockHash   common.Hash
	pendingBroadcast   *hotstuff.SignedState
	lastPersistenceErr error
	deferredRecovery   *fhsDeferredRecovery

	// contentMu protects proposal/body records and their GC accounting. GC takes
	// safetyMu before contentMu; content paths must never acquire safetyMu while
	// holding contentMu.
	contentMu                sync.Mutex
	proposalWritesSincePrune uint64
}

func (store *fhsSafetyStore) effectiveBodyMaxBytes() int {
	if store != nil && store.bodyMaxBytes > 0 {
		return store.bodyMaxBytes
	}
	return proposalBodySidecarMaxBytes
}

func (store *fhsSafetyStore) effectiveUncertifiedMaxBytes() int {
	if store != nil && store.uncertifiedMaxBytes > 0 {
		return store.uncertifiedMaxBytes
	}
	return fhsPersistenceUncertifiedBytes
}

func (store *fhsSafetyStore) deferRecovery(recovery *fhsDeferredRecovery) error {
	if store == nil || recovery == nil || recovery.HighestQC == nil || recovery.HighestBlockHash == (common.Hash{}) {
		return fmt.Errorf("invalid deferred FHS recovery")
	}
	store.safetyMu.Lock()
	defer store.safetyMu.Unlock()
	if err := store.loadLocked(); err != nil {
		return err
	}
	if store.state == nil || store.state.HighestQC == nil ||
		!hotstuff.SignedStateSemanticEqual(store.state.HighestQC, recovery.HighestQC) ||
		store.highestBlockHash != recovery.HighestBlockHash {
		return fmt.Errorf("deferred FHS recovery does not match the durable highest QC")
	}
	if existing := store.deferredRecovery; existing != nil {
		if !hotstuff.SignedStateSemanticEqual(existing.HighestQC, recovery.HighestQC) ||
			existing.HighestBlockHash != recovery.HighestBlockHash {
			return fmt.Errorf("conflicting deferred FHS recovery")
		}
	}
	store.deferredRecovery = cloneFHSDeferredRecovery(recovery)
	return nil
}

func (store *fhsSafetyStore) deferredRecoverySnapshot() *fhsDeferredRecovery {
	if store == nil {
		return nil
	}
	store.safetyMu.Lock()
	defer store.safetyMu.Unlock()
	return cloneFHSDeferredRecovery(store.deferredRecovery)
}

func (store *fhsSafetyStore) completeDeferredRecovery(qc *hotstuff.SignedState) error {
	if store == nil || qc == nil {
		return fmt.Errorf("invalid deferred FHS recovery completion")
	}
	store.safetyMu.Lock()
	defer store.safetyMu.Unlock()
	if store.deferredRecovery == nil {
		return nil
	}
	if !hotstuff.SignedStateSemanticEqual(store.deferredRecovery.HighestQC, qc) {
		return fmt.Errorf("deferred FHS recovery completion mismatch")
	}
	store.deferredRecovery = nil
	return nil
}

func (store *fhsSafetyStore) recoveryPendingLocked() bool {
	return store != nil && store.deferredRecovery != nil
}

func (s *Service) hasDeferredFHSRecovery() bool {
	return s != nil && s.fhsStore != nil && s.fhsStore.deferredRecoverySnapshot() != nil
}

// completeDeferredFHSRecovery opens the consensus gate only after the exact
// durable HighestQC has been executed, installed and committed as far as its
// two-chain proof permits. Peer authorization is narrowed back to the active
// committee before votes or pacemaker events can resume.
func (s *Service) completeDeferredFHSRecovery(qc *hotstuff.SignedState) (bool, error) {
	if s == nil || s.fhsStore == nil {
		return false, nil
	}
	recovery := s.fhsStore.deferredRecoverySnapshot()
	if recovery == nil {
		return false, nil
	}
	if qc == nil || !hotstuff.SignedStateSemanticEqual(recovery.HighestQC, qc) {
		return false, fmt.Errorf("deferred FHS recovery completion does not match durable HighestQC")
	}
	// Applying a repaired certified prefix invokes block-completion callbacks,
	// which normally restart the pacemaker. Close that transient window before
	// the recovery watermark is released.
	if s.pacetMakerTimer != nil {
		_ = s.pacetMakerTimer.stop()
	}
	if s.netService != nil && s.netService.server != nil {
		peers, err := activeFHSAuthorizedPeers(bftview.GetCurrentMember())
		if err != nil {
			return false, fmt.Errorf("restore active FHS peer authorization: %w", err)
		}
		if err := s.netService.server.UpdatePeerAuthorization(peers); err != nil {
			return false, fmt.Errorf("restore active FHS peer authorization: %w", err)
		}
		s.netService.setAuthenticatedPeerKeys(peers)
	}
	if err := s.fhsStore.completeDeferredRecovery(qc); err != nil {
		return false, err
	}
	s.applyFHSRecoveredView(recovery.RecoveredView)
	return true, nil
}

func newFHSSafetyStore(db ethdb.KeyValueStore, chainID uint64, genesisHash common.Hash) *fhsSafetyStore {
	return newFHSSafetyStoreForConfig(db, chainID, genesisHash, nil)
}

func newFHSSafetyStoreForConfig(db ethdb.KeyValueStore, chainID uint64, genesisHash common.Hash, config *params.ChainConfig) *fhsSafetyStore {
	return &fhsSafetyStore{
		db:                  db,
		chainID:             chainID,
		genesisHash:         genesisHash,
		bodyMaxBytes:        proposalBodyLimitForConfig(config),
		uncertifiedMaxBytes: proposalBodyCacheLimitForConfig(config),
		state:               hotstuff.NewFHSSafetyState(),
	}
}

func (store *fhsSafetyStore) loadLocked() error {
	if store == nil || store.db == nil {
		return fmt.Errorf("FHS safety store is unavailable")
	}
	if store.loaded {
		return store.lastPersistenceErr
	}
	encoded, err := rawdb.ReadFHSSafetyState(store.db)
	if err != nil {
		store.lastPersistenceErr = err
		return err
	}
	if len(encoded) == 0 {
		store.state = hotstuff.NewFHSSafetyState()
		store.lastPersistenceErr = nil
		store.loaded = true
		return nil
	}
	var disk fhsDiskSafety
	if err := rlp.DecodeBytes(encoded, &disk); err != nil {
		store.lastPersistenceErr = fmt.Errorf("decode FHS safety WAL: %w", err)
		return store.lastPersistenceErr
	}
	expected := hotstuff.NewFHSSafetyState()
	if disk.ChainID != store.chainID || disk.GenesisHash != store.genesisHash ||
		disk.State == nil || disk.State.Version != expected.Version || disk.State.Domain != expected.Domain {
		store.lastPersistenceErr = fmt.Errorf("FHS safety WAL belongs to an incompatible chain")
		return store.lastPersistenceErr
	}
	store.state = hotstuff.CloneFHSSafetyState(disk.State)
	store.highestBlockHash = disk.HighestBlockHash
	store.pendingBroadcast = hotstuff.CloneSignedState(disk.PendingBroadcast)
	store.lastPersistenceErr = nil
	store.loaded = true
	return nil
}

func (store *fhsSafetyStore) load() error {
	if store == nil {
		return fmt.Errorf("nil FHS safety store")
	}
	store.safetyMu.Lock()
	defer store.safetyMu.Unlock()
	return store.loadLocked()
}

func (store *fhsSafetyStore) snapshot() (*hotstuff.FHSSafetyState, common.Hash, error) {
	if store == nil {
		return nil, common.Hash{}, fmt.Errorf("nil FHS safety store")
	}
	store.safetyMu.Lock()
	defer store.safetyMu.Unlock()
	if err := store.loadLocked(); err != nil {
		return nil, common.Hash{}, err
	}
	return hotstuff.CloneFHSSafetyState(store.state), store.highestBlockHash, nil
}

func (store *fhsSafetyStore) pendingBroadcastSnapshot() (*hotstuff.SignedState, error) {
	if store == nil {
		return nil, fmt.Errorf("nil FHS safety store")
	}
	store.safetyMu.Lock()
	defer store.safetyMu.Unlock()
	if err := store.loadLocked(); err != nil {
		return nil, err
	}
	return hotstuff.CloneSignedState(store.pendingBroadcast), nil
}

// clearPendingBroadcast durably completes an outbox entry after its QC is
// already part of the canonical chain. Replaying it after every restart would
// only make peers request a proposal that no longer needs dissemination.
func (store *fhsSafetyStore) clearPendingBroadcast(qc *hotstuff.SignedState) error {
	if store == nil || qc == nil {
		return fmt.Errorf("invalid FHS pending broadcast completion")
	}
	store.safetyMu.Lock()
	defer store.safetyMu.Unlock()
	if err := store.loadLocked(); err != nil {
		return err
	}
	if store.pendingBroadcast == nil {
		return nil
	}
	if !hotstuff.SignedStateSemanticEqual(store.pendingBroadcast, qc) {
		return fmt.Errorf("FHS pending broadcast completion mismatch")
	}
	encoded, err := store.encodeSafetyWithPending(store.state, store.highestBlockHash, nil)
	if err != nil {
		return err
	}
	batch := store.db.NewBatch()
	if err := rawdb.WriteFHSSafetyState(batch, encoded); err != nil {
		return err
	}
	if err := writeFHSBatchSync(batch); err != nil {
		store.lastPersistenceErr = err
		return err
	}
	store.pendingBroadcast = nil
	return nil
}

// recoverySnapshot also upgrades WALs written before superseded timeout
// evidence was cleared with the replacing QC. The normalized record is synced
// before it is exposed to recovery so live memory and durable state agree.
func (store *fhsSafetyStore) recoverySnapshot() (*hotstuff.FHSSafetyState, common.Hash, error) {
	if store == nil {
		return nil, common.Hash{}, fmt.Errorf("nil FHS safety store")
	}
	store.safetyMu.Lock()
	defer store.safetyMu.Unlock()
	if err := store.loadLocked(); err != nil {
		return nil, common.Hash{}, err
	}
	next := hotstuff.CloneFHSSafetyState(store.state)
	changed, err := clearSupersededFHSTimeouts(next)
	if err != nil {
		return nil, common.Hash{}, err
	}
	if !changed {
		return next, store.highestBlockHash, nil
	}
	encoded, err := store.encodeSafety(next, store.highestBlockHash)
	if err != nil {
		return nil, common.Hash{}, err
	}
	batch := store.db.NewBatch()
	if err := rawdb.WriteFHSSafetyState(batch, encoded); err != nil {
		return nil, common.Hash{}, err
	}
	if err := writeFHSBatchSync(batch); err != nil {
		store.lastPersistenceErr = err
		return nil, common.Hash{}, err
	}
	store.state = next
	return hotstuff.CloneFHSSafetyState(next), store.highestBlockHash, nil
}

func (store *fhsSafetyStore) encodeSafety(state *hotstuff.FHSSafetyState, highest common.Hash) ([]byte, error) {
	return store.encodeSafetyWithPending(state, highest, store.pendingBroadcast)
}

func (store *fhsSafetyStore) encodeSafetyWithPending(state *hotstuff.FHSSafetyState, highest common.Hash, pending *hotstuff.SignedState) ([]byte, error) {
	return rlp.EncodeToBytes(&fhsDiskSafety{
		ChainID:          store.chainID,
		GenesisHash:      store.genesisHash,
		State:            hotstuff.CloneFHSSafetyState(state),
		HighestBlockHash: highest,
		PendingBroadcast: hotstuff.CloneSignedState(pending),
	})
}

func writeFHSBatchSync(batch ethdb.Batch) error {
	if batch == nil {
		return fmt.Errorf("nil FHS database batch")
	}
	syncBatch, ok := batch.(ethdb.SyncBatch)
	if !ok {
		return fmt.Errorf("database does not support synchronous FHS safety writes")
	}
	return syncBatch.WriteSync()
}

type fhsPersistenceProposalCandidate struct {
	proposalID common.Hash
	bodyHash   common.Hash
	number     uint64
	view       uint64
	bodySize   uint64
}

func fhsPersistencePruneThrough(current, retained uint64) uint64 {
	if current <= retained {
		return 0
	}
	return current - retained
}

func sortFHSHashes(hashes []common.Hash) {
	sort.Slice(hashes, func(i, j int) bool {
		return bytes.Compare(hashes[i][:], hashes[j][:]) < 0
	})
}

func deleteFHSHashesInBatches(
	db ethdb.KeyValueStore,
	hashes []common.Hash,
	remove func(ethdb.KeyValueWriter, common.Hash) error,
) error {
	if len(hashes) == 0 {
		return nil
	}
	if db == nil || remove == nil {
		return fmt.Errorf("invalid FHS delete batch")
	}
	sortFHSHashes(hashes)
	for start := 0; start < len(hashes); start += fhsPersistenceDeleteBatchSize {
		end := start + fhsPersistenceDeleteBatchSize
		if end > len(hashes) {
			end = len(hashes)
		}
		batch := db.NewBatch()
		for _, hash := range hashes[start:end] {
			if err := remove(batch, hash); err != nil {
				return err
			}
		}
		if err := batch.Write(); err != nil {
			return err
		}
	}
	return nil
}

// pruneFHSPersistence bounds the validator-local recovery cache. Safety state
// is never deleted. All uncommitted certificates, the durable vote/QC targets,
// and a conservative canonical suffix survive each pass. Bodies are removed
// only after every retained proposal reference has been collected, so a body
// shared by multiple proposal views cannot be collected prematurely.
func (s *Service) pruneFHSPersistence(canonicalNumber, currentView uint64) error {
	if s == nil || s.fhsStore == nil || s.fhsStore.db == nil {
		return nil
	}
	// Snapshot the active repair set before taking the store lock. The HighQC
	// worker registers an entry only after verifying its certificate, and keeps
	// the set active until serialized installation completes. This both avoids a
	// validation/store lock inversion and prevents a >64-certificate catch-up
	// from collecting its own durable prefix under the unsolicited-cache limit.
	activeRepairProposalIDs := s.activeHighQCProposalBodyIDs()
	store := s.fhsStore
	// Keep the safety snapshot stable while GC marks and sweeps. contentMu is
	// always acquired second; proposal/body readers and writers never take
	// safetyMu, so a large content write cannot invert this order.
	store.safetyMu.Lock()
	defer store.safetyMu.Unlock()
	store.contentMu.Lock()
	defer store.contentMu.Unlock()
	if err := store.loadLocked(); err != nil {
		return err
	}

	protectedProposalIDs := activeRepairProposalIDs
	protectedCertificateHashes := make(map[common.Hash]struct{})
	if (store.state.HighestQC == nil) != (store.highestBlockHash == (common.Hash{})) {
		return fmt.Errorf("incomplete highest FHS persistence watermark")
	}
	if store.pendingBroadcast != nil && store.state.HighestQC == nil {
		return fmt.Errorf("pending FHS QC broadcast has no highest certificate")
	}
	protectQC := func(name string, qc *hotstuff.SignedState, expectedBlockHash common.Hash) error {
		if qc == nil {
			return nil
		}
		ref, err := types.DecodeHotstuffProposalRef(qc.State)
		if err != nil {
			return fmt.Errorf("decode protected %s proposal: %w", name, err)
		}
		if ref.ChainID != store.chainID || ref.ViewNumber != qc.Number || ref.ViewID != qc.ViewID || ref.LeaderID != qc.LeaderID {
			return fmt.Errorf("protected %s proposal context mismatch", name)
		}
		if expectedBlockHash != (common.Hash{}) && ref.BlockHash != expectedBlockHash {
			return fmt.Errorf("protected %s block hash mismatch", name)
		}
		protectedProposalIDs[ref.ProposalID()] = struct{}{}
		if expectedBlockHash != (common.Hash{}) {
			protectedCertificateHashes[expectedBlockHash] = struct{}{}
		}
		return nil
	}
	if vote := store.state.LastVote; vote != nil {
		if err := validatePersistedVote(vote); err != nil {
			return fmt.Errorf("validate protected FHS vote: %w", err)
		}
		ref, err := types.DecodeHotstuffProposalRef(vote.ProposalRef)
		if err != nil || ref.ChainID != store.chainID {
			return fmt.Errorf("decode protected FHS vote proposal")
		}
		protectedProposalIDs[vote.ProposalID] = struct{}{}
	}
	if err := protectQC("highest QC", store.state.HighestQC, store.highestBlockHash); err != nil {
		return err
	}
	if err := protectQC("pending QC broadcast", store.pendingBroadcast, store.highestBlockHash); err != nil {
		return err
	}

	pruneBlockThrough := fhsPersistencePruneThrough(canonicalNumber, fhsPersistenceCanonicalRetention)
	pruneViewThrough := fhsPersistencePruneThrough(currentView, fhsPersistenceViewRetention)
	certificateBodyHashes := make(map[common.Hash]struct{})
	deleteCertificates := make([]common.Hash, 0)
	if err := rawdb.IterateFHSCertificates(store.db, func(blockHash common.Hash, encoded []byte) error {
		var certificate fhsDiskCertificate
		if err := rlp.DecodeBytes(encoded, &certificate); err != nil || certificate.QC == nil {
			return fmt.Errorf("decode FHS certificate %s", blockHash)
		}
		ref, err := types.DecodeHotstuffProposalRef(certificate.QC.State)
		if err != nil || ref.ChainID != store.chainID || ref.BlockHash != blockHash ||
			ref.ProposalID() != certificate.ProposalID || ref.ViewNumber != certificate.QC.Number ||
			ref.ViewID != certificate.QC.ViewID || ref.LeaderID != certificate.QC.LeaderID {
			return fmt.Errorf("invalid FHS certificate %s", blockHash)
		}
		_, protected := protectedCertificateHashes[blockHash]
		if !protected && pruneBlockThrough != 0 && ref.Number <= pruneBlockThrough {
			deleteCertificates = append(deleteCertificates, blockHash)
			return nil
		}
		protectedProposalIDs[certificate.ProposalID] = struct{}{}
		certificateBodyHashes[ref.BodyHash] = struct{}{}
		return nil
	}); err != nil {
		return err
	}

	retainedBodyHashes := make(map[common.Hash]struct{})
	for bodyHash := range certificateBodyHashes {
		// Certified proposal content may still be queued for asynchronous write or
		// awaiting DA repair. If the body is already present, never collect it merely
		// because its small proposal record is temporarily absent.
		retainedBodyHashes[bodyHash] = struct{}{}
	}
	bodySizes := make(map[common.Hash]uint64)
	deleteProposals := make([]common.Hash, 0)
	candidates := make([]fhsPersistenceProposalCandidate, 0)
	if err := rawdb.IterateFHSProposals(store.db, func(proposalID common.Hash, encoded []byte) error {
		var proposal fhsDiskProposal
		if err := rlp.DecodeBytes(encoded, &proposal); err != nil {
			return fmt.Errorf("decode FHS proposal %s: %w", proposalID, err)
		}
		ref, err := types.DecodeHotstuffProposalRef(proposal.ProposalRef)
		if err != nil {
			return fmt.Errorf("decode FHS proposal reference %s: %w", proposalID, err)
		}
		if proposal.ProposalID != proposalID || ref.ProposalID() != proposalID ||
			ref.ChainID != store.chainID || ref.BodyHash == (common.Hash{}) || ref.BodySize == 0 ||
			ref.BodySize > uint64(store.effectiveBodyMaxBytes()) {
			return fmt.Errorf("invalid FHS proposal %s (stored=%s derived=%s chain=%d body=%s bytes=%d)",
				proposalID, proposal.ProposalID, ref.ProposalID(), ref.ChainID, ref.BodyHash, ref.BodySize)
		}
		if size, ok := bodySizes[ref.BodyHash]; ok && size != ref.BodySize {
			return fmt.Errorf("conflicting FHS body sizes for %s", ref.BodyHash)
		}
		bodySizes[ref.BodyHash] = ref.BodySize
		if _, protected := protectedProposalIDs[proposalID]; protected {
			retainedBodyHashes[ref.BodyHash] = struct{}{}
			return nil
		}
		oldBlock := pruneBlockThrough != 0 && ref.Number <= pruneBlockThrough
		oldView := pruneViewThrough != 0 && ref.ViewNumber <= pruneViewThrough
		if oldBlock || oldView {
			deleteProposals = append(deleteProposals, proposalID)
			return nil
		}
		candidates = append(candidates, fhsPersistenceProposalCandidate{
			proposalID: proposalID,
			bodyHash:   ref.BodyHash,
			number:     ref.Number,
			view:       ref.ViewNumber,
			bodySize:   ref.BodySize,
		})
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].view != candidates[j].view {
			return candidates[i].view > candidates[j].view
		}
		if candidates[i].number != candidates[j].number {
			return candidates[i].number > candidates[j].number
		}
		return bytes.Compare(candidates[i].proposalID[:], candidates[j].proposalID[:]) > 0
	})
	retainedUncertified := 0
	retainedUncertifiedBytes := uint64(0)
	for _, candidate := range candidates {
		additionalBytes := uint64(0)
		if _, shared := retainedBodyHashes[candidate.bodyHash]; !shared {
			additionalBytes = candidate.bodySize
		}
		uncertifiedMaxBytes := uint64(store.effectiveUncertifiedMaxBytes())
		if retainedUncertified >= fhsPersistenceUncertifiedLimit ||
			additionalBytes > uncertifiedMaxBytes ||
			retainedUncertifiedBytes > uncertifiedMaxBytes-additionalBytes {
			deleteProposals = append(deleteProposals, candidate.proposalID)
			continue
		}
		retainedUncertified++
		retainedUncertifiedBytes += additionalBytes
		retainedBodyHashes[candidate.bodyHash] = struct{}{}
	}

	deleteBodies := make([]common.Hash, 0)
	if err := rawdb.IterateFHSBodies(store.db, func(bodyHash common.Hash) error {
		if _, retained := retainedBodyHashes[bodyHash]; !retained {
			deleteBodies = append(deleteBodies, bodyHash)
		}
		return nil
	}); err != nil {
		return err
	}
	// References are deleted before bodies. A partial database failure can leave
	// harmless orphan bodies, but can never leave a retained proposal dangling.
	if err := deleteFHSHashesInBatches(store.db, deleteCertificates, rawdb.DeleteFHSCertificate); err != nil {
		return fmt.Errorf("delete stale FHS certificates: %w", err)
	}
	if err := deleteFHSHashesInBatches(store.db, deleteProposals, rawdb.DeleteFHSProposal); err != nil {
		return fmt.Errorf("delete stale FHS proposals: %w", err)
	}
	if err := deleteFHSHashesInBatches(store.db, deleteBodies, rawdb.DeleteFHSBody); err != nil {
		return fmt.Errorf("delete unreferenced FHS bodies: %w", err)
	}
	store.proposalWritesSincePrune = 0
	if len(deleteCertificates)+len(deleteProposals)+len(deleteBodies) > 0 {
		log.Debug("Pruned durable FHS recovery cache",
			"canonical", canonicalNumber,
			"view", currentView,
			"certificates", len(deleteCertificates),
			"proposals", len(deleteProposals),
			"bodies", len(deleteBodies))
	}
	return nil
}

func (s *Service) pruneFHSPersistenceAtCurrentHead() error {
	if s == nil || !s.fairHotstuffEnabled() || s.bc == nil || s.bc.CurrentBlock() == nil {
		return nil
	}
	return s.pruneFHSPersistence(s.bc.CurrentBlock().NumberU64(), s.GetCurrentView().ViewNumber)
}

func persistedVotesEqual(a, b *hotstuff.PersistedVote) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.ViewNumber == b.ViewNumber && a.ViewID == b.ViewID && a.LeaderID == b.LeaderID &&
		a.ProposalID == b.ProposalID && a.ProposalRefHash == b.ProposalRefHash && bytes.Equal(a.ProposalRef, b.ProposalRef)
}

// clearSupersededFHSTimeouts removes timeout evidence that is no longer the
// pacemaker's high proof. A QC for the same or a later view dominates the TC;
// keeping that TC active across an epoch transition would make recovery try to
// validate it against the newly active committee.
func clearSupersededFHSTimeouts(state *hotstuff.FHSSafetyState) (bool, error) {
	if state == nil || state.HighestQC == nil {
		return false, nil
	}
	changed := false
	if state.LastTimeoutVote != nil && state.LastTimeoutVote.TimedOutView <= state.HighestQC.Number {
		state.LastTimeoutVote = nil
		changed = true
	}
	if state.HighestTC != nil && state.HighestTC.Statement.TimedOutView <= state.HighestQC.Number {
		if state.LastTimeoutView != state.HighestTC.Statement.TimedOutView {
			return false, fmt.Errorf("persisted FHS timeout certificate metadata mismatch")
		}
		state.HighestTC = nil
		state.LastTimeoutView = 0
		changed = true
	}
	return changed, nil
}

// validateCanonicalFHSQCAdvance decides whether a verified canonical QC may
// replace the durable watermark. Numeric view growth alone is insufficient:
// after a sync gap, the previous pointer must still identify an exact
// canonical ancestor of the target.
func validateCanonicalFHSQCAdvance(
	currentQC *hotstuff.SignedState,
	currentHash common.Hash,
	targetRef *types.HotstuffProposalRef,
	targetQC *hotstuff.SignedState,
	targetHash common.Hash,
	verifyCurrent func(*hotstuff.SignedState) (*types.HotstuffProposalRef, error),
	isCanonical func(uint64, common.Hash) bool,
) (bool, error) {
	if targetRef == nil || targetQC == nil || targetHash == (common.Hash{}) || verifyCurrent == nil || isCanonical == nil {
		return false, fmt.Errorf("incomplete canonical FHS QC advance input")
	}
	if currentQC == nil {
		if currentHash != (common.Hash{}) {
			return false, fmt.Errorf("incomplete highest FHS WAL pointer")
		}
		return true, nil
	}
	if currentHash == (common.Hash{}) {
		return false, fmt.Errorf("incomplete highest FHS WAL pointer")
	}
	currentRef, err := verifyCurrent(currentQC)
	if err != nil {
		return false, fmt.Errorf("verify prior highest FHS WAL certificate: %w", err)
	}
	if currentRef == nil || currentRef.BlockHash != currentHash {
		return false, fmt.Errorf("prior highest FHS WAL certificate/hash mismatch")
	}
	switch {
	case currentQC.Number > targetQC.Number:
		// A valid higher uncommitted QC may be ahead of the canonical head.
		return false, nil
	case currentQC.Number == targetQC.Number:
		if currentHash != targetHash || !hotstuff.SignedStateSemanticEqual(currentQC, targetQC) {
			return false, fmt.Errorf("conflicting canonical FHS QC watermark at view %d", targetQC.Number)
		}
		return false, nil
	default:
		if currentRef.Number >= targetRef.Number || !isCanonical(currentRef.Number, currentHash) {
			return false, fmt.Errorf("prior highest FHS QC is not an exact canonical ancestor of %d/%s", targetRef.Number, targetRef.BlockHash)
		}
		return true, nil
	}
}

func validatePersistedVote(vote *hotstuff.PersistedVote) error {
	if vote == nil || vote.ViewNumber == 0 || vote.ViewID == (common.Hash{}) || vote.LeaderID == "" {
		return fmt.Errorf("invalid FHS persisted vote context")
	}
	if vote.ProposalID == (common.Hash{}) || len(vote.ProposalRef) == 0 {
		return fmt.Errorf("empty FHS vote")
	}
	if vote.ProposalRefHash != hotstuff.StateDigest(vote.ProposalRef) {
		return fmt.Errorf("FHS proposal reference digest mismatch")
	}
	ref, err := types.DecodeHotstuffProposalRef(vote.ProposalRef)
	if err != nil {
		return fmt.Errorf("decode FHS vote proposal ref: %w", err)
	}
	if ref.ProposalID() != vote.ProposalID || ref.ViewNumber != vote.ViewNumber || ref.ViewID != vote.ViewID || ref.LeaderID != vote.LeaderID {
		return fmt.Errorf("FHS vote proposal context mismatch")
	}
	return nil
}

// validateFHSProposalCommitments validates every sidecar commitment without
// mutating the live proposal caches. Recovery uses this during its staging
// phase so a corrupt suffix cannot partially publish an earlier prefix.
func validateFHSProposalCommitments(ref *types.HotstuffProposalRef, encodedBlock, extra, encodedParentQC []byte) (*types.Block, error) {
	return validateFHSProposalCommitmentsForConfig(nil, ref, encodedBlock, extra, encodedParentQC)
}

func validateFHSProposalCommitmentsForConfig(config *params.ChainConfig, ref *types.HotstuffProposalRef, encodedBlock, extra, encodedParentQC []byte) (*types.Block, error) {
	if ref == nil {
		return nil, fmt.Errorf("nil FHS proposal reference")
	}
	if len(encodedBlock) == 0 || len(encodedBlock) > proposalBodyLimitForConfig(config) {
		return nil, fmt.Errorf("invalid FHS proposal body size: %d", len(encodedBlock))
	}
	if len(extra) > proposalBodyControlMaxBytes || len(encodedParentQC) > proposalBodyControlMaxBytes-len(extra) {
		return nil, fmt.Errorf("FHS proposal proof exceeds %d bytes", proposalBodyControlMaxBytes)
	}
	if ref.ExtraHash != types.HotstuffProposalExtraHash(extra) {
		return nil, fmt.Errorf("FHS proposal extra commitment mismatch")
	}
	parentQCID, err := proposalBodyParentQCID(encodedParentQC)
	if err != nil {
		return nil, fmt.Errorf("decode FHS proposal parent QC: %w", err)
	}
	if ref.ParentQCID != parentQCID {
		return nil, fmt.Errorf("FHS proposal parent QC commitment mismatch")
	}
	block := types.DecodeToBlock(encodedBlock)
	if block == nil {
		return nil, fmt.Errorf("decode FHS proposal block")
	}
	if err := ref.VerifyAgainstBlock(block, encodedBlock); err != nil {
		return nil, err
	}
	return block, nil
}

// persistFHSProposalData stores reconstructable proposal data once, outside the
// synchronous safety WAL. Losing this record affects liveness only: LastVote
// still prevents equivocation and the compact DA repair path can fetch the
// body again by its signed proposal reference.
func (s *Service) persistFHSProposalData(ref *types.HotstuffProposalRef, body *proposalBodyMsg) error {
	if s == nil || s.fhsStore == nil || s.fhsStore.db == nil || ref == nil || body == nil {
		return nil
	}
	record := &fhsDiskProposal{
		ProposalID:  ref.ProposalID(),
		ProposalRef: append([]byte(nil), ref.EncodeToBytes()...),
		Extra:       append([]byte(nil), body.Extra...),
		ParentQC:    append([]byte(nil), body.ParentQC...),
	}
	bodyRecord := &fhsDiskBody{BodyHash: ref.BodyHash, EncodedBlock: append([]byte(nil), body.EncodedBlock...)}
	encodedProposal, err := rlp.EncodeToBytes(record)
	if err != nil {
		return err
	}
	encodedBody, err := rlp.EncodeToBytes(bodyRecord)
	if err != nil {
		return err
	}
	store := s.fhsStore
	store.contentMu.Lock()
	existingProposal, err := rawdb.ReadFHSProposal(store.db, record.ProposalID)
	if err != nil {
		store.contentMu.Unlock()
		return err
	}
	if len(existingProposal) > 0 && !bytes.Equal(existingProposal, encodedProposal) {
		store.contentMu.Unlock()
		return fmt.Errorf("conflicting durable FHS proposal data for %s", record.ProposalID)
	}
	existingBody, err := rawdb.ReadFHSBody(store.db, ref.BodyHash)
	if err != nil {
		store.contentMu.Unlock()
		return err
	}
	if len(existingBody) > 0 && !bytes.Equal(existingBody, encodedBody) {
		store.contentMu.Unlock()
		return fmt.Errorf("conflicting durable FHS body data for %s", ref.BodyHash)
	}
	if len(existingProposal) > 0 && len(existingBody) > 0 {
		store.contentMu.Unlock()
		return nil
	}
	batch := store.db.NewBatch()
	if len(existingBody) == 0 {
		if err := rawdb.WriteFHSBody(batch, ref.BodyHash, encodedBody); err != nil {
			store.contentMu.Unlock()
			return err
		}
	}
	if len(existingProposal) == 0 {
		if err := rawdb.WriteFHSProposal(batch, record.ProposalID, encodedProposal); err != nil {
			store.contentMu.Unlock()
			return err
		}
	}
	if err := batch.Write(); err != nil {
		store.contentMu.Unlock()
		return err
	}
	store.proposalWritesSincePrune++
	shouldPrune := store.proposalWritesSincePrune >= fhsPersistencePruneWriteInterval
	store.contentMu.Unlock()
	if shouldPrune {
		if err := s.pruneFHSPersistenceAtCurrentHead(); err != nil {
			// Proposal durability is already complete. GC failure must not reject a
			// valid proposal or turn local maintenance into a consensus fault.
			log.Warn("Failed to prune durable FHS recovery cache", "err", err)
		}
	}
	return nil
}

// readFHSDurableProposalBody resolves an exact content-addressed proposal from
// its ProposalID. The disk record is not trusted: both the canonical
// ProposalRef and the full body/proof commitments are revalidated before the
// bytes may be used for recovery or served to a repair peer.
func (s *Service) readFHSDurableProposalBody(proposalID common.Hash) (*types.HotstuffProposalRef, *proposalBodyMsg, bool, error) {
	if proposalID == (common.Hash{}) || s == nil || s.fhsStore == nil || s.fhsStore.db == nil {
		return nil, nil, false, fmt.Errorf("FHS safety store not initialized")
	}
	store := s.fhsStore
	store.contentMu.Lock()
	defer store.contentMu.Unlock()
	encoded, err := rawdb.ReadFHSProposal(store.db, proposalID)
	if err != nil {
		return nil, nil, false, err
	}
	if len(encoded) == 0 {
		return nil, nil, false, nil
	}
	var proposal fhsDiskProposal
	if err := rlp.DecodeBytes(encoded, &proposal); err != nil {
		return nil, nil, true, fmt.Errorf("decode persisted FHS proposal %s: %w", proposalID, err)
	}
	ref, err := types.DecodeHotstuffProposalRef(proposal.ProposalRef)
	if err != nil {
		return nil, nil, true, fmt.Errorf("decode persisted FHS proposal reference %s: %w", proposalID, err)
	}
	if proposal.ProposalID != proposalID || ref.ProposalID() != proposalID || ref.ChainID != store.chainID {
		return nil, nil, true, fmt.Errorf("persisted FHS proposal record mismatch")
	}
	encodedBody, err := rawdb.ReadFHSBody(store.db, ref.BodyHash)
	if err != nil {
		return nil, nil, true, err
	}
	if len(encodedBody) == 0 {
		return ref, nil, false, nil
	}
	var bodyRecord fhsDiskBody
	if err := rlp.DecodeBytes(encodedBody, &bodyRecord); err != nil || bodyRecord.BodyHash != ref.BodyHash {
		return nil, nil, true, fmt.Errorf("invalid persisted FHS body %s", ref.BodyHash)
	}
	if _, err := validateFHSProposalCommitmentsForConfig(s.chainConfig, ref, bodyRecord.EncodedBlock, proposal.Extra, proposal.ParentQC); err != nil {
		return nil, nil, true, fmt.Errorf("invalid persisted FHS proposal: %w", err)
	}
	return ref, &proposalBodyMsg{
		Type:              proposalBodyMsgManifest,
		ProposalID:        proposal.ProposalID,
		BodyHash:          ref.BodyHash,
		BodySize:          ref.BodySize,
		Number:            ref.Number,
		ViewNumber:        ref.ViewNumber,
		ViewID:            ref.ViewID,
		LeaderID:          ref.LeaderID,
		From:              ref.LeaderID,
		ProposalKeyHash:   ref.KeyHash,
		EncodedBlock:      append([]byte(nil), bodyRecord.EncodedBlock...),
		Extra:             append([]byte(nil), proposal.Extra...),
		ParentQC:          append([]byte(nil), proposal.ParentQC...),
		CreatedAtUnixNano: 1,
	}, true, nil
}

// validateRestoredFHSVote fails closed for an invalid vote watermark or an
// altered proposal record. A missing proposal record is recoverable through DA
// and does not invalidate the already durable anti-equivocation watermark.
func (s *Service) readFHSProposalBody(ref *types.HotstuffProposalRef) (*proposalBodyMsg, bool, error) {
	if ref == nil {
		return nil, false, fmt.Errorf("nil FHS proposal reference")
	}
	storedRef, body, found, err := s.readFHSDurableProposalBody(ref.ProposalID())
	if err != nil || !found {
		return body, found, err
	}
	if storedRef == nil || !bytes.Equal(storedRef.EncodeToBytes(), ref.EncodeToBytes()) {
		return nil, true, fmt.Errorf("persisted FHS proposal reference mismatch")
	}
	return body, true, nil
}

func (s *Service) restoredFHSVoteProposal(vote *hotstuff.PersistedVote) (*proposalBodyMsg, error) {
	if vote == nil {
		return nil, nil
	}
	if err := validatePersistedVote(vote); err != nil {
		return nil, err
	}
	if s.fhsStore == nil || s.fhsStore.db == nil {
		return nil, fmt.Errorf("FHS safety store not initialized")
	}
	ref, err := types.DecodeHotstuffProposalRef(vote.ProposalRef)
	if err != nil {
		return nil, fmt.Errorf("decode persisted FHS vote proposal: %w", err)
	}
	if ref.ChainID != s.ChainID() || ref.ViewNumber != vote.ViewNumber || ref.ViewID != vote.ViewID || ref.LeaderID != vote.LeaderID {
		return nil, fmt.Errorf("persisted FHS vote proposal context mismatch")
	}
	body, found, err := s.readFHSProposalBody(ref)
	if err != nil {
		return nil, err
	}
	if !found {
		// The safety watermark remains sufficient to reject equivocation. Proposal
		// data is content-addressed and may be repaired after restart.
		return nil, nil
	}
	return body, nil
}

func (s *Service) validateRestoredFHSVote(vote *hotstuff.PersistedVote) error {
	_, err := s.restoredFHSVoteProposal(vote)
	return err
}

func (s *Service) installRestoredFHSVoteProposal(body *proposalBodyMsg) error {
	if body == nil {
		return nil
	}
	restored := cloneProposalBodyMsg(body)
	restored.Type = proposalBodyMsgManifest
	if restored.From == "" {
		restored.From = restored.LeaderID
	}
	restored.CreatedAtUnixNano = time.Now().UnixNano()
	if err := s.storeProposalBody(restored); err != nil {
		return fmt.Errorf("install persisted FHS vote proposal: %w", err)
	}
	return nil
}

func (s *Service) PersistFHSVote(vote *hotstuff.PersistedVote) error {
	if !s.fairHotstuffEnabled() {
		return nil
	}
	if err := validatePersistedVote(vote); err != nil {
		return err
	}
	if s.fhsStore == nil {
		return fmt.Errorf("FHS safety store not initialized")
	}

	ref, err := types.DecodeHotstuffProposalRef(vote.ProposalRef)
	if err != nil {
		return fmt.Errorf("decode FHS vote proposal ref: %w", err)
	}
	if ref.ChainID != s.ChainID() {
		return fmt.Errorf("FHS vote proposal chain mismatch")
	}

	store := s.fhsStore
	store.safetyMu.Lock()
	defer store.safetyMu.Unlock()
	if err := store.loadLocked(); err != nil {
		return err
	}
	if store.recoveryPendingLocked() {
		return errFHSRecoveryPending
	}
	if store.state.LastTimeoutView >= vote.ViewNumber ||
		(store.state.LastTimeoutVote != nil && store.state.LastTimeoutVote.TimedOutView >= vote.ViewNumber) {
		return fmt.Errorf("refusing vote in timed-out view %d", vote.ViewNumber)
	}
	if previous := store.state.LastVote; previous != nil {
		if vote.ViewNumber < previous.ViewNumber {
			return fmt.Errorf("refusing stale vote %d after %d", vote.ViewNumber, previous.ViewNumber)
		}
		if vote.ViewNumber == previous.ViewNumber {
			if !persistedVotesEqual(previous, vote) {
				return fmt.Errorf("refusing conflicting vote in view %d", vote.ViewNumber)
			}
			return nil
		}
	}
	if highest := store.state.HighestQC; highest != nil && vote.ViewNumber <= highest.Number {
		return fmt.Errorf("refusing vote at or below certified QC view %d", highest.Number)
	}

	next := hotstuff.CloneFHSSafetyState(store.state)
	next.LastVote = hotstuff.ClonePersistedVote(vote)
	encodedSafety, err := store.encodeSafety(next, store.highestBlockHash)
	if err != nil {
		return err
	}
	batch := store.db.NewBatch()
	if err := rawdb.WriteFHSSafetyState(batch, encodedSafety); err != nil {
		return err
	}
	if err := writeFHSBatchSync(batch); err != nil {
		store.lastPersistenceErr = err
		return err
	}
	store.state = next
	return nil
}

func (s *Service) PersistFHSTimeoutVote(statement *hotstuff.TimeoutStatement) error {
	if !s.fairHotstuffEnabled() {
		return nil
	}
	if statement == nil || statement.ChainID != s.ChainID() {
		return fmt.Errorf("invalid FHS timeout vote")
	}
	if _, err := hotstuff.TimeoutStatementDigest(statement); err != nil {
		return err
	}
	store := s.fhsStore
	if store == nil {
		return fmt.Errorf("FHS safety store not initialized")
	}
	store.safetyMu.Lock()
	defer store.safetyMu.Unlock()
	if err := store.loadLocked(); err != nil {
		return err
	}
	if store.recoveryPendingLocked() {
		return errFHSRecoveryPending
	}
	if statement.TimedOutView <= store.state.LastTimeoutView {
		return fmt.Errorf("refusing timeout vote at or below certified timeout view %d", store.state.LastTimeoutView)
	}
	if highest := store.state.HighestQC; highest != nil && statement.TimedOutView <= highest.Number {
		return fmt.Errorf("refusing timeout vote at or below certified QC view %d", highest.Number)
	}
	if previous := store.state.LastTimeoutVote; previous != nil {
		if statement.TimedOutView < previous.TimedOutView {
			return fmt.Errorf("refusing stale timeout vote %d after %d", statement.TimedOutView, previous.TimedOutView)
		}
		if statement.TimedOutView == previous.TimedOutView {
			if *statement != *previous {
				return fmt.Errorf("refusing conflicting timeout vote in view %d", statement.TimedOutView)
			}
			return nil
		}
	}
	next := hotstuff.CloneFHSSafetyState(store.state)
	statementCopy := *statement
	next.LastTimeoutVote = &statementCopy
	encoded, err := store.encodeSafety(next, store.highestBlockHash)
	if err != nil {
		return err
	}
	batch := store.db.NewBatch()
	if err := rawdb.WriteFHSSafetyState(batch, encoded); err != nil {
		return err
	}
	if err := writeFHSBatchSync(batch); err != nil {
		store.lastPersistenceErr = err
		return err
	}
	store.state = next
	return nil
}

// rotateFHSEpochSafety removes committee-specific timeout messages before a
// certified key-block transition becomes canonical. LastVote is deliberately
// retained: it is the global no-double-vote watermark, so the replica must not
// sign a different proposal in the same numeric view under the new epoch. The
// new committee can still form a timeout certificate for that view and move
// every replica forward together.
func (s *Service) rotateFHSEpochSafety(nextKeyHash common.Hash) error {
	if nextKeyHash == (common.Hash{}) {
		return fmt.Errorf("empty Fair HotStuff epoch key hash")
	}
	store := s.fhsStore
	if store == nil {
		return fmt.Errorf("FHS safety store not initialized")
	}
	store.safetyMu.Lock()
	defer store.safetyMu.Unlock()
	if err := store.loadLocked(); err != nil {
		return err
	}
	next := hotstuff.CloneFHSSafetyState(store.state)
	changed := false
	if next.LastTimeoutVote != nil && next.LastTimeoutVote.KeyHash != nextKeyHash {
		next.LastTimeoutVote = nil
		changed = true
	}
	if next.HighestTC != nil && next.HighestTC.Statement.KeyHash != nextKeyHash {
		if next.LastTimeoutView != next.HighestTC.Statement.TimedOutView {
			return fmt.Errorf("persisted FHS timeout certificate metadata mismatch")
		}
		next.HighestTC = nil
		next.LastTimeoutView = 0
		changed = true
	} else if next.HighestTC == nil && next.LastTimeoutView != 0 {
		return fmt.Errorf("persisted FHS timeout view has no certificate")
	}
	if !changed {
		return nil
	}
	encoded, err := store.encodeSafety(next, store.highestBlockHash)
	if err != nil {
		return err
	}
	batch := store.db.NewBatch()
	if err := rawdb.WriteFHSSafetyState(batch, encoded); err != nil {
		return err
	}
	if err := writeFHSBatchSync(batch); err != nil {
		store.lastPersistenceErr = err
		return err
	}
	store.state = next
	return nil
}

// reconcileFHSCanonicalQCWatermark advances the durable high-QC pointer to a
// block which the proof-aware full-sync importer has already made canonical.
// The block's own QC is only a safety watermark here; its verified child QC is
// what authorized the canonical commit. Gaps are safe only when the previous
// durable QC names an exact ancestor on the current canonical chain.
func (s *Service) reconcileFHSCanonicalQCWatermark(block *types.Block, ownQC *hotstuff.SignedState) error {
	if s == nil || s.bc == nil || s.fhsStore == nil || block == nil || ownQC == nil {
		return fmt.Errorf("incomplete canonical FHS QC reconciliation input")
	}
	canonical := s.bc.GetBlockByNumber(block.NumberU64())
	if canonical == nil || canonical.Hash() != block.Hash() || s.bc.GetCanonicalHash(block.NumberU64()) != block.Hash() {
		return fmt.Errorf("FHS QC watermark target is not exact canonical block %d/%s", block.NumberU64(), block.Hash())
	}
	targetRef, targetQC, err := s.bc.ReconstructFHSQC(canonical)
	if err != nil {
		return fmt.Errorf("reconstruct canonical FHS QC watermark: %w", err)
	}
	if !hotstuff.SignedStateSemanticEqual(targetQC, ownQC) {
		return fmt.Errorf("canonical FHS QC watermark differs from verified sync target")
	}
	verifiedRef, err := s.verifyFHSQCCryptographic(targetQC)
	if err != nil {
		return fmt.Errorf("verify canonical FHS QC watermark: %w", err)
	}
	if verifiedRef.BlockHash != canonical.Hash() || verifiedRef.Number != canonical.NumberU64() ||
		targetRef.BlockHash != verifiedRef.BlockHash || targetRef.Number != verifiedRef.Number {
		return fmt.Errorf("canonical FHS QC watermark proposal does not identify its exact block")
	}

	store := s.fhsStore
	store.safetyMu.Lock()
	defer store.safetyMu.Unlock()
	if err := store.loadLocked(); err != nil {
		return err
	}
	if store.state == nil {
		return fmt.Errorf("missing durable FHS safety state")
	}
	currentQC := store.state.HighestQC
	currentHash := store.highestBlockHash
	if store.pendingBroadcast != nil && (currentQC == nil || !hotstuff.SignedStateSemanticEqual(store.pendingBroadcast, currentQC)) {
		return fmt.Errorf("pending FHS QC broadcast does not match the highest certificate")
	}
	advance, err := validateCanonicalFHSQCAdvance(
		currentQC,
		currentHash,
		targetRef,
		targetQC,
		canonical.Hash(),
		s.verifyFHSQCCryptographic,
		func(number uint64, hash common.Hash) bool { return s.bc.GetCanonicalHash(number) == hash },
	)
	if err != nil {
		return err
	}
	if currentQC != nil && currentQC.Number > targetQC.Number {
		// Never lower a valid uncommitted high QC during canonical repair.
		return nil
	}

	next := hotstuff.CloneFHSSafetyState(store.state)
	if advance {
		next.HighestQC = hotstuff.CloneSignedState(targetQC)
	}
	changedTimeout, err := clearSupersededFHSTimeouts(next)
	if err != nil {
		return err
	}
	nextPending := hotstuff.CloneSignedState(store.pendingBroadcast)
	pendingChanged := false
	if nextPending != nil {
		switch {
		case nextPending.Number < targetQC.Number:
			nextPending = nil
			pendingChanged = true
		case nextPending.Number == targetQC.Number:
			if !hotstuff.SignedStateSemanticEqual(nextPending, targetQC) {
				return fmt.Errorf("conflicting pending FHS QC broadcast at canonical view %d", targetQC.Number)
			}
			nextPending = nil
			pendingChanged = true
		}
	}
	if !advance && !changedTimeout && !pendingChanged {
		return nil
	}
	encoded, err := store.encodeSafetyWithPending(next, canonical.Hash(), nextPending)
	if err != nil {
		return err
	}
	batch := store.db.NewBatch()
	if err := rawdb.WriteFHSSafetyState(batch, encoded); err != nil {
		return err
	}
	if err := writeFHSBatchSync(batch); err != nil {
		store.lastPersistenceErr = err
		return err
	}
	store.state = next
	store.highestBlockHash = canonical.Hash()
	store.pendingBroadcast = nextPending
	return nil
}

func (s *Service) persistFHSCertificate(ref *types.HotstuffProposalRef, qc *hotstuff.SignedState, body *proposalBodyMsg, extra []byte) error {
	return s.persistFHSCertificateWithBroadcast(ref, qc, body, extra, false)
}

func (s *Service) persistFHSCertificateWithBroadcast(ref *types.HotstuffProposalRef, qc *hotstuff.SignedState, body *proposalBodyMsg, extra []byte, pendingBroadcast bool) error {
	if s.fhsStore == nil || ref == nil || qc == nil || body == nil {
		return fmt.Errorf("incomplete FHS certificate persistence input")
	}
	if !bytes.Equal(qc.State, ref.EncodeToBytes()) || qc.Number != ref.ViewNumber || qc.ViewID != ref.ViewID || qc.LeaderID != ref.LeaderID {
		return fmt.Errorf("FHS certificate does not match proposal reference")
	}
	if !bytes.Equal(body.Extra, extra) {
		return fmt.Errorf("FHS certificate extra does not match proposal sidecar")
	}
	if _, err := validateFHSProposalCommitmentsForConfig(s.chainConfig, ref, body.EncodedBlock, extra, body.ParentQC); err != nil {
		return fmt.Errorf("invalid FHS certificate proposal body: %w", err)
	}
	return s.persistValidatedFHSCertificateWithBroadcast(ref, qc, pendingBroadcast)
}

// persistValidatedFHSCertificateWithBroadcast is the small serialized safety
// publication step. Its caller owns a private fhsHighQCValidationOutput whose
// body commitment, parent proof and EVM result were already validated by a
// bounded worker. Re-decoding/hashing up to 8 MiB here would put the same
// head-of-line stall back into the HotStuff control loop.
func (s *Service) persistValidatedFHSCertificateWithBroadcast(ref *types.HotstuffProposalRef, qc *hotstuff.SignedState, pendingBroadcast bool) error {
	if s == nil || s.fhsStore == nil || ref == nil || qc == nil {
		return fmt.Errorf("incomplete validated FHS certificate persistence input")
	}
	if !bytes.Equal(qc.State, ref.EncodeToBytes()) || qc.Number != ref.ViewNumber || qc.ViewID != ref.ViewID || qc.LeaderID != ref.LeaderID {
		return fmt.Errorf("validated FHS certificate does not match proposal reference")
	}
	certificate := &fhsDiskCertificate{
		ProposalID: ref.ProposalID(),
		QC:         hotstuff.CloneSignedState(qc),
	}
	encodedCertificate, err := rlp.EncodeToBytes(certificate)
	if err != nil {
		return err
	}

	store := s.fhsStore
	store.safetyMu.Lock()
	defer store.safetyMu.Unlock()
	if err := store.loadLocked(); err != nil {
		return err
	}
	if highest := store.state.HighestQC; highest != nil {
		if qc.Number < highest.Number {
			// Startup content repair reconstructs the certified in-memory prefix
			// below an already durable HighestQC. Never move the safety watermark
			// backwards; accept only an exact certificate that is already present
			// in the same WAL and only while that HighestQC recovery gate is held.
			if !store.recoveryPendingLocked() || store.deferredRecovery.HighestQC == nil ||
				!hotstuff.SignedStateSemanticEqual(store.deferredRecovery.HighestQC, highest) {
				return fmt.Errorf("refusing to persist lower FHS QC view %d after %d", qc.Number, highest.Number)
			}
			encodedExisting, err := rawdb.ReadFHSCertificate(store.db, ref.BlockHash)
			if err != nil {
				return fmt.Errorf("read deferred FHS prefix certificate %s: %w", ref.BlockHash, err)
			}
			if len(encodedExisting) == 0 {
				return fmt.Errorf("missing deferred FHS prefix certificate %s", ref.BlockHash)
			}
			var existing fhsDiskCertificate
			if err := rlp.DecodeBytes(encodedExisting, &existing); err != nil || existing.ProposalID != ref.ProposalID() ||
				!hotstuff.SignedStateSemanticEqual(existing.QC, qc) {
				return fmt.Errorf("deferred FHS prefix certificate mismatch for %s", ref.BlockHash)
			}
			return nil
		}
		if qc.Number == highest.Number {
			if !hotstuff.SignedStateSemanticEqual(qc, highest) || store.highestBlockHash != ref.BlockHash {
				return fmt.Errorf("refusing conflicting FHS QC at view %d", qc.Number)
			}
		} else {
			highestRef, err := types.DecodeHotstuffProposalRef(highest.State)
			if err != nil {
				return fmt.Errorf("decode persisted highest FHS QC: %w", err)
			}
			if ref.ParentHash != highestRef.BlockHash || ref.Number != highestRef.Number+1 {
				return fmt.Errorf("refusing non-contiguous higher FHS QC at view %d", qc.Number)
			}
		}
	}
	next := hotstuff.CloneFHSSafetyState(store.state)
	next.HighestQC = hotstuff.CloneSignedState(qc)
	// Persist timeout cleanup in the same synchronous batch as the QC so a
	// crash cannot leave an obsolete TC tied to an inactive committee.
	if _, err := clearSupersededFHSTimeouts(next); err != nil {
		return err
	}
	nextPending := hotstuff.CloneSignedState(store.pendingBroadcast)
	if pendingBroadcast {
		nextPending = hotstuff.CloneSignedState(qc)
	} else if nextPending != nil && qc.Number > nextPending.Number {
		// A higher QC proves that a quorum validated a proposal extending the
		// prior QC, so the older leader outbox no longer needs restart replay.
		nextPending = nil
	}
	encodedSafety, err := store.encodeSafetyWithPending(next, ref.BlockHash, nextPending)
	if err != nil {
		return err
	}
	batch := store.db.NewBatch()
	if err := rawdb.WriteFHSCertificate(batch, ref.BlockHash, encodedCertificate); err != nil {
		return err
	}
	if err := rawdb.WriteFHSSafetyState(batch, encodedSafety); err != nil {
		return err
	}
	if err := writeFHSBatchSync(batch); err != nil {
		store.lastPersistenceErr = err
		return err
	}
	store.state = next
	store.highestBlockHash = ref.BlockHash
	store.pendingBroadcast = nextPending
	return nil
}

func (s *Service) HighestFHSTimeoutCertificate() *hotstuff.TimeoutCertificate {
	if s.fhsStore == nil {
		return nil
	}
	state, _, err := s.fhsStore.snapshot()
	if err != nil || state == nil {
		return nil
	}
	return hotstuff.CloneTimeoutCertificate(state.HighestTC)
}

func (s *Service) pendingFHSQCBroadcast() (*hotstuff.SignedState, error) {
	if s.fhsStore == nil {
		return nil, nil
	}
	pending, err := s.fhsStore.pendingBroadcastSnapshot()
	if err != nil || pending == nil {
		return pending, err
	}
	if _, err := s.verifyFHSQCCryptographic(pending); err != nil {
		return nil, fmt.Errorf("invalid pending FHS QC broadcast: %w", err)
	}
	if pending.LeaderID != s.Self() {
		return nil, fmt.Errorf("pending FHS QC broadcast belongs to another leader")
	}
	return pending, nil
}

// preparePendingFHSQCBroadcastReplay resolves and authenticates the durable
// outbox entry without touching the network. Lifecycle-aware callers can do
// this while holding their local activation boundary, then release it before
// the physical committee broadcast.
func (s *Service) preparePendingFHSQCBroadcastReplay() (*hotstuff.SignedState, *hotstuff.HotstuffMessage, error) {
	if !s.fairHotstuffEnabled() || !s.isRunning() {
		return nil, nil, nil
	}
	pending, err := s.pendingFHSQCBroadcast()
	if err != nil {
		return nil, nil, err
	}
	if pending == nil {
		return nil, nil, nil
	}
	if s.fhsQCBroadcastReplaySuppressed(pending, time.Now()) {
		log.Debug("suppress immediate durable FHS QC replay for matching broadcast", "number", pending.Number, "viewID", pending.ViewID)
		return nil, nil, nil
	}
	msg, err := s.protocolMng.RebuildFHSQCBroadcast(pending)
	if err != nil {
		return nil, nil, fmt.Errorf("rebuild durable FHS QC broadcast for view %d: %w", pending.Number, err)
	}
	return pending, msg, nil
}

func (s *Service) broadcastPreparedFHSQCBroadcast(pending *hotstuff.SignedState, msg *hotstuff.HotstuffMessage) {
	if pending == nil || msg == nil {
		return
	}
	if errs := s.broadcastHotstuffToCommittee(msg); len(errs) > 0 {
		log.Warn("durable FHS QC broadcast queued with delivery errors", "number", pending.Number, "errors", len(errs))
	} else {
		log.Info("replayed durable FHS QC broadcast", "number", pending.Number, "viewID", pending.ViewID)
	}
}

func (s *Service) replayPendingFHSQCBroadcast() {
	pending, msg, err := s.preparePendingFHSQCBroadcastReplay()
	if err != nil {
		log.Error("cannot replay durable FHS QC broadcast", "err", err)
		return
	}
	s.broadcastPreparedFHSQCBroadcast(pending, msg)
}

func (s *Service) hasPendingFHSTimeoutVote() bool {
	if s.fhsStore == nil {
		return false
	}
	state, _, err := s.fhsStore.snapshot()
	if err != nil || state == nil || state.LastTimeoutVote == nil {
		return false
	}
	current := s.GetCurrentView()
	return state.LastTimeoutVote.TimedOutView == current.ViewNumber+1
}

func fhsRecoveryBaseView(currentView uint64, state *hotstuff.FHSSafetyState) uint64 {
	baseView := currentView
	if state == nil {
		return baseView
	}
	if state.HighestQC != nil && state.HighestQC.Number > baseView {
		baseView = state.HighestQC.Number
	}
	if state.HighestTC != nil && state.HighestTC.Statement.TimedOutView > baseView {
		baseView = state.HighestTC.Statement.TimedOutView
	}
	return baseView
}

// validateFHSTimeoutState validates persisted timeout safety data without
// mutating the live pacemaker. Recovery publishes the resulting view only
// after every WAL certificate and sidecar has also passed validation.
func (s *Service) validateFHSTimeoutState(state *hotstuff.FHSSafetyState) (uint64, error) {
	current := s.GetCurrentView()
	targetView := fhsRecoveryBaseView(current.ViewNumber, state)
	if state == nil {
		return targetView, nil
	}
	if state.LastTimeoutVote != nil {
		if state.LastTimeoutVote.ChainID != s.ChainID() {
			return 0, fmt.Errorf("persisted FHS timeout vote belongs to another chain")
		}
		if _, err := hotstuff.TimeoutStatementDigest(state.LastTimeoutVote); err != nil {
			return 0, fmt.Errorf("invalid persisted FHS timeout vote: %w", err)
		}
		if state.LastTimeoutVote.KeyNumber != current.KeyNumber || state.LastTimeoutVote.KeyHash != current.KeyHash || state.LastTimeoutVote.CommitteeHash != current.CommitteeHash {
			return 0, fmt.Errorf("persisted FHS timeout vote has inactive committee")
		}
		keys, err := s.GetPublicKey(state.LastTimeoutVote.KeyHash)
		if err != nil {
			return 0, err
		}
		if err := hotstuff.ValidateBFTCommitteeSize(len(keys)); err != nil {
			return 0, err
		}
		if state.LastTimeoutVote.TimedOutView != targetView+1 || state.LastTimeoutVote.TimedOutView <= state.LastTimeoutView {
			return 0, fmt.Errorf("persisted FHS timeout vote is not the active pending view")
		}
	}
	if state.HighestTC == nil {
		if state.LastTimeoutView != 0 {
			return 0, fmt.Errorf("persisted FHS timeout view has no certificate")
		}
		return targetView, nil
	}
	statement := &state.HighestTC.Statement
	if state.LastTimeoutView != statement.TimedOutView || statement.ChainID != s.ChainID() {
		return 0, fmt.Errorf("persisted FHS timeout certificate metadata mismatch")
	}
	keys, err := s.GetPublicKey(statement.KeyHash)
	if err != nil {
		return 0, err
	}
	if err := hotstuff.ValidateBFTCommitteeSize(len(keys)); err != nil {
		return 0, err
	}
	if err := hotstuff.VerifyTimeoutCertificate(state.HighestTC, keys, hotstuff.CalcThreshold(len(keys))); err != nil {
		return 0, fmt.Errorf("invalid persisted FHS timeout certificate: %w", err)
	}
	if statement.KeyNumber != current.KeyNumber || statement.KeyHash != current.KeyHash || statement.CommitteeHash != current.CommitteeHash {
		return 0, fmt.Errorf("persisted FHS timeout certificate has inactive committee")
	}
	return targetView, nil
}

// reconcileFHSTimeoutEpoch removes timeout-only WAL records that belong to a
// canonical historical key epoch after passive full sync has advanced the key
// chain. A timeout statement is committee-specific, unlike LastVote and
// HighestQC, so carrying it into the new epoch makes an otherwise valid restart
// fail with an inactive-committee error. We only rotate records whose exact key
// block is still in canonical history; same-height siblings, future epochs and
// malformed certificates remain fail-closed.
func (s *Service) reconcileFHSTimeoutEpoch(state *hotstuff.FHSSafetyState, highestHash common.Hash) (*hotstuff.FHSSafetyState, error) {
	if state == nil {
		return nil, nil
	}
	current := s.GetCurrentView()
	if current == nil || current.KeyHash == (common.Hash{}) {
		return nil, fmt.Errorf("cannot reconcile FHS timeout WAL without an active key epoch")
	}

	validateEpoch := func(statement *hotstuff.TimeoutStatement) (bool, error) {
		if statement == nil {
			return false, nil
		}
		if statement.ChainID != s.ChainID() {
			return false, fmt.Errorf("persisted FHS timeout statement belongs to another chain")
		}
		if _, err := hotstuff.TimeoutStatementDigest(statement); err != nil {
			return false, fmt.Errorf("invalid persisted FHS timeout statement: %w", err)
		}
		if statement.KeyNumber == current.KeyNumber && statement.KeyHash == current.KeyHash && statement.CommitteeHash == current.CommitteeHash {
			return false, nil
		}
		if statement.KeyNumber >= current.KeyNumber {
			return false, fmt.Errorf("persisted FHS timeout statement has a non-historical inactive committee")
		}
		keyBlock := s.kbc.GetBlockByNumber(statement.KeyNumber)
		if keyBlock == nil || keyBlock.Hash() != statement.KeyHash || keyBlock.CommitteeHash() != statement.CommitteeHash {
			return false, fmt.Errorf("persisted FHS timeout statement does not match canonical key history")
		}
		keys, err := s.GetPublicKey(statement.KeyHash)
		if err != nil {
			return false, err
		}
		if err := hotstuff.ValidateBFTCommitteeSize(len(keys)); err != nil {
			return false, err
		}
		return true, nil
	}

	staleVote, err := validateEpoch(state.LastTimeoutVote)
	if err != nil {
		return nil, err
	}
	if state.HighestTC == nil {
		if state.LastTimeoutView != 0 {
			return nil, fmt.Errorf("persisted FHS timeout view has no certificate")
		}
	} else {
		statement := &state.HighestTC.Statement
		if state.LastTimeoutView != statement.TimedOutView {
			return nil, fmt.Errorf("persisted FHS timeout certificate metadata mismatch")
		}
		keys, err := s.GetPublicKey(statement.KeyHash)
		if err != nil {
			return nil, err
		}
		if err := hotstuff.ValidateBFTCommitteeSize(len(keys)); err != nil {
			return nil, err
		}
		if err := hotstuff.VerifyTimeoutCertificate(state.HighestTC, keys, hotstuff.CalcThreshold(len(keys))); err != nil {
			return nil, fmt.Errorf("invalid persisted FHS timeout certificate: %w", err)
		}
	}
	var timeoutCertificateStatement *hotstuff.TimeoutStatement
	if state.HighestTC != nil {
		timeoutCertificateStatement = &state.HighestTC.Statement
	}
	staleTC, err := validateEpoch(timeoutCertificateStatement)
	if err != nil {
		return nil, err
	}
	if !staleVote && !staleTC {
		return state, nil
	}
	if err := s.rotateFHSEpochSafety(current.KeyHash); err != nil {
		return nil, fmt.Errorf("rotate historical FHS timeout WAL: %w", err)
	}
	refreshed, refreshedHighest, err := s.fhsStore.recoverySnapshot()
	if err != nil {
		return nil, err
	}
	if refreshedHighest != highestHash {
		return nil, fmt.Errorf("FHS timeout epoch rotation altered the highest certificate pointer")
	}
	return refreshed, nil
}

func (s *Service) applyFHSRecoveredView(targetView uint64) {
	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()
	if targetView <= s.currentView.ViewNumber {
		return
	}
	s.currentView.ViewNumber = targetView
	s.currentView.LeaderIndex = s.fairHotstuffLeaderIndexForCurrentLocked()
	s.currentView.NoDone = true
	s.waittingView.TxNumber = s.currentView.TxNumber
	s.waittingView.KeyNumber = s.currentView.KeyNumber
}

func (s *Service) verifyFHSQCCryptographic(qc *hotstuff.SignedState) (*types.HotstuffProposalRef, error) {
	if qc == nil {
		return nil, fmt.Errorf("nil FHS QC")
	}
	ref, err := types.DecodeHotstuffProposalRef(qc.State)
	if err != nil {
		return nil, err
	}
	if ref.ChainID != s.ChainID() || ref.ViewNumber != qc.Number || ref.ViewID != qc.ViewID || ref.LeaderID != qc.LeaderID {
		return nil, fmt.Errorf("FHS QC proposal context mismatch")
	}
	keys, err := s.GetPublicKey(ref.KeyHash)
	if err != nil {
		return nil, err
	}
	threshold := hotstuff.CalcThreshold(len(keys))
	if err := hotstuff.ValidateCanonicalSignerMask(qc.Mask, len(keys), threshold); err != nil {
		return nil, err
	}
	if !hotstuff.VerifyFHSSignatureWithContext(qc.Sign, qc.Mask, qc.State, keys, threshold, s.ChainID(), hotstuff.MsgVotePrepare, qc.ViewID, qc.LeaderID) {
		return nil, fmt.Errorf("invalid FHS QC signature")
	}
	return ref, nil
}

// AdoptFHSHighQC lets a lagging replica install the highest valid certificate
// carried by an n-f NewView proof before it evaluates the child proposal.
func (s *Service) AdoptFHSHighQC(qc *hotstuff.SignedState) error {
	if err := s.adoptFHSHighQC(qc, false, false); err != nil {
		return err
	}
	return s.commitFHS2ChainForCertified(qc)
}

type fhsHighQCValidationItem struct {
	ref      *types.HotstuffProposalRef
	qc       *hotstuff.SignedState
	body     *proposalBodyMsg
	verified *core.VerifiedProposal
}

type fhsHighQCValidationOutput struct {
	key                  hotstuff.FHSHighQCValidationKey
	targetQC             *hotstuff.SignedState
	baseCanonicalHash    common.Hash
	baseHighestQCID      common.Hash
	covered              bool
	items                []fhsHighQCValidationItem
	serviceGeneration    uint64
	validationGeneration uint64
}

// classifyFHSRefAgainstCanonical distinguishes an exact finalized proposal
// from an uncommitted future proposal and a finalized-height fork. The latter
// must never be treated as covered merely because its QC is cryptographically
// valid.
func classifyFHSRefAgainstCanonical(ref *types.HotstuffProposalRef, canonicalNumber uint64, canonicalHash func(uint64) common.Hash) (exact, finalizedHeight bool, err error) {
	if ref == nil || canonicalHash == nil {
		return false, false, fmt.Errorf("incomplete FHS canonical classification")
	}
	if ref.Number > canonicalNumber {
		return false, false, nil
	}
	hash := canonicalHash(ref.Number)
	if hash == (common.Hash{}) {
		return false, true, fmt.Errorf("missing canonical FHS block at height %d", ref.Number)
	}
	return hash == ref.BlockHash, true, nil
}

func cloneVerifiedProposalForValidation(verified *core.VerifiedProposal) *core.VerifiedProposal {
	if verified == nil {
		return nil
	}
	cloned := *verified
	if verified.StateDB != nil {
		cloned.StateDB = verified.StateDB.Copy()
	}
	cloned.Receipts = append(types.Receipts(nil), verified.Receipts...)
	cloned.Logs = append([]*types.Log(nil), verified.Logs...)
	return &cloned
}

func fhsQCIdentityHash(qc *hotstuff.SignedState) (common.Hash, error) {
	if qc == nil {
		return common.Hash{}, nil
	}
	id, err := hotstuff.SignedStateID(qc)
	if err != nil {
		return common.Hash{}, err
	}
	return id.Hash(), nil
}

func (s *Service) proposalBodyForHighQCStage(ctx context.Context, ref *types.HotstuffProposalRef, serviceGeneration uint64) (*proposalBodyMsg, error) {
	// A complete in-memory body is commitment-checked before cache publication.
	// Content durability is intentionally asynchronous and is not a prerequisite
	// for QC safety: a crash before the writer completes is repaired through the
	// signed ProposalRef and BodyHash.
	body := s.getProposalBody(ref.ProposalID())
	if body != nil && len(body.EncodedBlock) > 0 {
		return body, nil
	}
	diskBody, found, err := s.readFHSProposalBody(ref)
	if err != nil {
		return nil, fmt.Errorf("read durable certified FHS proposal body: %w", err)
	}
	if found {
		return diskBody, nil
	}
	body, err = s.waitProposalBodyForValidation(ctx, ref, serviceGeneration)
	if err != nil {
		return nil, fmt.Errorf("retrieve certified FHS proposal body: %w", err)
	}
	return body, nil
}

func (s *Service) stageFHSHighQC(ctx context.Context, key hotstuff.FHSHighQCValidationKey, qc *hotstuff.SignedState, serviceGeneration, validationGeneration uint64) (*fhsHighQCValidationOutput, error) {
	if !s.fairHotstuffEnabled() {
		return &fhsHighQCValidationOutput{key: key, targetQC: hotstuff.CloneSignedState(qc), covered: true,
			serviceGeneration: serviceGeneration, validationGeneration: validationGeneration}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ref, err := s.verifyFHSQCCryptographic(qc)
	if err != nil {
		return nil, err
	}
	if key.RequestID != 0 {
		id, idErr := hotstuff.SignedStateID(qc)
		if idErr != nil || id.Hash() != key.QCID || key.TargetView <= qc.Number {
			return nil, fmt.Errorf("FHS HighQC validation key mismatch")
		}
	}
	canonical := s.bc.CurrentBlock()
	if canonical == nil {
		return nil, fmt.Errorf("cannot stage FHS HighQC without canonical head")
	}

	s.muProposalBody.RLock()
	highest := s.fhsHighest
	existing := s.fhsCertifiedByHash[ref.BlockHash]
	var highestQC *hotstuff.SignedState
	var highestRef *types.HotstuffProposalRef
	if highest != nil {
		highestQC = hotstuff.CloneSignedState(highest.qc)
		if highest.ref != nil {
			copyRef := *highest.ref
			highestRef = &copyRef
		}
	}
	s.muProposalBody.RUnlock()
	highest = fhsCertifiedFrontierAboveCanonical(highest, canonical.NumberU64())
	if highest == nil {
		highestQC = nil
		highestRef = nil
	}
	baseHighestQCID, err := fhsQCIdentityHash(highestQC)
	if err != nil {
		return nil, err
	}
	output := &fhsHighQCValidationOutput{
		key:                  key,
		targetQC:             hotstuff.CloneSignedState(qc),
		baseCanonicalHash:    canonical.Hash(),
		baseHighestQCID:      baseHighestQCID,
		serviceGeneration:    serviceGeneration,
		validationGeneration: validationGeneration,
	}
	exactCanonical, finalizedHeight, err := classifyFHSRefAgainstCanonical(ref, canonical.NumberU64(), s.bc.GetCanonicalHash)
	if err != nil {
		return nil, err
	}
	if finalizedHeight {
		if !exactCanonical {
			return nil, fmt.Errorf("FHS HighQC block %d/%s conflicts with canonical hash %s",
				ref.Number, ref.BlockHash, s.bc.GetCanonicalHash(ref.Number))
		}
		output.covered = true
		return output, nil
	}
	if existing != nil {
		if !hotstuff.SignedStateSemanticEqual(existing.qc, qc) {
			return nil, fmt.Errorf("conflicting FHS QC for block %s", ref.BlockHash)
		}
		output.covered = true
		return output, nil
	}
	if highestQC != nil {
		if qc.Number < highestQC.Number {
			output.covered = true
			return output, nil
		}
		if qc.Number == highestQC.Number {
			if hotstuff.SignedStateSemanticEqual(highestQC, qc) {
				output.covered = true
				return output, nil
			}
			return nil, fmt.Errorf("conflicting FHS QCs at view %d", qc.Number)
		}
	}

	baseHash := canonical.Hash()
	baseNumber := canonical.NumberU64()
	var baseVerified *core.VerifiedProposal
	if highestRef != nil {
		baseHash = highestRef.BlockHash
		baseNumber = highestRef.Number
		baseVerified = s.snapshotFHSCertifiedVerified(baseHash)
		if baseVerified == nil {
			return nil, fmt.Errorf("highest FHS certificate has no verified proposal")
		}
	}

	chain := make([]fhsHighQCValidationItem, 0, 4)
	seen := make(map[common.Hash]struct{})
	cursorQC := hotstuff.CloneSignedState(qc)
	for {
		if err := ctx.Err(); err != nil {
			return nil, hotstuff.ErrOldState
		}
		current := s.bc.CurrentBlock()
		if current == nil || current.Hash() != output.baseCanonicalHash {
			return nil, hotstuff.ErrOldState
		}
		cursorRef, err := s.verifyFHSQCCryptographic(cursorQC)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[cursorRef.BlockHash]; duplicate {
			return nil, fmt.Errorf("cyclic FHS HighQC parent chain at %s", cursorRef.BlockHash)
		}
		seen[cursorRef.BlockHash] = struct{}{}
		if key.RequestID != 0 {
			if err := s.authorizeHighQCProposalBody(key, validationGeneration, cursorRef); err != nil {
				return nil, err
			}
		}
		body, err := s.proposalBodyForHighQCStage(ctx, cursorRef, serviceGeneration)
		if err != nil {
			return nil, err
		}
		block, err := validateFHSProposalCommitmentsForConfig(s.chainConfig, cursorRef, body.EncodedBlock, body.Extra, body.ParentQC)
		if err != nil {
			return nil, fmt.Errorf("invalid certified FHS proposal %s: %w", cursorRef.BlockHash, err)
		}
		chain = append(chain, fhsHighQCValidationItem{ref: cursorRef, qc: hotstuff.CloneSignedState(cursorQC), body: body,
			verified: &core.VerifiedProposal{Block: block}})
		if cursorRef.ParentHash == baseHash {
			if cursorRef.Number != baseNumber+1 {
				return nil, fmt.Errorf("FHS HighQC chain is not contiguous at %s", cursorRef.BlockHash)
			}
			break
		}
		parentQC, err := hotstuff.DecodeSignedState(body.ParentQC)
		if err != nil || parentQC == nil {
			return nil, fmt.Errorf("certified FHS proposal %s is missing its parent certificate", cursorRef.BlockHash)
		}
		parentRef, err := types.DecodeHotstuffProposalRef(parentQC.State)
		if err != nil || parentRef.BlockHash != cursorRef.ParentHash || parentRef.Number+1 != cursorRef.Number || parentQC.Number >= cursorQC.Number {
			return nil, fmt.Errorf("certified FHS proposal parent proof mismatch at %s", cursorRef.BlockHash)
		}
		cursorQC = parentQC
		if len(chain) > fhsMaxCertifiedChainDepth {
			return nil, fmt.Errorf("FHS HighQC catch-up chain is unreasonably deep")
		}
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	parentVerified := baseVerified
	for index := range chain {
		if err := ctx.Err(); err != nil {
			return nil, hotstuff.ErrOldState
		}
		current := s.bc.CurrentBlock()
		if current == nil || current.Hash() != output.baseCanonicalHash {
			return nil, hotstuff.ErrOldState
		}
		item := &chain[index]
		parentQC, err := hotstuff.DecodeSignedState(item.body.ParentQC)
		if err != nil {
			return nil, err
		}
		if index == 0 {
			if highestQC == nil {
				if parentQC != nil {
					parentRef, parentErr := s.verifyFHSQCCryptographic(parentQC)
					if parentErr != nil || parentRef.BlockHash != baseHash {
						return nil, fmt.Errorf("first staged FHS certificate has a non-canonical parent QC")
					}
				}
			} else if !hotstuff.SignedStateSemanticEqual(parentQC, highestQC) {
				return nil, fmt.Errorf("staged FHS chain does not extend the highest local QC")
			}
		} else if !hotstuff.SignedStateSemanticEqual(parentQC, chain[index-1].qc) {
			return nil, fmt.Errorf("staged FHS chain parent QC mismatch at %s", item.ref.BlockHash)
		}

		cached := cloneVerifiedProposalForValidation(s.getVerifiedProposal(item.ref.ProposalID()))
		if cached != nil && cached.SanityCheck() == nil && cached.ProposalID == item.ref.ProposalID() &&
			cached.BlockHash() == item.ref.BlockHash && cached.ParentHash == item.ref.ParentHash &&
			cached.ViewNumber == item.ref.ViewNumber && cached.ViewID == item.ref.ViewID && cached.LeaderID == item.ref.LeaderID {
			item.verified = cached
		} else {
			item.verified, err = s.txService.verifyHistoricalCertifiedProposalWithParent(item.ref, item.verified.Block, item.body.Extra, parentVerified)
			if err != nil {
				return nil, err
			}
		}
		if item.verified.Block.BlockType() == types.Key_Block {
			keyblock := types.DecodeToKeyBlock(item.verified.Block.KeyInfo())
			if keyblock == nil || item.verified.Block.NumberU64() == 0 {
				return nil, fmt.Errorf("invalid certified FHS keyblock")
			}
			if err := s.keyService.verifyKeyBlock(keyblock, types.DecodeToCandidate(item.body.Extra), item.verified.Block.NumberU64()-1); err != nil {
				return nil, err
			}
		}
		parentVerified = item.verified
		// The serialized apply step needs only the signed reference/QC and the
		// already executed artifact. Release the potentially 8 MiB body before
		// publishing the worker result so Apply cannot accidentally re-decode or
		// re-hash it on the control loop.
		item.body = nil
	}
	output.items = chain
	return output, nil
}

func validateStagedFHSCertificateArtifact(item *fhsHighQCValidationItem) error {
	if item == nil || item.ref == nil || item.qc == nil || item.body != nil || item.verified == nil || item.verified.Block == nil {
		return fmt.Errorf("incomplete staged FHS certificate")
	}
	ref, qc, verified := item.ref, item.qc, item.verified
	if err := verified.SanityCheck(); err != nil || verified.ProposalID != ref.ProposalID() || verified.BlockHash() != ref.BlockHash ||
		verified.ParentHash != ref.ParentHash || verified.ViewNumber != ref.ViewNumber || verified.ViewID != ref.ViewID || verified.LeaderID != ref.LeaderID {
		return fmt.Errorf("invalid staged FHS verified proposal: %v", err)
	}
	if !bytes.Equal(qc.State, ref.EncodeToBytes()) || qc.Number != ref.ViewNumber || qc.ViewID != ref.ViewID || qc.LeaderID != ref.LeaderID {
		return fmt.Errorf("staged FHS QC does not match its proposal reference")
	}
	return nil
}

func (s *Service) installStagedFHSCertificate(item *fhsHighQCValidationItem, notify, pendingBroadcast bool) error {
	if err := validateStagedFHSCertificateArtifact(item); err != nil {
		return err
	}
	ref, qc, verified := item.ref, item.qc, item.verified
	s.muProposalBody.RLock()
	highest := s.fhsHighest
	s.muProposalBody.RUnlock()
	if highest != nil {
		if ref.ParentHash != highest.ref.BlockHash || ref.Number != highest.ref.Number+1 || qc.Number <= highest.qc.Number {
			return fmt.Errorf("FHS certified block does not safely extend highest certificate")
		}
	} else if ref.ParentHash != s.bc.CurrentBlock().Hash() {
		return fmt.Errorf("first FHS certified block does not extend canonical head")
	}
	if err := s.persistValidatedFHSCertificateWithBroadcast(ref, qc, pendingBroadcast); err != nil {
		return fmt.Errorf("persist FHS certificate before adoption: %w", err)
	}

	verified.Block.SetFHSSignature(qc.Sign, qc.Mask, qc.ViewID, qc.LeaderID, qc.Number, ref.ExtraHash, ref.ParentQCID)
	record := &fhsCertifiedProposal{ref: ref, verified: verified, qc: hotstuff.CloneSignedState(qc)}
	s.muProposalBody.Lock()
	s.fhsCertifiedByHash[ref.BlockHash] = record
	s.fhsCertifiedByID[ref.ProposalID()] = record
	s.fhsHighest = record
	s.verifiedProposalByID[ref.ProposalID()] = verified
	s.muProposalBody.Unlock()

	s.txService.mu.Lock()
	s.txService.proposedChain.adoptCertified(verified.Block)
	s.txService.mu.Unlock()

	curKeyBlock := s.kbc.CurrentBlock()
	s.muCurrentView.Lock()
	s.currentView.TxNumber = ref.Number
	s.currentView.TxHash = ref.BlockHash
	if qc.Number > s.currentView.ViewNumber {
		s.currentView.ViewNumber = qc.Number
	}
	s.currentView.Round = 0
	if curKeyBlock != nil {
		s.currentView.KeyNumber = curKeyBlock.NumberU64()
		s.currentView.KeyHash = curKeyBlock.Hash()
		s.currentView.CommitteeHash = curKeyBlock.CommitteeHash()
	}
	s.currentView.NoDone = true
	s.currentView.LeaderIndex = s.fairHotstuffLeaderIndexFromBlockLocked(verified.Block)
	s.waittingView.TxNumber = ref.Number
	s.waittingView.KeyNumber = s.currentView.KeyNumber
	s.muCurrentView.Unlock()

	if notify {
		s.pacetMakerTimer.start()
		s.sendNewViewMsg(qc.Number)
	}
	return nil
}

func (s *Service) installStagedFHSHighQC(output *fhsHighQCValidationOutput, notify, pendingBroadcast bool) error {
	if output == nil || output.targetQC == nil {
		return fmt.Errorf("invalid staged FHS HighQC output")
	}
	canonical := s.bc.CurrentBlock()
	if canonical == nil || canonical.Hash() != output.baseCanonicalHash {
		return hotstuff.ErrOldState
	}
	s.muProposalBody.Lock()
	if err := s.reconcileFHSCertifiedFrontierLocked(canonical); err != nil {
		s.muProposalBody.Unlock()
		return err
	}
	currentHighest := s.fhsHighest
	s.muProposalBody.Unlock()
	var currentHighestQC *hotstuff.SignedState
	if currentHighest != nil {
		currentHighestQC = currentHighest.qc
	}
	currentHighestID, err := fhsQCIdentityHash(currentHighestQC)
	if err != nil || currentHighestID != output.baseHighestQCID {
		return hotstuff.ErrOldState
	}
	if output.covered {
		return nil
	}
	// Preflight the complete immutable chain before the first WAL/view mutation.
	// A deterministic error in item 65 must not leave the first 64 certificates
	// published. Only an external database failure can now interrupt installation,
	// and a retry safely resumes from the newly persisted highest prefix.
	expectedParentHash := canonical.Hash()
	expectedNumber := canonical.NumberU64() + 1
	previousQCNumber := uint64(0)
	if currentHighest != nil {
		if currentHighest.ref == nil || currentHighest.qc == nil {
			return fmt.Errorf("invalid current FHS highest certificate")
		}
		expectedParentHash = currentHighest.ref.BlockHash
		expectedNumber = currentHighest.ref.Number + 1
		previousQCNumber = currentHighest.qc.Number
	}
	for index := range output.items {
		item := &output.items[index]
		if err := validateStagedFHSCertificateArtifact(item); err != nil {
			return err
		}
		if item.ref.ParentHash != expectedParentHash || item.ref.Number != expectedNumber || item.qc.Number <= previousQCNumber {
			return fmt.Errorf("staged FHS certificate chain is not contiguous at %s", item.ref.BlockHash)
		}
		expectedParentHash = item.ref.BlockHash
		expectedNumber++
		previousQCNumber = item.qc.Number
	}
	if len(output.items) == 0 || !hotstuff.SignedStateSemanticEqual(output.items[len(output.items)-1].qc, output.targetQC) {
		return fmt.Errorf("staged FHS chain does not end at its target QC")
	}
	for index := range output.items {
		last := index == len(output.items)-1
		if err := s.installStagedFHSCertificate(&output.items[index], notify && last, pendingBroadcast && last); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) adoptFHSHighQC(qc *hotstuff.SignedState, notify, pendingBroadcast bool) error {
	output, err := s.stageFHSHighQC(context.Background(), hotstuff.FHSHighQCValidationKey{}, qc, 0, 0)
	if err != nil {
		return err
	}
	return s.installStagedFHSHighQC(output, notify, pendingBroadcast)
}

func (s *Service) deferFHSWALContentRecovery(
	qc *hotstuff.SignedState,
	highestHash common.Hash,
	recoveredView uint64,
	pendingBroadcast *hotstuff.SignedState,
	lastVoteBody *proposalBodyMsg,
) error {
	if s == nil || s.fhsStore == nil || qc == nil || highestHash == (common.Hash{}) {
		return fmt.Errorf("invalid missing-content FHS recovery state")
	}
	if err := s.installRestoredFHSVoteProposal(lastVoteBody); err != nil {
		return err
	}
	if err := s.fhsStore.deferRecovery(&fhsDeferredRecovery{
		HighestQC:        qc,
		HighestBlockHash: highestHash,
		RecoveredView:    recoveredView,
		PendingBroadcast: pendingBroadcast,
	}); err != nil {
		return err
	}
	log.Warn("Deferred FHS WAL application until proposal content is repaired",
		"view", qc.Number, "viewID", qc.ViewID, "blockHash", highestHash)
	return nil
}

func (s *Service) loadFHSWAL() error {
	if !s.fairHotstuffEnabled() {
		return nil
	}
	if s.fhsStore == nil {
		return fmt.Errorf("FHS safety store not initialized")
	}
	state, highestHash, err := s.fhsStore.recoverySnapshot()
	if err != nil {
		return err
	}
	if state == nil {
		return nil
	}
	// The canonical block and its QC are committed atomically, but the
	// validator-local safety WAL lives in a separate database batch. Repair the
	// crash window before applying the usual WAL recovery rules. This is also
	// what lets a passively synced validator restart at its actual canonical QC
	// instead of rejecting the next contiguous NewView certificate as a gap.
	canonicalHead := s.bc.CurrentBlock()
	if canonicalHead == nil {
		return fmt.Errorf("cannot restore FHS state without canonical head")
	}
	if canonicalHead.NumberU64() > 0 {
		_, canonicalQC, err := s.bc.ReconstructFHSQC(canonicalHead)
		if err != nil {
			return fmt.Errorf("reconstruct canonical FHS head QC: %w", err)
		}
		if err := s.reconcileFHSCanonicalQCWatermark(canonicalHead, canonicalQC); err != nil {
			return fmt.Errorf("reconcile canonical FHS head QC: %w", err)
		}
		state, highestHash, err = s.fhsStore.recoverySnapshot()
		if err != nil {
			return err
		}
	}
	lastVoteBody, err := s.restoredFHSVoteProposal(state.LastVote)
	if err != nil {
		return fmt.Errorf("invalid last FHS WAL vote: %w", err)
	}
	qcMissing := state.HighestQC == nil
	hashMissing := highestHash == (common.Hash{})
	if qcMissing != hashMissing {
		return fmt.Errorf("incomplete highest FHS WAL pointer")
	}
	var highestRef *types.HotstuffProposalRef
	if !qcMissing {
		highestRef, err = s.verifyFHSQCCryptographic(state.HighestQC)
		if err != nil {
			return fmt.Errorf("invalid highest FHS WAL certificate: %w", err)
		}
		if highestRef.BlockHash != highestHash {
			return fmt.Errorf("highest FHS WAL certificate/hash mismatch")
		}
	}
	pendingBroadcast, err := s.fhsStore.pendingBroadcastSnapshot()
	if err != nil {
		return err
	}
	if pendingBroadcast != nil {
		if qcMissing || !hotstuff.SignedStateSemanticEqual(pendingBroadcast, state.HighestQC) {
			return fmt.Errorf("pending FHS QC broadcast does not match the highest certificate")
		}
		if pendingBroadcast.LeaderID != s.Self() {
			return fmt.Errorf("pending FHS QC broadcast belongs to another leader")
		}
	}
	state, err = s.reconcileFHSTimeoutEpoch(state, highestHash)
	if err != nil {
		return fmt.Errorf("reconcile FHS timeout epoch: %w", err)
	}
	// Validate timeout recovery now, but publish its view only after every WAL
	// certificate and proposal sidecar has also passed validation.
	recoveredView, err := s.validateFHSTimeoutState(state)
	if err != nil {
		return err
	}
	if qcMissing {
		if err := s.installRestoredFHSVoteProposal(lastVoteBody); err != nil {
			return err
		}
		s.applyFHSRecoveredView(recoveredView)
		return nil
	}

	current := s.bc.CurrentBlock()
	if current == nil {
		return fmt.Errorf("cannot restore FHS state without canonical head")
	}
	if highestHash == current.Hash() || s.bc.GetCanonicalHash(highestRef.Number) == highestHash {
		if err := s.installRestoredFHSVoteProposal(lastVoteBody); err != nil {
			return err
		}
		if pendingBroadcast != nil {
			if err := s.fhsStore.clearPendingBroadcast(pendingBroadcast); err != nil {
				return fmt.Errorf("complete canonical FHS QC outbox: %w", err)
			}
		}
		s.applyFHSRecoveredView(recoveredView)
		return nil
	}
	recoveryKeyHash := s.GetCurrentView().KeyHash

	type restoreRecord struct {
		ref   *types.HotstuffProposalRef
		body  *proposalBodyMsg
		extra []byte
		qc    *hotstuff.SignedState
	}
	chain := make([]restoreRecord, 0, 3)
	cursor := highestHash
	for cursor != current.Hash() {
		encodedCertificate, err := rawdb.ReadFHSCertificate(s.fhsStore.db, cursor)
		if err != nil || len(encodedCertificate) == 0 {
			return fmt.Errorf("missing FHS certificate for %s", cursor)
		}
		var certificate fhsDiskCertificate
		if err := rlp.DecodeBytes(encodedCertificate, &certificate); err != nil || certificate.QC == nil {
			return fmt.Errorf("invalid FHS certificate for %s", cursor)
		}
		certificateRef, err := s.verifyFHSQCCryptographic(certificate.QC)
		if err != nil || certificateRef.BlockHash != cursor || certificateRef.ProposalID() != certificate.ProposalID {
			return fmt.Errorf("invalid FHS certificate identity for %s: %v", cursor, err)
		}
		if cursor == highestHash && !hotstuff.SignedStateSemanticEqual(certificate.QC, state.HighestQC) {
			return fmt.Errorf("highest FHS certificate record does not match its safety watermark")
		}
		encodedProposal, err := rawdb.ReadFHSProposal(s.fhsStore.db, certificate.ProposalID)
		if err != nil {
			return fmt.Errorf("read FHS proposal %s: %w", certificate.ProposalID, err)
		}
		if len(encodedProposal) == 0 {
			return s.deferFHSWALContentRecovery(state.HighestQC, highestHash, recoveredView, pendingBroadcast, lastVoteBody)
		}
		var proposal fhsDiskProposal
		if err := rlp.DecodeBytes(encodedProposal, &proposal); err != nil || proposal.ProposalID != certificate.ProposalID {
			return fmt.Errorf("invalid FHS proposal %s", certificate.ProposalID)
		}
		ref, err := types.DecodeHotstuffProposalRef(proposal.ProposalRef)
		if err != nil || ref.BlockHash != cursor || ref.ProposalID() != proposal.ProposalID ||
			ref.ProposalID() != certificateRef.ProposalID() ||
			!hotstuff.SignedStateSemanticEqual(certificate.QC, &hotstuff.SignedState{State: proposal.ProposalRef, ViewID: ref.ViewID, LeaderID: ref.LeaderID, Number: ref.ViewNumber}) {
			return fmt.Errorf("FHS proposal/certificate mismatch for %s", cursor)
		}
		encodedBody, err := rawdb.ReadFHSBody(s.fhsStore.db, ref.BodyHash)
		if err != nil {
			return fmt.Errorf("read FHS body %s: %w", ref.BodyHash, err)
		}
		if len(encodedBody) == 0 {
			return s.deferFHSWALContentRecovery(state.HighestQC, highestHash, recoveredView, pendingBroadcast, lastVoteBody)
		}
		var bodyRecord fhsDiskBody
		if err := rlp.DecodeBytes(encodedBody, &bodyRecord); err != nil || bodyRecord.BodyHash != ref.BodyHash {
			return fmt.Errorf("invalid FHS body %s", ref.BodyHash)
		}
		body := &proposalBodyMsg{
			Type:              proposalBodyMsgManifest,
			ProposalID:        proposal.ProposalID,
			BodyHash:          ref.BodyHash,
			BodySize:          ref.BodySize,
			Number:            ref.Number,
			ViewNumber:        ref.ViewNumber,
			ViewID:            ref.ViewID,
			LeaderID:          ref.LeaderID,
			ProposalKeyHash:   ref.KeyHash,
			EncodedBlock:      append([]byte(nil), bodyRecord.EncodedBlock...),
			Extra:             append([]byte(nil), proposal.Extra...),
			ParentQC:          append([]byte(nil), proposal.ParentQC...),
			CreatedAtUnixNano: 1,
		}
		chain = append(chain, restoreRecord{ref: ref, body: body, extra: append([]byte(nil), proposal.Extra...), qc: hotstuff.CloneSignedState(certificate.QC)})
		cursor = ref.ParentHash
		if len(chain) > fhsMaxCertifiedChainDepth {
			return fmt.Errorf("FHS uncommitted recovery chain is unreasonably deep")
		}
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	type stagedRestore struct {
		record   restoreRecord
		block    *types.Block
		verified *core.VerifiedProposal
	}
	staged := make([]stagedRestore, 0, len(chain))
	var parentVerified *core.VerifiedProposal
	for index, record := range chain {
		block, err := validateFHSProposalCommitmentsForConfig(s.chainConfig, record.ref, record.body.EncodedBlock, record.extra, record.body.ParentQC)
		if err != nil {
			return fmt.Errorf("invalid restored FHS proposal %s: %w", record.ref.BlockHash, err)
		}
		qcRef, err := s.verifyFHSQCCryptographic(record.qc)
		if err != nil {
			return fmt.Errorf("invalid persisted FHS QC for %s: %w", record.ref.BlockHash, err)
		}
		if qcRef.BlockHash != record.ref.BlockHash {
			return fmt.Errorf("persisted FHS QC/block mismatch for %s", record.ref.BlockHash)
		}
		parentQC, err := hotstuff.DecodeSignedState(record.body.ParentQC)
		if err != nil {
			return fmt.Errorf("decode restored parent QC for %s: %w", record.ref.BlockHash, err)
		}
		if parentQC == nil {
			if index > 0 || record.ref.ParentHash != current.Hash() || record.ref.Number != current.NumberU64()+1 {
				return fmt.Errorf("restored FHS proposal %s is missing parent QC", record.ref.BlockHash)
			}
		} else {
			parentRef, err := s.verifyFHSQCCryptographic(parentQC)
			if err != nil || parentRef.BlockHash != record.ref.ParentHash {
				return fmt.Errorf("restored FHS parent QC mismatch for %s", record.ref.BlockHash)
			}
			if index > 0 && !hotstuff.SignedStateSemanticEqual(parentQC, chain[index-1].qc) {
				return fmt.Errorf("restored FHS chain has non-contiguous parent proof at %s", record.ref.BlockHash)
			}
		}
		verified, err := s.txService.verifyHistoricalCertifiedProposalWithParent(record.ref, block, record.extra, parentVerified)
		if err != nil {
			return fmt.Errorf("replay restored FHS proposal %s: %w", record.ref.BlockHash, err)
		}
		if block.BlockType() == types.Key_Block {
			keyblock := types.DecodeToKeyBlock(block.KeyInfo())
			if keyblock == nil {
				return fmt.Errorf("invalid restored FHS keyblock %s", record.ref.BlockHash)
			}
			if block.NumberU64() == 0 {
				return fmt.Errorf("restored FHS keyblock %s cannot be transaction genesis", record.ref.BlockHash)
			}
			if err := s.keyService.verifyKeyBlock(keyblock, types.DecodeToCandidate(record.extra), block.NumberU64()-1); err != nil {
				return fmt.Errorf("verify restored FHS keyblock %s: %w", record.ref.BlockHash, err)
			}
		}
		staged = append(staged, stagedRestore{record: record, block: block, verified: verified})
		parentVerified = verified
	}
	// Preflight the complete install while holding the cache lock. No map is
	// mutated until every entry is known to fit and to be conflict-free.
	s.muProposalBody.Lock()
	entries, bytesUsed := s.proposalBodyCacheUsageLocked()
	additionalEntries, additionalBytes := 0, 0
	lastVoteStaged := false
	for _, item := range staged {
		record := item.record
		proposalID := record.ref.ProposalID()
		if existing := s.proposalBodies[proposalID]; existing != nil {
			if existing.BodyHash != record.body.BodyHash || !bytes.Equal(existing.EncodedBlock, record.body.EncodedBlock) ||
				!bytes.Equal(existing.Extra, record.body.Extra) || !bytes.Equal(existing.ParentQC, record.body.ParentQC) {
				s.muProposalBody.Unlock()
				return fmt.Errorf("conflicting restored FHS proposal %s", proposalID)
			}
		} else {
			additionalEntries++
			additionalBytes = saturatingAddInt(additionalBytes, proposalBodyMsgPayloadBytes(record.body))
		}
		if existing := s.fhsCertifiedByHash[record.ref.BlockHash]; existing != nil && !hotstuff.SignedStateSemanticEqual(existing.qc, record.qc) {
			s.muProposalBody.Unlock()
			return fmt.Errorf("conflicting restored FHS certificate %s", record.ref.BlockHash)
		}
		if lastVoteBody != nil && proposalID == lastVoteBody.ProposalID {
			lastVoteStaged = true
			if body := record.body; body.BodyHash != lastVoteBody.BodyHash ||
				!bytes.Equal(body.EncodedBlock, lastVoteBody.EncodedBlock) ||
				!bytes.Equal(body.Extra, lastVoteBody.Extra) || !bytes.Equal(body.ParentQC, lastVoteBody.ParentQC) {
				s.muProposalBody.Unlock()
				return fmt.Errorf("last FHS vote conflicts with restored certified proposal %s", proposalID)
			}
		}
	}
	if lastVoteBody != nil && !lastVoteStaged {
		if existing := s.proposalBodies[lastVoteBody.ProposalID]; existing != nil {
			if existing.BodyHash != lastVoteBody.BodyHash || !bytes.Equal(existing.EncodedBlock, lastVoteBody.EncodedBlock) ||
				!bytes.Equal(existing.Extra, lastVoteBody.Extra) || !bytes.Equal(existing.ParentQC, lastVoteBody.ParentQC) {
				s.muProposalBody.Unlock()
				return fmt.Errorf("conflicting restored last-vote proposal %s", lastVoteBody.ProposalID)
			}
		} else {
			additionalEntries++
			additionalBytes = saturatingAddInt(additionalBytes, proposalBodyMsgPayloadBytes(lastVoteBody))
		}
	}
	if entries+additionalEntries > proposalBodyCacheMaxEntries || !fitsIntBudget(bytesUsed, additionalBytes, proposalBodyCacheLimitForConfig(s.chainConfig)) {
		s.muProposalBody.Unlock()
		return fmt.Errorf("restored FHS chain exceeds proposal cache capacity")
	}
	for _, item := range staged {
		record, block, verified := item.record, item.block, item.verified
		proposalID := record.ref.ProposalID()
		body := cloneProposalBodyMsg(record.body)
		body.Type = proposalBodyMsgManifest
		body.From = s.Self()
		body.CreatedAtUnixNano = time.Now().UnixNano()
		block.SetFHSSignature(record.qc.Sign, record.qc.Mask, record.qc.ViewID, record.qc.LeaderID, record.qc.Number, record.ref.ExtraHash, record.ref.ParentQCID)
		recordValue := &fhsCertifiedProposal{ref: record.ref, verified: verified, qc: record.qc}
		s.proposalBodies[proposalID] = body
		s.verifiedProposalByID[proposalID] = verified
		s.fhsCertifiedByHash[record.ref.BlockHash] = recordValue
		s.fhsCertifiedByID[proposalID] = recordValue
		s.fhsHighest = recordValue
	}
	if lastVoteBody != nil && !lastVoteStaged && s.proposalBodies[lastVoteBody.ProposalID] == nil {
		body := cloneProposalBodyMsg(lastVoteBody)
		body.Type = proposalBodyMsgManifest
		body.From = body.LeaderID
		body.CreatedAtUnixNano = time.Now().UnixNano()
		s.proposalBodies[body.ProposalID] = body
	}
	s.muProposalBody.Unlock()

	// adoptCertified cannot fail. Keeping it after the error-free cache install
	// prevents a corrupt/capacity-exhausted WAL from publishing a prefix.
	s.txService.mu.Lock()
	for _, item := range staged {
		s.txService.proposedChain.adoptCertified(item.block)
	}
	s.txService.mu.Unlock()

	// If the WAL contains a certified child, its parent was already decided by
	// the 2-chain rule even if the process crashed just before the canonical
	// write. Complete that decision before the network or pacemaker starts so
	// every restarting replica enters the same committee epoch.
	if err := s.commitFHS2ChainForCertified(state.HighestQC); err != nil {
		return fmt.Errorf("complete restored FHS 2-chain commit: %w", err)
	}

	s.muProposalBody.RLock()
	highest := s.fhsHighest
	s.muProposalBody.RUnlock()
	if highest == nil || highest.ref == nil || highest.qc == nil {
		return fmt.Errorf("restored FHS highest certificate is unavailable")
	}
	curKeyBlock := s.kbc.CurrentBlock()
	if curKeyBlock == nil {
		return fmt.Errorf("restored FHS key head is unavailable")
	}
	s.muCurrentView.Lock()
	s.currentView.TxNumber = highest.ref.Number
	s.currentView.TxHash = highest.ref.BlockHash
	if curKeyBlock.Hash() != recoveryKeyHash {
		// commitFHS2ChainForCertified crossed an epoch while replaying WAL.
		// Old-epoch timeout maxima are not a common new-epoch starting point.
		s.currentView.ViewNumber = highest.qc.Number
	} else {
		if recoveredView > s.currentView.ViewNumber {
			s.currentView.ViewNumber = recoveredView
		}
		if highest.qc.Number > s.currentView.ViewNumber {
			s.currentView.ViewNumber = highest.qc.Number
		}
	}
	s.currentView.KeyNumber = curKeyBlock.NumberU64()
	s.currentView.KeyHash = curKeyBlock.Hash()
	s.currentView.CommitteeHash = curKeyBlock.CommitteeHash()
	s.currentView.Round = 0
	s.currentView.LeaderIndex = s.fairHotstuffLeaderIndexForCurrentLocked()
	s.currentView.NoDone = true
	s.waittingView.TxNumber = s.currentView.TxNumber
	s.waittingView.KeyNumber = s.currentView.KeyNumber
	s.muCurrentView.Unlock()
	return nil
}
