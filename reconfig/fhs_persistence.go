package reconfig

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

const fhsDiskVersion = uint32(5)

type fhsDiskSafety struct {
	Version          uint32
	ChainID          uint64
	GenesisHash      common.Hash
	State            *hotstuff.FHSSafetyState
	HighestBlockHash common.Hash
	PendingBroadcast *hotstuff.SignedState `rlp:"nil"`
}

type fhsDiskProposal struct {
	Version      uint32
	ProposalID   common.Hash
	ProposalRef  []byte
	EncodedBlock []byte
	Extra        []byte
	ParentQC     []byte
}

type fhsDiskCertificate struct {
	Version    uint32
	ProposalID common.Hash
	QC         *hotstuff.SignedState
}

type fhsSafetyStore struct {
	db          ethdb.KeyValueStore
	chainID     uint64
	genesisHash common.Hash

	mu                 sync.Mutex
	loaded             bool
	state              *hotstuff.FHSSafetyState
	highestBlockHash   common.Hash
	pendingBroadcast   *hotstuff.SignedState
	lastPersistenceErr error
}

func newFHSSafetyStore(db ethdb.KeyValueStore, chainID uint64, genesisHash common.Hash) *fhsSafetyStore {
	return &fhsSafetyStore{
		db:          db,
		chainID:     chainID,
		genesisHash: genesisHash,
		state:       hotstuff.NewFHSSafetyState(),
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
	if disk.Version != fhsDiskVersion || disk.ChainID != store.chainID || disk.GenesisHash != store.genesisHash ||
		disk.State == nil || disk.State.Version != expected.Version || disk.State.Domain != expected.Domain {
		store.lastPersistenceErr = fmt.Errorf("FHS safety WAL belongs to an incompatible chain or version")
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
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.loadLocked()
}

func (store *fhsSafetyStore) snapshot() (*hotstuff.FHSSafetyState, common.Hash, error) {
	if store == nil {
		return nil, common.Hash{}, fmt.Errorf("nil FHS safety store")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.loadLocked(); err != nil {
		return nil, common.Hash{}, err
	}
	return hotstuff.CloneFHSSafetyState(store.state), store.highestBlockHash, nil
}

func (store *fhsSafetyStore) pendingBroadcastSnapshot() (*hotstuff.SignedState, error) {
	if store == nil {
		return nil, fmt.Errorf("nil FHS safety store")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
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
	store.mu.Lock()
	defer store.mu.Unlock()
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
	store.mu.Lock()
	defer store.mu.Unlock()
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
		Version:          fhsDiskVersion,
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

func persistedVotesEqual(a, b *hotstuff.PersistedVote) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.ViewNumber == b.ViewNumber && a.ViewID == b.ViewID && a.LeaderID == b.LeaderID &&
		a.KStateHash == b.KStateHash && a.TStateHash == b.TStateHash &&
		bytes.Equal(a.KState, b.KState) && bytes.Equal(a.TState, b.TState) && bytes.Equal(a.Extra, b.Extra)
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
	if len(vote.KState) == 0 && len(vote.TState) == 0 {
		return fmt.Errorf("empty FHS vote")
	}
	if len(vote.KState) > 0 && vote.KStateHash != hotstuff.StateDigest(vote.KState) {
		return fmt.Errorf("FHS key-state vote digest mismatch")
	}
	if len(vote.TState) > 0 && vote.TStateHash != hotstuff.StateDigest(vote.TState) {
		return fmt.Errorf("FHS transaction-state vote digest mismatch")
	}
	return nil
}

// validateFHSProposalCommitments validates every sidecar commitment without
// mutating the live proposal caches. Recovery uses this during its staging
// phase so a corrupt suffix cannot partially publish an earlier prefix.
func validateFHSProposalCommitments(ref *types.HotstuffProposalRef, encodedBlock, extra, encodedParentQC []byte) (*types.Block, error) {
	if ref == nil {
		return nil, fmt.Errorf("nil FHS proposal reference")
	}
	if len(encodedBlock) == 0 || len(encodedBlock) > proposalBodySidecarMaxBytes {
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

// validateRestoredFHSVote fails closed if the last durable vote points at a
// missing or altered proposal record. Fair HotStuff certifies transaction proposal
// references only, so a KState-only WAL entry is corrupt and must fail closed.
func (s *Service) readFHSProposalBody(ref *types.HotstuffProposalRef) (*proposalBodyMsg, bool, error) {
	if ref == nil || s.fhsStore == nil || s.fhsStore.db == nil {
		return nil, false, fmt.Errorf("FHS safety store not initialized")
	}
	encoded, err := rawdb.ReadFHSProposal(s.fhsStore.db, ref.ProposalID())
	if err != nil {
		return nil, false, err
	}
	if len(encoded) == 0 {
		return nil, false, nil
	}
	var proposal fhsDiskProposal
	if err := rlp.DecodeBytes(encoded, &proposal); err != nil {
		return nil, true, fmt.Errorf("decode persisted FHS proposal %s: %w", ref.ProposalID(), err)
	}
	if proposal.Version != fhsDiskVersion || proposal.ProposalID != ref.ProposalID() ||
		!bytes.Equal(proposal.ProposalRef, ref.EncodeToBytes()) {
		return nil, true, fmt.Errorf("persisted FHS proposal record mismatch")
	}
	if _, err := validateFHSProposalCommitments(ref, proposal.EncodedBlock, proposal.Extra, proposal.ParentQC); err != nil {
		return nil, true, fmt.Errorf("invalid persisted FHS proposal: %w", err)
	}
	return &proposalBodyMsg{
		Type:              proposalBodyMsgData,
		ProposalID:        proposal.ProposalID,
		BodyHash:          ref.BodyHash,
		Number:            ref.Number,
		ViewNumber:        ref.ViewNumber,
		ViewID:            ref.ViewID,
		LeaderID:          ref.LeaderID,
		From:              ref.LeaderID,
		EncodedBlock:      append([]byte(nil), proposal.EncodedBlock...),
		Extra:             append([]byte(nil), proposal.Extra...),
		ParentQC:          append([]byte(nil), proposal.ParentQC...),
		CreatedAtUnixNano: 1,
	}, true, nil
}

func (s *Service) restoredFHSVoteProposal(vote *hotstuff.PersistedVote) (*proposalBodyMsg, error) {
	if vote == nil {
		return nil, nil
	}
	if err := validatePersistedVote(vote); err != nil {
		return nil, err
	}
	if len(vote.TState) == 0 {
		return nil, fmt.Errorf("Fair HotStuff persisted vote has no transaction proposal reference")
	}
	if s.fhsStore == nil || s.fhsStore.db == nil {
		return nil, fmt.Errorf("FHS safety store not initialized")
	}
	ref, err := types.DecodeHotstuffProposalRef(vote.TState)
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
		return nil, fmt.Errorf("missing persisted FHS vote proposal %s", ref.ProposalID())
	}
	if !bytes.Equal(body.Extra, vote.Extra) {
		return nil, fmt.Errorf("persisted FHS vote proposal record mismatch")
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
	restored.Type = proposalBodyMsgData
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

	var proposal *fhsDiskProposal
	if len(vote.TState) > 0 {
		ref, err := types.DecodeHotstuffProposalRef(vote.TState)
		if err != nil {
			return fmt.Errorf("decode FHS vote proposal ref: %w", err)
		}
		if ref.ViewNumber != vote.ViewNumber || ref.ViewID != vote.ViewID || ref.LeaderID != vote.LeaderID || ref.ChainID != s.ChainID() {
			return fmt.Errorf("FHS vote proposal context mismatch")
		}
		body := s.getProposalBody(ref.ProposalID())
		if body == nil || len(body.EncodedBlock) == 0 {
			return fmt.Errorf("FHS vote proposal body is unavailable")
		}
		if !bytes.Equal(body.Extra, vote.Extra) {
			return fmt.Errorf("FHS vote extra does not match verified proposal body")
		}
		if _, err := validateFHSProposalCommitments(ref, body.EncodedBlock, body.Extra, body.ParentQC); err != nil {
			return fmt.Errorf("invalid FHS vote proposal body: %w", err)
		}
		proposal = &fhsDiskProposal{
			Version:      fhsDiskVersion,
			ProposalID:   ref.ProposalID(),
			ProposalRef:  append([]byte(nil), vote.TState...),
			EncodedBlock: append([]byte(nil), body.EncodedBlock...),
			Extra:        append([]byte(nil), vote.Extra...),
			ParentQC:     append([]byte(nil), body.ParentQC...),
		}
	}

	store := s.fhsStore
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.loadLocked(); err != nil {
		return err
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
	if proposal != nil {
		encodedProposal, err := rlp.EncodeToBytes(proposal)
		if err != nil {
			return err
		}
		if err := rawdb.WriteFHSProposal(batch, proposal.ProposalID, encodedProposal); err != nil {
			return err
		}
	}
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
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.loadLocked(); err != nil {
		return err
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
	store.mu.Lock()
	defer store.mu.Unlock()
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
	store.mu.Lock()
	defer store.mu.Unlock()
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
	if _, err := validateFHSProposalCommitments(ref, body.EncodedBlock, extra, body.ParentQC); err != nil {
		return fmt.Errorf("invalid FHS certificate proposal body: %w", err)
	}
	proposal := &fhsDiskProposal{
		Version:      fhsDiskVersion,
		ProposalID:   ref.ProposalID(),
		ProposalRef:  append([]byte(nil), qc.State...),
		EncodedBlock: append([]byte(nil), body.EncodedBlock...),
		Extra:        append([]byte(nil), extra...),
		ParentQC:     append([]byte(nil), body.ParentQC...),
	}
	certificate := &fhsDiskCertificate{
		Version:    fhsDiskVersion,
		ProposalID: proposal.ProposalID,
		QC:         hotstuff.CloneSignedState(qc),
	}
	encodedProposal, err := rlp.EncodeToBytes(proposal)
	if err != nil {
		return err
	}
	encodedCertificate, err := rlp.EncodeToBytes(certificate)
	if err != nil {
		return err
	}

	store := s.fhsStore
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.loadLocked(); err != nil {
		return err
	}
	if highest := store.state.HighestQC; highest != nil {
		if qc.Number < highest.Number {
			return fmt.Errorf("refusing to persist lower FHS QC view %d after %d", qc.Number, highest.Number)
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
	if err := rawdb.WriteFHSProposal(batch, proposal.ProposalID, encodedProposal); err != nil {
		return err
	}
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

func (s *Service) replayPendingFHSQCBroadcast() {
	if !s.fairHotstuffEnabled() || !s.isRunning() {
		return
	}
	pending, err := s.pendingFHSQCBroadcast()
	if err != nil {
		log.Error("cannot replay durable FHS QC broadcast", "err", err)
		return
	}
	if pending == nil {
		return
	}
	msg, err := s.protocolMng.RebuildFHSQCBroadcast(pending)
	if err != nil {
		log.Error("cannot rebuild durable FHS QC broadcast", "number", pending.Number, "err", err)
		return
	}
	if errs := s.broadcastHotstuffToCommittee(msg); len(errs) > 0 {
		log.Warn("durable FHS QC broadcast queued with delivery errors", "number", pending.Number, "errors", len(errs))
	} else {
		log.Info("replayed durable FHS QC broadcast", "number", pending.Number, "viewID", pending.ViewID)
	}
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

func (s *Service) adoptFHSHighQC(qc *hotstuff.SignedState, notify, pendingBroadcast bool) error {
	if !s.fairHotstuffEnabled() {
		return nil
	}
	ref, err := s.verifyFHSQCCryptographic(qc)
	if err != nil {
		return err
	}

	s.muProposalBody.RLock()
	highest := s.fhsHighest
	existing := s.fhsCertifiedByHash[ref.BlockHash]
	s.muProposalBody.RUnlock()
	if existing != nil {
		if !hotstuff.SignedStateSemanticEqual(existing.qc, qc) {
			return fmt.Errorf("conflicting FHS QC for block %s", ref.BlockHash)
		}
		return nil
	}
	if highest != nil {
		if qc.Number < highest.qc.Number {
			return nil
		}
		if qc.Number == highest.qc.Number {
			if hotstuff.SignedStateSemanticEqual(highest.qc, qc) {
				return nil
			}
			return fmt.Errorf("conflicting FHS QCs at view %d", qc.Number)
		}
		// A lagging node may be several certificates behind. Parent sidecars are
		// recursively adopted below; direct-extension is enforced only after
		// that catch-up has completed.
	}

	proposalID := ref.ProposalID()
	verified := s.getVerifiedProposal(proposalID)
	body := s.getProposalBody(proposalID)
	if body == nil {
		diskBody, found, diskErr := s.readFHSProposalBody(ref)
		if diskErr != nil {
			return fmt.Errorf("read durable certified FHS proposal body: %w", diskErr)
		}
		if found {
			if err := s.installRestoredFHSVoteProposal(diskBody); err != nil {
				return err
			}
			body = diskBody
		} else {
			body, err = s.waitProposalBody(ref)
			if err != nil {
				return fmt.Errorf("retrieve certified FHS proposal body: %w", err)
			}
		}
	}
	if ref.ParentHash != s.bc.CurrentBlock().Hash() && s.getFHSCertifiedVerified(ref.ParentHash) == nil {
		parentQC, err := hotstuff.DecodeSignedState(body.ParentQC)
		if err != nil || parentQC == nil {
			return fmt.Errorf("certified FHS proposal is missing its parent certificate")
		}
		parentRef, err := types.DecodeHotstuffProposalRef(parentQC.State)
		if err != nil || parentRef.BlockHash != ref.ParentHash {
			return fmt.Errorf("certified FHS proposal parent proof mismatch")
		}
		if err := s.adoptFHSHighQC(parentQC, false, false); err != nil {
			return err
		}
	}
	if verified == nil || verified.Block == nil {
		block := types.DecodeToBlock(body.EncodedBlock)
		if block == nil {
			return fmt.Errorf("decode certified FHS proposal body")
		}
		if err := ref.VerifyAgainstBlock(block, body.EncodedBlock); err != nil {
			return err
		}
		verified, err = s.txService.verifyHistoricalCertifiedProposal(ref, block, body.Extra)
		if err != nil {
			return err
		}
		if block.BlockType() == types.Key_Block {
			keyblock := types.DecodeToKeyBlock(block.KeyInfo())
			if keyblock == nil {
				return fmt.Errorf("invalid certified FHS keyblock")
			}
			if block.NumberU64() == 0 {
				return fmt.Errorf("certified FHS keyblock cannot be transaction genesis")
			}
			if err := s.keyService.verifyKeyBlock(keyblock, types.DecodeToCandidate(body.Extra), block.NumberU64()-1); err != nil {
				return err
			}
		}
		s.storeVerifiedProposal(proposalID, verified)
	}
	s.muProposalBody.RLock()
	highest = s.fhsHighest
	s.muProposalBody.RUnlock()
	if highest != nil {
		if ref.ParentHash != highest.ref.BlockHash || ref.Number != highest.ref.Number+1 || qc.Number <= highest.qc.Number {
			return fmt.Errorf("FHS certified block does not safely extend highest certificate")
		}
	} else if ref.ParentHash != s.bc.CurrentBlock().Hash() {
		return fmt.Errorf("first FHS certified block does not extend canonical head")
	}
	if err := s.persistFHSCertificateWithBroadcast(ref, qc, body, body.Extra, pendingBroadcast); err != nil {
		return fmt.Errorf("persist FHS certificate before adoption: %w", err)
	}

	verified.Block.SetFHSSignature(qc.Sign, qc.Mask, qc.ViewID, qc.LeaderID, qc.Number, ref.ExtraHash, ref.ParentQCID)
	record := &fhsCertifiedProposal{ref: ref, verified: verified, qc: hotstuff.CloneSignedState(qc)}
	s.muProposalBody.Lock()
	s.fhsCertifiedByHash[ref.BlockHash] = record
	s.fhsCertifiedByID[proposalID] = record
	s.fhsHighest = record
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
		if err := rlp.DecodeBytes(encodedCertificate, &certificate); err != nil || certificate.Version != fhsDiskVersion || certificate.QC == nil {
			return fmt.Errorf("invalid FHS certificate for %s", cursor)
		}
		encodedProposal, err := rawdb.ReadFHSProposal(s.fhsStore.db, certificate.ProposalID)
		if err != nil || len(encodedProposal) == 0 {
			return fmt.Errorf("missing FHS proposal %s", certificate.ProposalID)
		}
		var proposal fhsDiskProposal
		if err := rlp.DecodeBytes(encodedProposal, &proposal); err != nil || proposal.Version != fhsDiskVersion || proposal.ProposalID != certificate.ProposalID {
			return fmt.Errorf("invalid FHS proposal %s", certificate.ProposalID)
		}
		ref, err := types.DecodeHotstuffProposalRef(proposal.ProposalRef)
		if err != nil || ref.BlockHash != cursor || ref.ProposalID() != proposal.ProposalID || !hotstuff.SignedStateSemanticEqual(certificate.QC, &hotstuff.SignedState{State: proposal.ProposalRef, ViewID: ref.ViewID, LeaderID: ref.LeaderID, Number: ref.ViewNumber}) {
			return fmt.Errorf("FHS proposal/certificate mismatch for %s", cursor)
		}
		body := &proposalBodyMsg{
			Type:              proposalBodyMsgData,
			ProposalID:        proposal.ProposalID,
			BodyHash:          ref.BodyHash,
			Number:            ref.Number,
			ViewNumber:        ref.ViewNumber,
			ViewID:            ref.ViewID,
			LeaderID:          ref.LeaderID,
			EncodedBlock:      append([]byte(nil), proposal.EncodedBlock...),
			Extra:             append([]byte(nil), proposal.Extra...),
			ParentQC:          append([]byte(nil), proposal.ParentQC...),
			CreatedAtUnixNano: 1,
		}
		chain = append(chain, restoreRecord{ref: ref, body: body, extra: append([]byte(nil), proposal.Extra...), qc: hotstuff.CloneSignedState(certificate.QC)})
		cursor = ref.ParentHash
		if len(chain) > 128 {
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
		block, err := validateFHSProposalCommitments(record.ref, record.body.EncodedBlock, record.extra, record.body.ParentQC)
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
			additionalBytes += len(record.body.EncodedBlock) + len(record.body.Extra) + len(record.body.ParentQC) + len(record.body.AuthSig)
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
			additionalBytes += len(lastVoteBody.EncodedBlock) + len(lastVoteBody.Extra) + len(lastVoteBody.ParentQC) + len(lastVoteBody.AuthSig)
		}
	}
	if entries+additionalEntries > proposalBodyCacheMaxEntries || bytesUsed+additionalBytes > proposalBodyCacheMaxBytes {
		s.muProposalBody.Unlock()
		return fmt.Errorf("restored FHS chain exceeds proposal cache capacity")
	}
	for _, item := range staged {
		record, block, verified := item.record, item.block, item.verified
		proposalID := record.ref.ProposalID()
		body := cloneProposalBodyMsg(record.body)
		body.Type = proposalBodyMsgData
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
		body.Type = proposalBodyMsgData
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
