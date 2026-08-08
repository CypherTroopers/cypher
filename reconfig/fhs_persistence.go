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
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

const fhsDiskVersion = uint32(3)

type fhsDiskSafety struct {
	Version          uint32
	ChainID          uint64
	GenesisHash      common.Hash
	State            *hotstuff.FHSSafetyState
	HighestBlockHash common.Hash
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

func (store *fhsSafetyStore) encodeSafety(state *hotstuff.FHSSafetyState, highest common.Hash) ([]byte, error) {
	return rlp.EncodeToBytes(&fhsDiskSafety{
		Version:          fhsDiskVersion,
		ChainID:          store.chainID,
		GenesisHash:      store.genesisHash,
		State:            hotstuff.CloneFHSSafetyState(state),
		HighestBlockHash: highest,
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
func (s *Service) validateRestoredFHSVote(vote *hotstuff.PersistedVote) error {
	if vote == nil {
		return nil
	}
	if err := validatePersistedVote(vote); err != nil {
		return err
	}
	if len(vote.TState) == 0 {
		return fmt.Errorf("Fair HotStuff persisted vote has no transaction proposal reference")
	}
	if s.fhsStore == nil || s.fhsStore.db == nil {
		return fmt.Errorf("FHS safety store not initialized")
	}
	ref, err := types.DecodeHotstuffProposalRef(vote.TState)
	if err != nil {
		return fmt.Errorf("decode persisted FHS vote proposal: %w", err)
	}
	if ref.ChainID != s.ChainID() || ref.ViewNumber != vote.ViewNumber || ref.ViewID != vote.ViewID || ref.LeaderID != vote.LeaderID {
		return fmt.Errorf("persisted FHS vote proposal context mismatch")
	}
	encoded, err := rawdb.ReadFHSProposal(s.fhsStore.db, ref.ProposalID())
	if err != nil || len(encoded) == 0 {
		return fmt.Errorf("missing persisted FHS vote proposal %s", ref.ProposalID())
	}
	var proposal fhsDiskProposal
	if err := rlp.DecodeBytes(encoded, &proposal); err != nil {
		return fmt.Errorf("decode persisted FHS vote proposal %s: %w", ref.ProposalID(), err)
	}
	if proposal.Version != fhsDiskVersion || proposal.ProposalID != ref.ProposalID() ||
		!bytes.Equal(proposal.ProposalRef, vote.TState) || !bytes.Equal(proposal.Extra, vote.Extra) {
		return fmt.Errorf("persisted FHS vote proposal record mismatch")
	}
	if _, err := validateFHSProposalCommitments(ref, proposal.EncodedBlock, proposal.Extra, proposal.ParentQC); err != nil {
		return fmt.Errorf("invalid persisted FHS vote proposal: %w", err)
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

func (s *Service) persistFHSCertificate(ref *types.HotstuffProposalRef, qc *hotstuff.SignedState, body *proposalBodyMsg, extra []byte) error {
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
	// A certificate at (or above) the pending timeout view supersedes that
	// timeout vote. Persist the cleanup in the same synchronous batch as the
	// QC so a crash cannot leave an otherwise valid WAL that recovery rejects.
	if next.LastTimeoutVote != nil && next.LastTimeoutVote.TimedOutView <= qc.Number {
		next.LastTimeoutVote = nil
	}
	encodedSafety, err := store.encodeSafety(next, ref.BlockHash)
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
	if err := hotstuff.VerifyTimeoutCertificate(state.HighestTC, keys, hotstuff.CalcThreshold(len(keys))); err != nil {
		return 0, fmt.Errorf("invalid persisted FHS timeout certificate: %w", err)
	}
	if statement.KeyNumber != current.KeyNumber || statement.KeyHash != current.KeyHash || statement.CommitteeHash != current.CommitteeHash {
		return 0, fmt.Errorf("persisted FHS timeout certificate has inactive committee")
	}
	return targetView, nil
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
	return s.adoptFHSHighQC(qc, false)
}

func (s *Service) adoptFHSHighQC(qc *hotstuff.SignedState, notify bool) error {
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
		body, err = s.waitProposalBody(ref)
		if err != nil {
			return fmt.Errorf("retrieve certified FHS proposal body: %w", err)
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
		if err := s.adoptFHSHighQC(parentQC, false); err != nil {
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
		verified, err = s.txService.verifyHotstuffProposal(ref, block, body.Extra)
		if err != nil {
			return err
		}
		if block.BlockType() == types.Key_Block {
			keyblock := types.DecodeToKeyBlock(block.KeyInfo())
			if keyblock == nil {
				return fmt.Errorf("invalid certified FHS keyblock")
			}
			if err := s.keyService.verifyKeyBlock(keyblock, types.DecodeToCandidate(body.Extra)); err != nil {
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
	if err := s.persistFHSCertificate(ref, qc, body, body.Extra); err != nil {
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
	state, highestHash, err := s.fhsStore.snapshot()
	if err != nil {
		return err
	}
	if state == nil {
		return nil
	}
	if err := s.validateRestoredFHSVote(state.LastVote); err != nil {
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
	// Validate timeout recovery now, but publish its view only after every WAL
	// certificate and proposal sidecar has also passed validation.
	recoveredView, err := s.validateFHSTimeoutState(state)
	if err != nil {
		return err
	}
	if qcMissing {
		s.applyFHSRecoveredView(recoveredView)
		return nil
	}

	current := s.bc.CurrentBlock()
	if current == nil {
		return fmt.Errorf("cannot restore FHS state without canonical head")
	}
	if highestHash == current.Hash() || s.bc.GetCanonicalHash(highestRef.Number) == highestHash {
		s.applyFHSRecoveredView(recoveredView)
		return nil
	}

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
		verified, err := s.txService.verifyHotstuffProposalWithParent(record.ref, block, record.extra, parentVerified)
		if err != nil {
			return fmt.Errorf("replay restored FHS proposal %s: %w", record.ref.BlockHash, err)
		}
		if block.BlockType() == types.Key_Block {
			keyblock := types.DecodeToKeyBlock(block.KeyInfo())
			if keyblock == nil {
				return fmt.Errorf("invalid restored FHS keyblock %s", record.ref.BlockHash)
			}
			if err := s.keyService.verifyKeyBlock(keyblock, types.DecodeToCandidate(record.extra)); err != nil {
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
	s.muProposalBody.Unlock()

	// adoptCertified cannot fail. Keeping it after the error-free cache install
	// prevents a corrupt/capacity-exhausted WAL from publishing a prefix.
	s.txService.mu.Lock()
	for _, item := range staged {
		s.txService.proposedChain.adoptCertified(item.block)
	}
	s.txService.mu.Unlock()
	if s.fhsHighest != nil {
		s.muCurrentView.Lock()
		s.currentView.TxNumber = s.fhsHighest.ref.Number
		s.currentView.TxHash = s.fhsHighest.ref.BlockHash
		s.currentView.ViewNumber = recoveredView
		s.currentView.LeaderIndex = s.fairHotstuffLeaderIndexForCurrentLocked()
		s.currentView.NoDone = true
		s.waittingView.TxNumber = s.currentView.TxNumber
		s.waittingView.KeyNumber = s.currentView.KeyNumber
		s.muCurrentView.Unlock()
	}
	return nil
}
