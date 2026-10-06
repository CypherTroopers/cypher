package reconfig

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync/atomic"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

var _ hotstuff.FHSApplication = (*Service)(nil)

// ValidateFHSContext verifies the common target-view identity after any QC/TC
// carried by the message has been durably adopted. It intentionally does not
// compare transaction hashes from different NewView reporters.
func (s *Service) ValidateFHSContext(ctx *hotstuff.FHSViewContext) error {
	if !s.fairHotstuffEnabled() || ctx == nil {
		return fmt.Errorf("Fair HotStuff is not enabled")
	}
	if err := ctx.Validate(); err != nil {
		return err
	}
	if ctx.ChainID != s.ChainID() {
		return fmt.Errorf("FHS context chain mismatch")
	}
	current := s.GetCurrentView()
	if ctx.TargetView != current.ViewNumber+1 {
		return fmt.Errorf("FHS target view mismatch: have %d want %d", ctx.TargetView, current.ViewNumber+1)
	}
	if ctx.KeyNumber != current.KeyNumber || ctx.KeyHash != current.KeyHash || ctx.CommitteeHash != current.CommitteeHash {
		return fmt.Errorf("FHS context committee mismatch")
	}
	committee, err := s.loadViewCommittee(current, true)
	if err != nil {
		return err
	}
	if current.LeaderIndex >= uint(len(committee.List)) || committee.List[current.LeaderIndex] == nil {
		return fmt.Errorf("FHS leader index outside committee")
	}
	leader := committee.List[current.LeaderIndex]
	expectedID := bftview.GetNodeID(leader.Address, leader.Public)
	if expectedID == "" || ctx.LeaderID != expectedID {
		return fmt.Errorf("FHS target leader mismatch")
	}
	return nil
}

// AcceptFHSTimeoutCertificate durably records a 2f+1 timeout proof before it
// changes the pacemaker view. Signature bytes are not part of TC identity;
// different valid signer subsets for the same statement are idempotent.
func (s *Service) AcceptFHSTimeoutCertificate(tc *hotstuff.TimeoutCertificate) error {
	if !s.fairHotstuffEnabled() || tc == nil || tc.Statement.ChainID != s.ChainID() {
		return fmt.Errorf("invalid FHS timeout certificate")
	}
	keys, err := s.GetPublicKey(tc.Statement.KeyHash)
	if err != nil {
		return err
	}
	if err := hotstuff.ValidateBFTCommitteeSize(len(keys)); err != nil {
		return err
	}
	if err := hotstuff.VerifyTimeoutCertificate(tc, keys, hotstuff.CalcThreshold(len(keys))); err != nil {
		return err
	}
	current := s.GetCurrentView()
	if tc.Statement.KeyNumber != current.KeyNumber || tc.Statement.KeyHash != current.KeyHash || tc.Statement.CommitteeHash != current.CommitteeHash {
		return fmt.Errorf("timeout certificate committee is not active")
	}
	if s.fhsStore == nil {
		return fmt.Errorf("FHS safety store not initialized")
	}

	store := s.fhsStore
	store.safetyMu.Lock()
	if err := store.loadLocked(); err != nil {
		store.safetyMu.Unlock()
		return err
	}
	if store.recoveryPendingLocked() {
		store.safetyMu.Unlock()
		return errFHSRecoveryPending
	}
	// A QC for this or a later view already supersedes the timeout proof. Do
	// not let a delayed/replayed TC recreate stale pacemaker state after the QC
	// and its committee transition were durably installed.
	if highest := store.state.HighestQC; highest != nil && tc.Statement.TimedOutView <= highest.Number {
		store.safetyMu.Unlock()
		return nil
	}
	alreadyPersisted := false
	if highest := store.state.HighestTC; highest != nil {
		if tc.Statement.TimedOutView < highest.Statement.TimedOutView {
			store.safetyMu.Unlock()
			return nil
		}
		if tc.Statement.TimedOutView == highest.Statement.TimedOutView {
			if tc.Statement != highest.Statement {
				store.safetyMu.Unlock()
				return fmt.Errorf("conflicting timeout certificates for view %d", tc.Statement.TimedOutView)
			}
			alreadyPersisted = true
		}
	}
	if !alreadyPersisted {
		next := hotstuff.CloneFHSSafetyState(store.state)
		next.HighestTC = hotstuff.CloneTimeoutCertificate(tc)
		if next.LastTimeoutVote != nil && next.LastTimeoutVote.TimedOutView <= tc.Statement.TimedOutView {
			next.LastTimeoutVote = nil
		}
		if next.LastTimeoutView < tc.Statement.TimedOutView {
			next.LastTimeoutView = tc.Statement.TimedOutView
		}
		encoded, err := store.encodeSafety(next, store.highestBlockHash)
		if err != nil {
			store.safetyMu.Unlock()
			return err
		}
		batch := store.db.NewBatch()
		if err := rawdb.WriteFHSSafetyState(batch, encoded); err != nil {
			store.safetyMu.Unlock()
			return err
		}
		if err := writeFHSBatchSync(batch); err != nil {
			store.lastPersistenceErr = err
			store.safetyMu.Unlock()
			return err
		}
		store.state = next
	}
	store.safetyMu.Unlock()

	s.muCurrentView.Lock()
	if s.currentView.ViewNumber < tc.Statement.TimedOutView {
		s.currentView.ViewNumber = tc.Statement.TimedOutView
		s.currentView.LeaderIndex = s.fairHotstuffLeaderIndexForCurrentLocked()
		s.currentView.NoDone = true
		s.waittingView.TxNumber = s.currentView.TxNumber
		s.waittingView.KeyNumber = s.currentView.KeyNumber
	}
	s.muCurrentView.Unlock()
	return nil
}

// FHSRoute is the authoritative transaction-ingress route for the next Fair
// HotStuff proposal view. ProposalView is the exact view used by the FHS leader
// election PRF; LeaderIndex is therefore never inferred from committee order.
//
// The route is intentionally expressed in rnet committee coordinates. The eth
// TxQUIC layer owns the rnet->TxQUIC port mapping and route caching.
type FHSRoute struct {
	Enabled       bool            `json:"enabled"`
	CurrentView   uint64          `json:"currentView"`
	ProposalView  uint64          `json:"proposalView"`
	TxNumber      uint64          `json:"txNumber"`
	TxHash        common.Hash     `json:"txHash"`
	KeyNumber     uint64          `json:"keyNumber"`
	KeyHash       common.Hash     `json:"keyHash"`
	CommitteeHash common.Hash     `json:"committeeHash"`
	LeaderIndex   uint            `json:"leaderIndex"`
	LeaderID      string          `json:"leaderId"`
	Leader        *common.Cnode   `json:"leader"`
	Committee     []*common.Cnode `json:"committee"`
}

// OnNewView --------------------------------------------------------------------------
func (s *Service) OnNewView(data []byte, extraes [][]byte) error { //buf is snapshot, //verify repla' block before newview
	view := bftview.DecodeToView(data)
	if view == nil {
		return fmt.Errorf("invalid new-view state")
	}
	log.Info("OnNewView..", "txNumber", view.TxNumber, "keyNumber", view.KeyNumber)

	s.muCurrentView.Lock()
	s.replicaView = view
	if view.EqualNoIndex(&s.currentView) {
		s.currentView.LeaderIndex = view.LeaderIndex
	}
	s.muCurrentView.Unlock()

	var bestCandidates []*types.Candidate
	for _, extraD := range extraes {
		if extraD == nil {
			continue
		}
		cand := types.DecodeToCandidate(extraD)
		if cand == nil {
			continue
		}
		bestCandidates = append(bestCandidates, cand)
	}
	s.keyService.setBestCandidate(bestCandidates)
	s.clearProposalNoWork()
	return nil
}

func (s *Service) CurrentN() uint64 {
	curView := s.GetCurrentView()
	if s.fairHotstuffEnabled() {
		return curView.ViewNumber + 1
	}
	return curView.TxNumber + 1
}

// CurrentState call by hotstuff
func (s *Service) CurrentState() ([]byte, string, uint64) { //recv by onnewview
	curView := s.GetCurrentView()
	leaderID := ""
	mb, committeeErr := s.loadViewCommittee(curView, true)
	committeeSize := 0
	if mb != nil {
		committeeSize = len(mb.List)
	}
	if mb != nil && curView.LeaderIndex < uint(len(mb.List)) && mb.List[curView.LeaderIndex] != nil {
		leader := mb.List[curView.LeaderIndex]
		log.Info("CurrentState.NextLeader", "index", curView.LeaderIndex, "ip", leader.Address)
		leaderID = bftview.GetNodeID(leader.Address, leader.Public)
	} else {
		log.Error("CurrentState.NextLeader: invalid committee or leader index",
			"index", curView.LeaderIndex,
			"committeeSize", committeeSize,
			"err", committeeErr)
		s.Committee_Request(curView.KeyNumber, curView.KeyHash)
	}

	log.Info("CurrentState", "TxNumber", curView.TxNumber, "KeyNumber", curView.KeyNumber, "LeaderIndex", curView.LeaderIndex, "NoDone", curView.NoDone)

	number := curView.TxNumber + 1
	if s.fairHotstuffEnabled() {
		number = curView.ViewNumber + 1
	}
	return curView.EncodeConsensusToBytes(), leaderID, number
}

// FHSProposalReadinessSnapshot returns only immutable/copy-on-read consensus
// identity for the local retry gate. Unlike CurrentState it never loads a
// committee, logs, requests committee data, or performs network work.
func (s *Service) FHSProposalReadinessSnapshot() ([]byte, uint64, *hotstuff.SignedState) {
	s.muCurrentView.Lock()
	current := s.currentView
	s.muCurrentView.Unlock()
	return current.EncodeConsensusToBytes(), current.ViewNumber + 1, s.SelectedFHSProposalParent()
}

// GetPublicKey resolves the exact historical signer order for a key block.
func (s *Service) GetPublicKey(keyHash common.Hash) ([]*bls.PublicKey, error) {
	if keyHash == (common.Hash{}) {
		return nil, fmt.Errorf("empty committee key block hash")
	}
	_, committee, _, err := s.resolveExactFHSCommittee(keyHash, false)
	if err != nil {
		return nil, err
	}
	publicKeys := committee.ToBlsPublicKeys(keyHash)
	if len(publicKeys) == 0 || len(publicKeys) != len(committee.List) {
		return nil, fmt.Errorf("invalid committee public keys for key block %s", keyHash)
	}
	return append([]*bls.PublicKey(nil), publicKeys...), nil
}

// FHSLeaderPublicKey resolves the exact historical address-to-BLS-key binding
// used to authenticate a self-contained QC broadcast after volatile views have
// been lost. Looking up by key hash prevents a later committee from
// reinterpreting an older certificate.
func (s *Service) FHSLeaderPublicKey(keyHash common.Hash, leaderID string) (*bls.PublicKey, error) {
	_, resolved, _, err := s.resolveExactFHSCommittee(keyHash, false)
	if err != nil {
		return nil, err
	}
	for _, node := range resolved.List {
		if node != nil && node.Address == leaderID {
			public := bftview.StrToBlsPubKey(node.Public)
			if public == nil {
				return nil, fmt.Errorf("invalid BLS key for historical leader %s", leaderID)
			}
			return public, nil
		}
	}
	return nil, fmt.Errorf("leader %s is not in historical committee %s", leaderID, keyHash)
}

// CheckView call by hotstuff
func (s *Service) CheckView(data []byte) error {
	_, _, _, err := s.ValidateView(data)
	return err
}

func validateViewAgainstSnapshot(data []byte, current bftview.View, useFHS2Chain bool) ([]byte, uint64, error) {
	view := bftview.DecodeToView(data)
	if view == nil {
		return nil, 0, fmt.Errorf("invalid hotstuff view encoding")
	}

	expectedState := current.EncodeConsensusToBytes()
	expectedNumber := current.TxNumber + 1
	if useFHS2Chain {
		expectedNumber = current.ViewNumber + 1
		if view.ViewNumber < current.ViewNumber {
			return expectedState, expectedNumber, hotstuff.ErrOldState
		}
		if view.ViewNumber > current.ViewNumber {
			return expectedState, expectedNumber, hotstuff.ErrFutureState
		}
	}
	if view.KeyNumber < current.KeyNumber ||
		(view.KeyNumber == current.KeyNumber && view.TxNumber < current.TxNumber) {
		return expectedState, expectedNumber, hotstuff.ErrOldState
	}
	if view.KeyNumber > current.KeyNumber ||
		(view.KeyNumber == current.KeyNumber && view.TxNumber > current.TxNumber) {
		return expectedState, expectedNumber, hotstuff.ErrFutureState
	}
	return expectedState, expectedNumber, nil
}

// ValidateView returns validation and the expected state from one currentView
// snapshot. Reading the blockchain height first and currentView afterwards can
// observe a block between insertion and procBlockDone, incorrectly turning a
// future NewView into a mismatched current view and permanently dropping it.
func (s *Service) ValidateView(data []byte) ([]byte, string, uint64, error) {
	if !s.isRunning() {
		return nil, "", 0, types.ErrNotRunning
	}
	view := bftview.DecodeToView(data)
	if view == nil {
		return nil, "", 0, fmt.Errorf("invalid hotstuff view encoding")
	}

	s.muCurrentView.Lock()
	current := s.currentView
	s.muCurrentView.Unlock()

	log.Debug("ValidateView..",
		"txNumber", view.TxNumber,
		"keyNumber", view.KeyNumber,
		"local key number", current.KeyNumber,
		"tx number", current.TxNumber)

	expectedState, expectedNumber, err := validateViewAgainstSnapshot(data, current, s.fairHotstuffEnabled())
	if err != nil {
		return expectedState, "", expectedNumber, err
	}
	committee, err := s.loadViewCommittee(&current, true)
	if err != nil {
		return expectedState, "", expectedNumber, err
	}
	if current.LeaderIndex >= uint(len(committee.List)) || committee.List[current.LeaderIndex] == nil {
		return expectedState, "", expectedNumber, fmt.Errorf("invalid leader index %d for committee %s", current.LeaderIndex, current.KeyHash)
	}
	leader := committee.List[current.LeaderIndex]
	leaderID := bftview.GetNodeID(leader.Address, leader.Public)
	if leaderID == "" {
		return expectedState, "", expectedNumber, fmt.Errorf("empty leader id for committee %s", current.KeyHash)
	}
	return expectedState, leaderID, expectedNumber, nil
}

func (s *Service) normalizeLeaderIndex(index uint) uint {
	mb := bftview.GetCurrentMember()
	if mb == nil || len(mb.List) == 0 {
		return 0
	}
	if index >= uint(len(mb.List)) {
		return 0
	}
	return index
}

// refreshFHSRouteBaseLocked bootstraps/repairs the route view from canonical
// chain state without discarding a validator's newer certified/timeout view.
// This is important for common RPC nodes: they instantiate reconfig but do not
// run the validator pacemaker, so currentView must still be usable as a routing
// authority before miner.start is ever called on that node.
func (s *Service) refreshFHSRouteBaseLocked() error {
	if s == nil || !s.fairHotstuffEnabled() || s.bc == nil || s.kbc == nil {
		return fmt.Errorf("Fair HotStuff route is unavailable")
	}
	curBlock := s.bc.CurrentBlock()
	curKeyBlock := s.kbc.CurrentBlock()
	if curBlock == nil || curKeyBlock == nil {
		return fmt.Errorf("Fair HotStuff canonical heads are unavailable")
	}

	passive := atomic.LoadInt32(&s.runningState) == 0
	needsTxRefresh := s.currentView.TxHash == (common.Hash{}) || s.currentView.TxNumber < curBlock.NumberU64()
	if passive && s.currentView.TxNumber == curBlock.NumberU64() && s.currentView.TxHash != curBlock.Hash() {
		needsTxRefresh = true
	}
	needsKeyRefresh := s.currentView.KeyHash == (common.Hash{}) || s.currentView.KeyNumber < curKeyBlock.NumberU64()
	if passive && s.currentView.KeyNumber == curKeyBlock.NumberU64() && s.currentView.KeyHash != curKeyBlock.Hash() {
		needsKeyRefresh = true
	}

	routeBaseChanged := false
	if needsTxRefresh {
		s.currentView.TxNumber = curBlock.NumberU64()
		s.currentView.TxHash = curBlock.Hash()
		s.currentView.Round = 0
		s.currentView.NoDone = true

		canonicalView := curBlock.NumberU64()
		if signInfo := curBlock.SignInfo(); signInfo != nil && signInfo.ViewNumber > canonicalView {
			canonicalView = signInfo.ViewNumber
		}
		// A running validator may already know a newer TC/QC view than the
		// canonical head. Never move that pacemaker backwards. Passive/common
		// nodes, however, must advance to every newly imported canonical view.
		if canonicalView > s.currentView.ViewNumber {
			s.currentView.ViewNumber = canonicalView
		}
		routeBaseChanged = true
	}
	if needsKeyRefresh {
		s.currentView.KeyNumber = curKeyBlock.NumberU64()
		s.currentView.KeyHash = curKeyBlock.Hash()
		s.currentView.CommitteeHash = curKeyBlock.CommitteeHash()
		s.currentView.Round = 0
		s.currentView.NoDone = true
		routeBaseChanged = true
	}
	if s.currentView.CommitteeHash == (common.Hash{}) && s.currentView.KeyHash == curKeyBlock.Hash() {
		s.currentView.CommitteeHash = curKeyBlock.CommitteeHash()
		routeBaseChanged = true
	}

	// Common RPC nodes do not run the FHS pacemaker. Whenever canonical chain
	// import moves their route base, maintain currentView.LeaderIndex exactly as
	// a validator would: leader(currentView.ViewNumber+1, seed, committeeHash).
	// CurrentFHSRoute then reads this field as the sole leader authority.
	if routeBaseChanged {
		if s.currentView.ViewNumber == ^uint64(0) {
			return fmt.Errorf("Fair HotStuff proposal view overflow")
		}
		committee, err := s.loadViewCommittee(&s.currentView, false)
		if err != nil {
			return err
		}
		if committee == nil || len(committee.List) == 0 || committee.RlpHash() != s.currentView.CommitteeHash {
			return fmt.Errorf("Fair HotStuff route committee is unavailable")
		}
		leaderIndex, err := fairHotstuffLeaderIndex(
			s.chainConfig.FairHotstuffSeed,
			s.ChainID(),
			s.currentView.ViewNumber+1,
			s.currentView.CommitteeHash,
			len(committee.List),
		)
		if err != nil {
			return err
		}
		s.currentView.LeaderIndex = leaderIndex
	}
	return nil
}

// CurrentFHSRoute returns the single authoritative route for the next proposal
// view. The leader is always derived from
//
//	ProposalView + FairHotstuffSeed + CommitteeHash
//
// and currentView.LeaderIndex is repaired to that deterministic result before
// the route is published. fixedCommittee only freezes committee membership; it
// never selects committee index 0 as the Fair HotStuff leader.
func (s *Service) CurrentFHSRoute() (*FHSRoute, error) {
	if s == nil || !s.fairHotstuffEnabled() {
		return nil, fmt.Errorf("Fair HotStuff is not enabled")
	}

	// Committee/view transitions can race this read. Retry against a fresh
	// snapshot rather than combining a committee from one epoch with another
	// epoch's proposal view.
	for attempt := 0; attempt < 4; attempt++ {
		s.muCurrentView.Lock()
		if err := s.refreshFHSRouteBaseLocked(); err != nil {
			s.muCurrentView.Unlock()
			return nil, err
		}
		view := s.currentView
		s.muCurrentView.Unlock()

		if view.ViewNumber == ^uint64(0) {
			return nil, fmt.Errorf("Fair HotStuff proposal view overflow")
		}
		proposalView := view.ViewNumber + 1
		committee, err := s.loadViewCommittee(&view, true)
		if err != nil {
			return nil, err
		}
		if committee == nil || len(committee.List) == 0 || committee.RlpHash() != view.CommitteeHash {
			return nil, fmt.Errorf("Fair HotStuff route committee is unavailable")
		}

		// currentView.LeaderIndex is the single authoritative leader selector.
		// Recompute only as an invariant check; never infer a replacement from
		// committee ordering and never silently route to index 0.
		expectedIndex, err := fairHotstuffLeaderIndex(
			s.chainConfig.FairHotstuffSeed,
			s.ChainID(),
			proposalView,
			view.CommitteeHash,
			len(committee.List),
		)
		if err != nil {
			return nil, err
		}
		if view.LeaderIndex != expectedIndex {
			return nil, fmt.Errorf("Fair HotStuff leader invariant mismatch: proposalView=%d currentView.LeaderIndex=%d deterministic=%d", proposalView, view.LeaderIndex, expectedIndex)
		}
		if view.LeaderIndex >= uint(len(committee.List)) || committee.List[view.LeaderIndex] == nil {
			return nil, fmt.Errorf("Fair HotStuff leader index %d is outside committee", view.LeaderIndex)
		}

		s.muCurrentView.Lock()
		// If a QC/TC or key transition moved the view while the committee was
		// resolved, restart with the new authoritative state.
		if s.currentView.ViewNumber != view.ViewNumber ||
			s.currentView.KeyNumber != view.KeyNumber ||
			s.currentView.KeyHash != view.KeyHash ||
			s.currentView.CommitteeHash != view.CommitteeHash ||
			s.currentView.LeaderIndex != view.LeaderIndex {
			s.muCurrentView.Unlock()
			continue
		}
		s.muCurrentView.Unlock()

		leader := committee.List[view.LeaderIndex]
		leaderCopy := *leader
		leaderID := bftview.GetNodeID(leader.Address, leader.Public)
		if leaderID == "" {
			return nil, fmt.Errorf("Fair HotStuff leader identity is empty")
		}
		committeeCopy := make([]*common.Cnode, len(committee.List))
		for index, member := range committee.List {
			if member == nil {
				return nil, fmt.Errorf("Fair HotStuff committee member %d is nil", index)
			}
			memberCopy := *member
			committeeCopy[index] = &memberCopy
		}
		return &FHSRoute{
			Enabled:       true,
			CurrentView:   view.ViewNumber,
			ProposalView:  proposalView,
			TxNumber:      view.TxNumber,
			TxHash:        view.TxHash,
			KeyNumber:     view.KeyNumber,
			KeyHash:       view.KeyHash,
			CommitteeHash: view.CommitteeHash,
			LeaderIndex:   view.LeaderIndex,
			LeaderID:      leaderID,
			Leader:        &leaderCopy,
			Committee:     committeeCopy,
		}, nil
	}
	return nil, fmt.Errorf("Fair HotStuff route changed repeatedly while resolving")
}

func (s *Service) fairHotstuffLeaderIndexForTargetLocked(targetView uint64, committeeHash common.Hash) uint {
	if s.chainConfig == nil || s.chainConfig.FairHotstuffSeed == (common.Hash{}) || targetView == 0 ||
		committeeHash == (common.Hash{}) || committeeHash != s.currentView.CommitteeHash {
		return 0
	}
	// Resolve the committee from the same historical key block whose hash is in
	// the PRF input. The mutable global current committee can switch before the
	// view fields do, which would otherwise combine an old hash with a new size.
	view := s.currentView
	committee, err := s.loadViewCommittee(&view, false)
	if err != nil || committee == nil || len(committee.List) == 0 || committee.RlpHash() != committeeHash {
		return 0
	}
	index, err := fairHotstuffLeaderIndex(s.chainConfig.FairHotstuffSeed, s.ChainID(), targetView, committeeHash, len(committee.List))
	if err != nil {
		return 0
	}
	return index
}

func fairHotstuffLeaderIndex(seed common.Hash, chainID, targetView uint64, committeeHash common.Hash, committeeSize int) (uint, error) {
	if seed == (common.Hash{}) || chainID == 0 || targetView == 0 || committeeHash == (common.Hash{}) || committeeSize <= 0 {
		return 0, fmt.Errorf("invalid Fair HotStuff leader election input")
	}
	n := uint64(committeeSize)
	// Rejection sampling avoids the modulo bias that would otherwise make the
	// first (2^64 mod n) committee indices slightly more likely.
	cutoff := -n % n
	for counter := uint64(0); ; counter++ {
		h := sha256.New()
		h.Write([]byte("cypher-fhs-leader-v2"))
		h.Write(seed[:])
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], chainID)
		h.Write(encoded[:])
		binary.BigEndian.PutUint64(encoded[:], targetView)
		h.Write(encoded[:])
		h.Write(committeeHash[:])
		binary.BigEndian.PutUint64(encoded[:], counter)
		h.Write(encoded[:])
		sum := h.Sum(nil)
		candidate := binary.BigEndian.Uint64(sum[:8])
		if candidate >= cutoff {
			return uint(candidate % n), nil
		}
	}
}

func (s *Service) fairHotstuffLeaderIndexForCurrentLocked() uint {
	// The block and its QC are deliberately not entropy sources. A Byzantine
	// leader can choose the block contents and the 2f+1 signer subset.
	return s.fairHotstuffLeaderIndexForTargetLocked(s.currentView.ViewNumber+1, s.currentView.CommitteeHash)
}

// Update current view data
func (s *Service) updateCurrentView(curBlock *types.Block, curKeyBlock *types.KeyBlock, fromKeyBlock bool) { //call by keyblock done
	s.muCurrentView.Lock()

	if curBlock == nil {
		curBlock = s.bc.CurrentBlock()
	}
	if curKeyBlock == nil {
		curKeyBlock = s.kbc.CurrentBlock()
	}

	s.currentView.TxNumber = curBlock.NumberU64()
	s.currentView.TxHash = curBlock.Hash()
	s.currentView.KeyNumber = curKeyBlock.NumberU64()
	s.currentView.KeyHash = curKeyBlock.Hash()
	s.currentView.CommitteeHash = curKeyBlock.CommitteeHash()
	s.currentView.Round = 0

	if s.fairHotstuffEnabled() {
		viewNumber := curBlock.NumberU64()
		if signInfo := curBlock.SignInfo(); signInfo != nil && signInfo.ViewNumber > viewNumber {
			viewNumber = signInfo.ViewNumber
		}
		s.currentView.ViewNumber = viewNumber
		s.currentView.LeaderIndex = s.fairHotstuffLeaderIndexForCurrentLocked()
		s.currentView.NoDone = true
	} else if fromKeyBlock || curBlock.NumberU64() > curKeyBlock.T_Number() {
		s.currentView.LeaderIndex = 0
		s.currentView.NoDone = true
	}
	log.Debug("updateCurrentView", "TxNumber", s.currentView.TxNumber, "KeyNumber", s.currentView.KeyNumber, "LeaderIndex", s.currentView.LeaderIndex, "NoDone", s.currentView.NoDone, "Round", s.currentView.Round)
	sendNewView := false
	newViewNumber := s.currentView.TxNumber
	if fromKeyBlock || (s.currentView.TxNumber >= s.waittingView.TxNumber && s.currentView.KeyNumber >= s.waittingView.KeyNumber) || curBlock.BlockType() == types.Key_Block {
		sendNewView = true
		s.waittingView.KeyNumber = s.currentView.KeyNumber
		s.waittingView.TxNumber = s.currentView.TxNumber
	}
	s.muCurrentView.Unlock()

	// sendNewViewMsg snapshots currentView through GetCurrentView, so it must run
	// after releasing muCurrentView.
	if sendNewView && atomic.LoadInt32(&s.runningState) == 1 {
		s.sendNewViewMsg(newViewNumber)
	}
}

func (s *Service) GetCurrentView() *bftview.View {
	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()

	v := s.currentView
	return &v
}

func (s *Service) currentHotstuffBaseNumber() uint64 {
	if s.fairHotstuffEnabled() {
		return s.GetCurrentView().ViewNumber
	}
	return s.bc.CurrentBlockN()
}
