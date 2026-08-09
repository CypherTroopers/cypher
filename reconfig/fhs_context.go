package reconfig

import (
	"fmt"

	"github.com/cypherium/cypher/core/rawdb"
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
	store.mu.Lock()
	if err := store.loadLocked(); err != nil {
		store.mu.Unlock()
		return err
	}
	// A QC for this or a later view already supersedes the timeout proof. Do
	// not let a delayed/replayed TC recreate stale pacemaker state after the QC
	// and its committee transition were durably installed.
	if highest := store.state.HighestQC; highest != nil && tc.Statement.TimedOutView <= highest.Number {
		store.mu.Unlock()
		return nil
	}
	alreadyPersisted := false
	if highest := store.state.HighestTC; highest != nil {
		if tc.Statement.TimedOutView < highest.Statement.TimedOutView {
			store.mu.Unlock()
			return nil
		}
		if tc.Statement.TimedOutView == highest.Statement.TimedOutView {
			if tc.Statement != highest.Statement {
				store.mu.Unlock()
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
			store.mu.Unlock()
			return err
		}
		batch := store.db.NewBatch()
		if err := rawdb.WriteFHSSafetyState(batch, encoded); err != nil {
			store.mu.Unlock()
			return err
		}
		if err := writeFHSBatchSync(batch); err != nil {
			store.lastPersistenceErr = err
			store.mu.Unlock()
			return err
		}
		store.state = next
	}
	store.mu.Unlock()

	s.muCurrentView.Lock()
	if s.currentView.ViewNumber <= tc.Statement.TimedOutView {
		s.currentView.ViewNumber = tc.Statement.TimedOutView
		s.currentView.LeaderIndex = s.fairHotstuffLeaderIndexForCurrentLocked()
		s.currentView.NoDone = true
		s.waittingView.TxNumber = s.currentView.TxNumber
		s.waittingView.KeyNumber = s.currentView.KeyNumber
	}
	s.muCurrentView.Unlock()
	return nil
}
