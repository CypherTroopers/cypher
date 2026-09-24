package hotstuff

import (
	"errors"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/reconfig/bftview"
)

type earlyQCApplication struct {
	*fhsAsyncValidationApp
	leaderKey *bls.PublicKey
}

func (a *earlyQCApplication) CurrentState() ([]byte, string, uint64) {
	state, leader, number := a.fhsAsyncValidationApp.CurrentState()
	v := bftview.DecodeToView(state)
	v.LeaderIndex = 3
	return v.EncodeConsensusToBytes(), leader, number
}

func (a *earlyQCApplication) FHSLeaderPublicKey(keyHash common.Hash, leaderID string) (*bls.PublicKey, error) {
	if keyHash != a.keyHash || leaderID != a.leaderID {
		return nil, ErrInvalidLeaderView
	}
	return a.leaderKey, nil
}

// Sending NewView installs a view before its Prepare is received. A valid QC
// can then overtake that Prepare on another network stream; the empty view
// must not disable the same authenticated recovery supported after restart.
func TestFHSEarlyQCBeforePrepareUsesAuthenticatedCatchup(t *testing.T) {
	for _, bad := range []string{"", "aggregate", "envelope", "proposal", "conflicting cached proposal"} {
		t.Run(bad, func(t *testing.T) {
			fixture := newFHSAsyncValidationFixture(t)
			app := &earlyQCApplication{fhsAsyncValidationApp: fixture.async, leaderKey: fixture.keys[3]}
			fixture.manager.app = app
			if err := fixture.manager.newFHSNewView(); err != nil {
				t.Fatal(err)
			}
			ref, _ := fixture.prepare(t)
			state := ref.EncodeToBytes()
			msg := &HotstuffMessage{
				Code: MsgQCBroadcast, Number: ref.ViewNumber, ViewId: ref.ViewID,
				DataB: aggregateContextSignatures(t, fixture.secrets, []int{0, 1, 2}, app.ChainID(), MsgVotePrepare, ref.ViewID, ref.LeaderID, state),
				DataC: []byte{7}, DataD: state,
			}
			v := fixture.manager.views[ref.ViewID]
			if v == nil || v.hasTState() || v.replicaMsg[MsgNewView] == nil {
				t.Fatal("fixture did not install an empty NewView-only view")
			}
			switch bad {
			case "aggregate":
				msg.DataB = fixture.secrets[0].SignHash([]byte("other QC")).Serialize()
			case "proposal":
				ref.BlockHash[0] ^= 1
				msg.DataD = ref.EncodeToBytes()
			case "conflicting cached proposal":
				v.proposedTState = []byte("already received another proposal")
			}
			fixture.authenticate(t, 3, msg)
			if bad == "envelope" {
				fixture.authenticate(t, 0, msg)
			}
			certified := 0
			app.onCertified = func(qc *SignedState) error {
				certified++
				if qc.Number != msg.Number || qc.ViewID != msg.ViewId || qc.LeaderID != ref.LeaderID {
					t.Fatal("recovered a different certificate")
				}
				return nil
			}
			err := fixture.manager.HandleMessage(msg)
			if bad != "" {
				if err == nil || errors.Is(err, ErrProposalValidationPending) || len(app.highScheduled) != 0 || certified != 0 {
					t.Fatalf("invalid early QC reached catchup: err=%v jobs=%d certified=%d", err, len(app.highScheduled), certified)
				}
				return
			}
			if !errors.Is(err, ErrProposalValidationPending) || len(app.highScheduled) != 1 || certified != 0 {
				t.Fatalf("valid early QC did not schedule full content validation: err=%v jobs=%d certified=%d", err, len(app.highScheduled), certified)
			}
			if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: app.highScheduled[0].Key}); err != nil {
				t.Fatal(err)
			}
			if certified != 1 || len(app.highApplied) != 1 || fixture.manager.pendingHighQC != nil || len(app.persisted) != 0 {
				t.Fatalf("catchup did not complete exactly once without a local vote: certified=%d applied=%d pending=%v votes=%d", certified, len(app.highApplied), fixture.manager.pendingHighQC, len(app.persisted))
			}
		})
	}
}
