package reconfig

import (
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func TestValidateViewUsesCurrentViewSnapshot(t *testing.T) {
	s := &Service{}
	s.currentView = bftview.View{
		TxNumber:  301,
		KeyNumber: 1,
	}

	future := bftview.View{
		TxNumber:  302,
		KeyNumber: 1,
	}

	// ValidateView must classify against currentView, which is the state encoded
	// by CurrentState. The blockchain may already be at 302 while procBlockDone
	// has not advanced currentView yet.
	_, number, err := validateViewAgainstSnapshot(future.EncodeToBytes(), s.currentView)
	if err != hotstuff.ErrFutureState {
		t.Fatalf("ValidateView snapshot error = %v, want %v", err, hotstuff.ErrFutureState)
	}
	if number != 302 {
		t.Fatalf("expected number = %d, want 302", number)
	}
}

func TestObserveHotstuffProgressAcceptsDifferentCanonicalView(t *testing.T) {
	s := &Service{
		lastProgressN:      10,
		lastProgressViewID: common.HexToHash("0xffff"),
		lastProgressRank:   3,
		hotstuffProgressAt: time.Now().Add(-time.Minute),
	}
	nextView := common.HexToHash("0x01")

	s.observeHotstuffProgress(&hotstuff.HotstuffMessage{
		Code:   hotstuff.MsgPrepare,
		Number: 10,
		ViewId: nextView,
	})

	if s.lastProgressViewID != nextView {
		t.Fatalf("progress view = %s, want %s", s.lastProgressViewID, nextView)
	}
	if time.Since(s.hotstuffProgressAt) > time.Second {
		t.Fatalf("progress timestamp was not refreshed: %s", s.hotstuffProgressAt)
	}
}

func TestValidateViewNormalizesProposalMode(t *testing.T) {
	current := bftview.View{
		TxNumber:      974,
		TxHash:        common.HexToHash("0x01"),
		KeyNumber:     15,
		KeyHash:       common.HexToHash("0x02"),
		CommitteeHash: common.HexToHash("0x03"),
		LeaderIndex:   0,
		NoDone:        true,
	}
	wire := current
	wire.NoDone = false

	expected, number, err := validateViewAgainstSnapshot(wire.EncodeConsensusToBytes(), current)
	if err != nil {
		t.Fatalf("proposal-mode-only difference rejected: %v", err)
	}
	if number != current.TxNumber+1 {
		t.Fatalf("expected number = %d, want %d", number, current.TxNumber+1)
	}
	if string(expected) != string(current.EncodeConsensusToBytes()) {
		t.Fatal("validation returned non-canonical consensus state")
	}
}
