package bftview

import (
	"testing"

	"github.com/cypherium/cypher/common"
)

func TestConsensusStateIgnoresProposalMode(t *testing.T) {
	txMode := &View{
		TxNumber:      974,
		TxHash:        common.HexToHash("0x01"),
		KeyNumber:     15,
		KeyHash:       common.HexToHash("0x02"),
		CommitteeHash: common.HexToHash("0x03"),
		LeaderIndex:   0,
		NoDone:        true,
	}
	keyMode := *txMode
	keyMode.NoDone = false

	if txMode.EqualAll(&keyMode) {
		t.Fatal("full view comparison must retain the local proposal mode")
	}
	if !txMode.EqualConsensus(&keyMode) {
		t.Fatal("proposal mode must not split an otherwise identical consensus view")
	}
	if txMode.ConsensusHash() != keyMode.ConsensusHash() {
		t.Fatal("proposal mode changed the consensus view hash")
	}
	if string(txMode.EncodeConsensusToBytes()) != string(keyMode.EncodeConsensusToBytes()) {
		t.Fatal("proposal mode changed the signed consensus state")
	}

	decoded := DecodeToView(txMode.EncodeConsensusToBytes())
	if decoded == nil {
		t.Fatal("failed to decode consensus state")
	}
	if decoded.NoDone {
		t.Fatal("signed consensus state must normalize the proposal mode")
	}
}

func TestConsensusStateStillBindsLeader(t *testing.T) {
	first := &View{TxNumber: 1, LeaderIndex: 0, NoDone: true}
	second := *first
	second.LeaderIndex = 1

	if first.EqualConsensus(&second) {
		t.Fatal("leader index must remain part of the consensus view")
	}
	if first.ConsensusHash() == second.ConsensusHash() {
		t.Fatal("leader change must produce a different consensus view hash")
	}
}

func TestConsensusStateIgnoresRecoveryRound(t *testing.T) {
	first := &View{TxNumber: 1, LeaderIndex: 0, NoDone: true}
	second := *first
	second.Round = 1

	if !first.EqualConsensus(&second) {
		t.Fatal("recovery round must not split an otherwise identical consensus view")
	}
	if first.ConsensusHash() != second.ConsensusHash() {
		t.Fatal("recovery round changed the consensus view hash")
	}
	if string(first.EncodeConsensusToBytes()) != string(second.EncodeConsensusToBytes()) {
		t.Fatal("recovery round changed the signed consensus state")
	}

	decoded := DecodeToView(second.EncodeConsensusToBytes())
	if decoded == nil {
		t.Fatal("failed to decode consensus state")
	}
	if decoded.Round != 0 {
		t.Fatalf("decoded consensus round = %d, want 0", decoded.Round)
	}
}

func TestConsensusStatePreservesFHSViewNumber(t *testing.T) {
	view := &View{
		TxNumber:   12,
		TxHash:     common.HexToHash("0x12"),
		KeyNumber:  3,
		KeyHash:    common.HexToHash("0x03"),
		Round:      7,
		ViewNumber: 41,
	}
	decoded := DecodeToView(view.EncodeConsensusToBytes())
	if decoded == nil {
		t.Fatal("failed to decode consensus view")
	}
	if decoded.Round != 0 {
		t.Fatalf("consensus recovery round = %d, want 0", decoded.Round)
	}
	if decoded.ViewNumber != 41 {
		t.Fatalf("consensus FHS view number = %d, want 41", decoded.ViewNumber)
	}
}
