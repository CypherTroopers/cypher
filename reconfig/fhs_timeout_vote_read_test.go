package reconfig

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/ethdb/memorydb"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func TestFHSPendingTimeoutVoteReloadsImmutableStatement(t *testing.T) {
	db := memorydb.New()
	t.Cleanup(func() { db.Close() })
	config := &params.ChainConfig{ChainID: big.NewInt(101), FairHotstuff: true}
	genesis := common.HexToHash("0xabc")
	s := &Service{chainConfig: config, fhsStore: newFHSSafetyStore(db, 101, genesis)}
	if vote, err := s.PendingFHSTimeoutVote(); err != nil || vote != nil {
		t.Fatalf("empty timeout WAL read = %v, %v", vote, err)
	}
	statement := &hotstuff.TimeoutStatement{Version: hotstuff.NewFHSSafetyState().Version,
		ChainID: 101, TimedOutView: 7, KeyHash: common.HexToHash("0x11"), CommitteeHash: common.HexToHash("0x22")}
	if err := s.PersistFHSTimeoutVote(statement); err != nil {
		t.Fatal(err)
	}
	s.fhsStore = newFHSSafetyStore(db, 101, genesis)
	read, err := s.PendingFHSTimeoutVote()
	if err != nil || read == nil || *read != *statement {
		t.Fatalf("timeout statement did not reload from WAL: %v, %v", read, err)
	}
	read.TimedOutView++
	again, err := s.PendingFHSTimeoutVote()
	if err != nil || again == nil || *again != *statement {
		t.Fatal("caller mutated the pending durable timeout statement")
	}
	injected := errors.New("unavailable safety WAL")
	s.fhsStore.lastPersistenceErr = injected
	if _, err := s.PendingFHSTimeoutVote(); !errors.Is(err, injected) {
		t.Fatalf("timeout recovery concealed safety-store error: %v", err)
	}
}
