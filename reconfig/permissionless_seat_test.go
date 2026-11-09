package reconfig

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func testPermissionlessConfig() *params.ChainConfig {
	return &params.ChainConfig{
		ChainID:          big.NewInt(10101919),
		FairHotstuff:     true,
		FairHotstuffSeed: common.HexToHash("0xacb7b49e23815caf94dc47bcf81dab93cc986cf9ab04e243efcbc204c6a2a627"),
	}
}

func testPermissionlessCommittee() *bftview.Committee {
	pubs := []string{
		"aa11",
		"bb22",
		"cc33",
		"0410",
	}
	list := make([]*common.Cnode, len(pubs))
	for i, pub := range pubs {
		list[i] = &common.Cnode{
			Address:  "127.0.0.1:7100",
			CoinBase: "000000000000000000000000000000000000000" + string(rune('1'+i)),
			Public:   pub,
		}
	}
	return &bftview.Committee{List: list}
}

func TestEvictIndexUsesCertifiedLeaderFaults(t *testing.T) {
	config := testPermissionlessConfig()
	committee := testPermissionlessCommittee()
	parentHash := common.HexToHash("0x11")
	committeeHash := committee.RlpHash()

	rotated, err := evictIndex(config, committee, parentHash, committeeHash, []uint32{0, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	again, err := evictIndex(config, committee, parentHash, committeeHash, []uint32{0, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	if rotated != again {
		t.Fatalf("rotation seat changed between calls: %d then %d", rotated, again)
	}

	// Seats 1 and 2 are tied. 0x0410 is the smaller key and occupies seat 3,
	// so the tie between seats 1 (0xbb22) and 2 (0xcc33) selects seat 1.
	faulted, err := evictIndex(config, committee, parentHash, committeeHash, []uint32{0, 2, 2, 0})
	if err != nil {
		t.Fatal(err)
	}
	if faulted != 1 {
		t.Fatalf("tied fault seat = %d, want 1", faulted)
	}
	smaller, err := evictIndex(config, committee, parentHash, committeeHash, []uint32{1, 0, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	if smaller != 3 {
		t.Fatalf("smaller public key seat = %d, want 3", smaller)
	}
}

func TestPermissionlessSeatReplacementRoundTrip(t *testing.T) {
	config := testPermissionlessConfig()
	parentCommittee := testPermissionlessCommittee()
	parent := types.NewKeyBlock(&types.KeyBlockHeader{
		Number:     big.NewInt(1),
		ParentHash: common.HexToHash("0x01"),
		Difficulty: big.NewInt(1),
		Time:       100,
		BlockType:  types.TimeReconfig,
	})
	parent.SetCommitteeHash(parentCommittee.RlpHash())

	candidate := types.NewCandidate(parent.Hash(), big.NewInt(1), 2, 1, nil, []byte{127, 0, 0, 1}, "dd44", "00000000000000000000000000000000000000dd", 7200)
	candidate.KeyCandidate.Difficulty = big.NewInt(1)
	candidate.KeyCandidate.Time = 700
	next, evicted, index, err := applyPermissionlessSeat(config, parentCommittee, parent.Hash(), parent.CommitteeHash(), candidate, nil)
	if err != nil {
		t.Fatal(err)
	}
	if index < 0 || index >= len(next.List) || next.List[index].Public != candidate.PubKey {
		t.Fatalf("incoming member was not placed at seat %d", index)
	}
	for seat, member := range next.List {
		if seat == index {
			continue
		}
		if member.Public != parentCommittee.List[seat].Public {
			t.Fatalf("seat %d changed from %s to %s", seat, parentCommittee.List[seat].Public, member.Public)
		}
	}

	leaderIndex, err := fairHotstuffLeaderIndex(config.FairHotstuffSeed, config.ChainID.Uint64(), 4, parent.CommitteeHash(), len(parentCommittee.List))
	if err != nil {
		t.Fatal(err)
	}
	leader := parentCommittee.List[leaderIndex]
	header := &types.KeyBlockHeader{
		Number:        big.NewInt(2),
		ParentHash:    parent.Hash(),
		Difficulty:    candidate.KeyCandidate.Difficulty,
		Time:          candidate.KeyCandidate.Time,
		BlockType:     types.PowReconfig,
		CommitteeHash: next.RlpHash(),
		T_Number:      1,
	}
	keyblock := types.NewKeyBlock(header).WithBody(candidate.PubKey, candidate.Coinbase, evicted.Public, evicted.CoinBase, leader.Public, leader.CoinBase)
	keyblock.SetPermissionlessFaults(nil)
	encoded := keyblock.EncodeToBytes()
	decoded := types.DecodeToKeyBlock(encoded)
	if decoded == nil || !decoded.PermissionlessSeat() {
		t.Fatal("permissionless key block did not round-trip")
	}
	if _, _, err := checkPermissionlessKeyblock(config, parentCommittee, parent, decoded, candidate, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := next.Replace(index, &common.Cnode{Public: candidate.PubKey, CoinBase: candidate.Coinbase}); err == nil {
		t.Fatal("duplicate public key was accepted")
	}
}

func TestMissingLocalTimeoutRejectsOmission(t *testing.T) {
	local := []*hotstuff.TimeoutCertificate{{Statement: hotstuff.TimeoutStatement{TimedOutView: 9}}}
	if err := missingLocalTimeout(local, nil); err == nil {
		t.Fatal("omitted timeout proof was accepted")
	}
	if err := missingLocalTimeout(local, local); err != nil {
		t.Fatal(err)
	}
}

func TestDiscardClosedEpochTimeoutsClearsCommittedParent(t *testing.T) {
	parent := types.NewKeyBlock(&types.KeyBlockHeader{
		Number:     big.NewInt(16),
		Difficulty: big.NewInt(1),
		Time:       1,
		BlockType:  types.TimeReconfig,
	})
	child := types.NewKeyBlock(&types.KeyBlockHeader{
		Number:     big.NewInt(17),
		ParentHash: parent.Hash(),
		Difficulty: big.NewInt(1),
		Time:       2,
		BlockType:  types.PowReconfig,
	})
	kbc := &core.KeyBlockChain{}
	kbc.CurrentBlockStore(child)

	s := &Service{kbc: kbc}
	s.epochTimeoutReady = true
	s.epochTimeoutKey = parent.Hash()
	s.epochTimeouts = map[uint64]*hotstuff.TimeoutCertificate{
		115: {Statement: hotstuff.TimeoutStatement{TimedOutView: 115, KeyHash: parent.Hash()}},
	}
	s.discardClosedEpochTimeouts()
	if s.epochTimeoutKey != (common.Hash{}) || len(s.epochTimeouts) != 0 {
		t.Fatalf("closed epoch timeouts were retained: key=%s count=%d", s.epochTimeoutKey, len(s.epochTimeouts))
	}
}

func TestPermissionlessKeyProposalIncludesIndexZero(t *testing.T) {
	attempt, isDone := keyProposalPlan(false, true, 0, true, true)
	if !attempt || !isDone {
		t.Fatalf("permissionless key proposal attempt=%t done=%t", attempt, isDone)
	}
	attempt, isDone = keyProposalPlan(false, true, 0, true, false)
	if attempt || !isDone {
		t.Fatalf("early permissionless key proposal attempt=%t done=%t", attempt, isDone)
	}
}
