package hotstuff

import (
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
)

type simulatedSafetyWAL struct {
	view     uint64
	proposal common.Hash
}

type simulatedFHSReplica struct {
	secret *bls.SecretKey
	wal    *simulatedSafetyWAL
}

func (replica *simulatedFHSReplica) vote(view uint64, viewID common.Hash, leader string, proposal []byte) *bls.Sign {
	proposalID := StateDigest(proposal)
	if replica.wal.view > view || (replica.wal.view == view && replica.wal.proposal != proposalID) {
		return nil
	}
	// This assignment models the synchronous WAL write which production performs
	// before signing or sending VotePrepare.
	replica.wal.view, replica.wal.proposal = view, proposalID
	digest := hotstuffContextDigest(10101919, MsgVotePrepare, viewID, leader, proposal)
	digest, err := fhsSignerDigest(digest, replica.secret.GetPublicKey())
	if err != nil {
		return nil
	}
	return replica.secret.SignHash(digest)
}

func aggregateSimulationVotes(votes map[int]*bls.Sign, committeeSize int) ([]byte, []byte) {
	mask := make([]byte, canonicalMaskLength(committeeSize))
	var aggregate *bls.Sign
	for index := 0; index < committeeSize; index++ {
		vote := votes[index]
		if vote == nil {
			continue
		}
		mask[index/8] |= 1 << uint(index&7)
		if aggregate == nil {
			copySign := *vote
			aggregate = &copySign
		} else {
			aggregate.Add(vote)
		}
	}
	if aggregate == nil {
		return nil, mask
	}
	return aggregate.Serialize(), mask
}

func newSevenReplicaSimulation(t *testing.T) ([]simulatedFHSReplica, []*bls.PublicKey) {
	t.Helper()
	secrets, public := makeTestCommittee(t, 7)
	replicas := make([]simulatedFHSReplica, 7)
	for index := range replicas {
		replicas[index] = simulatedFHSReplica{secret: &secrets[index], wal: new(simulatedSafetyWAL)}
	}
	return replicas, public
}

func TestFHSSevenNodesProgressWhenTwoByzantineWithhold(t *testing.T) {
	replicas, public := newSevenReplicaSimulation(t)
	view, viewID, leader := uint64(20), common.HexToHash("0x20"), "leader"
	proposal := []byte("honest-proposal")
	votes := make(map[int]*bls.Sign)
	for index := 0; index < 5; index++ { // replicas 5 and 6 withhold
		votes[index] = replicas[index].vote(view, viewID, leader, proposal)
	}
	signature, mask := aggregateSimulationVotes(votes, 7)
	if !VerifyFHSSignatureWithContext(signature, mask, proposal, public, 5, 10101919, MsgVotePrepare, viewID, leader) {
		t.Fatal("five honest replicas could not form a QC after two Byzantine replicas withheld")
	}
}

func TestFHSSevenNodesTwoByzantineCannotCertifyBothEquivocations(t *testing.T) {
	replicas, public := newSevenReplicaSimulation(t)
	view, viewID, leader := uint64(22), common.HexToHash("0x22"), "leader"
	proposalA, proposalB := []byte("equivocation-a"), []byte("equivocation-b")

	// The Byzantine replicas vote for both branches. Honest replicas vote only
	// once, split 3/2. Quorum intersection therefore lets at most one branch
	// reach five votes.
	votesA, votesB := make(map[int]*bls.Sign), make(map[int]*bls.Sign)
	for _, index := range []int{0, 1, 2} {
		votesA[index] = replicas[index].vote(view, viewID, leader, proposalA)
	}
	for _, index := range []int{3, 4} {
		votesB[index] = replicas[index].vote(view, viewID, leader, proposalB)
	}
	for _, index := range []int{5, 6} {
		digestA := hotstuffContextDigest(10101919, MsgVotePrepare, viewID, leader, proposalA)
		digestB := hotstuffContextDigest(10101919, MsgVotePrepare, viewID, leader, proposalB)
		digestA, _ = fhsSignerDigest(digestA, replicas[index].secret.GetPublicKey())
		digestB, _ = fhsSignerDigest(digestB, replicas[index].secret.GetPublicKey())
		votesA[index] = replicas[index].secret.SignHash(digestA)
		votesB[index] = replicas[index].secret.SignHash(digestB)
	}
	signatureA, maskA := aggregateSimulationVotes(votesA, 7)
	signatureB, maskB := aggregateSimulationVotes(votesB, 7)
	validA := VerifyFHSSignatureWithContext(signatureA, maskA, proposalA, public, 5, 10101919, MsgVotePrepare, viewID, leader)
	validB := VerifyFHSSignatureWithContext(signatureB, maskB, proposalB, public, 5, 10101919, MsgVotePrepare, viewID, leader)
	if !validA || validB {
		t.Fatalf("equivocation QC validity = (%v,%v), want (true,false)", validA, validB)
	}
}

func TestFHSSevenNodesRestartDoesNotEnableConflictingQC(t *testing.T) {
	replicas, public := newSevenReplicaSimulation(t)
	view, viewID, leader := uint64(21), common.HexToHash("0x21"), "leader"
	proposalA, proposalB := []byte("proposal-a"), []byte("proposal-b")

	votesA := make(map[int]*bls.Sign)
	for _, index := range []int{0, 1, 2, 5, 6} { // 3 honest + both Byzantine
		votesA[index] = replicas[index].vote(view, viewID, leader, proposalA)
	}
	signatureA, maskA := aggregateSimulationVotes(votesA, 7)
	if !VerifyFHSSignatureWithContext(signatureA, maskA, proposalA, public, 5, 10101919, MsgVotePrepare, viewID, leader) {
		t.Fatal("first 5-of-7 QC did not verify")
	}

	// Honest replicas 0..2 restart. Their private keys are reloaded, but the same
	// durable WAL remains. Byzantine replicas 5 and 6 may equivocate freely.
	for index := 0; index < 3; index++ {
		replicas[index] = simulatedFHSReplica{secret: replicas[index].secret, wal: replicas[index].wal}
	}
	votesB := make(map[int]*bls.Sign)
	for index := 0; index < 7; index++ {
		if index >= 5 {
			digest := hotstuffContextDigest(10101919, MsgVotePrepare, viewID, leader, proposalB)
			digest, _ = fhsSignerDigest(digest, replicas[index].secret.GetPublicKey())
			votesB[index] = replicas[index].secret.SignHash(digest)
			continue
		}
		votesB[index] = replicas[index].vote(view, viewID, leader, proposalB)
	}
	if votesB[0] != nil || votesB[1] != nil || votesB[2] != nil {
		t.Fatal("restarted honest replica signed a conflicting proposal in the same view")
	}
	signatureB, maskB := aggregateSimulationVotes(votesB, 7)
	if VerifyFHSSignatureWithContext(signatureB, maskB, proposalB, public, 5, 10101919, MsgVotePrepare, viewID, leader) {
		t.Fatal("two Byzantine replicas formed a conflicting QC after honest restarts")
	}
}
