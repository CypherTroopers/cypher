package hotstuff

import (
	"math/big"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
)

func testFHSContext() FHSViewContext {
	return FHSViewContext{
		Version:       fhsWireVersion,
		ChainID:       10101919,
		TargetView:    12,
		KeyNumber:     3,
		KeyHash:       common.HexToHash("0x1001"),
		CommitteeHash: common.HexToHash("0x2002"),
		LeaderID:      "127.0.0.1:7100",
		EntryKind:     FHSViewFromQC,
	}
}

func aggregateNewViewReports(t *testing.T, secrets []bls.SecretKey, signerIndexes []int, context FHSViewContext) *AggregateQC {
	t.Helper()
	aggregate := &AggregateQC{Context: context, Mask: make([]byte, canonicalMaskLength(len(secrets)))}
	var signature *bls.Sign
	for _, index := range signerIndexes {
		report := NewViewReport{Context: context, SignerIndex: uint32(index)}
		digest, err := NewViewReportDigest(&report)
		if err != nil {
			t.Fatal(err)
		}
		partial := secrets[index].SignHash(digest)
		if signature == nil {
			signature = partial
		} else {
			signature.Add(partial)
		}
		aggregate.Reports = append(aggregate.Reports, report)
		aggregate.Mask[index/8] |= 1 << uint(index&7)
	}
	aggregate.Sign = signature.Serialize()
	return aggregate
}

func aggregateReportsWithHighQC(t *testing.T, secrets []bls.SecretKey, context FHSViewContext, highQCs []*SignedState) *AggregateQC {
	t.Helper()
	aggregate := &AggregateQC{Context: context, Mask: make([]byte, canonicalMaskLength(len(secrets)))}
	var signature *bls.Sign
	for index, highQC := range highQCs {
		report := NewViewReport{Context: context, SignerIndex: uint32(index), HighQC: CloneSignedState(highQC)}
		digest, err := NewViewReportDigest(&report)
		if err != nil {
			t.Fatal(err)
		}
		partial := secrets[index].SignHash(digest)
		if signature == nil {
			signature = partial
		} else {
			signature.Add(partial)
		}
		aggregate.Reports = append(aggregate.Reports, report)
		aggregate.Mask[index/8] |= 1 << uint(index&7)
	}
	aggregate.Sign = signature.Serialize()
	return aggregate
}

func signFHSAugmented(t *testing.T, secret *bls.SecretKey, public *bls.PublicKey, baseDigest []byte) *bls.Sign {
	t.Helper()
	digest, err := fhsSignerDigest(baseDigest, public)
	if err != nil {
		t.Fatal(err)
	}
	signature := secret.SignHash(digest)
	if signature == nil {
		t.Fatal("failed to sign augmented FHS digest")
	}
	return signature
}

func TestFHSQCUsesPublicKeyAugmentedAggregate(t *testing.T) {
	secrets, publicKeys := makeTestCommittee(t, 7)
	state := []byte("augmented-qc")
	viewID := common.HexToHash("0xabc")
	leaderID := "leader"
	baseDigest := hotstuffContextDigest(10101919, MsgVotePrepare, viewID, leaderID, state)
	mask := []byte{0x1f}
	var augmented, legacy *bls.Sign
	for index := 0; index < 5; index++ {
		augmentedVote := signFHSAugmented(t, &secrets[index], publicKeys[index], baseDigest)
		legacyVote := secrets[index].SignHash(baseDigest)
		if augmented == nil {
			augmented, legacy = augmentedVote, legacyVote
		} else {
			augmented.Add(augmentedVote)
			legacy.Add(legacyVote)
		}
	}
	if !VerifyFHSSignatureWithContext(augmented.Serialize(), mask, state, publicKeys, 5, 10101919, MsgVotePrepare, viewID, leaderID) {
		t.Fatal("valid public-key-augmented FHS QC was rejected")
	}
	if VerifyFHSSignatureWithContext(legacy.Serialize(), mask, state, publicKeys, 5, 10101919, MsgVotePrepare, viewID, leaderID) {
		t.Fatal("legacy same-message aggregate was accepted as an FHS v3 QC")
	}
	first, _ := fhsSignerDigest(baseDigest, publicKeys[0])
	second, _ := fhsSignerDigest(baseDigest, publicKeys[1])
	if string(first) == string(second) {
		t.Fatal("different committee keys produced the same augmented digest")
	}
}

func TestVerifyAggregateQCDistinctReports(t *testing.T) {
	secrets, publicKeys := makeTestCommittee(t, 7)
	aggregate := aggregateNewViewReports(t, secrets, []int{0, 1, 2, 3, 4}, testFHSContext())
	if _, err := VerifyAggregateQC(aggregate, publicKeys, 5, func(*SignedState) error { return nil }); err != nil {
		t.Fatalf("valid aggregate latest-QC proof rejected: %v", err)
	}

	tampered := *aggregate
	tampered.Reports = append([]NewViewReport(nil), aggregate.Reports...)
	tampered.Reports[2].Extra = []byte("tampered")
	if _, err := VerifyAggregateQC(&tampered, publicKeys, 5, func(*SignedState) error { return nil }); err == nil {
		t.Fatal("aggregate signature accepted a tampered report")
	}
}

func TestNewViewReportRoundTripAllowsNilGenesisQC(t *testing.T) {
	report := &NewViewReport{Context: testFHSContext(), SignerIndex: 2}
	encoded, err := EncodeNewViewReport(report)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeNewViewReport(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.HighQC != nil || decoded.SignerIndex != report.SignerIndex || decoded.Context != report.Context {
		t.Fatalf("decoded genesis NewView report = %#v", decoded)
	}
}

func TestVerifyAggregateQCRejectsMaskReportMismatch(t *testing.T) {
	secrets, publicKeys := makeTestCommittee(t, 7)
	aggregate := aggregateNewViewReports(t, secrets, []int{0, 1, 2, 3, 4}, testFHSContext())
	aggregate.Mask = []byte{0x3f}
	if _, err := VerifyAggregateQC(aggregate, publicKeys, 5, func(*SignedState) error { return nil }); err == nil {
		t.Fatal("aggregate accepted a signer bit with no report")
	}
}

func TestAggregateQCSelectsLatestValidQCForLaggingReplica(t *testing.T) {
	secrets, publicKeys := makeTestCommittee(t, 7)
	qc8 := &SignedState{State: []byte("proposal-v8"), Sign: []byte{1}, Mask: []byte{0x1f}, ViewID: common.HexToHash("0x08"), LeaderID: "leader-8", Number: 8}
	qc10 := &SignedState{State: []byte("proposal-v10"), Sign: []byte{2}, Mask: []byte{0x1f}, ViewID: common.HexToHash("0x10"), LeaderID: "leader-10", Number: 10}
	aggregate := aggregateReportsWithHighQC(t, secrets, testFHSContext(), []*SignedState{qc10, qc8, nil, qc10, qc8})
	highest, err := VerifyAggregateQC(aggregate, publicKeys, 5, func(qc *SignedState) error {
		if qc.Number != 8 && qc.Number != 10 {
			return ErrInvalidHighQC
		}
		return nil
	})
	if err != nil {
		t.Fatalf("mixed latest-QC reports rejected: %v", err)
	}
	if !SignedStateSemanticEqual(highest, qc10) {
		t.Fatalf("selected highest QC = %#v, want view 10", highest)
	}

	forged := &SignedState{State: []byte("forged-v100"), Sign: []byte{3}, Mask: []byte{0x1f}, ViewID: common.HexToHash("0x100"), LeaderID: "attacker", Number: 100}
	aggregate = aggregateReportsWithHighQC(t, secrets, testFHSContext(), []*SignedState{forged, qc10, qc8, nil, qc10})
	if _, err := VerifyAggregateQC(aggregate, publicKeys, 5, func(qc *SignedState) error {
		if qc.Number == 100 {
			return ErrInvalidHighQC
		}
		return nil
	}); err == nil {
		t.Fatal("forged higher QC was selected from NewView reports")
	}
}

func TestSignedStateSemanticEqualityIgnoresSignerSubset(t *testing.T) {
	base := &SignedState{
		State:    []byte("same certified proposal"),
		Sign:     []byte{1, 2, 3},
		Mask:     []byte{0x1f},
		ViewID:   common.HexToHash("0x1234"),
		LeaderID: "leader",
		Number:   9,
	}
	other := CloneSignedState(base)
	other.Sign = []byte{9, 8, 7}
	other.Mask = []byte{0x3e}
	if !SignedStateSemanticEqual(base, other) {
		t.Fatal("valid signer-subset variants must identify the same certified statement")
	}
	other.State = []byte("conflicting proposal")
	if SignedStateSemanticEqual(base, other) {
		t.Fatal("different certified statements must not compare equal")
	}
}

func TestValidateCanonicalSignerMask(t *testing.T) {
	if err := ValidateCanonicalSignerMask([]byte{0x1f}, 7, 5); err != nil {
		t.Fatalf("canonical 5-of-7 mask rejected: %v", err)
	}
	for _, mask := range [][]byte{{0x1f, 0}, {0x9f}, {0x0f}} {
		if err := ValidateCanonicalSignerMask(mask, 7, 5); err == nil {
			t.Fatalf("non-canonical or under-quorum mask accepted: %x", mask)
		}
	}
}

func TestValidateBFTCommitteeSizeThreeFPlusOne(t *testing.T) {
	for _, size := range []int{1, 4, 7, 10, 100} {
		if err := ValidateBFTCommitteeSize(size); err != nil {
			t.Fatalf("valid committee size %d rejected: %v", size, err)
		}
	}
	for _, size := range []int{0, 2, 3, 5, 6, 8, 9, 103} {
		if err := ValidateBFTCommitteeSize(size); err == nil {
			t.Fatalf("invalid committee size %d accepted", size)
		}
	}
}

func TestFHSNewViewReportSizeIsBoundedBeforeQuorum(t *testing.T) {
	report := &NewViewReport{Extra: make([]byte, maxFHSNewViewExtraBytes)}
	encoded := make([]byte, maxFHSNewViewReportBytes)
	if err := validateFHSNewViewReportSize(encoded, report); err != nil {
		t.Fatalf("boundary-size NewView report rejected: %v", err)
	}
	report.Extra = append(report.Extra, 0)
	if err := validateFHSNewViewReportSize(encoded, report); err == nil {
		t.Fatal("oversized signed NewView Extra was accepted")
	}
	report.Extra = nil
	if err := validateFHSNewViewReportSize(append(encoded, 0), report); err == nil {
		t.Fatal("oversized encoded NewView report was accepted")
	}
}

func TestTimeoutCertificateNeedsFiveOfSeven(t *testing.T) {
	secrets, publicKeys := makeTestCommittee(t, 7)
	statement := &TimeoutStatement{
		Version:       fhsWireVersion,
		ChainID:       10101919,
		TimedOutView:  42,
		KeyNumber:     3,
		KeyHash:       common.HexToHash("0x300"),
		CommitteeHash: common.HexToHash("0x700"),
	}
	digest, err := TimeoutStatementDigest(statement)
	if err != nil {
		t.Fatal(err)
	}
	votes := make(map[int]*bls.Sign)
	for index := 0; index < 4; index++ {
		votes[index] = signFHSAugmented(t, &secrets[index], publicKeys[index], digest)
	}
	tc, err := buildTimeoutCertificate(statement, votes, 7)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTimeoutCertificate(tc, publicKeys, 5); err == nil {
		t.Fatal("four timeout votes advanced a seven-node committee")
	}
	votes[4] = signFHSAugmented(t, &secrets[4], publicKeys[4], digest)
	tc, err = buildTimeoutCertificate(statement, votes, 7)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTimeoutCertificate(tc, publicKeys, 5); err != nil {
		t.Fatalf("five timeout votes rejected: %v", err)
	}
}

func TestTimeoutCertificateRejectsMixedViewVotes(t *testing.T) {
	secrets, publicKeys := makeTestCommittee(t, 7)
	statement := &TimeoutStatement{
		Version:       fhsWireVersion,
		ChainID:       10101919,
		TimedOutView:  42,
		KeyNumber:     3,
		KeyHash:       common.HexToHash("0x300"),
		CommitteeHash: common.HexToHash("0x700"),
	}
	digest, _ := TimeoutStatementDigest(statement)
	other := *statement
	other.TimedOutView++
	otherDigest, _ := TimeoutStatementDigest(&other)
	votes := make(map[int]*bls.Sign)
	for index := 0; index < 5; index++ {
		voteDigest := digest
		if index == 4 {
			voteDigest = otherDigest
		}
		votes[index] = signFHSAugmented(t, &secrets[index], publicKeys[index], voteDigest)
	}
	tc, err := buildTimeoutCertificate(statement, votes, 7)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTimeoutCertificate(tc, publicKeys, 5); err == nil {
		t.Fatal("mixed-view timeout certificate verified")
	}
}

func TestTimeoutStateIsBoundedAndExpires(t *testing.T) {
	manager := NewHotstuffProtocolManager(&recoveryTestApp{}, nil, nil)
	now := time.Now()
	for view := uint64(1); view <= maxTimeoutStates+8; view++ {
		id := common.BigToHash(new(big.Int).SetUint64(view))
		manager.timeoutVotes[id] = map[int]*bls.Sign{}
		manager.timeoutEchoed[id] = true
		manager.timeoutSeen[id] = now.Add(time.Duration(view) * time.Millisecond)
		manager.timeoutView[id] = view
		manager.pruneTimeoutState(1)
	}
	if len(manager.timeoutSeen) > maxTimeoutStates {
		t.Fatalf("timeout state grew to %d entries, limit %d", len(manager.timeoutSeen), maxTimeoutStates)
	}
	for id := range manager.timeoutSeen {
		manager.timeoutSeen[id] = now.Add(-pendingMessageTTL - time.Second)
	}
	manager.pruneTimeoutState(maxTimeoutStates + 8)
	if len(manager.timeoutSeen) != 0 || len(manager.timeoutVotes) != 0 || len(manager.timeoutEchoed) != 0 {
		t.Fatal("expired timeout state was not removed")
	}
}
