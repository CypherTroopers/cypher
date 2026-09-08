package types

import (
	"bytes"
	"math/big"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/rlp"
)

func signedCommonV2(t *testing.T) *CommonTxAdmissionBatch {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	a := makeSignedCommonTxAdmissionBatch(t, 2)
	a.Version, a.Miner, a.RewardRecipient = CommonRPCVersionV2, crypto.PubkeyToAddress(key.PublicKey), common.HexToAddress("0xb123")
	a.AdmissionID = CommonTxAdmissionID(a)
	a.Signature, err = crypto.Sign(CommonTxAdmissionSigningHash(a).Bytes(), key)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestCommonRPCV2CommitsRecipientAndRejectsTampering(t *testing.T) {
	a := signedCommonV2(t)
	if err := VerifyCommonTxAdmissionSignature(a); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*CommonTxAdmissionBatch){
		"recipient":        func(b *CommonTxAdmissionBatch) { b.RewardRecipient[0] ^= 1 },
		"recipient-and-id": func(b *CommonTxAdmissionBatch) { b.RewardRecipient[0] ^= 1; b.AdmissionID = CommonTxAdmissionID(b) },
		"signer-and-id":    func(b *CommonTxAdmissionBatch) { b.Miner[0] ^= 1; b.AdmissionID = CommonTxAdmissionID(b) },
		"chain-and-id": func(b *CommonTxAdmissionBatch) {
			b.ChainID.Add(b.ChainID, big.NewInt(1))
			b.AdmissionID = CommonTxAdmissionID(b)
		},
		"genesis-and-id": func(b *CommonTxAdmissionBatch) { b.GenesisHash[0] ^= 1; b.AdmissionID = CommonTxAdmissionID(b) },
		"transaction-and-root-and-id": func(b *CommonTxAdmissionBatch) {
			b.TxHashes[0][0] ^= 1
			b.TxRoot = DeriveCommonTxAdmissionTxRoot(b.TxHashes)
			b.AdmissionID = CommonTxAdmissionID(b)
		},
		"downgrade": func(b *CommonTxAdmissionBatch) {
			b.Version = 0
			b.RewardRecipient = common.Address{}
			b.AdmissionID = CommonTxAdmissionID(b)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			b := cloneCommonTxAdmissionBatchForTest(a)
			mutate(b)
			if err := VerifyCommonTxAdmissionSignature(b); err == nil {
				t.Fatal("tampered proof accepted")
			}
		})
	}
	b := cloneCommonTxAdmissionBatchForTest(a)
	b.RewardRecipient[0] ^= 1
	if CommonTxAdmissionID(a) == CommonTxAdmissionID(b) || bytes.Equal(CommonTxAdmissionSigningPayload(a), CommonTxAdmissionSigningPayload(b)) {
		t.Fatal("recipient missing from signed commitment")
	}
	if DeriveCommonTxAdmissionRoot([]*CommonTxAdmissionBatch{a}, []CommonTxAdmissionRef{{}}) == DeriveCommonTxAdmissionRoot([]*CommonTxAdmissionBatch{b}, []CommonTxAdmissionRef{{}}) {
		t.Fatal("recipient missing from admission root")
	}
	r := &CommonTxReward{TxHash: a.TxHashes[0], Approver: a.Miner, ApproverReward: big.NewInt(3), Burn: big.NewInt(12), Version: 2, RewardRecipient: a.RewardRecipient}
	s := *r
	s.RewardRecipient[0] ^= 1
	if DeriveCommonTxRewardRoot([]*CommonTxReward{r}) == DeriveCommonTxRewardRoot([]*CommonTxReward{&s}) {
		t.Fatal("recipient missing from reward root")
	}
}

func TestCommonRPCV2RecipientCannotGrindWinnerOrTieBreak(t *testing.T) {
	a := signedCommonV2(t)
	other := signedCommonV2(t)
	want := IsBetterCommonTxAdmission(a, other, a.TxHashes[0])
	for index := 1; index < 1000; index++ {
		b := cloneCommonTxAdmissionBatchForTest(a)
		b.RewardRecipient = common.BigToAddress(big.NewInt(int64(index)))
		b.AdmissionID = CommonTxAdmissionID(b)
		if IsBetterCommonTxAdmission(b, other, a.TxHashes[0]) != want {
			t.Fatal("recipient changed inter-operator priority")
		}
		if IsBetterCommonTxAdmission(b, a, a.TxHashes[0]) || IsBetterCommonTxAdmission(a, b, a.TxHashes[0]) {
			t.Fatal("recipient changed same-operator tie-break")
		}
	}
}

func TestCommonRPCOnlyCanonicalRecipientBearingWireFormat(t *testing.T) {
	a := signedCommonV2(t)
	fields := []interface{}{a.Version, a.ChainID, a.GenesisHash, a.TxRoot, a.AdmissionID, a.Miner, a.RewardRecipient, a.KeyBlockNumber, a.Timestamp, a.TxHashes, a.Signature}
	want, err := rlp.EncodeToBytes(fields)
	if err != nil {
		t.Fatal(err)
	}
	got, err := rlp.EncodeToBytes(a)
	if err != nil || !bytes.Equal(want, got) {
		t.Fatalf("admission did not use canonical flat versioned list: %v", err)
	}
	var decoded CommonTxAdmissionBatch
	if err := rlp.DecodeBytes(want, &decoded); err != nil || !reflect.DeepEqual(a, &decoded) {
		t.Fatalf("canonical admission roundtrip: %v", err)
	}
	legacy := []interface{}{a.ChainID, a.GenesisHash, a.TxRoot, a.AdmissionID, a.Miner, a.KeyBlockNumber, a.Timestamp, a.TxHashes, a.Signature}
	for _, old := range []interface{}{legacy, []interface{}{uint8(2), legacy, a.RewardRecipient}} {
		raw, _ := rlp.EncodeToBytes(old)
		if err := rlp.DecodeBytes(raw, &decoded); err == nil {
			t.Fatal("obsolete admission wire format accepted")
		}
	}
	for _, version := range []uint8{0, 1, 3} {
		bad := *a
		bad.Version = version
		if _, err := rlp.EncodeToBytes(&bad); err == nil {
			t.Fatalf("unsupported admission version %d encoded", version)
		}
		fields[0] = version
		raw, _ := rlp.EncodeToBytes(fields)
		if err := rlp.DecodeBytes(raw, &decoded); err == nil {
			t.Fatalf("unsupported admission version %d decoded", version)
		}
	}
	r := &CommonTxReward{TxHash: a.TxHashes[0], Approver: a.Miner, Version: 2, RewardRecipient: a.RewardRecipient, ApproverReward: big.NewInt(3), Burn: big.NewInt(12)}
	rewardFields := []interface{}{r.Version, r.TxHash, r.Approver, r.RewardRecipient, r.ApproverReward, r.Burn}
	want, _ = rlp.EncodeToBytes(rewardFields)
	got, err = rlp.EncodeToBytes(r)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("reward did not use canonical flat versioned list: %v", err)
	}
	var reward CommonTxReward
	if err := rlp.DecodeBytes(want, &reward); err != nil || !reflect.DeepEqual(r, &reward) {
		t.Fatalf("canonical reward roundtrip: %v", err)
	}
	for _, version := range []uint8{0, 1, 3} {
		rewardFields[0] = version
		raw, _ := rlp.EncodeToBytes(rewardFields)
		if err := rlp.DecodeBytes(raw, &reward); err == nil {
			t.Fatalf("unsupported reward version %d decoded", version)
		}
	}
	fields[0], rewardFields[0] = CommonRPCVersionV2, CommonRPCVersionV2
	for _, invalid := range []common.Address{{}, a.Miner} {
		fields[6], rewardFields[3] = invalid, invalid
		raw, _ := rlp.EncodeToBytes(fields)
		if err := rlp.DecodeBytes(raw, &decoded); err == nil {
			t.Fatalf("invalid admission recipient %s decoded", invalid)
		}
		raw, _ = rlp.EncodeToBytes(rewardFields)
		if err := rlp.DecodeBytes(raw, &reward); err == nil {
			t.Fatalf("invalid reward recipient %s decoded", invalid)
		}
	}
	oldReward, _ := rlp.EncodeToBytes([]interface{}{r.TxHash, r.Approver, r.ApproverReward, r.Burn})
	if err := rlp.DecodeBytes(oldReward, &reward); err == nil {
		t.Fatal("legacy reward wire format accepted")
	}
	legacyReward := *r
	legacyReward.Version = 0
	legacyReward.RewardRecipient = common.Address{}
	if legacyReward.EffectiveRewardRecipient() != (common.Address{}) {
		t.Fatal("legacy reward silently fell back to signer payout")
	}
}

func TestCommonRPCV2BlockWireRoundTripAndUnknownVersion(t *testing.T) {
	a := signedCommonV2(t)
	r := &CommonTxReward{TxHash: a.TxHashes[0], Approver: a.Miner, ApproverReward: big.NewInt(3), Burn: big.NewInt(12), Version: 2, RewardRecipient: a.RewardRecipient}
	b := NewBlockWithHeader(&Header{Number: big.NewInt(1), Difficulty: big.NewInt(1)})
	b.AttachCommonTxData([]*CommonTxAdmissionBatch{a}, []CommonTxAdmissionRef{{}}, []*CommonTxReward{r})
	wire, err := rlp.EncodeToBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Block
	if err := rlp.DecodeBytes(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Hash() != b.Hash() || !reflect.DeepEqual(decoded.CommonTxAdmissionBatches(), b.CommonTxAdmissionBatches()) || !reflect.DeepEqual(decoded.CommonTxRewards(), b.CommonTxRewards()) {
		t.Fatal("V2 block roundtrip lost signed recipient")
	}
	a.Version = 9
	if _, err := rlp.EncodeToBytes(a); err == nil {
		t.Fatal("unsupported version encoded")
	}
	unknown, _ := rlp.EncodeToBytes([]interface{}{uint8(9), r.TxHash, r.Approver, r.RewardRecipient, r.ApproverReward, r.Burn})
	var reward CommonTxReward
	if err := rlp.DecodeBytes(unknown, &reward); err == nil {
		t.Fatal("unsupported reward version decoded")
	}
}
