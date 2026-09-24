package checkpoint

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/cypherium/cypher/dex/protocol"
)

func TestSettlementBundleIndependentGolden(t *testing.T) {
	raw, err := os.ReadFile("../testdata/settlement_bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct{ Encoded, Hash string }
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	encoded, err := hex.DecodeString(vector.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DecodeSettlementBundle(encoded)
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeSettlementBundle(b)
	if err != nil || !bytes.Equal(got, encoded) {
		t.Fatal("canonical golden", err)
	}
	h := protocol.Digest("common-dex/settlement-bundle/v1", got)
	if hex.EncodeToString(h[:]) != vector.Hash {
		t.Fatal("golden hash")
	}
	c, _ := protocol.DecodeCheckpoint(b.Checkpoint)
	f, _ := protocol.DecodeFinanceSummary(b.Finance)
	withdrawals, rewards := []protocol.Claim{}, []protocol.Claim{}
	for _, p := range b.Withdrawals {
		withdrawals = append(withdrawals, p.Claim)
	}
	for _, p := range b.Rewards {
		rewards = append(rewards, p.Claim)
	}
	built, err := BuildSettlementBundle(c, b.Proof, f, withdrawals, rewards)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := EncodeSettlementBundle(built)
	if err != nil || !bytes.Equal(encoded, rebuilt) {
		t.Fatal("independent paths", err)
	}
	if _, err = VerifySettlementBundle(nil, b); err == nil {
		t.Fatal("missing registered epoch")
	}
	fixture := newProofFixture(t)
	if _, err = VerifySettlementBundle(fixture.epoch, b); err == nil {
		t.Fatal("opaque golden proof is not valid finality")
	}
}

func settlementBundleFixture(t *testing.T) (*proofFixture, SettlementBundle) {
	f := newProofFixture(t)
	f.c.DataSchema = 4
	claim := protocol.Claim{Domain: f.c.Domain(), Sequence: 1, Kind: protocol.Withdrawal, ID: protocol.Hash{1}, Owner: [20]byte{2}, Recipient: [20]byte{3}, Amount: protocol.Amount{31: 7}}
	h, err := claim.Hash()
	if err != nil {
		t.Fatal(err)
	}
	f.c.WithdrawalRoot, _, err = protocol.BuildCountedTree([]protocol.Hash{h})
	if err != nil {
		t.Fatal(err)
	}
	f.c.WithdrawalTotal = claim.Amount
	finance := protocol.FinanceSummary{Version: 1, Domain: f.c.Domain(), Custody: [20]byte{4}, Sequence: 1, WithdrawalTotal: claim.Amount}
	f.c.FundingRef, err = finance.Hash()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := EncodeProof(f.proof(t, []uint64{1, 2}, []uint64{1, 2}))
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildSettlementBundle(f.c, proof, finance, []protocol.Claim{claim}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return f, b
}

func TestSettlementBundleAuthenticatesCompleteSetsAndOwnsCopies(t *testing.T) {
	f, b := settlementBundleFixture(t)
	v, err := VerifySettlementBundle(f.epoch, b)
	if err != nil {
		t.Fatal(err)
	}
	if v.Checkpoint() != f.c || v.Withdrawals()[0].Claim.Amount.Big().Uint64() != 7 {
		t.Fatal("verified getters")
	}
	b.Proof[0] ^= 1
	b.Checkpoint[0] ^= 1
	b.Withdrawals[0].Claim.Amount[31]++
	proof := v.Proof()
	proof[0] ^= 1
	paths := v.Withdrawals()
	paths[0].Claim.Recipient[0] ^= 1
	if v.Checkpoint() != f.c || v.Withdrawals()[0].Claim.Recipient[0] != 3 {
		t.Fatal("verified bundle aliases input/getter")
	}
	for _, name := range []string{"proof", "single-qc", "omitted", "amount", "owner", "recipient", "index", "count", "depth", "finance", "funding", "domain", "too-many"} {
		t.Run(name, func(t *testing.T) {
			f, b := settlementBundleFixture(t)
			switch name {
			case "proof":
				b.Proof[len(b.Proof)-1] ^= 1
			case "single-qc":
				b.Proof = []byte{0xc1, 1}
			case "omitted":
				b.Withdrawals = nil
			case "amount":
				b.Withdrawals[0].Claim.Amount[31]++
			case "owner":
				b.Withdrawals[0].Claim.Owner[0]++
			case "recipient":
				b.Withdrawals[0].Claim.Recipient[0]++
			case "index":
				b.Withdrawals[0].Index++
			case "count":
				b.Withdrawals[0].Count++
			case "depth":
				b.Withdrawals[0].Siblings = make([]protocol.Hash, 8)
			case "finance":
				b.Finance[len(b.Finance)-1] ^= 1
			case "funding":
				c, _ := protocol.DecodeCheckpoint(b.Checkpoint)
				c.FundingRef[0]++
				b.Checkpoint, _ = c.Encode()
			case "domain":
				b.Withdrawals[0].Claim.Domain.DEXID[0]++
			case "too-many":
				b.Withdrawals = make([]ClaimPath, 129)
			}
			if _, err := VerifySettlementBundle(f.epoch, b); err == nil {
				t.Fatal("invalid bundle accepted")
			}
		})
	}
}

func FuzzSettlementBundleDecoder(f *testing.F) {
	raw, err := os.ReadFile("../testdata/settlement_bundle.json")
	if err != nil {
		f.Fatal(err)
	}
	var v struct{ Encoded string }
	if err = json.Unmarshal(raw, &v); err != nil {
		f.Fatal(err)
	}
	b, _ := hex.DecodeString(v.Encoded)
	f.Add(b)
	f.Add([]byte{})
	f.Add(append(bytes.Clone(b), 0))
	f.Fuzz(func(t *testing.T, raw []byte) {
		b, err := DecodeSettlementBundle(raw)
		if err != nil {
			return
		}
		out, err := EncodeSettlementBundle(b)
		if err != nil || !bytes.Equal(raw, out) {
			t.Fatal("accepted noncanonical bundle", err)
		}
	})
}
