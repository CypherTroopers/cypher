package types

import (
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

const nativeTestPrivateKey = "0000000000000000000000000000000000000000000000000000000000000001"

func TestNativeAccessEncodedMinimumMatchesPlanningBound(t *testing.T) {
	encoded, err := rlp.EncodeToBytes(NativeAccess{
		Resource: NativeResource{Kind: NativeResourceAccount},
		Mode:     NativeAccessRead,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) < params.NativeMinimumEncodedAccessBytes {
		t.Fatalf("minimum NativeAccess encoding %d is below planning bound %d", len(encoded), params.NativeMinimumEncodedAccessBytes)
	}
}

func nativeTestKey(t *testing.T) (*Transaction, Signer) {
	t.Helper()
	key, err := crypto.HexToECDSA(nativeTestPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	payer := crypto.PubkeyToAddress(key.PublicKey)
	to := common.HexToAddress("0xffffffffffffffffffffffffffffffffffffffff")
	inner := &NativeTxV1{
		ChainID:               big.NewInt(12367),
		RecentBlockHash:       common.HexToHash("0x123456"),
		RecentBlockNumber:     100,
		ValidUntil:            150,
		Payer:                 payer,
		ReplaySequence:        42,
		To:                    to,
		Value:                 big.NewInt(7),
		Data:                  []byte{0xaa, 0xbb, 0xcc},
		MaxFeePerCompute:      big.NewInt(100),
		PriorityFeePerCompute: big.NewInt(3),
		ComputeLimit:          80_000,
		MemoryLimit:           2 << 20,
		LogLimit:              64 << 10,
		OutputLimit:           128 << 10,
		Accesses: []NativeAccess{
			{
				Resource: NativeResource{Kind: NativeResourceAccount, Address: payer},
				Mode:     NativeAccessWrite,
			},
			{
				Resource: NativeResource{Kind: NativeResourceAccount, Address: to},
				Mode:     NativeAccessWrite,
			},
			{
				Resource: NativeResource{Kind: NativeResourceStorage, Address: to, Slot: common.HexToHash("0x01")},
				Mode:     NativeAccessWrite,
			},
		},
		V: new(big.Int),
		R: new(big.Int),
		S: new(big.Int),
	}
	if err := ValidateNativeManifest(inner); err != nil {
		t.Fatalf("invalid native test fixture: %v", err)
	}
	return NewTx(inner), NewNativeSigner(inner.ChainID)
}

func TestNativeTxV1IsNotAcceptedByPublicDecoders(t *testing.T) {
	unsigned, signer := nativeTestKey(t)
	key, err := crypto.HexToECDSA(nativeTestPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignTx(unsigned, signer, key)
	if err != nil {
		t.Fatal(err)
	}
	// MarshalBinary remains only so boundary tests can construct a retired type-5
	// fixture. Untrusted binary and JSON decoders must reject it before the
	// transaction can enter any public, pool, propagation or consensus path.
	wire, err := signed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) == 0 || wire[0] != NativeTxType {
		t.Fatalf("native envelope prefix = %x", wire)
	}
	var binaryRoundTrip Transaction
	if err := binaryRoundTrip.UnmarshalBinary(wire); err == nil {
		t.Fatal("retired type-5 binary envelope was accepted")
	}

	jsonBlob, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var jsonRoundTrip Transaction
	if err := json.Unmarshal(jsonBlob, &jsonRoundTrip); err == nil {
		t.Fatal("retired type-5 JSON envelope was accepted")
	}
}

func TestNativeTxV1SigningHashBindsEveryUnsignedField(t *testing.T) {
	baseTx, signer := nativeTestKey(t)
	base := baseTx.data.(*NativeTxV1)
	want := signer.Hash(baseTx)
	tests := []struct {
		name   string
		mutate func(*NativeTxV1)
	}{
		{"chain id", func(tx *NativeTxV1) { tx.ChainID.Add(tx.ChainID, big.NewInt(1)) }},
		{"recent block hash", func(tx *NativeTxV1) { tx.RecentBlockHash[0] ^= 1 }},
		{"recent block number", func(tx *NativeTxV1) { tx.RecentBlockNumber++ }},
		{"valid until", func(tx *NativeTxV1) { tx.ValidUntil++ }},
		{"payer", func(tx *NativeTxV1) { tx.Payer[0] ^= 1 }},
		{"replay sequence", func(tx *NativeTxV1) { tx.ReplaySequence++ }},
		{"to", func(tx *NativeTxV1) { tx.To[0] ^= 1 }},
		{"value", func(tx *NativeTxV1) { tx.Value.Add(tx.Value, big.NewInt(1)) }},
		{"data", func(tx *NativeTxV1) { tx.Data[0] ^= 1 }},
		{"max fee", func(tx *NativeTxV1) { tx.MaxFeePerCompute.Add(tx.MaxFeePerCompute, big.NewInt(1)) }},
		{"priority fee", func(tx *NativeTxV1) { tx.PriorityFeePerCompute.Add(tx.PriorityFeePerCompute, big.NewInt(1)) }},
		{"compute limit", func(tx *NativeTxV1) { tx.ComputeLimit++ }},
		{"memory limit", func(tx *NativeTxV1) { tx.MemoryLimit++ }},
		{"log limit", func(tx *NativeTxV1) { tx.LogLimit++ }},
		{"output limit", func(tx *NativeTxV1) { tx.OutputLimit++ }},
		{"accesses", func(tx *NativeTxV1) { tx.Accesses[len(tx.Accesses)-1].Mode = NativeAccessRead }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := base.copy().(*NativeTxV1)
			test.mutate(mutated)
			if got := signer.Hash(NewTx(mutated)); got == want {
				t.Fatalf("signing hash did not bind %s", test.name)
			}
		})
	}

	withSignature := base.copy().(*NativeTxV1)
	withSignature.V.SetUint64(1)
	withSignature.R.SetUint64(2)
	withSignature.S.SetUint64(3)
	if got := signer.Hash(NewTx(withSignature)); got != want {
		t.Fatalf("signing hash included V/R/S: have %s want %s", got, want)
	}
}

func TestNativeTxV1ManifestValidation(t *testing.T) {
	baseTx, _ := nativeTestKey(t)
	base := baseTx.data.(*NativeTxV1)
	tests := []struct {
		name   string
		mutate func(*NativeTxV1)
		want   error
	}{
		{"unsorted", func(tx *NativeTxV1) { tx.Accesses[0], tx.Accesses[1] = tx.Accesses[1], tx.Accesses[0] }, ErrNonCanonicalNativeAccess},
		{"duplicate", func(tx *NativeTxV1) { tx.Accesses[1] = tx.Accesses[0] }, ErrNonCanonicalNativeAccess},
		{"invalid mode", func(tx *NativeTxV1) { tx.Accesses[0].Mode = 99 }, ErrInvalidNativeManifest},
		{"invalid kind", func(tx *NativeTxV1) { tx.Accesses[0].Resource.Kind = 99 }, ErrInvalidNativeManifest},
		{"account slot", func(tx *NativeTxV1) { tx.Accesses[0].Resource.Slot = common.HexToHash("0x01") }, ErrInvalidNativeManifest},
		{"payer read only", func(tx *NativeTxV1) { tx.Accesses[0].Mode = NativeAccessRead }, ErrInvalidNativeManifest},
		{"target missing", func(tx *NativeTxV1) { tx.To = common.HexToAddress("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee") }, ErrInvalidNativeManifest},
		{"value target read only", func(tx *NativeTxV1) { tx.Accesses[1].Mode = NativeAccessRead }, ErrInvalidNativeManifest},
		{"storage account missing", func(tx *NativeTxV1) {
			tx.Accesses[2].Resource.Address = common.HexToAddress("0xdddddddddddddddddddddddddddddddddddddddd")
		}, ErrInvalidNativeManifest},
		{"expired before reference", func(tx *NativeTxV1) { tx.ValidUntil = tx.RecentBlockNumber - 1 }, ErrInvalidNativeManifest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inner := base.copy().(*NativeTxV1)
			test.mutate(inner)
			if err := ValidateNativeManifest(inner); !errors.Is(err, test.want) {
				t.Fatalf("ValidateNativeManifest error = %v, want %v", err, test.want)
			}
			if _, err := NewTx(inner).MarshalBinary(); !errors.Is(err, test.want) {
				t.Fatalf("MarshalBinary error = %v, want %v", err, test.want)
			}
		})
	}

	readOnlyTarget := base.copy().(*NativeTxV1)
	readOnlyTarget.Value.SetUint64(0)
	readOnlyTarget.Accesses[1].Mode = NativeAccessRead
	if err := ValidateNativeManifest(readOnlyTarget); err != nil {
		t.Fatalf("zero-value read-only target rejected: %v", err)
	}

	malformed := base.copy().(*NativeTxV1)
	malformed.Accesses[0], malformed.Accesses[1] = malformed.Accesses[1], malformed.Accesses[0]
	payload, err := rlp.EncodeToBytes(malformed)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Transaction
	if err := decoded.UnmarshalBinary(append([]byte{NativeTxType}, payload...)); err == nil {
		t.Fatal("retired type-5 binary envelope was accepted")
	}
}

func TestNativeTxV1PayerMustMatchRecoveredSigner(t *testing.T) {
	tx, signer := nativeTestKey(t)
	otherKey, err := crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000002")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignTx(tx, signer, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sender(signer, signed); !errors.Is(err, ErrNativePayerMismatch) {
		t.Fatalf("Sender error = %v, want %v", err, ErrNativePayerMismatch)
	}
}

func TestNativeTxV1RejectsOversizedIntegerFields(t *testing.T) {
	baseTx, _ := nativeTestKey(t)
	inner := baseTx.data.(*NativeTxV1).copy().(*NativeTxV1)
	inner.MaxFeePerCompute.Lsh(big.NewInt(1), 256)
	if _, err := NewTx(inner).MarshalBinary(); err == nil {
		t.Fatal("oversized native fee was accepted on encode")
	}
	payload, err := rlp.EncodeToBytes(inner)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Transaction
	if err := decoded.UnmarshalBinary(append([]byte{NativeTxType}, payload...)); err == nil {
		t.Fatal("oversized native fee was accepted on decode")
	}
}

func TestNativeTxV1JSONRequiresExecutionTarget(t *testing.T) {
	tx, _ := nativeTestKey(t)
	blob, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]interface{}
	if err := json.Unmarshal(blob, &object); err != nil {
		t.Fatal(err)
	}
	delete(object, "to")
	blob, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Transaction
	if err := json.Unmarshal(blob, &decoded); err == nil {
		t.Fatal("native JSON without execution target was accepted")
	}
}

func TestNativeTxV1JSONRequiresExplicitReplaySequence(t *testing.T) {
	tx, _ := nativeTestKey(t)
	blob, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]interface{}
	if err := json.Unmarshal(blob, &object); err != nil {
		t.Fatal(err)
	}
	delete(object, "replaySequence")
	blob, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Transaction
	if err := json.Unmarshal(blob, &decoded); err == nil {
		t.Fatal("native JSON without replaySequence was accepted")
	}
}

func TestNativeTxV1JSONWithExplicitZeroReplaySequenceIsRejected(t *testing.T) {
	tx, _ := nativeTestKey(t)
	inner := tx.data.(*NativeTxV1).copy().(*NativeTxV1)
	inner.ReplaySequence = 0
	blob, err := json.Marshal(NewTx(inner))
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]interface{}
	if err := json.Unmarshal(blob, &object); err != nil {
		t.Fatal(err)
	}
	if value, exists := object["replaySequence"]; !exists || value != "0x0" {
		t.Fatalf("explicit zero replaySequence = %#v present=%t", value, exists)
	}
	var decoded Transaction
	if err := json.Unmarshal(blob, &decoded); err == nil {
		t.Fatal("retired type-5 JSON envelope was accepted")
	}
}

func TestNativeTxV1RejectsWirePayloadWithoutReplaySequence(t *testing.T) {
	tx, _ := nativeTestKey(t)
	wire, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var fields []rlp.RawValue
	if err := rlp.DecodeBytes(wire[1:], &fields); err != nil {
		t.Fatal(err)
	}
	const replaySequenceField = 5
	if len(fields) <= replaySequenceField {
		t.Fatalf("native wire field count = %d", len(fields))
	}
	fields = append(fields[:replaySequenceField], fields[replaySequenceField+1:]...)
	oldPayload, err := rlp.EncodeToBytes(fields)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Transaction
	if err := decoded.UnmarshalBinary(append([]byte{NativeTxType}, oldPayload...)); err == nil {
		t.Fatal("native wire payload without replay sequence was accepted")
	}
}
