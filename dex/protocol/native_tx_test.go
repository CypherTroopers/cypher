package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

func TestIndependentNativeFundingPayloadGolden(t *testing.T) {
	raw, err := os.ReadFile("../testdata/native_tx.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Funding []struct {
			Name, Sender, Owner, Amount, Call, Encoded string
			Asset                                      uint32
			Bucket                                     uint8
			PayloadHash                                string `json:"payload_hash"`
			SourceID                                   string `json:"source_id"`
		} `json:"funding_payloads"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil || len(vectors.Funding) != 6 {
		t.Fatal("funding golden vectors", err)
	}
	for _, v := range vectors.Funding {
		t.Run(v.Name, func(t *testing.T) {
			var sender, owner, custody [20]byte
			b, _ := hex.DecodeString(v.Sender)
			copy(sender[:], b)
			b, _ = hex.DecodeString(v.Owner)
			copy(owner[:], b)
			b, _ = hex.DecodeString("0000000000000000000000000000000000de0001")
			copy(custody[:], b)
			n, ok := new(big.Int).SetString(v.Amount, 10)
			if !ok {
				t.Fatal("amount")
			}
			amount, err := AmountFromBig(n)
			if err != nil {
				t.Fatal(err)
			}
			call, _ := hex.DecodeString(v.Call)
			hash, err := NativeFundingPayloadHash(sender, owner, amount, v.Asset, v.Bucket, call)
			if err != nil || hex.EncodeToString(hash[:]) != v.PayloadHash {
				t.Fatal("funding payload golden", err)
			}
			encoded, _ := hex.DecodeString(v.Encoded)
			if len(encoded) != 91 || Digest("common-dex/native-funding-payload/v2", encoded) != hash {
				t.Fatal("fixed funding payload encoding")
			}
			entry := InboxEntry{Version: 2, ChainID: 10101919, Custody: custody, Sender: sender, Owner: owner, Nonce: 7, PayloadHash: hash, Amount: amount, Bucket: v.Bucket}
			for i := range entry.Genesis {
				entry.Genesis[i], entry.DEXID[i] = 1, 2
			}
			source, err := entry.SourceID()
			if err != nil || hex.EncodeToString(source[:]) != v.SourceID {
				t.Fatal("funding source identity golden", err)
			}
			if _, err := NativeFundingPayloadHash(sender, owner, amount, 1, v.Bucket, call); err == nil {
				t.Fatal("non-native asset admitted")
			}
			if _, err := NativeFundingPayloadHash(sender, owner, amount, 0, v.Bucket%3+1, call); err == nil {
				t.Fatal("mismatched bucket admitted")
			}
			if _, err := NativeFundingPayloadHash(sender, owner, Amount{}, 0, v.Bucket, call); err == nil {
				t.Fatal("zero amount admitted")
			}
			if _, err := NativeFundingPayloadHash(sender, owner, amount, 0, v.Bucket, append(call, 0)); err == nil {
				t.Fatal("noncanonical call admitted")
			}
		})
	}
}

func TestIndependentNativeCallGolden(t *testing.T) {
	raw, err := os.ReadFile("../testdata/native_tx.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Calls []struct {
			Opcode      uint8
			Encoded     string
			PayloadHash string `json:"payload_hash"`
		}
		Genesis struct{ Seed, Domain, Custody, Root string }
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Calls) != 5 {
		t.Fatal("missing calls")
	}
	for _, v := range vectors.Calls {
		b, _ := hex.DecodeString(v.Encoded)
		call, err := DecodeNativeCall(b)
		if err != nil || call.Operation != v.Opcode {
			t.Fatal("native call", err)
		}
		out, err := call.Encode()
		if err != nil || !bytes.Equal(b, out) {
			t.Fatal("roundtrip", err)
		}
		if call.Operation == NativeCheckpoint {
			c, f, dex, clx, err := DecodeNativeCheckpoint(call.Body)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := EncodeNativeCheckpoint(c, f, dex, clx)
			if err != nil || !bytes.Equal(encoded, b) {
				t.Fatal("checkpoint envelope golden", err)
			}
		}
		if call.Operation == NativeClaim {
			c, index, count, path, err := DecodeNativeClaim(call.Body)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := EncodeNativeClaim(c, index, count, path)
			if err != nil || !bytes.Equal(encoded, b) {
				t.Fatal("claim envelope golden", err)
			}
		}
		hash := NativePayloadHash(b)
		if hex.EncodeToString(hash[:]) != v.PayloadHash {
			t.Fatal("payload hash")
		}
		if _, err = DecodeNativeCall(append(b, 0)); err == nil {
			t.Fatal("trailing data accepted")
		}
		b[7] = 1
		if _, err = DecodeNativeCall(b); err == nil {
			t.Fatal("reserved byte")
		}
	}
	var seed Hash
	var domain Domain
	var custody [20]byte
	b, _ := hex.DecodeString(vectors.Genesis.Seed)
	copy(seed[:], b)
	b, _ = hex.DecodeString(vectors.Genesis.Domain)
	if err = binary.Read(bytes.NewReader(b), binary.BigEndian, &domain); err != nil {
		t.Fatal(err)
	}
	b, _ = hex.DecodeString(vectors.Genesis.Custody)
	copy(custody[:], b)
	root, err := NativeGenesisRoot(seed, domain, custody)
	if err != nil || hex.EncodeToString(root[:]) != vectors.Genesis.Root {
		t.Fatal("genesis golden", err)
	}
	domain.Genesis[0]++
	other, err := NativeGenesisRoot(seed, domain, custody)
	if err != nil || other == root {
		t.Fatal("actual genesis not bound")
	}
	if _, err = (NativeCall{Operation: NativeClaim, Body: make([]byte, MaxNativeCallBytes)}).Encode(); err == nil {
		t.Fatal("unbounded native call")
	}
}

func TestNativeClaimCodecBounds(t *testing.T) {
	raw, err := os.ReadFile("../testdata/claims.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct{ Leaves []struct{ Encoded string } }
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	b, _ := hex.DecodeString(vectors.Leaves[0].Encoded)
	claim, err := DecodeClaim(b)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeNativeClaim(claim, 0, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	call, err := DecodeNativeCall(encoded)
	if err != nil {
		t.Fatal(err)
	}
	got, index, count, path, err := DecodeNativeClaim(call.Body)
	if err != nil || got != claim || index != 0 || count != 1 || len(path) != 0 {
		t.Fatal("claim roundtrip", err)
	}
	call.Body[ClaimSize+8] = 1
	if _, _, _, _, err = DecodeNativeClaim(call.Body); err == nil {
		t.Fatal("truncated sibling")
	}
}
