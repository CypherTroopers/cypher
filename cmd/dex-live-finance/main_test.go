package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
	"testing"
)

func TestOfflineInputAndAmountBounds(t *testing.T) {
	for _, value := range []string{"-1", "01", "+1", "340282366920938463463374607431768211456"} {
		if _, err := amount(value); err == nil {
			t.Fatalf("accepted noncanonical/outsize %s", value)
		}
	}
	for _, value := range []string{"0", "1", "340282366920938463463374607431768211455"} {
		if _, err := amount(value); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range [][]byte{[]byte(`{"Unknown":1}`), []byte(`{"Op":"identity"} {}`), bytes.Repeat([]byte("x"), maxRequest+1)} {
		if parse(value, new(request)) == nil {
			t.Fatal("accepted malformed/unbounded helper request")
		}
	}
}

func TestNativeFundingCodecProjectionAndMutationRefusal(t *testing.T) {
	for _, operation := range []uint8{protocol.NativeDeposit, protocol.NativeSupport, protocol.NativeInsurance} {
		raw, err := (protocol.NativeCall{Operation: operation}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeNative("0x" + hex.EncodeToString(raw))
		if err != nil || decoded.(map[string]interface{})["operation"] != operation {
			t.Fatal("native funding roundtrip", err)
		}
		raw[7] = 1
		if _, err := decodeNative("0x" + hex.EncodeToString(raw)); err == nil {
			t.Fatal("noncanonical calldata accepted")
		}
	}
	keys, err := project(request{Op: "projection-keys"})
	if err != nil {
		t.Fatal(err)
	}
	slots := map[common.Hash]common.Hash{}
	for _, key := range keys.(map[string]interface{})["slots"].([]string) {
		slots[common.HexToHash(key)] = common.Hash{}
	}
	if len(slots) == 0 || len(slots) > 128 {
		t.Fatal("projection key bounds")
	}
	if _, err = project(request{Op: "projection", Slots: slots, Balance: "0"}); err != nil {
		t.Fatal(err)
	}
	for k := range slots {
		delete(slots, k)
		break
	}
	if _, err = project(request{Op: "projection", Slots: slots, Balance: "0"}); err == nil {
		t.Fatal("partial native projection accepted")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("read-only projection mutated")
		}
	}()
	new(projection).SetState(common.Address{}, common.Hash{}, common.Hash{})
}

func TestCandidateGenesisBindingRetainsApprovedChainID(t *testing.T) {
	raw := []byte(`{"config":{"chainId":10101919,"dexDevnet":{"version":4}}}`)
	inv := inventory{ChainID: 10101919, ConfigurationVersion: 4, GenesisSHA256: fmt.Sprintf("%x", sha256.Sum256(raw))}
	if err := validateGenesis(raw, inv); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*inventory){func(i *inventory) { i.ChainID++ }, func(i *inventory) { i.GenesisSHA256 = "" }} {
		changed := inv
		mutate(&changed)
		if validateGenesis(raw, changed) == nil {
			t.Fatal("foreign inventory accepted")
		}
	}
	for _, malformed := range []string{`{"config":{"chainId":10101919}}`, `{"config":{"chainId":10101919,"dexDevnet":{"version":3}}}`, `{"config":{"chainId":0,"dexDevnet":{"version":4}}}`} {
		changed := inv
		changed.GenesisSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(malformed)))
		if validateGenesis([]byte(malformed), changed) == nil {
			t.Fatal("DEX-disabled, retired or zero-chain genesis accepted")
		}
	}
	if validateGenesis(append(raw, ' '), inv) == nil {
		t.Fatal("unapproved genesis bytes accepted")
	}
}

func TestAncestryGenesisRequiresMatchingInventoryVersion(t *testing.T) {
	raw := []byte(`{"config":{"chainId":10101919,"dexDevnet":{"version":5}}}`)
	i := inventory{ChainID: 10101919, ConfigurationVersion: 5, GenesisSHA256: fmt.Sprintf("%x", sha256.Sum256(raw))}
	if err := validateGenesis(raw, i); err != nil {
		t.Fatal(err)
	}
	i.ConfigurationVersion = 4
	if validateGenesis(raw, i) == nil {
		t.Fatal("old inventory reinterpreted as ancestry deployment")
	}
}

func TestCommittedCloseCertificateOrderIsHeightThenParticipant(t *testing.T) {
	c := []rewards.Certificate{{Duty: rewards.Duty{Height: 12, Participant: 0}}, {Duty: rewards.Duty{Height: 11, Participant: 2}}, {Duty: rewards.Duty{Height: 11, Participant: 1}}}
	sortCloseCertificates(c)
	if c[0].Duty.Height != 11 || c[0].Duty.Participant != 1 || c[1].Duty.Participant != 2 || c[2].Duty.Height != 12 {
		t.Fatal("close package used hash-storage order")
	}
}
