// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
)

func TestDeriveEntityReplayDomainIDGoldenAndIsolation(t *testing.T) {
	entity := EntityRef{Kind: EntityIdentity, PrincipalKind: 2, ID: "agent-01"}
	got, err := DeriveEntityReplayDomainID("iam.production.eu", entity)
	if err != nil {
		t.Fatal(err)
	}
	const want = "cph-iam-replay-v1:sha256:576ade561a6b8e78ece06305c9598100c8478cbeafbf5fd584219103a237fb31"
	if got != want {
		t.Fatalf("replay domain = %q", got)
	}
	mutations := []EntityRef{
		{Kind: EntityIdentity, PrincipalKind: 2, ID: "agent-02"},
		{Kind: EntityIdentity, PrincipalKind: 3, ID: "agent-01"},
		{Kind: EntityKeyLifecycle, PrincipalKind: 2, ID: "agent-01"},
	}
	for _, mutated := range mutations {
		value, deriveErr := DeriveEntityReplayDomainID("iam.production.eu", mutated)
		if deriveErr != nil {
			t.Fatal(deriveErr)
		}
		if value == got {
			t.Fatalf("mutation shares replay domain: %+v", mutated)
		}
	}
	otherBase, err := DeriveEntityReplayDomainID("iam.production.us", entity)
	if err != nil || otherBase == got {
		t.Fatalf("deployment isolation = %q, err=%v", otherBase, err)
	}
}

func TestEntityReplayDomainsAllowIndependentEqualGenerations(t *testing.T) {
	store := ccse.NewMemoryReplayStore()
	base := "iam.production.eu"
	makeEntry := func(id string, message byte) ccse.ReplayEntry {
		domain, err := DeriveEntityReplayDomainID(base,
			EntityRef{Kind: EntityIdentity, PrincipalKind: 2, ID: id})
		if err != nil {
			t.Fatal(err)
		}
		messageID := [16]byte{message}
		return ccse.ReplayEntry{MessageTypeID: 1, SchemaVersion: ccse.Version{Major: 1},
			CounterKind: ccse.CounterExpectedGeneration, ReplayDomainID: domain,
			SenderIdentity: "spiffe://cph.example/admin/01", Environment: "production",
			ChainID: digest(0x91), GenesisHash: digest(0x92), MessageID: messageID,
			Sequence: 1, Digest: digest(message + 10), ExpiresAt: testNow + 100}
	}
	handler := func(context.Context, ccse.VerifiedRecord) ([32]byte, error) {
		return sha256.Sum256([]byte("applied")), nil
	}
	for _, entry := range []ccse.ReplayEntry{makeEntry("agent-01", 1), makeEntry("agent-02", 2)} {
		if _, err := store.Execute(context.Background(), entry, ccse.VerifiedRecord{}, handler); err != nil {
			t.Fatalf("independent generation rejected: %v", err)
		}
	}
}

func TestKeyReplayDomainsAllowIndependentEqualGenerationsAndFenceTransferFork(t *testing.T) {
	store := ccse.NewMemoryReplayStore()
	base := "iam.production.eu"
	makeEntry := func(ref EntityRef, message byte) ccse.ReplayEntry {
		domain, err := DeriveEntityReplayDomainID(base, ref)
		if err != nil {
			t.Fatal(err)
		}
		return ccse.ReplayEntry{MessageTypeID: 1, SchemaVersion: ccse.Version{Major: 1},
			CounterKind: ccse.CounterExpectedGeneration, ReplayDomainID: domain,
			SenderIdentity: "spiffe://cph.example/admin/01", Environment: "production",
			ChainID: digest(0x91), GenesisHash: digest(0x92), MessageID: [16]byte{message},
			Sequence: 1, Digest: digest(message + 30), ExpiresAt: testNow + 100}
	}
	handler := func(context.Context, ccse.VerifiedRecord) ([32]byte, error) {
		return sha256.Sum256([]byte("applied")), nil
	}
	for _, entry := range []ccse.ReplayEntry{
		makeEntry(EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: 2, ID: "key-a"}, 11),
		makeEntry(EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: 2, ID: "key-b"}, 12),
	} {
		if _, err := store.Execute(context.Background(), entry, ccse.VerifiedRecord{}, handler); err != nil {
			t.Fatalf("independent key generation rejected: %v", err)
		}
	}

	transferStore := ccse.NewMemoryReplayStore()
	previous := EntityRef{Kind: EntityIdentity, PrincipalKind: 2, ID: "agent-old"}
	first, second := makeEntry(previous, 21), makeEntry(previous, 22)
	if _, err := transferStore.Execute(context.Background(), first, ccse.VerifiedRecord{}, handler); err != nil {
		t.Fatal(err)
	}
	if _, err := transferStore.Execute(context.Background(), second, ccse.VerifiedRecord{}, handler); !errors.Is(err, ccse.ErrReplaySequence) {
		t.Fatalf("competing transfer at same previous generation accepted: %v", err)
	}
}

func TestDeriveEntityReplayDomainIDRejectsInvalidTarget(t *testing.T) {
	for _, test := range []struct {
		base string
		ref  EntityRef
	}{
		{"", EntityRef{Kind: EntityIdentity, PrincipalKind: 2, ID: "agent-01"}},
		{"iam", EntityRef{}},
		{"iam", EntityRef{Kind: EntityIdentity, PrincipalKind: 0, ID: "agent-01"}},
		{"iam", EntityRef{Kind: EntityIdentity, PrincipalKind: 2}},
	} {
		if _, err := DeriveEntityReplayDomainID(test.base, test.ref); err == nil {
			t.Fatalf("accepted invalid replay target: %+v", test)
		}
	}
}
