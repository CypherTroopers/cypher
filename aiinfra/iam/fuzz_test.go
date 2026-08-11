// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"crypto/ed25519"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
)

func FuzzKeyIDFailClosedAndContentAddressed(f *testing.F) {
	valid, _ := testKey(0x21)
	f.Add(uint32(ccse.SignatureAlgorithmEd25519), []byte(valid))
	f.Add(uint32(ccse.SignatureAlgorithmP256SHA256), []byte(valid))
	f.Add(uint32(ccse.SignatureAlgorithmEd25519), []byte(valid[:31]))
	f.Fuzz(func(t *testing.T, rawAlgorithm uint32, key []byte) {
		algorithm := ccse.SignatureAlgorithmID(rawAlgorithm)
		canonical, canonicalErr := CanonicalPublicKey(algorithm, key)
		keyID, deriveErr := DeriveKeyID(algorithm, key)
		validInput := algorithm == ccse.SignatureAlgorithmEd25519 && len(key) == ed25519.PublicKeySize
		if !validInput {
			if canonicalErr == nil || deriveErr == nil || keyID != "" {
				t.Fatalf("unsupported algorithm/key shape accepted: algorithm=%d len=%d", algorithm, len(key))
			}
			return
		}
		if canonicalErr != nil || deriveErr != nil || ValidateKeyID(keyID, algorithm, key) != nil {
			t.Fatalf("valid Ed25519 key rejected: canonical=%v derive=%v", canonicalErr, deriveErr)
		}
		if len(canonical) != len(key) || &canonical[0] == &key[0] {
			t.Fatal("canonical key is not a detached exact-length copy")
		}
		mutated := keyID[:len(keyID)-1] + map[bool]string{true: "0", false: "1"}[keyID[len(keyID)-1] != '0']
		if ValidateKeyID(mutated, algorithm, key) == nil {
			t.Fatal("mutated content address accepted")
		}
	})
}

func FuzzProofOfPossessionBindsEveryEnrollmentField(f *testing.F) {
	for selector := byte(0); selector < 12; selector++ {
		f.Add(selector, byte(1))
	}
	f.Fuzz(func(t *testing.T, selector, delta byte) {
		if delta == 0 {
			delta = 1
		}
		public, private := testKey(0x31)
		keyID, err := DeriveKeyID(ccse.SignatureAlgorithmEd25519, public)
		if err != nil {
			t.Fatal(err)
		}
		subject := "spiffe://cph.example/agent/fuzz"
		kind := uint32(2)
		target := EntityRef{Kind: EntityIdentity, PrincipalKind: kind, ID: "agent-fuzz"}
		transfer := [32]byte{}
		domain := testEnrollmentDomain()
		challenge := digest(0x41)
		expires := testNow + 1_000
		proof, err := ProofOfPossessionDigest(keyID, subject, kind, target, transfer, domain, challenge, expires)
		if err != nil {
			t.Fatal(err)
		}
		signature := ed25519.Sign(private, proof[:])
		if _, err := VerifyProofOfPossession(ccse.SignatureAlgorithmEd25519, public, keyID,
			subject, kind, target, transfer, domain, challenge, expires, signature); err != nil {
			t.Fatalf("valid proof rejected: %v", err)
		}

		switch selector % 12 {
		case 0:
			replacement := "0"
			if keyID[len(keyID)-1] == '0' {
				replacement = "1"
			}
			keyID = keyID[:len(keyID)-1] + replacement
		case 1:
			subject += string(rune('a' + delta%26))
		case 2:
			kind = 3
		case 3:
			target.ID += string(rune('a' + delta%26))
		case 4:
			target.PrincipalKind = 3
		case 5:
			transfer[0] ^= delta
		case 6:
			domain.EnrollmentDomainID += string(rune('a' + delta%26))
		case 7:
			domain.Environment += string(rune('a' + delta%26))
		case 8:
			domain.GenesisHash[0] ^= delta
		case 9:
			challenge[0] ^= delta
		case 10:
			expires += int64(delta)
		case 11:
			signature[0] ^= delta
		}
		if _, err := VerifyProofOfPossession(ccse.SignatureAlgorithmEd25519, public, keyID,
			subject, kind, target, transfer, domain, challenge, expires, signature); err == nil {
			t.Fatalf("PoP field mutation %d accepted", selector%12)
		}
	})
}
