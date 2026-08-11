// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"reflect"
	"testing"

	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

func identityProjectionFixtures(t testing.TB) []struct {
	name       string
	projection any
	messageID  uint32
	kind       uint32
	entityID   string
	principal  string
	bindings   IdentityBindings
} {
	t.Helper()
	key := materialSnapshot(t, 0x61, "spiffe://unused", 8).KeyID
	return []struct {
		name       string
		projection any
		messageID  uint32
		kind       uint32
		entityID   string
		principal  string
		bindings   IdentityBindings
	}{
		{"provider", foundationv1.ProviderIdentitySigningProjection{Metadata: metadata(1, 7, 0x61), ProviderID: "provider-01",
			OrganizationIdentity: "spiffe://cph.example/provider/01", PayoutIdentity: "cph:provider:01",
			Jurisdictions: []string{"US", "DE"}, PolicyDigestsSHA256: [][32]byte{digest(0x71), digest(0x70)},
			OwnershipGeneration: 1, ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 1},
			schema.MessageTypeProviderIdentity, 1, "provider-01", "spiffe://cph.example/provider/01",
			IdentityBindings{PayoutIdentity: "cph:provider:01"}},
		{"agent", foundationv1.AgentIdentitySigningProjection{Metadata: metadata(1, 7, 0x62), AgentID: "agent-01",
			ProviderID: "provider-01", HostID: "host-01", SPIFFEID: "spiffe://cph.example/agent/01", KeyID: key,
			OwnershipGeneration: 1, ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 1},
			schema.MessageTypeAgentIdentity, 2, "agent-01", "spiffe://cph.example/agent/01",
			IdentityBindings{ProviderID: "provider-01", HostID: "host-01"}},
		{"host", foundationv1.HostIdentitySigningProjection{Metadata: metadata(1, 7, 0x63), HostID: "host-01",
			ProviderID: "provider-01", ProviderSiteID: "site-01", AttestationIdentity: "urn:tpm:host:01", KeyID: key,
			OwnershipGeneration: 1, ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 1},
			schema.MessageTypeHostIdentity, 3, "host-01", "urn:tpm:host:01",
			IdentityBindings{ProviderID: "provider-01", ProviderSiteID: "site-01"}},
		{"device", foundationv1.DeviceIdentitySigningProjection{Metadata: metadata(1, 7, 0x64), DeviceID: "device-01",
			ProviderID: "provider-01", HostID: "host-01", VendorSerialDigestSHA256: digest(0x81),
			AttestationIdentity: "urn:tpm:device:01", KeyID: key, OwnershipGeneration: 1,
			ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 1},
			schema.MessageTypeDeviceIdentity, 4, "device-01", "urn:tpm:device:01",
			IdentityBindings{ProviderID: "provider-01", HostID: "host-01"}},
		{"miner", foundationv1.MinerIdentitySigningProjection{Metadata: metadata(1, 7, 0x65), MinerID: "miner-01",
			ProviderID: "provider-01", AgentID: "agent-01", DeviceIDs: []string{"device-02", "device-01"},
			PayoutIdentity: "cph:miner:01", KeyID: key, BindingGeneration: 1,
			ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 1},
			schema.MessageTypeMinerIdentity, 5, "miner-01", "miner-01",
			IdentityBindings{ProviderID: "provider-01", AgentID: "agent-01", DeviceIDs: []string{"device-01", "device-02"}, PayoutIdentity: "cph:miner:01"}},
		{"runner", foundationv1.RunnerIdentitySigningProjection{Metadata: metadata(1, 7, 0x66), RunnerAttemptID: "runner-01",
			ProviderID: "provider-01", AgentID: "agent-01", LeaseID: "lease-01", JobID: "job-01", AttemptID: "attempt-01",
			WorkloadIdentity: "spiffe://cph.example/runner/01", KeyID: key,
			ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 1},
			schema.MessageTypeRunnerIdentity, 6, "runner-01", "spiffe://cph.example/runner/01",
			IdentityBindings{ProviderID: "provider-01", AgentID: "agent-01", LeaseID: "lease-01", JobID: "job-01", AttemptID: "attempt-01"}},
		{"buyer", foundationv1.BuyerIdentitySigningProjection{Metadata: metadata(1, 7, 0x67), BuyerID: "buyer-01",
			OrganizationIdentityURI: "spiffe://cph.example/buyer/01", BillingIdentity: "billing-01", KeyID: key,
			AuthorizationGeneration: 1, ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 1},
			schema.MessageTypeBuyerIdentity, 7, "buyer-01", "spiffe://cph.example/buyer/01", IdentityBindings{BillingIdentity: "billing-01"}},
		{"service", foundationv1.ServiceIdentitySigningProjection{Metadata: metadata(1, 7, 0x68), ServiceID: "service-01",
			ServiceName: "iam", SPIFFEID: "spiffe://cph.example/service/01", DeploymentEnvironment: "testnet", KeyID: key,
			CredentialGeneration: 1, ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 1},
			schema.MessageTypeServiceIdentity, 8, "service-01", "spiffe://cph.example/service/01", IdentityBindings{Environment: "testnet"}},
	}
}

func TestNormalizeAllIdentityProjectionFieldTableAndRoundTrip(t *testing.T) {
	for _, fixture := range identityProjectionFixtures(t) {
		t.Run(fixture.name, func(t *testing.T) {
			snapshot, err := NormalizeIdentity(fixture.projection)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.MessageTypeID != fixture.messageID || snapshot.Ref.PrincipalKind != fixture.kind ||
				snapshot.Ref.ID != fixture.entityID || snapshot.PrincipalIdentity != fixture.principal ||
				!reflect.DeepEqual(snapshot.Bindings, fixture.bindings) || snapshot.ImmutableBindingDigest == ([32]byte{}) {
				t.Fatalf("snapshot field table mismatch: %#v", snapshot)
			}
			derived, err := normalizeViewIdentity(snapshot)
			if err != nil || !reflect.DeepEqual(snapshot, derived) {
				t.Fatalf("view roundtrip = %#v, %v", derived, err)
			}
			tampered := cloneIdentity(snapshot)
			tampered.StateVersion++
			if _, err := normalizeViewIdentity(tampered); err == nil {
				t.Fatal("split metadata tamper accepted")
			}
		})
	}
}

func TestIdentityImmutableProjectionAndCanonicalSetPermutation(t *testing.T) {
	for _, fixture := range identityProjectionFixtures(t) {
		t.Run(fixture.name, func(t *testing.T) {
			original, err := NormalizeIdentity(fixture.projection)
			if err != nil {
				t.Fatal(err)
			}
			volatile, static := mutateIdentityFixture(fixture.projection)
			volatileSnapshot, err := NormalizeIdentity(volatile)
			if err != nil {
				t.Fatal(err)
			}
			staticSnapshot, err := NormalizeIdentity(static)
			if err != nil {
				t.Fatal(err)
			}
			if original.ImmutableBindingDigest != volatileSnapshot.ImmutableBindingDigest {
				t.Fatal("state/metadata/key mutation changed static binding")
			}
			if original.ImmutableBindingDigest == staticSnapshot.ImmutableBindingDigest {
				t.Fatal("static field mutation did not change binding")
			}
		})
	}

	miner := identityProjectionFixtures(t)[4].projection.(foundationv1.MinerIdentitySigningProjection)
	permuted := miner
	permuted.DeviceIDs = []string{"device-01", "device-02"}
	first, _ := NormalizeIdentity(miner)
	second, _ := NormalizeIdentity(permuted)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("canonical DeviceID set permutation changed normalized snapshot")
	}
	provider := identityProjectionFixtures(t)[0].projection.(foundationv1.ProviderIdentitySigningProjection)
	provider.Metadata.PolicyDigestsSHA256 = [][32]byte{digest(0x52), digest(0x51)}
	permutedProvider := provider
	permutedProvider.Metadata.PolicyDigestsSHA256 = [][32]byte{digest(0x51), digest(0x52)}
	first, _ = NormalizeIdentity(provider)
	second, _ = NormalizeIdentity(permutedProvider)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("canonical policy set permutation changed normalized snapshot")
	}
}

func TestNormalizeLifecycleRejectsUnmodeledHumanUserKind(t *testing.T) {
	material := materialSnapshot(t, 0x6a, "spiffe://cph.example/agent/unused", 2)
	projection := lifecycleProjection(material, 1, 1, 7)
	projection.SubjectKind = 9
	if _, err := NormalizeKeyLifecycle(projection); err == nil {
		t.Fatal("HumanUser key accepted without a HumanUser identity/View contract")
	}
}

func mutateIdentityFixture(projection any) (volatile, static any) {
	switch value := projection.(type) {
	case foundationv1.ProviderIdentitySigningProjection:
		v := value
		v.Metadata.StateVersion++
		v.Metadata.RecordID += "-next"
		v.State = 2
		s := value
		s.PayoutIdentity += "-changed"
		return v, s
	case foundationv1.AgentIdentitySigningProjection:
		v := value
		v.Metadata.StateVersion++
		v.Metadata.RecordID += "-next"
		v.State = 2
		v.KeyID += "-next"
		s := value
		s.HostID += "-changed"
		return v, s
	case foundationv1.HostIdentitySigningProjection:
		v := value
		v.Metadata.StateVersion++
		v.Metadata.RecordID += "-next"
		v.State = 2
		v.KeyID += "-next"
		s := value
		s.ProviderSiteID += "-changed"
		return v, s
	case foundationv1.DeviceIdentitySigningProjection:
		v := value
		v.Metadata.StateVersion++
		v.Metadata.RecordID += "-next"
		v.State = 2
		v.KeyID += "-next"
		s := value
		s.VendorSerialDigestSHA256[0] ^= 1
		return v, s
	case foundationv1.MinerIdentitySigningProjection:
		v := value
		v.Metadata.StateVersion++
		v.Metadata.RecordID += "-next"
		v.State = 2
		v.KeyID += "-next"
		s := value
		s.PayoutIdentity += "-changed"
		return v, s
	case foundationv1.RunnerIdentitySigningProjection:
		v := value
		v.Metadata.StateVersion++
		v.Metadata.RecordID += "-next"
		v.State = 2
		v.KeyID += "-next"
		s := value
		s.AttemptID += "-changed"
		return v, s
	case foundationv1.BuyerIdentitySigningProjection:
		v := value
		v.Metadata.StateVersion++
		v.Metadata.RecordID += "-next"
		v.State = 2
		v.KeyID += "-next"
		s := value
		s.BillingIdentity += "-changed"
		return v, s
	case foundationv1.ServiceIdentitySigningProjection:
		v := value
		v.Metadata.StateVersion++
		v.Metadata.RecordID += "-next"
		v.State = 2
		v.KeyID += "-next"
		s := value
		s.DeploymentEnvironment += "-changed"
		return v, s
	default:
		panic("unknown fixture")
	}
}
