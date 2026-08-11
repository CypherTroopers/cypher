// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package translator

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
	commonv1 "github.com/cypherium/cypher/aiinfra/schema/common/v1"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
	"github.com/cypherium/cypher/aiinfra/schema/strictproto"
	transportv1 "github.com/cypherium/cypher/aiinfra/schema/transport/v1"
	"google.golang.org/protobuf/proto"
)

func TestTranslateUnverifiedAllFoundationPayloads(t *testing.T) {
	for _, projection := range validProjections() {
		projection := projection
		t.Run(fmt.Sprint(projection.MessageTypeID()), func(t *testing.T) {
			wrapper := validWrapper(t, projection)
			wire := marshalWrapper(t, wrapper)
			record, err := TranslateUnverified(wire)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := projection.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			if record.MessageTypeID != projection.MessageTypeID() || record.SchemaVersion != schemaV1 || !bytes.Equal(record.Payload, expected) {
				t.Fatalf("translated record mismatch: id=%d payload=%x", record.MessageTypeID, record.Payload)
			}
			if record.Envelope.PayloadDigest != sha256.Sum256(expected) || !bytes.Equal(record.Signature, wrapper.Envelope.Signature) {
				t.Fatal("transport digest or signature was not preserved")
			}
			for index := range wire {
				wire[index] ^= 0xff
			}
			wrapper.Envelope.Signature[0] ^= 0xff
			if !bytes.Equal(record.Payload, expected) || record.Signature[0] != 0x71 {
				t.Fatal("source mutation changed translated record")
			}
		})
	}
}

func TestTranslateUnverifiedRequiredBoundaryFailures(t *testing.T) {
	provider := validProjections()[0]
	tests := []struct {
		name   string
		mutate func(*transportv1.SignedFoundationRecord)
		want   error
	}{
		{"domain", func(w *transportv1.SignedFoundationRecord) { w.SigningDomain = nil }, ErrMissingRequiredField},
		{"envelope", func(w *transportv1.SignedFoundationRecord) { w.Envelope = nil }, ErrMissingRequiredField},
		{"payload", func(w *transportv1.SignedFoundationRecord) { w.Payload = nil }, ErrMissingRequiredField},
		{"empty payload", func(w *transportv1.SignedFoundationRecord) {
			w.Payload = &transportv1.SignedFoundationRecord_ProviderIdentity{}
		}, ErrMissingRequiredField},
		{"metadata", func(w *transportv1.SignedFoundationRecord) { w.GetProviderIdentity().Metadata = nil }, ErrMissingRequiredField},
		{"purpose", func(w *transportv1.SignedFoundationRecord) { w.SigningDomain.Purpose += ".wrong" }, ErrInvalidPurpose},
		{"domain schema", func(w *transportv1.SignedFoundationRecord) { w.SigningDomain.SchemaVersion.Major = 2 }, ErrInvalidSchemaVersion},
		{"metadata schema", func(w *transportv1.SignedFoundationRecord) { w.GetProviderIdentity().Metadata.SchemaVersion.Minor = 1 }, ErrInvalidSchemaVersion},
		{"sender", func(w *transportv1.SignedFoundationRecord) { w.Envelope.SenderIdentity += ".wrong" }, ccse.ErrDomainEnvelopeMismatch},
		{"chain", func(w *transportv1.SignedFoundationRecord) { w.Envelope.ChainIdUint256Be[0] ^= 1 }, ccse.ErrDomainEnvelopeMismatch},
		{"environment", func(w *transportv1.SignedFoundationRecord) { w.Envelope.Environment += ".wrong" }, ccse.ErrDomainEnvelopeMismatch},
		{"issued", func(w *transportv1.SignedFoundationRecord) { w.Envelope.IssuedAtUnixNano++ }, ccse.ErrDomainEnvelopeMismatch},
		{"expires", func(w *transportv1.SignedFoundationRecord) { w.Envelope.ExpiresAtUnixNano++ }, ccse.ErrDomainEnvelopeMismatch},
		{"replay", func(w *transportv1.SignedFoundationRecord) {
			w.Envelope.ReplayGuard = &commonv1.TransportEnvelope_ExpectedGeneration{ExpectedGeneration: 7}
		}, ccse.ErrDomainEnvelopeMismatch},
		{"algorithm", func(w *transportv1.SignedFoundationRecord) {
			w.Envelope.SignatureAlgorithm = commonv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_P256_SHA256
		}, ccse.ErrDomainEnvelopeMismatch},
		{"key", func(w *transportv1.SignedFoundationRecord) { w.Envelope.SignatureKeyId += ".wrong" }, ccse.ErrDomainEnvelopeMismatch},
		{"digest", func(w *transportv1.SignedFoundationRecord) { w.Envelope.PayloadDigestSha256[0] ^= 1 }, ccse.ErrPayloadDigestMismatch},
		{"message length", func(w *transportv1.SignedFoundationRecord) { w.Envelope.MessageId = w.Envelope.MessageId[:15] }, ErrInvalidFixedLength},
		{"chain length", func(w *transportv1.SignedFoundationRecord) {
			w.SigningDomain.ChainIdUint256Be = w.SigningDomain.ChainIdUint256Be[:31]
		}, ErrInvalidFixedLength},
		{"missing replay", func(w *transportv1.SignedFoundationRecord) { w.SigningDomain.ReplayGuard = nil }, ErrMissingRequiredField},
		{"unspecified algorithm", func(w *transportv1.SignedFoundationRecord) { w.SigningDomain.SignatureAlgorithm = 0 }, ErrMissingRequiredField},
		{"missing signature", func(w *transportv1.SignedFoundationRecord) { w.Envelope.Signature = nil }, ErrInvalidSignatureSize},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrapper := validWrapper(t, provider)
			test.mutate(wrapper)
			_, err := TranslateUnverified(marshalWrapper(t, wrapper))
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want errors.Is(_, %v)", err, test.want)
			}
		})
	}
}

func TestTranslateUnverifiedExtensionPolicy(t *testing.T) {
	provider := validProjections()[0]
	tests := []struct {
		name       string
		extensions []*commonv1.TransportExtension
		want       error
	}{
		{"unknown", []*commonv1.TransportExtension{{ExtensionId: 1, Value: []byte("x")}}, ccse.ErrUnknownExtension},
		{"critical", []*commonv1.TransportExtension{{ExtensionId: 1, Critical: true}}, ccse.ErrUnknownCriticalExtension},
		{"duplicate", []*commonv1.TransportExtension{{ExtensionId: 1}, {ExtensionId: 1}}, ccse.ErrDuplicateExtension},
		{"zero", []*commonv1.TransportExtension{{}}, ccse.ErrInvalidExtension},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrapper := validWrapper(t, provider)
			wrapper.Envelope.Extensions = test.extensions
			_, err := TranslateUnverified(marshalWrapper(t, wrapper))
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestTranslateUnverifiedStrictWireFailures(t *testing.T) {
	wrapper := validWrapper(t, validProjections()[0])
	wire := marshalWrapper(t, wrapper)
	tests := []struct {
		name string
		wire []byte
		want error
	}{
		{"unknown", append(append([]byte(nil), wire...), 0xf8, 0x01, 0x01), strictproto.ErrUnknownField},
		{"reserved", append(append([]byte(nil), wire...), 0x18, 0x01), strictproto.ErrUnknownField},
		{"duplicate domain", append(append([]byte(nil), wire...), wireField(t, wire, 1)...), strictproto.ErrDuplicateField},
		{"same oneof", append(append([]byte(nil), wire...), wireField(t, wire, 16)...), strictproto.ErrDuplicateField},
	}
	other := validWrapper(t, validProjections()[1])
	tests = append(tests, struct {
		name string
		wire []byte
		want error
	}{"different oneof", append(append([]byte(nil), wire...), wireField(t, marshalWrapper(t, other), 17)...), strictproto.ErrOneofConflict})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := TranslateUnverified(test.wire)
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestTranslateUnverifiedStrictNestedFailures(t *testing.T) {
	provider := validProjections()[0]
	tests := []struct {
		name   string
		mutate func(*transportv1.SignedFoundationRecord)
		want   error
	}{
		{"nested unknown", func(w *transportv1.SignedFoundationRecord) {
			w.GetProviderIdentity().ProtoReflect().SetUnknown([]byte{0xf8, 0x01, 0x01})
		}, strictproto.ErrUnknownField},
		{"domain unknown", func(w *transportv1.SignedFoundationRecord) {
			w.SigningDomain.ProtoReflect().SetUnknown([]byte{0xf8, 0x01, 0x01})
		}, strictproto.ErrUnknownField},
		{"unknown enum", func(w *transportv1.SignedFoundationRecord) {
			w.GetProviderIdentity().State = foundationv1.IdentityState(99)
		}, strictproto.ErrUnknownEnum},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrapper := validWrapper(t, provider)
			test.mutate(wrapper)
			_, err := TranslateUnverified(marshalWrapper(t, wrapper))
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestTranslateOwnershipTransferStrictNestedAndEvidenceSemantics(t *testing.T) {
	projection := validOwnershipTransferProjection(validMetadataProjection())
	projection.EvidenceCommitments = append(projection.EvidenceCommitments,
		foundationv1.TransferEvidenceCommitmentSigningProjection{
			EvidenceKind: foundationv1.TransferEvidenceOldProviderAuthority, CCSERecordDigestSHA256: digest32(0x7f),
		})
	if record, err := TranslateUnverified(marshalWrapper(t, validWrapper(t, projection))); err != nil || record.MessageTypeID != schema.MessageTypeOwnershipTransferAuthorization {
		t.Fatalf("same-kind distinct transfer evidence: record=%#v err=%v", record, err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*transportv1.SignedFoundationRecord)
		want   error
	}{
		{"nested evidence unknown field", func(w *transportv1.SignedFoundationRecord) {
			w.GetOwnershipTransferAuthorization().EvidenceCommitments[0].ProtoReflect().SetUnknown([]byte{0xf8, 0x01, 0x01})
		}, strictproto.ErrUnknownField},
		{"nested closure unknown field", func(w *transportv1.SignedFoundationRecord) {
			w.GetOwnershipTransferAuthorization().OldKeyClosures[0].ProtoReflect().SetUnknown([]byte{0xf8, 0x01, 0x01})
		}, strictproto.ErrUnknownField},
		{"unknown evidence enum", func(w *transportv1.SignedFoundationRecord) {
			w.GetOwnershipTransferAuthorization().EvidenceCommitments[0].EvidenceKind = foundationv1.TransferEvidenceKind(99)
		}, strictproto.ErrUnknownEnum},
	} {
		t.Run(test.name, func(t *testing.T) {
			wrapper := validWrapper(t, projection)
			test.mutate(wrapper)
			if _, err := TranslateUnverified(marshalWrapper(t, wrapper)); !errors.Is(err, test.want) {
				t.Fatalf("error=%v, want %v", err, test.want)
			}
		})
	}
}

func TestTranslateUnverifiedCanonicalSemanticFailures(t *testing.T) {
	provider := validProjections()[0]
	tests := []struct {
		name   string
		mutate func(*transportv1.SignedFoundationRecord)
		want   error
	}{
		{"duplicate string set", func(w *transportv1.SignedFoundationRecord) {
			w.GetProviderIdentity().Jurisdictions = []string{"DE", "DE"}
		}, ccse.ErrDuplicateSetValue},
		{"duplicate digest set", func(w *transportv1.SignedFoundationRecord) {
			d := repeat(0x31, 32)
			w.GetProviderIdentity().PolicyDigestsSha256 = [][]byte{d, append([]byte(nil), d...)}
		}, ccse.ErrDuplicateSetValue},
		{"non NFC payload", func(w *transportv1.SignedFoundationRecord) { w.GetProviderIdentity().ProviderId = "e\u0301" }, ccse.ErrNonNFCString},
		{"zero enum", func(w *transportv1.SignedFoundationRecord) {
			w.GetProviderIdentity().State = foundationv1.IdentityState_IDENTITY_STATE_UNSPECIFIED
		}, foundationv1.ErrInvalidEnumValue},
		{"non NFC domain", func(w *transportv1.SignedFoundationRecord) { w.SigningDomain.Audience = []string{"e\u0301"} }, ccse.ErrNonNFCString},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrapper := validWrapper(t, provider)
			test.mutate(wrapper)
			_, err := TranslateUnverified(marshalWrapper(t, wrapper))
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want errors.Is(_, %v)", err, test.want)
			}
		})
	}
}

func TestTranslateUnverifiedPreservesOptionalPresentEmpty(t *testing.T) {
	provider := validProjections()[0].(foundationv1.ProviderIdentitySigningProjection)
	provider.StakeReference = foundationv1.OptionalString{Present: true, Value: ""}
	wrapper := validWrapper(t, provider)
	wrapper.SigningDomain.TenantOrganization = stringPointer("")
	record, err := TranslateUnverified(marshalWrapper(t, wrapper))
	if err != nil {
		t.Fatal(err)
	}
	if !record.Domain.TenantOrganization.Present || record.Domain.TenantOrganization.Value != "" {
		t.Fatal("present-empty domain optional was lost")
	}
	expected, err := provider.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(record.Payload, expected) {
		t.Fatal("present-empty payload optional was lost")
	}
}

func TestTranslateUnverifiedPreservesCatalogAlgorithmForFailClosedVerifier(t *testing.T) {
	for _, algorithm := range []commonv1.SignatureAlgorithm{
		commonv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_P256_SHA256,
		commonv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_EIP712,
	} {
		t.Run(algorithm.String(), func(t *testing.T) {
			wrapper := validWrapper(t, validProjections()[0])
			wrapper.SigningDomain.SignatureAlgorithm = algorithm
			wrapper.Envelope.SignatureAlgorithm = algorithm
			record, err := TranslateUnverified(marshalWrapper(t, wrapper))
			if err != nil {
				t.Fatal(err)
			}
			if record.Domain.SignatureAlgorithm != ccse.SignatureAlgorithmID(algorithm) ||
				record.Envelope.SignatureAlgorithm != ccse.SignatureAlgorithmID(algorithm) {
				t.Fatal("translator changed a catalog-pinned algorithm identifier")
			}
			// TranslateUnverified is not the cryptographic authorization
			// boundary. The generic ccse.Verifier intentionally returns
			// ErrUnsupportedAlgorithm for both identifiers.
		})
	}
}

func TestTranslateUnverifiedRejectsHeaderBeforePayloadProjection(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*transportv1.SignedFoundationRecord)
		want   error
	}{
		{
			name: "purpose",
			mutate: func(wrapper *transportv1.SignedFoundationRecord) {
				wrapper.SigningDomain.Purpose = "wrong.purpose"
			},
			want: ErrInvalidPurpose,
		},
		{
			name: "binding",
			mutate: func(wrapper *transportv1.SignedFoundationRecord) {
				wrapper.Envelope.SenderIdentity = "spiffe://cph.example/service/other"
			},
			want: ccse.ErrDomainEnvelopeMismatch,
		},
		{
			name: "domain semantics",
			mutate: func(wrapper *transportv1.SignedFoundationRecord) {
				wrapper.SigningDomain.SenderIdentity = ""
				wrapper.Envelope.SenderIdentity = ""
			},
			want: ccse.ErrEmptyRequiredDomainField,
		},
		{
			name: "extension policy",
			mutate: func(wrapper *transportv1.SignedFoundationRecord) {
				wrapper.Envelope.Extensions = []*commonv1.TransportExtension{{ExtensionId: 7, Critical: true}}
			},
			want: ccse.ErrUnknownCriticalExtension,
		},
		{
			name: "signature boundary",
			mutate: func(wrapper *transportv1.SignedFoundationRecord) {
				wrapper.Envelope.Signature = nil
			},
			want: ErrInvalidSignatureSize,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrapper := validWrapper(t, validProjections()[0])
			// Every case also carries an invalid payload. The expected header
			// error therefore proves that no canonical payload conversion or
			// payload hash was attempted first.
			wrapper.GetProviderIdentity().State = foundationv1.IdentityState_IDENTITY_STATE_UNSPECIFIED
			test.mutate(wrapper)
			_, err := TranslateUnverified(marshalWrapper(t, wrapper))
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want errors.Is(_, %v)", err, test.want)
			}
		})
	}
}

func TestTranslateUnverifiedPayloadFieldSwapSensitivity(t *testing.T) {
	mutations := []func(*transportv1.SignedFoundationRecord){
		func(wrapper *transportv1.SignedFoundationRecord) {
			payload := wrapper.GetProviderIdentity()
			payload.ProviderId, payload.OrganizationIdentityUri = payload.OrganizationIdentityUri, payload.ProviderId
		},
		func(wrapper *transportv1.SignedFoundationRecord) {
			payload := wrapper.GetAgentIdentity()
			payload.AgentId, payload.ProviderId = payload.ProviderId, payload.AgentId
		},
		func(wrapper *transportv1.SignedFoundationRecord) {
			payload := wrapper.GetHostIdentity()
			payload.HostId, payload.ProviderId = payload.ProviderId, payload.HostId
		},
		func(wrapper *transportv1.SignedFoundationRecord) {
			payload := wrapper.GetDeviceIdentity()
			payload.DeviceId, payload.ProviderId = payload.ProviderId, payload.DeviceId
		},
		func(wrapper *transportv1.SignedFoundationRecord) {
			payload := wrapper.GetMinerIdentity()
			payload.MinerId, payload.ProviderId = payload.ProviderId, payload.MinerId
		},
		func(wrapper *transportv1.SignedFoundationRecord) {
			payload := wrapper.GetRunnerIdentity()
			payload.RunnerAttemptId, payload.ProviderId = payload.ProviderId, payload.RunnerAttemptId
		},
		func(wrapper *transportv1.SignedFoundationRecord) {
			payload := wrapper.GetBuyerIdentity()
			payload.BuyerId, payload.BillingIdentity = payload.BillingIdentity, payload.BuyerId
		},
		func(wrapper *transportv1.SignedFoundationRecord) {
			payload := wrapper.GetServiceIdentity()
			payload.ServiceId, payload.ServiceName = payload.ServiceName, payload.ServiceId
		},
		func(wrapper *transportv1.SignedFoundationRecord) {
			payload := wrapper.GetKeyLifecycle()
			payload.KeyId, payload.SubjectIdentity = payload.SubjectIdentity, payload.KeyId
		},
		func(wrapper *transportv1.SignedFoundationRecord) {
			payload := wrapper.GetPolicyBundle()
			payload.PolicyBundleId, payload.PolicyKind = payload.PolicyKind, payload.PolicyBundleId
		},
		func(wrapper *transportv1.SignedFoundationRecord) {
			payload := wrapper.GetAuditEvent()
			payload.EventType, payload.CauseCode = payload.CauseCode, payload.EventType
		},
		func(wrapper *transportv1.SignedFoundationRecord) {
			payload := wrapper.GetEvidenceRecord()
			payload.EvidenceId, payload.CapabilityId = payload.CapabilityId, payload.EvidenceId
		},
		func(wrapper *transportv1.SignedFoundationRecord) {
			payload := wrapper.GetExperimentPlan()
			payload.ExperimentPlanId, payload.CapabilityId = payload.CapabilityId, payload.ExperimentPlanId
		},
		func(wrapper *transportv1.SignedFoundationRecord) {
			payload := wrapper.GetOwnershipTransferAuthorization()
			payload.PreviousEntityId, payload.NextEntityId = payload.NextEntityId, payload.PreviousEntityId
		},
	}
	projections := validProjections()
	if len(mutations) != len(projections) {
		t.Fatalf("mutation coverage=%d payloads=%d", len(mutations), len(projections))
	}
	for index, projection := range projections {
		t.Run(fmt.Sprint(projection.MessageTypeID()), func(t *testing.T) {
			wrapper := validWrapper(t, projection)
			mutations[index](wrapper)
			_, err := TranslateUnverified(marshalWrapper(t, wrapper))
			if !errors.Is(err, ccse.ErrPayloadDigestMismatch) {
				t.Fatalf("got %v, want field swap to change canonical payload digest", err)
			}
		})
	}
}

func TestTranslateUnverifiedDeepFieldSwapSensitivity(t *testing.T) {
	tests := []struct {
		name       string
		projection signingProjection
		mutate     func(*transportv1.SignedFoundationRecord)
	}{
		{
			name:       "evidence observation",
			projection: validProjections()[11],
			mutate: func(wrapper *transportv1.SignedFoundationRecord) {
				payload := wrapper.GetEvidenceRecord()
				payload.Observations[0].MetricId, payload.ApprovingRole = payload.ApprovingRole, payload.Observations[0].MetricId
			},
		},
		{
			name:       "experiment criterion",
			projection: validProjections()[12],
			mutate: func(wrapper *transportv1.SignedFoundationRecord) {
				criterion := wrapper.GetExperimentPlan().Criteria[0]
				criterion.MetricId, criterion.Unit = criterion.Unit, criterion.MetricId
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrapper := validWrapper(t, test.projection)
			test.mutate(wrapper)
			_, err := TranslateUnverified(marshalWrapper(t, wrapper))
			if !errors.Is(err, ccse.ErrPayloadDigestMismatch) {
				t.Fatalf("got %v, want deep field swap to change canonical payload digest", err)
			}
		})
	}
}

type testFataler interface {
	Helper()
	Fatal(args ...any)
}

func validWrapper(t testFataler, projection signingProjection) *transportv1.SignedFoundationRecord {
	t.Helper()
	payload, err := projection.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	purpose := purposeFor(projection.MessageTypeID())
	wrapper := &transportv1.SignedFoundationRecord{
		SigningDomain: &commonv1.TransportSigningDomain{
			Purpose: purpose, SenderIdentity: "spiffe://cph.example/service/writer", Audience: []string{"service:foundation"},
			TenantOrganization: stringPointer("tenant-01"), ProviderOrganization: stringPointer("provider-org-01"),
			ChainIdUint256Be: repeat(0x51, 32), GenesisHashSha256: repeat(0x52, 32), Environment: "testnet",
			ProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, SchemaVersion: &commonv1.SchemaVersion{Major: 1},
			SignatureAlgorithm: commonv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519, SignatureKeyId: "key-writer-01",
			IssuedAtUnixNano: 1_799_999_000_000_000_000, ExpiresAtUnixNano: 1_800_001_000_000_000_000,
			ReplayGuard: &commonv1.TransportSigningDomain_Sequence{Sequence: 7}, ReplayDomainId: "foundation:testnet",
		},
		Envelope: &commonv1.TransportEnvelope{
			ProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, SchemaVersion: &commonv1.SchemaVersion{Major: 1},
			MessageId: repeat(0x61, 16), CorrelationId: repeat(0x62, 16), CausationId: repeat(0x63, 16),
			SenderIdentity: "spiffe://cph.example/service/writer", ChainIdUint256Be: repeat(0x51, 32), Environment: "testnet",
			IssuedAtUnixNano: 1_799_999_000_000_000_000, ExpiresAtUnixNano: 1_800_001_000_000_000_000,
			ReplayGuard: &commonv1.TransportEnvelope_Sequence{Sequence: 7}, PayloadDigestSha256: append([]byte(nil), digest[:]...),
			SignatureAlgorithm: commonv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519, SignatureKeyId: "key-writer-01",
			Signature: repeat(0x71, 64),
		},
	}
	setProtoArm(wrapper, projection)
	return wrapper
}

func marshalWrapper(t testFataler, wrapper *transportv1.SignedFoundationRecord) []byte {
	t.Helper()
	wire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(wrapper)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func purposeFor(id uint32) string {
	for _, message := range reviewedMessages {
		if message.id == id {
			return message.purpose
		}
	}
	return ""
}

func validProjections() []signingProjection {
	metadata := validMetadataProjection()
	return []signingProjection{
		foundationv1.ProviderIdentitySigningProjection{Metadata: metadata, ProviderID: "provider-01", OrganizationIdentity: "spiffe://cph.example/provider/01", PayoutIdentity: "cph:01", Jurisdictions: []string{"DE"}, PolicyDigestsSHA256: [][32]byte{digest32(0x31)}, StakeReference: foundationv1.OptionalString{Present: true}, OwnershipGeneration: 1, ValidFromUnixNano: 1_800_000_000_000_000_000, ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2},
		foundationv1.AgentIdentitySigningProjection{Metadata: metadata, AgentID: "agent-01", ProviderID: "provider-01", HostID: "host-01", SPIFFEID: "spiffe://cph.example/agent/01", KeyID: "key-agent-01", OwnershipGeneration: 1, ValidFromUnixNano: 1_800_000_000_000_000_000, ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2},
		foundationv1.HostIdentitySigningProjection{Metadata: metadata, HostID: "host-01", ProviderID: "provider-01", ProviderSiteID: "site-01", AttestationIdentity: "attestation:host:01", KeyID: "key-host-01", OwnershipGeneration: 1, ValidFromUnixNano: 1_800_000_000_000_000_000, ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2},
		foundationv1.DeviceIdentitySigningProjection{Metadata: metadata, DeviceID: "device-01", ProviderID: "provider-01", HostID: "host-01", VendorSerialDigestSHA256: digest32(0x32), AttestationIdentity: "attestation:device:01", KeyID: "key-device-01", OwnershipGeneration: 1, ValidFromUnixNano: 1_800_000_000_000_000_000, ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2},
		foundationv1.MinerIdentitySigningProjection{Metadata: metadata, MinerID: "miner-01", ProviderID: "provider-01", AgentID: "agent-01", DeviceIDs: []string{"device-01"}, PayoutIdentity: "cph:01", KeyID: "key-miner-01", BindingGeneration: 1, ValidFromUnixNano: 1_800_000_000_000_000_000, ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2},
		foundationv1.RunnerIdentitySigningProjection{Metadata: metadata, RunnerAttemptID: "runner-attempt-01", ProviderID: "provider-01", AgentID: "agent-01", LeaseID: "lease-01", JobID: "job-01", AttemptID: "attempt-01", WorkloadIdentity: "spiffe://cph.example/runner/01", KeyID: "key-runner-01", ValidFromUnixNano: 1_800_000_000_000_000_000, ValidUntilUnixNano: 1_800_003_600_000_000_000, State: 2},
		foundationv1.BuyerIdentitySigningProjection{Metadata: metadata, BuyerID: "buyer-01", OrganizationIdentityURI: "spiffe://cph.example/buyer/01", BillingIdentity: "billing-01", KeyID: "key-buyer-01", AuthorizationGeneration: 1, ValidFromUnixNano: 1_800_000_000_000_000_000, ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2},
		foundationv1.ServiceIdentitySigningProjection{Metadata: metadata, ServiceID: "service-01", ServiceName: "lease-service", SPIFFEID: "spiffe://cph.example/service/lease", DeploymentEnvironment: "testnet", KeyID: "key-service-01", CredentialGeneration: 1, ValidFromUnixNano: 1_800_000_000_000_000_000, ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2},
		foundationv1.KeyLifecycleSigningProjection{Metadata: metadata, KeyID: "key-01", SubjectIdentity: "spiffe://cph.example/service/scheduler", SubjectKind: 8, Algorithm: 1, State: 2, NotBeforeUnixNano: 1_800_000_000_000_000_000, NotAfterUnixNano: 1_800_086_400_000_000_000, RotationPredecessorKeyID: foundationv1.OptionalString{Present: true, Value: "key-00"}, AllowedMessageTypeIDs: []uint32{schema.MessageTypeExperimentPlan}, AuthorizationPolicyDigestSHA256: digest32(0x33), TransitionReasonCode: foundationv1.OptionalString{Present: true, Value: "scheduled"}},
		foundationv1.PolicyBundleSigningProjection{Metadata: metadata, PolicyBundleID: "policy-01", PolicyKind: "provider-eligibility", PolicyVersion: foundationv1.SchemaVersionSigningProjection{Major: 1}, Sequence: 1, ApprovedAtUnixNano: 1_799_999_000_000_000_000, EffectiveAtUnixNano: 1_800_000_000_000_000_000, ExpiresAtUnixNano: 1_900_000_000_000_000_000, PolicyDocumentDigestSHA256: digest32(0x34), PolicyDocumentMediaType: "application/json", ApproverIdentities: []string{"approver-01"}, ApproverKeyIDs: []string{"key-approver-01"}, MinimumApprovals: 1, Emergency: true, BreakGlassExpiresAtUnixNano: foundationv1.OptionalInt64{Present: true, Value: 1_850_000_000_000_000_000}, State: 3},
		foundationv1.AuditEventSigningProjection{Metadata: metadata, AuditEventID: "audit-01", EventType: "PolicyActivated", ActorIdentity: "actor-01", ActorKeyID: "key-actor-01", SubjectIDs: []string{"policy-01"}, CauseCode: "scheduled", CorrelationID: id16(0x35), CausationID: foundationv1.OptionalFixedBytes16{Present: true, Value: id16(0x36)}, OccurredAtUnixNano: 1_800_000_000_000_000_000, Outcome: 1, AppliedPolicyDigestsSHA256: [][32]byte{digest32(0x37)}, EvidenceDigestsSHA256: [][32]byte{digest32(0x38)}, RedactedDetailsDigestSHA256: foundationv1.OptionalFixedBytes32{Present: true, Value: digest32(0x39)}, PreviousEventDigestSHA256: digest32(0x3a), AuditSequence: 1},
		validEvidenceProjection(metadata),
		validExperimentProjection(metadata),
		validOwnershipTransferProjection(metadata),
	}
}

func validOwnershipTransferProjection(metadata foundationv1.RecordMetadataSigningProjection) foundationv1.OwnershipTransferAuthorizationSigningProjection {
	return foundationv1.OwnershipTransferAuthorizationSigningProjection{
		Metadata: metadata, TransferAuthorizationID: "transfer-01", SubjectKind: 2,
		PreviousEntityID: "agent-old", NextEntityID: "agent-new", PreviousPrincipalIdentity: "principal-old",
		NextPrincipalIdentity: "principal-new", PreviousProviderID: "provider-old", NextProviderID: "provider-new",
		ExpectedGeneration: 1, NextGeneration: 2, PreviousTerminalIdentityPayloadDigestSHA256: digest32(0x71),
		NextPendingIdentityPayloadDigestSHA256: digest32(0x72),
		OldKeyClosures:                         []foundationv1.KeyClosureSigningProjection{{KeyID: "key-old", TerminalKeyLifecyclePayloadDigestSHA256: digest32(0x73)}},
		NewKeyID:                               "key-new",
		EvidenceCommitments: []foundationv1.TransferEvidenceCommitmentSigningProjection{
			{EvidenceKind: foundationv1.TransferEvidenceOldProviderAuthority, CCSERecordDigestSHA256: digest32(0x74)},
			{EvidenceKind: foundationv1.TransferEvidenceNewProviderAuthority, CCSERecordDigestSHA256: digest32(0x75)},
			{EvidenceKind: foundationv1.TransferEvidenceDescendantIdentityClosure, CCSERecordDigestSHA256: digest32(0x76)},
			{EvidenceKind: foundationv1.TransferEvidenceLeaseOfferWorkloadClosure, CCSERecordDigestSHA256: digest32(0x77)},
		},
		EffectiveAtUnixNano: 1_800_000_000_000_000_000, ExpiresAtUnixNano: 1_800_003_600_000_000_000,
		OldAuthorities: []foundationv1.TransferAuthoritySigningProjection{{Identity: "authority-old", KeyID: "authority-key-old"}},
		NewAuthorities: []foundationv1.TransferAuthoritySigningProjection{{Identity: "authority-new", KeyID: "authority-key-new"}},
	}
}

func validMetadataProjection() foundationv1.RecordMetadataSigningProjection {
	return foundationv1.RecordMetadataSigningProjection{SchemaVersion: foundationv1.SchemaVersionSigningProjection{Major: 1}, RecordID: "record-01", CreatedAtUnixNano: 1_800_000_000_000_000_000, IntegrityDigest: digest32(0x21), HomeRegion: "eu-central-1", WriterEpoch: 1, StateVersion: 1, IdempotencyKey: id16(0x22), PolicyDigestsSHA256: [][32]byte{digest32(0x23)}}
}

func validEvidenceProjection(metadata foundationv1.RecordMetadataSigningProjection) foundationv1.EvidenceRecordSigningProjection {
	return foundationv1.EvidenceRecordSigningProjection{Metadata: metadata, EvidenceID: "evidence-01", ExperimentPlanID: "plan-01", CapabilityID: "CAP-01", Component: "agent", OwnerIdentity: "owner-01", SoftwareVersion: "v1", HardwareScope: []string{"gpu:01"}, WorkloadScope: []string{"mining"}, RegionScope: []string{"eu"}, TestStartedAtUnixNano: 1_799_000_000_000_000_000, TestEndedAtUnixNano: 1_799_500_000_000_000_000, SampleSize: 100, EvidenceArtifactDigestsSHA256: [][32]byte{digest32(0x41)}, Observations: []foundationv1.MetricObservationSigningProjection{{MetricID: "latency", ObservedNumerator: 5, ObservedDenominator: 1, SampleSize: 100, ConfidenceLowerNumerator: 4, ConfidenceLowerDenominator: 1, ConfidenceUpperNumerator: 6, ConfidenceUpperDenominator: 1, CriterionPassed: true}}, ApprovingRole: "reviewer", ApprovingIdentities: []string{"reviewer-01"}, ApprovedAtUnixNano: 1_799_600_000_000_000_000, ExpiresAtUnixNano: 1_900_000_000_000_000_000, RevalidationTriggers: []string{"major-change"}, AchievedLevel: 4, Status: 2}
}

func validExperimentProjection(metadata foundationv1.RecordMetadataSigningProjection) foundationv1.ExperimentPlanSigningProjection {
	return foundationv1.ExperimentPlanSigningProjection{Metadata: metadata, ExperimentPlanID: "plan-01", CapabilityID: "CAP-01", Component: "agent", OwnerIdentity: "owner-01", SoftwareVersion: "v1", HardwareScope: []string{"gpu:01"}, WorkloadScope: []string{"mining"}, RegionScope: []string{"eu"}, CollectionNotBeforeUnixNano: 1_800_000_100_000_000_000, ObservationWindowNanos: 86_400_000_000_000, MinimumSampleSize: 100, ConfidenceLevelBasisPoints: 9500, ConfidenceMethod: 2, Criteria: []foundationv1.MetricCriterionSigningProjection{{MetricID: "latency", Comparison: 6, ThresholdNumerator: 4, ThresholdDenominator: 1, UpperThresholdNumerator: foundationv1.OptionalInt64{Present: true, Value: 6}, UpperThresholdDenominator: foundationv1.OptionalUint64{Present: true, Value: 1}, Unit: "seconds", PercentileBasisPoints: foundationv1.OptionalUint32{Present: true, Value: 9500}, MinimumMetricSampleSize: 100}}, RevalidationTriggers: []string{"major-change"}, ExpiresAtUnixNano: 1_900_000_000_000_000_000, ExperimentPolicyDigestSHA256: digest32(0x42), TargetLevel: 4, FrozenAtUnixNano: 1_800_000_000_000_000_000, ApprovingIdentities: []string{"reviewer-01"}}
}

func repeat(fill byte, size int) []byte { return bytes.Repeat([]byte{fill}, size) }
func digest32(fill byte) (out [32]byte) {
	for i := range out {
		out[i] = fill
	}
	return out
}
func id16(fill byte) (out [16]byte) {
	for i := range out {
		out[i] = fill
	}
	return out
}
func stringPointer(value string) *string { return &value }
