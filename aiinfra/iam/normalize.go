// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"reflect"
	"sort"
	"sync"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
	"github.com/cypherium/cypher/aiinfra/schema/foundation/v1/canonical"
)

const identityBindingDomain = "CPH-AIIE-IDENTITY-BINDING-V1\x00"

var (
	canonicalValidatorOnce sync.Once
	canonicalValidator     *canonical.Validator
	canonicalValidatorErr  error
)

func foundationCanonicalValidator() (*canonical.Validator, error) {
	canonicalValidatorOnce.Do(func() { canonicalValidator, canonicalValidatorErr = canonical.NewValidator() })
	return canonicalValidator, canonicalValidatorErr
}

// NormalizeIdentity validates any of the eight immutable v1 identity signing
// projections and returns their common detached semantic form.
func NormalizeIdentity(projection any) (IdentitySnapshot, error) {
	switch value := projection.(type) {
	case foundationv1.ProviderIdentitySigningProjection:
		return normalizeProvider(value)
	case *foundationv1.ProviderIdentitySigningProjection:
		if value == nil {
			return IdentitySnapshot{}, ErrInvalidInput
		}
		return normalizeProvider(*value)
	case foundationv1.AgentIdentitySigningProjection:
		return normalizeAgent(value)
	case *foundationv1.AgentIdentitySigningProjection:
		if value == nil {
			return IdentitySnapshot{}, ErrInvalidInput
		}
		return normalizeAgent(*value)
	case foundationv1.HostIdentitySigningProjection:
		return normalizeHost(value)
	case *foundationv1.HostIdentitySigningProjection:
		if value == nil {
			return IdentitySnapshot{}, ErrInvalidInput
		}
		return normalizeHost(*value)
	case foundationv1.DeviceIdentitySigningProjection:
		return normalizeDevice(value)
	case *foundationv1.DeviceIdentitySigningProjection:
		if value == nil {
			return IdentitySnapshot{}, ErrInvalidInput
		}
		return normalizeDevice(*value)
	case foundationv1.MinerIdentitySigningProjection:
		return normalizeMiner(value)
	case *foundationv1.MinerIdentitySigningProjection:
		if value == nil {
			return IdentitySnapshot{}, ErrInvalidInput
		}
		return normalizeMiner(*value)
	case foundationv1.RunnerIdentitySigningProjection:
		return normalizeRunner(value)
	case *foundationv1.RunnerIdentitySigningProjection:
		if value == nil {
			return IdentitySnapshot{}, ErrInvalidInput
		}
		return normalizeRunner(*value)
	case foundationv1.BuyerIdentitySigningProjection:
		return normalizeBuyer(value)
	case *foundationv1.BuyerIdentitySigningProjection:
		if value == nil {
			return IdentitySnapshot{}, ErrInvalidInput
		}
		return normalizeBuyer(*value)
	case foundationv1.ServiceIdentitySigningProjection:
		return normalizeService(value)
	case *foundationv1.ServiceIdentitySigningProjection:
		if value == nil {
			return IdentitySnapshot{}, ErrInvalidInput
		}
		return normalizeService(*value)
	default:
		return IdentitySnapshot{}, fmt.Errorf("%w: unsupported identity projection %T", ErrInvalidInput, projection)
	}
}

type identityCore struct {
	metadata          foundationv1.RecordMetadataSigningProjection
	messageTypeID     uint32
	principalKind     uint32
	entityID          string
	principalIdentity string
	keyID             string
	state             uint32
	generation        uint64
	validFrom         int64
	validUntil        int64
	bindings          IdentityBindings
}

func identitySnapshot(core identityCore, canonical, immutable []byte) (IdentitySnapshot, error) {
	if core.metadata.SchemaVersion.Major != 1 || core.metadata.SchemaVersion.Minor != 0 {
		return IdentitySnapshot{}, fmt.Errorf("%w: identity schema version must be 1.0", ErrInvalidInput)
	}
	if len(canonical) == 0 || len(immutable) == 0 {
		return IdentitySnapshot{}, ErrInvalidInput
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(identityBindingDomain))
	_, _ = hash.Write(immutable)
	var binding [32]byte
	copy(binding[:], hash.Sum(nil))
	policies := cloneDigests(core.metadata.PolicyDigestsSHA256)
	sort.Slice(policies, func(i, j int) bool { return bytes.Compare(policies[i][:], policies[j][:]) < 0 })
	bindings := core.bindings
	bindings.DeviceIDs = append([]string(nil), core.bindings.DeviceIDs...)
	sort.Strings(bindings.DeviceIDs)
	return IdentitySnapshot{
		Ref:           EntityRef{Kind: EntityIdentity, PrincipalKind: core.principalKind, ID: core.entityID},
		MessageTypeID: core.messageTypeID,
		RecordID:      core.metadata.RecordID, CreatedAtUnixNano: core.metadata.CreatedAtUnixNano,
		PrincipalIdentity: core.principalIdentity, KeyID: core.keyID,
		State: core.state, Generation: core.generation, ValidFromUnixNano: core.validFrom,
		ValidUntilUnixNano: core.validUntil, HomeRegion: core.metadata.HomeRegion,
		WriterEpoch: core.metadata.WriterEpoch, StateVersion: core.metadata.StateVersion,
		IdempotencyKey:        core.metadata.IdempotencyKey,
		PolicyDigestsSHA256:   policies,
		IntegrityDigestSHA256: core.metadata.IntegrityDigest,
		CanonicalPayload:      append([]byte(nil), canonical...), Bindings: bindings,
		ImmutableBindingDigest: binding,
	}, nil
}

func immutableProjection(messageTypeID uint32, emit func(*ccse.Encoder)) ([]byte, error) {
	return ccse.Marshal(32768, func(out *ccse.Encoder) {
		out.Uint32(messageTypeID)
		emit(out)
	})
}

func encodedStringSet(values []string) ([][]byte, error) {
	encoded := make([][]byte, len(values))
	for i := range values {
		item, err := ccse.Marshal(4096, func(out *ccse.Encoder) { out.String(values[i]) })
		if err != nil {
			return nil, err
		}
		encoded[i] = item
	}
	return encoded, nil
}

func encodedDigestSet(values [][32]byte) ([][]byte, error) {
	encoded := make([][]byte, len(values))
	for i := range values {
		item, err := ccse.Marshal(64, func(out *ccse.Encoder) { out.FixedBytes(values[i][:], 32) })
		if err != nil {
			return nil, err
		}
		encoded[i] = item
	}
	return encoded, nil
}

func normalizeProvider(value foundationv1.ProviderIdentitySigningProjection) (IdentitySnapshot, error) {
	canonical, err := value.CanonicalBytes()
	if err != nil {
		return IdentitySnapshot{}, err
	}
	jurisdictions, err := encodedStringSet(value.Jurisdictions)
	if err != nil {
		return IdentitySnapshot{}, err
	}
	policies, err := encodedDigestSet(value.PolicyDigestsSHA256)
	if err != nil {
		return IdentitySnapshot{}, err
	}
	immutable, err := immutableProjection(schema.MessageTypeProviderIdentity, func(out *ccse.Encoder) {
		out.String(value.ProviderID)
		out.String(value.OrganizationIdentity)
		out.String(value.PayoutIdentity)
		out.EncodedSet(jurisdictions)
		out.EncodedSet(policies)
		out.OptionalString(value.StakeReference.Present, value.StakeReference.Value)
	})
	if err != nil {
		return IdentitySnapshot{}, err
	}
	return identitySnapshot(identityCore{metadata: value.Metadata, messageTypeID: schema.MessageTypeProviderIdentity,
		principalKind: 1, entityID: value.ProviderID, principalIdentity: value.OrganizationIdentity,
		state: value.State, generation: value.OwnershipGeneration, validFrom: value.ValidFromUnixNano,
		validUntil: value.ValidUntilUnixNano, bindings: IdentityBindings{PayoutIdentity: value.PayoutIdentity}}, canonical, immutable)
}

func normalizeAgent(value foundationv1.AgentIdentitySigningProjection) (IdentitySnapshot, error) {
	canonical, err := value.CanonicalBytes()
	if err != nil {
		return IdentitySnapshot{}, err
	}
	immutable, err := immutableProjection(schema.MessageTypeAgentIdentity, func(out *ccse.Encoder) {
		out.String(value.AgentID)
		out.String(value.ProviderID)
		out.String(value.HostID)
		out.String(value.SPIFFEID)
	})
	if err != nil {
		return IdentitySnapshot{}, err
	}
	return identitySnapshot(identityCore{metadata: value.Metadata, messageTypeID: schema.MessageTypeAgentIdentity,
		principalKind: 2, entityID: value.AgentID, principalIdentity: value.SPIFFEID, keyID: value.KeyID,
		state: value.State, generation: value.OwnershipGeneration, validFrom: value.ValidFromUnixNano,
		validUntil: value.ValidUntilUnixNano, bindings: IdentityBindings{ProviderID: value.ProviderID, HostID: value.HostID}}, canonical, immutable)
}

func normalizeHost(value foundationv1.HostIdentitySigningProjection) (IdentitySnapshot, error) {
	canonical, err := value.CanonicalBytes()
	if err != nil {
		return IdentitySnapshot{}, err
	}
	immutable, err := immutableProjection(schema.MessageTypeHostIdentity, func(out *ccse.Encoder) {
		out.String(value.HostID)
		out.String(value.ProviderID)
		out.String(value.ProviderSiteID)
		out.String(value.AttestationIdentity)
	})
	if err != nil {
		return IdentitySnapshot{}, err
	}
	return identitySnapshot(identityCore{metadata: value.Metadata, messageTypeID: schema.MessageTypeHostIdentity,
		principalKind: 3, entityID: value.HostID, principalIdentity: value.AttestationIdentity, keyID: value.KeyID,
		state: value.State, generation: value.OwnershipGeneration, validFrom: value.ValidFromUnixNano,
		validUntil: value.ValidUntilUnixNano,
		bindings:   IdentityBindings{ProviderID: value.ProviderID, ProviderSiteID: value.ProviderSiteID}}, canonical, immutable)
}

func normalizeDevice(value foundationv1.DeviceIdentitySigningProjection) (IdentitySnapshot, error) {
	canonical, err := value.CanonicalBytes()
	if err != nil {
		return IdentitySnapshot{}, err
	}
	immutable, err := immutableProjection(schema.MessageTypeDeviceIdentity, func(out *ccse.Encoder) {
		out.String(value.DeviceID)
		out.String(value.ProviderID)
		out.String(value.HostID)
		out.FixedBytes(value.VendorSerialDigestSHA256[:], 32)
		out.String(value.AttestationIdentity)
	})
	if err != nil {
		return IdentitySnapshot{}, err
	}
	return identitySnapshot(identityCore{metadata: value.Metadata, messageTypeID: schema.MessageTypeDeviceIdentity,
		principalKind: 4, entityID: value.DeviceID, principalIdentity: value.AttestationIdentity, keyID: value.KeyID,
		state: value.State, generation: value.OwnershipGeneration, validFrom: value.ValidFromUnixNano,
		validUntil: value.ValidUntilUnixNano, bindings: IdentityBindings{ProviderID: value.ProviderID, HostID: value.HostID}}, canonical, immutable)
}

func normalizeMiner(value foundationv1.MinerIdentitySigningProjection) (IdentitySnapshot, error) {
	canonical, err := value.CanonicalBytes()
	if err != nil {
		return IdentitySnapshot{}, err
	}
	devices, err := encodedStringSet(value.DeviceIDs)
	if err != nil {
		return IdentitySnapshot{}, err
	}
	immutable, err := immutableProjection(schema.MessageTypeMinerIdentity, func(out *ccse.Encoder) {
		out.String(value.MinerID)
		out.String(value.ProviderID)
		out.String(value.AgentID)
		out.EncodedSet(devices)
		out.String(value.PayoutIdentity)
	})
	if err != nil {
		return IdentitySnapshot{}, err
	}
	return identitySnapshot(identityCore{metadata: value.Metadata, messageTypeID: schema.MessageTypeMinerIdentity,
		principalKind: 5, entityID: value.MinerID, principalIdentity: value.MinerID, keyID: value.KeyID,
		state: value.State, generation: value.BindingGeneration, validFrom: value.ValidFromUnixNano,
		validUntil: value.ValidUntilUnixNano, bindings: IdentityBindings{ProviderID: value.ProviderID,
			AgentID: value.AgentID, DeviceIDs: append([]string(nil), value.DeviceIDs...), PayoutIdentity: value.PayoutIdentity}}, canonical, immutable)
}

func normalizeRunner(value foundationv1.RunnerIdentitySigningProjection) (IdentitySnapshot, error) {
	canonical, err := value.CanonicalBytes()
	if err != nil {
		return IdentitySnapshot{}, err
	}
	immutable, err := immutableProjection(schema.MessageTypeRunnerIdentity, func(out *ccse.Encoder) {
		out.String(value.RunnerAttemptID)
		out.String(value.ProviderID)
		out.String(value.AgentID)
		out.String(value.LeaseID)
		out.String(value.JobID)
		out.String(value.AttemptID)
		out.String(value.WorkloadIdentity)
	})
	if err != nil {
		return IdentitySnapshot{}, err
	}
	return identitySnapshot(identityCore{metadata: value.Metadata, messageTypeID: schema.MessageTypeRunnerIdentity,
		principalKind: 6, entityID: value.RunnerAttemptID, principalIdentity: value.WorkloadIdentity, keyID: value.KeyID,
		state: value.State, validFrom: value.ValidFromUnixNano, validUntil: value.ValidUntilUnixNano,
		bindings: IdentityBindings{ProviderID: value.ProviderID, AgentID: value.AgentID, LeaseID: value.LeaseID,
			JobID: value.JobID, AttemptID: value.AttemptID}}, canonical, immutable)
}

func normalizeBuyer(value foundationv1.BuyerIdentitySigningProjection) (IdentitySnapshot, error) {
	canonical, err := value.CanonicalBytes()
	if err != nil {
		return IdentitySnapshot{}, err
	}
	immutable, err := immutableProjection(schema.MessageTypeBuyerIdentity, func(out *ccse.Encoder) {
		out.String(value.BuyerID)
		out.String(value.OrganizationIdentityURI)
		out.String(value.BillingIdentity)
	})
	if err != nil {
		return IdentitySnapshot{}, err
	}
	return identitySnapshot(identityCore{metadata: value.Metadata, messageTypeID: schema.MessageTypeBuyerIdentity,
		principalKind: 7, entityID: value.BuyerID, principalIdentity: value.OrganizationIdentityURI, keyID: value.KeyID,
		state: value.State, generation: value.AuthorizationGeneration, validFrom: value.ValidFromUnixNano,
		validUntil: value.ValidUntilUnixNano, bindings: IdentityBindings{BillingIdentity: value.BillingIdentity}}, canonical, immutable)
}

func normalizeService(value foundationv1.ServiceIdentitySigningProjection) (IdentitySnapshot, error) {
	canonical, err := value.CanonicalBytes()
	if err != nil {
		return IdentitySnapshot{}, err
	}
	immutable, err := immutableProjection(schema.MessageTypeServiceIdentity, func(out *ccse.Encoder) {
		out.String(value.ServiceID)
		out.String(value.ServiceName)
		out.String(value.SPIFFEID)
		out.String(value.DeploymentEnvironment)
	})
	if err != nil {
		return IdentitySnapshot{}, err
	}
	return identitySnapshot(identityCore{metadata: value.Metadata, messageTypeID: schema.MessageTypeServiceIdentity,
		principalKind: 8, entityID: value.ServiceID, principalIdentity: value.SPIFFEID, keyID: value.KeyID,
		state: value.State, generation: value.CredentialGeneration, validFrom: value.ValidFromUnixNano,
		validUntil: value.ValidUntilUnixNano, bindings: IdentityBindings{Environment: value.DeploymentEnvironment}}, canonical, immutable)
}

func normalizeViewIdentity(snapshot IdentitySnapshot) (IdentitySnapshot, error) {
	if len(snapshot.CanonicalPayload) > 32768 || len(snapshot.PolicyDigestsSHA256) > 64 || len(snapshot.Bindings.DeviceIDs) > 64 {
		return IdentitySnapshot{}, ErrViewInconsistent
	}
	snapshot = cloneIdentity(snapshot)
	if snapshot.Ref.Kind != EntityIdentity || snapshot.Ref.PrincipalKind < 1 || snapshot.Ref.PrincipalKind > 8 ||
		snapshot.Ref.ID == "" || snapshot.MessageTypeID == 0 || len(snapshot.CanonicalPayload) == 0 ||
		snapshot.StateVersion == 0 || snapshot.WriterEpoch == 0 || snapshot.ImmutableBindingDigest == ([32]byte{}) {
		return IdentitySnapshot{}, ErrViewInconsistent
	}
	validator, err := foundationCanonicalValidator()
	if err != nil {
		return IdentitySnapshot{}, err
	}
	decoded, err := validator.Decode(snapshot.MessageTypeID, ccse.Version{Major: 1}, snapshot.CanonicalPayload)
	if err != nil {
		return IdentitySnapshot{}, fmt.Errorf("%w: decode identity payload: %v", ErrViewInconsistent, err)
	}
	derived, err := NormalizeIdentity(decoded)
	if err != nil || !reflect.DeepEqual(snapshot, derived) {
		return IdentitySnapshot{}, ErrViewInconsistent
	}
	return derived, nil
}

func terminalIdentityState(state uint32) bool { return state == 4 || state == 5 || state == 6 }

func sameEntityRef(left, right EntityRef) bool {
	return left.Kind == right.Kind && left.PrincipalKind == right.PrincipalKind && left.ID == right.ID
}

func checkedNextVersion(current, proposed uint64) error {
	if current == ^uint64(0) || proposed != current+1 {
		return ErrStateVersionConflict
	}
	return nil
}
