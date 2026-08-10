// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package canonical

import (
	"github.com/cypherium/cypher/aiinfra/ccse"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

func decodeProviderIdentity(v *Validator, in *ccse.Decoder, rules projectionRules) (Payload, error) {
	decoder := newProjectionDecoder(in, rules)
	metadata, _ := decodeMetadataField(v, decoder)
	value := foundationv1.ProviderIdentitySigningProjection{
		Metadata:             metadata,
		ProviderID:           decoder.String(2, "provider_id"),
		OrganizationIdentity: decoder.String(3, "organization_identity_uri"),
		PayoutIdentity:       decoder.String(4, "payout_identity"),
		Jurisdictions:        decoder.StringSet(5, "jurisdictions"),
		PolicyDigestsSHA256:  decoder.Fixed32Set(6, "policy_digests_sha256"),
		StakeReference:       decoder.OptionalString(7, "stake_reference"),
		OwnershipGeneration:  decoder.Uint64(8, "ownership_generation"),
		ValidFromUnixNano:    decoder.Int64(9, "valid_from_unix_nano"),
		ValidUntilUnixNano:   decoder.Int64(10, "valid_until_unix_nano"),
		State:                decoder.Enum(11, "state", 1, 6),
	}
	if err := decoder.FinishFields(); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeAgentIdentity(v *Validator, in *ccse.Decoder, rules projectionRules) (Payload, error) {
	decoder := newProjectionDecoder(in, rules)
	metadata, _ := decodeMetadataField(v, decoder)
	value := foundationv1.AgentIdentitySigningProjection{
		Metadata:            metadata,
		AgentID:             decoder.String(2, "agent_id"),
		ProviderID:          decoder.String(3, "provider_id"),
		HostID:              decoder.String(4, "host_id"),
		SPIFFEID:            decoder.String(5, "spiffe_id"),
		KeyID:               decoder.String(6, "key_id"),
		OwnershipGeneration: decoder.Uint64(7, "ownership_generation"),
		ValidFromUnixNano:   decoder.Int64(8, "valid_from_unix_nano"),
		ValidUntilUnixNano:  decoder.Int64(9, "valid_until_unix_nano"),
		State:               decoder.Enum(10, "state", 1, 6),
	}
	if err := decoder.FinishFields(); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeHostIdentity(v *Validator, in *ccse.Decoder, rules projectionRules) (Payload, error) {
	decoder := newProjectionDecoder(in, rules)
	metadata, _ := decodeMetadataField(v, decoder)
	value := foundationv1.HostIdentitySigningProjection{
		Metadata:            metadata,
		HostID:              decoder.String(2, "host_id"),
		ProviderID:          decoder.String(3, "provider_id"),
		ProviderSiteID:      decoder.String(4, "provider_site_id"),
		AttestationIdentity: decoder.String(5, "attestation_identity"),
		KeyID:               decoder.String(6, "key_id"),
		OwnershipGeneration: decoder.Uint64(7, "ownership_generation"),
		ValidFromUnixNano:   decoder.Int64(8, "valid_from_unix_nano"),
		ValidUntilUnixNano:  decoder.Int64(9, "valid_until_unix_nano"),
		State:               decoder.Enum(10, "state", 1, 6),
	}
	if err := decoder.FinishFields(); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeDeviceIdentity(v *Validator, in *ccse.Decoder, rules projectionRules) (Payload, error) {
	decoder := newProjectionDecoder(in, rules)
	metadata, _ := decodeMetadataField(v, decoder)
	value := foundationv1.DeviceIdentitySigningProjection{
		Metadata:                 metadata,
		DeviceID:                 decoder.String(2, "device_id"),
		ProviderID:               decoder.String(3, "provider_id"),
		HostID:                   decoder.String(4, "host_id"),
		VendorSerialDigestSHA256: decoder.Fixed32(5, "vendor_serial_digest_sha256"),
		AttestationIdentity:      decoder.String(6, "attestation_identity"),
		KeyID:                    decoder.String(7, "key_id"),
		OwnershipGeneration:      decoder.Uint64(8, "ownership_generation"),
		ValidFromUnixNano:        decoder.Int64(9, "valid_from_unix_nano"),
		ValidUntilUnixNano:       decoder.Int64(10, "valid_until_unix_nano"),
		State:                    decoder.Enum(11, "state", 1, 6),
	}
	if err := decoder.FinishFields(); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeMinerIdentity(v *Validator, in *ccse.Decoder, rules projectionRules) (Payload, error) {
	decoder := newProjectionDecoder(in, rules)
	metadata, _ := decodeMetadataField(v, decoder)
	value := foundationv1.MinerIdentitySigningProjection{
		Metadata:           metadata,
		MinerID:            decoder.String(2, "miner_id"),
		ProviderID:         decoder.String(3, "provider_id"),
		AgentID:            decoder.String(4, "agent_id"),
		DeviceIDs:          decoder.StringSet(5, "device_ids"),
		PayoutIdentity:     decoder.String(6, "payout_identity"),
		KeyID:              decoder.String(7, "key_id"),
		BindingGeneration:  decoder.Uint64(8, "binding_generation"),
		ValidFromUnixNano:  decoder.Int64(9, "valid_from_unix_nano"),
		ValidUntilUnixNano: decoder.Int64(10, "valid_until_unix_nano"),
		State:              decoder.Enum(11, "state", 1, 6),
	}
	if err := decoder.FinishFields(); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeRunnerIdentity(v *Validator, in *ccse.Decoder, rules projectionRules) (Payload, error) {
	decoder := newProjectionDecoder(in, rules)
	metadata, _ := decodeMetadataField(v, decoder)
	value := foundationv1.RunnerIdentitySigningProjection{
		Metadata:           metadata,
		RunnerAttemptID:    decoder.String(2, "runner_attempt_id"),
		ProviderID:         decoder.String(3, "provider_id"),
		AgentID:            decoder.String(4, "agent_id"),
		LeaseID:            decoder.String(5, "lease_id"),
		JobID:              decoder.String(6, "job_id"),
		AttemptID:          decoder.String(7, "attempt_id"),
		WorkloadIdentity:   decoder.String(8, "workload_identity"),
		KeyID:              decoder.String(9, "key_id"),
		ValidFromUnixNano:  decoder.Int64(10, "valid_from_unix_nano"),
		ValidUntilUnixNano: decoder.Int64(11, "valid_until_unix_nano"),
		State:              decoder.Enum(12, "state", 1, 6),
	}
	if err := decoder.FinishFields(); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeBuyerIdentity(v *Validator, in *ccse.Decoder, rules projectionRules) (Payload, error) {
	decoder := newProjectionDecoder(in, rules)
	metadata, _ := decodeMetadataField(v, decoder)
	value := foundationv1.BuyerIdentitySigningProjection{
		Metadata:                metadata,
		BuyerID:                 decoder.String(2, "buyer_id"),
		OrganizationIdentityURI: decoder.String(3, "organization_identity_uri"),
		BillingIdentity:         decoder.String(4, "billing_identity"),
		KeyID:                   decoder.String(5, "key_id"),
		AuthorizationGeneration: decoder.Uint64(6, "authorization_generation"),
		ValidFromUnixNano:       decoder.Int64(7, "valid_from_unix_nano"),
		ValidUntilUnixNano:      decoder.Int64(8, "valid_until_unix_nano"),
		State:                   decoder.Enum(9, "state", 1, 6),
	}
	if err := decoder.FinishFields(); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeServiceIdentity(v *Validator, in *ccse.Decoder, rules projectionRules) (Payload, error) {
	decoder := newProjectionDecoder(in, rules)
	metadata, _ := decodeMetadataField(v, decoder)
	value := foundationv1.ServiceIdentitySigningProjection{
		Metadata:              metadata,
		ServiceID:             decoder.String(2, "service_id"),
		ServiceName:           decoder.String(3, "service_name"),
		SPIFFEID:              decoder.String(4, "spiffe_id"),
		DeploymentEnvironment: decoder.String(5, "deployment_environment"),
		KeyID:                 decoder.String(6, "key_id"),
		CredentialGeneration:  decoder.Uint64(7, "credential_generation"),
		ValidFromUnixNano:     decoder.Int64(8, "valid_from_unix_nano"),
		ValidUntilUnixNano:    decoder.Int64(9, "valid_until_unix_nano"),
		State:                 decoder.Enum(10, "state", 1, 6),
	}
	if err := decoder.FinishFields(); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeKeyLifecycle(v *Validator, in *ccse.Decoder, rules projectionRules) (Payload, error) {
	decoder := newProjectionDecoder(in, rules)
	metadata, _ := decodeMetadataField(v, decoder)
	value := foundationv1.KeyLifecycleSigningProjection{
		Metadata:                        metadata,
		KeyID:                           decoder.String(2, "key_id"),
		SubjectIdentity:                 decoder.String(3, "subject_identity"),
		SubjectKind:                     decoder.Enum(4, "subject_kind", 1, 9),
		Algorithm:                       decoder.Enum(5, "algorithm", 1, 3),
		State:                           decoder.Enum(6, "state", 1, 5),
		NotBeforeUnixNano:               decoder.Int64(7, "not_before_unix_nano"),
		NotAfterUnixNano:                decoder.Int64(8, "not_after_unix_nano"),
		RevokedAtUnixNano:               decoder.OptionalInt64(9, "revoked_at_unix_nano"),
		RotationPredecessorKeyID:        decoder.OptionalString(10, "rotation_predecessor_key_id"),
		AllowedMessageTypeIDs:           decoder.Uint32Set(11, "allowed_message_type_ids"),
		AuthorizationPolicyDigestSHA256: decoder.Fixed32(12, "authorization_policy_digest_sha256"),
		TransitionReasonCode:            decoder.OptionalString(13, "transition_reason_code"),
	}
	if err := decoder.FinishFields(); err != nil {
		return nil, err
	}
	return value, nil
}
