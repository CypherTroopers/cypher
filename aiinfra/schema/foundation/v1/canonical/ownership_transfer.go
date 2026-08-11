// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package canonical

import (
	"github.com/cypherium/cypher/aiinfra/ccse"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

func decodeOwnershipTransferAuthorization(v *Validator, in *ccse.Decoder, rules projectionRules) (Payload, error) {
	decoder := newProjectionDecoder(in, rules)
	metadata, _ := decodeMetadataField(v, decoder)
	value := foundationv1.OwnershipTransferAuthorizationSigningProjection{
		Metadata:                  metadata,
		TransferAuthorizationID:   decoder.String(2, "transfer_authorization_id"),
		SubjectKind:               decoder.Enum(3, "subject_kind", 2, 4),
		PreviousEntityID:          decoder.String(4, "previous_entity_id"),
		NextEntityID:              decoder.String(5, "next_entity_id"),
		PreviousPrincipalIdentity: decoder.String(6, "previous_principal_identity"),
		NextPrincipalIdentity:     decoder.String(7, "next_principal_identity"),
		PreviousProviderID:        decoder.String(8, "previous_provider_id"),
		NextProviderID:            decoder.String(9, "next_provider_id"),
		ExpectedGeneration:        decoder.Uint64(10, "expected_generation"),
		NextGeneration:            decoder.Uint64(11, "next_generation"),
		PreviousTerminalIdentityPayloadDigestSHA256: decoder.Fixed32(12, "previous_terminal_identity_payload_digest_sha256"),
		NextPendingIdentityPayloadDigestSHA256:      decoder.Fixed32(13, "next_pending_identity_payload_digest_sha256"),
		OldKeyClosures:                              decodeKeyClosureSet(v, decoder, 14, "old_key_closures"),
		NewKeyID:                                    decoder.String(15, "new_key_id"),
		EvidenceCommitments:                         decodeTransferEvidenceSet(v, decoder, 16, "evidence_commitments"),
		EffectiveAtUnixNano:                         decoder.Int64(17, "effective_at_unix_nano"),
		ExpiresAtUnixNano:                           decoder.Int64(18, "expires_at_unix_nano"),
		OldAuthorities:                              decodeTransferAuthoritySet(v, decoder, 19, "old_authorities"),
		NewAuthorities:                              decodeTransferAuthoritySet(v, decoder, 20, "new_authorities"),
	}
	if err := decoder.FinishFields(); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeKeyClosure(in *ccse.Decoder, rules projectionRules) (foundationv1.KeyClosureSigningProjection, error) {
	decoder := newProjectionDecoder(in, rules)
	value := foundationv1.KeyClosureSigningProjection{
		KeyID:                                   decoder.String(1, "key_id"),
		TerminalKeyLifecyclePayloadDigestSHA256: decoder.Fixed32(2, "terminal_key_lifecycle_payload_digest_sha256"),
	}
	if err := decoder.FinishFields(); err != nil {
		return foundationv1.KeyClosureSigningProjection{}, err
	}
	_, err := value.CanonicalBytes()
	return value, err
}

func decodeTransferEvidence(in *ccse.Decoder, rules projectionRules) (foundationv1.TransferEvidenceCommitmentSigningProjection, error) {
	decoder := newProjectionDecoder(in, rules)
	value := foundationv1.TransferEvidenceCommitmentSigningProjection{
		EvidenceKind:           decoder.Enum(1, "evidence_kind", 1, 7),
		CCSERecordDigestSHA256: decoder.Fixed32(2, "ccse_record_digest_sha256"),
	}
	if err := decoder.FinishFields(); err != nil {
		return foundationv1.TransferEvidenceCommitmentSigningProjection{}, err
	}
	_, err := value.CanonicalBytes()
	return value, err
}

func decodeTransferAuthority(in *ccse.Decoder, rules projectionRules) (foundationv1.TransferAuthoritySigningProjection, error) {
	decoder := newProjectionDecoder(in, rules)
	value := foundationv1.TransferAuthoritySigningProjection{
		Identity: decoder.String(1, "identity"),
		KeyID:    decoder.String(2, "key_id"),
	}
	if err := decoder.FinishFields(); err != nil {
		return foundationv1.TransferAuthoritySigningProjection{}, err
	}
	_, err := value.CanonicalBytes()
	return value, err
}

func decodeKeyClosureSet(v *Validator, decoder *projectionDecoder, order int, name string) []foundationv1.KeyClosureSigningProjection {
	field, ok := decoder.MessageSet(order, name, keyClosureType)
	if !ok {
		return nil
	}
	values := make([]foundationv1.KeyClosureSigningProjection, 0)
	elements := make([][]byte, 0)
	err := decoder.in.ValidatedSet(field.MaxItems, v.nested.keyClosure.limits.MaxPayloadBytes, func(_ int, child *ccse.Decoder) error {
		value, err := decodeKeyClosure(child, v.nested.keyClosure)
		if err != nil {
			return err
		}
		encoded, err := value.CanonicalBytes()
		if err != nil {
			return err
		}
		values = append(values, value)
		elements = append(elements, encoded)
		return nil
	})
	if err == nil {
		err = enforceMessageSetBound(field, elements)
	}
	decoder.record(err)
	if err != nil {
		return nil
	}
	return values
}

func decodeTransferEvidenceSet(v *Validator, decoder *projectionDecoder, order int, name string) []foundationv1.TransferEvidenceCommitmentSigningProjection {
	field, ok := decoder.MessageSet(order, name, transferEvidenceType)
	if !ok {
		return nil
	}
	values := make([]foundationv1.TransferEvidenceCommitmentSigningProjection, 0)
	elements := make([][]byte, 0)
	err := decoder.in.ValidatedSet(field.MaxItems, v.nested.transferEvidence.limits.MaxPayloadBytes, func(_ int, child *ccse.Decoder) error {
		value, err := decodeTransferEvidence(child, v.nested.transferEvidence)
		if err != nil {
			return err
		}
		encoded, err := value.CanonicalBytes()
		if err != nil {
			return err
		}
		values = append(values, value)
		elements = append(elements, encoded)
		return nil
	})
	if err == nil {
		err = enforceMessageSetBound(field, elements)
	}
	decoder.record(err)
	if err != nil {
		return nil
	}
	return values
}

func decodeTransferAuthoritySet(v *Validator, decoder *projectionDecoder, order int, name string) []foundationv1.TransferAuthoritySigningProjection {
	field, ok := decoder.MessageSet(order, name, transferAuthorityType)
	if !ok {
		return nil
	}
	values := make([]foundationv1.TransferAuthoritySigningProjection, 0)
	elements := make([][]byte, 0)
	err := decoder.in.ValidatedSet(field.MaxItems, v.nested.transferAuthority.limits.MaxPayloadBytes, func(_ int, child *ccse.Decoder) error {
		value, err := decodeTransferAuthority(child, v.nested.transferAuthority)
		if err != nil {
			return err
		}
		encoded, err := value.CanonicalBytes()
		if err != nil {
			return err
		}
		values = append(values, value)
		elements = append(elements, encoded)
		return nil
	})
	if err == nil {
		err = enforceMessageSetBound(field, elements)
	}
	decoder.record(err)
	if err != nil {
		return nil
	}
	return values
}
