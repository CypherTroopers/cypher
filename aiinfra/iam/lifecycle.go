// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"reflect"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

const keyLifecycleBindingDomain = "CPH-AIIE-KEY-LIFECYCLE-BINDING-V1\x00"

// NormalizeKeyLifecycle validates and detaches a v1 KeyLifecycle projection.
func NormalizeKeyLifecycle(projection any) (KeyLifecycleSnapshot, error) {
	var value foundationv1.KeyLifecycleSigningProjection
	switch candidate := projection.(type) {
	case foundationv1.KeyLifecycleSigningProjection:
		value = candidate
	case *foundationv1.KeyLifecycleSigningProjection:
		if candidate == nil {
			return KeyLifecycleSnapshot{}, ErrInvalidInput
		}
		value = *candidate
	default:
		return KeyLifecycleSnapshot{}, fmt.Errorf("%w: unsupported lifecycle projection %T", ErrInvalidInput, projection)
	}
	canonical, err := value.CanonicalBytes()
	if err != nil {
		return KeyLifecycleSnapshot{}, err
	}
	if value.Metadata.SchemaVersion.Major != 1 || value.Metadata.SchemaVersion.Minor != 0 {
		return KeyLifecycleSnapshot{}, fmt.Errorf("%w: lifecycle schema version must be 1.0", ErrInvalidInput)
	}
	// Foundation v1 reserves principal kind 9 for HumanUser, but there is no
	// authoritative HumanUser identity projection/View path in WS0.2a. A key
	// admitted for that kind could never become safely ACTIVE, so the semantic
	// kernel rejects it until the missing identity contract is versioned.
	if value.SubjectKind < 1 || value.SubjectKind > 8 {
		return KeyLifecycleSnapshot{}, ErrInvalidInput
	}
	allowed := append([]uint32(nil), value.AllowedMessageTypeIDs...)
	sort.Slice(allowed, func(i, j int) bool { return allowed[i] < allowed[j] })
	policies := cloneDigests(value.Metadata.PolicyDigestsSHA256)
	sort.Slice(policies, func(i, j int) bool { return bytes.Compare(policies[i][:], policies[j][:]) < 0 })
	elements := make([][]byte, len(allowed))
	for i := range allowed {
		elements[i], err = ccse.Marshal(4, func(item *ccse.Encoder) { item.Uint32(allowed[i]) })
		if err != nil {
			return KeyLifecycleSnapshot{}, err
		}
	}
	immutable, err := ccse.Marshal(32768, func(out *ccse.Encoder) {
		out.String(value.KeyID)
		out.String(value.SubjectIdentity)
		out.Uint32(value.SubjectKind)
		out.Uint32(value.Algorithm)
		out.Int64(value.NotBeforeUnixNano)
		out.Int64(value.NotAfterUnixNano)
		out.OptionalString(value.RotationPredecessorKeyID.Present, value.RotationPredecessorKeyID.Value)
		out.EncodedSet(elements)
		out.FixedBytes(value.AuthorizationPolicyDigestSHA256[:], 32)
	})
	if err != nil {
		return KeyLifecycleSnapshot{}, err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(keyLifecycleBindingDomain))
	_, _ = hash.Write(immutable)
	var binding [32]byte
	copy(binding[:], hash.Sum(nil))
	return KeyLifecycleSnapshot{
		KeyID: value.KeyID, RecordID: value.Metadata.RecordID,
		CreatedAtUnixNano: value.Metadata.CreatedAtUnixNano,
		SubjectIdentity:   value.SubjectIdentity, SubjectKind: value.SubjectKind,
		Algorithm: ccse.SignatureAlgorithmID(value.Algorithm), State: value.State,
		NotBeforeUnixNano: value.NotBeforeUnixNano, NotAfterUnixNano: value.NotAfterUnixNano,
		RevokedAtUnixNano: value.RevokedAtUnixNano.Value, HasRevokedAt: value.RevokedAtUnixNano.Present,
		RotationPredecessorKeyID:        value.RotationPredecessorKeyID.Value,
		HasRotationPredecessor:          value.RotationPredecessorKeyID.Present,
		AllowedMessageTypeIDs:           allowed,
		AuthorizationPolicyDigestSHA256: value.AuthorizationPolicyDigestSHA256,
		TransitionReasonCode:            value.TransitionReasonCode.Value,
		HasTransitionReason:             value.TransitionReasonCode.Present,
		HomeRegion:                      value.Metadata.HomeRegion, WriterEpoch: value.Metadata.WriterEpoch,
		StateVersion: value.Metadata.StateVersion, IdempotencyKey: value.Metadata.IdempotencyKey,
		PolicyDigestsSHA256:   policies,
		IntegrityDigestSHA256: value.Metadata.IntegrityDigest,
		CanonicalPayload:      append([]byte(nil), canonical...), ImmutableBindingDigest: binding,
	}, nil
}

func normalizeViewLifecycle(snapshot KeyLifecycleSnapshot) (KeyLifecycleSnapshot, error) {
	if len(snapshot.CanonicalPayload) > 32768 || len(snapshot.PolicyDigestsSHA256) > 64 || len(snapshot.AllowedMessageTypeIDs) > 256 {
		return KeyLifecycleSnapshot{}, ErrViewInconsistent
	}
	snapshot = cloneLifecycle(snapshot)
	if snapshot.KeyID == "" || snapshot.SubjectIdentity == "" || snapshot.SubjectKind < 1 || snapshot.SubjectKind > 8 ||
		snapshot.State < 1 || snapshot.State > 5 || snapshot.StateVersion == 0 || snapshot.WriterEpoch == 0 ||
		len(snapshot.CanonicalPayload) == 0 || len(snapshot.AllowedMessageTypeIDs) == 0 || snapshot.ImmutableBindingDigest == ([32]byte{}) {
		return KeyLifecycleSnapshot{}, ErrViewInconsistent
	}
	validator, err := foundationCanonicalValidator()
	if err != nil {
		return KeyLifecycleSnapshot{}, err
	}
	decoded, err := validator.Decode(schema.MessageTypeKeyLifecycle, ccse.Version{Major: 1}, snapshot.CanonicalPayload)
	if err != nil {
		return KeyLifecycleSnapshot{}, fmt.Errorf("%w: decode lifecycle payload: %v", ErrViewInconsistent, err)
	}
	derived, err := NormalizeKeyLifecycle(decoded)
	if err != nil || !reflect.DeepEqual(snapshot, derived) {
		return KeyLifecycleSnapshot{}, ErrViewInconsistent
	}
	return derived, nil
}

func terminalLifecycleState(state uint32) bool { return state == 4 || state == 5 }

func validateLifecycleTransition(previous, next KeyLifecycleSnapshot, at int64) error {
	if terminalLifecycleState(previous.State) {
		return ErrTerminalLifecycle
	}
	valid := (previous.State == 1 && next.State == 2) ||
		(previous.State == 2 && next.State == 3) ||
		((previous.State == 1 || previous.State == 2 || previous.State == 3) && next.State == 5) ||
		((previous.State == 1 || previous.State == 2 || previous.State == 3) && next.State == 4)
	if !valid {
		return fmt.Errorf("%w: %d -> %d", ErrInvalidTransition, previous.State, next.State)
	}
	if next.State == 2 && (at < next.NotBeforeUnixNano || at >= next.NotAfterUnixNano) {
		return fmt.Errorf("%w: activation outside key lifetime", ErrInvalidTransition)
	}
	if next.State == 3 && (at < next.NotBeforeUnixNano || at >= next.NotAfterUnixNano) {
		return fmt.Errorf("%w: retirement outside key lifetime", ErrInvalidTransition)
	}
	if next.State == 5 && at < next.NotAfterUnixNano {
		return fmt.Errorf("%w: expiry before not_after", ErrInvalidTransition)
	}
	if next.State == 4 {
		if !next.HasRevokedAt || next.RevokedAtUnixNano != at {
			return fmt.Errorf("%w: revocation time must equal transition time", ErrInvalidTransition)
		}
	} else if next.HasRevokedAt {
		return fmt.Errorf("%w: non-revoked lifecycle carries revocation time", ErrInvalidTransition)
	}
	return nil
}
