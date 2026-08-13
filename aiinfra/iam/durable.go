// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

const (
	durablePendingCodec                = "cph.aiinfra.iam.pending.v1"
	durablePendingCodecVersion         = uint32(1)
	durablePendingMaxBytes             = 64 << 20
	durablePendingEnvelopeDigestDomain = "CPH-AIIE-IAM-DURABLE-PENDING-ENVELOPE-V1\x00"
	durablePendingMaxJSONDepth         = 64
	// A maximum transfer acceptance embeds the immutable 256-closure evidence
	// once in the accepted snapshot and once in its staged cutover. Its bounded
	// canonical JSON is about 4 MiB but legitimately exceeds 512K scalar tokens.
	durablePendingMaxJSONTokens      = 2 << 20
	durablePendingMaxContainerTokens = 2048
)

// DurablePendingKind is a closed discriminator for the versioned durable
// pending codec. No decoded value is commit-ready.
type DurablePendingKind uint8

const (
	DurablePendingMutation DurablePendingKind = iota + 1
	DurablePendingKeyEnrollment
	DurablePendingOwnershipTransferCollection
	DurablePendingReconciliation
	DurablePendingOwnershipTransferCutover
	DurablePendingOwnershipTransferAcceptance
)

// DurablePendingEnvelope is an opaque, alias-safe, verified durable snapshot.
// It can only be created from a plan whose digest verifies, or by decoding
// canonical bytes and re-verifying every nested plan/evidence digest.
type DurablePendingEnvelope struct {
	kind    DurablePendingKind
	encoded []byte
	digest  [32]byte
	// capability is set only when this process constructs the envelope from a
	// Planner-verified plan. A public decode proves canonical integrity, not
	// semantic provenance, and therefore never grants joined-audit authority.
	capability     bool
	mutation       *PendingMutationPlan
	enrollment     *PendingKeyEnrollmentPlan
	transfer       *OwnershipTransferApprovalCollectionPlan
	reconciliation *PendingReconciliationPlan
	cutover        *PendingOwnershipTransferCutoverPlan
	acceptance     *PendingOwnershipTransferAcceptancePlan
}

// DecodedDurablePendingEnvelope is inert untrusted storage data. Canonical
// decoding proves only byte integrity; it does not prove that a Planner ever
// authorized the embedded CAS or AuditIntent. Consequently this type exposes
// no nested plan getter and cannot create a JoinedAuditRequest. A caller must
// pass it through Planner.RevalidateDurablePending before it becomes a
// capability-bearing DurablePendingEnvelope.
type DecodedDurablePendingEnvelope struct {
	kind       DurablePendingKind
	encoded    []byte
	digest     [32]byte
	collection *OwnershipTransferApprovalCollectionSnapshot
}

func (envelope DecodedDurablePendingEnvelope) Kind() DurablePendingKind { return envelope.kind }
func (envelope DecodedDurablePendingEnvelope) CodecVersion() uint32 {
	return durablePendingCodecVersion
}
func (envelope DecodedDurablePendingEnvelope) Bytes() []byte {
	return append([]byte(nil), envelope.encoded...)
}
func (envelope DecodedDurablePendingEnvelope) Digest() [32]byte { return envelope.digest }

// OwnershipTransferApprovalCollection exposes only the detached inert next
// snapshot restored from a strict kind-3 envelope. It does not expose the
// private plan or confer any execution capability.
func (envelope DecodedDurablePendingEnvelope) OwnershipTransferApprovalCollection() (
	OwnershipTransferApprovalCollectionSnapshot, bool) {
	if envelope.kind != DurablePendingOwnershipTransferCollection || envelope.collection == nil {
		return OwnershipTransferApprovalCollectionSnapshot{}, false
	}
	return cloneTransferCollection(*envelope.collection), true
}

func (envelope DurablePendingEnvelope) Kind() DurablePendingKind { return envelope.kind }
func (envelope DurablePendingEnvelope) Bytes() []byte {
	return append([]byte(nil), envelope.encoded...)
}
func (envelope DurablePendingEnvelope) Digest() [32]byte  { return envelope.digest }
func (envelope DurablePendingEnvelope) CommitReady() bool { return false }

func (envelope DurablePendingEnvelope) PendingDigest() [32]byte {
	switch envelope.kind {
	case DurablePendingMutation:
		return envelope.mutation.Digest()
	case DurablePendingKeyEnrollment:
		return envelope.enrollment.Digest()
	case DurablePendingOwnershipTransferCollection:
		return envelope.transfer.Digest()
	case DurablePendingReconciliation:
		return envelope.reconciliation.Digest()
	case DurablePendingOwnershipTransferCutover:
		return envelope.cutover.Digest()
	case DurablePendingOwnershipTransferAcceptance:
		return envelope.acceptance.Digest()
	default:
		return [32]byte{}
	}
}

func (envelope DurablePendingEnvelope) PendingMutationPlan() (PendingMutationPlan, bool) {
	if !envelope.capability || envelope.kind != DurablePendingMutation || envelope.mutation == nil {
		return PendingMutationPlan{}, false
	}
	return *envelope.mutation, true
}

func (envelope DurablePendingEnvelope) PendingKeyEnrollmentPlan() (PendingKeyEnrollmentPlan, bool) {
	if !envelope.capability || envelope.kind != DurablePendingKeyEnrollment || envelope.enrollment == nil {
		return PendingKeyEnrollmentPlan{}, false
	}
	return *envelope.enrollment, true
}

func (envelope DurablePendingEnvelope) OwnershipTransferCollectionPlan() (OwnershipTransferApprovalCollectionPlan, bool) {
	if !envelope.capability || envelope.kind != DurablePendingOwnershipTransferCollection || envelope.transfer == nil {
		return OwnershipTransferApprovalCollectionPlan{}, false
	}
	return *envelope.transfer, true
}

func (envelope DurablePendingEnvelope) PendingReconciliationPlan() (PendingReconciliationPlan, bool) {
	if !envelope.capability || envelope.kind != DurablePendingReconciliation || envelope.reconciliation == nil {
		return PendingReconciliationPlan{}, false
	}
	return *envelope.reconciliation, true
}

func (envelope DurablePendingEnvelope) PendingOwnershipTransferCutoverPlan() (
	PendingOwnershipTransferCutoverPlan, bool) {
	if !envelope.capability || envelope.kind != DurablePendingOwnershipTransferCutover ||
		envelope.cutover == nil {
		return PendingOwnershipTransferCutoverPlan{}, false
	}
	return clonePendingOwnershipTransferCutoverPlan(*envelope.cutover), true
}

func (envelope DurablePendingEnvelope) PendingOwnershipTransferAcceptancePlan() (
	PendingOwnershipTransferAcceptancePlan, bool) {
	if !envelope.capability || envelope.kind != DurablePendingOwnershipTransferAcceptance ||
		envelope.acceptance == nil {
		return PendingOwnershipTransferAcceptancePlan{}, false
	}
	return clonePendingOwnershipTransferAcceptancePlan(*envelope.acceptance), true
}

func (envelope DurablePendingEnvelope) VerifyDigest() error {
	wire, err := envelope.toWire()
	if err != nil {
		return err
	}
	encoded, err := marshalDurableWire(wire)
	if err != nil || !bytes.Equal(encoded, envelope.encoded) ||
		domainDigest(durablePendingEnvelopeDigestDomain, encoded) != envelope.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

func (plan PendingMutationPlan) DurableEnvelope() (DurablePendingEnvelope, error) {
	if err := plan.VerifyDigest(); err != nil {
		return DurablePendingEnvelope{}, err
	}
	copy := plan
	return newDurableEnvelope(durableEnvelopeWire{Codec: durablePendingCodec,
		Version: durablePendingCodecVersion, Kind: DurablePendingMutation,
		Mutation: pendingMutationToWire(plan)}, &copy, nil, nil, nil, nil, nil)
}

func (plan PendingKeyEnrollmentPlan) DurableEnvelope() (DurablePendingEnvelope, error) {
	if err := plan.VerifyDigest(); err != nil {
		return DurablePendingEnvelope{}, err
	}
	copy := plan
	return newDurableEnvelope(durableEnvelopeWire{Codec: durablePendingCodec,
		Version: durablePendingCodecVersion, Kind: DurablePendingKeyEnrollment,
		Enrollment: pendingEnrollmentToWire(plan)}, nil, &copy, nil, nil, nil, nil)
}

func (plan OwnershipTransferApprovalCollectionPlan) DurableEnvelope() (DurablePendingEnvelope, error) {
	if err := plan.VerifyDigest(); err != nil {
		return DurablePendingEnvelope{}, err
	}
	copy := plan
	return newDurableEnvelope(durableEnvelopeWire{Codec: durablePendingCodec,
		Version: durablePendingCodecVersion, Kind: DurablePendingOwnershipTransferCollection,
		Transfer: transferPlanToWire(plan)}, nil, nil, &copy, nil, nil, nil)
}

func (plan PendingReconciliationPlan) DurableEnvelope() (DurablePendingEnvelope, error) {
	if err := plan.VerifyDigest(); err != nil {
		return DurablePendingEnvelope{}, err
	}
	copy := plan
	return newDurableEnvelope(durableEnvelopeWire{Codec: durablePendingCodec,
		Version: durablePendingCodecVersion, Kind: DurablePendingReconciliation,
		Reconciliation: reconciliationToWire(plan)}, nil, nil, nil, &copy, nil, nil)
}

func (plan PendingOwnershipTransferCutoverPlan) DurableEnvelope() (DurablePendingEnvelope, error) {
	_ = plan
	// The nested cutover pending value is persisted only through the atomic
	// acceptance envelope. Exposing a standalone envelope here would permit a
	// second admission after the acceptance transaction reserved X/Y, member
	// aliases and identifiers.
	return DurablePendingEnvelope{}, ErrTransferAuthorizationRequired
}

func durableEnvelopeForAcceptedCutover(plan PendingOwnershipTransferCutoverPlan) (
	DurablePendingEnvelope, error) {
	if err := plan.VerifyDigest(); err != nil {
		return DurablePendingEnvelope{}, err
	}
	copy := clonePendingOwnershipTransferCutoverPlan(plan)
	return newDurableEnvelope(durableEnvelopeWire{Codec: durablePendingCodec,
		Version: durablePendingCodecVersion, Kind: DurablePendingOwnershipTransferCutover,
		Cutover: cutoverPlanToWire(plan)}, nil, nil, nil, nil, &copy, nil)
}

func (plan PendingOwnershipTransferAcceptancePlan) DurableEnvelope() (DurablePendingEnvelope, error) {
	if err := plan.VerifyDigest(); err != nil {
		return DurablePendingEnvelope{}, err
	}
	copy := clonePendingOwnershipTransferAcceptancePlan(plan)
	return newDurableEnvelope(durableEnvelopeWire{Codec: durablePendingCodec,
		Version: durablePendingCodecVersion, Kind: DurablePendingOwnershipTransferAcceptance,
		Acceptance: acceptancePlanToWire(plan)}, nil, nil, nil, nil, nil, &copy)
}

func newDurableEnvelope(wire durableEnvelopeWire, mutation *PendingMutationPlan,
	enrollment *PendingKeyEnrollmentPlan, transfer *OwnershipTransferApprovalCollectionPlan,
	reconciliation *PendingReconciliationPlan, cutover *PendingOwnershipTransferCutoverPlan,
	acceptance *PendingOwnershipTransferAcceptancePlan) (
	DurablePendingEnvelope, error) {
	encoded, err := marshalDurableWire(wire)
	if err != nil {
		return DurablePendingEnvelope{}, fmt.Errorf("%w: encode durable envelope: %v", ErrPendingPlanInvalid, err)
	}
	envelope := DurablePendingEnvelope{kind: wire.Kind, encoded: encoded,
		digest: domainDigest(durablePendingEnvelopeDigestDomain, encoded), capability: true, mutation: mutation,
		enrollment: enrollment, transfer: transfer, reconciliation: reconciliation, cutover: cutover,
		acceptance: acceptance}
	if err := envelope.VerifyDigest(); err != nil {
		return DurablePendingEnvelope{}, fmt.Errorf("%w: verify durable envelope: %v", ErrPendingPlanInvalid, err)
	}
	return envelope, nil
}

// DecodeDurablePendingEnvelope performs a bounded one-copy JSON decode,
// rejects unknown/noncanonical bytes, reconstructs all private plan fields and
// signatures, and then verifies every nested digest.
func DecodeDurablePendingEnvelope(input []byte) (DecodedDurablePendingEnvelope, error) {
	envelope, err := decodeDurablePendingEnvelope(input)
	if err != nil {
		return DecodedDurablePendingEnvelope{}, err
	}
	result := DecodedDurablePendingEnvelope{kind: envelope.kind, encoded: envelope.encoded, digest: envelope.digest}
	if envelope.transfer != nil {
		value := envelope.transfer.NextCollection()
		result.collection = &value
	}
	return result, nil
}

func decodeDurablePendingEnvelope(input []byte) (DurablePendingEnvelope, error) {
	if len(input) == 0 || len(input) > durablePendingMaxBytes {
		return DurablePendingEnvelope{}, ErrPendingPlanInvalid
	}
	owned := append([]byte(nil), input...)
	if err := preflightDurableJSON(owned); err != nil {
		return DurablePendingEnvelope{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(owned))
	decoder.DisallowUnknownFields()
	var wire durableEnvelopeWire
	if err := decoder.Decode(&wire); err != nil {
		return DurablePendingEnvelope{}, ErrPendingPlanInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return DurablePendingEnvelope{}, ErrPendingPlanInvalid
	}
	if wire.Codec != durablePendingCodec || wire.Version != durablePendingCodecVersion {
		return DurablePendingEnvelope{}, ErrPendingPlanInvalid
	}
	canonical, err := marshalDurableWire(wire)
	if err != nil || !bytes.Equal(canonical, owned) {
		return DurablePendingEnvelope{}, ErrPendingPlanInvalid
	}
	var mutation *PendingMutationPlan
	var enrollment *PendingKeyEnrollmentPlan
	var transfer *OwnershipTransferApprovalCollectionPlan
	var reconciliation *PendingReconciliationPlan
	var cutover *PendingOwnershipTransferCutoverPlan
	var acceptance *PendingOwnershipTransferAcceptancePlan
	switch wire.Kind {
	case DurablePendingMutation:
		if wire.Mutation == nil || wire.Enrollment != nil || wire.Transfer != nil ||
			wire.Reconciliation != nil || wire.Cutover != nil || wire.Acceptance != nil {
			return DurablePendingEnvelope{}, ErrPendingPlanInvalid
		}
		value, decodeErr := pendingMutationFromWire(*wire.Mutation)
		if decodeErr != nil {
			return DurablePendingEnvelope{}, decodeErr
		}
		mutation = &value
	case DurablePendingKeyEnrollment:
		if wire.Mutation != nil || wire.Enrollment == nil || wire.Transfer != nil ||
			wire.Reconciliation != nil || wire.Cutover != nil || wire.Acceptance != nil {
			return DurablePendingEnvelope{}, ErrPendingPlanInvalid
		}
		value, decodeErr := pendingEnrollmentFromWire(*wire.Enrollment)
		if decodeErr != nil {
			return DurablePendingEnvelope{}, decodeErr
		}
		enrollment = &value
	case DurablePendingOwnershipTransferCollection:
		if wire.Mutation != nil || wire.Enrollment != nil || wire.Transfer == nil ||
			wire.Reconciliation != nil || wire.Cutover != nil || wire.Acceptance != nil {
			return DurablePendingEnvelope{}, ErrPendingPlanInvalid
		}
		value, decodeErr := transferPlanFromWire(*wire.Transfer)
		if decodeErr != nil {
			return DurablePendingEnvelope{}, decodeErr
		}
		transfer = &value
	case DurablePendingReconciliation:
		if wire.Mutation != nil || wire.Enrollment != nil || wire.Transfer != nil ||
			wire.Reconciliation == nil || wire.Cutover != nil || wire.Acceptance != nil {
			return DurablePendingEnvelope{}, ErrPendingPlanInvalid
		}
		value, decodeErr := reconciliationFromWire(*wire.Reconciliation)
		if decodeErr != nil {
			return DurablePendingEnvelope{}, decodeErr
		}
		reconciliation = &value
	case DurablePendingOwnershipTransferCutover:
		if wire.Mutation != nil || wire.Enrollment != nil || wire.Transfer != nil ||
			wire.Reconciliation != nil || wire.Cutover == nil || wire.Acceptance != nil {
			return DurablePendingEnvelope{}, ErrPendingPlanInvalid
		}
		value, decodeErr := cutoverPlanFromWire(*wire.Cutover)
		if decodeErr != nil {
			return DurablePendingEnvelope{}, decodeErr
		}
		cutover = &value
	case DurablePendingOwnershipTransferAcceptance:
		if wire.Mutation != nil || wire.Enrollment != nil || wire.Transfer != nil ||
			wire.Reconciliation != nil || wire.Cutover != nil || wire.Acceptance == nil {
			return DurablePendingEnvelope{}, ErrPendingPlanInvalid
		}
		value, decodeErr := acceptancePlanFromWire(*wire.Acceptance)
		if decodeErr != nil {
			return DurablePendingEnvelope{}, decodeErr
		}
		acceptance = &value
	default:
		return DurablePendingEnvelope{}, ErrPendingPlanInvalid
	}
	envelope := DurablePendingEnvelope{kind: wire.Kind, encoded: owned,
		digest: domainDigest(durablePendingEnvelopeDigestDomain, owned), capability: false, mutation: mutation,
		enrollment: enrollment, transfer: transfer, reconciliation: reconciliation, cutover: cutover,
		acceptance: acceptance}
	if err := envelope.VerifyDigest(); err != nil {
		return DurablePendingEnvelope{}, err
	}
	return envelope, nil
}

// preflightDurableJSON bounds structural expansion before encoding/json is
// allowed to allocate typed slices. []byte values are base64 JSON strings, so
// the per-container token ceiling does not constrain legitimate payload bytes.
func preflightDurableJSON(input []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	type frame struct {
		delim json.Delim
		count int
	}
	stack := make([]frame, 0, 16)
	tokens := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if len(stack) != 0 {
				return fmt.Errorf("%w: unterminated JSON depth %d", ErrPendingPlanInvalid, len(stack))
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: JSON token: %v", ErrPendingPlanInvalid, err)
		}
		tokens++
		if tokens > durablePendingMaxJSONTokens {
			return fmt.Errorf("%w: JSON tokens exceed %d", ErrPendingPlanInvalid,
				durablePendingMaxJSONTokens)
		}
		if len(stack) > 0 {
			stack[len(stack)-1].count++
			if stack[len(stack)-1].count > durablePendingMaxContainerTokens {
				return fmt.Errorf("%w: JSON container tokens exceed %d", ErrPendingPlanInvalid,
					durablePendingMaxContainerTokens)
			}
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{', '[':
				if len(stack) >= durablePendingMaxJSONDepth {
					return fmt.Errorf("%w: JSON depth exceeds %d", ErrPendingPlanInvalid,
						durablePendingMaxJSONDepth)
				}
				stack = append(stack, frame{delim: value})
			case '}', ']':
				if len(stack) == 0 || (value == '}' && stack[len(stack)-1].delim != '{') ||
					(value == ']' && stack[len(stack)-1].delim != '[') {
					return fmt.Errorf("%w: mismatched JSON delimiter", ErrPendingPlanInvalid)
				}
				stack = stack[:len(stack)-1]
			}
		case string:
			if len(value) > durablePendingMaxBytes {
				return fmt.Errorf("%w: JSON string exceeds %d", ErrPendingPlanInvalid,
					durablePendingMaxBytes)
			}
		}
	}
}

type durableEnvelopeWire struct {
	Codec          string                      `json:"codec"`
	Version        uint32                      `json:"version"`
	Kind           DurablePendingKind          `json:"kind"`
	Mutation       *durablePendingMutationWire `json:"mutation,omitempty"`
	Enrollment     *durableEnrollmentWire      `json:"enrollment,omitempty"`
	Transfer       *durableTransferPlanWire    `json:"transfer,omitempty"`
	Reconciliation *durableReconciliationWire  `json:"reconciliation,omitempty"`
	Cutover        *durableCutoverWire         `json:"cutover,omitempty"`
	Acceptance     *durableAcceptanceWire      `json:"acceptance,omitempty"`
}

func marshalDurableWire(wire durableEnvelopeWire) ([]byte, error) {
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("%w: JSON: %v", ErrPendingPlanInvalid, err)
	}
	if len(encoded) == 0 || len(encoded) > durablePendingMaxBytes {
		return nil, fmt.Errorf("%w: durable bytes %d exceed %d", ErrPendingPlanInvalid,
			len(encoded), durablePendingMaxBytes)
	}
	if err := preflightDurableJSON(encoded); err != nil {
		return nil, fmt.Errorf("%w: JSON preflight (%d bytes): %v", ErrPendingPlanInvalid,
			len(encoded), err)
	}
	return encoded, nil
}

func (envelope DurablePendingEnvelope) toWire() (durableEnvelopeWire, error) {
	wire := durableEnvelopeWire{Codec: durablePendingCodec, Version: durablePendingCodecVersion, Kind: envelope.kind}
	switch envelope.kind {
	case DurablePendingMutation:
		if envelope.mutation == nil || envelope.mutation.VerifyDigest() != nil || envelope.cutover != nil ||
			envelope.acceptance != nil {
			return durableEnvelopeWire{}, ErrPendingPlanInvalid
		}
		wire.Mutation = pendingMutationToWire(*envelope.mutation)
	case DurablePendingKeyEnrollment:
		if envelope.enrollment == nil || envelope.enrollment.VerifyDigest() != nil || envelope.cutover != nil ||
			envelope.acceptance != nil {
			return durableEnvelopeWire{}, ErrPendingPlanInvalid
		}
		wire.Enrollment = pendingEnrollmentToWire(*envelope.enrollment)
	case DurablePendingOwnershipTransferCollection:
		if envelope.transfer == nil || envelope.transfer.VerifyDigest() != nil || envelope.cutover != nil ||
			envelope.acceptance != nil {
			return durableEnvelopeWire{}, ErrPendingPlanInvalid
		}
		wire.Transfer = transferPlanToWire(*envelope.transfer)
	case DurablePendingReconciliation:
		if envelope.reconciliation == nil || envelope.reconciliation.VerifyDigest() != nil || envelope.cutover != nil ||
			envelope.acceptance != nil {
			return durableEnvelopeWire{}, ErrPendingPlanInvalid
		}
		wire.Reconciliation = reconciliationToWire(*envelope.reconciliation)
	case DurablePendingOwnershipTransferCutover:
		if envelope.cutover == nil || envelope.cutover.VerifyDigest() != nil || envelope.mutation != nil ||
			envelope.enrollment != nil || envelope.transfer != nil || envelope.reconciliation != nil ||
			envelope.acceptance != nil {
			return durableEnvelopeWire{}, ErrPendingPlanInvalid
		}
		wire.Cutover = cutoverPlanToWire(*envelope.cutover)
	case DurablePendingOwnershipTransferAcceptance:
		if envelope.acceptance == nil || envelope.acceptance.VerifyDigest() != nil || envelope.mutation != nil ||
			envelope.enrollment != nil || envelope.transfer != nil || envelope.reconciliation != nil ||
			envelope.cutover != nil {
			return durableEnvelopeWire{}, ErrPendingPlanInvalid
		}
		wire.Acceptance = acceptancePlanToWire(*envelope.acceptance)
	default:
		return durableEnvelopeWire{}, ErrPendingPlanInvalid
	}
	return wire, nil
}

type durableMutationWire struct {
	Kind            MutationKind          `json:"kind"`
	CAS             CASIntent             `json:"cas"`
	EvaluatedAt     int64                 `json:"evaluated_at"`
	CommitNotBefore int64                 `json:"commit_not_before"`
	CommitNotAfter  int64                 `json:"commit_not_after"`
	Material        *KeyMaterialSnapshot  `json:"material,omitempty"`
	Identity        *IdentitySnapshot     `json:"identity,omitempty"`
	Lifecycle       *KeyLifecycleSnapshot `json:"lifecycle,omitempty"`
	Digest          [32]byte              `json:"digest"`
}

func mutationToWire(plan MutationPlan) durableMutationWire {
	wire := durableMutationWire{Kind: plan.Kind(), CAS: plan.CAS(), EvaluatedAt: plan.EvaluatedAtUnixNano(),
		CommitNotBefore: plan.CommitNotBeforeUnixNano(), CommitNotAfter: plan.CommitNotAfterUnixNano(), Digest: plan.Digest()}
	if value, ok := plan.KeyMaterial(); ok {
		wire.Material = &value
	}
	if value, ok := plan.Identity(); ok {
		wire.Identity = &value
	}
	if value, ok := plan.KeyLifecycle(); ok {
		wire.Lifecycle = &value
	}
	return wire
}

func mutationFromWire(wire durableMutationWire) (MutationPlan, error) {
	window := planWindow{EvaluatedAtUnixNano: wire.EvaluatedAt,
		CommitNotBeforeUnixNano: wire.CommitNotBefore, CommitNotAfterUnixNano: wire.CommitNotAfter}
	var plan MutationPlan
	var err error
	switch wire.Kind {
	case MutationCreateKeyMaterial:
		if wire.Material == nil || wire.Identity != nil || wire.Lifecycle != nil {
			return MutationPlan{}, ErrPendingPlanInvalid
		}
		plan, err = newMaterialPlan(wire.CAS, *wire.Material, window)
	case MutationAppendIdentity:
		if wire.Material != nil || wire.Identity == nil || wire.Lifecycle != nil {
			return MutationPlan{}, ErrPendingPlanInvalid
		}
		plan, err = newIdentityPlan(wire.CAS, *wire.Identity, window)
	case MutationAppendKeyLifecycle:
		if wire.Material != nil || wire.Identity != nil || wire.Lifecycle == nil {
			return MutationPlan{}, ErrPendingPlanInvalid
		}
		plan, err = newLifecyclePlan(wire.CAS, *wire.Lifecycle, window)
	default:
		return MutationPlan{}, ErrPendingPlanInvalid
	}
	if err != nil || plan.Digest() != wire.Digest || verifyMutationPlan(plan) != nil {
		return MutationPlan{}, ErrPendingPlanInvalid
	}
	return plan, nil
}

type durableAuditWire struct {
	AuditEventID                string                 `json:"audit_event_id"`
	EventType                   string                 `json:"event_type"`
	ActorIdentity               string                 `json:"actor_identity"`
	ActorKeyID                  string                 `json:"actor_key_id"`
	SubjectIDs                  []string               `json:"subject_ids"`
	CauseCode                   string                 `json:"cause_code"`
	CorrelationID               [16]byte               `json:"correlation_id"`
	CausationID                 ccse.OptionalMessageID `json:"causation_id"`
	MessageID                   [16]byte               `json:"message_id"`
	IdempotencyKey              [16]byte               `json:"idempotency_key"`
	ExpectedAuditIdempotencyKey [16]byte               `json:"expected_audit_idempotency_key"`
	HasSource                   bool                   `json:"has_source"`
	SourceRecord                ccse.Record            `json:"source_record"`
	SourceDigest                [32]byte               `json:"source_digest"`
	SourceCausationID           ccse.OptionalMessageID `json:"source_causation_id"`
	OccurredAt                  int64                  `json:"occurred_at"`
	PolicyDigests               [][32]byte             `json:"policy_digests"`
	EvidenceDigests             [][32]byte             `json:"evidence_digests"`
	Digest                      [32]byte               `json:"digest"`
}

func auditToWire(audit AuditIntent) durableAuditWire {
	record, hasSource := audit.SourceAuthorizationRecord()
	return durableAuditWire{AuditEventID: audit.AuditEventID(), EventType: audit.EventType(),
		ActorIdentity: audit.ActorIdentity(), ActorKeyID: audit.ActorKeyID(), SubjectIDs: audit.SubjectIDs(),
		CauseCode: audit.CauseCode(), CorrelationID: audit.CorrelationID(), CausationID: audit.CausationID(),
		MessageID: audit.MessageID(), IdempotencyKey: audit.IdempotencyKey(),
		ExpectedAuditIdempotencyKey: audit.ExpectedAuditIdempotencyKey(), HasSource: hasSource,
		SourceRecord: record, SourceDigest: audit.SourceAuthorizationDigest(),
		SourceCausationID: audit.SourceCausationID(), OccurredAt: audit.OccurredAtUnixNano(),
		PolicyDigests: audit.PolicyDigestsSHA256(), EvidenceDigests: audit.EvidenceDigestsSHA256(), Digest: audit.Digest()}
}

func auditFromWire(wire durableAuditWire) (AuditIntent, error) {
	source := auditSourceEvidence{Present: wire.HasSource, ActorKeyID: wire.ActorKeyID,
		Record: cloneCCSERecord(wire.SourceRecord), Digest: wire.SourceDigest, CausationID: wire.SourceCausationID}
	audit, err := newAuditIntent(wire.AuditEventID, wire.EventType, wire.ActorIdentity, wire.SubjectIDs,
		wire.CauseCode, wire.CorrelationID, wire.CausationID, wire.MessageID, wire.IdempotencyKey,
		wire.ExpectedAuditIdempotencyKey, source, wire.OccurredAt, wire.PolicyDigests, wire.EvidenceDigests)
	if err != nil || audit.Digest() != wire.Digest || verifyAuditIntent(audit) != nil {
		return AuditIntent{}, ErrPendingPlanInvalid
	}
	return audit, nil
}

type durableAdmissionWire struct {
	IdentifierReservations  []globalid.Claim    `json:"identifier_reservations"`
	IdempotencyReservations []idempotency.Claim `json:"idempotency_reservations"`
	CoreEvidenceDigest      [32]byte            `json:"core_evidence_digest"`
	EvaluatedAt             int64               `json:"evaluated_at"`
	CommitNotBefore         int64               `json:"commit_not_before"`
	CommitNotAfter          int64               `json:"commit_not_after"`
	Digest                  [32]byte            `json:"digest"`
}

func admissionToWire(intent PendingAdmissionIntent) durableAdmissionWire {
	return durableAdmissionWire{IdentifierReservations: intent.IdentifierReservations(),
		IdempotencyReservations: intent.IdempotencyReservations(), CoreEvidenceDigest: intent.CoreEvidenceDigest(),
		EvaluatedAt: intent.EvaluatedAtUnixNano(), CommitNotBefore: intent.CommitNotBeforeUnixNano(),
		CommitNotAfter: intent.CommitNotAfterUnixNano(), Digest: intent.Digest()}
}

func admissionFromWire(wire durableAdmissionWire) (PendingAdmissionIntent, error) {
	intent, err := newPendingAdmissionIntent(wire.IdentifierReservations, wire.IdempotencyReservations,
		wire.CoreEvidenceDigest, wire.EvaluatedAt, wire.CommitNotBefore, wire.CommitNotAfter)
	if err != nil || intent.Digest() != wire.Digest {
		return PendingAdmissionIntent{}, ErrPendingPlanInvalid
	}
	return intent, nil
}

type durablePendingMutationWire struct {
	Mutation    durableMutationWire  `json:"mutation"`
	Audit       durableAuditWire     `json:"audit"`
	Admission   durableAdmissionWire `json:"admission"`
	Completions []idempotency.Claim  `json:"completions"`
	Digest      [32]byte             `json:"digest"`
}

func pendingMutationToWire(plan PendingMutationPlan) *durablePendingMutationWire {
	return &durablePendingMutationWire{Mutation: mutationToWire(plan.mutation), Audit: auditToWire(plan.audit),
		Admission: admissionToWire(plan.admission), Completions: plan.IdempotencyCompletionClaims(), Digest: plan.Digest()}
}

func pendingMutationFromWire(wire durablePendingMutationWire) (PendingMutationPlan, error) {
	mutation, err := mutationFromWire(wire.Mutation)
	if err != nil {
		return PendingMutationPlan{}, err
	}
	audit, err := auditFromWire(wire.Audit)
	if err != nil {
		return PendingMutationPlan{}, err
	}
	admission, err := admissionFromWire(wire.Admission)
	if err != nil {
		return PendingMutationPlan{}, err
	}
	plan := PendingMutationPlan{mutation: mutation, audit: audit, admission: admission,
		idempotencyCompletion: append([]idempotency.Claim(nil), wire.Completions...), digest: wire.Digest}
	if plan.VerifyDigest() != nil {
		return PendingMutationPlan{}, ErrPendingPlanInvalid
	}
	return plan, nil
}

type durableEnrollmentWire struct {
	Material        durableMutationWire  `json:"material"`
	Lifecycle       durableMutationWire  `json:"lifecycle"`
	Audit           durableAuditWire     `json:"audit"`
	EvaluatedAt     int64                `json:"evaluated_at"`
	CommitNotBefore int64                `json:"commit_not_before"`
	CommitNotAfter  int64                `json:"commit_not_after"`
	Admission       durableAdmissionWire `json:"admission"`
	Completions     []idempotency.Claim  `json:"completions"`
	Digest          [32]byte             `json:"digest"`
}

func pendingEnrollmentToWire(plan PendingKeyEnrollmentPlan) *durableEnrollmentWire {
	return &durableEnrollmentWire{Material: mutationToWire(plan.material), Lifecycle: mutationToWire(plan.lifecycle),
		Audit: auditToWire(plan.audit), EvaluatedAt: plan.evaluatedAtUnixNano,
		CommitNotBefore: plan.commitNotBeforeUnixNano, CommitNotAfter: plan.commitNotAfterUnixNano,
		Admission: admissionToWire(plan.admission), Completions: plan.IdempotencyCompletionClaims(), Digest: plan.Digest()}
}

func pendingEnrollmentFromWire(wire durableEnrollmentWire) (PendingKeyEnrollmentPlan, error) {
	material, err := mutationFromWire(wire.Material)
	if err != nil || material.Kind() != MutationCreateKeyMaterial {
		return PendingKeyEnrollmentPlan{}, ErrPendingPlanInvalid
	}
	lifecycle, err := mutationFromWire(wire.Lifecycle)
	if err != nil || lifecycle.Kind() != MutationAppendKeyLifecycle {
		return PendingKeyEnrollmentPlan{}, ErrPendingPlanInvalid
	}
	audit, err := auditFromWire(wire.Audit)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	admission, err := admissionFromWire(wire.Admission)
	if err != nil {
		return PendingKeyEnrollmentPlan{}, err
	}
	plan := PendingKeyEnrollmentPlan{material: material, lifecycle: lifecycle, audit: audit,
		evaluatedAtUnixNano: wire.EvaluatedAt, commitNotBeforeUnixNano: wire.CommitNotBefore,
		commitNotAfterUnixNano: wire.CommitNotAfter, admission: admission,
		idempotencyCompletion: append([]idempotency.Claim(nil), wire.Completions...), digest: wire.Digest}
	if plan.VerifyDigest() != nil {
		return PendingKeyEnrollmentPlan{}, ErrPendingPlanInvalid
	}
	return plan, nil
}

type durableRetainedRecordWire struct {
	Record ccse.Record `json:"record"`
	Digest [32]byte    `json:"digest"`
}

func retainedToWire(record RetainedVerifiedRecord) durableRetainedRecordWire {
	return durableRetainedRecordWire{Record: record.Record(), Digest: record.Digest()}
}

func retainedFromWire(wire durableRetainedRecordWire) (RetainedVerifiedRecord, error) {
	digest, err := wire.Record.Digest(ccse.DefaultLimits())
	if err != nil || digest != wire.Digest {
		return RetainedVerifiedRecord{}, ErrPendingPlanInvalid
	}
	if _, err := canonicalSignedAuthorizationEvidence(wire.Record); err != nil {
		return RetainedVerifiedRecord{}, ErrPendingPlanInvalid
	}
	return RetainedVerifiedRecord{record: cloneCCSERecord(wire.Record), digest: wire.Digest}, nil
}

type durableTransferAdmissionWire struct {
	Authority            OwnershipTransferAuthorityRequirement `json:"authority"`
	OldSide              bool                                  `json:"old_side"`
	Signed               durableRetainedRecordWire             `json:"signed"`
	Historical           HistoricalKeyAuthorizationSnapshot    `json:"historical"`
	Receiver             ReceiverProfile                       `json:"receiver"`
	CurrentPreconditions []SnapshotPrecondition                `json:"current_preconditions"`
	ProfileDigest        [32]byte                              `json:"profile_digest"`
	ActivationDigest     [32]byte                              `json:"activation_digest"`
	ValidatedAt          int64                                 `json:"validated_at"`
	Fingerprint          [32]byte                              `json:"fingerprint"`
}

func transferAdmissionToWire(admission OwnershipTransferAuthorityAdmission) durableTransferAdmissionWire {
	return durableTransferAdmissionWire{Authority: admission.Authority, OldSide: admission.OldSide,
		Signed: retainedToWire(admission.Signed), Historical: HistoricalKeyAuthorizationSnapshot{
			Material: cloneKeyMaterial(admission.Historical.Material), Lifecycle: cloneLifecycle(admission.Historical.Lifecycle),
			Identity: cloneIdentity(admission.Historical.Identity)},
		Receiver:             cloneReceiverProfile(admission.Receiver),
		CurrentPreconditions: append([]SnapshotPrecondition(nil), admission.CurrentPreconditions...),
		ProfileDigest:        admission.AdmissionProfileDigest, ActivationDigest: admission.AdmissionActivationDigest,
		ValidatedAt: admission.ValidatedAtUnixNano,
		Fingerprint: admission.Fingerprint}
}

func transferAdmissionFromWire(wire durableTransferAdmissionWire) (OwnershipTransferAuthorityAdmission, error) {
	signed, err := retainedFromWire(wire.Signed)
	if err != nil {
		return OwnershipTransferAuthorityAdmission{}, err
	}
	admission := OwnershipTransferAuthorityAdmission{Authority: wire.Authority, OldSide: wire.OldSide,
		Signed: signed, Historical: HistoricalKeyAuthorizationSnapshot{Material: cloneKeyMaterial(wire.Historical.Material),
			Lifecycle: cloneLifecycle(wire.Historical.Lifecycle), Identity: cloneIdentity(wire.Historical.Identity)},
		Receiver:               cloneReceiverProfile(wire.Receiver),
		CurrentPreconditions:   append([]SnapshotPrecondition(nil), wire.CurrentPreconditions...),
		AdmissionProfileDigest: wire.ProfileDigest, AdmissionActivationDigest: wire.ActivationDigest,
		ValidatedAtUnixNano: wire.ValidatedAt, Fingerprint: wire.Fingerprint}
	digest, err := transferAuthorityAdmissionFingerprint(admission)
	if err != nil || digest != admission.Fingerprint {
		return OwnershipTransferAuthorityAdmission{}, ErrPendingPlanInvalid
	}
	return admission, nil
}

type durableTransferEvidenceAdmissionWire struct {
	RecordDigest         [32]byte                           `json:"record_digest"`
	EvidenceKind         uint32                             `json:"evidence_kind"`
	Historical           HistoricalKeyAuthorizationSnapshot `json:"historical"`
	Receiver             ReceiverProfile                    `json:"receiver"`
	ProfileDigest        [32]byte                           `json:"profile_digest"`
	ActivationDigest     [32]byte                           `json:"activation_digest"`
	PolicyDecisionDigest [32]byte                           `json:"policy_decision_digest"`
	ValidatedAt          int64                              `json:"validated_at"`
	Fingerprint          [32]byte                           `json:"fingerprint"`
}

func transferEvidenceAdmissionToWire(admission OwnershipTransferEvidenceAdmission) durableTransferEvidenceAdmissionWire {
	return durableTransferEvidenceAdmissionWire{RecordDigest: admission.RecordDigest,
		EvidenceKind: admission.EvidenceKind,
		Historical: HistoricalKeyAuthorizationSnapshot{Material: cloneKeyMaterial(admission.Historical.Material),
			Lifecycle: cloneLifecycle(admission.Historical.Lifecycle), Identity: cloneIdentity(admission.Historical.Identity)},
		Receiver: cloneReceiverProfile(admission.Receiver), ProfileDigest: admission.ProfileDigest,
		ActivationDigest: admission.ActivationDigest, PolicyDecisionDigest: admission.PolicyDecisionDigest,
		ValidatedAt: admission.ValidatedAtUnixNano, Fingerprint: admission.Fingerprint}
}

func transferEvidenceAdmissionFromWire(wire durableTransferEvidenceAdmissionWire) (OwnershipTransferEvidenceAdmission, error) {
	admission := OwnershipTransferEvidenceAdmission{RecordDigest: wire.RecordDigest,
		EvidenceKind: wire.EvidenceKind,
		Historical: HistoricalKeyAuthorizationSnapshot{Material: cloneKeyMaterial(wire.Historical.Material),
			Lifecycle: cloneLifecycle(wire.Historical.Lifecycle), Identity: cloneIdentity(wire.Historical.Identity)},
		Receiver: cloneReceiverProfile(wire.Receiver), ProfileDigest: wire.ProfileDigest,
		ActivationDigest: wire.ActivationDigest, PolicyDecisionDigest: wire.PolicyDecisionDigest,
		ValidatedAtUnixNano: wire.ValidatedAt, Fingerprint: wire.Fingerprint}
	digest, err := transferEvidenceAdmissionFingerprint(admission)
	if err != nil || digest != admission.Fingerprint {
		return OwnershipTransferEvidenceAdmission{}, ErrPendingPlanInvalid
	}
	return admission, nil
}

type durableTransferFixedWire struct {
	PreviousTerminal   IdentitySnapshot                       `json:"previous_terminal"`
	NextPending        IdentitySnapshot                       `json:"next_pending"`
	PreviousCAS        SnapshotPrecondition                   `json:"previous_cas"`
	ClosureRecords     []durableRetainedRecordWire            `json:"closure_records"`
	ClosureSnapshots   []KeyLifecycleSnapshot                 `json:"closure_snapshots"`
	EvidenceRecords    []durableRetainedRecordWire            `json:"evidence_records"`
	EvidenceAdmissions []durableTransferEvidenceAdmissionWire `json:"evidence_admissions"`
	ClosureCAS         []SnapshotPrecondition                 `json:"closure_cas"`
	EvidenceCAS        []SnapshotPrecondition                 `json:"evidence_cas"`
}

func transferFixedToWire(fixed OwnershipTransferFixedEvidence) durableTransferFixedWire {
	wire := durableTransferFixedWire{PreviousTerminal: cloneIdentity(fixed.PreviousTerminalIdentity),
		NextPending: cloneIdentity(fixed.NextPendingIdentity), PreviousCAS: fixed.PreviousIdentityCAS,
		ClosureSnapshots: make([]KeyLifecycleSnapshot, len(fixed.KeyClosureSnapshots)),
		ClosureCAS:       append([]SnapshotPrecondition(nil), fixed.ClosurePreconditions...),
		EvidenceCAS:      append([]SnapshotPrecondition(nil), fixed.EvidencePreconditions...)}
	for index := range fixed.KeyClosureRecords {
		wire.ClosureRecords = append(wire.ClosureRecords, retainedToWire(fixed.KeyClosureRecords[index]))
	}
	for index := range fixed.KeyClosureSnapshots {
		wire.ClosureSnapshots[index] = cloneLifecycle(fixed.KeyClosureSnapshots[index])
	}
	for index := range fixed.EvidenceRecords {
		wire.EvidenceRecords = append(wire.EvidenceRecords, retainedToWire(fixed.EvidenceRecords[index]))
	}
	for index := range fixed.EvidenceAdmissions {
		wire.EvidenceAdmissions = append(wire.EvidenceAdmissions,
			transferEvidenceAdmissionToWire(fixed.EvidenceAdmissions[index]))
	}
	return wire
}

func transferFixedFromWire(wire durableTransferFixedWire) (OwnershipTransferFixedEvidence, error) {
	fixed := OwnershipTransferFixedEvidence{PreviousTerminalIdentity: cloneIdentity(wire.PreviousTerminal),
		NextPendingIdentity: cloneIdentity(wire.NextPending), PreviousIdentityCAS: wire.PreviousCAS,
		KeyClosureSnapshots:   make([]KeyLifecycleSnapshot, len(wire.ClosureSnapshots)),
		ClosurePreconditions:  append([]SnapshotPrecondition(nil), wire.ClosureCAS...),
		EvidencePreconditions: append([]SnapshotPrecondition(nil), wire.EvidenceCAS...)}
	for _, recordWire := range wire.ClosureRecords {
		record, err := retainedFromWire(recordWire)
		if err != nil {
			return OwnershipTransferFixedEvidence{}, err
		}
		fixed.KeyClosureRecords = append(fixed.KeyClosureRecords, record)
	}
	for index := range wire.ClosureSnapshots {
		fixed.KeyClosureSnapshots[index] = cloneLifecycle(wire.ClosureSnapshots[index])
	}
	for _, recordWire := range wire.EvidenceRecords {
		record, err := retainedFromWire(recordWire)
		if err != nil {
			return OwnershipTransferFixedEvidence{}, err
		}
		fixed.EvidenceRecords = append(fixed.EvidenceRecords, record)
	}
	for _, admissionWire := range wire.EvidenceAdmissions {
		admission, err := transferEvidenceAdmissionFromWire(admissionWire)
		if err != nil {
			return OwnershipTransferFixedEvidence{}, err
		}
		fixed.EvidenceAdmissions = append(fixed.EvidenceAdmissions, admission)
	}
	if len(fixed.EvidenceAdmissions) != len(fixed.EvidenceRecords) {
		return OwnershipTransferFixedEvidence{}, ErrPendingPlanInvalid
	}
	return fixed, nil
}

type durableTransferCollectionWire struct {
	Binding          idempotency.Binding            `json:"binding"`
	Version          uint64                         `json:"version"`
	ProgressDigest   [32]byte                       `json:"progress_digest"`
	CanonicalPayload []byte                         `json:"canonical_payload"`
	TransferDigest   [32]byte                       `json:"transfer_digest"`
	Profile          OwnershipTransferProfile       `json:"profile"`
	ProfileDigest    [32]byte                       `json:"profile_digest"`
	Approvals        []durableTransferAdmissionWire `json:"approvals"`
	Fixed            durableTransferFixedWire       `json:"fixed"`
	HomeRegion       string                         `json:"home_region"`
	WriterEpoch      uint64                         `json:"writer_epoch"`
}

func transferCollectionToWire(snapshot OwnershipTransferApprovalCollectionSnapshot) durableTransferCollectionWire {
	wire := durableTransferCollectionWire{Binding: snapshot.Binding, Version: snapshot.Version,
		ProgressDigest: snapshot.ProgressDigest, CanonicalPayload: append([]byte(nil), snapshot.CanonicalPayload...),
		TransferDigest: snapshot.TransferEvidenceDigest, Profile: cloneTransferProfile(snapshot.Profile),
		ProfileDigest: snapshot.ProfileDigest, Fixed: transferFixedToWire(snapshot.FixedEvidence),
		HomeRegion: snapshot.HomeRegion, WriterEpoch: snapshot.WriterEpoch}
	for _, approval := range snapshot.Approvals {
		wire.Approvals = append(wire.Approvals, transferAdmissionToWire(approval))
	}
	return wire
}

func transferCollectionFromWire(wire durableTransferCollectionWire) (OwnershipTransferApprovalCollectionSnapshot, error) {
	fixed, err := transferFixedFromWire(wire.Fixed)
	if err != nil {
		return OwnershipTransferApprovalCollectionSnapshot{}, err
	}
	snapshot := OwnershipTransferApprovalCollectionSnapshot{Binding: wire.Binding, Version: wire.Version,
		ProgressDigest: wire.ProgressDigest, CanonicalPayload: append([]byte(nil), wire.CanonicalPayload...),
		TransferEvidenceDigest: wire.TransferDigest, Profile: cloneTransferProfile(wire.Profile),
		ProfileDigest: wire.ProfileDigest, FixedEvidence: fixed, HomeRegion: wire.HomeRegion, WriterEpoch: wire.WriterEpoch}
	for _, approvalWire := range wire.Approvals {
		approval, admissionErr := transferAdmissionFromWire(approvalWire)
		if admissionErr != nil {
			return OwnershipTransferApprovalCollectionSnapshot{}, admissionErr
		}
		snapshot.Approvals = append(snapshot.Approvals, approval)
	}
	digest, err := transferCollectionDigest(snapshot)
	if err != nil || digest != snapshot.ProgressDigest {
		return OwnershipTransferApprovalCollectionSnapshot{}, ErrPendingPlanInvalid
	}
	return snapshot, nil
}

type durableAcceptedTransferWire struct {
	Projection       foundationv1.OwnershipTransferAuthorizationSigningProjection `json:"projection"`
	CanonicalPayload []byte                                                       `json:"canonical_payload"`
	TransferDigest   [32]byte                                                     `json:"transfer_digest"`
	Profile          OwnershipTransferProfile                                     `json:"profile"`
	ProfileDigest    [32]byte                                                     `json:"profile_digest"`
	Approvals        []durableTransferAdmissionWire                               `json:"approvals"`
	Fixed            durableTransferFixedWire                                     `json:"fixed"`
	AcceptedAt       int64                                                        `json:"accepted_at"`
	StateVersion     uint64                                                       `json:"state_version"`
	WriterEpoch      uint64                                                       `json:"writer_epoch"`
	SnapshotDigest   [32]byte                                                     `json:"snapshot_digest"`
}

func acceptedToWire(snapshot AcceptedOwnershipTransferSnapshot) *durableAcceptedTransferWire {
	wire := &durableAcceptedTransferWire{Projection: cloneTransferProjection(snapshot.Projection),
		CanonicalPayload: append([]byte(nil), snapshot.CanonicalPayload...), TransferDigest: snapshot.TransferEvidenceDigest,
		Profile: cloneTransferProfile(snapshot.Profile), ProfileDigest: snapshot.ProfileDigest,
		Fixed: transferFixedToWire(snapshot.FixedEvidence), AcceptedAt: snapshot.AcceptedAtUnixNano,
		StateVersion: snapshot.StateVersion, WriterEpoch: snapshot.WriterEpoch, SnapshotDigest: snapshot.SnapshotDigest}
	for _, approval := range snapshot.Approvals {
		wire.Approvals = append(wire.Approvals, transferAdmissionToWire(approval))
	}
	return wire
}

func acceptedFromWire(wire durableAcceptedTransferWire) (AcceptedOwnershipTransferSnapshot, error) {
	fixed, err := transferFixedFromWire(wire.Fixed)
	if err != nil {
		return AcceptedOwnershipTransferSnapshot{}, err
	}
	snapshot := AcceptedOwnershipTransferSnapshot{Projection: cloneTransferProjection(wire.Projection),
		CanonicalPayload: append([]byte(nil), wire.CanonicalPayload...), TransferEvidenceDigest: wire.TransferDigest,
		Profile: cloneTransferProfile(wire.Profile), ProfileDigest: wire.ProfileDigest, FixedEvidence: fixed,
		AcceptedAtUnixNano: wire.AcceptedAt, StateVersion: wire.StateVersion,
		WriterEpoch: wire.WriterEpoch, SnapshotDigest: wire.SnapshotDigest}
	for _, approvalWire := range wire.Approvals {
		approval, admissionErr := transferAdmissionFromWire(approvalWire)
		if admissionErr != nil {
			return AcceptedOwnershipTransferSnapshot{}, admissionErr
		}
		snapshot.Approvals = append(snapshot.Approvals, approval)
	}
	digest, err := acceptedTransferDigest(snapshot)
	if err != nil || digest != snapshot.SnapshotDigest {
		return AcceptedOwnershipTransferSnapshot{}, ErrPendingPlanInvalid
	}
	return snapshot, nil
}

type durableCutoverStepWire struct {
	Kind                OwnershipTransferCutoverStepKind `json:"kind"`
	Mutation            durableMutationWire              `json:"mutation"`
	PlannedPredecessors []SnapshotPrecondition           `json:"planned_predecessors"`
}

type durableCutoverWire struct {
	Accepted             durableAcceptedTransferWire       `json:"accepted"`
	Steps                []durableCutoverStepWire          `json:"steps"`
	Dependencies         []SnapshotPrecondition            `json:"dependencies"`
	Evidence             []durableRetainedRecordWire       `json:"evidence"`
	Audit                durableAuditWire                  `json:"audit"`
	EvaluatedAt          int64                             `json:"evaluated_at"`
	CommitNotBefore      int64                             `json:"commit_not_before"`
	CommitNotAfter       int64                             `json:"commit_not_after"`
	Admission            durableAdmissionWire              `json:"admission"`
	Completions          []idempotency.Claim               `json:"completions"`
	MemberAdmissions     []idempotency.CompoundMemberClaim `json:"member_admissions"`
	MemberCompletions    []idempotency.CompoundMemberClaim `json:"member_completions"`
	IdentifierAssertions []globalid.Claim                  `json:"identifier_assertions"`
	Digest               [32]byte                          `json:"digest"`
}

func cutoverPlanToWire(plan PendingOwnershipTransferCutoverPlan) *durableCutoverWire {
	accepted := acceptedToWire(plan.accepted)
	wire := &durableCutoverWire{Accepted: *accepted, Dependencies: plan.Dependencies(),
		Audit: auditToWire(plan.audit), EvaluatedAt: plan.evaluatedAtUnixNano,
		CommitNotBefore: plan.commitNotBeforeUnixNano, CommitNotAfter: plan.commitNotAfterUnixNano,
		Admission: admissionToWire(plan.admission), Completions: plan.IdempotencyCompletionClaims(),
		MemberAdmissions:     plan.CompoundMemberAdmissionClaims(),
		MemberCompletions:    plan.CompoundMemberCompletionClaims(),
		IdentifierAssertions: plan.IdentifierAssertions(), Digest: plan.Digest()}
	for _, step := range plan.steps {
		wire.Steps = append(wire.Steps, durableCutoverStepWire{Kind: step.Kind,
			Mutation:            mutationToWire(step.Mutation),
			PlannedPredecessors: append([]SnapshotPrecondition(nil), step.PlannedPredecessors...)})
	}
	for _, evidence := range plan.evidence {
		wire.Evidence = append(wire.Evidence, retainedToWire(evidence))
	}
	return wire
}

func cutoverPlanFromWire(wire durableCutoverWire) (PendingOwnershipTransferCutoverPlan, error) {
	accepted, err := acceptedFromWire(wire.Accepted)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	audit, err := auditFromWire(wire.Audit)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	admission, err := admissionFromWire(wire.Admission)
	if err != nil {
		return PendingOwnershipTransferCutoverPlan{}, err
	}
	steps := make([]OwnershipTransferCutoverStep, len(wire.Steps))
	for index, stepWire := range wire.Steps {
		mutation, mutationErr := mutationFromWire(stepWire.Mutation)
		if mutationErr != nil {
			return PendingOwnershipTransferCutoverPlan{}, mutationErr
		}
		steps[index] = OwnershipTransferCutoverStep{Kind: stepWire.Kind, Mutation: mutation,
			PlannedPredecessors: append([]SnapshotPrecondition(nil), stepWire.PlannedPredecessors...)}
	}
	evidence := make([]RetainedVerifiedRecord, 0, len(wire.Evidence))
	for _, evidenceWire := range wire.Evidence {
		value, evidenceErr := retainedFromWire(evidenceWire)
		if evidenceErr != nil {
			return PendingOwnershipTransferCutoverPlan{}, evidenceErr
		}
		evidence = append(evidence, value)
	}
	plan := PendingOwnershipTransferCutoverPlan{accepted: accepted, steps: steps,
		dependencies: append([]SnapshotPrecondition(nil), wire.Dependencies...), evidence: evidence,
		audit: audit, evaluatedAtUnixNano: wire.EvaluatedAt,
		commitNotBeforeUnixNano: wire.CommitNotBefore, commitNotAfterUnixNano: wire.CommitNotAfter,
		admission: admission, idempotencyCompletion: append([]idempotency.Claim(nil), wire.Completions...),
		memberAdmission:      append([]idempotency.CompoundMemberClaim(nil), wire.MemberAdmissions...),
		memberCompletion:     append([]idempotency.CompoundMemberClaim(nil), wire.MemberCompletions...),
		identifierAssertions: append([]globalid.Claim(nil), wire.IdentifierAssertions...),
		digest:               wire.Digest}
	if plan.VerifyDigest() != nil {
		return PendingOwnershipTransferCutoverPlan{}, ErrPendingPlanInvalid
	}
	return plan, nil
}

// durableAcceptanceWire stores the authoritative collection fence once and
// derives its immutable payload/profile/evidence body from Cutover.Accepted.
// This avoids duplicating the potentially 256-record accepted bundle in one
// envelope while preserving exact collection ProgressDigest verification.
type durableAcceptanceWire struct {
	CollectionBinding             idempotency.Binding    `json:"collection_binding"`
	CollectionVersion             uint64                 `json:"collection_version"`
	CollectionProgress            [32]byte               `json:"collection_progress"`
	CollectionHomeRegion          string                 `json:"collection_home_region"`
	CollectionWriterEpoch         uint64                 `json:"collection_writer_epoch"`
	ExpectedCollectionVersion     uint64                 `json:"expected_collection_version"`
	ExpectedCollectionProgress    [32]byte               `json:"expected_collection_progress"`
	ExpectedCollectionHomeRegion  string                 `json:"expected_collection_home_region"`
	ExpectedCollectionWriterEpoch uint64                 `json:"expected_collection_writer_epoch"`
	AuthorizedWriterEpoch         uint64                 `json:"authorized_writer_epoch"`
	WriterEvidenceDigest          [32]byte               `json:"writer_evidence_digest"`
	WriterFence                   WriterFence            `json:"writer_fence"`
	Cutover                       durableCutoverWire     `json:"cutover"`
	TransferCompletion            []idempotency.Claim    `json:"transfer_completion"`
	IdentifierAssertions          []globalid.Claim       `json:"identifier_assertions"`
	Dependencies                  []SnapshotPrecondition `json:"dependencies"`
	Audit                         durableAuditWire       `json:"audit"`
	EvaluatedAt                   int64                  `json:"evaluated_at"`
	CommitNotBefore               int64                  `json:"commit_not_before"`
	CommitNotAfter                int64                  `json:"commit_not_after"`
	Digest                        [32]byte               `json:"digest"`
}

func acceptancePlanToWire(plan PendingOwnershipTransferAcceptancePlan) *durableAcceptanceWire {
	return &durableAcceptanceWire{
		CollectionBinding: plan.collection.Binding, CollectionVersion: plan.collection.Version,
		CollectionProgress:   plan.collection.ProgressDigest,
		CollectionHomeRegion: plan.collection.HomeRegion, CollectionWriterEpoch: plan.collection.WriterEpoch,
		ExpectedCollectionVersion:     plan.expectedCollectionVersion,
		ExpectedCollectionProgress:    plan.expectedCollectionProgress,
		ExpectedCollectionHomeRegion:  plan.expectedCollectionHomeRegion,
		ExpectedCollectionWriterEpoch: plan.expectedCollectionWriterEpoch,
		AuthorizedWriterEpoch:         plan.authorizedWriterEpoch,
		WriterEvidenceDigest:          plan.writerEvidenceDigest, WriterFence: plan.writerFence,
		Cutover: *cutoverPlanToWire(plan.cutover), TransferCompletion: plan.TransferCompletionClaims(),
		IdentifierAssertions: plan.IdentifierAssertions(), Dependencies: plan.Dependencies(),
		Audit: auditToWire(plan.audit), EvaluatedAt: plan.evaluatedAtUnixNano,
		CommitNotBefore: plan.commitNotBeforeUnixNano, CommitNotAfter: plan.commitNotAfterUnixNano,
		Digest: plan.digest,
	}
}

func acceptancePlanFromWire(wire durableAcceptanceWire) (PendingOwnershipTransferAcceptancePlan, error) {
	cutover, err := cutoverPlanFromWire(wire.Cutover)
	if err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}
	audit, err := auditFromWire(wire.Audit)
	if err != nil {
		return PendingOwnershipTransferAcceptancePlan{}, err
	}
	accepted := cloneAcceptedTransfer(cutover.accepted)
	collection := OwnershipTransferApprovalCollectionSnapshot{
		Binding: wire.CollectionBinding, Version: wire.CollectionVersion,
		ProgressDigest:         wire.CollectionProgress,
		CanonicalPayload:       append([]byte(nil), accepted.CanonicalPayload...),
		TransferEvidenceDigest: accepted.TransferEvidenceDigest,
		Profile:                cloneTransferProfile(accepted.Profile), ProfileDigest: accepted.ProfileDigest,
		Approvals:     cloneAcceptedTransfer(accepted).Approvals,
		FixedEvidence: cloneTransferFixedEvidence(accepted.FixedEvidence),
		HomeRegion:    wire.CollectionHomeRegion, WriterEpoch: wire.CollectionWriterEpoch,
	}
	plan := PendingOwnershipTransferAcceptancePlan{
		collection: collection, expectedCollectionVersion: wire.ExpectedCollectionVersion,
		expectedCollectionProgress:    wire.ExpectedCollectionProgress,
		expectedCollectionHomeRegion:  wire.ExpectedCollectionHomeRegion,
		expectedCollectionWriterEpoch: wire.ExpectedCollectionWriterEpoch,
		authorizedWriterEpoch:         wire.AuthorizedWriterEpoch,
		writerEvidenceDigest:          wire.WriterEvidenceDigest, writerFence: wire.WriterFence,
		accepted: accepted, cutover: cutover,
		transferCompletion:   append([]idempotency.Claim(nil), wire.TransferCompletion...),
		identifierAssertions: append([]globalid.Claim(nil), wire.IdentifierAssertions...),
		dependencies:         append([]SnapshotPrecondition(nil), wire.Dependencies...), audit: audit,
		evaluatedAtUnixNano: wire.EvaluatedAt, commitNotBeforeUnixNano: wire.CommitNotBefore,
		commitNotAfterUnixNano: wire.CommitNotAfter, digest: wire.Digest,
	}
	if plan.VerifyDigest() != nil {
		return PendingOwnershipTransferAcceptancePlan{}, ErrPendingPlanInvalid
	}
	return plan, nil
}

type durableTransferPlanWire struct {
	Disposition                OwnershipTransferCollectionDisposition `json:"disposition"`
	EvaluatedAt                int64                                  `json:"evaluated_at"`
	CommitNotBefore            int64                                  `json:"commit_not_before"`
	CommitNotAfter             int64                                  `json:"commit_not_after"`
	ExpectedVersion            uint64                                 `json:"expected_version"`
	ExpectedProgress           [32]byte                               `json:"expected_progress"`
	ExpectedHomeRegion         string                                 `json:"expected_home_region"`
	ExpectedWriterEpoch        uint64                                 `json:"expected_writer_epoch"`
	AuthorizedWriterEpoch      uint64                                 `json:"authorized_writer_epoch"`
	AuthorizedWriterIdentity   string                                 `json:"authorized_writer_identity"`
	AuthorizedWriterHomeRegion string                                 `json:"authorized_writer_home_region"`
	WriterEvidence             [32]byte                               `json:"writer_evidence"`
	Dependencies               []SnapshotPrecondition                 `json:"dependencies"`
	Next                       durableTransferCollectionWire          `json:"next"`
	IdempotencyClaims          []idempotency.Claim                    `json:"idempotency_claims"`
	JoinedAuditSnapshot        idempotency.Snapshot                   `json:"joined_audit_snapshot"`
	IdentifierClaims           []globalid.Claim                       `json:"identifier_claims"`
	Quorum                     bool                                   `json:"quorum"`
	Accepted                   *durableAcceptedTransferWire           `json:"accepted,omitempty"`
	Audit                      *durableAuditWire                      `json:"audit,omitempty"`
	Completions                []idempotency.Claim                    `json:"completions"`
	Digest                     [32]byte                               `json:"digest"`
}

func transferPlanToWire(plan OwnershipTransferApprovalCollectionPlan) *durableTransferPlanWire {
	wire := &durableTransferPlanWire{Disposition: plan.disposition, EvaluatedAt: plan.evaluatedAtUnixNano,
		CommitNotBefore: plan.commitNotBeforeUnixNano, CommitNotAfter: plan.commitNotAfterUnixNano,
		ExpectedVersion: plan.expectedVersion, ExpectedProgress: plan.expectedProgressDigest,
		ExpectedHomeRegion: plan.expectedHomeRegion, ExpectedWriterEpoch: plan.expectedWriterEpoch,
		AuthorizedWriterEpoch:      plan.authorizedWriterEpoch,
		AuthorizedWriterIdentity:   plan.authorizedWriterIdentity,
		AuthorizedWriterHomeRegion: plan.authorizedWriterHomeRegion,
		WriterEvidence:             plan.writerEvidenceDigest,
		Dependencies:               plan.Dependencies(), Next: transferCollectionToWire(plan.next),
		IdempotencyClaims: plan.IdempotencyClaims(), JoinedAuditSnapshot: plan.joinedAuditSnapshot,
		IdentifierClaims: plan.IdentifierClaims(), Quorum: plan.quorumSatisfied,
		Completions: plan.IdempotencyCompletionClaims(), Digest: plan.Digest()}
	if plan.accepted != nil {
		wire.Accepted = acceptedToWire(*plan.accepted)
	}
	if plan.audit != nil {
		audit := auditToWire(*plan.audit)
		wire.Audit = &audit
	}
	return wire
}

func transferPlanFromWire(wire durableTransferPlanWire) (OwnershipTransferApprovalCollectionPlan, error) {
	next, err := transferCollectionFromWire(wire.Next)
	if err != nil {
		return OwnershipTransferApprovalCollectionPlan{}, err
	}
	plan := OwnershipTransferApprovalCollectionPlan{disposition: wire.Disposition,
		evaluatedAtUnixNano: wire.EvaluatedAt, commitNotBeforeUnixNano: wire.CommitNotBefore,
		commitNotAfterUnixNano: wire.CommitNotAfter, expectedVersion: wire.ExpectedVersion,
		expectedProgressDigest: wire.ExpectedProgress, expectedHomeRegion: wire.ExpectedHomeRegion,
		expectedWriterEpoch: wire.ExpectedWriterEpoch, authorizedWriterEpoch: wire.AuthorizedWriterEpoch,
		authorizedWriterIdentity:   wire.AuthorizedWriterIdentity,
		authorizedWriterHomeRegion: wire.AuthorizedWriterHomeRegion,
		writerEvidenceDigest:       wire.WriterEvidence, dependencies: append([]SnapshotPrecondition(nil), wire.Dependencies...),
		next: next, idempotencyClaims: append([]idempotency.Claim(nil), wire.IdempotencyClaims...),
		joinedAuditSnapshot: wire.JoinedAuditSnapshot, identifierClaims: append([]globalid.Claim(nil), wire.IdentifierClaims...),
		quorumSatisfied: wire.Quorum, idempotencyCompletion: append([]idempotency.Claim(nil), wire.Completions...), digest: wire.Digest}
	if wire.Accepted != nil {
		accepted, acceptedErr := acceptedFromWire(*wire.Accepted)
		if acceptedErr != nil {
			return OwnershipTransferApprovalCollectionPlan{}, acceptedErr
		}
		plan.accepted = &accepted
	}
	if wire.Audit != nil {
		audit, auditErr := auditFromWire(*wire.Audit)
		if auditErr != nil {
			return OwnershipTransferApprovalCollectionPlan{}, auditErr
		}
		plan.audit = &audit
	}
	if plan.VerifyDigest() != nil {
		return OwnershipTransferApprovalCollectionPlan{}, ErrPendingPlanInvalid
	}
	return plan, nil
}

type durableReconciliationAuditWire struct {
	AuditEventID        string                 `json:"audit_event_id"`
	EventType           string                 `json:"event_type"`
	ActorIdentity       string                 `json:"actor_identity"`
	ActorKeyID          string                 `json:"actor_key_id"`
	CorrelationID       [16]byte               `json:"correlation_id"`
	CausationID         ccse.OptionalMessageID `json:"causation_id"`
	AuditIdempotencyKey [16]byte               `json:"audit_idempotency_key"`
	SourceDigest        [32]byte               `json:"source_digest"`
	SourceRecord        ccse.Record            `json:"source_record"`
	HasSource           bool                   `json:"has_source"`
	OriginalAuditDigest [32]byte               `json:"original_audit_digest"`
	PolicyDigests       [][32]byte             `json:"policy_digests"`
	SubjectIDs          []string               `json:"subject_ids"`
	CauseCode           string                 `json:"cause_code"`
	OccurredAt          int64                  `json:"occurred_at"`
	FreshRequirement    [32]byte               `json:"fresh_requirement"`
}

type durableReconciliationWire struct {
	OriginalEnvelope         []byte                            `json:"original_envelope"`
	OriginalEnvelopeDigest   [32]byte                          `json:"original_envelope_digest"`
	PendingDigest            [32]byte                          `json:"pending_digest"`
	Disposition              PendingDisposition                `json:"disposition"`
	EvaluatedAt              int64                             `json:"evaluated_at"`
	CommitNotBefore          int64                             `json:"commit_not_before"`
	CommitNotAfter           int64                             `json:"commit_not_after"`
	FailureEvidence          [32]byte                          `json:"failure_evidence"`
	FailureEvidenceValue     durableReconciliationEvidenceWire `json:"failure_evidence_value"`
	FailureResultContentType string                            `json:"failure_result_content_type"`
	FailureResultPayload     []byte                            `json:"failure_result_payload"`
	FailureOutcome           [32]byte                          `json:"failure_outcome"`
	Completions              []idempotency.Claim               `json:"completions"`
	MemberCompletions        []idempotency.CompoundMemberClaim `json:"member_completions,omitempty"`
	Tombstones               []globalid.Claim                  `json:"tombstones"`
	Audit                    durableReconciliationAuditWire    `json:"audit"`
	Digest                   [32]byte                          `json:"digest"`
}

type durableReconciliationEvidenceWire struct {
	Kind                        pendingReconciliationEvidenceKind `json:"kind"`
	Disposition                 PendingDisposition                `json:"disposition"`
	AuditOccurredAt             int64                             `json:"audit_occurred_at"`
	FinalClockPendingDigest     [32]byte                          `json:"final_clock_pending_digest"`
	FinalClockOriginalDeadline  int64                             `json:"final_clock_original_deadline"`
	FinalClockAuditOccurredAt   int64                             `json:"final_clock_audit_occurred_at"`
	FinalClockRequirementDigest [32]byte                          `json:"final_clock_requirement_digest"`
	FailureRecord               ccse.Record                       `json:"failure_record"`
	FailureDigest               [32]byte                          `json:"failure_digest"`
	Digest                      [32]byte                          `json:"digest"`
}

func reconciliationToWire(plan PendingReconciliationPlan) *durableReconciliationWire {
	audit := plan.audit
	return &durableReconciliationWire{OriginalEnvelope: plan.OriginalPendingEnvelopeBytes(),
		OriginalEnvelopeDigest: plan.originalEnvelopeDigest, PendingDigest: plan.pendingDigest,
		Disposition: plan.disposition, EvaluatedAt: plan.evaluatedAtUnixNano,
		CommitNotBefore: plan.commitNotBeforeUnixNano, CommitNotAfter: plan.commitNotAfterUnixNano,
		FailureEvidence: plan.failureEvidenceDigest,
		FailureEvidenceValue: durableReconciliationEvidenceWire{
			Kind: plan.failureEvidence.kind, Disposition: plan.failureEvidence.Disposition(),
			AuditOccurredAt:             plan.failureEvidence.AuditOccurredAtUnixNano(),
			FinalClockPendingDigest:     plan.failureEvidence.FinalClockRequirement().PendingDigest(),
			FinalClockOriginalDeadline:  plan.failureEvidence.FinalClockRequirement().OriginalCommitNotAfterUnixNano(),
			FinalClockAuditOccurredAt:   plan.failureEvidence.FinalClockRequirement().AuditOccurredAtUnixNano(),
			FinalClockRequirementDigest: plan.failureEvidence.FinalClockRequirement().Digest(),
			FailureRecord:               cloneCCSERecord(plan.failureEvidence.failureRecord),
			FailureDigest:               plan.failureEvidence.failureRecordDigest, Digest: plan.failureEvidence.Digest()},
		FailureResultContentType: plan.failureResult.ContentType(), FailureResultPayload: plan.failureResult.Payload(),
		FailureOutcome: plan.failureOutcomeDigest, Completions: plan.IdempotencyCompletionClaims(),
		MemberCompletions: plan.CompoundMemberCompletionClaims(),
		Tombstones:        plan.IdentifierTombstoneAssertions(), Audit: durableReconciliationAuditWire{
			AuditEventID: audit.auditEventID, EventType: audit.eventType, ActorIdentity: audit.logicalActorIdentity,
			ActorKeyID: audit.logicalActorKeyID, CorrelationID: audit.correlationID, CausationID: audit.causationID,
			AuditIdempotencyKey: audit.auditIdempotencyKey, SourceDigest: audit.sourceAuthorizationDigest,
			SourceRecord: cloneCCSERecord(audit.sourceAuthorizationRecord), HasSource: audit.hasSourceAuthorization,
			OriginalAuditDigest: audit.originalAuditIntentDigest,
			PolicyDigests:       cloneDigests(audit.policyDigestsSHA256), SubjectIDs: audit.SubjectIDs(),
			CauseCode: audit.causeCode, OccurredAt: audit.occurredAtUnixNano,
			FreshRequirement: audit.freshRequirementDigest}, Digest: plan.digest}
}

func reconciliationFromWire(wire durableReconciliationWire) (PendingReconciliationPlan, error) {
	evidence, evidenceErr := newPendingReconciliationEvidence(wire.FailureEvidenceValue.Kind,
		wire.FailureEvidenceValue.Disposition, wire.FailureEvidenceValue.FinalClockPendingDigest,
		wire.FailureEvidenceValue.FinalClockOriginalDeadline,
		wire.FailureEvidenceValue.AuditOccurredAt, wire.FailureEvidenceValue.FailureRecord)
	finalClock := evidence.FinalClockRequirement()
	if evidenceErr != nil || evidence.Digest() != wire.FailureEvidenceValue.Digest ||
		evidence.Digest() != wire.FailureEvidence ||
		finalClock.PendingDigest() != wire.FailureEvidenceValue.FinalClockPendingDigest ||
		finalClock.OriginalCommitNotAfterUnixNano() != wire.FailureEvidenceValue.FinalClockOriginalDeadline ||
		finalClock.AuditOccurredAtUnixNano() != wire.FailureEvidenceValue.FinalClockAuditOccurredAt ||
		finalClock.Digest() != wire.FailureEvidenceValue.FinalClockRequirementDigest ||
		evidence.failureRecordDigest != wire.FailureEvidenceValue.FailureDigest {
		return PendingReconciliationPlan{}, ErrPendingPlanInvalid
	}
	audit := ReconciliationAuditRequirement{auditEventID: wire.Audit.AuditEventID,
		eventType: wire.Audit.EventType, logicalActorIdentity: wire.Audit.ActorIdentity,
		logicalActorKeyID: wire.Audit.ActorKeyID, correlationID: wire.Audit.CorrelationID,
		causationID: wire.Audit.CausationID, auditIdempotencyKey: wire.Audit.AuditIdempotencyKey,
		sourceAuthorizationDigest: wire.Audit.SourceDigest,
		sourceAuthorizationRecord: cloneCCSERecord(wire.Audit.SourceRecord),
		hasSourceAuthorization:    wire.Audit.HasSource, originalAuditIntentDigest: wire.Audit.OriginalAuditDigest,
		policyDigestsSHA256: cloneDigests(wire.Audit.PolicyDigests),
		subjectIDs:          append([]string(nil), wire.Audit.SubjectIDs...), causeCode: wire.Audit.CauseCode,
		occurredAtUnixNano: wire.Audit.OccurredAt, freshRequirementDigest: wire.Audit.FreshRequirement}
	plan, err := newPendingReconciliationPlan(wire.PendingDigest, wire.Disposition, wire.EvaluatedAt,
		wire.CommitNotBefore, evidence, wire.Completions, wire.MemberCompletions,
		wire.Tombstones, audit,
		wire.OriginalEnvelope)
	if err != nil || plan.originalEnvelopeDigest != wire.OriginalEnvelopeDigest ||
		plan.commitNotAfterUnixNano != wire.CommitNotAfter ||
		plan.failureResult.ContentType() != wire.FailureResultContentType ||
		!bytes.Equal(plan.failureResult.Payload(), wire.FailureResultPayload) ||
		plan.audit.freshRequirementDigest != wire.Audit.FreshRequirement ||
		plan.failureOutcomeDigest != wire.FailureOutcome || plan.digest != wire.Digest {
		return PendingReconciliationPlan{}, ErrPendingPlanInvalid
	}
	return plan, nil
}

// String keeps codec errors concise without exposing encoded signed evidence.
func (kind DurablePendingKind) String() string {
	switch kind {
	case DurablePendingMutation:
		return "mutation"
	case DurablePendingKeyEnrollment:
		return "key-enrollment"
	case DurablePendingOwnershipTransferCollection:
		return "ownership-transfer-collection"
	case DurablePendingReconciliation:
		return "reconciliation"
	case DurablePendingOwnershipTransferCutover:
		return "ownership-transfer-cutover"
	default:
		return fmt.Sprintf("unknown-%d", kind)
	}
}
