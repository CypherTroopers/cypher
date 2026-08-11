// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
)

type transferByteBudget struct {
	used uint64
}

func (budget *transferByteBudget) add(size uint64) error {
	if size > maxTransferCompoundInputBytes || budget.used > maxTransferCompoundInputBytes-size {
		return ErrTransferAuthorizationRequired
	}
	budget.used += size
	return nil
}

func (budget *transferByteBudget) addString(value string) error {
	return budget.add(uint64(len(value)))
}

func (budget *transferByteBudget) addBytes(value []byte) error {
	return budget.add(uint64(len(value)))
}

func (budget *transferByteBudget) addRecord(record *ccse.Record, messageTypeID uint32,
	payloadLimit int) error {
	if record == nil || record.MessageTypeID != messageTypeID ||
		record.SchemaVersion != (ccse.Version{Major: 1}) {
		return ErrTransferAuthorizationRequired
	}
	size, err := record.PreflightSize(transferVerifiedRecordLimits(payloadLimit))
	if err != nil {
		return ErrTransferAuthorizationRequired
	}
	return budget.add(size)
}

func (budget *transferByteBudget) addMaterial(material KeyMaterialSnapshot) error {
	if len(material.EnrollmentPolicyDigestsSHA256) > 64 {
		return ErrTransferAuthorizationRequired
	}
	for _, value := range []string{material.KeyID, material.SubjectIdentity, material.TargetIdentity.ID,
		material.EnrollmentDomain.EnrollmentDomainID, material.EnrollmentDomain.Environment,
		material.EnrollmentAuthorityIdentity, material.WriterIdentity, material.HomeRegion} {
		if err := budget.addString(value); err != nil {
			return err
		}
	}
	if err := budget.addBytes(material.CanonicalPublicKey); err != nil {
		return err
	}
	if err := budget.addBytes(material.ProofSignature); err != nil {
		return err
	}
	return budget.add(uint64(len(material.EnrollmentPolicyDigestsSHA256)) * 32)
}

func (budget *transferByteBudget) addIdentity(identity IdentitySnapshot) error {
	if len(identity.PolicyDigestsSHA256) > 64 || len(identity.Bindings.DeviceIDs) > 64 {
		return ErrTransferAuthorizationRequired
	}
	if err := budget.addBytes(identity.CanonicalPayload); err != nil {
		return err
	}
	for _, value := range []string{identity.Ref.ID, identity.RecordID, identity.PrincipalIdentity,
		identity.KeyID, identity.HomeRegion, identity.Bindings.ProviderID, identity.Bindings.HostID,
		identity.Bindings.ProviderSiteID, identity.Bindings.AgentID, identity.Bindings.LeaseID,
		identity.Bindings.JobID, identity.Bindings.AttemptID, identity.Bindings.PayoutIdentity,
		identity.Bindings.BillingIdentity, identity.Bindings.Environment} {
		if err := budget.addString(value); err != nil {
			return err
		}
	}
	for _, value := range identity.Bindings.DeviceIDs {
		if err := budget.add(4); err != nil {
			return err
		}
		if err := budget.addString(value); err != nil {
			return err
		}
	}
	return budget.add(uint64(len(identity.PolicyDigestsSHA256)) * 32)
}

func (budget *transferByteBudget) addLifecycle(lifecycle KeyLifecycleSnapshot) error {
	if len(lifecycle.AllowedMessageTypeIDs) > 256 || len(lifecycle.PolicyDigestsSHA256) > 64 {
		return ErrTransferAuthorizationRequired
	}
	if err := budget.addBytes(lifecycle.CanonicalPayload); err != nil {
		return err
	}
	for _, value := range []string{lifecycle.KeyID, lifecycle.RecordID, lifecycle.SubjectIdentity,
		lifecycle.RotationPredecessorKeyID, lifecycle.TransitionReasonCode, lifecycle.HomeRegion} {
		if err := budget.addString(value); err != nil {
			return err
		}
	}
	if err := budget.add(uint64(len(lifecycle.AllowedMessageTypeIDs)) * 4); err != nil {
		return err
	}
	return budget.add(uint64(len(lifecycle.PolicyDigestsSHA256)) * 32)
}

func (budget *transferByteBudget) addProfile(profile OwnershipTransferProfile) error {
	if err := budget.addString(profile.ProfileID); err != nil {
		return err
	}
	for _, values := range [][]OwnershipTransferAuthorityRequirement{profile.OldAuthorities, profile.NewAuthorities} {
		for _, value := range values {
			for _, field := range []string{value.Identity, value.KeyID, value.ProviderID,
				value.OrganizationID, value.Role} {
				if err := budget.addString(field); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (budget *transferByteBudget) addReceiver(receiver ReceiverProfile) error {
	encoded, err := canonicalReceiverProfile(receiver)
	if err != nil {
		return ErrTransferAuthorizationRequired
	}
	return budget.addBytes(encoded)
}

func (budget *transferByteBudget) addHistorical(snapshot HistoricalKeyAuthorizationSnapshot) error {
	if err := budget.addMaterial(snapshot.Material); err != nil {
		return err
	}
	if err := budget.addLifecycle(snapshot.Lifecycle); err != nil {
		return err
	}
	return budget.addIdentity(snapshot.Identity)
}

func preflightTransferSnapshot(profile OwnershipTransferProfile,
	approvals []OwnershipTransferAuthorityAdmission, fixed OwnershipTransferFixedEvidence,
	canonical []byte) error {
	budget := transferByteBudget{}
	return preflightTransferSnapshotInto(&budget, profile, approvals, fixed, canonical)
}

func preflightTransferSnapshotInto(budget *transferByteBudget, profile OwnershipTransferProfile,
	approvals []OwnershipTransferAuthorityAdmission, fixed OwnershipTransferFixedEvidence,
	canonical []byte) error {
	if budget == nil {
		return ErrTransferAuthorizationRequired
	}
	if len(canonical) == 0 || len(canonical) > 196608 || len(approvals) == 0 ||
		len(approvals) > maxTransferAuthorities || len(profile.OldAuthorities) == 0 ||
		len(profile.OldAuthorities) > 32 || len(profile.NewAuthorities) == 0 ||
		len(profile.NewAuthorities) > 32 || len(fixed.KeyClosureRecords) == 0 ||
		len(fixed.KeyClosureRecords) > 256 ||
		len(fixed.KeyClosureSnapshots) != len(fixed.KeyClosureRecords) ||
		len(fixed.EvidenceRecords) == 0 || len(fixed.EvidenceRecords) > 64 ||
		len(fixed.EvidenceAdmissions) != len(fixed.EvidenceRecords) ||
		len(fixed.ClosurePreconditions) > 2048 || len(fixed.EvidencePreconditions) > 512 {
		return ErrTransferAuthorizationRequired
	}
	if err := budget.addBytes(canonical); err != nil {
		return err
	}
	if err := budget.addProfile(profile); err != nil {
		return err
	}
	if err := budget.addIdentity(fixed.PreviousTerminalIdentity); err != nil {
		return err
	}
	if err := budget.addIdentity(fixed.NextPendingIdentity); err != nil {
		return err
	}
	for index := range approvals {
		approval := &approvals[index]
		if len(approval.CurrentPreconditions) > 8 ||
			budget.addRecord(&approval.Signed.record, schema.MessageTypeOwnershipTransferAuthorization, 196608) != nil ||
			budget.addHistorical(approval.Historical) != nil ||
			budget.addReceiver(approval.Receiver) != nil {
			return ErrTransferAuthorizationRequired
		}
	}
	for index := range fixed.KeyClosureRecords {
		if budget.addRecord(&fixed.KeyClosureRecords[index].record,
			schema.MessageTypeKeyLifecycle, 32768) != nil ||
			budget.addLifecycle(fixed.KeyClosureSnapshots[index]) != nil {
			return ErrTransferAuthorizationRequired
		}
	}
	for index := range fixed.EvidenceRecords {
		if budget.addRecord(&fixed.EvidenceRecords[index].record,
			schema.MessageTypeEvidenceRecord, 262144) != nil ||
			budget.addHistorical(fixed.EvidenceAdmissions[index].Historical) != nil ||
			budget.addReceiver(fixed.EvidenceAdmissions[index].Receiver) != nil {
			return ErrTransferAuthorizationRequired
		}
	}
	return nil
}

func preflightTransferCollection(snapshot OwnershipTransferApprovalCollectionSnapshot) error {
	return preflightTransferSnapshot(snapshot.Profile, snapshot.Approvals,
		snapshot.FixedEvidence, snapshot.CanonicalPayload)
}

// preflightTransferAcceptanceInput applies one aggregate allocation budget to
// the untrusted stored collection and every detached cutover record before the
// collection is cloned or an AuthenticatedEvidenceRecord getter is invoked.
func preflightTransferAcceptanceInput(collection OwnershipTransferApprovalCollectionSnapshot,
	command OwnershipTransferCutoverCommand) error {
	budget := transferByteBudget{}
	if err := preflightTransferSnapshotInto(&budget, collection.Profile, collection.Approvals,
		collection.FixedEvidence, collection.CanonicalPayload); err != nil {
		return err
	}
	if len(command.AuthenticatedEvidence) != 3 || len(command.KeyClosureWriterFences) > 256 {
		return ErrTransferAuthorizationRequired
	}
	for _, value := range command.AuthenticatedEvidence {
		switch value.MessageTypeID() {
		case schema.MessageTypeAgentIdentity, schema.MessageTypeHostIdentity,
			schema.MessageTypeDeviceIdentity, schema.MessageTypeKeyLifecycle:
		default:
			return ErrTransferAuthorizationRequired
		}
		size, err := value.PreflightSize(transferVerifiedRecordLimits(32768))
		if value.SchemaVersion() != (ccse.Version{Major: 1}) || err != nil || size == 0 ||
			budget.add(size) != nil {
			return ErrTransferAuthorizationRequired
		}
	}
	material := command.NewKeyEnrollment.Material
	for _, value := range []string{material.ClaimedKeyID, material.SubjectIdentity,
		material.TargetIdentity.ID, material.EnrollmentDomain.EnrollmentDomainID,
		material.EnrollmentDomain.Environment, material.EnrollmentAuthorityIdentity,
		material.CauseCode, material.Fence.Entity.ID, material.Fence.WriterIdentity,
		material.Fence.HomeRegion} {
		if err := budget.addString(value); err != nil {
			return err
		}
	}
	if len(material.EnrollmentPolicyDigestsSHA256) > 64 ||
		budget.addBytes(material.CanonicalPublicKey) != nil ||
		budget.addBytes(material.ProofSignature) != nil ||
		budget.add(uint64(len(material.EnrollmentPolicyDigestsSHA256))*32) != nil {
		return ErrTransferAuthorizationRequired
	}
	// Account for bounded fence strings and list headers even when strings are
	// empty; otherwise a large slice of zero values could allocate beyond the
	// aggregate byte fence.
	for _, fence := range command.KeyClosureWriterFences {
		if budget.add(64) != nil || budget.addString(fence.Entity.ID) != nil ||
			budget.addString(fence.WriterIdentity) != nil || budget.addString(fence.HomeRegion) != nil {
			return ErrTransferAuthorizationRequired
		}
	}
	return nil
}
