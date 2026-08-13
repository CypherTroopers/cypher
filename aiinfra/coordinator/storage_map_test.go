// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package coordinator

import (
	"fmt"
	"testing"

	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/governance"
	"github.com/cypherium/cypher/aiinfra/iam"
	"github.com/cypherium/cypher/aiinfra/storage/postgres"
)

func TestFinalIdentifierAssertionsAcceptExactMaxWithoutDuplicateAppend(t *testing.T) {
	claims := make([]globalid.Claim, 0, globalid.MaxClaims)
	for index := 0; index < globalid.MaxClaims-1; index++ {
		claim, err := globalid.Reserve(fmt.Sprintf("identifier-%03d", index), globalid.Owner{
			Domain: globalid.OwnerCanonicalRecord, ID: fmt.Sprintf("record-%03d", index),
		})
		if err != nil {
			t.Fatal(err)
		}
		claims = append(claims, claim)
	}
	const eventID = "cph-audit-v1:00000000000000000000000000000001"
	event, err := globalid.Reserve(eventID, globalid.Owner{
		Domain: globalid.OwnerGovernanceAuditEvent, ID: eventID,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims = append(claims, event)
	normalized, err := normalizeFinalIdentifierAssertions(claims, event)
	if err != nil || len(normalized) != globalid.MaxClaims {
		t.Fatalf("maximal assertion set: len=%d err=%v", len(normalized), err)
	}
	missing := append([]globalid.Claim(nil), claims[:len(claims)-1]...)
	if _, err := normalizeFinalIdentifierAssertions(missing, event); err == nil {
		t.Fatal("missing joined AuditEvent assertion was accepted")
	}
}

func TestCanonicalStateCatalogsRemainByteExact(t *testing.T) {
	governanceCases := []struct{ semantic, storageKind, semanticType, storageType string }{
		{governance.CanonicalStateKindGovernancePolicyRegistry, string(postgres.CanonicalStateGovernancePolicyRegistry), governance.CanonicalStateContentTypeGovernancePolicyRegistry, postgres.CanonicalStateGovernancePolicyRegistryContentType},
		{governance.CanonicalStateKindGovernanceProfileActivation, string(postgres.CanonicalStateGovernanceProfileActivation), governance.CanonicalStateContentTypeGovernanceProfileActivation, postgres.CanonicalStateGovernanceProfileActivationContentType},
	}
	for _, item := range governanceCases {
		if item.semantic != item.storageKind || item.semanticType != item.storageType {
			t.Fatalf("governance/storage canonical state catalog drift: %#v", item)
		}
	}
	iamCases := []struct{ semantic, storageKind, semanticType, storageType string }{
		{iam.CanonicalStateKindIAMKeyMaterial, string(postgres.CanonicalStateIAMKeyMaterial), iam.CanonicalStateContentTypeIAMKeyMaterial, postgres.CanonicalStateIAMKeyMaterialContentType},
		{iam.CanonicalStateKindIAMIdentity, string(postgres.CanonicalStateIAMIdentity), iam.CanonicalStateContentTypeIAMIdentity, postgres.CanonicalStateIAMIdentityContentType},
		{iam.CanonicalStateKindIAMKeyLifecycle, string(postgres.CanonicalStateIAMKeyLifecycle), iam.CanonicalStateContentTypeIAMKeyLifecycle, postgres.CanonicalStateIAMKeyLifecycleContentType},
		{iam.CanonicalStateKindIAMAcceptedOwnershipTransfer, string(postgres.CanonicalStateIAMAcceptedOwnershipTransfer), iam.CanonicalStateContentTypeIAMAcceptedOwnershipTransfer, postgres.CanonicalStateIAMAcceptedOwnershipTransferContentType},
		{iam.CanonicalStateKindIAMProofChallenge, string(postgres.CanonicalStateIAMProofChallenge), iam.CanonicalStateContentTypeIAMProofChallenge, postgres.CanonicalStateIAMProofChallengeContentType},
		{iam.CanonicalStateKindIAMPrincipalIdentityIndex, string(postgres.CanonicalStateIAMPrincipalIdentityIndex), iam.CanonicalStateContentTypeIAMPrincipalIdentityIndex, postgres.CanonicalStateIAMPrincipalIdentityIndexContentType},
		{iam.CanonicalStateKindIAMRotationPredecessorIndex, string(postgres.CanonicalStateIAMRotationPredecessorIndex), iam.CanonicalStateContentTypeIAMRotationPredecessorIndex, postgres.CanonicalStateIAMRotationPredecessorIndexContentType},
		{iam.CanonicalStateKindIAMSubjectKeySet, string(postgres.CanonicalStateIAMSubjectKeySet), iam.CanonicalStateContentTypeIAMSubjectKeySet, postgres.CanonicalStateIAMSubjectKeySetContentType},
		{iam.CanonicalStateKindIAMWriterLease, string(postgres.CanonicalStateIAMWriterLease), iam.CanonicalStateContentTypeIAMWriterLease, postgres.CanonicalStateIAMWriterLeaseContentType},
		{iam.CanonicalStateKindIAMTransferProfileActivation, string(postgres.CanonicalStateIAMTransferProfileActivation), iam.CanonicalStateContentTypeIAMTransferProfileActivation, postgres.CanonicalStateIAMTransferProfileActivationContentType},
	}
	for _, item := range iamCases {
		if item.semantic != item.storageKind || item.semanticType != item.storageType {
			t.Fatalf("IAM/storage canonical state catalog drift: %#v", item)
		}
	}
}

func TestCanonicalStateMappingRejectsUnknownOrCrossNamespaceRows(t *testing.T) {
	if _, err := mapGovernanceCanonicalState(governance.CanonicalStateRecord{}); err == nil {
		t.Fatal("zero Governance state row was accepted")
	}
	if _, err := mapIAMCanonicalState(iam.CanonicalStateRecord{}); err == nil {
		t.Fatal("zero IAM state row was accepted")
	}
	value := iam.CanonicalStateRecord{Namespace: iam.CanonicalStateNamespaceIAM,
		Kind: iam.CanonicalStateKindIAMIdentity, ContentType: governance.CanonicalStateContentTypeGovernancePolicyRegistry}
	if _, err := mapIAMCanonicalState(value); err == nil {
		t.Fatal("cross-domain content type was accepted")
	}
}
