// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/iam"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
	"github.com/cypherium/cypher/aiinfra/schema/foundation/v1/canonical"
)

const joinedIAMEvidenceOriginEventID = "joined-iam-admission-origin"

// joinedIAMView is deliberately independent of Governance's IAM adapter. It
// creates a real opaque iam.JoinedAuditRequest through IAM's public planner,
// then the test installs only IAM's resolved authorization snapshot into the
// Governance view. This catches accidental coupling to private IAM fields.
type joinedIAMView struct {
	identities         map[iam.EntityRef]iam.IdentitySnapshot
	materials          map[string]iam.KeyMaterialSnapshot
	lifecycles         map[string]iam.KeyLifecycleSnapshot
	challenges         map[[ccse.DigestSize]byte]iam.ProofChallengeSnapshot
	leases             map[iam.EntityRef]iam.WriterLeaseSnapshot
	transfers          map[[ccse.DigestSize]byte]iam.OwnershipTransferSnapshot
	globalIDs          map[string]globalid.Snapshot
	idempotency        map[[ccse.MessageIDSize]byte]idempotency.Snapshot
	collections        map[[ccse.MessageIDSize]byte]iam.OwnershipTransferApprovalCollectionSnapshot
	accepted           map[[ccse.DigestSize]byte]iam.AcceptedOwnershipTransferSnapshot
	compoundMembers    map[[ccse.MessageIDSize]byte]idempotency.CompoundMemberSnapshot
	pendingPersistence map[[ccse.MessageIDSize]byte]joinedIAMPendingPersistence
	clockAt            int64
}

type joinedIAMPendingPersistence struct {
	revision iam.IAMPendingStoredRevision
	evidence []iam.IAMPersistenceEvidenceRecord
}

func newJoinedIAMView() *joinedIAMView {
	return &joinedIAMView{
		identities: make(map[iam.EntityRef]iam.IdentitySnapshot), materials: make(map[string]iam.KeyMaterialSnapshot),
		lifecycles: make(map[string]iam.KeyLifecycleSnapshot), challenges: make(map[[ccse.DigestSize]byte]iam.ProofChallengeSnapshot),
		leases: make(map[iam.EntityRef]iam.WriterLeaseSnapshot), transfers: make(map[[ccse.DigestSize]byte]iam.OwnershipTransferSnapshot),
		globalIDs: make(map[string]globalid.Snapshot), idempotency: make(map[[ccse.MessageIDSize]byte]idempotency.Snapshot),
		collections:        make(map[[ccse.MessageIDSize]byte]iam.OwnershipTransferApprovalCollectionSnapshot),
		accepted:           make(map[[ccse.DigestSize]byte]iam.AcceptedOwnershipTransferSnapshot),
		compoundMembers:    make(map[[ccse.MessageIDSize]byte]idempotency.CompoundMemberSnapshot),
		pendingPersistence: make(map[[ccse.MessageIDSize]byte]joinedIAMPendingPersistence),
	}
}

func (v *joinedIAMView) SnapshotIAMPendingPersistence(_ context.Context, key [ccse.MessageIDSize]byte,
	revision uint64, _ [][ccse.DigestSize]byte) (iam.IAMPendingStoredRevision,
	[]iam.IAMPersistenceEvidenceRecord, bool, error) {
	value, ok := v.pendingPersistence[key]
	if !ok || value.revision.Revision != revision {
		return iam.IAMPendingStoredRevision{}, nil, false, nil
	}
	result := value.revision
	result.CanonicalEnvelope = append([]byte(nil), value.revision.CanonicalEnvelope...)
	result.EvidenceDigestsSHA256 = append([][ccse.DigestSize]byte(nil), value.revision.EvidenceDigestsSHA256...)
	evidence := make([]iam.IAMPersistenceEvidenceRecord, len(value.evidence))
	for index := range value.evidence {
		evidence[index] = value.evidence[index]
		evidence[index].CanonicalContent = append([]byte(nil), value.evidence[index].CanonicalContent...)
	}
	return result, evidence, true, nil
}

func joinedIAMCanonicalStateSpec(entity iam.EntityRef) (string, string, bool) {
	switch entity.Kind {
	case iam.EntityIdentity:
		return iam.CanonicalStateKindIAMIdentity, iam.CanonicalStateContentTypeIAMIdentity, true
	case iam.EntityKeyMaterial:
		return iam.CanonicalStateKindIAMKeyMaterial, iam.CanonicalStateContentTypeIAMKeyMaterial, true
	case iam.EntityKeyLifecycle:
		return iam.CanonicalStateKindIAMKeyLifecycle, iam.CanonicalStateContentTypeIAMKeyLifecycle, true
	case iam.EntityOwnershipTransfer:
		return iam.CanonicalStateKindIAMAcceptedOwnershipTransfer,
			iam.CanonicalStateContentTypeIAMAcceptedOwnershipTransfer, true
	case iam.EntityOwnershipTransferProfileActivation:
		return iam.CanonicalStateKindIAMTransferProfileActivation,
			iam.CanonicalStateContentTypeIAMTransferProfileActivation, true
	default:
		return "", "", false
	}
}

func joinedIAMSidecarSpec(kind string) (string, bool) {
	switch kind {
	case iam.CanonicalStateKindIAMProofChallenge:
		return iam.CanonicalStateContentTypeIAMProofChallenge, true
	case iam.CanonicalStateKindIAMPrincipalIdentityIndex:
		return iam.CanonicalStateContentTypeIAMPrincipalIdentityIndex, true
	case iam.CanonicalStateKindIAMRotationPredecessorIndex:
		return iam.CanonicalStateContentTypeIAMRotationPredecessorIndex, true
	case iam.CanonicalStateKindIAMSubjectKeySet:
		return iam.CanonicalStateContentTypeIAMSubjectKeySet, true
	case iam.CanonicalStateKindIAMWriterLease:
		return iam.CanonicalStateContentTypeIAMWriterLease, true
	default:
		return "", false
	}
}

func (v *joinedIAMView) CanonicalIAMSidecarState(_ context.Context, request iam.CanonicalIAMSidecarRequest) (
	iam.CanonicalStateRecord, bool, iam.CanonicalStateRecord, bool, error) {
	contentType, ok := joinedIAMSidecarSpec(request.Kind)
	if !ok || request.ObjectID == "" {
		return iam.CanonicalStateRecord{}, false, iam.CanonicalStateRecord{}, false, iam.ErrViewInconsistent
	}
	record := func(next bool, version uint64) iam.CanonicalStateRecord {
		digest, canonical, terminal, eventID := request.ExpectedStateDigestSHA256,
			request.ExpectedCanonicalState, request.ExpectedTerminal, "historical:"+request.ObjectID
		if next {
			digest, canonical, terminal, eventID = request.NextStateDigestSHA256,
				request.NextCanonicalState, request.NextTerminal, request.AuditEventID
		}
		return iam.CanonicalStateRecord{
			Namespace: iam.CanonicalStateNamespaceIAM, Kind: request.Kind, ObjectID: request.ObjectID,
			Version: version, StateDigestSHA256: digest, ContentType: contentType,
			CanonicalState: append([]byte(nil), canonical...), Terminal: terminal, AuditEventID: eventID,
		}
	}
	var expected iam.CanonicalStateRecord
	if request.ExpectedPresent {
		version := request.ExpectedVersion
		if version == 0 {
			version = 1
		}
		expected = record(false, version)
	}
	var next iam.CanonicalStateRecord
	if request.NextPresent {
		version := request.NextVersion
		if version == 0 {
			version = 1
			if request.ExpectedPresent {
				version = expected.Version + 1
			}
		}
		next = record(true, version)
	}
	return expected, request.ExpectedPresent, next, request.NextPresent, nil
}

func (v *joinedIAMView) CanonicalIAMStateAssertion(_ context.Context, precondition iam.SnapshotPrecondition,
	_ string) (iam.CanonicalStateRecord, bool, error) {
	kind, contentType, ok := joinedIAMCanonicalStateSpec(precondition.Entity)
	if !ok || precondition.ExpectedStateVersion == 0 || precondition.ExpectedSnapshotDigest == ([32]byte{}) {
		return iam.CanonicalStateRecord{}, false, iam.ErrViewInconsistent
	}
	canonical := append([]byte("joined-iam-assertion-v1\x00"), precondition.ExpectedSnapshotDigest[:]...)
	return iam.CanonicalStateRecord{
		Namespace: iam.CanonicalStateNamespaceIAM, Kind: kind, ObjectID: precondition.Entity.ID,
		Version: precondition.ExpectedStateVersion, StateDigestSHA256: precondition.ExpectedSnapshotDigest,
		ContentType: contentType, CanonicalState: canonical,
		AuditEventID: "historical:" + precondition.Entity.ID,
	}, true, nil
}

func (v *joinedIAMView) CanonicalIAMStateTransition(_ context.Context, request iam.CanonicalIAMStateTransition) (
	iam.CanonicalStateRecord, bool, iam.CanonicalStateRecord, error) {
	kind, contentType, ok := joinedIAMCanonicalStateSpec(request.Entity)
	if !ok {
		return iam.CanonicalStateRecord{}, false, iam.CanonicalStateRecord{}, iam.ErrViewInconsistent
	}
	next := iam.CanonicalStateRecord{
		Namespace: iam.CanonicalStateNamespaceIAM, Kind: kind, ObjectID: request.Entity.ID,
		Version: request.NextVersion, StateDigestSHA256: request.SemanticStateDigestSHA256,
		ContentType: contentType, CanonicalState: append([]byte(nil), request.CanonicalSemanticState...),
		Terminal: request.Terminal, AuditEventID: request.AuditEventID,
		HasValidityWindow: request.HasValidityWindow, ValidFromUnixNano: request.ValidFromUnixNano,
		ValidUntilUnixNano: request.ValidUntilUnixNano,
	}
	if request.ExpectedAbsent {
		return iam.CanonicalStateRecord{}, false, next, nil
	}
	canonical := append([]byte("joined-iam-expected-v1\x00"), request.ExpectedStateDigestSHA256[:]...)
	expected := iam.CanonicalStateRecord{
		Namespace: iam.CanonicalStateNamespaceIAM, Kind: kind, ObjectID: request.Entity.ID,
		Version: request.ExpectedVersion, StateDigestSHA256: request.ExpectedStateDigestSHA256,
		ContentType: contentType, CanonicalState: canonical, AuditEventID: "historical:" + request.Entity.ID,
		HasValidityWindow: request.HasValidityWindow, ValidFromUnixNano: request.ValidFromUnixNano,
		ValidUntilUnixNano: request.ValidUntilUnixNano,
	}
	return expected, true, next, nil
}

func (v *joinedIAMView) LookupBusinessIdempotency(_ context.Context, key [ccse.MessageIDSize]byte) (idempotency.Snapshot, bool, error) {
	value, ok := v.idempotency[key]
	return value, ok, nil
}

func (v *joinedIAMView) SnapshotBusinessIdempotencyPair(_ context.Context, parent, joined [ccse.MessageIDSize]byte) (idempotency.Snapshot, bool, idempotency.Snapshot, bool, error) {
	parentValue, parentOK := v.idempotency[parent]
	joinedValue, joinedOK := v.idempotency[joined]
	return parentValue, parentOK, joinedValue, joinedOK, nil
}

func (v *joinedIAMView) SnapshotCompoundMemberState(_ context.Context, key [ccse.MessageIDSize]byte) (idempotency.CompoundMemberSnapshot, bool, idempotency.Snapshot, bool, idempotency.Snapshot, bool, error) {
	member, found := v.compoundMembers[key]
	if !found {
		return idempotency.CompoundMemberSnapshot{}, false, idempotency.Snapshot{}, false, idempotency.Snapshot{}, false, nil
	}
	parent, parentOK := v.idempotency[member.ParentBinding.Key]
	joined, err := idempotency.JoinedAuditBinding(member.ParentBinding)
	if err != nil {
		return idempotency.CompoundMemberSnapshot{}, false, idempotency.Snapshot{}, false, idempotency.Snapshot{}, false, err
	}
	audit, auditOK := v.idempotency[joined.Key]
	return member, true, parent, parentOK, audit, auditOK, nil
}

func (v *joinedIAMView) LookupGlobalID(_ context.Context, identifier string) (globalid.Snapshot, bool, error) {
	value, ok := v.globalIDs[identifier]
	return value, ok, nil
}

func (v *joinedIAMView) LookupIdentity(_ context.Context, ref iam.EntityRef) (iam.IdentitySnapshot, bool, error) {
	value, ok := v.identities[ref]
	return value, ok, nil
}

func (v *joinedIAMView) LookupIdentityByPrincipal(_ context.Context, kind uint32, principal string) (iam.IdentitySnapshot, bool, error) {
	var result iam.IdentitySnapshot
	found := false
	for _, value := range v.identities {
		if value.Ref.PrincipalKind != kind || value.PrincipalIdentity != principal {
			continue
		}
		if found {
			return iam.IdentitySnapshot{}, false, fmt.Errorf("duplicate IAM principal")
		}
		result, found = value, true
	}
	return result, found, nil
}

func (v *joinedIAMView) LookupKeyMaterial(_ context.Context, keyID string) (iam.KeyMaterialSnapshot, bool, error) {
	value, ok := v.materials[keyID]
	return value, ok, nil
}

func (v *joinedIAMView) LookupKeyLifecycle(_ context.Context, keyID string) (iam.KeyLifecycleSnapshot, bool, error) {
	value, ok := v.lifecycles[keyID]
	return value, ok, nil
}

func (v *joinedIAMView) LookupSubjectKeyLifecycles(_ context.Context, kind uint32, principal string) ([]iam.KeyLifecycleSnapshot, error) {
	result := make([]iam.KeyLifecycleSnapshot, 0)
	for _, value := range v.lifecycles {
		if value.SubjectKind == kind && value.SubjectIdentity == principal {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].KeyID < result[j].KeyID })
	return result, nil
}

func (v *joinedIAMView) LookupRotationSuccessor(_ context.Context, predecessor string) (iam.KeyLifecycleSnapshot, bool, error) {
	var result iam.KeyLifecycleSnapshot
	found := false
	for _, value := range v.lifecycles {
		if !value.HasRotationPredecessor || value.RotationPredecessorKeyID != predecessor {
			continue
		}
		if found {
			return iam.KeyLifecycleSnapshot{}, false, fmt.Errorf("duplicate IAM rotation successor")
		}
		result, found = value, true
	}
	return result, found, nil
}

func (v *joinedIAMView) LookupOwnershipTransfer(_ context.Context, digest [ccse.DigestSize]byte) (iam.OwnershipTransferSnapshot, bool, error) {
	value, ok := v.transfers[digest]
	return value, ok, nil
}

func (v *joinedIAMView) LookupIdentityAt(ctx context.Context, ref iam.EntityRef, at int64) (iam.IdentitySnapshot, bool, error) {
	value, found, err := v.LookupIdentity(ctx, ref)
	if err != nil || !found || value.CreatedAtUnixNano > at {
		return iam.IdentitySnapshot{}, false, err
	}
	return value, true, nil
}

func (v *joinedIAMView) LookupKeyLifecycleAt(ctx context.Context, keyID string, at int64) (iam.KeyLifecycleSnapshot, bool, error) {
	value, found, err := v.LookupKeyLifecycle(ctx, keyID)
	if err != nil || !found || value.CreatedAtUnixNano > at {
		return iam.KeyLifecycleSnapshot{}, false, err
	}
	return value, true, nil
}

func (v *joinedIAMView) SnapshotOwnershipTransferApprovalCollection(_ context.Context, key [ccse.MessageIDSize]byte) (iam.OwnershipTransferApprovalCollectionSnapshot, bool, error) {
	value, ok := v.collections[key]
	return value, ok, nil
}

func (v *joinedIAMView) LookupAcceptedOwnershipTransfer(_ context.Context, digest [ccse.DigestSize]byte) (iam.AcceptedOwnershipTransferSnapshot, bool, error) {
	value, ok := v.accepted[digest]
	return value, ok, nil
}

func (v *joinedIAMView) LookupProofChallenge(_ context.Context, challenge [ccse.DigestSize]byte) (iam.ProofChallengeSnapshot, bool, error) {
	value, ok := v.challenges[challenge]
	return value, ok, nil
}

func (v *joinedIAMView) LookupWriterLease(_ context.Context, ref iam.EntityRef) (iam.WriterLeaseSnapshot, bool, error) {
	value, ok := v.leases[ref]
	return value, ok, nil
}

func (v *joinedIAMView) SnapshotReconciliationTransactionClock(_ context.Context, pending [ccse.DigestSize]byte, deadline int64) (iam.ReconciliationTransactionClockSnapshot, error) {
	return iam.NewReconciliationTransactionClockSnapshot("governance-joined-test-tx", v.clockAt, pending, deadline)
}

type joinedIAMProfile struct{ governance Profile }

func (*joinedIAMProfile) ValidateAuthority(context.Context, iam.AuthorityRequest) error { return nil }
func (*joinedIAMProfile) ValidateEnrollmentAuthority(context.Context, iam.EnrollmentAuthorityRequest) error {
	return nil
}
func (*joinedIAMProfile) ValidateIdentityTransition(context.Context, iam.IdentityTransitionRequest) error {
	return nil
}
func (*joinedIAMProfile) ValidateAllowedMessageTypes(context.Context, iam.AllowedMessageTypesRequest) error {
	return nil
}
func (*joinedIAMProfile) OwnershipTransferProfile(context.Context, iam.OwnershipTransferProfileRequest) (iam.OwnershipTransferProfile, error) {
	return iam.OwnershipTransferProfile{}, iam.ErrTransferAuthorizationRequired
}
func (*joinedIAMProfile) OwnershipTransferProfileAt(context.Context, iam.OwnershipTransferProfileHistoryRequest) (iam.OwnershipTransferProfile, error) {
	return iam.OwnershipTransferProfile{}, iam.ErrTransferAuthorizationRequired
}
func (*joinedIAMProfile) ValidateOwnershipTransferEvidence(context.Context, iam.OwnershipTransferEvidenceRequest) error {
	return iam.ErrTransferAuthorizationRequired
}
func (*joinedIAMProfile) ValidateOwnershipTransferEvidenceAt(context.Context, iam.OwnershipTransferEvidenceHistoryRequest) error {
	return iam.ErrTransferAuthorizationRequired
}

func (p *joinedIAMProfile) ReceiverProfile(_ context.Context, messageTypeID uint32) (iam.ReceiverProfile, error) {
	registry, err := schema.LoadDefault()
	if err != nil {
		return iam.ReceiverProfile{}, err
	}
	message, ok := registry.LookupMessage(messageTypeID)
	if !ok {
		return iam.ReceiverProfile{}, iam.ErrUnknownMessageType
	}
	return iam.ReceiverProfile{
		ProtocolVersion: p.governance.ProtocolVersion, SchemaVersion: p.governance.SchemaVersion,
		Purpose: message.Purpose, Audience: append([]string(nil), p.governance.Audience...),
		TenantOrganization: p.governance.TenantOrganization, ProviderOrganization: p.governance.ProviderOrganization,
		Environment: p.governance.Environment, EnrollmentDomainID: p.governance.EnrollmentDomainID,
		ChainID: p.governance.ChainID, GenesisHash: p.governance.GenesisHash,
		ReplayDomainID: "iam/governance-joined/test", CounterKind: ccse.CounterExpectedGeneration,
		MaxClockSkewNanos: p.governance.MaxClockSkewNanos, MaxValidityWindowNanos: p.governance.MaxRecordValidityNanos,
		MaxPlanCommitLatencyNanos: p.governance.MaxPlanCommitLatencyNanos,
	}, nil
}

type joinedIAMScenario struct {
	governance *governanceFixture
	iamView    *joinedIAMView
	iamPlanner *iam.Planner
	pending    iam.PendingMutationPlan
	request    iam.JoinedAuditRequest
	sourceKey  GovernanceKeySnapshot
	evaluated  int64
}

func newJoinedIAMScenario(t testing.TB) joinedIAMScenario {
	t.Helper()
	governance := newGovernanceFixture(t)
	evaluated := testBaseTime + int64(30*time.Minute)
	view := newJoinedIAMView()
	profile := &joinedIAMProfile{governance: governance.profile}
	planner, err := iam.NewDefaultPlanner(view, profile)
	if err != nil {
		t.Fatal(err)
	}

	authorizerRef := iam.EntityRef{Kind: iam.EntityIdentity, PrincipalKind: 8, ID: "iam-authorization-writer"}
	authorizerMaterial, authorizerPrivate := joinedIAMMaterial(t, governance.profile, 0x81,
		"spiffe://cph.test/service/iam-authorization-writer", authorizerRef, evaluated)
	authorizerLifecycle := joinedIAMLifecycle(t, authorizerMaterial, schema.MessageTypeServiceIdentity,
		2, "iam-authorization-lifecycle", testID(0x82), evaluated)
	authorizerIdentity := joinedIAMServiceIdentity(t, authorizerMaterial, 2,
		"iam-authorization-identity", testID(0x83), evaluated)
	view.materials[authorizerMaterial.KeyID] = authorizerMaterial
	view.lifecycles[authorizerMaterial.KeyID] = authorizerLifecycle
	view.identities[authorizerRef] = authorizerIdentity
	installJoinedIAMGlobalIDs(view, authorizerMaterial)

	targetRef := iam.EntityRef{Kind: iam.EntityIdentity, PrincipalKind: 8, ID: "governance-joined-target"}
	targetMaterial, _ := joinedIAMMaterial(t, governance.profile, 0x91,
		"spiffe://cph.test/service/governance-joined-target", targetRef, evaluated)
	targetLifecycle := joinedIAMLifecycle(t, targetMaterial, schema.MessageTypeServiceIdentity,
		2, "governance-joined-target-lifecycle", testID(0x92), evaluated)
	view.materials[targetMaterial.KeyID] = targetMaterial
	view.lifecycles[targetMaterial.KeyID] = targetLifecycle
	installJoinedIAMGlobalIDs(view, targetMaterial)

	projection := joinedIAMServiceProjection(targetMaterial, 1,
		"governance-joined-target-pending", testID(0x93), evaluated)
	normalized, err := iam.NormalizeIdentity(projection)
	if err != nil {
		t.Fatal(err)
	}
	correlation := testID(0x94)
	authorization := joinedIAMAuthorization(t, governance.profile, profile, authorizerMaterial,
		authorizerPrivate, normalized, targetRef, correlation, evaluated)
	leaseDigest := testDigest(0x95)
	view.leases[targetRef] = iam.WriterLeaseSnapshot{
		Entity: targetRef, WriterIdentity: authorizerMaterial.SubjectIdentity, HomeRegion: "eu-test-1", WriterEpoch: 7,
		ValidFromUnixNano: evaluated - int64(time.Hour), ValidUntilUnixNano: evaluated + int64(2*time.Hour), EvidenceDigest: leaseDigest,
	}
	pending, err := planner.PlanIdentity(context.Background(), iam.IdentityCommand{
		Projection: projection, ActorIdentity: authorizerMaterial.SubjectIdentity, EvaluatedAtUnixNano: evaluated,
		CorrelationID: correlation, CauseCode: "governance-joined-integration",
		Fence: iam.WriterFence{Entity: targetRef, WriterIdentity: authorizerMaterial.SubjectIdentity,
			HomeRegion: "eu-test-1", WriterEpoch: 7, EvidenceDigest: leaseDigest},
		Authorization: authorization,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := pending.JoinedAuditRequest()
	if err != nil || request.VerifyDigest() != nil {
		t.Fatalf("IAM joined request: %v / %v", err, request.VerifyDigest())
	}
	request, err = planner.BindCanonicalStateCapabilities(context.Background(), request)
	if err != nil || request.VerifyDigest() != nil {
		t.Fatalf("IAM canonical state binding: %v / %v", err, request.VerifyDigest())
	}
	installJoinedIAMPersistence(t, view, request)
	request, err = planner.BindPendingPersistenceCapability(context.Background(), request)
	if err != nil || request.VerifyDigest() != nil {
		t.Fatalf("IAM pending persistence binding: %v / %v", err, request.VerifyDigest())
	}

	resolver, err := iam.NewDefaultKeySnapshotResolver(view)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ResolveKeySnapshot(context.Background(), authorizerMaterial.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	sourceKey := joinedGovernanceKey(resolved, governance.profile)
	governance.iam.keys[sourceKey.KeyID] = cloneKeySnapshot(sourceKey)
	governance.iam.historical[sourceKey.KeyID] = cloneKeySnapshot(sourceKey)
	installJoinedGovernanceState(t, governance, request)
	return joinedIAMScenario{governance: governance, iamView: view, iamPlanner: planner,
		pending: pending, request: request, sourceKey: sourceKey, evaluated: evaluated}
}

func TestPlanIAMJoinedAuditOpaqueBundleSuccessAndTamper(t *testing.T) {
	scenario := newJoinedIAMScenario(t)
	request := scenario.request
	bundle, ok := request.AuditEvidenceBundle()
	if !ok || bundle.VerifyFor(request) != nil {
		t.Fatal("IAM typed evidence bundle was not available")
	}
	receipt := bundle.CanonicalBytes()
	receipt[0] ^= 1
	if bundle.CanonicalBytes()[0] == receipt[0] {
		t.Fatal("IAM bundle canonical getter aliases retained bytes")
	}
	source, ok := bundle.SourceAuthorizationRecord()
	if !ok {
		t.Fatal("IAM bundle omitted source authorization")
	}
	source.Signature[0] ^= 1
	detached, _ := bundle.SourceAuthorizationRecord()
	if detached.Signature[0] == source.Signature[0] {
		t.Fatal("IAM bundle source getter aliases retained signature")
	}

	intent := joinedSuccessAuditIntent(t, scenario)
	audit := scenario.governance.auditCommandForIntent(t, 1,
		scenario.governance.profile.AuditDeploymentAnchorSHA256, intent)
	if _, linkErr := iamPendingEvidenceLinks(request, bundle.SourceAuthorizationDigest(),
		request.JoinedAuditEventID()); linkErr != nil {
		t.Fatalf("IAM persistence evidence bridge: %v", linkErr)
	}
	fragment, err := scenario.governance.planner.PlanIAMJoinedAudit(context.Background(), IAMJoinedAuditCommand{
		AtUnixNano: scenario.evaluated, Request: request, AuditEvent: audit.Event,
	})
	if err != nil || fragment.CommitReady() || fragment.VerifyDigest() != nil {
		t.Fatalf("joined success fragment = %#v / %v", fragment, err)
	}
	snapshot := fragment.Snapshot()
	if snapshot.IAMAuditEvidenceBundleDigestSHA256 != bundle.Digest() ||
		snapshot.IAMAuditEvidenceBundleDomain != iamAuditEvidenceReceiptDomain ||
		len(snapshot.AuditSourceDigestsSHA256) != 2 || len(snapshot.AuditSourceEvidence) != 2 ||
		len(snapshot.AuditSourceStorageCapabilities) != 2 ||
		len(snapshot.AuditSourceKeyPreconditions) != 1 || len(snapshot.CanonicalStateAssertions) != 1 ||
		snapshot.CanonicalStateAssertions[0].VerifyDigest() != nil ||
		snapshot.CanonicalStateAssertions[0].Record().Kind != CanonicalStateKindGovernanceProfileActivation {
		t.Fatalf("joined evidence closure = %#v", snapshot)
	}
	if len(snapshot.CanonicalKeyStateAssertions) != 2 {
		t.Fatalf("joined canonical key read set = %#v", snapshot.CanonicalKeyStateAssertions)
	}
	keyReadSet := map[string]bool{}
	for _, assertion := range snapshot.CanonicalKeyStateAssertions {
		if assertion.VerifyDigest() != nil || len(assertion.Records()) != 3 {
			t.Fatalf("joined canonical key assertion = %#v", assertion)
		}
		keyReadSet[assertion.KeyPrecondition().KeyID] = true
	}
	if !keyReadSet[scenario.sourceKey.KeyID] || !keyReadSet[scenario.governance.profile.AuditWriterKeyID] {
		t.Fatalf("joined canonical key set = %#v", keyReadSet)
	}
	if snapshot.CanonicalAuditWriterLeaseAssertion.VerifyDigest() != nil ||
		snapshot.CanonicalAuditWriterLeaseAssertion.Requirement() != auditWriterLeaseRequirement(
			scenario.governance.audit.head, scenario.governance.keys["key-audit"].snapshot) ||
		snapshot.CanonicalAuditWriterLeaseAssertion.Record().Kind != CanonicalStateKindIAMWriterLease {
		t.Fatalf("joined canonical audit writer lease = %#v", snapshot.CanonicalAuditWriterLeaseAssertion)
	}
	kinds := map[EvidenceKind]bool{}
	for _, evidence := range snapshot.AuditSourceEvidence {
		kinds[evidence.Kind()] = true
	}
	if !kinds[EvidenceSignedCCSERecord] || !kinds[EvidenceSemanticReceipt] {
		t.Fatalf("joined evidence kinds = %#v", kinds)
	}
	storageKinds := map[DurableEvidenceStorageKind]bool{}
	sourceStorageFound := false
	sourceStorageIndex := -1
	for index, capability := range snapshot.AuditSourceStorageCapabilities {
		storageKinds[capability.Kind()] = true
		if capability.VerifyDigest() != nil ||
			capability.AuditAssertionEventID() != snapshot.JoinedAuditEventID ||
			!containsDigest(snapshot.AuditSourceDigestsSHA256, capability.EvidenceDigest()) {
			t.Fatalf("joined storage capability = %#v", capability)
		}
		if capability.EvidenceDigest() == bundle.SourceAuthorizationDigest() {
			sourceStorageFound = true
			sourceStorageIndex = index
			key, revision, linked := capability.PendingLink()
			if capability.Disposition() != DurableEvidenceStorageAssertExisting || !linked ||
				key != request.ParentBinding().Key || revision != request.ParentExpectedSnapshot().Version ||
				capability.ContentType() != iam.IAMEvidenceContentTypeSignedCCSERecord ||
				capability.ExpectedAuditEventID() != joinedIAMEvidenceOriginEventID {
				t.Fatalf("IAM source persistence closure = %#v", capability)
			}
		} else if capability.Disposition() != DurableEvidenceStorageReserveNew {
			t.Fatalf("fresh semantic receipt was not reserved = %#v", capability)
		}
	}
	if !sourceStorageFound || !storageKinds[DurableEvidenceStorageSignedCCSE] || !storageKinds[DurableEvidenceStorageSemantic] {
		t.Fatalf("joined storage capability kinds = %#v", storageKinds)
	}
	for name, mutate := range map[string]func(*DurableEvidenceStorageCapability){
		"immutable origin":  func(value *DurableEvidenceStorageCapability) { value.expectedAuditEventID += "-other" },
		"current assertion": func(value *DurableEvidenceStorageCapability) { value.auditAssertionEventID += "-other" },
		"pending revision":  func(value *DurableEvidenceStorageCapability) { value.pendingRevision++ },
		"typed IAM proof":   func(value *DurableEvidenceStorageCapability) { value.iamExistingProof = nil },
	} {
		t.Run("reject source persistence tamper "+name, func(t *testing.T) {
			tampered := fragment.audit.Snapshot()
			mutate(&tampered.AuditSourceStorageCapabilities[sourceStorageIndex])
			if (MutationPlan{value: tampered, digest: fragment.audit.Digest()}).VerifyDigest() == nil {
				t.Fatalf("%s tamper retained the audit plan", name)
			}
		})
	}
	if snapshot.CanonicalAuditAppend.VerifyDigest() != nil ||
		snapshot.CanonicalAuditAppend.EventID() != snapshot.JoinedAuditEventID ||
		snapshot.CanonicalAuditAppend.RecordDigest() != snapshot.NextAuditRecordDigestSHA256 ||
		!bytes.Equal(snapshot.CanonicalAuditAppend.CanonicalEvent(), snapshot.AuditEventEvidence.Record().Payload) {
		t.Fatalf("joined canonical audit append = %#v", snapshot.CanonicalAuditAppend)
	}
	domain, receipt, receiptDigest := bundle.SemanticReceipt()
	semanticFound := false
	for _, capability := range snapshot.AuditSourceStorageCapabilities {
		if capability.Kind() != DurableEvidenceStorageSemantic {
			continue
		}
		semanticFound = true
		var decodedDomain string
		var decodedReceipt []byte
		if err := ccse.Unmarshal(capability.CanonicalContent(), durableEvidenceStorageMaxBytes, func(in *ccse.Decoder) error {
			version, decodeErr := in.Uint32()
			if decodeErr != nil || version != durableEvidenceStorageCodecVersion {
				return ErrAuditEvidence
			}
			codec, decodeErr := in.String(255)
			if decodeErr != nil || codec != durableSemanticStorageCodec {
				return ErrAuditEvidence
			}
			decodedDomain, decodeErr = in.String(255)
			if decodeErr != nil {
				return decodeErr
			}
			decodedReceipt, decodeErr = in.Bytes(durableEvidenceStorageMaxBytes)
			return decodeErr
		}); err != nil || decodedDomain != domain || capability.EvidenceDigest() != receiptDigest ||
			!bytes.Equal(decodedReceipt, receipt) {
			t.Fatal("semantic storage codec did not retain the exact domain and receipt")
		}
	}
	if !semanticFound {
		t.Fatal("semantic storage capability is absent")
	}
	detachedCapabilities := snapshot.AuditSourceStorageCapabilities
	detachedCapabilities[0].canonicalContent[0] ^= 1
	if bytes.Equal(detachedCapabilities[0].canonicalContent,
		fragment.Snapshot().AuditSourceStorageCapabilities[0].CanonicalContent()) {
		t.Fatal("joined fragment storage capability aliases retained bytes")
	}
	tamperedPlan := fragment.audit.Snapshot()
	tamperedPlan.AuditSourceStorageCapabilities[0].canonicalContent[0] ^= 1
	if (MutationPlan{value: tamperedPlan, digest: fragment.audit.Digest()}).VerifyDigest() == nil {
		t.Fatal("tampered joined storage capability retained the audit plan")
	}
	tamperedKeys := fragment.audit.Snapshot()
	tamperedKeys.CanonicalKeyStateAssertions[0].records[0].record.CanonicalState[0] ^= 1
	if (MutationPlan{value: tamperedKeys, digest: fragment.audit.Digest()}).VerifyDigest() == nil {
		t.Fatal("tampered joined key read assertion retained the audit plan")
	}
	missingKeys := fragment.audit.Snapshot()
	missingKeys.CanonicalKeyStateAssertions = missingKeys.CanonicalKeyStateAssertions[1:]
	if (MutationPlan{value: missingKeys, digest: fragment.audit.Digest()}).VerifyDigest() == nil {
		t.Fatal("missing joined key read assertion retained the audit plan")
	}
	tamperedLease := fragment
	tamperedLeaseAudit := fragment.audit.Snapshot()
	tamperedLeaseAudit.CanonicalAuditWriterLeaseAssertion.record.record.CanonicalState[0] ^= 1
	tamperedLease.audit = MutationPlan{value: tamperedLeaseAudit, digest: fragment.audit.Digest()}
	if tamperedLease.VerifyDigest() == nil {
		t.Fatal("tampered joined audit writer lease assertion retained the fragment")
	}
	detachedLease := snapshot.CanonicalAuditWriterLeaseAssertion.Record()
	detachedLease.CanonicalState[0] ^= 1
	if bytes.Equal(detachedLease.CanonicalState,
		fragment.Snapshot().CanonicalAuditWriterLeaseAssertion.Record().CanonicalState) {
		t.Fatal("joined audit writer lease getter aliases retained bytes")
	}

	tampered := scenario.governance.mutateAndResignAudit(t, audit.Event,
		func(event *foundationv1.AuditEventSigningProjection) {
			event.EvidenceDigestsSHA256 = event.EvidenceDigestsSHA256[:1]
		})
	if _, err := scenario.governance.planner.PlanIAMJoinedAudit(context.Background(), IAMJoinedAuditCommand{
		AtUnixNano: scenario.evaluated, Request: request, AuditEvent: tampered,
	}); err == nil {
		t.Fatal("AuditEvent missing the IAM bundle root was accepted")
	}
}

func TestPlanIAMJoinedAuditReconciliationUsesHistoricalCausationAndFreshWriter(t *testing.T) {
	scenario := newJoinedIAMScenario(t)
	envelope, err := scenario.pending.DurableEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := iam.DecodeDurablePendingEnvelope(envelope.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	scenario.iamView.clockAt = scenario.pending.CommitNotAfterUnixNano()
	evidence, err := scenario.iamPlanner.PreparePendingReconciliationEvidenceAt(context.Background(), decoded,
		iam.PendingDispositionExpired, ccse.AuthenticatedEvidenceRecord{}, scenario.pending.CommitNotAfterUnixNano())
	if err != nil {
		t.Fatal(err)
	}
	reconciliation, err := scenario.pending.PlanReconciliation(iam.PendingReconciliationCommand{
		Disposition: iam.PendingDispositionExpired, EvaluatedAtUnixNano: evidence.AuditOccurredAtUnixNano(), Evidence: evidence,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := reconciliation.JoinedAuditRequest()
	if err != nil || request.VerifyDigest() != nil {
		t.Fatalf("reconciliation request = %v / %v", err, request.VerifyDigest())
	}
	request, err = scenario.iamPlanner.BindPendingPersistenceCapability(context.Background(), request)
	if err != nil || request.VerifyDigest() != nil {
		t.Fatalf("reconciliation persistence binding = %v / %v", err, request.VerifyDigest())
	}
	installJoinedGovernanceState(t, scenario.governance, request)

	// Prove the original signer is not consulted as current authority. Its
	// immutable historical row remains available while current lookup fails.
	delete(scenario.governance.iam.keys, scenario.sourceKey.KeyID)
	requirement, ok := request.ReconciliationAuditRequirement()
	if !ok || !requirement.FreshReconcilerAuthorityRequired() {
		t.Fatal("fresh reconciliation requirement missing")
	}
	intent := AuditIntentSnapshot{
		Required: true, StreamID: scenario.governance.profile.AuditReplayDomainID,
		EventType: requirement.EventType(), AuditEventID: requirement.AuditEventID(),
		ActorIdentity: scenario.governance.profile.AuditWriterIdentity,
		ActorKeyID:    scenario.governance.profile.AuditWriterKeyID,
		SubjectIDs:    requirement.SubjectIDs(), CauseCode: requirement.CauseCode(),
		OccurredAtUnixNano: requirement.OccurredAtUnixNano(), Outcome: request.ExpectedOutcome(),
		IdempotencyKey: requirement.AuditIdempotencyKey(), CorrelationID: requirement.CorrelationID(),
		CausationID: requirement.CausationID(),
		AppliedPolicyDigestsSHA256: uniqueSortedDigests(append(requirement.PolicyDigestsSHA256(),
			scenario.sourceKey.AuthorizationPolicyDigestSHA256, scenario.governance.profileDigest)),
		EvidenceDigestsSHA256: requestAuditSources(t, request),
	}
	audit := scenario.governance.auditCommandForIntent(t, 1,
		scenario.governance.profile.AuditDeploymentAnchorSHA256, intent)
	fragment, err := scenario.governance.planner.PlanIAMJoinedAudit(context.Background(), IAMJoinedAuditCommand{
		AtUnixNano: requirement.OccurredAtUnixNano(), Request: request, AuditEvent: audit.Event,
	})
	if err != nil || fragment.VerifyDigest() != nil {
		t.Fatalf("historical reconciliation fragment = %#v / %v", fragment, err)
	}
	snapshot := fragment.Snapshot()
	if snapshot.CanonicalAuditIntent.ActorIdentity != scenario.governance.profile.AuditWriterIdentity ||
		snapshot.CanonicalAuditIntent.ActorKeyID != scenario.governance.profile.AuditWriterKeyID ||
		len(snapshot.AuditSourceKeyPreconditions) != 0 ||
		snapshot.AuditWriterKeyPrecondition.KeyID != scenario.governance.profile.AuditWriterKeyID {
		t.Fatalf("historical/current authority split = %#v", snapshot)
	}
	if len(snapshot.CanonicalKeyStateAssertions) != 1 ||
		snapshot.CanonicalKeyStateAssertions[0].KeyPrecondition().KeyID != scenario.governance.profile.AuditWriterKeyID ||
		snapshot.CanonicalKeyStateAssertions[0].VerifyDigest() != nil {
		t.Fatalf("reconciliation current key read set = %#v", snapshot.CanonicalKeyStateAssertions)
	}

	tampered := scenario.governance.mutateAndResignAudit(t, audit.Event,
		func(event *foundationv1.AuditEventSigningProjection) {
			event.ActorIdentity = requirement.LogicalActorIdentity()
			event.ActorKeyID = requirement.LogicalActorKeyID()
		})
	if _, err := scenario.governance.planner.PlanIAMJoinedAudit(context.Background(), IAMJoinedAuditCommand{
		AtUnixNano: requirement.OccurredAtUnixNano(), Request: request, AuditEvent: tampered,
	}); err == nil {
		t.Fatal("historical signer was accepted as fresh reconciliation authority")
	}

	forgedHistory := cloneKeySnapshot(scenario.sourceKey)
	forgedHistory.PublicKey[0] ^= 1
	scenario.governance.iam.historical[scenario.sourceKey.KeyID] = forgedHistory
	if _, err := scenario.governance.planner.PlanIAMJoinedAudit(context.Background(), IAMJoinedAuditCommand{
		AtUnixNano: requirement.OccurredAtUnixNano(), Request: request, AuditEvent: audit.Event,
	}); err == nil {
		t.Fatal("historical IAM key substitution was accepted")
	}
}

func joinedSuccessAuditIntent(t testing.TB, scenario joinedIAMScenario) AuditIntentSnapshot {
	t.Helper()
	iamIntent, ok := scenario.request.ExpectedAuditIntent()
	if !ok {
		t.Fatal("IAM success audit intent missing")
	}
	return AuditIntentSnapshot{
		Required: true, StreamID: scenario.governance.profile.AuditReplayDomainID,
		EventType: iamIntent.EventType(), AuditEventID: scenario.request.JoinedAuditEventID(),
		ActorIdentity: iamIntent.ActorIdentity(), ActorKeyID: iamIntent.ActorKeyID(),
		SubjectIDs: iamIntent.SubjectIDs(), CauseCode: iamIntent.CauseCode(),
		OccurredAtUnixNano: iamIntent.OccurredAtUnixNano(), Outcome: scenario.request.ExpectedOutcome(),
		IdempotencyKey: scenario.request.JoinedBinding().Key, CorrelationID: iamIntent.CorrelationID(),
		CausationID: iamIntent.CausationID(),
		AppliedPolicyDigestsSHA256: uniqueSortedDigests(append(iamIntent.PolicyDigestsSHA256(),
			scenario.sourceKey.AuthorizationPolicyDigestSHA256, scenario.governance.profileDigest)),
		EvidenceDigestsSHA256: requestAuditSources(t, scenario.request),
	}
}

func requestAuditSources(t testing.TB, request iam.JoinedAuditRequest) [][ccse.DigestSize]byte {
	t.Helper()
	bundle, ok := request.AuditEvidenceBundle()
	if !ok || bundle.VerifyFor(request) != nil {
		t.Fatal("invalid IAM evidence bundle")
	}
	return bundle.AuditSourceDigestsSHA256()
}

func installJoinedGovernanceState(t testing.TB, fixture *governanceFixture, request iam.JoinedAuditRequest) {
	t.Helper()
	fixture.idempotency.snapshots[request.ParentBinding().Key] = request.ParentExpectedSnapshot()
	fixture.idempotency.snapshots[request.JoinedBinding().Key] = request.JoinedExpectedSnapshot()
	claim := request.JoinedAuditEventIdentifierAssertion()
	if claim.Mode != globalid.AssertExisting || claim.Identifier != request.JoinedAuditEventID() {
		t.Fatalf("joined AuditEvent assertion = %#v", claim)
	}
	fixture.ids.ids[claim.Identifier] = globalid.Snapshot{
		Identifier: claim.Identifier, Owner: claim.ExpectedOwner, Version: claim.ExpectedVersion,
	}
}

func installJoinedIAMPersistence(t testing.TB, view *joinedIAMView, request iam.JoinedAuditRequest) {
	t.Helper()
	bundle, ok := request.AuditEvidenceBundle()
	if !ok || bundle.VerifyFor(request) != nil {
		t.Fatal("cannot seed persistence without IAM evidence bundle")
	}
	source, ok := bundle.SourceAuthorizationRecord()
	if !ok {
		t.Fatal("IAM evidence bundle omitted source record")
	}
	sourceDigest := bundle.SourceAuthorizationDigest()
	preimage, err := source.Preimage(ccse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	canonicalSource, err := ccse.Marshal(2<<20, func(out *ccse.Encoder) {
		out.Bytes(preimage)
		out.Bytes(source.Signature)
	})
	if err != nil {
		t.Fatal(err)
	}
	references := request.EvidenceReferences()
	records := make([]iam.IAMPersistenceEvidenceRecord, 0, len(references))
	digests := make([][ccse.DigestSize]byte, 0, len(references))
	for _, reference := range references {
		record := iam.IAMPersistenceEvidenceRecord{
			DigestSHA256: reference.Digest, Kind: iam.IAMEvidenceSemanticReceipt,
			ContentType:          "application/cph.aiinfra.iam.evidence.v1",
			CanonicalContent:     append([]byte("semantic:"), reference.Digest[:]...),
			ExpectedAuditEventID: request.JoinedAuditEventID(),
		}
		if reference.Digest == sourceDigest {
			record.Kind = iam.IAMEvidenceSignedCCSERecord
			record.ContentType = iam.IAMEvidenceContentTypeSignedCCSERecord
			record.CanonicalContent = canonicalSource
			record.ExpectedAuditEventID = joinedIAMEvidenceOriginEventID
		}
		records = append(records, record)
		digests = append(digests, reference.Digest)
	}
	sort.Slice(digests, func(i, j int) bool { return bytes.Compare(digests[i][:], digests[j][:]) < 0 })
	view.pendingPersistence[request.ParentBinding().Key] = joinedIAMPendingPersistence{
		revision: iam.IAMPendingStoredRevision{
			PendingKey: request.ParentBinding().Key, Kind: request.Kind(), Codec: "cph.aiinfra.iam.pending.v1",
			CodecVersion: request.CodecVersion(), Revision: request.ParentExpectedSnapshot().Version,
			EnvelopeDigestSHA256: request.DurableEnvelopeDigest(), CanonicalEnvelope: request.DurableEnvelopeBytes(),
			EvidenceDigestsSHA256: digests, Status: iam.IAMPendingStatusOpen,
			CommitNotBeforeUnixNano: request.CommitNotBeforeUnixNano(),
			CommitNotAfterUnixNano:  request.CommitNotAfterUnixNano(), ExpectedAuditEventID: request.JoinedAuditEventID(),
		},
		evidence: records,
	}
}

func joinedIAMMaterial(t testing.TB, profile Profile, seed byte, subject string,
	target iam.EntityRef, evaluated int64) (iam.KeyMaterialSnapshot, ed25519.PrivateKey) {
	t.Helper()
	seedBytes := make([]byte, ed25519.SeedSize)
	for index := range seedBytes {
		seedBytes[index] = seed
	}
	private := ed25519.NewKeyFromSeed(seedBytes)
	public := append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)
	keyID, err := iam.DeriveKeyID(ccse.SignatureAlgorithmEd25519, public)
	if err != nil {
		t.Fatal(err)
	}
	challenge := testDigest(seed + 1)
	expires := evaluated + int64(4*time.Hour)
	domain := iam.EnrollmentDomain{EnrollmentDomainID: profile.EnrollmentDomainID,
		Environment: profile.Environment, GenesisHash: profile.GenesisHash}
	proof, err := iam.ProofOfPossessionDigest(keyID, subject, target.PrincipalKind, target,
		[ccse.DigestSize]byte{}, domain, challenge, expires)
	if err != nil {
		t.Fatal(err)
	}
	material := iam.KeyMaterialSnapshot{
		KeyID: keyID, Algorithm: ccse.SignatureAlgorithmEd25519, CanonicalPublicKey: public,
		SubjectIdentity: subject, SubjectKind: target.PrincipalKind, TargetIdentity: target,
		EnrollmentDomain: domain, ProofChallenge: challenge, ProofExpiresAtUnixNano: expires,
		ProofSignature: ed25519.Sign(private, proof[:]), ProofDigest: proof,
		ChallengeEvidenceDigest:       testDigest(seed + 2),
		EnrollmentAuthorityIdentity:   "spiffe://cph.test/service/enrollment-authority",
		EnrollmentPolicyDigestsSHA256: [][ccse.DigestSize]byte{testDigest(seed + 3)},
		WriterIdentity:                "spiffe://cph.test/service/iam-writer", HomeRegion: "eu-test-1",
		WriterEpoch: 7, StateVersion: 1, IdempotencyKey: testID(seed + 4),
	}
	material.EnrollmentBindingDigest, err = joinedIAMEnrollmentBindingDigest(material)
	if err != nil {
		t.Fatal(err)
	}
	return material, append(ed25519.PrivateKey(nil), private...)
}

func joinedIAMEnrollmentBindingDigest(material iam.KeyMaterialSnapshot) ([ccse.DigestSize]byte, error) {
	policies := append([][ccse.DigestSize]byte(nil), material.EnrollmentPolicyDigestsSHA256...)
	sortDigests(policies)
	elements := make([][]byte, len(policies))
	for index := range policies {
		encoded, err := ccse.Marshal(36, func(out *ccse.Encoder) {
			out.FixedBytes(policies[index][:], ccse.DigestSize)
		})
		if err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		elements[index] = encoded
	}
	encoded, err := ccse.Marshal(32768, func(out *ccse.Encoder) {
		out.String(material.KeyID)
		out.String(material.SubjectIdentity)
		out.Uint32(material.SubjectKind)
		out.Uint32(uint32(material.TargetIdentity.Kind))
		out.Uint32(material.TargetIdentity.PrincipalKind)
		out.String(material.TargetIdentity.ID)
		out.FixedBytes(material.TransferEvidenceDigest[:], ccse.DigestSize)
		out.String(material.EnrollmentDomain.EnrollmentDomainID)
		out.String(material.EnrollmentDomain.Environment)
		out.FixedBytes(material.EnrollmentDomain.GenesisHash[:], ccse.DigestSize)
		out.FixedBytes(material.ProofDigest[:], ccse.DigestSize)
		out.FixedBytes(material.ChallengeEvidenceDigest[:], ccse.DigestSize)
		out.String(material.EnrollmentAuthorityIdentity)
		out.EncodedSet(elements)
	})
	if err != nil {
		return [ccse.DigestSize]byte{}, err
	}
	return domainSeparatedContentDigest("CPH-AIIE-IAM-ENROLLMENT-BINDING-V1\x00", encoded), nil
}

func joinedIAMLifecycle(t testing.TB, material iam.KeyMaterialSnapshot, messageType uint32,
	state uint32, recordID string, idempotencyKey [ccse.MessageIDSize]byte, evaluated int64) iam.KeyLifecycleSnapshot {
	t.Helper()
	projection := foundationv1.KeyLifecycleSigningProjection{
		Metadata: joinedIAMMetadata(recordID, idempotencyKey, testDigest(0xa1), evaluated-int64(10*time.Minute)),
		KeyID:    material.KeyID, SubjectIdentity: material.SubjectIdentity, SubjectKind: material.SubjectKind,
		Algorithm: uint32(material.Algorithm), State: state,
		NotBeforeUnixNano: evaluated - int64(time.Hour), NotAfterUnixNano: evaluated + int64(3*time.Hour),
		AllowedMessageTypeIDs: []uint32{messageType}, AuthorizationPolicyDigestSHA256: testDigest(0xa2),
	}
	value, err := iam.NormalizeKeyLifecycle(projection)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func joinedIAMServiceProjection(material iam.KeyMaterialSnapshot, state uint32, recordID string,
	idempotencyKey [ccse.MessageIDSize]byte, evaluated int64) foundationv1.ServiceIdentitySigningProjection {
	return foundationv1.ServiceIdentitySigningProjection{
		Metadata:  joinedIAMMetadata(recordID, idempotencyKey, testDigest(0xa3), evaluated-int64(2*time.Minute)),
		ServiceID: material.TargetIdentity.ID, ServiceName: material.TargetIdentity.ID,
		SPIFFEID: material.SubjectIdentity, DeploymentEnvironment: material.EnrollmentDomain.Environment,
		KeyID: material.KeyID, CredentialGeneration: 1,
		ValidFromUnixNano: evaluated - int64(time.Hour), ValidUntilUnixNano: evaluated + int64(3*time.Hour), State: state,
	}
}

func joinedIAMServiceIdentity(t testing.TB, material iam.KeyMaterialSnapshot, state uint32,
	recordID string, idempotencyKey [ccse.MessageIDSize]byte, evaluated int64) iam.IdentitySnapshot {
	t.Helper()
	value, err := iam.NormalizeIdentity(joinedIAMServiceProjection(material, state, recordID, idempotencyKey, evaluated))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func joinedIAMMetadata(recordID string, idempotencyKey [ccse.MessageIDSize]byte,
	policy [ccse.DigestSize]byte, created int64) foundationv1.RecordMetadataSigningProjection {
	return foundationv1.RecordMetadataSigningProjection{
		SchemaVersion: foundationv1.SchemaVersionSigningProjection{Major: 1}, RecordID: recordID,
		CreatedAtUnixNano: created, IntegrityDigest: sha256.Sum256([]byte("joined-iam:" + recordID)),
		HomeRegion: "eu-test-1", WriterEpoch: 7, StateVersion: 1,
		IdempotencyKey: idempotencyKey, PolicyDigestsSHA256: [][ccse.DigestSize]byte{policy},
	}
}

func joinedIAMAuthorization(t testing.TB, governance Profile, profile *joinedIAMProfile,
	material iam.KeyMaterialSnapshot, private ed25519.PrivateKey, target iam.IdentitySnapshot,
	replayEntity iam.EntityRef, correlation [ccse.MessageIDSize]byte, evaluated int64) iam.VerifiedAuthorization {
	t.Helper()
	receiver, err := profile.ReceiverProfile(context.Background(), target.MessageTypeID)
	if err != nil {
		t.Fatal(err)
	}
	replayDomain, err := iam.DeriveEntityReplayDomainID(receiver.ReplayDomainID, replayEntity)
	if err != nil {
		t.Fatal(err)
	}
	issued := evaluated - int64(time.Minute)
	expires := evaluated + int64(90*time.Minute)
	domain := ccse.Domain{
		Purpose: receiver.Purpose, SenderIdentity: material.SubjectIdentity,
		Audience: append([]string(nil), receiver.Audience...), TenantOrganization: receiver.TenantOrganization,
		ProviderOrganization: receiver.ProviderOrganization, Environment: governance.Environment,
		ChainID: governance.ChainID, GenesisHash: governance.GenesisHash,
		ProtocolVersion: governance.ProtocolVersion, SchemaVersion: governance.SchemaVersion,
		SignatureAlgorithm: ccse.SignatureAlgorithmEd25519, SignatureKeyID: material.KeyID,
		IssuedAtUnixNano: issued, ExpiresAtUnixNano: expires,
		CounterKind: ccse.CounterExpectedGeneration, ReplayDomainID: replayDomain,
	}
	envelope := ccse.Envelope{
		ProtocolVersion: governance.ProtocolVersion, SchemaVersion: governance.SchemaVersion,
		MessageID: testID(0xb1), CorrelationID: correlation, SenderIdentity: material.SubjectIdentity,
		ChainID: governance.ChainID, Environment: governance.Environment,
		IssuedAtUnixNano: issued, ExpiresAtUnixNano: expires,
		CounterKind:        ccse.CounterExpectedGeneration,
		SignatureAlgorithm: ccse.SignatureAlgorithmEd25519, SignatureKeyID: material.KeyID,
	}
	record, err := ccse.NewRecord(target.MessageTypeID, governance.SchemaVersion, domain, envelope, target.CanonicalPayload)
	if err != nil {
		t.Fatal(err)
	}
	if err := record.SignEd25519(private, ccse.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	keys := ccse.NewMemoryKeyRegistry()
	if err := keys.Add(ccse.KeyRecord{
		KeyID: material.KeyID, SubjectIdentity: material.SubjectIdentity,
		Algorithm: material.Algorithm, PublicKey: append([]byte(nil), material.CanonicalPublicKey...),
		NotBeforeUnixNano: evaluated - int64(time.Hour), NotAfterUnixNano: evaluated + int64(3*time.Hour),
		AllowedMessageTypes: []uint32{target.MessageTypeID},
	}); err != nil {
		t.Fatal(err)
	}
	validator, err := canonical.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	verifier := ccse.Verifier{
		Expectations: ccse.Expectations{
			MessageTypeID: target.MessageTypeID, SchemaVersion: governance.SchemaVersion,
			ProtocolVersion: governance.ProtocolVersion, Purpose: receiver.Purpose,
			SenderIdentity: ccse.OptionalString{Present: true, Value: material.SubjectIdentity},
			Audience:       append([]string(nil), receiver.Audience...), TenantOrganization: receiver.TenantOrganization,
			ProviderOrganization: receiver.ProviderOrganization, Environment: governance.Environment,
			ChainID: governance.ChainID, GenesisHash: governance.GenesisHash,
			ReplayDomainID: replayDomain, CounterKind: ccse.CounterExpectedGeneration,
			MaxClockSkew: time.Duration(governance.MaxClockSkewNanos), MaxValidityWindow: time.Duration(governance.MaxRecordValidityNanos),
		},
		Limits: ccse.DefaultLimits(), Clock: ccse.ClockFunc(func() time.Time { return time.Unix(0, evaluated) }),
		Keys: keys, Replay: ccse.NewMemoryReplayStore(), Schema: validator,
		Handle: func(context.Context, ccse.VerifiedRecord) ([ccse.DigestSize]byte, error) {
			return testDigest(0xb2), nil
		},
	}
	result, err := verifier.Verify(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	return iam.AuthorizationFromVerifiedRecord(result.Verified)
}

func installJoinedIAMGlobalIDs(view *joinedIAMView, material iam.KeyMaterialSnapshot) {
	view.globalIDs[material.KeyID] = globalid.Snapshot{Identifier: material.KeyID,
		Owner: globalid.Owner{Domain: globalid.OwnerIAMKey, ID: material.KeyID}, Version: 1}
	owner := globalid.Owner{Domain: globalid.OwnerIAMIdentity,
		ID: fmt.Sprintf("iam-identity-v1:%d:%d:%s", material.TargetIdentity.PrincipalKind,
			len(material.TargetIdentity.ID), material.TargetIdentity.ID)}
	view.globalIDs[material.TargetIdentity.ID] = globalid.Snapshot{
		Identifier: material.TargetIdentity.ID, Owner: owner, Version: 1,
	}
	view.globalIDs[material.SubjectIdentity] = globalid.Snapshot{
		Identifier: material.SubjectIdentity, Owner: owner, Version: 1,
	}
}

func joinedGovernanceKey(resolved iam.ResolvedKeySnapshot, profile Profile) GovernanceKeySnapshot {
	return GovernanceKeySnapshot{
		KeyID: resolved.KeyID, SubjectIdentity: resolved.SubjectIdentity,
		TargetIdentityKind: uint32(resolved.TargetIdentity.Kind), TargetPrincipalKind: resolved.TargetIdentity.PrincipalKind,
		TargetIdentityID: resolved.TargetIdentity.ID, OrganizationIdentity: "spiffe://cph.test/org/iam",
		Algorithm: resolved.Algorithm, PublicKey: append([]byte(nil), resolved.PublicKey...),
		LifecycleState: resolved.State, NotBeforeUnixNano: resolved.NotBeforeUnixNano,
		NotAfterUnixNano: resolved.NotAfterUnixNano, RevokedAtUnixNano: resolved.RevokedAtUnixNano,
		AllowedMessageTypeIDs:           append([]uint32(nil), resolved.AllowedMessageTypeIDs...),
		Roles:                           []string{"iam.authorization.source"},
		AuthorizationPolicyDigestSHA256: resolved.AuthorizationPolicyDigestSHA256,
		KeyMaterialStateVersion:         resolved.MaterialStateVersion,
		KeyMaterialStateDigestSHA256:    resolved.MaterialSnapshotDigest,
		StateVersion:                    resolved.StateVersion, WriterEpoch: resolved.WriterEpoch,
		SnapshotDigestSHA256: resolved.SnapshotDigest,
		IdentityStateVersion: resolved.IdentityStateVersion, IdentityWriterEpoch: resolved.IdentityWriterEpoch,
		IdentitySnapshotDigestSHA256: resolved.IdentitySnapshotDigest,
		EnrollmentDomainID:           profile.EnrollmentDomainID, EnrollmentEnvironment: profile.Environment,
		EnrollmentGenesisHash: profile.GenesisHash,
	}
}
