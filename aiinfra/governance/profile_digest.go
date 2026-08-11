// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
)

const governanceProfileDigestDomain = "CPH-AIIE-GOVERNANCE-PROFILE-V1\x00"

// ProfileDigest commits the immutable v1 deployment semantics used to accept
// policy history. Changing a quorum, role, emergency scope, duration, region,
// or deployment anchor requires an explicit versioned migration; silently
// reinterpreting accepted history under a new profile fails closed.
func ProfileDigest(profile Profile) ([ccse.DigestSize]byte, error) {
	if !preflightProfile(profile) {
		return [ccse.DigestSize]byte{}, ErrInvalidConfiguration
	}
	profile = cloneProfile(profile)
	if err := validateProfile(profile); err != nil {
		return [ccse.DigestSize]byte{}, err
	}
	return digestGovernanceProfile(profile)
}

func digestGovernanceProfile(profile Profile) ([ccse.DigestSize]byte, error) {
	audience := append([]string(nil), profile.Audience...)
	requiredRoles := append([]string(nil), profile.RequiredApprovalRoles...)
	breakGlassRoles := append([]string(nil), profile.BreakGlassRequiredRoles...)
	breakGlassScopes := append([]string(nil), profile.AllowedBreakGlassScopes...)
	sort.Strings(audience)
	sort.Strings(requiredRoles)
	sort.Strings(breakGlassRoles)
	sort.Strings(breakGlassScopes)

	w := newDigestWriter(governanceProfileDigestDomain)
	w.uint64(uint64(profile.ProtocolVersion.Major))
	w.uint64(uint64(profile.ProtocolVersion.Minor))
	w.uint64(uint64(profile.SchemaVersion.Major))
	w.uint64(uint64(profile.SchemaVersion.Minor))
	w.strings(audience)
	w.bool(profile.TenantOrganization.Present)
	w.string(profile.TenantOrganization.Value)
	w.bool(profile.ProviderOrganization.Present)
	w.string(profile.ProviderOrganization.Value)
	w.string(profile.Environment)
	w.digest(profile.ChainID)
	w.digest(profile.GenesisHash)
	w.string(profile.PolicyReplayDomainID)
	w.string(profile.AuditReplayDomainID)
	w.string(profile.AuditWriterIdentity)
	w.string(profile.AuditWriterKeyID)
	w.string(profile.AuditWriterRole)
	// Current writer home regions are lease state, not immutable policy
	// semantics. They are fenced separately in every mutation plan so a valid
	// higher-epoch regional failover does not reinterpret historical policy.
	w.digest(profile.AuditDeploymentAnchorSHA256)
	w.string(profile.EnrollmentDomainID)
	w.uint64(uint64(profile.MinimumApprovals))
	w.uint64(uint64(profile.MinimumDistinctApprovalOrganizations))
	w.strings(requiredRoles)
	w.uint64(uint64(profile.BreakGlassMinimumApprovals))
	w.uint64(uint64(profile.BreakGlassMinimumDistinctOrganizations))
	w.strings(breakGlassRoles)
	w.strings(breakGlassScopes)
	w.int64(profile.MinActivationDelayNanos)
	w.int64(profile.MaxBreakGlassDurationNanos)
	w.int64(profile.MaxRecordValidityNanos)
	w.int64(profile.MaxClockSkewNanos)
	w.int64(profile.MaxPlanCommitLatencyNanos)
	w.uint64(uint64(profile.MaxPolicyRecords))
	return w.sum()
}
