// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package globalid

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"golang.org/x/text/unicode/norm"
)

const (
	// MaxClaims covers both admission and finalization of the largest v1
	// ownership-transfer cutover. Finalization asserts both the key identifier
	// and the terminal record identifier for each of 256 old keys, then adds
	// identity, principal, new-key and joined-audit claims. The bound remains
	// deliberately closed rather than scaling with untrusted input.
	MaxClaims          = 768
	MaxIdentifierBytes = 1024
	MaxOwnerIDBytes    = 1024
	MaxCanonicalBytes  = 4 << 20

	// These machine-derived identifier namespaces are reserved for their exact
	// semantic owners; another object cannot pre-squat them before admission.
	IAMKeyIDPrefix           = "cph-key-v1:sha256:"
	JoinedAuditEventIDPrefix = "cph-audit-v1:"

	claimsDigestDomain = "CPH-AIIE-GLOBAL-ID-CLAIMS-V1\x00"
)

var (
	ErrInvalidIdentifier = errors.New("aiinfra globalid: invalid identifier")
	ErrInvalidOwner      = errors.New("aiinfra globalid: invalid owner")
	ErrInvalidClaim      = errors.New("aiinfra globalid: invalid claim")
	ErrConflictingClaim  = errors.New("aiinfra globalid: conflicting identifier claim")
	ErrSnapshotMismatch  = errors.New("aiinfra globalid: snapshot does not match identifier owner")
)

// OwnerDomain is a closed, versioned catalog. It is metadata only: storage
// uniqueness MUST use Identifier as the sole key and MUST NOT namespace it by
// OwnerDomain.
type OwnerDomain string

const (
	OwnerIAMIdentity            OwnerDomain = "cph.aiinfra.iam.identity.v1"
	OwnerIAMKey                 OwnerDomain = "cph.aiinfra.iam.key.v1"
	OwnerCanonicalRecord        OwnerDomain = "cph.aiinfra.canonical.record.v1"
	OwnerGovernancePolicyBundle OwnerDomain = "cph.aiinfra.governance.policy-bundle.v1"
	OwnerGovernanceAuditEvent   OwnerDomain = "cph.aiinfra.governance.audit-event.v1"
)

var ownerDomains = [...]OwnerDomain{
	OwnerIAMIdentity,
	OwnerIAMKey,
	OwnerCanonicalRecord,
	OwnerGovernancePolicyBundle,
	OwnerGovernanceAuditEvent,
}

// Owner is the stable semantic object to which a globally unique identifier
// is bound. ID is the object's stable ID, not a database primary key or a
// mutable display name.
type Owner struct {
	Domain OwnerDomain
	ID     string
}

// Snapshot is an authoritative registry row. Version starts at one and is
// incremented only by an explicitly evidenced ownership transfer.
type Snapshot struct {
	Identifier string
	Owner      Owner
	Version    uint64
}

// View is the read-only deployment-global index used by semantic planners.
// A durable adapter must implement its corresponding claims in the same
// serializable transaction as replay, domain mutation, audit and result.
type View interface {
	LookupGlobalID(context.Context, string) (Snapshot, bool, error)
}

type ClaimMode uint8

const (
	ReserveNew ClaimMode = iota + 1
	AssertExisting
	TransferExisting
)

// Claim is a complete compare-and-swap instruction. ExpectedOwner and
// ExpectedVersion describe the locked row before mutation; Owner and
// NextVersion describe it after mutation. TransferEvidenceDigest is nonzero
// only for TransferExisting.
type Claim struct {
	Identifier             string
	Mode                   ClaimMode
	ExpectedOwner          Owner
	Owner                  Owner
	ExpectedVersion        uint64
	NextVersion            uint64
	TransferEvidenceDigest [sha256.Size]byte
}

// Reserve constructs an absent-to-version-one claim.
func Reserve(identifier string, owner Owner) (Claim, error) {
	claim := Claim{Identifier: identifier, Mode: ReserveNew, Owner: owner, NextVersion: 1}
	if err := claim.Validate(); err != nil {
		return Claim{}, err
	}
	return claim, nil
}

// Assert constructs an immutable ownership assertion against an exact
// authoritative snapshot.
func Assert(identifier string, snapshot Snapshot, owner Owner) (Claim, error) {
	if err := snapshot.Validate(); err != nil || snapshot.Identifier != identifier || snapshot.Owner != owner {
		return Claim{}, ErrSnapshotMismatch
	}
	claim := Claim{
		Identifier: identifier, Mode: AssertExisting, ExpectedOwner: owner, Owner: owner,
		ExpectedVersion: snapshot.Version, NextVersion: snapshot.Version,
	}
	if err := claim.Validate(); err != nil {
		return Claim{}, err
	}
	return claim, nil
}

// Transfer constructs an exact old-owner-to-new-owner claim. The evidence
// digest must name the immutable authorization for the transfer.
func Transfer(identifier string, snapshot Snapshot, next Owner, evidence [sha256.Size]byte) (Claim, error) {
	if err := snapshot.Validate(); err != nil || snapshot.Identifier != identifier || snapshot.Version == math.MaxUint64 {
		return Claim{}, ErrSnapshotMismatch
	}
	claim := Claim{
		Identifier: identifier, Mode: TransferExisting, ExpectedOwner: snapshot.Owner, Owner: next,
		ExpectedVersion: snapshot.Version, NextVersion: snapshot.Version + 1,
		TransferEvidenceDigest: evidence,
	}
	if err := claim.Validate(); err != nil {
		return Claim{}, err
	}
	return claim, nil
}

func (owner Owner) Validate() error {
	if !knownOwnerDomain(owner.Domain) || validateText(owner.ID, MaxOwnerIDBytes) != nil {
		return ErrInvalidOwner
	}
	return nil
}

func (snapshot Snapshot) Validate() error {
	if validateText(snapshot.Identifier, MaxIdentifierBytes) != nil || snapshot.Owner.Validate() != nil ||
		validateIdentifierOwner(snapshot.Identifier, snapshot.Owner) != nil || snapshot.Version == 0 {
		return ErrSnapshotMismatch
	}
	return nil
}

func (claim Claim) Validate() error {
	var zeroOwner Owner
	var zeroDigest [sha256.Size]byte
	if validateText(claim.Identifier, MaxIdentifierBytes) != nil || claim.Owner.Validate() != nil ||
		validateIdentifierOwner(claim.Identifier, claim.Owner) != nil {
		return ErrInvalidClaim
	}
	switch claim.Mode {
	case ReserveNew:
		if claim.ExpectedOwner != zeroOwner || claim.ExpectedVersion != 0 || claim.NextVersion != 1 || claim.TransferEvidenceDigest != zeroDigest {
			return ErrInvalidClaim
		}
	case AssertExisting:
		if claim.ExpectedOwner.Validate() != nil || validateIdentifierOwner(claim.Identifier, claim.ExpectedOwner) != nil ||
			claim.ExpectedOwner != claim.Owner || claim.ExpectedVersion == 0 ||
			claim.NextVersion != claim.ExpectedVersion || claim.TransferEvidenceDigest != zeroDigest {
			return ErrInvalidClaim
		}
	case TransferExisting:
		if claim.ExpectedOwner.Validate() != nil || validateIdentifierOwner(claim.Identifier, claim.ExpectedOwner) != nil ||
			claim.ExpectedOwner.Domain != OwnerIAMIdentity ||
			claim.ExpectedOwner.Domain != claim.Owner.Domain ||
			claim.ExpectedOwner == claim.Owner || claim.ExpectedVersion == 0 ||
			claim.ExpectedVersion == math.MaxUint64 || claim.NextVersion != claim.ExpectedVersion+1 || claim.TransferEvidenceDigest == zeroDigest {
			return ErrInvalidClaim
		}
	default:
		return ErrInvalidClaim
	}
	return nil
}

func validateIdentifierOwner(identifier string, owner Owner) error {
	switch {
	case strings.HasPrefix(identifier, IAMKeyIDPrefix):
		if owner.Domain != OwnerIAMKey || owner.ID != identifier ||
			!isLowerHexSuffix(identifier[len(IAMKeyIDPrefix):], sha256.Size*2) {
			return ErrInvalidOwner
		}
	case owner.Domain == OwnerIAMKey:
		if owner.ID != identifier || !strings.HasPrefix(identifier, IAMKeyIDPrefix) ||
			!isLowerHexSuffix(identifier[len(IAMKeyIDPrefix):], sha256.Size*2) {
			return ErrInvalidOwner
		}
	case strings.HasPrefix(identifier, JoinedAuditEventIDPrefix):
		if owner.Domain != OwnerGovernanceAuditEvent || owner.ID != identifier ||
			!isLowerHexSuffix(identifier[len(JoinedAuditEventIDPrefix):], ccse.MessageIDSize*2) {
			return ErrInvalidOwner
		}
	case owner.Domain == OwnerGovernanceAuditEvent:
		if owner.ID != identifier {
			return ErrInvalidOwner
		}
	}
	return nil
}

func isLowerHexSuffix(value string, exactLength int) bool {
	if len(value) != exactLength {
		return false
	}
	for _, char := range []byte(value) {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

// NormalizeClaims validates, sorts by the identifier's raw UTF-8 bytes and
// removes only byte-for-byte identical duplicates. Different claims for the
// same globally unique ID fail closed.
func NormalizeClaims(input []Claim) ([]Claim, error) {
	if len(input) == 0 || len(input) > MaxClaims {
		return nil, ErrInvalidClaim
	}
	claims := append([]Claim(nil), input...)
	for i := range claims {
		if err := claims[i].Validate(); err != nil {
			return nil, fmt.Errorf("%w at index %d: %v", ErrInvalidClaim, i, err)
		}
	}
	sort.Slice(claims, func(i, j int) bool {
		return bytes.Compare([]byte(claims[i].Identifier), []byte(claims[j].Identifier)) < 0
	})
	result := claims[:0]
	for _, claim := range claims {
		if len(result) == 0 || result[len(result)-1].Identifier != claim.Identifier {
			result = append(result, claim)
			continue
		}
		if result[len(result)-1] != claim {
			return nil, fmt.Errorf("%w: %q", ErrConflictingClaim, claim.Identifier)
		}
	}
	return append([]Claim(nil), result...), nil
}

// CanonicalBytes returns the fixed signing-independent projection embedded in
// domain mutation plan digests. It is not a database serialization.
func CanonicalBytes(input []Claim) ([]byte, error) {
	claims, err := NormalizeClaims(input)
	if err != nil {
		return nil, err
	}
	elements := make([][]byte, len(claims))
	for i, claim := range claims {
		elements[i], err = ccse.Marshal(8192, func(out *ccse.Encoder) {
			out.String(claim.Identifier)
			out.Uint32(uint32(claim.Mode))
			out.Bool(claim.Mode != ReserveNew)
			if claim.Mode != ReserveNew {
				out.String(string(claim.ExpectedOwner.Domain))
				out.String(claim.ExpectedOwner.ID)
			}
			out.String(string(claim.Owner.Domain))
			out.String(claim.Owner.ID)
			out.Uint64(claim.ExpectedVersion)
			out.Uint64(claim.NextVersion)
			out.FixedBytes(claim.TransferEvidenceDigest[:], sha256.Size)
		})
		if err != nil {
			return nil, fmt.Errorf("%w: encode claim %d: %v", ErrInvalidClaim, i, err)
		}
	}
	return ccse.Marshal(MaxCanonicalBytes, func(out *ccse.Encoder) { out.EncodedList(elements) })
}

func Digest(input []Claim) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	encoded, err := CanonicalBytes(input)
	if err != nil {
		return result, err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(claimsDigestDomain))
	_, _ = hash.Write(encoded)
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func KnownOwnerDomains() []OwnerDomain {
	result := append([]OwnerDomain(nil), ownerDomains[:]...)
	return result
}

func knownOwnerDomain(domain OwnerDomain) bool {
	for _, candidate := range ownerDomains {
		if domain == candidate {
			return true
		}
	}
	return false
}

func validateText(value string, limit int) error {
	if value == "" || len(value) > limit || !utf8.ValidString(value) || !norm.NFC.IsNormalString(value) {
		return ErrInvalidIdentifier
	}
	for _, character := range value {
		if character == 0 || unicode.IsControl(character) {
			return ErrInvalidIdentifier
		}
	}
	return nil
}
