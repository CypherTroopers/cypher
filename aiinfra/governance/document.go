// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
)

const (
	breakGlassDocumentMediaType = "application/json"
	maxPolicyDocumentBytes      = 64 << 10
)

// breakGlassDocumentV1 is the only policy-document shape from which v1 may
// derive emergency scopes. The view supplies content-addressed bytes; it does
// not get to assert their meaning. Re-encoding below pins both the JSON shape
// and its byte-level canonical representation.
type breakGlassDocumentV1 struct {
	PolicyKind       string   `json:"policy_kind"`
	BreakGlassScopes []string `json:"break_glass_scopes"`
}

func decodeBreakGlassDocument(snapshot PolicyDocumentSnapshot, expectedDigest [32]byte, expectedMediaType, expectedKind string) ([]string, error) {
	if validatePolicyDocument(snapshot, expectedDigest, expectedMediaType) != nil {
		return nil, ErrBreakGlassScope
	}

	decoder := json.NewDecoder(bytes.NewReader(snapshot.CanonicalDocument))
	decoder.DisallowUnknownFields()
	var document breakGlassDocumentV1
	if err := decoder.Decode(&document); err != nil {
		return nil, ErrBreakGlassScope
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, ErrBreakGlassScope
	}
	// validatePolicyDocument has already re-encoded the generic JSON value and
	// compared the exact bytes. Re-encoding this typed struct would impose Go
	// field declaration order instead of the generic canonical key order.
	if document.PolicyKind != expectedKind {
		return nil, ErrBreakGlassScope
	}
	// Arrays are semantically sets in this boundary. Requiring their canonical
	// lexical order makes the content digest deterministic for one scope set.
	for index := 1; index < len(document.BreakGlassScopes); index++ {
		if document.BreakGlassScopes[index-1] >= document.BreakGlassScopes[index] {
			return nil, ErrBreakGlassScope
		}
	}
	return append([]string(nil), document.BreakGlassScopes...), nil
}

// validatePolicyDocument pins the v1 document media type and byte-level JSON
// canonicality for every policy. This prevents two byte representations from
// acquiring different content identities or an adapter from echoing a digest
// for bytes that consumers cannot deterministically parse.
func validatePolicyDocument(snapshot PolicyDocumentSnapshot, expectedDigest [32]byte, expectedMediaType string) error {
	if snapshot.MediaType != breakGlassDocumentMediaType || expectedMediaType != breakGlassDocumentMediaType ||
		len(snapshot.CanonicalDocument) == 0 || len(snapshot.CanonicalDocument) > maxPolicyDocumentBytes ||
		sha256.Sum256(snapshot.CanonicalDocument) != expectedDigest || snapshot.DigestSHA256 != expectedDigest {
		return ErrSnapshotInconsistent
	}
	decoder := json.NewDecoder(bytes.NewReader(snapshot.CanonicalDocument))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return ErrSnapshotInconsistent
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrSnapshotInconsistent
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, snapshot.CanonicalDocument) {
		return ErrSnapshotInconsistent
	}
	return nil
}
