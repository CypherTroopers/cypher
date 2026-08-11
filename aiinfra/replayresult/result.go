// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

// Package replayresult defines the adapter-neutral, content-addressed durable
// result boundary used by CCSE replay stores and semantic planners.
package replayresult

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	// MaxContentTypeBytes matches the immutable PostgreSQL replay schema.
	MaxContentTypeBytes = 255
	// MaxPayloadBytes matches the immutable PostgreSQL durable-result limit.
	MaxPayloadBytes = 1 << 20

	digestDomain = "CPH-AIIE-DURABLE-RESULT-V1\x00"
)

var ErrInvalidResult = errors.New("aiinfra replay result: invalid durable result")

// Result is an owned, immutable snapshot of a durable replay result. Callers
// must still interpret ContentType through a closed operation-specific catalog;
// this type proves byte integrity, not business success.
type Result struct {
	contentType string
	payload     []byte
	digest      [sha256.Size]byte
}

// New validates the bounded framing and takes one owned copy of payload.
func New(contentType string, payload []byte) (Result, error) {
	if err := Validate(contentType, payload); err != nil {
		return Result{}, err
	}
	owned := append([]byte(nil), payload...)
	return Result{
		contentType: contentType,
		payload:     owned,
		digest:      Digest(contentType, owned),
	}, nil
}

// Validate performs the no-copy bounded validation shared with durable replay
// adapters. Content types are deliberately restricted to stable visible ASCII.
func Validate(contentType string, payload []byte) error {
	if contentType == "" || len(contentType) > MaxContentTypeBytes ||
		!utf8.ValidString(contentType) || strings.TrimSpace(contentType) != contentType ||
		strings.IndexByte(contentType, 0) >= 0 {
		return fmt.Errorf("%w: invalid content type", ErrInvalidResult)
	}
	for index := range len(contentType) {
		if contentType[index] < 0x21 || contentType[index] > 0x7e {
			return fmt.Errorf("%w: content type must use visible ASCII", ErrInvalidResult)
		}
	}
	if len(payload) > MaxPayloadBytes {
		return fmt.Errorf("%w: payload exceeds %d bytes", ErrInvalidResult, MaxPayloadBytes)
	}
	return nil
}

// Digest binds the exact content type and payload using the frozen v1 framing.
// Validate must be called at an untrusted boundary before Digest when input
// sizes are not already bounded.
func Digest(contentType string, payload []byte) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(digestDomain))
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(contentType)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write([]byte(contentType))
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(payload)
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

// ContentType returns the immutable media type.
func (result Result) ContentType() string { return result.contentType }

// Payload returns a detached copy of the immutable payload.
func (result Result) Payload() []byte { return append([]byte(nil), result.payload...) }

// Digest returns the frozen content-addressed digest.
func (result Result) Digest() [sha256.Size]byte { return result.digest }

// Verify rejects zero values, aliases forged through unsafe construction, and
// any stored digest that no longer matches the retained bytes.
func (result Result) Verify() error {
	if err := Validate(result.contentType, result.payload); err != nil {
		return err
	}
	if result.digest == ([sha256.Size]byte{}) ||
		result.digest != Digest(result.contentType, result.payload) {
		return fmt.Errorf("%w: digest mismatch", ErrInvalidResult)
	}
	return nil
}
