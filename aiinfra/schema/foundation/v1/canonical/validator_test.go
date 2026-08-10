// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package canonical

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

var versionOne = ccse.Version{Major: 1, Minor: 0}

func TestValidatorDecodesAndReencodesAllFoundationMessages(t *testing.T) {
	validator := newTestValidator(t)
	payloads := validPayloads()
	if len(payloads) != 13 {
		t.Fatalf("fixture count = %d", len(payloads))
	}
	seen := make(map[uint32]struct{}, len(payloads))
	for _, fixture := range payloads {
		fixture := fixture
		t.Run(fmt.Sprint(fixture.MessageTypeID()), func(t *testing.T) {
			canonical, err := fixture.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			snapshot := append([]byte(nil), canonical...)
			decoded, err := validator.Decode(fixture.MessageTypeID(), versionOne, canonical)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.MessageTypeID() != fixture.MessageTypeID() {
				t.Fatalf("decoded message type = %d", decoded.MessageTypeID())
			}
			reencoded, err := decoded.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(reencoded, snapshot) {
				t.Fatal("decoded payload did not re-encode byte-for-byte")
			}
			if err := validator.ValidateCanonicalPayload(context.Background(), fixture.MessageTypeID(), versionOne, canonical); err != nil {
				t.Fatalf("SchemaValidator rejected canonical payload: %v", err)
			}
			// Decoder results and the comparison candidate must not alias caller input.
			for index := range canonical {
				canonical[index] ^= 0xff
			}
			afterMutation, err := decoded.CanonicalBytes()
			if err != nil || !bytes.Equal(afterMutation, snapshot) {
				t.Fatalf("decoded result aliases input: bytes=%x err=%v", afterMutation, err)
			}
		})
		seen[fixture.MessageTypeID()] = struct{}{}
	}
	for _, expected := range expectedMessages {
		if _, ok := seen[expected.id]; !ok {
			t.Errorf("missing fixture for %d", expected.id)
		}
	}
}

func TestValidatorRejectsUnknownCatalogCoordinatesAndExtensions(t *testing.T) {
	validator := newTestValidator(t)
	fixture := validPayloads()[0]
	payload, err := fixture.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validator.Decode(0xffffffff, versionOne, payload); !errors.Is(err, ErrUnknownMessageType) {
		t.Fatalf("unknown ID error = %v", err)
	}
	for _, version := range []ccse.Version{{}, {Major: 1, Minor: 1}, {Major: 2}} {
		if _, err := validator.Decode(fixture.MessageTypeID(), version, payload); !errors.Is(err, ErrUnsupportedSchemaVersion) {
			t.Errorf("version %v error = %v", version, err)
		}
	}
	if err := validator.ValidateExtensions(context.Background(), fixture.MessageTypeID(), versionOne, nil); err != nil {
		t.Fatalf("empty extensions: %v", err)
	}
	if err := validator.ValidateExtensions(context.Background(), fixture.MessageTypeID(), versionOne, []ccse.Extension{{ID: 1}}); !errors.Is(err, ccse.ErrUnknownExtension) {
		t.Fatalf("non-critical extension error = %v", err)
	}
	if err := validator.ValidateExtensions(context.Background(), fixture.MessageTypeID(), versionOne, []ccse.Extension{{ID: 1, Critical: true}}); !errors.Is(err, ccse.ErrUnknownCriticalExtension) {
		t.Fatalf("critical extension error = %v", err)
	}
	if err := validator.ValidateExtensions(context.Background(), 0xffffffff, versionOne, nil); !errors.Is(err, ErrUnknownMessageType) {
		t.Fatalf("unknown extension coordinate error = %v", err)
	}
	var nilValidator *Validator
	if _, err := nilValidator.Decode(fixture.MessageTypeID(), versionOne, payload); !errors.Is(err, ErrValidatorNotInitialized) {
		t.Fatalf("nil validator error = %v", err)
	}
	if _, err := new(Validator).Decode(fixture.MessageTypeID(), versionOne, payload); !errors.Is(err, ErrValidatorNotInitialized) {
		t.Fatalf("zero validator error = %v", err)
	}
}

func TestValidatorRejectsMalformedAndNonCanonicalPayloads(t *testing.T) {
	validator := newTestValidator(t)
	provider := providerWithJurisdictions(t, "DE", "US")
	canonical, err := provider.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	providerIDLength, jurisdictionSet := providerOffsets(t, canonical)
	firstFrame, secondFrame := firstTwoSetFrames(t, canonical, jurisdictionSet)

	mutations := []struct {
		name string
		data func() []byte
	}{
		{"trailing", func() []byte { return append(append([]byte(nil), canonical...), 0) }},
		{"truncated", func() []byte { return append([]byte(nil), canonical[:len(canonical)-1]...) }},
		{"oversize-input", func() []byte { return make([]byte, 32769) }},
		{"invalid-enum", func() []byte {
			out := append([]byte(nil), canonical...)
			binary.BigEndian.PutUint32(out[len(out)-4:], 7)
			return out
		}},
		{"invalid-optional-presence", func() []byte {
			out := append([]byte(nil), canonical...)
			stakePresence := len(out) - 29 - (4 + len(provider.StakeReference.Value))
			out[stakePresence] = 2
			return out
		}},
		{"oversize-field", func() []byte {
			out := append([]byte(nil), canonical...)
			binary.BigEndian.PutUint32(out[providerIDLength:], 253)
			return out
		}},
		{"invalid-utf8", func() []byte { return replaceFramedValue(t, canonical, providerIDLength, []byte{0xff}) }},
		{"non-nfc", func() []byte { return replaceFramedValue(t, canonical, providerIDLength, []byte{'e', 0xcc, 0x81}) }},
		{"unsorted-set", func() []byte {
			out := append([]byte(nil), canonical...)
			first := append([]byte(nil), out[firstFrame.start:firstFrame.end]...)
			second := append([]byte(nil), out[secondFrame.start:secondFrame.end]...)
			if len(first) != len(second) {
				t.Fatal("test fixture set frames differ in width")
			}
			copy(out[firstFrame.start:firstFrame.end], second)
			copy(out[secondFrame.start:secondFrame.end], first)
			return out
		}},
		{"duplicate-set", func() []byte {
			out := append([]byte(nil), canonical...)
			copy(out[secondFrame.start:secondFrame.end], out[firstFrame.start:firstFrame.end])
			return out
		}},
		{"too-many-set-items", func() []byte {
			out := append([]byte(nil), canonical...)
			binary.BigEndian.PutUint32(out[jurisdictionSet:], 33)
			return out
		}},
		{"semantic-time-range", func() []byte {
			out := append([]byte(nil), canonical...)
			copy(out[len(out)-12:len(out)-4], out[len(out)-20:len(out)-12])
			return out
		}},
		{"metadata-zero-major", func() []byte {
			out := append([]byte(nil), canonical...)
			binary.BigEndian.PutUint32(out[:4], 0)
			return out
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			_, err := validator.Decode(schema.MessageTypeProviderIdentity, versionOne, mutation.data())
			if err == nil {
				t.Fatal("malformed payload accepted")
			}
			if !errors.Is(err, ccse.ErrNonCanonicalPayload) {
				t.Fatalf("error does not classify as noncanonical: %v", err)
			}
			switch mutation.name {
			case "invalid-optional-presence":
				if !errors.Is(err, ccse.ErrInvalidBoolean) {
					t.Fatalf("optional presence error = %v", err)
				}
			case "unsorted-set":
				if !errors.Is(err, ccse.ErrNonCanonicalSetOrder) {
					t.Fatalf("set order error = %v", err)
				}
			case "duplicate-set":
				if !errors.Is(err, ccse.ErrDuplicateSetValue) {
					t.Fatalf("duplicate set error = %v", err)
				}
			}
		})
	}
}

func TestMetadataSchemaVersionUsesRegistryProjectionSemantics(t *testing.T) {
	validator := newTestValidator(t)
	provider, ok := validPayloads()[0].(foundationv1.ProviderIdentitySigningProjection)
	if !ok {
		t.Fatal("provider fixture has wrong type")
	}
	// RecordMetadata.SchemaVersion is a nested signed field, not the envelope's
	// catalog coordinate. The frozen parent projection permits any non-zero
	// major; the runtime decoder must not invent a conflicting v1.0-only rule.
	provider.Metadata.SchemaVersion = foundationv1.SchemaVersionSigningProjection{Major: 2, Minor: 7}
	payload, err := provider.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validator.Decode(schema.MessageTypeProviderIdentity, versionOne, payload); err != nil {
		t.Fatalf("registry-permitted metadata schema version rejected: %v", err)
	}
}

func TestAllNestedProjectionDecoders(t *testing.T) {
	validator := newTestValidator(t)

	schemaBytes, err := ccse.Marshal(8, func(out *ccse.Encoder) {
		out.Uint32(1)
		out.Uint32(0)
	})
	if err != nil {
		t.Fatal(err)
	}
	var schemaVersion foundationv1.SchemaVersionSigningProjection
	if err := ccse.Unmarshal(schemaBytes, 8, func(in *ccse.Decoder) error {
		var decodeErr error
		schemaVersion, decodeErr = decodeSchemaVersion(in, validator.nested.schemaVersion)
		return decodeErr
	}); err != nil || schemaVersion.Major != 1 || schemaVersion.Minor != 0 {
		t.Fatalf("schema version = %+v, err=%v", schemaVersion, err)
	}

	providerBytes, err := validPayloads()[0].CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	cursor := &wireCursor{t: t, b: providerBytes}
	cursor.metadata()
	var metadata foundationv1.RecordMetadataSigningProjection
	if err := ccse.Unmarshal(providerBytes[:cursor.o], 8192, func(in *ccse.Decoder) error {
		var decodeErr error
		metadata, decodeErr = decodeRecordMetadata(validator, in, validator.nested.recordMetadata)
		return decodeErr
	}); err != nil || metadata.RecordID != "record-01" {
		t.Fatalf("metadata = %+v, err=%v", metadata, err)
	}

	criterion := validCriterion("readiness.p99")
	criterionBytes, err := criterion.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := ccse.Unmarshal(criterionBytes, 1024, func(in *ccse.Decoder) error {
		decoded, decodeErr := decodeMetricCriterion(in, validator.nested.metricCriterion)
		if decodeErr == nil && decoded.MetricID != criterion.MetricID {
			return errors.New("criterion value mismatch")
		}
		return decodeErr
	}); err != nil {
		t.Fatalf("criterion: %v", err)
	}

	observation := validObservation("readiness.p99", true)
	observationBytes, err := observation.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := ccse.Unmarshal(observationBytes, 1024, func(in *ccse.Decoder) error {
		decoded, decodeErr := decodeMetricObservation(in, validator.nested.metricObservation)
		if decodeErr == nil && (decoded.MetricID != observation.MetricID || !decoded.CriterionPassed) {
			return errors.New("observation value mismatch")
		}
		return decodeErr
	}); err != nil {
		t.Fatalf("observation: %v", err)
	}
}

func TestValidatorRejectsInvalidBooleanAndNestedSemanticViolation(t *testing.T) {
	validator := newTestValidator(t)
	policy := validPayloads()[9]
	policyBytes, err := policy.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	// Tail is minimum_approvals(4), emergency(1), rollback presence(1),
	// break-glass presence+value(9), state(4).
	policyBytes[len(policyBytes)-15] = 2
	if _, err := validator.Decode(schema.MessageTypePolicyBundle, versionOne, policyBytes); !errors.Is(err, ccse.ErrInvalidBoolean) {
		t.Fatalf("boolean error = %v", err)
	}

	evidence := validEvidenceRecord(validMetadata())
	evidenceBytes, err := evidence.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	observationSet := evidenceObservationSetOffset(t, evidenceBytes)
	observationFrame := firstSetFrame(t, evidenceBytes, observationSet)
	invalidNestedBoolean := append([]byte(nil), evidenceBytes...)
	invalidNestedBoolean[observationFrame.end-1] = 2
	if _, err := validator.Decode(schema.MessageTypeEvidenceRecord, versionOne, invalidNestedBoolean); !errors.Is(err, ccse.ErrInvalidBoolean) {
		t.Fatalf("nested boolean error = %v", err)
	}

	nestedTrailing := append([]byte(nil), evidenceBytes[:observationFrame.end]...)
	nestedTrailing = append(nestedTrailing, 0)
	nestedTrailing = append(nestedTrailing, evidenceBytes[observationFrame.end:]...)
	binary.BigEndian.PutUint32(nestedTrailing[observationFrame.start:observationFrame.start+4], uint32(observationFrame.end-observationFrame.start-4+1))
	if _, err := validator.Decode(schema.MessageTypeEvidenceRecord, versionOne, nestedTrailing); !errors.Is(err, ccse.ErrTrailingData) {
		t.Fatalf("nested trailing error = %v", err)
	}

	// Change the record sample size to less than the nested observation sample
	// size. Wire syntax stays valid; the parent projection must reject the
	// cross-field semantic contradiction after typed nested decoding.
	sampleOffset := evidenceSampleSizeOffset(t, evidenceBytes)
	binary.BigEndian.PutUint64(evidenceBytes[sampleOffset:sampleOffset+8], 1)
	if _, err := validator.Decode(schema.MessageTypeEvidenceRecord, versionOne, evidenceBytes); !errors.Is(err, foundationv1.ErrInvalidProjectionValue) {
		t.Fatalf("nested cross-field semantic error = %v", err)
	}
}

func TestValidatorConcurrentUse(t *testing.T) {
	validator := newTestValidator(t)
	for _, fixture := range validPayloads() {
		fixture := fixture
		t.Run(fmt.Sprint(fixture.MessageTypeID()), func(t *testing.T) {
			t.Parallel()
			payload, err := fixture.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			for iteration := 0; iteration < 25; iteration++ {
				if _, err := validator.Decode(fixture.MessageTypeID(), versionOne, payload); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func FuzzValidatorDecode(f *testing.F) {
	validator, err := NewValidator()
	if err != nil {
		f.Fatal(err)
	}
	for _, fixture := range validPayloads() {
		payload, err := fixture.CanonicalBytes()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(fixture.MessageTypeID(), payload)
	}
	f.Fuzz(func(t *testing.T, messageTypeID uint32, input []byte) {
		if len(input) > 300000 {
			t.Skip()
		}
		decoded, err := validator.Decode(messageTypeID, versionOne, input)
		if err != nil {
			return
		}
		if decoded.MessageTypeID() != messageTypeID {
			t.Fatalf("decoded ID = %d, requested %d", decoded.MessageTypeID(), messageTypeID)
		}
		canonical, err := decoded.CanonicalBytes()
		if err != nil {
			t.Fatalf("accepted value cannot re-encode: %v", err)
		}
		if !bytes.Equal(canonical, input) {
			t.Fatal("accepted input differs from canonical re-encoding")
		}
	})
}

func newTestValidator(t testing.TB) *Validator {
	t.Helper()
	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

func assertNonCanonical(t testing.TB, validator *Validator, messageTypeID uint32, input []byte) {
	t.Helper()
	if _, err := validator.Decode(messageTypeID, versionOne, input); !errors.Is(err, ccse.ErrNonCanonicalPayload) {
		t.Fatalf("noncanonical error = %v", err)
	}
}

func providerWithJurisdictions(t testing.TB, values ...string) foundationv1.ProviderIdentitySigningProjection {
	t.Helper()
	provider, ok := validPayloads()[0].(foundationv1.ProviderIdentitySigningProjection)
	if !ok {
		t.Fatal("provider fixture has wrong type")
	}
	provider.Jurisdictions = values
	return provider
}

type byteRange struct{ start, end int }

type wireCursor struct {
	t testing.TB
	b []byte
	o int
}

func (c *wireCursor) skip(width int) {
	c.t.Helper()
	if width < 0 || c.o > len(c.b)-width {
		c.t.Fatalf("wire fixture truncated at %d, need %d", c.o, width)
	}
	c.o += width
}

func (c *wireCursor) uint32() uint32 {
	c.t.Helper()
	if c.o > len(c.b)-4 {
		c.t.Fatalf("wire fixture truncated at u32 %d", c.o)
	}
	value := binary.BigEndian.Uint32(c.b[c.o : c.o+4])
	c.o += 4
	return value
}

func (c *wireCursor) framed() byteRange {
	c.t.Helper()
	start := c.o
	length := int(c.uint32())
	c.skip(length)
	return byteRange{start: start, end: c.o}
}

func (c *wireCursor) set() byteRange {
	c.t.Helper()
	start := c.o
	count := int(c.uint32())
	for index := 0; index < count; index++ {
		c.framed()
	}
	return byteRange{start: start, end: c.o}
}

func (c *wireCursor) metadata() {
	c.t.Helper()
	c.skip(8)
	c.framed()
	c.skip(8)
	c.framed()
	c.framed()
	c.skip(16)
	c.framed()
	c.set()
}

func providerOffsets(t testing.TB, input []byte) (providerIDLength, jurisdictionSet int) {
	t.Helper()
	cursor := &wireCursor{t: t, b: input}
	cursor.metadata()
	providerIDLength = cursor.o
	cursor.framed()
	cursor.framed()
	cursor.framed()
	return providerIDLength, cursor.o
}

func firstTwoSetFrames(t testing.TB, input []byte, setOffset int) (byteRange, byteRange) {
	t.Helper()
	cursor := &wireCursor{t: t, b: input, o: setOffset}
	if count := cursor.uint32(); count < 2 {
		t.Fatalf("set count = %d", count)
	}
	return cursor.framed(), cursor.framed()
}

func firstSetFrame(t testing.TB, input []byte, setOffset int) byteRange {
	t.Helper()
	cursor := &wireCursor{t: t, b: input, o: setOffset}
	if count := cursor.uint32(); count < 1 {
		t.Fatalf("set count = %d", count)
	}
	return cursor.framed()
}

func replaceFramedValue(t testing.TB, input []byte, lengthOffset int, value []byte) []byte {
	t.Helper()
	if lengthOffset > len(input)-4 {
		t.Fatal("invalid framed value offset")
	}
	oldLength := int(binary.BigEndian.Uint32(input[lengthOffset : lengthOffset+4]))
	oldEnd := lengthOffset + 4 + oldLength
	if oldEnd > len(input) {
		t.Fatal("invalid framed value length")
	}
	out := make([]byte, 0, len(input)-oldLength+len(value))
	out = append(out, input[:lengthOffset]...)
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(value)))
	out = append(out, prefix[:]...)
	out = append(out, value...)
	out = append(out, input[oldEnd:]...)
	return out
}

func evidenceSampleSizeOffset(t testing.TB, input []byte) int {
	t.Helper()
	cursor := &wireCursor{t: t, b: input}
	cursor.metadata()
	for index := 0; index < 6; index++ {
		cursor.framed()
	}
	for index := 0; index < 3; index++ {
		cursor.set()
	}
	cursor.skip(16)
	return cursor.o
}

func evidenceObservationSetOffset(t testing.TB, input []byte) int {
	t.Helper()
	cursor := &wireCursor{t: t, b: input}
	cursor.metadata()
	for index := 0; index < 6; index++ {
		cursor.framed()
	}
	for index := 0; index < 3; index++ {
		cursor.set()
	}
	cursor.skip(24)
	cursor.set()
	return cursor.o
}
