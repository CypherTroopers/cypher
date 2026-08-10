// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package schema

import (
	"bytes"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestDefaultRegistryAndFixedProductionIDs(t *testing.T) {
	registry, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		id     uint32
		symbol string
		name   string
	}{
		{MessageTypeProviderIdentity, "FOUNDATION_PROVIDER_IDENTITY_V1", "cph.aiinfra.foundation.v1.ProviderIdentity"},
		{MessageTypeAgentIdentity, "FOUNDATION_AGENT_IDENTITY_V1", "cph.aiinfra.foundation.v1.AgentIdentity"},
		{MessageTypeHostIdentity, "FOUNDATION_HOST_IDENTITY_V1", "cph.aiinfra.foundation.v1.HostIdentity"},
		{MessageTypeDeviceIdentity, "FOUNDATION_DEVICE_IDENTITY_V1", "cph.aiinfra.foundation.v1.DeviceIdentity"},
		{MessageTypeMinerIdentity, "FOUNDATION_MINER_IDENTITY_V1", "cph.aiinfra.foundation.v1.MinerIdentity"},
		{MessageTypeRunnerIdentity, "FOUNDATION_RUNNER_IDENTITY_V1", "cph.aiinfra.foundation.v1.RunnerIdentity"},
		{MessageTypeBuyerIdentity, "FOUNDATION_BUYER_IDENTITY_V1", "cph.aiinfra.foundation.v1.BuyerIdentity"},
		{MessageTypeServiceIdentity, "FOUNDATION_SERVICE_IDENTITY_V1", "cph.aiinfra.foundation.v1.ServiceIdentity"},
		{MessageTypeKeyLifecycle, "FOUNDATION_KEY_LIFECYCLE_V1", "cph.aiinfra.foundation.v1.KeyLifecycle"},
		{MessageTypePolicyBundle, "FOUNDATION_POLICY_BUNDLE_V1", "cph.aiinfra.foundation.v1.PolicyBundle"},
		{MessageTypeAuditEvent, "FOUNDATION_AUDIT_EVENT_V1", "cph.aiinfra.foundation.v1.AuditEvent"},
		{MessageTypeEvidenceRecord, "FOUNDATION_EVIDENCE_RECORD_V1", "cph.aiinfra.foundation.v1.EvidenceRecord"},
		{MessageTypeExperimentPlan, "FOUNDATION_EXPERIMENT_PLAN_V1", "cph.aiinfra.foundation.v1.ExperimentPlan"},
	}
	if len(registry.Messages) != len(want) {
		t.Fatalf("message count %d, want %d", len(registry.Messages), len(want))
	}
	for i, expected := range want {
		message := registry.Messages[i]
		if message.MessageTypeID != expected.id || message.IDSymbol != expected.symbol || message.Name != expected.name {
			t.Fatalf("message[%d] = (%d, %q, %q), want (%d, %q, %q)", i, message.MessageTypeID, message.IDSymbol, message.Name, expected.id, expected.symbol, expected.name)
		}
		lookedUp, ok := registry.LookupMessage(expected.id)
		if !ok || lookedUp.Name != expected.name {
			t.Fatalf("lookup %d failed: %#v, %v", expected.id, lookedUp, ok)
		}
	}
	if _, ok := registry.LookupMessage(100); ok {
		t.Fatal("test-only message type 100 is registered for production")
	}
	if len(registry.ReservedMessageTypeRanges) != 1 || registry.ReservedMessageTypeRanges[0].First != 1 || registry.ReservedMessageTypeRanges[0].Last != 65535 {
		t.Fatalf("unexpected test-only reservation: %#v", registry.ReservedMessageTypeRanges)
	}
}

func TestRegistryValidatorRejectsStructuralAmbiguity(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Registry)
		want   error
	}{
		{
			name: "duplicate message ID",
			mutate: func(r *Registry) {
				r.Messages[1].MessageTypeID = r.Messages[0].MessageTypeID
			},
			want: ErrDuplicateMessageID,
		},
		{
			name: "duplicate message name",
			mutate: func(r *Registry) {
				r.Messages[1].Name = r.Messages[0].Name
			},
			want: ErrDuplicateName,
		},
		{
			name: "non-contiguous order",
			mutate: func(r *Registry) {
				r.Messages[0].Fields[1].Order = 3
			},
			want: ErrInvalidFieldOrder,
		},
		{
			name: "map type",
			mutate: func(r *Registry) {
				r.Messages[0].Fields[1].Type = "map"
			},
			want: ErrUnknownFieldType,
		},
		{
			name: "float type",
			mutate: func(r *Registry) {
				r.Messages[0].Fields[1].Type = "float"
			},
			want: ErrUnknownFieldType,
		},
		{
			name: "double type",
			mutate: func(r *Registry) {
				r.Messages[0].Fields[1].Type = "double"
			},
			want: ErrUnknownFieldType,
		},
		{
			name: "zero payload bound",
			mutate: func(r *Registry) {
				r.Messages[0].Limits.MaxPayloadBytes = 0
			},
			want: ErrInvalidLimits,
		},
		{
			name: "required uint64 bound too small",
			mutate: func(r *Registry) {
				r.Messages[0].Fields[7].MaxEncodedBytes = 7
			},
			want: ErrEncodedBoundTooSmall,
		},
		{
			name: "optional uint32 bound lacks presence byte",
			mutate: func(r *Registry) {
				r.Structures[2].Fields[7].MaxEncodedBytes = 4
			},
			want: ErrEncodedBoundTooSmall,
		},
		{
			name: "required fixed bytes lacks len32",
			mutate: func(r *Registry) {
				r.Structures[1].Fields[3].MaxEncodedBytes = 35
			},
			want: ErrEncodedBoundTooSmall,
		},
		{
			name: "optional fixed bytes lacks len32",
			mutate: func(r *Registry) {
				r.Messages[9].Fields[5].MaxEncodedBytes = 36
			},
			want: ErrEncodedBoundTooSmall,
		},
		{
			name: "fixed bytes set lacks element frame",
			mutate: func(r *Registry) {
				r.Messages[0].Fields[5].MaxEncodedBytes = 2563
			},
			want: ErrEncodedBoundTooSmall,
		},
		{
			name: "variable set cannot hold declared empty elements",
			mutate: func(r *Registry) {
				r.Messages[0].Fields[4].MaxEncodedBytes = 259
			},
			want: ErrEncodedBoundTooSmall,
		},
		{
			name: "fixed width bound is exact",
			mutate: func(r *Registry) {
				r.Structures[1].Fields[3].MaxEncodedBytes = 37
			},
			want: ErrFixedWidthBound,
		},
		{
			name: "missing critical declaration",
			mutate: func(r *Registry) {
				r.Messages[0].Fields[0].Critical = nil
			},
			want: ErrInvalidField,
		},
		{
			name: "test-only production message",
			mutate: func(r *Registry) {
				r.Messages[0].MessageTypeID = 100
			},
			want: ErrReservedMessageID,
		},
		{
			name: "recursive projection",
			mutate: func(r *Registry) {
				r.Messages[0].Fields[0].MessageType = r.Messages[0].Name
			},
			want: ErrRecursiveProjection,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry, err := LoadDefault()
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&registry)
			if err := registry.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRegistryStrictJSONAndCanonicalRoundTrip(t *testing.T) {
	source, err := EmbeddedRegistryJSON()
	if err != nil {
		t.Fatal(err)
	}
	unknown := bytes.Replace(source, []byte(`"format":`), []byte(`"unknown_member":true,"format":`), 1)
	if _, err := Parse(unknown); !errors.Is(err, ErrInvalidRegistry) {
		t.Fatalf("unknown JSON member error = %v", err)
	}
	duplicate := bytes.Replace(source, []byte(`"format": "cph.aiinfra.ccse.registry",`), []byte(`"format":"wrong","format": "cph.aiinfra.ccse.registry",`), 1)
	if _, err := Parse(duplicate); !errors.Is(err, ErrInvalidRegistry) || !strings.Contains(err.Error(), "duplicate JSON member") {
		t.Fatalf("duplicate JSON member error = %v", err)
	}
	registry, err := Parse(source)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := registry.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := Parse(canonical)
	if err != nil {
		t.Fatal(err)
	}
	first, err := registry.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	second, err := roundTrip.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("canonical round-trip digest changed: %x != %x", first, second)
	}
}

func TestMinimumEncodedBoundIncludesCanonicalFrames(t *testing.T) {
	critical := true
	tests := []struct {
		name  string
		field Field
		want  int
	}{
		{
			name:  "required fixed16 scalar",
			field: Field{Type: "fixed_bytes_16", Presence: "required", Collection: "scalar", Critical: &critical, MaxItems: 1},
			want:  4 + 16,
		},
		{
			name:  "optional fixed32 scalar",
			field: Field{Type: "fixed_bytes_32", Presence: "optional", Collection: "scalar", Critical: &critical, MaxItems: 1},
			want:  1 + 4 + 32,
		},
		{
			name:  "required fixed64 scalar",
			field: Field{Type: "fixed_bytes_64", Presence: "required", Collection: "scalar", Critical: &critical, MaxItems: 1},
			want:  4 + 64,
		},
		{
			name:  "optional fixed64 scalar",
			field: Field{Type: "fixed_bytes_64", Presence: "optional", Collection: "scalar", Critical: &critical, MaxItems: 1},
			want:  1 + 4 + 64,
		},
		{
			name:  "fixed32 set",
			field: Field{Type: "fixed_bytes_32", Presence: "required", Collection: "set", Critical: &critical, MaxItems: 64},
			want:  4 + 64*(4+4+32),
		},
		{
			name:  "scalar message inline",
			field: Field{Type: "message", Presence: "required", Collection: "scalar", Critical: &critical, MaxItems: 1},
			want:  0,
		},
		{
			name:  "message set outer frames only",
			field: Field{Type: "message", Presence: "required", Collection: "set", Critical: &critical, MaxItems: 2},
			want:  4 + 2*4,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := minimumEncodedBound(test.field)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("minimumEncodedBound() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestRegistryCanonicalSHA256(t *testing.T) {
	registry, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	got, err := registry.SHA256Hex()
	if err != nil {
		t.Fatal(err)
	}
	const want = "d432c225de9f5747feaad2fd7971834d3a389f7e37e155a0761685e61acb779e"
	if got != want {
		t.Fatalf("registry SHA-256 = %s, want %s", got, want)
	}
}

func TestProtoSourcesForbidMapAndFloatingPoint(t *testing.T) {
	sources, err := EmbeddedProtoSources()
	if err != nil {
		t.Fatal(err)
	}
	forbidden := regexp.MustCompile(`(?m)\b(?:map\s*<|float|double)\b`)
	for _, source := range sources {
		clean := stripProtoComments(string(source.Source))
		if match := forbidden.FindString(clean); match != "" {
			t.Fatalf("%s contains forbidden signed-schema token %q", source.Path, match)
		}
	}
}

func TestRegistryProjectionMatchesProtoFields(t *testing.T) {
	registry, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	sources, err := EmbeddedProtoSources()
	if err != nil {
		t.Fatal(err)
	}
	protoMessages := make(map[string][]protoField)
	for _, source := range sources {
		parsed, err := parseProtoMessages(string(source.Source))
		if err != nil {
			t.Fatalf("parse %s: %v", source.Path, err)
		}
		for name, fields := range parsed {
			if _, duplicate := protoMessages[name]; duplicate {
				t.Fatalf("duplicate protobuf message %s", name)
			}
			protoMessages[name] = fields
		}
	}
	projections := make([]Projection, 0, len(registry.Structures)+len(registry.Messages))
	projections = append(projections, registry.Structures...)
	for _, message := range registry.Messages {
		projections = append(projections, Projection{Name: message.Name, Fields: message.Fields})
	}
	for _, projection := range projections {
		protoFields, ok := protoMessages[projection.Name]
		if !ok {
			t.Fatalf("registered projection %s has no protobuf transport message", projection.Name)
		}
		if len(protoFields) != len(projection.Fields) {
			t.Fatalf("%s protobuf has %d fields; registry has %d", projection.Name, len(protoFields), len(projection.Fields))
		}
		for i, registered := range projection.Fields {
			transport := protoFields[i]
			if registered.Name != transport.name || registered.Order != transport.number {
				t.Fatalf("%s field[%d] protobuf=(%s,%d) registry=(%s,%d)", projection.Name, i, transport.name, transport.number, registered.Name, registered.Order)
			}
		}
	}
}

type protoField struct {
	name   string
	number int
}

var (
	protoPackagePattern = regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z_][A-Za-z0-9_.]*)\s*;`)
	protoMessagePattern = regexp.MustCompile(`(?m)^\s*message\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{`)
	protoFieldPattern   = regexp.MustCompile(`(?m)^\s*(?:(?:optional|repeated)\s+)?[A-Za-z_][A-Za-z0-9_.]*\s+([a-z][a-z0-9_]*)\s*=\s*([0-9]+)\s*;`)
	protoBlockComment   = regexp.MustCompile(`(?s)/\*.*?\*/`)
	protoLineComment    = regexp.MustCompile(`(?m)//.*$`)
)

func stripProtoComments(source string) string {
	source = protoBlockComment.ReplaceAllString(source, "")
	return protoLineComment.ReplaceAllString(source, "")
}

func parseProtoMessages(source string) (map[string][]protoField, error) {
	source = stripProtoComments(source)
	packageMatch := protoPackagePattern.FindStringSubmatch(source)
	if len(packageMatch) != 2 {
		return nil, errors.New("missing package")
	}
	out := make(map[string][]protoField)
	locations := protoMessagePattern.FindAllStringSubmatchIndex(source, -1)
	for _, location := range locations {
		name := source[location[2]:location[3]]
		open := strings.IndexByte(source[location[0]:location[1]], '{') + location[0]
		depth := 0
		closeIndex := -1
		for index := open; index < len(source); index++ {
			switch source[index] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					closeIndex = index
					index = len(source)
				}
			}
		}
		if closeIndex < 0 {
			return nil, errors.New("unterminated message " + name)
		}
		block := source[open+1 : closeIndex]
		matches := protoFieldPattern.FindAllStringSubmatch(block, -1)
		fields := make([]protoField, 0, len(matches))
		for _, match := range matches {
			number, err := strconv.Atoi(match[2])
			if err != nil {
				return nil, err
			}
			fields = append(fields, protoField{name: match[1], number: number})
		}
		out[packageMatch[1]+"."+name] = fields
	}
	return out, nil
}
