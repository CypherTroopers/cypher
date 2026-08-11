// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package foundationv1

import (
	"reflect"
	"testing"

	"github.com/cypherium/cypher/aiinfra/schema"
)

type registeredSigningProjection interface {
	MessageTypeID() uint32
	SigningFieldNames() []string
}

func TestImplementedProjectionFieldCountAndOrderMatchRegistry(t *testing.T) {
	registry, err := schema.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	projections := []registeredSigningProjection{
		ProviderIdentitySigningProjection{},
		AgentIdentitySigningProjection{},
		HostIdentitySigningProjection{},
		DeviceIdentitySigningProjection{},
		MinerIdentitySigningProjection{},
		RunnerIdentitySigningProjection{},
		BuyerIdentitySigningProjection{},
		ServiceIdentitySigningProjection{},
		KeyLifecycleSigningProjection{},
		PolicyBundleSigningProjection{},
		AuditEventSigningProjection{},
		EvidenceRecordSigningProjection{},
		ExperimentPlanSigningProjection{},
		OwnershipTransferAuthorizationSigningProjection{},
	}
	for _, projection := range projections {
		message, ok := registry.LookupMessage(projection.MessageTypeID())
		if !ok {
			t.Fatalf("message type %d is not registered", projection.MessageTypeID())
		}
		got := projection.SigningFieldNames()
		want := make([]string, len(message.Fields))
		for index, field := range message.Fields {
			if field.Order != index+1 {
				t.Fatalf("%s registry order[%d] = %d", message.Name, index, field.Order)
			}
			want[index] = field.Name
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s signing fields\n got %#v\nwant %#v", message.Name, got, want)
		}
		if len(got) != message.Limits.MaxFields {
			t.Fatalf("%s implemented fields=%d registry max_fields=%d", message.Name, len(got), message.Limits.MaxFields)
		}
		if len(got) > 0 {
			got[0] = "mutated"
			if projection.SigningFieldNames()[0] == "mutated" {
				t.Fatalf("%s exposes mutable field descriptor", message.Name)
			}
		}
	}
}

func TestNestedProjectionFieldCountAndOrderMatchRegistry(t *testing.T) {
	registry, err := schema.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	projections := map[string]interface{ SigningFieldNames() []string }{
		"cph.aiinfra.common.v1.SchemaVersion":                  SchemaVersionSigningProjection{},
		"cph.aiinfra.common.v1.RecordMetadata":                 RecordMetadataSigningProjection{},
		"cph.aiinfra.foundation.v1.MetricCriterion":            MetricCriterionSigningProjection{},
		"cph.aiinfra.foundation.v1.MetricObservation":          MetricObservationSigningProjection{},
		"cph.aiinfra.foundation.v1.KeyClosure":                 KeyClosureSigningProjection{},
		"cph.aiinfra.foundation.v1.TransferEvidenceCommitment": TransferEvidenceCommitmentSigningProjection{},
		"cph.aiinfra.foundation.v1.TransferAuthority":          TransferAuthoritySigningProjection{},
	}
	if len(projections) != len(registry.Structures) {
		t.Fatalf("implemented structures=%d registry structures=%d", len(projections), len(registry.Structures))
	}
	for _, structure := range registry.Structures {
		projection, ok := projections[structure.Name]
		if !ok {
			t.Fatalf("registered structure %s has no implemented projection", structure.Name)
		}
		got := projection.SigningFieldNames()
		want := make([]string, len(structure.Fields))
		for index, field := range structure.Fields {
			if field.Order != index+1 {
				t.Fatalf("%s registry order[%d] = %d", structure.Name, index, field.Order)
			}
			want[index] = field.Name
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s signing fields\n got %#v\nwant %#v", structure.Name, got, want)
		}
		if len(got) != structure.Limits.MaxFields {
			t.Fatalf("%s implemented fields=%d registry max_fields=%d", structure.Name, len(got), structure.Limits.MaxFields)
		}
		if len(got) > 0 {
			got[0] = "mutated"
			if projection.SigningFieldNames()[0] == "mutated" {
				t.Fatalf("%s exposes mutable field descriptor", structure.Name)
			}
		}
	}
}
