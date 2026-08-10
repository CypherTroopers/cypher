// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package foundationv1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
)

func TestIdentityProjectionsPositive(t *testing.T) {
	tests := []struct {
		name string
		id   uint32
		make func() ([]byte, error)
	}{
		{"agent", schema.MessageTypeAgentIdentity, func() ([]byte, error) { return validAgentIdentity().CanonicalBytes() }},
		{"host", schema.MessageTypeHostIdentity, func() ([]byte, error) { return validHostIdentity().CanonicalBytes() }},
		{"device", schema.MessageTypeDeviceIdentity, func() ([]byte, error) { return validDeviceIdentity().CanonicalBytes() }},
		{"miner", schema.MessageTypeMinerIdentity, func() ([]byte, error) { return validMinerIdentity().CanonicalBytes() }},
		{"runner", schema.MessageTypeRunnerIdentity, func() ([]byte, error) { return validRunnerIdentity().CanonicalBytes() }},
		{"buyer", schema.MessageTypeBuyerIdentity, func() ([]byte, error) { return validBuyerIdentity().CanonicalBytes() }},
		{"service", schema.MessageTypeServiceIdentity, func() ([]byte, error) { return validServiceIdentity().CanonicalBytes() }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := test.make()
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded) == 0 {
				t.Fatal("empty canonical projection")
			}
		})
	}
	if (AgentIdentitySigningProjection{}).MessageTypeID() != schema.MessageTypeAgentIdentity ||
		(HostIdentitySigningProjection{}).MessageTypeID() != schema.MessageTypeHostIdentity ||
		(DeviceIdentitySigningProjection{}).MessageTypeID() != schema.MessageTypeDeviceIdentity ||
		(MinerIdentitySigningProjection{}).MessageTypeID() != schema.MessageTypeMinerIdentity ||
		(RunnerIdentitySigningProjection{}).MessageTypeID() != schema.MessageTypeRunnerIdentity ||
		(BuyerIdentitySigningProjection{}).MessageTypeID() != schema.MessageTypeBuyerIdentity ||
		(ServiceIdentitySigningProjection{}).MessageTypeID() != schema.MessageTypeServiceIdentity {
		t.Fatal("identity projection message ID mismatch")
	}
}

func TestIdentityProjectionOneFieldMutationsFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		encode func() error
	}{
		{"agent.agent_id", func() error {
			value := validAgentIdentity()
			value.AgentID = ""
			_, err := value.CanonicalBytes()
			return err
		}},
		{"host.provider_site_id", func() error {
			value := validHostIdentity()
			value.ProviderSiteID = ""
			_, err := value.CanonicalBytes()
			return err
		}},
		{"device.vendor_digest", func() error {
			value := validDeviceIdentity()
			value.VendorSerialDigestSHA256 = [32]byte{}
			_, err := value.CanonicalBytes()
			return err
		}},
		{"miner.device_ids", func() error {
			value := validMinerIdentity()
			value.DeviceIDs = nil
			_, err := value.CanonicalBytes()
			return err
		}},
		{"runner.lease_id", func() error {
			value := validRunnerIdentity()
			value.LeaseID = ""
			_, err := value.CanonicalBytes()
			return err
		}},
		{"buyer.billing_identity", func() error {
			value := validBuyerIdentity()
			value.BillingIdentity = ""
			_, err := value.CanonicalBytes()
			return err
		}},
		{"service.environment", func() error {
			value := validServiceIdentity()
			value.DeploymentEnvironment = ""
			_, err := value.CanonicalBytes()
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.encode(); err == nil {
				t.Fatal("one-field mutation was accepted")
			}
		})
	}
}

func TestIdentityLifecycleAndFieldLimitsFailClosed(t *testing.T) {
	agent := validAgentIdentity()
	agent.State = 99
	if _, err := agent.CanonicalBytes(); !errors.Is(err, ErrInvalidEnumValue) {
		t.Fatalf("unknown identity state error = %v", err)
	}
	agent = validAgentIdentity()
	agent.ValidUntilUnixNano = agent.ValidFromUnixNano
	if _, err := agent.CanonicalBytes(); !errors.Is(err, ErrInvalidTimeRange) {
		t.Fatalf("invalid validity error = %v", err)
	}
	agent = validAgentIdentity()
	agent.AgentID = strings.Repeat("a", 253) // len32 + 253 > registry field cap 256.
	if _, err := agent.CanonicalBytes(); !errors.Is(err, ErrFieldLimit) {
		t.Fatalf("oversize agent_id error = %v", err)
	}

	miner := validMinerIdentity()
	miner.DeviceIDs = []string{"device-01", "device-01"}
	if _, err := miner.CanonicalBytes(); !errors.Is(err, ccse.ErrDuplicateSetValue) {
		t.Fatalf("duplicate device error = %v", err)
	}
	miner = validMinerIdentity()
	miner.DeviceIDs = make([]string, 65)
	for index := range miner.DeviceIDs {
		miner.DeviceIDs[index] = "device-" + string(rune('A'+index))
	}
	if _, err := miner.CanonicalBytes(); !errors.Is(err, ErrFieldLimit) {
		t.Fatalf("device count error = %v", err)
	}
}

func TestMinerDeviceSetOrderIsCanonical(t *testing.T) {
	first := validMinerIdentity()
	first.DeviceIDs = []string{"device-02", "device-01"}
	second := first
	second.DeviceIDs = []string{"device-01", "device-02"}
	firstBytes, err := first.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := second.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("device set permutation changed canonical projection")
	}
}

func TestScalarSchemaVersionMessageIsInline(t *testing.T) {
	encoded, err := validMetadata().canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) < 8 || binary.BigEndian.Uint32(encoded[:4]) != 1 || binary.BigEndian.Uint32(encoded[4:8]) != 0 {
		t.Fatalf("metadata does not begin with inline schema version: %x", encoded)
	}
	if binary.BigEndian.Uint32(encoded[:4]) == 8 {
		t.Fatal("metadata schema version unexpectedly has a scalar-message len32 frame")
	}
}

func validAgentIdentity() AgentIdentitySigningProjection {
	return AgentIdentitySigningProjection{
		Metadata: validMetadata(), AgentID: "agent-01", ProviderID: "provider-01", HostID: "host-01",
		SPIFFEID: "spiffe://cph.example/agent/01", KeyID: "key-agent-01", OwnershipGeneration: 1,
		ValidFromUnixNano: 1_800_000_000_000_000_000, ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2,
	}
}

func validHostIdentity() HostIdentitySigningProjection {
	return HostIdentitySigningProjection{
		Metadata: validMetadata(), HostID: "host-01", ProviderID: "provider-01", ProviderSiteID: "site-01",
		AttestationIdentity: "attestation:host:01", KeyID: "key-host-01", OwnershipGeneration: 1,
		ValidFromUnixNano: 1_800_000_000_000_000_000, ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2,
	}
}

func validDeviceIdentity() DeviceIdentitySigningProjection {
	return DeviceIdentitySigningProjection{
		Metadata: validMetadata(), DeviceID: "device-01", ProviderID: "provider-01", HostID: "host-01",
		VendorSerialDigestSHA256: digest32(0x31), AttestationIdentity: "attestation:device:01", KeyID: "key-device-01",
		OwnershipGeneration: 1, ValidFromUnixNano: 1_800_000_000_000_000_000,
		ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2,
	}
}

func validMinerIdentity() MinerIdentitySigningProjection {
	return MinerIdentitySigningProjection{
		Metadata: validMetadata(), MinerID: "miner-01", ProviderID: "provider-01", AgentID: "agent-01",
		DeviceIDs: []string{"device-01"}, PayoutIdentity: "cph:0x0000000000000000000000000000000000000001",
		KeyID: "key-miner-01", BindingGeneration: 1, ValidFromUnixNano: 1_800_000_000_000_000_000,
		ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2,
	}
}

func validRunnerIdentity() RunnerIdentitySigningProjection {
	return RunnerIdentitySigningProjection{
		Metadata: validMetadata(), RunnerAttemptID: "runner-attempt-01", ProviderID: "provider-01", AgentID: "agent-01",
		LeaseID: "lease-01", JobID: "job-01", AttemptID: "attempt-01", WorkloadIdentity: "spiffe://cph.example/runner/attempt-01",
		KeyID: "key-runner-01", ValidFromUnixNano: 1_800_000_000_000_000_000,
		ValidUntilUnixNano: 1_800_003_600_000_000_000, State: 2,
	}
}

func validBuyerIdentity() BuyerIdentitySigningProjection {
	return BuyerIdentitySigningProjection{
		Metadata: validMetadata(), BuyerID: "buyer-01", OrganizationIdentityURI: "spiffe://cph.example/buyer/01",
		BillingIdentity: "billing-01", KeyID: "key-buyer-01", AuthorizationGeneration: 1,
		ValidFromUnixNano: 1_800_000_000_000_000_000, ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2,
	}
}

func validServiceIdentity() ServiceIdentitySigningProjection {
	return ServiceIdentitySigningProjection{
		Metadata: validMetadata(), ServiceID: "service-01", ServiceName: "lease-service",
		SPIFFEID: "spiffe://cph.example/service/lease", DeploymentEnvironment: "testnet", KeyID: "key-service-01",
		CredentialGeneration: 1, ValidFromUnixNano: 1_800_000_000_000_000_000,
		ValidUntilUnixNano: 1_800_086_400_000_000_000, State: 2,
	}
}
