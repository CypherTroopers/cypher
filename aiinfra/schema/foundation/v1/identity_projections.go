// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package foundationv1

import (
	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
)

const (
	identityMaxPayload = 24576
	minerMaxPayload    = 32768
	runnerMaxPayload   = 28672
)

var (
	agentIdentitySigningFields = [...]string{
		"metadata", "agent_id", "provider_id", "host_id", "spiffe_id", "key_id",
		"ownership_generation", "valid_from_unix_nano", "valid_until_unix_nano", "state",
	}
	hostIdentitySigningFields = [...]string{
		"metadata", "host_id", "provider_id", "provider_site_id", "attestation_identity", "key_id",
		"ownership_generation", "valid_from_unix_nano", "valid_until_unix_nano", "state",
	}
	deviceIdentitySigningFields = [...]string{
		"metadata", "device_id", "provider_id", "host_id", "vendor_serial_digest_sha256",
		"attestation_identity", "key_id", "ownership_generation", "valid_from_unix_nano",
		"valid_until_unix_nano", "state",
	}
	minerIdentitySigningFields = [...]string{
		"metadata", "miner_id", "provider_id", "agent_id", "device_ids", "payout_identity",
		"key_id", "binding_generation", "valid_from_unix_nano", "valid_until_unix_nano", "state",
	}
	runnerIdentitySigningFields = [...]string{
		"metadata", "runner_attempt_id", "provider_id", "agent_id", "lease_id", "job_id", "attempt_id",
		"workload_identity", "key_id", "valid_from_unix_nano", "valid_until_unix_nano", "state",
	}
	buyerIdentitySigningFields = [...]string{
		"metadata", "buyer_id", "organization_identity_uri", "billing_identity", "key_id",
		"authorization_generation", "valid_from_unix_nano", "valid_until_unix_nano", "state",
	}
	serviceIdentitySigningFields = [...]string{
		"metadata", "service_id", "service_name", "spiffe_id", "deployment_environment", "key_id",
		"credential_generation", "valid_from_unix_nano", "valid_until_unix_nano", "state",
	}
)

type AgentIdentitySigningProjection struct {
	Metadata            RecordMetadataSigningProjection
	AgentID             string
	ProviderID          string
	HostID              string
	SPIFFEID            string
	KeyID               string
	OwnershipGeneration uint64
	ValidFromUnixNano   int64
	ValidUntilUnixNano  int64
	State               uint32
}

type HostIdentitySigningProjection struct {
	Metadata            RecordMetadataSigningProjection
	HostID              string
	ProviderID          string
	ProviderSiteID      string
	AttestationIdentity string
	KeyID               string
	OwnershipGeneration uint64
	ValidFromUnixNano   int64
	ValidUntilUnixNano  int64
	State               uint32
}

type DeviceIdentitySigningProjection struct {
	Metadata                 RecordMetadataSigningProjection
	DeviceID                 string
	ProviderID               string
	HostID                   string
	VendorSerialDigestSHA256 [32]byte
	AttestationIdentity      string
	KeyID                    string
	OwnershipGeneration      uint64
	ValidFromUnixNano        int64
	ValidUntilUnixNano       int64
	State                    uint32
}

type MinerIdentitySigningProjection struct {
	Metadata           RecordMetadataSigningProjection
	MinerID            string
	ProviderID         string
	AgentID            string
	DeviceIDs          []string
	PayoutIdentity     string
	KeyID              string
	BindingGeneration  uint64
	ValidFromUnixNano  int64
	ValidUntilUnixNano int64
	State              uint32
}

type RunnerIdentitySigningProjection struct {
	Metadata           RecordMetadataSigningProjection
	RunnerAttemptID    string
	ProviderID         string
	AgentID            string
	LeaseID            string
	JobID              string
	AttemptID          string
	WorkloadIdentity   string
	KeyID              string
	ValidFromUnixNano  int64
	ValidUntilUnixNano int64
	State              uint32
}

type BuyerIdentitySigningProjection struct {
	Metadata                RecordMetadataSigningProjection
	BuyerID                 string
	OrganizationIdentityURI string
	BillingIdentity         string
	KeyID                   string
	AuthorizationGeneration uint64
	ValidFromUnixNano       int64
	ValidUntilUnixNano      int64
	State                   uint32
}

type ServiceIdentitySigningProjection struct {
	Metadata              RecordMetadataSigningProjection
	ServiceID             string
	ServiceName           string
	SPIFFEID              string
	DeploymentEnvironment string
	KeyID                 string
	CredentialGeneration  uint64
	ValidFromUnixNano     int64
	ValidUntilUnixNano    int64
	State                 uint32
}

func (p AgentIdentitySigningProjection) CanonicalBytes() ([]byte, error) {
	metadata, err := p.Metadata.prepare()
	if err != nil {
		return nil, err
	}
	if err := validateIdentityLifecycle(p.OwnershipGeneration, p.ValidFromUnixNano, p.ValidUntilUnixNano, p.State); err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{"agent_id", p.AgentID, 256}, {"provider_id", p.ProviderID, 256}, {"host_id", p.HostID, 256},
		{"spiffe_id", p.SPIFFEID, 1024}, {"key_id", p.KeyID, 256},
	} {
		if err := validateRequiredStringField(field.name, field.value, field.max); err != nil {
			return nil, err
		}
	}
	return ccse.Marshal(identityMaxPayload, func(out *ccse.Encoder) {
		metadata.encode(out)
		out.String(p.AgentID)
		out.String(p.ProviderID)
		out.String(p.HostID)
		out.String(p.SPIFFEID)
		out.String(p.KeyID)
		out.Uint64(p.OwnershipGeneration)
		out.Int64(p.ValidFromUnixNano)
		out.Int64(p.ValidUntilUnixNano)
		out.Uint32(p.State)
	})
}

func (AgentIdentitySigningProjection) MessageTypeID() uint32 { return schema.MessageTypeAgentIdentity }
func (AgentIdentitySigningProjection) SigningFieldNames() []string {
	return copyFieldNames(agentIdentitySigningFields[:])
}

func (p HostIdentitySigningProjection) CanonicalBytes() ([]byte, error) {
	metadata, err := p.Metadata.prepare()
	if err != nil {
		return nil, err
	}
	if err := validateIdentityLifecycle(p.OwnershipGeneration, p.ValidFromUnixNano, p.ValidUntilUnixNano, p.State); err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{"host_id", p.HostID, 256}, {"provider_id", p.ProviderID, 256}, {"provider_site_id", p.ProviderSiteID, 256},
		{"attestation_identity", p.AttestationIdentity, 1024}, {"key_id", p.KeyID, 256},
	} {
		if err := validateRequiredStringField(field.name, field.value, field.max); err != nil {
			return nil, err
		}
	}
	return ccse.Marshal(identityMaxPayload, func(out *ccse.Encoder) {
		metadata.encode(out)
		out.String(p.HostID)
		out.String(p.ProviderID)
		out.String(p.ProviderSiteID)
		out.String(p.AttestationIdentity)
		out.String(p.KeyID)
		out.Uint64(p.OwnershipGeneration)
		out.Int64(p.ValidFromUnixNano)
		out.Int64(p.ValidUntilUnixNano)
		out.Uint32(p.State)
	})
}

func (HostIdentitySigningProjection) MessageTypeID() uint32 { return schema.MessageTypeHostIdentity }
func (HostIdentitySigningProjection) SigningFieldNames() []string {
	return copyFieldNames(hostIdentitySigningFields[:])
}

func (p DeviceIdentitySigningProjection) CanonicalBytes() ([]byte, error) {
	metadata, err := p.Metadata.prepare()
	if err != nil {
		return nil, err
	}
	if err := validateIdentityLifecycle(p.OwnershipGeneration, p.ValidFromUnixNano, p.ValidUntilUnixNano, p.State); err != nil {
		return nil, err
	}
	if err := validateRequiredFixed32("vendor_serial_digest_sha256", p.VendorSerialDigestSHA256); err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{"device_id", p.DeviceID, 256}, {"provider_id", p.ProviderID, 256}, {"host_id", p.HostID, 256},
		{"attestation_identity", p.AttestationIdentity, 1024}, {"key_id", p.KeyID, 256},
	} {
		if err := validateRequiredStringField(field.name, field.value, field.max); err != nil {
			return nil, err
		}
	}
	return ccse.Marshal(identityMaxPayload, func(out *ccse.Encoder) {
		metadata.encode(out)
		out.String(p.DeviceID)
		out.String(p.ProviderID)
		out.String(p.HostID)
		out.FixedBytes(p.VendorSerialDigestSHA256[:], len(p.VendorSerialDigestSHA256))
		out.String(p.AttestationIdentity)
		out.String(p.KeyID)
		out.Uint64(p.OwnershipGeneration)
		out.Int64(p.ValidFromUnixNano)
		out.Int64(p.ValidUntilUnixNano)
		out.Uint32(p.State)
	})
}

func (DeviceIdentitySigningProjection) MessageTypeID() uint32 {
	return schema.MessageTypeDeviceIdentity
}
func (DeviceIdentitySigningProjection) SigningFieldNames() []string {
	return copyFieldNames(deviceIdentitySigningFields[:])
}

func (p MinerIdentitySigningProjection) CanonicalBytes() ([]byte, error) {
	metadata, err := p.Metadata.prepare()
	if err != nil {
		return nil, err
	}
	if err := validateIdentityLifecycle(p.BindingGeneration, p.ValidFromUnixNano, p.ValidUntilUnixNano, p.State); err != nil {
		return nil, err
	}
	devices, err := canonicalStringSetField("device_ids", p.DeviceIDs, 64, 17408, true)
	if err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{"miner_id", p.MinerID, 256}, {"provider_id", p.ProviderID, 256}, {"agent_id", p.AgentID, 256},
		{"payout_identity", p.PayoutIdentity, 256}, {"key_id", p.KeyID, 256},
	} {
		if err := validateRequiredStringField(field.name, field.value, field.max); err != nil {
			return nil, err
		}
	}
	return ccse.Marshal(minerMaxPayload, func(out *ccse.Encoder) {
		metadata.encode(out)
		out.String(p.MinerID)
		out.String(p.ProviderID)
		out.String(p.AgentID)
		out.EncodedSet(devices)
		out.String(p.PayoutIdentity)
		out.String(p.KeyID)
		out.Uint64(p.BindingGeneration)
		out.Int64(p.ValidFromUnixNano)
		out.Int64(p.ValidUntilUnixNano)
		out.Uint32(p.State)
	})
}

func (MinerIdentitySigningProjection) MessageTypeID() uint32 { return schema.MessageTypeMinerIdentity }
func (MinerIdentitySigningProjection) SigningFieldNames() []string {
	return copyFieldNames(minerIdentitySigningFields[:])
}

func (p RunnerIdentitySigningProjection) CanonicalBytes() ([]byte, error) {
	metadata, err := p.Metadata.prepare()
	if err != nil {
		return nil, err
	}
	if err := validateRequiredTimeRange("runner credential validity", p.ValidFromUnixNano, p.ValidUntilUnixNano); err != nil {
		return nil, err
	}
	if err := validateEnumRange("state", p.State, 1, 6); err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{"runner_attempt_id", p.RunnerAttemptID, 256}, {"provider_id", p.ProviderID, 256}, {"agent_id", p.AgentID, 256},
		{"lease_id", p.LeaseID, 256}, {"job_id", p.JobID, 256}, {"attempt_id", p.AttemptID, 256},
		{"workload_identity", p.WorkloadIdentity, 1024}, {"key_id", p.KeyID, 256},
	} {
		if err := validateRequiredStringField(field.name, field.value, field.max); err != nil {
			return nil, err
		}
	}
	return ccse.Marshal(runnerMaxPayload, func(out *ccse.Encoder) {
		metadata.encode(out)
		out.String(p.RunnerAttemptID)
		out.String(p.ProviderID)
		out.String(p.AgentID)
		out.String(p.LeaseID)
		out.String(p.JobID)
		out.String(p.AttemptID)
		out.String(p.WorkloadIdentity)
		out.String(p.KeyID)
		out.Int64(p.ValidFromUnixNano)
		out.Int64(p.ValidUntilUnixNano)
		out.Uint32(p.State)
	})
}

func (RunnerIdentitySigningProjection) MessageTypeID() uint32 {
	return schema.MessageTypeRunnerIdentity
}
func (RunnerIdentitySigningProjection) SigningFieldNames() []string {
	return copyFieldNames(runnerIdentitySigningFields[:])
}

func (p BuyerIdentitySigningProjection) CanonicalBytes() ([]byte, error) {
	metadata, err := p.Metadata.prepare()
	if err != nil {
		return nil, err
	}
	if err := validateIdentityLifecycle(p.AuthorizationGeneration, p.ValidFromUnixNano, p.ValidUntilUnixNano, p.State); err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{"buyer_id", p.BuyerID, 256}, {"organization_identity_uri", p.OrganizationIdentityURI, 1024},
		{"billing_identity", p.BillingIdentity, 256}, {"key_id", p.KeyID, 256},
	} {
		if err := validateRequiredStringField(field.name, field.value, field.max); err != nil {
			return nil, err
		}
	}
	return ccse.Marshal(identityMaxPayload, func(out *ccse.Encoder) {
		metadata.encode(out)
		out.String(p.BuyerID)
		out.String(p.OrganizationIdentityURI)
		out.String(p.BillingIdentity)
		out.String(p.KeyID)
		out.Uint64(p.AuthorizationGeneration)
		out.Int64(p.ValidFromUnixNano)
		out.Int64(p.ValidUntilUnixNano)
		out.Uint32(p.State)
	})
}

func (BuyerIdentitySigningProjection) MessageTypeID() uint32 { return schema.MessageTypeBuyerIdentity }
func (BuyerIdentitySigningProjection) SigningFieldNames() []string {
	return copyFieldNames(buyerIdentitySigningFields[:])
}

func (p ServiceIdentitySigningProjection) CanonicalBytes() ([]byte, error) {
	metadata, err := p.Metadata.prepare()
	if err != nil {
		return nil, err
	}
	if err := validateIdentityLifecycle(p.CredentialGeneration, p.ValidFromUnixNano, p.ValidUntilUnixNano, p.State); err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{"service_id", p.ServiceID, 256}, {"service_name", p.ServiceName, 256}, {"spiffe_id", p.SPIFFEID, 1024},
		{"deployment_environment", p.DeploymentEnvironment, 128}, {"key_id", p.KeyID, 256},
	} {
		if err := validateRequiredStringField(field.name, field.value, field.max); err != nil {
			return nil, err
		}
	}
	return ccse.Marshal(identityMaxPayload, func(out *ccse.Encoder) {
		metadata.encode(out)
		out.String(p.ServiceID)
		out.String(p.ServiceName)
		out.String(p.SPIFFEID)
		out.String(p.DeploymentEnvironment)
		out.String(p.KeyID)
		out.Uint64(p.CredentialGeneration)
		out.Int64(p.ValidFromUnixNano)
		out.Int64(p.ValidUntilUnixNano)
		out.Uint32(p.State)
	})
}

func (ServiceIdentitySigningProjection) MessageTypeID() uint32 {
	return schema.MessageTypeServiceIdentity
}
func (ServiceIdentitySigningProjection) SigningFieldNames() []string {
	return copyFieldNames(serviceIdentitySigningFields[:])
}

func validateIdentityLifecycle(generation uint64, validFrom, validUntil int64, state uint32) error {
	if err := validatePositive("identity generation", generation); err != nil {
		return err
	}
	if err := validateRequiredTimeRange("identity validity", validFrom, validUntil); err != nil {
		return err
	}
	return validateEnumRange("state", state, 1, 6)
}

func copyFieldNames(source []string) []string {
	return append([]string(nil), source...)
}
