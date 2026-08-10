# CPH Canonical Signing Encoding v1

This directory is the transport-independent conformance kernel for Master
Architecture §10.1 and ADR-0010. It is not a Protobuf canonicalizer. A message
schema first projects its typed payload into the ordered encoding below; CCSE
then binds that projection to its authorization domain and envelope.

## Primitive encoding

All integers are fixed-width big-endian. Signed `i64` uses two's complement.

```text
bool             = 0x00 | 0x01
u32              = 4 bytes
u64              = 8 bytes
i64              = 8 bytes
bytes            = u32(length) || value
string           = bytes(valid UTF-8 already in NFC)
optional<T>      = bool(present) || (canonical(T) when present)
ordered-list<T>  = u32(count) || repeated bytes(canonical(T))
set<T>           = ordered-list(sorted unique canonical(T) byte strings)
```

An absent optional must retain no hidden value. Maps, floats, host-width
integers, locale conversion, implicit Unicode normalization, and transport wire
bytes are forbidden. Schema-fixed byte values still carry the `bytes` length
prefix; the schema additionally checks the exact width.

## Domain projection v1

The canonical domain is the following fields in exact order:

```text
string purpose
string sender_identity
set<string> audience
optional<string> tenant_organization
optional<string> provider_organization
fixed-bytes[32] chain_id_uint256
fixed-bytes[32] genesis_hash
string environment
u32 protocol_major, u32 protocol_minor
u32 schema_major, u32 schema_minor
u32 signature_algorithm_id
string signature_key_id
i64 issued_at_unix_nano
i64 expires_at_unix_nano
u32 counter_kind
u64 counter
string replay_domain_id
```

`chain_id_uint256` is an unsigned 256-bit value in big-endian order. Message,
correlation, and causation identifiers are exactly 16 bytes before their CCSE
byte-string prefix.

## Envelope-without-signature projection v1

```text
u32 protocol_major, u32 protocol_minor
u32 schema_major, u32 schema_minor
fixed-bytes[16] message_id
fixed-bytes[16] correlation_id
optional<fixed-bytes[16]> causation_id
string sender_identity
fixed-bytes[32] chain_id_uint256
string environment
i64 issued_at_unix_nano
i64 expires_at_unix_nano
u32 counter_kind
u64 counter
fixed-bytes[32] sha256(canonical_payload)
u32 signature_algorithm_id
string signature_key_id
set<Extension> extensions
```

An `Extension` is `u32 id || bool critical || bytes value`. Its canonical
encoding begins with the ID, so ascending unsigned ID order is also encoded-byte
order. Duplicate or zero IDs are invalid. CCSE-v1 rejects every signed extension
that is absent from the exact message registry, including one the sender marks
noncritical. A schema may ignore an unknown transport field only when that field
is explicitly outside the canonical signing projection.

## Record and signature

```text
preimage = "CPH-AIIE-CCSE-V1\0"
         || u32(message_type_id)
         || u32(schema_major) || u32(schema_minor)
         || u32(len(domain)) || domain
         || u64(len(envelope_without_signature)) || envelope_without_signature
         || u64(len(canonical_payload)) || canonical_payload

record_digest = SHA-256(preimage)
```

The reference off-chain profile signs `record_digest` with Ed25519. Algorithm
and key IDs occur in both bound projections and must match exactly. P-256 is
reserved for an explicitly policy-scoped TPM/HSM adapter; unsupported
algorithms fail closed. Solidity-facing authorization uses the separately
versioned EIP-712 bridge and commits this SHA-256 digest.

## Receiver rules

A receiver applies encoded/decoded limits, reconstructs canonical bytes, fixes
message type, schema/protocol, purpose, exact audience set, sender policy,
tenant/provider, chain, genesis, environment, replay domain, and counter kind,
then checks validity time and key lifecycle, verifies the signature, validates
the exact registered extension set and typed payload canonicality, and finally
performs an atomic replay admission.

CCSE-v1 NFC validation is pinned to Unicode 15.0.0, implemented here by
`golang.org/x/text/unicode/norm` v0.38.0. Other language implementations must
use Unicode 15.0.0 normalization data and pass the same conformance vectors.

The replay sequence namespace is scoped by replay domain, sender, environment,
chain, and genesis. It deliberately does not include the signing key, so key
rotation cannot reset a sequence. An exact repeated message ID and digest is
classified as a duplicate and must return the stored idempotent result without
executing the operation again. Reusing an ID with different bytes, or using a
new ID at a stale sequence, fails closed.

The in-memory key and replay stores in this package are conformance/development
implementations. Production services must use durable IAM and replay state with
the same atomic semantics. `ReplayStore.Execute` owns one authoritative database
transaction: it checks the inbox/sequence, invokes the bound handler with that
transaction in its context, and commits the business row, outcome and outbox
together. A handler error or process/transaction abort leaves no replay
reservation or business effect, so retry is safe. The handler must never perform
an uncommitted external side effect; it records a durable outbox intent instead.
