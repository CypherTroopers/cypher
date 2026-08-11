# CPH AIIE foundation schemas

This directory is the first Workstream 0 schema slice. It deliberately keeps
two representations separate:

- `common/v1/common.proto`, `foundation/v1/foundation.proto`, and
  `transport/v1/foundation_transport.proto` are modern Protobuf
  transport/data-model sources;
- `ccse/v1/registry.json` is the authorization source for ordered CCSE-v1
  signing projections.

Protobuf bytes, including deterministic Protobuf bytes, are not CCSE bytes and
must never be signed as a substitute. The checked-in `*.pb.go` files are
transport bindings only. They use the official
`google.golang.org/protobuf` runtime pinned to `v1.36.11` in the root
module. This modern runtime is separate from, and does not replace, the legacy
`github.com/dedis/protobuf` dependency used elsewhere in the node.

## Pinned generation and compatibility gate

Schema-development dependencies are isolated in `tools/go.mod`; they do not
enter the node's runtime dependency graph:

- [Buf CLI `v1.69.0`](https://github.com/bufbuild/buf/releases/tag/v1.69.0);
- [`protoc-gen-go` `v1.36.11`](https://github.com/protocolbuffers/protobuf-go/releases/tag/v1.36.11).

Both versions correspond to their official upstream releases. The generator
build also requires the reviewed Go `go1.26.2` toolchain with
`GOTOOLCHAIN=local`, an empty `GOEXPERIMENT`, and `CGO_ENABLED=0`; it rejects
different compiler or binary build metadata instead of silently downloading a
new toolchain or linking an ambient C library. Go module `h1` sums and the
complete transitive graph are fixed in `tools/go.sum`.
`scripts/bootstrap-tools.sh` runs `go mod verify`, builds both binaries with
`-mod=readonly -trimpath` into `.codex-tmp/schema-tools/bin`, and rejects a
binary whose compiler, CGO setting, or reported application version is not
exact. Buf supplies the Protobuf compiler, so generation never invokes an
ambient `protoc`.

Run the complete read-only gate from the repository root:

```console
aiinfra/schema/scripts/verify.sh
```

The gate:

1. requires canonical `buf format` output;
2. applies Buf `STANDARD` lint with comment suppressions disabled;
3. applies Buf `FILE` breaking checks against
   `descriptor/baseline-v1.binpb`;
4. generates Go bindings twice into separate temporary directories and
   requires byte-identical results;
5. requires those results to equal the checked-in `*.pb.go` files; and
6. rebuilds a standard `FileDescriptorSet` and requires it to equal
   `descriptor/current.binpb`.

The sole lint exception is `PACKAGE_DIRECTORY_MATCH`: the stable package
prefix is `cph.aiinfra`, while this repository intentionally places the Buf
module at `aiinfra/schema`. All other `STANDARD` rules remain active.
`buf.yaml` and `buf.gen.yaml` use the documented
[Buf v2 configuration](https://buf.build/docs/configuration/v2/buf-yaml/).
`scripts/generate.sh` is the explicit mutating regeneration command; it does
not update the compatibility baseline.

The immutable v1 compatibility baseline has SHA-256
`6aff2b5c3321eefc7439fab7e65a6ace41f943cbddf6a1de85dd5a296fb7d3a2`.
The additive transport-wrapper descriptor image has SHA-256
`bf90801eec8ad89ad865f671f9e4b7d736560a9f4eb01189b48b87a804c1151a`.
The baseline must only change after an explicit compatibility/version review;
adding the wrapper updated only `current.binpb`.
Normal `go test` uses checked-in bindings and descriptor images and therefore
does not execute Buf, `protoc-gen-go`, or their untracked binaries. Once the
ordinary root Go dependencies are restored, the tests run offline. A fresh
machine needs network access once for those dependencies; the explicit
generation gate additionally populates its isolated, verified tool-module
cache. After that, `GOPROXY=off aiinfra/schema/scripts/verify.sh` is
supported.

CCSE fixed-width byte fields still use the baseline byte-string `len32` prefix.
An optional fixed-width scalar adds a one-byte presence marker. A fixed-width
set adds `count32`, then an outer `len32` frame around every already-canonical
`len32 || fixed-bytes` element. Registry bounds include all of these frames.
Scalar nested messages are projected inline in their registered field order,
without another length prefix. Message collections use `count32` and one outer
`len32` element frame around each canonical nested-message body.

Production message type IDs are fixed as follows. IDs `1..65535`, including
the conformance vector ID `100`, are reserved for tests and cannot appear in
the production registry.

| ID (hex) | ID (decimal) | Signed payload |
|---|---:|---|
| `0x00010001` | 65537 | `ProviderIdentity` |
| `0x00010002` | 65538 | `AgentIdentity` |
| `0x00010003` | 65539 | `HostIdentity` |
| `0x00010004` | 65540 | `DeviceIdentity` |
| `0x00010005` | 65541 | `MinerIdentity` |
| `0x00010006` | 65542 | `RunnerIdentity` |
| `0x00010007` | 65543 | `BuyerIdentity` |
| `0x00010008` | 65544 | `ServiceIdentity` |
| `0x00010009` | 65545 | `KeyLifecycle` |
| `0x0001000a` | 65546 | `PolicyBundle` |
| `0x0001000b` | 65547 | `AuditEvent` |
| `0x0001000c` | 65548 | `EvidenceRecord` |
| `0x0001000d` | 65549 | `ExperimentPlan` |
| `0x0001000e` | 65550 | `OwnershipTransferAuthorization` |

The compact canonical registry SHA-256 is
`5a4faaee3e51629aed73edbb17047a865b223add9aece7dbe90f27fbfd4a30eb`.
The reviewed, human-readable `registry.json` file SHA-256 is
`899ada6d2ba3753d61d137c05b1294fd8b39c02b26ffc8a960831b7cf9ef7890`.
The Go test intentionally pins this digest. Any registry change therefore
requires an explicit version/compatibility review and a reviewed digest update.

`foundation/v1` contains explicit Go signing projections for all fourteen
registered top-level payloads and all seven registered nested structures. These
are not generated Protobuf types. Offline tests compare the checked descriptor
against `registry.json` for package/message identity, field order and number,
name, scalar/message kind and target, repeated set/list shape, proto3 optional
presence and oneof shape. They reject maps, floating-point fields,
unregistered signing messages and enums outside pinned contiguous ranges with
an explicit zero `*_UNSPECIFIED` sentinel. Four common messages
(`ProtocolVersion`, `TransportSigningDomain`, `TransportExtension`, and
`TransportEnvelope`) and the `transport/v1.SignedFoundationRecord` wrapper are
explicitly allowlisted as transport-only rather than silently treated as
signing projections.

`SignedFoundationRecord` carries the signing domain, envelope, and exactly one
of the fourteen foundation payloads. The selected oneof arm determines the
production message type ID; no caller-controlled duplicate numeric ID is
present on the wire. The wrapper itself is never a signing projection.

Registry compatibility version 1.1 adds
`OwnershipTransferAuthorization` without changing the schema version, field
order, message type ID, or canonical bytes of any 1.0 payload. Its nested
`KeyClosure`, `TransferEvidenceCommitment`, and `TransferAuthority` projections
commit terminal key state, typed evidence records, and identity/key authority
pairs. The transfer payload deliberately contains neither a signer-record
digest in each authority pair nor a key-enrollment/proof-of-possession digest;
those would duplicate retained CCSE evidence or introduce digest cycles. It
also contains no caller-selected quorum or separation rule. The IAM receiver's
frozen profile determines the exact signer sets.

Transfer evidence is a closed seven-kind enum with a rejected zero
`UNSPECIFIED` sentinel. Old-provider and new-provider
authority evidence are always required. Agent transfers additionally require
descendant-identity and lease/offer/workload closure evidence; Host and Device
transfers require their matching sanitation attestation and new-attestation
readiness evidence. Multiple distinct records of the same applicable kind are
allowed, while an identical `(kind, CCSE-record-digest)` pair is rejected by
canonical set encoding. Evidence, key-closure, and authority collections are
bounded at 64, 256, and 32 entries per authority side respectively. The
key-closure limit supports the full 256-key IAM subject-key lifecycle contract;
both boundaries reject a 257th key.
Their 4,608-, 77,824-, and 50,176-byte field bounds include CCSE count and
element frames; the sum of every declared field maximum is 194,668 bytes and
therefore fits the 192 KiB top-level bound. The 1,536-byte authority body bound
accommodates the 1,024-byte identity and 256-byte key fields with their
canonical frames. These limits permit threshold evidence without making
transport preflight unbounded.
`ccse_record_digest_sha256` is `ccse.Record.Digest`, the SHA-256 of the exact
canonical signature preimage; the complete record, including its signature,
must still be stored because the digest is a commitment, not evidence storage.

The production translator recursively rejects unknown Protobuf fields at every
message depth, rejects unknown enum values, validates all required fields, and
preserves proto3 optional/oneof presence before calling `CanonicalBytes`.
Generated unmarshalling alone is not authorization validation and is not a
substitute for that fail-closed translator.

The projection layer enforces local canonical, lifecycle, field-size,
collection, rational and enum invariants. Receiver policy still has to resolve
identity ownership and active keys, verify PolicyBundle approver-key ownership
and separation of duties, compare EvidenceRecord to its frozen ExperimentPlan,
and resolve audit sequence history. In v1, policy approver identities and key
IDs are independent sets rather than signed identity/key pairs; ownership must
therefore be checked externally. The first AuditEvent previous-digest anchor is
also a deployment policy input and must be fixed before an audit store ships.
For ownership transfers, the schema boundary is only the signed commitment.
IAM must retain and independently reverify every complete transfer
authorization and every typed evidence CCSE record, then validate the exact
old/new authority sets against its frozen profile before mutation. The
remaining Gate 0 receiver-policy and cross-component evidence must still pass
independently.
