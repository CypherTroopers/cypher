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
`dd55192a2780dc3329c909bdf98c04a09f0b2101dca64c0e3a0c8b26cc752a94`.
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

The compact canonical registry SHA-256 is
`d432c225de9f5747feaad2fd7971834d3a389f7e37e155a0761685e61acb779e`.
The Go test intentionally pins this digest. Any registry change therefore
requires an explicit version/compatibility review and a reviewed digest update.

`foundation/v1` contains explicit Go signing projections for all thirteen
registered top-level payloads and all four registered nested structures. These
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
of the thirteen foundation payloads. The selected oneof arm determines the
production message type ID; no caller-controlled duplicate numeric ID is
present on the wire. The wrapper itself is never a signing projection.

The production translator must recursively reject unknown Protobuf fields at
every message depth, reject unknown enum values, validate all required fields,
and preserve proto3 optional/oneof presence before calling `CanonicalBytes`.
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
This slice does not satisfy Gate 0. The production transport-to-signing
translator and runtime `SchemaValidator` are intentionally deferred to the
next Workstream 0.1b slice, and the remaining Gate 0 receiver-policy and
cross-component evidence must still pass independently.
