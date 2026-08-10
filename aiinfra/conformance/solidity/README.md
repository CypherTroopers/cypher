# CCSE-v1 Solidity-facing EIP-712 bridge

This directory is the Gate 0 Solidity-facing conformance profile for Master
Architecture §10.1 and ADR-0010. It is deliberately a bridge, not a Solidity
implementation of CCSE or Ed25519.

An authorized bridge signer first verifies the complete CCSE-v1 record off
chain: canonical projection, SHA-256 record digest, Ed25519/P-256 policy,
audience, chain/genesis/environment, time, key lifecycle, schema, replay, and
atomic admission. The signer may then authorize an EVM financial operation with
EIP-712/secp256k1. A contract trusts that separately governed signer role; the
32-byte CCSE digest alone is not evidence that those off-chain checks ran.
The adapter must derive the EIP-712 domain and every authorization field from
that verified typed record plus canonical financial state. It must never sign
two independently client-supplied CCSE and EIP-712 field sets.

The source CCSE golden vector currently has conformance-only message type 100
and an evidence-publication purpose. It is reused here only to prove exact
SHA-256 digest commitment across the bridge. Policy MUST NOT treat that fixture
as a financial authorization. A production bridge type requires a registered
financial CCSE message/purpose/audience and matching cross-language vectors.

## Frozen profile v1

The EIP-712 domain type is exactly:

```text
EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)
```

`name` and `version` are protocol configuration, `chainId` is the runtime EVM
chain, `verifyingContract` is the consuming contract, and `salt` is the exact
32-byte CCSE `genesis_hash`. No field may be supplied by an untrusted request in
a production consumer.

The primary type is exactly:

```text
CPHFinancialAuthorizationV1(
  bytes32 ccseRecordDigest,
  bytes32 financialOperationId,
  bytes32 leaseId,
  bytes32 receiptId,
  bytes32 settlementId,
  bytes32 assetId,
  address payer,
  address payee,
  uint256 amountSmallestUnit,
  uint64 expectedGeneration,
  uint64 validAfterUnix,
  uint64 validBeforeUnix
)
```

The line breaks above are explanatory only; `eip712_bridge_vectors.json` carries
the exact single-line type string. IDs are already-canonical 32-byte values
from the authoritative financial state. The bridge does not derive them from
display strings. Amount is an integer in the asset's declared smallest unit.
The half-open validity window is `[validAfterUnix, validBeforeUnix)`.
The bridge signer must derive that seconds-resolution window fail-closed from
policy and keep it inside the verified CCSE nanosecond validity window; the EVM
window may shorten but never extend the source authorization. `assetId` must
resolve to immutable asset/decimals metadata for the signed amount.

This first type is a conformance authorization shared by settlement-style
financial operations. Each future production financial operation must receive
its own registered primary type and positive/negative vectors if its canonical
identifier set differs; optional zero placeholders are not permitted.

## Consumer obligations

A state-changing consumer must:

1. derive domain name/version/genesis from immutable governance configuration
   and use `block.chainid` plus `address(this)`;
2. validate the financial IDs, asset, amount, generation, and validity window
   against canonical state, including a compare-and-swap on
   `expectedGeneration`;
3. authorize the recovered bridge signer through a least-privilege role and
   key-rotation policy; and
4. consume `financialOperationId` atomically with the economic effect so a
   signature cannot be replayed.

`CCSEEIP712VerifierV1` supplies domain-bound hashing and signature recovery but
intentionally does not invent role, ledger, or replay storage for an unknown
future contract. `ecrecover` is the only signature primitive; high-s signatures,
invalid `v`, zero components, and the zero recovered address fail closed.

## Conformance execution

The Solidity compiler is pinned by artifact name, release commit, official URL,
and SHA-256 in `solc.lock.json`. Provision it into the ignored repository-local
toolchain directory (never into this tracked directory):

```sh
./aiinfra/conformance/solidity/fetch-solc.sh
```

The provisioning script refuses an existing binary with a different digest.
The test independently re-hashes the executable and verifies its exact version
output before allowing compilation. A missing, non-executable, wrong-version,
or wrong-digest compiler fails the test; it is never skipped or replaced by a
compiler found incidentally on `PATH`.

`solc_standard_json_profile.json` is the input sent to the compiler. It fixes
the optimizer at 200 runs, disables `viaIR`, targets the legacy-compatible
`paris` EVM, disables CBOR/bytecode-hash metadata, uses literal source content,
and requests only ABI plus creation/runtime bytecode. The harness compiles the
profile twice and requires byte-identical standard-JSON output.

Ordinary Go tests run the portable vector checks and deliberately do not need
an untracked compiler binary:

```sh
GO111MODULE=on go test -mod=readonly ./aiinfra/conformance/solidity
```

Run the fail-closed compiler and Cypher-EVM Gate harness explicitly from the
repository root:

```sh
./aiinfra/conformance/solidity/run-conformance.sh
```

`solc_evm_test.go` is protected by the `solidity_conformance` build tag so a
fresh checkout can run its normal unit suite before provisioning external
tools. The Gate script does not skip that test: it provisions the exact locked
compiler, then runs `go test -tags=solidity_conformance` with module mode and
repository-local temporary/cache directories. A future Workstream 0 CI job
must make this script mandatory; until that job and independent review exist,
Gate 0 is not complete.

The harness independently constructs the fixed-width EIP-712 ABI words while
using the repository's existing Keccak-256 and secp256k1 implementations; it
does not implement cryptography. It strictly loads the golden JSON, reproduces
the domain, struct, final hashes and signature, and executes every declared negative.
Changing chain, contract, name, version, genesis salt, CCSE digest, any canonical
financial field, or signature must fail expected-signer verification.

`CCSEEIP712BridgeHarnessV1` exposes the bridge library's pure domain, struct,
digest, and signer-verification paths. The Go test consumes the ABI and runtime
bytecode emitted by the pinned compiler and runs those paths directly in
Cypher's in-memory EVM. It requires the positive digest/signer result and exact
custom-error selectors for all 27 negative vectors. Cypher's legacy ABI decoder
does not understand `type=error` entries, so the test first validates their
exact compiled signatures and removes only those entries before ABI-packing the
function calls. The executable set includes zero `r`, zero `s`, zero expected
signer, and an invalid `r` that exercises the zero-address `ecrecover` result;
deleting or adding a case without updating the reviewed required-ID set fails
both harnesses.

The fixture remains `candidate`: compilation and local Cypher-EVM execution do
not constitute independent review or freeze the production fork/opcode/gas
profile. Before deployment, Gate G must additionally pin that runtime profile
and run invariant, fuzz, and differential tests against the state-changing
consumer contract.
