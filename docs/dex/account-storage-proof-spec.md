# G2 bounded account and storage proof helper

Status: implemented after both G1 gates passed; focused race gate PASS.
This helper is for authenticated RPC relay observations. It adds no transaction
opcode, new wire codec, account mutation, or finality rule.

API in `dex/clxevidence`:

```go
type StorageProof struct {
    Key   protocol.Hash
    Proof [][]byte
}
type AccountEvidence struct {
    Exists      bool
    Nonce       uint64
    Balance     *big.Int
    StorageRoot protocol.Hash
    CodeHash    protocol.Hash
    Values      []protocol.Hash
}
func VerifyAccountStorage(
    trustedRoot protocol.Hash,
    address [20]byte,
    accountProof [][]byte,
    slots []StorageProof,
) (AccountEvidence, error)
```

The caller must derive `trustedRoot` from an authenticated CLX anchor. The
function proves membership or nonmembership relative to that root; a
request-supplied root cannot establish CLX finality. It returns no `VerifiedRange`
or credit capability.

All collection and byte bounds are checked before MPT traversal: at most 32
distinct slot keys, at most 65 nodes per path, at most 1024 bytes per node, and
at most 4 MiB in all paths. Duplicate slot keys and duplicate nodes within any
path are rejected. A zero root is invalid. The zero address and zero slot key
remain valid EVM keys.

The existing secure-trie proof verifier hashes the address or slot key once.
It bounds traversal and verifies every requested slot against the storage root
from the authenticated account RLP. The account must decode canonically with
`uint64` nonce, nonnegative balance of at most 256 bits, nonzero storage root,
and a 32-byte code hash. Balance uses a newly allocated `big.Int`; the DEX
financial amount's uint128 restriction does not apply to this general account
observation. Returned slot values preserve input order and contain canonical
256-bit storage words.

Proven account nonmembership returns `Exists=false`, nonce/balance zero, an
empty storage root, empty-code hash, and zero requested values. Empty paths
are only sufficient for the corresponding known empty trie. Slot absence in
a nonempty storage trie requires an authenticated nonmembership proof.
Absence and malformed/unavailable proof data are distinct: a missing required
path must fail rather than become a zero value. On any failure, the returned
`AccountEvidence` is zero and carries no partially verified values.

Executed tests use real in-memory StateDB roots and standard EIP-1186 proof
generation: present account/nonce/u256 balance; present and absent slots;
account nonmembership and empty state; root/address/key/value/path corruption;
missing and duplicate nodes; duplicated slot keys; byte/count bounds; and
input/output ownership. No independent new encoding golden is required because
the helper introduces no encoding and reuses the existing canonical MPT/RLP
format. Actual RPC and relayer completion tests remain separate gates.

Recorded execution: [JSONL](results/continuous-g2-account-proof-unit.jsonl),
[metadata](results/continuous-g2-account-proof-unit-metadata.json). Five top-level
tests, 33 PASS events, zero FAIL/SKIP, race enabled, 1.092 seconds package elapsed.
The fresh namespace had only loopback, and Go source hashes were unchanged
between the recorded pre/post manifests.
