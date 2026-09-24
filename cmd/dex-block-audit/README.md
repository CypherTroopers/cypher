# Local CLX block issuance audit

This standalone tool reads block RLP observations on stdin and emits one JSON
accounting record per input line. It has no node connection, StateDB writer or
DEX engine. It is not linked into the normal `cypher` executable.

Each input line must contain exactly these fields (no duplicate or unknown keys):

```json
{"rlp":"<debug_getBlockRlp hex, optional 0x>","expected_hash":"0x<64 hex digits>","expected_number":3515}
```

Build to a dedicated tools directory, then use saved observations:

```sh
go build -mod=readonly -trimpath -o /tmp/dex-block-audit ./cmd/dex-block-audit
/tmp/dex-block-audit < blocks.ndjson > issuance.ndjson
```

A nonzero exit means the run is incomplete; do not treat an already emitted
prefix as a complete interval. The tool does not deduplicate or prove interval
continuity. The caller must select an exact canonical interval, check all
expected block hashes/heights, and sum each block once. Repeated input lines
produce repeated observations, not additional actual issuance.

The output extracts the actual RLP `Header.Coinbase`, not the `miner` projection
of `eth_getBlockByNumber`. The latter can be replaced with
`keyblock.OutAddress(1)` by `internal/ethapi/api.go`. Integer amounts are decimal
strings in native CLX atoms. The independently implemented formulas follow
`consensus/colossusX/consensus.go` (`accumulateRewards` and
`ApplyKeyblockPowRewardByKeyInfo`):

- Base reward is `100000 * 10^18` atoms. Nonempty FastTx/SlowTx and Key carriers
  receive it; empty FastTx/SlowTx receive no static or uncle reward.
- Each uncle receives `(uncleNumber + 8 - blockNumber) * base / 8`; the actual
  block coinbase additionally receives `base / 32` for each uncle.
- Key carriers with a nonempty `KeyInfo.OutAddress(0)` (after removing one
  leading `*`) receive another `100000 * 10^18` at that address. An empty
  outAddress does not use the leader fallback of `OutAddress(1)`.
- Genesis allocation is excluded. Transfers, gas, Common RPC fees, burn and DEX
  accounting are excluded and must be reconciled separately.

The tool checks expected header hash/height, canonical RLP decoding, current
seven-field block encoding, TX and uncle body commitments, and KeyInfo/KeyHash
carrier-parent consistency (`Header.KeyHash == carriedKey.ParentHash`, not the
carried key hash). These are observation consistency checks. **It does not authenticate
FHS finality, signatures, committee history, complete execution or state roots.**
`SignInfo` is excluded from the header hash; changing it may preserve the hash.
Key block header hash alone does not authenticate all KeyInfo body fields; the
outer carrier header hash does bind its embedded KeyInfo bytes.
Treat input as a local canonical observation, never as an independent proof.

Local audit limits are 4 MiB decoded block RLP, 256 KiB KeyInfo, 65,536 TXs,
64 uncles, 4,096 input lines, 128 MiB total input, and `2*4 MiB+1024` bytes per
line. These limits are not consensus rules. Unsupported block kinds, non-uint64
heights and uncle heights outside the positive reward range (1–7 behind) fail
closed. They are not silently coerced or treated as zero issuance.

Validation:

```sh
go test -mod=readonly ./cmd/dex-block-audit
go test -mod=readonly -race ./cmd/dex-block-audit
```

The tests use independent decimal issuance expectations, distinct block and
KeyInfo recipients, no leader fallback, recipient aggregation, uint64 and RLP
bounds, same-header TX body mutation, and NDJSON failure handling. They are
component tests; they do not establish live network finality or financial DEX
correctness.
