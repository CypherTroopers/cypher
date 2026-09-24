# G2 authenticated HTTP source client

This development-only source client observes an ordinary Common's read-only
HTTP RPC. The RPC server is untrusted; block discovery never becomes finality.
It neither submits transactions nor opens a StateDB. Its immutable CLX config
must originate from the local trusted genesis and seven-member source registry.
The G3 extension authenticates deterministic reordering of those same identities
through certified CLX key carriers; it does not trust a current RPC committee.

`dex/relay/source.Open(Config{Endpoint, Dir, CLX})` returns a serialized client.
`Dir` is a new private source subdirectory below the relay's owned directory, or
a directory already marked by this client. The parent directory must exist.
Concurrent opens, unmarked existing directories, symlink files/directories,
and unsupported durable-lock platforms are rejected. The client exposes:

- `Current() Anchor` and `Segments() []Segment`, which return owned values;
  each `Segment` contains `Base`, `Target`, and `Evidence`.
- `Advance(ctx) (Segment,error)`: discover the current height, then request up
  to 32 explicit positive-height `eth_getCLXFinalityWitness` objects. Stop at
  unavailable finality, and authenticate every collected header from the current
  stored anchor. Request custody count/account paths with `eth_getProof` at the
  exact target block hash. `VerifyRolling` determines the target anchor. Shorten
  the segment if necessary to fit the existing 64 KiB native call limit, with
  conservative envelope overhead reserved. No progress returns unavailable.
- `BuildRange(ctx, trustedBase, targetHeight, start, entries)` obtains bounded
  witness/proof data and returns `RollingEvidence` plus its verified target.
  The base must come from authenticated DEX parent state or authenticated CLX
  settlement slots. The RPC cannot provide a replacement base.
- `AnchorAt(ctx,height,hash)` reconstructs an anchor from the nearest retained
  authenticated segment base at or below that height. The explicit target hash
  must match. Historical account/count MPT paths are still required; a header
  alone is not a complete anchor.
- `Entries(ctx,anchor,start,count)` fetches 1–128 canonical native inbox
  entries from `eth_getDEXInboxEntries(blockHash,start,count)`. It checks fixed
  codecs, source identity and contiguous indices. The result is transport data;
  `BuildRange` must verify its storage commitments before credit.
- `Account(ctx,anchor,address,keys)` uses `VerifyAccountStorage` for at most 32
  distinct slots and returns the verified account plus a canonical forensic
  proof bundle. Claimed nonce/balance/value/storageHash fields in the RPC
  response confer no authority. Storage proof paths are matched by the caller's
  request order and verified against those requested keys, not trusted labels.

Only numeric loopback HTTP endpoints with an explicit port are accepted.
Credentials, redirects, proxies, query strings and fragments are disallowed.
Every call has a three-second timeout and an eight-MiB response cap. HTTP/RPC
failure or missing/pruned data is explicit unavailable; malformed codecs,
invalid proofs and foreign identity fail authentication. Discovery is capped
before fetching, including when a malicious server advertises a huge height.

Persistence is `source-wal.json`: a JSON envelope containing `payload` and a
hex checksum. The payload has ordered fields `version:1`, `bootstrap` (lowercase
hex 32-byte anchor ID, no prefix), and `segments` (base64 strings of canonical
RLPv2, legacy RLPv3 or RLPv4 rolling evidence). The checksum is
`SHA256("common-dex/relay-source-wal/v1" || 0x00 || compactPayloadJSON)`.
At most 1024 segments and 32 MiB are retained. On every open the full chain is
decoded and reverified from the exact immutable bootstrap, with no cached anchor
trusted from disk. Saving uses an owned temporary file, file fsync, atomic rename,
then directory fsync. Any persistence error poisons the open client; it cannot
publish the uncommitted advancement or continue writes. Restart must revalidate
the on-disk state. Files are mode 0600 and the directory is 0700.

An interrupted save uses the single exclusive name `source-wal.pending.tmp`
under the acquired source lock. Reopen first authenticates the canonical WAL;
only after that succeeds may it remove an orphan. For upgrade from the initial
random-name implementation it also recognizes `source-wal-*.tmp`. Cleanup reads
at most 128 directory entries and accepts at most 32 candidate files, each a
regular, single-link, current-user-owned mode-0600 file no larger than the WAL
bound. All candidates are checked before deletion; symlinks, foreign ownership,
oversized files and invalid canonical WAL fail closed. Unrelated files are not
removed. Cleanup ends with directory fsync. Temporary bytes never establish an
anchor, even if they appear to contain a later valid state.

The forensic account bundle is canonical RLP:
`[1, stateRoot32, address20, accountProofNodes, [[slotKey32, proofNodes], ...]]`.
It records proof bytes without asserting finality. Its version/shape are covered
by an independent Python codec-only golden before implementation. The empty-WAL
golden also fixes checksum and JSON bytes. Neither codec-only vector contains
authenticated chain evidence.

Executed isolated tests exercise actual loopback HTTP, invalid response labels,
bad signatures/MPT proofs, partial finality, deadlines/response bounds,
restart/reverification, foreign bootstrap, corruption, exclusive lock and
durability failure. This source client does not prove receipt of a transaction
or native payout; the relay's semantic completion checks remain a separate layer.

The final focused gate is recorded in
[JSONL](results/continuous-g2-source-unit.jsonl) and
[metadata](results/continuous-g2-source-unit-metadata.json): eight top-level tests,
25 PASS events, zero FAIL/SKIP. Race was enabled; package timings are recorded in
the JSONL (`clxevidence`, the external shared-fixture HTTP tests, and `relay/source`).
The pre/post Go manifests have no differences. The first passing run is retained
under `continuous-g2-source-initial-*`; the rerun added a real 32-header segment,
two-segment cold restore, and forged finality rejection even after the attacker
recomputed the WAL checksum. The latest run additionally verifies 20 injected
partial-write/reopen cycles without file accumulation, safe legacy-orphan
cleanup, refusal of unsafe candidates before any deletion, preservation of an
invalid canonical WAL and a two-segment authenticated height40 restore beside
a partial candidate. The preceding source gate is retained under
`continuous-g2-source-before-orphan-*`. These interrupted writes were injected
file states, not physical power cuts. Initial namespace approval timed out before
execution; the identical permitted retry executed successfully.

These source unit tests use actual HTTP sockets serving unit-generated signed
CLX evidence and real MPT proofs. The separate normal Common process-network
integration is recorded in [normal-eth-source-spec.md](normal-eth-source-spec.md).
The tests run only with `CYPHER_DEX_SOURCE_DEVNET=1` in a loopback-only namespace;
ordinary package runs label them SKIP. Full Common ETH sync, relay semantic
completion and physical storage power loss require separate records.


## G3 authenticated key renewals

See [key-renewal specification](fixed-key-renewal-spec.md). Before the first
carrier the source obtains the genesis key-header preimage using the already
public `eth_getKeyBlockByHash` with an exact hash. It rebuilds the header and
checks its hash and ordered committee commitment; the response's `hash` label
has no authority. Later current and historical key contexts are derived by
`VerifyHeaderContext` from an already verified retained segment and its prefix
of at most32 headers. A base absent from that retained chain is unavailable.
Neither source nor settlement accepts an arbitrary latest committee.

The old RLPv3 context remains v3 when restoring a pending old-key boundary.
Adding an Order without its authenticated previous header/order would be an
invalid partial upgrade and is not performed. New source ranges use RLPv4.
Only current and pending previous key contexts travel in a range; renewal
history is not appended to future proof payloads. Cold WAL open still replays
all stored independent bounded segments from genesis.

The isolated HTTP renewal fixture reaches height260 through three certified
same-member permutations, cold-reopens at pending carriers3 and255, reconstructs
the historical boundary130→131, and verifies same-anchor later credit. This is
unit-generated signed CLX evidence delivered over real HTTP, not the separate
actual CLX/DEX/relay long-running process gate. No PoW candidate is generated.
