# Canonical genesis integration proof

Executed 2026-10-03 at 19:12:56 UTC: **PASS**. This is an offline native derivation, not a live-node or consensus interoperability test.

`main.go` imports the current `/root/cypher` native implementation; it does not implement a parallel header codec/hash. It reads the authoritative `genesis.json`, validates its Fair HotStuff commitment, derives `Genesis.ToBlock(nil)`, initializes key genesis and transaction genesis in `rawdb.NewMemoryDatabase`, reopens the in-memory stored config, and compares the resulting network to the standard Common relay configuration. No existing DB, owner IPC, socket or live native process is accessed. No keys are generated or read. Native source/genesis/go.mod/go.sum inputs remained unchanged (`source-stability.json`).

| Value | Measured result |
| --- | --- |
| chainId | 10101919 |
| transaction genesis block hash, both native paths | `0x001c8239f25a697933e2a54511a576205fb21cbb80dc974adb29894dc80250ad` |
| key genesis block hash | `0xfd4eea7524a89a440d09282888220a0731c3cb152be4b4a535031b7bbef86285` |
| genesis state root | `0x4ff47f7df865cb444bec5079d060aa505bfe528f15d65424082e1727edd4a103` |
| FHS configuration commitment | `0xe4626eb7946b1d869ffd3fcd3136652fcae7ea1f912f8b7101a2e98a266050df` |
| JSON file SHA-256, a separate byte fingerprint | `cbba1850877ca5d2a4b2f2c9ef759c357ef579918130196ce773c29ee0c06b6c` |
| committee mode / members | fixedCommittee=true, fixedLeader=false, fairHotstuff=true / 7 |
| standard Common config network equality | PASS |

## Reproduction

The exact cwd/arguments/environment and successful exit are in `command.json`. Go 1.27.1, one compiler process, nice15, local cached dependencies and disabled downloads were used. `proof.mod` / `proof.sum` are temporary copies of the original module graph with one existing bounded-storage fork replacement; the repository module files were not edited. The existing reviewed fork was `/tmp/cypher-mesh-regression-mftgn6ta/leveldb-bounded` with checksum-pinned upstream `github.com/syndtr/goleveldb@v1.0.1-0.20220721030215-126854af5e6d` plus `build/goleveldb-bounded.patch` (SHA-256 in source-provenance.json). Reusing this temporary dependency path is sufficient on this host. For later reproduction after temporary cleanup, recreate that fork using the existing `build/build-cypher.sh:153-195` procedure and point a fresh temporary modfile to it; do not distribute or depend on the original `/tmp` path as a runtime input. Existing native BLS libraries were used through the repository package's normal CGO linker flags; this was not a second release binary build.

```sh
cd /root/cypher
env GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off \
  GOMAXPROCS=1 GOCACHE=/tmp/cypher-browser-relay-gocache \
  GOTMPDIR=/tmp/cypher-consolidation-genesis-proof/go-tmp \
  nice -n 15 go run -p=1 -mod=readonly \
  -modfile=/tmp/cypher-consolidation-genesis-proof/proof.mod \
  -tags=cypher_bounded_storage \
  /tmp/cypher-consolidation-genesis-proof/main.go \
  /root/cypher/genesis.json \
  /root/cypher/config/browser-relay/common-mine.json \
  /tmp/cypher-consolidation-genesis-proof/result.json
```

Retain `main.go`, `result.json`, `command.json`, `run.log`, `source-provenance.json`, and `source-stability.json` as the compact evidence. `proof.mod` / `proof.sum` document the exact run graph but contain a temporary fork path and should not become application configuration. The empty `go-tmp` has no retained build output.

## Source trace: genesis to browser

All native paths are relative to `/root/cypher`; Web paths below are relative to the Web repository wherever the authorized full relocation places it.

1. `genesis.json:3,39-44` defines chainId/FHS/committee mode. Standard launchers read this same file only for previously uninitialized datadirs; all pass `--networkid 10101919`. P2P network ID and chainId are separate concepts even though their configured values match.
2. `cmd/cypher/chaincmd.go:226-275` parses both `core.GenesisKey` and `core.Genesis`, then initializes them. `core/genesis.go:314-391` derives state/header; `core/types/block.go:551-563,623-629,1292-1298` implements canonical header RLP+Keccak, omitting SignInfo. `core/genesis.go:412-418` validates FHS commitment. The proof executed these existing paths in RAM.
3. `cmd/cypher/browser_public_relay.go:87-124` binds the adapter to the existing backend/lifecycle and enforces Common role. `cmd/cypher/browser_mesh.go:91-108` checks actual backend chainId and block-0 hash against relay config, then uses the native node key signer. This prevents merely relabeling a different live backend as the configured research network.
4. `p2p/browser_mesh.go:180` uses native SetupConn. `p2p/server.go:990-1011,1041-1050` requires authenticated RLPx and verifies the native peer key. `eth/handler.go:349-359` sends local blockchain status; `eth/peer.go:741-751` rejects mismatching network ID, protocol version, genesis and incompatible fork ID. Browser transport does not bypass native chain authentication.
5. `node/browserrelay/mesh_protocol.go:217-228,301-319` puts network, native enode, sourceId, gateway origin, boot generation, sequence and TTL into the exact signed endpoint bytes; the domain is `cypher-browser-mesh-endpoint-v1` plus NUL, signed over Keccak by the native key. `cmd/cypher/browser_mesh.go:313-331` serves only the existing envelope; missing configured public origin returns404.
6. Web `relay/discovery.mjs:108-117` polls the owner-local endpoint, verifies native signature/network and configured local nodeId/sourceId/origin, and retains the envelope. `relay/gateway.mjs:356-357` checks the native HELLO public identity and network before forwarding. HTTPS provides the initial page/config network policy; a signed arbitrary identity does not independently define the user's intended chain.
7. Web `public/mesh-discovery.js:28-44,62-68,98-105` performs secp256k1 verification, exact network equality, schema and TTL checks for endpoint and mesh advertisement. `public/mesh-protocol.js:42-47` accepts independently verified transit Commons without a central key allowlist. `public/mesh-worker.js:129-145` binds each native HELLO to its local assignment or previously verified remote endpoint and checks boot generation. The browser verifies discovery identity/network claims; it does not re-execute consensus or independently establish finality for the encrypted native stream.

## Scope limits

PASS establishes current JSON-to-native-genesis reproducibility and equality with the standard relay pin, plus the inspected source binding chain. It does not establish that every currently running node uses that JSON/binary, that the standard Common's public endpoint is already published, or that a post-relocation browser has relayed data. Those require the separately owned deployment/owner-local/browser acceptance checks. No protocol or consensus code was changed for this verification.
