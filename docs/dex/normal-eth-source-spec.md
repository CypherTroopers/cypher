# G2 ordinary ETH source connection

The new version3 isolated fixture exposes the actual CLX process blockchain
through the existing ETH ProtocolManager and an owned loopback RLPx server.
The committee's normal `NewMinedBlockEvent` drives ETH block propagation. The
coordinator does not insert blocks, repair canonical state, call the downloader
manually, or replace finality records.

The ETH production refactor exports `ProtocolManager.Protocols()` as the
existing version-to-protocol construction loop. `Ethereum.Protocols()` keeps its
ENR attributes and dial candidates. There is no new consensus, sync, mining or
transaction admission rule.

Only the new config3 native process fixture starts these additional peer servers.
Config2 financial fixtures and legacy recovery/reward fixtures retain their
existing transport lifecycle. Each new server uses a separate persistent test
node key and listener address under its own newly created CLX test datadir.
Discovery is disabled. Endpoints are communicated through test-only child status
and `FHSNativeNetwork.ETHPeers()` / `P2PURLs()`.

The fixture RPC backend gains read-only wrappers for ordinary block height/block
lookup, bounded `eth_getCLXFinalityWitness`, and `eth_getDEXInboxEntries`; proofs
still use ordinary `eth_getProof`. No RPC exposes StateDB mutation or local
signature manufacture. Consumers authenticate all returned evidence.
The normal public HTTP read-method whitelist now explicitly permits these two
new read APIs; all source proofs remain subject to their devnet activation and
authentication checks. The normal-handler whitelist has a separate regression.

The focused gate starts seven actual CLX QUIC child processes and one normal
Common with RPC admission enabled and DEX disabled as the HTTP source. It uses
ordinary EIP-155 transactions through HTTP+TxQUIC, connects
the source through ETH, checks automatic progress beyond height5, restarts the
source on its own datadir, then checks later progress and source-client proofs.
The source must not activate PoW, DEX workers, or the financial execution engine.
Only new isolated datadirs and owned processes are involved. This is a transport
prerequisite; the full continuous financial relay scenario remains separate.

Executed result: [raw log](results/continuous-g2-ordinary-eth-unit.log) and
[metadata](results/continuous-g2-ordinary-eth-unit-metadata.json), PASS 34.499s.
Six deposits advanced the ordinary source to heights 1, 3, 5, 7, 9 and, after
same-datadir restart, 11. The proof client authenticated six inbox entries and
the custody balance of 6 native CLX from the normal HTTP API. PoW/FHS-service
activation stayed false on the Common, DEX engine counters did not increase,
and there was no coordinator `InsertChain`, canonical-state repair, or manual
downloader invocation. This fixture uses seven child processes plus the source
Common in the test coordinator; it is not the later full financial role matrix.
The pre/post Go manifests differ only in the concurrent standalone
`node/dex_rpc_public_test.go` edit, outside the selected test's compiled package
tests. Normal PoW nonce search and physical power loss were not run.

Earlier failures are preserved as `continuous-g2-ordinary-eth-attempt1-*`
through `attempt4-*`: a test-only integer type compile error; two Common services
in one coordinator overwriting existing package-global RPC signer context; then
an unavailable source proof whose detailed rerun identified the missing public
read whitelist. The source chain contained real signature/finality evidence;
no weaker finality or cached-head fallback was introduced. One ordinary Common
now performs RPC admission and proof serving, with its original operator key
reopened on restart. No fixture secret is printed.
