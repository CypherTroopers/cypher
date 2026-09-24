# New-Generation Candidate for the Designated Network (Not Initialized/Deployed)

2026-09-23. The generator [cmd/dex-live-candidate](../../cmd/dex-live-candidate/main.go) read existing `genesis.json` and saved a candidate in a new private directory. It did not connect to existing DBs, PM2, RPC, or networks, or send ordinary CLX TXs/votes. Mid-run initialization was unapproved at this point; the candidate remained **BLOCKED**.

Output: `build/stage/live-generation-candidate` (0700). Private keys exist only in 0600 files under `keys`. Do not include this whole directory or key-hash inventories in public archives/Git. Public material consists only of `public/inventory.json`, genesis, and public fields of manifests/relay configs, without key contents. Inventory paths are not secrets.

## Candidate Bindings

|Item|Candidate value|
|---|---|
|CLX chain ID|10101920 (changed from 10101919)|
|CLX genesis hash|`0x986078d0f7c08949cf2070d3a863fb3b2c7db73fd2108b1af87ce4d20be1aa16`|
|Genesis state root|`0xd3e0fd99e2cbcafe3ca718d616b73ea47664153c0ffc01888c3cedef893a33f0`|
|Key genesis hash|`0x772ee32fea8a3d971ed1185955ce794cec8d64e05dea736c7f7499738fa01347`|
|DEX ID|`0x12ca5d25e81fb6eeaefb371f049e922f1c7bb763d55a7c910174b27b8e095086`|
|DEX committee commitment|`0x931f1d9e780d96bc311fba709a34a99011c60a5b8378caebf1f6dfa344018ae6`|
|Genesis JSON SHA-256|`fbb36fe9a2a9e460ad6af1febfc0b48cecd43215e3e1a987129f0afac6850a08`|
|Configuration|DEX genesis config 4, manifest 2, relay manifest 2, fixed DEX epoch 1|
|Storage candidate|Separate hot 128 from absolute MaxHeight 4096; DEX archive budget 256 MiB|
|Startup conditions|StorageGenerations=true, duty at every height, no legacy ReceiptHeights fixture|

Existing 12 alloc entries and 7 CLX committee identities were unchanged; the generator neither read nor changed original CLX/Common wallet/node keys. Independent BLS vote keys, Ed25519 TLS keys, and secp256k1 native reward keys were generated for 7 DEX members, corresponding to existing `cyphermine` and additional `cypherdex1`–`cypherdex6`. Heavy DEX startup was not configured for committee nodes `cypher0`–`cypher6`.

DEX TLS uses loopback `18000`–`18006`; order APIs use `19000`–`19006`. Candidate datadirs for new Common nodes are `build/stage/live-commons/chaindbdex1`–`chaindbdex6`, P2P `6201`–`6206`, rnet `7202,7204,...,7212`. Existing Common wallets are not replaced with new keys. Additional Common wallet keys are also separate from DEX vote/reward keys and independently recorded in inventory. The generator does not reserve ports or start processes.

There are 2 independent relays, each with 3 dedicated gas-payer keys for anchor/checkpoint/claim lanes. Recipient keys and CLX committee keys are not reused as relay signers. Source/submit use existing Common at `http://127.0.0.1:8999`; DEX endpoints are bound to the candidates above.

The product is the existing BTC/CLX fixture; Oracle is explicitly a synthetic feed. Dedicated keys were prepared for 2 traders, Oracle, insurance owner, and support owner, but new-account genesis allocations added were **0**. Initial funding was planned through ordinary transfers from the existing owned committee 0 account after approved new-generation startup; `Funding` in inventory records the budget in minimum units (254 CLX total). These transfers had not occurred. Native custody/support/insurance start empty; DEX credit is not created without the inbox.

## Go Validation

Following ordinary CLI initialization order, candidate JSON was decoded into `core.GenesisKey` and `core.Genesis`, and `SetupGenesisKeyBlock`→`SetupGenesisBlock` ran **only in a memory DB**. Separately, `Genesis.ToBlock` hash/root agreement was checked. The key-genesis hash does not use a fixture's self-reported value.

From the formally derived genesis header/config/key hash, validation passed through `clxevidence.New` and `BootstrapAnchor`, checking JSON roundtrips for all 7 `service.LoadManifest` inputs, `finance.ValidateRegistration`, `checkpoint.NewEpoch`, `transport.RegistryCommitment`, vote public keys, and TLS pin/key pairs. This validates source-genesis bootstrap; it does not treat nonexistent financial blocks as finalized.

`TestDEXLiveCandidateRelayCLIValidation` is an opt-in test requiring an explicit private candidate path. It passed 2 configurations through ordinary `cmd/cypher` relay parsing, configuration validation, and local key loading. Without starting relays or sending network traffic, it was **PASS(UNIT)**. Record: `/tmp/common-dex-live.8gezz_j9/public/q2-candidate-relay-cli.log`. Inventory's CLI gate preserves NOT_RUN at generation time; this separate test log records subsequent verification.

Generator unit tests checked unchanged source genesis, no added allocations, unique identities, secret permissions, rejection of overwriting existing output, symlink ancestors, input from chains other than the old chain, and changes to genesis/domain/committee/TLS/vote/epoch. The first test incorrectly detected drift by comparing cached in-memory objects such as Header with JSON-decoded objects using `reflect.DeepEqual`, producing 2 FAIL results. Replacing that comparison with canonical JSON roundtrips and all authentication validators made the rerun PASS. Financial values and authentication conditions were not relaxed.

## Unexecuted Work and Conditions for Use

Final full storage-generation changes, unit/race/LIVE verification, 60-minute financial operation in one generation, and 2 transitions with actual settings are not included in candidate-generation PASS. Required gates were completion of the candidate schema, comparison with final source/build hashes, an exact initialization plan for all 14 target Common/committee nodes and relays, backup of all existing data, and separate mid-run-initialization approval. Copying the candidate alone must not enable live DEX.

Regeneration rejects existing output. Do not silently regenerate wallet keys already used to prepare additional Common nodes. Candidate revisions preserve the current identity inventory and record reasons and old/new public commitments. Distinguish replay of old-chain protected TXs from the separate acceptance decision for legacy unprotected TXs. Current CLX retains Homestead signature recovery for unprotected TXs, so a new chain ID alone does not categorically reject those old signatures. See [initialization replay limits](live-init-plan.md#replay-and-recovery-limits). The new financial runner enforces the new EIP-155 chain ID and does not import old raw TXs/nonces/queues into the new generation.
