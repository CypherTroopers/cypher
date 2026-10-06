# Deployment commands — confirmation required, NOT executed live

Worktree: `/root/cypher`, branch `FHS-D`. Existing running targets are `chaindb0`…`chaindb6` and `chaindbmine`; wrappers are `start-cypher0.sh`…`start-cypher6.sh` and `start-cyphermine.sh`. Committee RLPx ports are 6000…6006 and rnet ports are 7102,7104,7106,7108,7110,7112,7114. Common miner ports are 6099 / 7155. Network ID is 10101919.

The fresh-datadir and initialization steps below concern the earlier v3-to-v4 genesis/relay cutover. The TxQUIC automatic-role correction alone does not change the genesis or wire protocol and requires no reinitialization or additional committee configuration files. With `AutoRole = true`, use the existing startup configuration and verified `miner.start` key-loading procedure; a current committee member then opens its TxQUIC receiver.

Do not execute `init.sh`, `reset-chain.sh`, the existing wrappers, or `start-mining.sh` as part of this upgrade without confirming exact processes, data destinations, key handling, public IPs and finalized configs. Existing wrappers reference the old binary and committee-star `static-nodes.toml`. No existing process or data directory was changed.

## Candidate and genesis

Verified binary: `/tmp/cypher-common-relay-build-20261003-n99n0l/cypher`

SHA256: `a22a557e3afe3667c897b830840e8407c6058cec12594602aacdf919286cece5`. This is a temporary review artifact, not an installed production binary. Build a uniquely named permanent artifact before deployment, without replacing live binaries:

```sh
cd /root/cypher
go build -mod=readonly -o /root/cypher/build/bin/cypher-fhsd-relay-v4 ./cmd/cypher
sha256sum /root/cypher/build/bin/cypher-fhsd-relay-v4
```

Genesis source is `/root/cypher/genesis.json` (not `gensis.json`). Only its mixHash changed to match the corrected seal genesis domain. All nodes must initialize from this same reviewed file.

## Suggested non-destructive cutover, pending approval

Proposed **new** datadirs: `/root/cypher/relay-v4-data/chaindb0`…`chaindb6`, `/root/cypher/relay-v4-data/chaindbmine`. Proposed operator configs: `/root/cypher/relay-v4-config/committee-0.toml`…`committee-6.toml`, `common-mine.toml`, plus individually named gateways. These paths have NOT been created or approved. Replace every example enode; retain nodekeys if the operator wants the same pinned identities. Copy wallet/keystore material only after a reviewed consistent backup. Do not copy chain/outbox databases or expose private keys.

After confirming process names and completing backup, an operator may stop only these approved PM2 apps (verify their mappings first):

```sh
pm2 stop cypher0 cypher1 cypher2 cypher3 cypher4 cypher5 cypher6 cyphermine
```

Confirm no child node still writes the old targets. Leave all old directories intact for rollback. No `rm`, `pm2 stop all`, global flush, or global reset is needed. For each **approved empty new** datadir, initialize with:

```sh
/root/cypher/build/bin/cypher-fhsd-relay-v4 \
  --datadir /root/cypher/relay-v4-data/chaindb0 \
  init /root/cypher/genesis.json
```

Repeat only for the explicitly approved targets. The exact corresponding foreground start template for committee 0 is:

```sh
/root/cypher/build/bin/cypher-fhsd-relay-v4 \
  --config /root/cypher/relay-v4-config/committee-0.toml \
  --datadir /root/cypher/relay-v4-data/chaindb0 \
  --networkid 10101919 --syncmode full --port 6000 --rnetport 7102 \
  --nat extip:APPROVED_PUBLIC_IP --gcmode archive console
```

For committee i use the matching config/datadir, port `6000+i`, rnet `7102+2*i`. For the common miner use `common-mine.toml`, `chaindbmine`, port 6099 and rnet 7155. A common config using the relay overlay must enable Relay but not Gateway. Selected gateway operators explicitly enable Gateway and arrange at least two gateway-reaching paths within TTL. Committee configs pin the other core enodes and keep `TxQUIC.AutoRole = true`; `miner.start` supplies the verified BLS identity and determines membership from the current canonical committee. Omit the deprecated `CommitteePublicKey` hint. Keep RPC bound locally unless separately reviewed; do not copy the old wildcard RPC/unlock settings.

Starting consensus/mining requires the existing approved account/BLS setup and private IPC procedure; do not copy passwords from old scripts into new commands or logs. Confirm that procedure and all target process identities before launch. Then check genesis agreement, block/keyblock sync, pinned reconnect, transaction committee receipts, PoW admission and reward identity, failover and resource metrics.

## Isolated proof actually executed

The candidate successfully initialized **only** `/tmp/cypher-relay-genesis-proof-BkOwEY` from the updated genesis, with exit code 0. Log: `/tmp/cypher-genesis-proof.log`. It never started networking. All live `chaindb*` data and processes were left alone.
