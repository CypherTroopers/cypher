# Native Common endpoints for the browser mesh

## Standard production Common after consolidation

The Web checkout is `/root/cypher/browser-llm-lab`. Its production gateway connects to the standard `common-mine` through the owner-only socket `/root/cypher/config/browser-relay/common-mine.sock`. Native configuration is `/root/cypher/config/browser-relay/common-mine.json`; the public endpoint origin must be `https://ai-test.make-cph-great-again.community`. The gateway pins the actual native identity served by that socket, rather than reusing the old A/B identities.

Use the standard `/root/cypher` build and `/root/cypher/build/bin/cypher-linux-amd64`. The existing `chaindbmine` database and native key remain owned by that Common. Preserve the network from `/root/cypher/genesis.json`; relocation does not require reinitialization, another DB reader, or a copy/merge of chain state. `mesh.publicGatewayOrigin` enables the existing node-signed endpoint API. The Web helper and `cypher-browser-mesh.service` manage only gateway and TURN; starting/stopping the normal Common remains a separate native operation through `start-cyphermine.sh` and its established process manager.

A/B datadirs, identities, old binaries and historical reports remain retained test assets. The maintained `relay/native/a` and `relay/native/b` templates now derive their installed runtime directory and execute the canonical native binary. The `relay/mesh.ecosystem.json` descriptor is for explicit fixtures only; the production startup helper does not read it. B must retain its loopback-only namespace when used as an isolated acceptance endpoint. Do not start those fixtures, reinitialize them, or add them to the production gateway merely by starting Web services.

`relay/mesh-native-inspect.py` and the A/B browser harnesses are retained research-fixture tools, not generic one-Common production health checks. Reuse them only with explicitly prepared A/B sockets/configuration; otherwise inspect the standard Common's documented owner APIs. Two browsers connected to one native Common do not demonstrate a relay between distinct Commons. Record new standard-Common interoperability separately from previous A/B results, including actual native identity/network and browser transport.

## Historical A/B research deployment before consolidation

The following record describes the former dedicated test deployment. Its old absolute paths, observed PIDs, build hashes and four-process startup statements are historical, not current commands or current process identity. The retained runtime data now travel with the relocated checkout; current startup scope is described above and in [managed operations](managed-operations.md).

This deployment implements the native endpoints of `Common A — WSS — Browser A — WebRTC — Browser B — WSS — Common B`. The browser path must be tested independently; these endpoints do not themselves prove WebRTC delivery. The previous signed-header source is an obsolete auxiliary deployment and its historical artifacts remain in the private staging snapshot and its retired runtime. They are not gateway dependencies.

### Running identities

| Endpoint | PM2 name / id | Initial PID | Runtime / owner sockets |
| --- | --- | --- | --- |
| Common A | `cypher-browser-mesh-a` / 11 | 3088210 | `/root/browser-llm-lab/.runtime/mesh-a`, `source.sock`, `node.ipc` |
| Common B | `cypher-browser-mesh-b` / 12 | 3088211 | `/root/browser-llm-lab/.runtime/mesh-b`, `source.sock`, `node.ipc` |

Full `{id,socketPath,enode,nodeId,network}` descriptors are in `mesh-targets.json`. Native identity comes from each fresh datadir's own nodekey. Neither wallet/committee keys nor the old P-256 distribution key are reused. Runtime parents are 0700; native nodekeys and source sockets are 0600. The source JSON enables ONLY mesh; no header exporter or distribution signing key is configured.

A maintains two explicitly configured ordinary native TCP upstreams: the existing research Common at `127.0.0.1:6099` and existing node0 at `127.0.0.1:6000`. The node0 upstream was added only to A at 2026-10-03 04:59:35.936146 UTC during the final browser soak, after an independent miner launcher change made the old upstream unavailable. Both static peers are maintained concurrently; this is not a strict primary/failover priority. No original node process or configuration was changed. B has no bootstrap/static/trusted peer, no discovery and no outbound IP path. Both nodes are locked, non-mining, have empty keystores, no HTTP/WS RPC, and no TxQUIC ingress/bridge/HTTP3 ingress. Owner read-only RPC uses each dedicated Unix IPC socket.

The earlier capacity upgrade on2026-10-03 restarted only these owned endpoints: A PID3208962 and B PID3208999 were observed at that historical upgrade check. These PIDs are superseded by later scoped endpoint-signer deployment records. Both expose80 sessions/native mesh peer ceiling40. PIDs are observations, not startup configuration. Common-wide40 circuits are shared across all sessions, including pending opens; no browser is counted as a native peer. See [capacity-update.md](capacity-update.md).

### Isolation that must survive every B restart

B's PM2 launcher always execs `unshare -Urn -- python3 mesh-exec.py`. The wrapper brings up only `lo`, checks there are no other interfaces or non-loopback routes, records `logs/namespace-bootstrap.json`, and execs Cypher. No veth, default route, NAT, physical interface or host network is attached. Filesystem Unix sockets remain accessible to the host gateway under the same owner's permissions.

`evidence/mesh-isolation-proof.json` independently records B network namespace `net:[4026532462]` vs host `net:[4026531833]`, only loopback, empty IPv4/IPv6 routes, exact binary and permissions. Inodes/PIDs change on restart; re-record them rather than assuming these original values. Never launch B's binary directly on the host to work around a namespace startup problem. Native data learned from mesh must not be copied/imported from A or any existing DB.

### Build and genesis

At the earlier capacity upgrade, both dedicated binary copies had SHA256 `3efc534447a00e0abb0926f04325d78f498e5077d75e31ffd5b4e48c29f9ee29`, matching that capacity-update build and its `build/stage/linux-amd64/manifest.txt`. This is a historical binary identity, superseded by the separately scoped native endpoint-signer deployment; inspect the final `relay/evidence/discovery-update/` binary/process records for that deployment rather than treating this paragraph as current process identity. The earlier `3bafe0...` build and its evidence remain historical. The scoped upgrade, current private80/40 API responses, process identities and renewed B isolation proof are recorded in `evidence/capacity-update/native-upgrade.json`; build provenance is `evidence/capacity-update/native-build-manifest.txt`. Dedicated A/B `Node.P2P.MaxPeers` was increased from8 to40; MaxPendingPeers remains4. This total includes ordinary native peers, and inbound/outbound constraints still apply. The standard native build embeds the bounded storage addition through its staged patch; no external storage checkout or root go.mod change was needed. The native dirty/untracked64-file baseline is in `evidence/mesh-native-baseline.json`; no native source files were edited by that original setup. The later endpoint-signer implementation is a separate authorized native change, documented in [common-endpoint-native-handoff.md](common-endpoint-native-handoff.md).

Fresh independent datadirs were initialized once with copied `/root/cypher/genesis.json`, chainId10101919 and genesis `0x001c8239f25a697933e2a54511a576205fb21cbb80dc974adb29894dc80250ad`. Do not rerun initialization against populated/running data. Do not run `/root/cypher/init.sh`, which resets unrelated research nodes.

### Gateway boundary

Only proxy `/relay/v1/mesh/*` to the selected fixed socket descriptor. Do not proxy `node.ipc`, arbitrary paths/URLs or header-owner APIs. Native allowed Origin is exactly `https://ai-test.make-cph-great-again.community`. A local HTTP browser fixture gateway may authenticate and validate its own fixed fixture Origin, then stamp this approved native Origin on the private upstream request. Never blindly forward or accept an arbitrary caller-supplied native target/origin. Session tokens belong only in the specified bearer header / first WS authentication message; do not print or log them.

### Independent acceptance observations

```sh
PYTHONDONTWRITEBYTECODE=1 python3 relay/mesh-native-inspect.py --output relay/evidence/mesh-snapshot.json
PYTHONDONTWRITEBYTECODE=1 python3 relay/mesh-native-inspect.py --require-transfer --output relay/evidence/mesh-browser-native-result.json
```

The first command records read-only owner RPC, private mesh status, mining/account state, and common canonical block hashes at 0/1/1000/current-common-head. Set `MESH_REFERENCE_IPC=/root/cypher/chaindb0/cypher.ipc` to explicitly use the existing node0 only as a canonical-hash reference. Without an override, an unavailable miner IPC causes fallback to that one known node0 socket; `reference.path`, `selection`, and `fallbackReason` record the choice. An unavailable explicit override fails rather than silently changing references. No reference is added as a peer or data-ingress route. The second additionally requires a non-genesis B head, an authenticated `transport=browser-mesh` B peer and native circuit received bytes. It never starts a browser, WS bridge or direct injection and never opens a chain database. Browser test evidence must independently show the actual WebRTC route and interruption/failover; native circuit bytes alone are not a browser-hop ACK or finality proof.

Before any browser connection, `evidence/mesh-before-browser.json` recorded B at height0 with zero peers, sessions, circuits and candidates. A was syncing normally over native TCP. This is the isolation baseline, not a claim that browser transfer already passed.

### Operations

Launchers and node/source configuration records are in `native/a/` and `native/b/`; `mesh.ecosystem.json` is the live PM2 descriptor. Runtime keys and databases are deliberately excluded. The dedicated mesh apps are supervised by PM2. The scoped `cypher-browser-mesh.service` is now enabled for future boots; see `managed-operations.md` for the single start/stop command and its boundaries. No global `pm2 save` or `resurrect` was performed. The unit was not started during installation and a real host reboot remains NOT_RUN. The old app `cypher-browser-relay-source` id10 was gracefully stopped after both mesh endpoints were ready. After acceptance testing, its verified stopped PM2 entry and obsolete P-256 distribution key were removed at 2026-10-03 05:15:02 UTC. Its databases, configuration, binary, and logs remain archived and were not repurposed for mesh. See `evidence/retired-source-cleanup.json`; the retired source cannot restart without explicit reconfiguration and a new distribution identity.

Before stopping/restarting an endpoint, coordinate with the active browser test, verify current PM2 name/executable/datadir/starttime, and address only that specific app. Never use `pm2 ... all`, a process-name kill or reset/flush unrelated apps. A normal stop cleans owner sockets; do not blindly remove existing socket paths on startup. The eight original native PIDs/starttimes are recorded in `evidence/mesh-process-baseline.json` and verified unchanged by `evidence/mesh-isolation-proof.json`.

### Source availability change during the public soak

Only A’s `StaticNodes` and owner-IPC `admin_addPeer` were changed. A’s native identity and the gateway/browser pins remain the same two Common A/B endpoints. node0 is an ordinary TCP data source and has no browser mesh endpoint. Adding a `StaticNodes` entry does not itself exclude a native identity from mesh; the specification’s `ReservedNodes` exclusion is a separate operator setting. Do not add node0 to the gateway node list or browser pins.

At 05:01:36 UTC, A/B/reference all reached 3789 (A/B were 3777 before the addition), with matching hashes at 0, 1, 1000 and 3789. The same test-owned B/C RTC circuit remained active and B native received bytes increased 1568 to 18288. B retained only loopback and no external routes. Exact operation timestamps, source peer metadata, test-owned route IDs and namespace proof are in `evidence/mesh-upstream-addition.json`. This is an explicitly recorded source-availability change during the soak, not a change to RTC transport or the protected original nodes.
