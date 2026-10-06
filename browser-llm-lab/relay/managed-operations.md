# Scoped Web gateway and TURN operations

The maintained `cypher-browser-mesh.service` starts only two Web components. The standard Common `common-mine` is managed separately from `/root/cypher`. Historical dedicated A/B nodes are not part of this startup or stop operation.

| App | PM2_HOME | Start descriptor |
| --- | --- | --- |
| `cypher-header-turn` | `/root/cypher/browser-llm-lab/.runtime/relay-turn/pm2` | `relay/turn.ecosystem.json` |
| `cypher-browser-mesh-gateway` | `/root/cypher/browser-llm-lab/.runtime/mesh-gateway/pm2` | `relay/gateway.ecosystem.json` |

```sh
cd /root/cypher/browser-llm-lab
./relay/start-managed.sh status
./relay/start-managed.sh check
./relay/start-managed.sh start
# Coordinate with active browsers before stopping gateway and TURN:
./relay/start-managed.sh stop
```

`status` never starts a missing PM2 daemon. `check` validates the two current descriptors and gateway configuration; it does not require A/B fixture launchers. `start` starts absent apps with `--only <exact-name>`, resumes only verified stopped/errored app IDs, and leaves online apps unchanged. Executable, cwd, interpreter and arguments must match, and duplicate names or transitioning processes are refused. `stop` validates both identities before stopping only their numeric IDs in reverse dependency order. A nonblocking lock prevents concurrent operations. No native Common, unrelated PM2 application, database or identity is started, stopped, reset or deleted by this helper.

The gateway source is `/root/cypher/config/browser-relay/common-mine.sock`, owned by the separately running standard Common. Its native config is `/root/cypher/config/browser-relay/common-mine.json`, with network matching `/root/cypher/genesis.json` and public gateway origin matching this site. Native build/start/stop remains in `/root/cypher`, preserving `chaindbmine` and its existing identity. The gateway may start before its source; a missing source prevents browser admission and does not authorize native startup.

After reviewing the installed unit and completing runtime relocation, the unit can be maintained with:

```sh
install -o root -g root -m 0644 relay/cypher-browser-mesh.service /etc/systemd/system/cypher-browser-mesh.service
systemctl daemon-reload
systemctl enable cypher-browser-mesh.service
```

Those commands install boot configuration; they do not establish a successful real reboot test. The unit is ordered after network readiness and optional `pm2-root.service`. `KillMode=process` and exact selected IDs prevent stopping an entire shared PM2 cgroup. There is no global `pm2 save`, `resurrect`, `startup`, `stop all` or daemon shutdown. Disable future startup with `systemctl disable cypher-browser-mesh.service`; omit `--now` when only changing future startup policy.

Descriptors contain private file paths and public identities, not private keys or session tokens. Keep `.runtime/` excluded from version control and preserve all stored data. Do not print complete PM2 environment JSON or secret values. The old `relay/mesh.ecosystem.json` and `relay/native/{a,b}` templates remain available only for explicit research fixture operations; they are not read by the production helper.

Verification: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_managed_ops.py -v` checks exact two-app scope, idempotence, duplicate/executable/cwd collision rejection, untouched native processes and preflight without A/B resources. `systemd-analyze verify relay/cypher-browser-mesh.service` checks unit syntax. Actual relocated startup, source connection and reboot status require separate runtime evidence.

## Historical startup evidence

Before consolidation the helper managed four processes, including research A/B. `evidence/mesh-boot-readiness.json` records that earlier installation and the then-observed process identities. Preserve it as history; it does not prove the two-service unit's relocated state or a real reboot. The original node-isolation and capacity/discovery reports likewise remain historical.

That evidence separately records a concurrent change to the original miner: its launcher was modified at 04:27:00 UTC and PM2 explicitly stopped it at 04:27:07 UTC, after which its new public-relay startup configuration failed. No operation in this helper addressed that app. The other seven original native PID/starttime pairs and both new mesh nodes remained unchanged. Do not treat the initial eight-node baseline as a claim that the independently changed miner remained running throughout later tests.
