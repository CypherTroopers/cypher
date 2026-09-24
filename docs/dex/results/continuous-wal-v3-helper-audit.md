# Local WAL format helper audit before the proposed v3 encoding

Read-only review of source59b0ac84536503682915fb0a1d5c75de60dedf7c70fd74ab9f65eb7bc729823d.
No codec implementation is implied by this inventory.

| Reader | Current assumption | Minimal conditional change |
|---|---|---|
| `reconfig/dex_financial_faults_test.go:263` `readFinancialWAL` | Local `fhs/state.json`, maximum2MiB, versioned digest | Keep bounds/path; extend only its checksum helper after v3 spec is approved |
| Same file:280 `validateFinancialWALChecksum` | Payload.Version1→wal/v1;Version2/schema4→wal/v2 | Add explicitly approved Version3/schema4→wal/v3; preserve v1/v2 rejection cases |
| Same file:309 `financialWALSafety` | Payload.Safety containing LastVote | No change if v3 preserves top-level Safety |
| `reconfig/dex_financial_wal_test.go` | Synthetic envelope version/digest checks | Addv3 valid/wrong-domain/wrong-schema andunknown-version cases; checksum mutation stays rejected |
| `reconfig/dex_continuous_faults_test.go` pause/resume | Exact raw bytes unchanged while stopped; later safety non-regression | No semantic change; reads go through versioned checksum helper |
| `reconfig/dex_financial_cli_test.go` identity substitution | Rejected identity must leave existing WAL byte-identical | No change |
| `reconfig/dex_continuous_diagnostics_test.go` `certifiedRecord` | HTTP `/v1/snapshot` Records include expanded Actions, verifies QC/data/state roots | No change if public snapshotv2 is unchanged; this is not a local WAL reader |
| `dex_continuous_economy_test.go`, `dex_continuous_flat_slots_test.go`, `dex_continuous_fixture_test.go` | Actions from the above verified public snapshot | No change |
| Late seventh-node snapshot import in `dex_continuous_economy_test.go` | Authenticated public snapshot, own vote key and fresh WAL | Public snapshotv2 remains unchanged; no local WAL injection |
| Failure archive/public external watcher | Explicit allowlist byte copies and SHA,2MiB local WAL size diagnostics | No codec dependency; preserve both versions as raw evidence |
| `scripts/dex/compact_replay_vectors.py` | Existing v2 compact snapshot/WAL golden | Preserve original; create separately named v3 local-codec vectors if adopted |

A new local encoding must not silently change public snapshotv2, proposal bytes,
checkpoint roots, native evidence or financial golden values. Full authenticated
replay remains in consensus.Application.Open; the test checksum helper is not a
substitute for that validation. External Trial13 byte/record profiling is only
failure diagnostics and may need a format-aware reader for future v3 files.

Implementation follow-up after approval of `../wal-action-dictionary-spec.md`:
only the two checksum-helper files above were changed. Version3/schema4 selects
`common-dex/wal/v3`; old v1/v2 conditions and the2MiB read cap remain. The focused
`TestFinancialFaultWALChecksumVersions` race test, three repetitions, passed in
1.093s (`continuous-trial14-wal-helper-race.jsonl`). This is envelope-check evidence,
not the production dictionary/replay acceptance gate or a G3 network PASS.
