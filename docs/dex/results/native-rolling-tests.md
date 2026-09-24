# G1 CLX native rolling component results

2026-09-22, uncommitted source identified by [source SHA256](native-rolling-source.sha256).
This is a StateDB/cryptographic component gate, not a multi-process G1 network gate.

Executed PASS:

- `python3 scripts/dex/native_rolling_vectors.py --check`: independent root-v3,
  storage keys, metadata, ID index and canonical opcode6 envelope vectors.
- `go test -race ./dex/settlement ./dex/protocol ./params -count=1`, with isolated
  GOCACHE and GOPROXY=off: [raw result](native-rolling-race.log).
- Settlement production dependency closure has no dex/engine, dex/devnet,
  dex/accounting, dex/consensus or dex/service import.
- Staged anchors16/32 cannot authorize checkpoint; recent48/64 confirm the
  bounded chain. Historical20 is later inserted through retained16→20→32.
  Checkpoint20 is accepted at executing height300 without querying GetHash.
- Wrong ancestor, current-block target, missing base, corrupt MPT, altered
  continuation, absent retained descendant, occupied-height conflict, malformed
  codecs, aggregate header and byte bounds, unsupported config and mixed schema
  reject. Injected StateDB error rolls back record writes and events.
- Normal anchor uses12 storage writes; first anchor plus config/root/surplus uses15,
  below16. Exact replay performs zero storage writes/events, including after a
  forced native surplus appears.
- StateDB commit/reopen preserves anchors and old checkpoint claims. Full1024
  anchor capacity rejects another insertion and still permits an old native claim.
  Unit accounting:225 CLX custody→215 after10 withdrawal, plus1 forced surplus atom;
  replay does not pay again. Earlier225→214 integration is a separate scenario.

NOT_RUN in this component gate: actual CLI relayers, network G1 finality/admission,
two independent relay processes, long-duration mixed workload, production economics.
The signed source headers are unit generated using real CLX/FHS codecs, signatures
and StateDB MPTs; they are not described as actual process consensus results.

Retained anchor capacity remains finite1024. Existing checkpoint/inbox/DEX record
limits are unchanged. This component does not claim indefinite operation or G2.
