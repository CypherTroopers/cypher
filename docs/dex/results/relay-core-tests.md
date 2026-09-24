# G2 durable relay core component results

2026-09-22. [Source manifest](relay-core-source.sha256), [raw boundary results](relay-core-boundaries.log),
[race result](relay-core-race.log). Go uses isolated GOCACHE and GOPROXY=off.

Executed PASS:

- Independent Python RLP binding/job/state/disk-envelope golden verification.
- `go test -race ./dex/relay -run '^TestRelay' -count=1`:2.091s.
- Seven actual SIGKILL child-process boundaries and reopen: intent, prepared
  unsigned template, signed bytes, before send, after send, after proof,
  completion. The killed process owns only fresh dedicated test data.
- Seven hook-error boundaries, identical raw-TX retransmission after ambiguous
  ACK, unsigned template fsync before signing, raw-TX fsync before broadcasting,
  and completion-proof revalidation after restart.
- Unverified/not-ready observations and insufficient gas balance cannot cause
  signing. RPC ACK cannot complete. Externally completed jobs retain our signed
  nonce reservation until authenticated nonce consumption. Missing effect after
  nonce consumption becomes conflict, while another payer proceeds.
- Malicious signer template rejected; stale unsent evidence can explicitly be
  replaced while prepared/signed attempts cannot. Binding mismatch, double open,
  unowned directory, symlink and corrupted snapshot rejected. Persistence failure
  stops further signing/sending. Nested store counts/bytes are bounded before
  full decode and signature revalidation.
- Failed first lane cannot starve others after restart. Per-lane208 headroom,
  global256 active budget,1024 completed history, dependency-preserving pruning
  and bounded in-memory indexes are checked.
- Production dependency closure contains no dex/engine, dex/devnet,
  dex/accounting, dex/consensus or dex/service.

These core tests deliberately use an internal fake proof backend to isolate
persistence and nonce state-machine behavior. They do not claim that fake
observations establish financial finality. The production network backend must
perform actual genesis-bound CLX/DEX finality and MPT verification; that has
separate tests and results. The helper SIGKILL test skips in the parent and runs
only in each spawned child.

NOT_RUN here: real autonomous relay CLI, real Common admission/TxQUIC and CLX/DEX
FHS integration, two independent real relayers, fee accounting from certified
receipts, sustained60-minute mixed load. Those gates remain separate.
