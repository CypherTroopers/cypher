# G2 explicit relay CLI and interrupted-write recovery

2026-09-22. [Source manifest](relay-cli-orphan-source.sha256).

Executed PASS:

- `go test -race ./cmd/cypher -run '^TestDEXRelayCLI' -count=1 -v`:3.794s,
  [raw CLI result](relay-cli-race.log). Strict config rejects unknown/duplicate/
  discarded nested fields, wrong domain/config, inappropriate endpoints, absent
  devnet intent, invalid payer purpose, recipient reuse and unsafe key files.
- Sign-only gas provider validates payer, chain, destination, zero value and
  fee template. No default node flag starts a relay. Discovery failure still
  calls durable Step and writes bounded status. ACK remains a submission label.
- Actual `dex-relay` subprocess runs with a finite duration, writes source/core
  sibling stores, restarts, and exits successfully after SIGINT. Source endpoints
  intentionally unavailable: status retains trusted genesis and does not invent
  CLX/DEX progress. Key file hashes remain unchanged.
- Fixed `status.next` replacement plus20 injected partial-write/reopen cycles
  leaves canonical status unchanged and does not accumulate disk generations.
- `go test -race ./dex/relay -run '^TestRelay' -count=1 -v`:2.433s,
  [raw core result](relay-core-orphan-race.log). In addition to prior core tests,
  actual SIGKILL after writing `state.next` but before fsync runs3 times. Restart
  retains the preceding canonical snapshot, does not promote an uncommitted
  intent, and returns to exactly OWNER/LOCK/state.bin files.
- Legacy temporary recovery validates all candidates before deletion and retains
  unrelated files. Symlinks, invalid canonical snapshot and excess legacy orphan
  count fail closed without partial cleanup. Core cleanup is under its lock,
  after canonical binding/codec/signature validation; status recovery parses only
  operational metadata and never turns it into a financial trust root.

One initial CLI test failed because its test-only lock probe retained an acquired
lock. The test was fixed; production signal handling did not change for that
failure. [Initial raw failure](relay-cli-initial-test-failure.log) is retained.

NOT_RUN in this gate: actual autonomous funding→DEX→native claims, two live
relayers, continuous financial operating costs, power-loss durability and60-minute
mixed workload. Real network/finality verification is covered by separate gates.
SIGKILL tests establish process-crash behavior, not power-failure behavior.
