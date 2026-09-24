# CLX canonical state persistence after process crash

The isolated full financial run
`/tmp/common-dex-integration.hnc63_8r/logs/native-financial-sockets-4.log`
accepted 18 DEX checkpoints and reached CLX height 43 before killing its seven
owned CLX processes. All restarted nodes reported a missing head state. FHS
safety restoration then failed on a missing certificate.

The missing certificate was for block 22,
`0x3ea2ae32358c418919f8e1ff9808eb39108ff04d3fbaae45c9d01a5de99e0847`,
as identified by its original proposal log in
`/tmp/fhs-process-failure-1534402094.log`. It was an old canonical block, rather
than the highest uncommitted certificate. The error used raw `%s` hash bytes
and the test control JSON replaced invalid UTF-8, so the matching original
proposal log was needed to recover its complete printable hash.

`persistValidatedFHSCertificates` writes certificates and the highest safety
watermark in one synchronous database batch. `pruneFHSPersistence` preserves
every above-head certificate and an eight-block canonical suffix, and may
collect older canonical certificates. However, the previous
`writeBlockWithState` retained recent trie nodes in memory using the ordinary
128-block trie window. After a process crash, startup could rewind below the
pruned canonical suffix. `loadFHSWAL` then followed the durable highest
certificate toward that rolled-back head and encountered legitimately
collected historical data. The certificate error was downstream of canonical
state loss; no separate certificate verification exception is added.

The storage fix persists the validated FHS state root before canonical head
publication and synchronously writes the canonical head batch before exposing
the new in-memory head. The central `writeHeadBlock` boundary also covers a
previously staged block whose state is present only in the trie cache. It
retains strict finality checks and the existing quorum. No balances are
reconstructed from an old checkpoint or refunded during recovery.

Executed unit evidence in `core/fhs_state_durability_test.go`:

- Real five-of-seven BLS target and direct-child certificates enter
  `CommitFHSVerifiedProposalWithProof`, with an already-executed StateDB fixture.
  The changed account balance, nonce, contract code and storage are absent from
  a fresh trie database before publication.
- Both fresh-proposal and known-cached-state paths expose the exact state from
  a fresh trie database immediately after commit and after reopening LevelDB.
  Neither path calls `Blockchain.Stop`, so shutdown cannot flush missing nodes
  and hide the bug. The stored block retains the exact finality proof.
- An injected canonical head `WriteSync` failure returns an error while durable
  and in-memory head markers remain at genesis; the failed block does not
  become canonical.

The core FHS/HotStuff race subset passed in 4.233 seconds; log
`clx-cold-state-core-race.log` under the artifact root above. The focused test,
including injected fsync failure, passed under the race detector; log
`clx-cold-state-fsync-race.log`. These are persistence-boundary tests, not a
replacement for the independent seven-process SIGKILL/restart financial run.
That full-run result is tracked separately. Storage cost and hardware power
failure behavior have not been benchmarked or simulated by these unit tests.
