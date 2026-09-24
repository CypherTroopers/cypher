# Pre-execution review of the financial runner

2026-09-23. Read-only source review of `scripts/dex/live_finance.py`, `live_finance_accounting.py`,
and `cmd/dex-live-finance`. This records review of the runner while under development; it is not a
financial LIVE PASS,60-minute operation, failure recovery, or performance result. The reviewer did
not send TXs or modify live DBs, PM2, genesis, or private keys.

Boundaries checked:

- The helper matches candidate inventory and manifest chain/genesis/DEX domain/config 4/manifest 2,
  constructing the formal registry/source verifier. It opens neither network connections nor live StateDB.
  Financial dry execution exists only in this independent client helper, outside CLX settlement imports.
- Funding-source signing uses the existing owned wallet's normal IPC `eth_signTransaction`.
  Together with TXs from new helper-created test accounts, it recovers and verifies EIP-155 signatures
  for the new chain ID. **Submission uses existing Common HTTP 8999 `eth_sendRawTransaction`.**
  There is no path directly executing deposits/payments through committee IPC.
- Business ID, signed bytes, sender/nonce/gas/value/calldata are fsynced to the journal before RPC
  submission. Resume uses the recorded identical raw TX. External pending nonces or nonce gaps
  stop operation without silently substituting another nonce. RPC ACK and canonical receipt are
  not displayed as independent finality.
- DEX actions also persist signed bytes and expected transitions first. Local progress advances only
  after the authenticated certified-state root matches the prediction; mismatches retain unfinished work
  and stop. Certified is `certified_not_finalized`; descendant proof is `dex_finalized_not_clx_accepted`.
- Initial funding plan: total 254 CLX from owned accounts and 225 CLX custody deposits. Allocation
  matches the candidate:105 CLX per trader and 6 CLX per relay checkpoint lane. The runner's own gas
  reservation is at most 1 CLX, with 1024 TXs/512 actions and bounded duration/injection intervals.
  Relay gas budgets are separate. Synthetic Oracle/BTC-CLX is not labeled real Oracle/BTC-USD.
- Native accounting helper is read projection only. Mutation methods panic; it does not use the
  consensus adapter to change live balances. The ledger reconciles receipts against normal signed
  TXs, gas/Common rewards/burn, bucket movements, claim events/nullifiers, and every target wallet delta.
  It explicitly distinguishes accounting from canonical observations from independent CLX source-finality authentication.
- Drain does not treat the certified tail as paid. Even after observing DEX proofs and relay-authenticated
  accepted sequences, it reports `AWAITING_INDEPENDENT_LEDGER_AND_LIVE_FAULT_REVIEW`.
  Claim payments require separate ledger/nullifier checks.

Points raised for clarification/correction during review:

1. Helper `io.LimitReader(stdin, 64 MiB)` limits the process's entire lifetime, not each request.
   A60-minute run repeatedly supplying full certified records/states may stop before the 3 MiB/request
   or 10000-request limits. Safe stateless-helper restart or a measured continuous budget is required.
2. Output `resolve/mkdir/LOCK.open` alone cannot reject selecting an incorrect existing operational
   datadir as output. Dedicated stage paths, private modes, ownership markers, and symlink/regular-file
   checks must distinguish journal/event destinations.
3. Explicitly rejecting anything outside current `DataSchema==5` in the finalized verifier, as in the
   certified verifier, makes the fixed current specification boundary clear.

These are observations shared during development and must be mapped to final post-change source/hashes
and execution results. Subsequent source gracefully terminates/recreates only the stateless helper child
before reaching 32 MiB total or 1000 requests. This is not a restart of a validator holding votes/WAL/nonces.
Output now requires a private owned directory under dedicated `build/stage/live-finance-*` or
`/tmp/live-finance-*` paths and a generation-bound OWNER marker. It does not follow symlinks and uses
no-follow handling for journal/LOCK/event files. Explicit finalized-verifier domain/schema 5/state-size
checks were also added. The revised source was independently checked. Record these units separately
from actual 60-minute operation.

Latest source also handles failed malformed native TXs without requiring native calldata to decode
successfully, counting only receipt revert/log checks and gas/Common/burn. It does not add treatment of
successful unknown EVM calls as transfers. A read-only auditor was also checked: it compares
hash/stateRoot/receiptRoot/gas/native projection and heavy engine 0 across all 14 CLX processes, plus
finalized checkpoints/roots across all 7 DEX nodes. These are LIVE unrun. This runner alone does not
establish completion of A/B/C load comparison or the targeted process-failure orchestrator; finance
receipts and drain observations do not substitute for them.

For final verification, the reviewer independently reran 8 tests in `test_live_finance.py`: PASS(UNIT).
Raw log: `/tmp/common-dex-live.8gezz_j9/public/q3-independent-finance-runner-final-unit.log`.
Main checks:254 CLX allocation,225→214 conservation, duplicate claims without extra payment,
revert gas, private output ownership boundaries, and rejection of remote fallback. These are not
financial LIVE operation results.
