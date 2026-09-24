# Relay inbox observation after fixed-membership CLX key renewal

2026-09-23. Trial8 preserved at `/tmp/common-dex-check.9yWB0ai8/continuous.log`.
Both relay journals in `/tmp/continuous-public-failure-3293954290` retained job
`489d9dd43c61cfbafb509d37c3892f50ff12ca2c6428197c634ceb733e0a3cfb` as quarantined
with `invalid relay job / rolling CLX trusted base mismatch`, sends0. Its target
is anchor v2, source height245, inbox8; its input proof advances229→245, has16
headers and2entries. DEX finalized51/certified52 still referenced source229.
The readonly RLP/journal extraction is `/tmp/common-dex-continuous.uye5vgqi/trial8-relay-readonly.json`.

## Cause and required boundary (fixed before implementation)

`Network.observeInbox` authenticates the target with `Source.AnchorAt`, then
rechecks the job's account/count/entry MPT proofs as a zero-header same-anchor
range. That synthetic range lost the **target** key context. `VerifyHeaderContext`
correctly rejects v2 anchors without authenticated key-header/order/boundary
preimages, even for an empty header interval. Thus a valid post-renewal inbox job
is quarantined before it can be submitted. This does not demonstrate a different
financial state root or a successful unauthenticated credit.

Add a bounded source read returning the same fully authenticated historical
anchor and its matching key context. It must use the already verified source
segments (at most32 header witnesses for that segment prefix) and the existing
account/count MPT verification. It must preserve chain/genesis/DEX/custody,
height/hash/root, epoch/current-key/ordered-committee, activation end/root and
inbox count. Missing or inconsistent history is an error; a caller-supplied
anchor/context is never a new trust root. Returned byte slices must be owned.
Legacy v1 keeps its empty context. Source cold recovery still verifies the WAL
from the configured bootstrap before returning any context.

The relay compares the returned full anchor with the job authorization, then
attaches only this authenticated target context to the synthetic same-anchor
range. It retains the **original job's** account/count/entry proof bytes: it may
not silently replace a bad job proof with a newly fetched good proof. The range's
input context cannot simply be copied: across renewal it describes the old base
key/order, while the target requires the new key/order and possibly pending
previous-key boundary. Verifier, key activation and signature rules stay intact.
No codec, evidence-size limit, gas rule, deposit schedule or economic rule changes.

## Required regression scope

Real loopback HTTP plus real registered BLS source/DEX proofs and MPT paths:
renewal-crossing and same-anchor jobs; empty and nonempty inbox ranges; target at
pending activation and after the boundary; cold source/relay reopening; altered
job account/count/entry proofs; forged target identity; absent/wrong current or
previous context rejected by the existing verifier. The test must first fail
before the production correction. A focused PASS is not the final G3 network
PASS and does not attest WAN, C BLS heap or permanent historical-data recovery.

## Executed focused regression

Before the production correction, all eight renewal/same-anchor variants of
`TestRelayInboxRenewalTargetContext` failed with the reproduced base mismatch
(one top-level FAIL, nine test FAIL events, 2.936s). The failure log is retained.
After the correction, the final isolated loopback race run passed three
top-level tests / 63 test PASS events, zero FAIL/SKIP, 16.902s:

- `TestRelayInboxRenewalTargetContext`: eight renewal/pending/same-anchor,
  empty/nonempty variants; authenticated target context ownership; absent or
  changed current/previous/boundary context rejection; cold source/relay reads.
- `TestRelayInboxRenewalDoesNotReplaceInvalidJobProofs`: changed account,
  count and entry MPT paths and changed target identity stay quarantined. The
  relay does not fetch replacement job proof bytes to turn these into success.
- `TestRelayInboxRenewalReadyACKThenColdCompletion`: five pre-finality variants
  submit the original action exactly once; HTTP ACK leaves `submitted`; cold
  source/relay reopening completes only after a registered DEX quorum proof.
  These signed fixture witnesses do not substitute for ordinary process FHS.

Raw before/after/final logs, source hashes and environment are retained in
[`results/continuous-relay-renewal/metadata.json`](results/continuous-relay-renewal/metadata.json).
The source manifest was captured immediately after the focused run; the ordinary
G3 runner must independently capture before/after manifests for its final run.
No verifier, evidence bound, native transaction path or financial rule changed.
The additional bounded context verification occurs in the relay; its incremental
wall-clock and C allocation costs have not been separately measured.

## Existing quarantine is not automatically migrated

The trial8 stores are preserved. This fix prevents the reproduced quarantine in
new execution; it does **not** automatically rehabilitate an already quarantined
record. Selection skips quarantined records, and enqueueing an identical payload
does not reset that phase. The explicit `ReplaceUnsent` library operation can
reset an eligible never-reserved/never-sent job, but the ordinary CLI has no
operator job-reset API. No old record was reset in this work. The cold recovery
tests above cover queued/submitted/completed records, not quarantine migration.
