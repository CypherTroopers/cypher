# CLX QC arrival-order regression

Observed 2026-09-22 during the isolated native financial integration run
`/tmp/common-dex-integration.hnc63_8r/logs/native-financial-sockets-2.log`.
The support transaction was proposed at CLX height 5, with an empty successor
certified at height 6. One replica rejected that successor QC with
`hotstuff prepareQC invalid` and remained at view 6. The test waits for every
validator's native receipt, so this replica prevented the funding gate from
completing. Other nodes repeatedly announcing view 7 is compatible with ordinary
quiescence after finalizing the transaction, rather than evidence by itself
that all validators stopped committing.

The failed replica's full log is `/tmp/fhs-process-failure-2531368040.log`.
This log alone does not expose its volatile view contents. The matching cause
is independently reproduced by an authenticated deterministic test:
`TestFHSEarlyQCBeforePrepareUsesAuthenticatedCatchup`.

`newFHSNewView` installs a volatile view before receiving Prepare.
`handleQCBroadcastMsg` previously treated any existing view as containing the
proposal: the authenticated QC's nonempty `DataD` differed from the empty
`proposedTState`, so it rejected before scheduling content validation. With no
volatile view after a restart, the same valid QC already used the standalone
historical committee, leader envelope, aggregate vote, and full proposal/state
validation path. A cache entry therefore made recovery less capable.

The bounded fix routes a matching-number FHS view with neither key nor
transaction proposal state through that existing standalone verifier. It does
not weaken the comparison for an existing nonempty proposal, change committee
thresholds, change finality, skip state reexecution, or alter timeout values.

Executed evidence:

- Before the fix, the deterministic valid case failed with the exact QC error,
  no validation job and no certification callback. Invalid aggregate,
  envelope, proposal and conflicting nonempty cached proposal cases rejected.
  Raw log: `clx-early-qc-before-fix.log` under the artifact root above.
- After the fix, the complete `reconfig/hotstuff` package passed with the race
  detector in 7.806 seconds. The valid case schedules asynchronous validation,
  completes certification once, and creates no local vote. The negative cases
  still reject. Raw log: `clx-early-qc-after-fix-race.log`.

The additional opt-in process regression
`TestFHSProcessRecoveryQCBeforePrepare` drops only Prepare messages to one
nonleader; it keeps real QUIC, authenticated QC delivery, data repair, WAL,
execution validation and finality. Its result is recorded separately from the
unit gate and from the complete native financial scenario.

- Initial process run: the new test incorrectly required finalized height 2
  from an existing fixture that emits just one transaction until a separate
  heal command. All seven actually reached identical finalized height 1 and
  certified height 2; the isolated replica dropped both Prepares and obtained
  transaction bodies through repair. This test expectation failure is retained
  in `clx-early-qc-process.log`; it is not classified as a production failure.
- Corrected process run: PASS, 26.10 seconds. PID 916048 dropped two Prepares,
  reached finalized height 1 / certified height 2, and agreed with all six
  peers on canonical transaction, block hash, receipt status, gas and state
  root. Raw log: `clx-early-qc-process-2.log`. The test does not need another
  transaction, a forced timeout, or an application-specific state shortcut.
