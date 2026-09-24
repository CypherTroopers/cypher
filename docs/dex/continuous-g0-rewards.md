# G0 / O05: committed participation, deterministic reward execution

## Reproduced defect (before correction)

On 2026-09-22 the new regression
`TestNativeCLXFinancialFHSScenario/reward_execution_independent_of_local_certificate_delivery`
failed on identical finalized parent-17 bytes, parent root, context and signed
proposal-18 bytes. A collector without the omitted certificate accepted and
computed a post root; another collector retaining that valid certificate
returned `ErrOmittedCertificate`. Raw result:
`/tmp/common-dex-continuous.uye5vgqi/logs/o05-reward-local-state-before.jsonl`
(20.467 seconds). No cryptographic check was bypassed in the reproduction.

The prior I27 test proved a local omission policy and unchanged balances, not
consensus determinism. Its local-knowledge-dependent acceptance is superseded
here. `Execution.Execute -> Collector.CheckClose` and the post-finality
`Collector.Close` must cease influencing consensus execution/replay: delayed
local delivery must neither change a post root nor stop replay of finalized
financial state. Collector receipt cutoff/vote WAL safeguards remain intact.

## Versioned specification fixed before implementation

A separate signed participation commit action records authenticated evidence
in the DEX state before reward close. It uses new marker `CDXP`; old `CDXR`
close bytes and receipt/certificate golden vectors remain unchanged. The
envelope is marker:4 || existing signed-engine-action:282 || payload-length:u32
|| commit payload. The engine command uses RewardClose solely for existing
oracle authorization, nonce and clock checks; this action reserves no reward.
Its Target is the first 20 bytes of SHA256(`common-dex/participation-commit/v2`
|| zero || payload). A different close hash domain prevents envelope confusion.

Commit payload: ASCII `CDXPCB02` (8), version:u16=2, count:u16 in 1..70,
then ascending unique duty-hash ordered `(certificate-length:u16, certificate)`.
Every certificate is bounded to 425 bytes and cryptographically verified against
the immutable registry. Aggregate action bound remains 64 KiB. Independent
Python vectors precede the Go codec; structural zero signatures are not valid
cryptographic certificates.

The state stores Participation version 2 and a duty-hash sorted set of
`{CommittedAt, Certificate}` records. Maximum pending records is 140; pending
periods are limited to the next two after Engine.RewardPeriod. A commit must
occur strictly after its duty height and no later than period-end+4. Duplicate
duty proofs are idempotent and preserve the originally committed representation
and height. A valid certificate is proof of timely collected participation,
not proof that its proposal eventually became canonical.

At close, the 11 existing bounded FHS finality witnesses authenticate canonical
period targets and the grace boundary. Only committed certificates matching
those target proposal IDs/views are eligible. Authenticated noncanonical fork
certificates remain evidence but earn no points and cannot poison closing the
canonical period. The submitted close package must include exactly every
eligible committed duty and no uncommitted duty. Alternate valid collector
signature subsets for the same duty do not change set membership or points.
At least one committed record for the period is required; without committed
participation the reward period remains frozen and ordinary market work can
continue. The exact set, proofs and parent state are the only close inputs.
After close, the state's records for that period are removed; historical
evidence remains in authenticated action/checkpoint history.

FinancialState versions 1/2 remain decodable. Their first explicit CDXP action
transitions deterministically to version 3/4 with root hash domains
`common-dex/financial-state/v3` / `v4`. Missing participation state makes close
fail identically on every validator. Genesis bytes and old codec vectors are
retained. New Execution IDs v3/v4 prevent opening old execution WALs as if this
were the same application. There is no automatic conversion of a previously
closed local collector root into consensus state. Later native rolling
configuration may use FinancialState version 5 with participation v2 present
from genesis; that is a separate change.

The existing height-6 oracle Noop is replaced with the commit envelope, retaining
the same nonce, height count, fee formula and 225 CLX custody / 11 CLX claims /
214 CLX remaining economic expectation. Close remains at height 18.

## Scope and residual fairness limits

The collector still creates and retains timely receipts/certificates for relay
and diagnostics. Its local close/check methods remain available as local-policy
regressions, but are not a consensus validity or finalized callback gate. A
late local certificate must not alter replay or invalidate a committed payout.

This fixes deterministic execution and omission of committed evidence. It does
not prove censorship-resistant certificate admission: a complete certificate
which never enters the agreed log has no consensus inclusion guarantee. The
oracle-authorized fixture, bounded capacity and deadline can delay or refuse
submission. Those limits remain explicit; local evidence is retained, not
silently deleted to manufacture successful payment. Public fairness, forced
inclusion and incentives are not declared complete.

## Validation status

Before-fix divergence: reproduced FAIL, raw path above. An initial new-test
brace typo caused a setup failure (`o05-committed-rewards.jsonl`) and was fixed;
it is an implementation-time test typo, not an inherited production failure.

Executed after correction:

* Independent Python v2 golden generator `--check`: PASS. Old participation
  golden bytes were retained unchanged.
* New codec/exact-set/deadline/duplicate/orphan-duty unit tests: PASS, 0.725s,
  `logs/o05-committed-rewards-2.jsonl`.
* Whole in-process funded financial trace: PASS, 27.410s,
  `logs/o05-financial-committed-1.jsonl`. Height 6 commits seven certificates,
  height 18 reserves the same funded reward, and the existing native custody
  and claim assertions remain unchanged.
* `go test -race ./dex/rewards ./dex/devnet ./dex/service/finance
  ./dex/devnet/testnet -count=1 -json`: all four packages PASS (3.740s, 48.852s,
  1.437s, 1.088s respectively), `logs/o05-rewards-finance-race.jsonl`.
  The identical-parent/proposal test also checks local alternative close state
  and collector shutdown/reopen: execution rejection and finalized callbacks
  remain independent of that local WAL.
* Additional CDXP wrong envelope domain, modified signature, modified payload,
  version transition and zero immediate reward tests: PASS, 26.121s including
  the surrounding financial fixture, `logs/o05-commit-envelope-financial.jsonl`.

These logs are under `/tmp/common-dex-continuous.uye5vgqi`; preserved copies of
the JSONL results are in `docs/dex/results/continuous-g0-*`. The corrected normal
CLI / real-process financial scenario has not been rerun by this subtask.
Existing prior process PASS results must not substitute for that changed trace.
