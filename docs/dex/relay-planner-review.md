# G2 independent planner review

Scope: `dex/relay/planner.go`, `network.go`, the source client's rolling evidence
boundary, and cold relay/source recovery. No financial engine, native accounting,
process harness, epoch policy or monetary parameter was changed by this review.

Two liveness defects were found and corrected following implementation review:

* Historical discovery allowed a retained interval up to64 source headers, but
  asked `Source.BuildRange` for either entire leg, whose existing limit is32.
  The planner now fetches at most two32-header legs per side, joins their
  authenticated headers with the final target MPT and reverifies from the
  original authenticated base. The complete native update keeps64 headers and
  the existing64KiB byte cap. This does not authenticate an RPC-supplied anchor.
* Empty inbox job IDs already described the target anchor rather than a proof
  encoding, but completion required the exact action data hash. Equivalent
  successful actions by competing relays could therefore leave a durable job
  waiting forever. Completion now uses the source-authenticated target or a
  later source-authenticated anchor in a verified schema4 DEX checkpoint.
  Nonempty jobs likewise reconcile contiguous split ranges by recomputing each
  entry commitment; broader overlaps require fresh full-range source MPT
  proofs and entry-by-entry comparison. A cursor or a claimed latest height
  alone cannot complete a job.

Every consumed checkpoint bundle is retained in the inbox completion's opaque
forensic proof; broader source ranges retain their evidence too. Added evidence
is limited to2MiB before collection, within the unchanged4MiB core observation
bound. The core still freshly authenticates a stored completion on reopen.
No receipt status or HTTP acknowledgement is treated as finality.

Focused tests use actual isolated HTTP sockets, real BLS signatures and actual
StateDB/MPT proofs generated in unit fixtures. They cover equivalent empty
proofs, a source-authenticated descendant, split and broader credit ranges,
conflicting commitments, a skipped cursor, historical1+33 and33+1 header legs,
source cold restore beyond64 blocks, a freshly empty DEX discovery cache, and
repeated empty/nonempty reconciliation. These tests do not assert process-based
financial execution; the separate ordinary CLI relay/long-run scenarios supply
that evidence.

The first attempt failed because the new test proposal omitted its required
parent hash; that fixture was corrected, without changing the production
verifier. The second passed all semantic completion cases but the proposed
positive40-header historical fixture exceeded the unchanged64KiB native cap.
That failure is retained, and the positive boundary uses34 headers. Large proof
bytes remain an explicit bounded stop rather than an automatic weaker proof or
expanded limit. Logs `continuous-g2-planner-attempt1-*` and `attempt2-*` preserve
these distinctions. The first all-pass run is retained as
`continuous-g2-planner-before-negatives-*`; the final run additionally checks
wrong exact/later anchor hashes and the complete forensic proof set.

Final focused race gate: [JSONL](results/continuous-g2-planner-unit.jsonl) and
[metadata](results/continuous-g2-planner-unit-metadata.json), four top-level tests
and16 PASS events, zero FAIL/SKIP. The pre/post Go manifests differ only in the
concurrent independent `reconfig/dex_continuous_economy_test.go` edit, not a
package test compiled by this selection. Source WAL, planner, network and all
selected fixture/test files were unchanged during the run.

Physical power loss, new public epochs, and unbounded archival retention are
outside this focused test's execution boundary. No operational node or data was
touched, and no remote push was performed.

The later whole socket regression exposed one older observation test still
expecting an empty update with different action bytes to remain incomplete.
That assertion predates the semantic-anchor rule above. It is now named
`empty-equivalent-anchor` and expects completion from the authenticated matching
source anchor; an adjacent `empty-conflicting-anchor` case changes the
QC-certified checkpoint's source hash and requires conflict isolation. The
initial socket FAIL is retained. This changes a superseded test contract, not
the source authentication or nonempty-credit checks. Final socket rerun is
recorded in the continuous-operation acceptance results.
