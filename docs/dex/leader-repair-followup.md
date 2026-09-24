# Leader recovery: selected QC ancestry repair

2026-09-24; branch `FHS-D-ExchangeCore`; applies to the r8 follow-up of leader-owned CLX submission. This change does not add a node role, change the financial schema, or relax FHS finality.

## Observed live failure

After the leader sidecar `cypherdex2` was stopped and restored using the same DB, six participants progressed to DEX certified 166 / finalized 165. The restored participant remained at certified 162 / finalized 160. Public WAL inspection found:

| Statement | Semantic QC ID |
|---|---|
| Restored height 162, view 1146 | `4310777ca46134671b781fadf7e585373580624f9ea478abc18ae19f330d4271` |
| Selected height 162, view 1147 | `48ba9a312b9ef0a061f34a40c1fbef854b64ab9b25537b340f2239c89ba3a858` |
| Selected height 163, view 1152 parent | `48ba9a312b9ef0a061f34a40c1fbef854b64ab9b25537b340f2239c89ba3a858` |

The two height-162 records have the same checkpoint hash and state root, but different authenticated view statements. They are not interchangeable as `ParentQCID`. Both nodes have the exact selected height-160/view-1139 parent required by height 161. The former replication request asked only for records strictly after local certified height, so it repeatedly fetched the child without requesting the missing height-162 sibling. No invalid child was accepted.

Evidence: `results/r7-restored-repair-parent-qc.jsonl` in the task artifact directory `/tmp/common-dex-leader-submit-yda0gkpo`. This is a read-only metadata diagnostic, not an independent reauthentication of live WAL state.

## Narrow repair

`dex/service/replication/controller.go` retains the 8-byte request and one-record reply. The source serves `SelectedCertifiedData(after+1)`, following the actual highest-QC ancestry or authenticated finalized archive; it does not select the highest view independently at each height.

Seven fixed-size actor-local peer cursors start at the local authenticated finalized prefix. A cursor advances only after `ImportProposalData` has validated canonical encoding, domain, the five-signature QC, exact parent, deterministic execution, and finalized-state consistency. Missing parents reset only the scheduling cursor and request the finalized prefix. An unavailable child remains unacknowledged/retriable in the existing bounded transport. These cursors are neither voting state nor new trust roots; cold restart reconstructs them from consensus state.

The existing transport rotates past attempted unacknowledged frames, allowing a later parent response to be delivered while a child waits. No accepted frame, own vote, lock, timeout certificate, financial record, or claim is deleted by this change. Wire, signature, record, byte, and queue caps are unchanged.

## Validation and remaining boundary

`TestRepairColdSameHeightQCSiblingWithoutNewActions` constructs actual five-signature certificates and reproduces an old same-height QC, cold restart, missing child parent, higher-view unselected sibling, malformed signature, successful selected-ancestry repair, finality, and another cold restart. The stored own vote remains identical. No new consensus action or `Application.Start` is used to force progress. The focused run passed with 13 extension messages; this is a component result, not a live-network completion claim.

A separate actual TLS test covers an unacknowledged child followed by an available parent; final test logs and live deployment results are maintained in the task artifacts and final report.

If the missing semantic parent itself is an alternate QC of an already archived finalized anchor, this narrow repair can remain unavailable: the existing importer does not turn an alternate archived QC into a new trusted anchor. That case remains fail-closed and is not claimed as completed. Current live node 2 has the required finalized parent; its missing sibling is in the hot unfinalized suffix. General archived alternate-parent recovery requires a separately specified retention/import rule.
