# G2 independent relay network review

This review covers `dex/relay/network.go` against
[relay-network-spec.md](relay-network-spec.md). Production changes were made by
the network owner; this reviewer added tests only. It is not a review of all
future planner behavior, nor a claim that the normal CLI integration gate ran.

## Finding reproduced and corrected

A correctly signed DEX bundle with a FinanceSummary for a different custody
address passed `refreshDEX` and entered its authenticated cache. The generic
bundle verifier intentionally receives an Epoch, which has no custody field.
The network backend must additionally compare the summary custody to its own
genesis-bound relay configuration. Without that comparison the native handler
still rejects the checkpoint, but the relay could consume gas submitting it.

`TestNetworkDiscoveryRequiresAuthenticatedSequentialBundles/foreign-custody`
reproduced this: no error and one cached bundle. The initial raw FAIL is retained
as `results/continuous-g2-network-audit-1.jsonl`. The owner added custody equality
checks to discovery and checkpoint/claim authorization, an empty-codeHash check
for the authenticated native custody account, and owned copies of mutable relay
configuration fields. The same test then passed with the race detector, along
with the other nine discovery cases: valid proof, unauthenticated height alone,
altered signature, previous/pre-root/sequence/schema mismatch, oversized discovery
height and unavailable data. Package elapsed1.231s, raw
`results/continuous-g2-network-audit-2.jsonl`.

## Completion and trust boundaries

- Native completion reads exact checkpoint-history hash, nullifier leaf or
  retained anchor ID through account/storage inclusion proofs against
  `Source.Current()`'s authenticated source state root. RPC receipt/status/ACK
  fields do not populate completion. Payer nonce and balance come from the same
  anchor root. The core treats nonce consumption without the expected economic
  effect as a conflict; an ACK alone cannot release the nonce reservation.
- Anchor jobs verify source finality from a base retrieved through authenticated
  CLX storage, and historical continuation must meet a retained descendant.
  SignInfo is verified even though the ordinary block hash excludes it.
- Checkpoint and claim calldata are reconstructed from the full verified bundle
  and must exactly equal the queued payload. Claim owner, fixed recipient,
  amount, index/count/path and original checkpoint remain bound. The native
  settlement handler independently repeats its own fund/nullifier checks.
- Inbox completion checks the complete range and entry root, not a cursor lower
  bound. Empty-range completion requires the exact submitted action's data root.
  Target anchors are reconstructed with Source.AnchorAt rather than trusted from
  job Authorization. Source proof APIs that accept an Anchor as an argument are
  lower-level helpers; the reviewed network passes its own authenticated Current
  or stored/derived anchors and must preserve that discipline in new callers.

`TestRelayInboxCompletionNeedsWholeProofBoundEffect` uses actual isolated HTTP,
signed CLX headers, StateDB MPT proofs and the production Network plus Relay.Step.
Eight cases pass under `-race`: a full matching range and exact empty action
complete; advanced cursor alone, a different entry root and a different empty
action do not; modified amount, same-hash forged SignInfo and an untrusted target
root are quarantined. No native transaction signer is invoked for the Inbox lane.
The DEX bundles are deliberately registered committee-signed fixtures: they test
the consumer trust boundary, not correctness of financial execution under a QC.
Package elapsed1.949s, raw
`results/continuous-g2-inbox-observation-sockets-1.jsonl`.

An initial non-opt-in compile run skipped this HTTP test as intended. The first
namespace execution request did not start because automatic approval review
timed out; its permitted single retry produced the PASS above. No operational
network/node was involved.

## Remaining gates

These focused tests do not execute native anchor/claim transactions through a
real CLX process, or test every nonce/receipt observation over RPC. The separate
relay-core crash tests and normal-CLI short integration gate cover those paths.
The new planner and long G3 run require their own results. Bounded caches/history,
proof/data unavailability, trusted committees and finite128 DEX record capacity
remain explicit limitations.
