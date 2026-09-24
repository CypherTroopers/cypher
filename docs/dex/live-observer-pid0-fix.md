# Fix for observing stopped PM2 PIDs

2026-09-23. Changes are limited to `scripts/dex/live_observe.py` and its unit tests.
This work performed no PM2 operations, DB operations, starts/stops, or fund operations.

In saved `start-observation.json`, stopped `cypherdex1`–`cypherdex6` had PM2 PID 0.
The old implementation expanded PPid descendants from `{0}`, traversing the entire host from
processes with PPid=0 such as PID 1. It incorrectly attributed 257 processes, including 8 main processes
with datadirs, to each stopped app. This is not evidence that those stopped apps actually launched them.

The new `descendant_pids` starts only from positive integer root PIDs present in the `/proc`
observation snapshot. PID 0, invalid types, and vanished roots return an empty set. Valid
shell → CLX → sidecar parent/child relationships remain intact. No rule was added to hide surviving
processes based solely on PM2 status strings. An empty set means no process could be attributed to
that PM2 root; it does not guarantee absence of orphan processes on the host. Existing PID/start-tick/
datadir checks remain separately necessary to confirm stopping.

Observation tests mocking all PM2, `/proc`, and socket access reproduced 2 pre-fix FAIL results:
incorrect host-wide attribution from PID 0 and incorrect orphan attribution from a vanished root.
After the fix, these 2 cases, invalid roots, and existing secret-argument exclusion total 4 tests
PASS(UNIT). They also confirm attribution only to valid 100→101→102 descendants, excluding sibling
apps and PID 1.

Raw logs and mappings are under `/tmp/common-dex-live-resume-496b6e0e/public/`.

- `observer-pid0-before.log`:2 pre-fix FAIL results.
- `observer-pid0-final-unit.log`: final 4 tests PASS.
- `observer-fix-before.json`: hashes of the pre-change observer and original observation.
- `observer-pid0-result.json`: final source hash, saved-snapshot reevaluation, and unrun scope.

Original `start-observation.json` is unchanged, retaining SHA-256
`c876428339be48c9c1a38e6834cde81722f014a712dd529dffecd0a7949002aa`.
Applying corrected attribution rules to the saved snapshot yields empty sets for all 6 stopped apps,
but this is not a new LIVE observation. Current PM2/CLX state requires fresh retrieval by the coordinating runner.
