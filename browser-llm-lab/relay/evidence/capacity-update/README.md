# Capacity update evidence

Captured on 2026-10-03 for the 80-session / 40-circuit deployment. See ../../capacity-update.md for the interpretation and reproduction commands.

- baseline.json and working-tree-preservation.json: initial dirty state/hashes and final touched-file inventory; no baseline file was removed.
- native-upgrade-preflight.json / native-upgrade.json: scoped owned-Common binary/config switch and post-start private APIs, unrelated-process preservation and B isolation.
- native-source-preservation.json / native-build-manifest.txt: unchanged supplied native source/binary checks and build provenance. No new native build or Go test run is claimed.
- integrated-unit.log / integrated-python.log: final test suite. gateway-capacity-tests.tap and worker-capacity-tests.log are subsets, not additional totals.
- gateway-capacity-tests-initial.tap: retained earlier failed test iteration, superseded by the final passing log; do not count it as PASS.
- deployment.json / public-deployment.json / gateway-restart.json / final-readiness.json: hashes, actual public HTTPS responses and exact process switch.
- native-browser-capacity-report.json / -runner.json / -events.json: raw browser run and events. The report and runner copy are intentionally preserved for the existing audit format.
- native-browser-capacity-report-audited.json / native-browser-capacity-audit.json / native-browser-capacity-summary.json: separate interpretation and concise metrics.
- native-browser-capacity-recovery.json: the unplanned C readmission. Cause was not determined; this run is not uninterrupted stability or a 30-minute soak.
- native-browser-capacity-cleanup.json / native-after-ui-cleanup.json: read-only post-test cleanup observations, not an extra data-ingress path.
- capacity-public-ui/: ordinary public UI acceptance, mobile viewport and desktop screenshots. Physical phones were not used.

Absolute /tmp paths inside original reports identify the original execution location and have intentionally not been rewritten. Source/test reproduction paths are in the live repository. Runtime secrets and datadirs are not included. The baseline tracked diffs are compressed under the private operator rollback directory .runtime/releases/capacity-v1/baseline/, outside these public-source evidence files. Historical evidence from earlier revisions is retained unchanged.
