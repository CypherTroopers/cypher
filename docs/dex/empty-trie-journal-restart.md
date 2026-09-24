# Empty trie journal and ordinary Common restart

The first full ordinary-CLI financial restart failed with a missing key genesis.
A four-second standalone native CLI reproduction failed at the same call to
`core.SetupGenesisKeyBlock`. No operational directory was opened or modified.

The diagnostic run read the newly initialized, closed LevelDB in read-only mode.
Both key0 and transaction0 mappings existed after `init`. Immediately after a
normal Common SIGINT shutdown, before the rejected DEX-recipient probe, the
`chaindata` directory itself was absent. The shutdown log saved the clean trie
cache at the whole instance directory (`…/common/cypher`). Therefore the recipient
probe did not cause the data loss and the restart did not use a different path.

Source chain:

- `eth/backend.go` passed `stack.ResolvePath(config.TrieCleanCacheJournal)` even
  when the configured string was empty. The same expression exists in reference
  HEAD `70862a71dfaf2b00694dc1354c6a64e9504d7db5` at line272.
- `node/config.go:317` resolves an empty relative path to the instance directory.
- `core/blockchain.go:1212` saves the cache on shutdown whenever that resolved
  journal string is nonempty.
- `trie/database.go:843` calls fastcache persistence. The installed
  `github.com/VictoriaMetrics/fastcache@v1.13.3/file.go:69` removes the destination
  before atomically renaming the newly saved cache into its place.

The fix preserves an empty journal string as disabled in `eth.New`. Nonempty
configured paths retain their existing resolution. No genesis reinitialization,
authenticated-history bypass or fallback was added. Explicitly pointing a
nonempty cache path at other data remains an operator configuration concern;
this change fixes the unintended transformation of the disabled value.

Evidence:

- `results/integration-native-cli-restart-attempt1.log`: original missing-genesis
  panic reproduced on a fresh native Common fixture.
- `results/integration-native-cli-restart-diagnostic.log`: key/transaction genesis
  initially present; entire chaindata absent after shutdown, before DEX probe.
- `results/integration-native-cli-restart-fixed-attempt1.log`: native restart
  passed7.95s and preserved both mappings. The separately added DEX-OFF fixture
  initially failed its genesis commitment check because its test constructor
  omitted recalculation after replacing committee endpoints; that fixture error
  is retained and was corrected without changing the commitment rule.
- `results/integration-native-cli-restart-fixed.log`: both final restart cases
  passed (DEX OFF7.29s, native ON7.58s, package14.926s), preserving closed key0/tx0
  mappings before and after the recipient probe and across the same-data restart.
- `results/integration-trie-journal-cli.log` and `integration-trie-journal-eth.log`:
  post-fix ordinary CLI eight roles, native smoke and both restart cases passed
  together in54.756s; the full eth package regression passed in19.897s. The eth
  suite reports three skips for subprocess helpers and the explicit role opt-in;
  role coverage is recorded separately in the preceding final role run. A fresh normal binary
  also built successfully; source hashes and binary hash are in
  `results/integration-trie-journal-metadata.json`.

The earlier eight-role CLI tests verified role lifecycle and shutdown but did not
reopen the Common database. Their PASS does not establish restart durability.
The new DEX-OFF test starts the ordinary CLI twice on the same directory with
DEX/mining disabled, checking both closed genesis mappings each time. The native
test also runs the rejected recipient probe, then restarts with identical CLI
arguments and existing datadir, without a second `init`.
