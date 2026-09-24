# Fixed-membership key renewal: component validation

The authenticated continuation component passed its final full race run:
45 top-level tests, 243 PASS events, zero FAIL and zero SKIP. Package times
were `dex/clxevidence` 87.202s and `dex/relay/source` 1.098s. See
[raw JSONL](continuous-g3-key-renewal-final-race.jsonl) and
[metadata](continuous-g3-key-renewal-metadata.json). The recorded owned-source
pre/post manifests have zero differences; their limited scope is listed in the
metadata rather than claimed to cover every transitive dependency.

This run uses unit-generated real BLS signatures over CLX codecs, actual StateDB
MPT paths and real HTTP sockets confined to a fresh loopback-only network
namespace. It does not establish the result of the separate actual CLX/DEX/relay
long-run process gate. The source emits no native transaction by itself.

The new regression coverage includes:

- Independent Python anchor246/anchor286, boundary-ID and RLPv2/v3/v4 codec
  bytes; unchanged v1 JSON fields/order and strict nested unknown-field rejection.
- Three certified renewals through height260, including nonzero-PRF leader
  permutations of the same seven identities and restart at pending boundaries.
- Validly signed old-key children after expiry, a different old-key semantic QC
  during the boundary and an early new-key child. Each negative fixture's QC
  signatures are verified first to distinguish lifetime rejection from signature
  corruption. Current/previous header and order mutations are rejected.
- Same-anchor later inbox credit, historical130→131 continuation and cold source
  WAL revalidation. An old RLPv3 pending WAL stays v3 until it clears; it is not
  partially converted into v4 without its previous-key preimages.
- Shared immutable Verifier legacy/v4 Go race regression, public helper rejection
  of a nonempty v2 continuation without its key context, and preservation of the
  bounded source/planner/MPT regressions in both packages.

The component run preceding the final lifetime-negative additions is retained
in [component JSONL](continuous-g3-key-renewal-component-race.jsonl). The first
namespace attempt failed with sandbox `unshare` EPERM before starting a test;
[attempt1](continuous-g3-key-renewal-namespace-attempt1.log) is retained. The
subsequent approved invocation used the same fresh isolated-network procedure.
During fixture development, a skipped view required a two-descendant finality
proof, and zero-time genesis permitted timestamp601; the negative fixture was
corrected to599. These fixture failures did not relax a production rule.

No operational datadir, genesis, process, funds or distributed binary was
modified. No remote push occurred. Source is frozen for the actual long-run
trial. Public membership changes and PoW reward-candidate-bearing key renewals
remain explicitly unsupported; ordinary PoW nonce search was NOT_RUN because
of its previously recorded resource requirements. This limitation does not make
PoW a prerequisite for DEX participation.
