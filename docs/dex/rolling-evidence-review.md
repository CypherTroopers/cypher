# G1 rolling CLX evidence verifier

This records the isolated verifier gate, not an actual network's continuous run.
The format and trust boundary are specified in [rolling-anchor-spec.md](rolling-anchor-spec.md).

`scripts/dex/rolling_anchor_golden.py` produced the two fixed 246-byte anchor
encodings, domain-separated IDs, and the RLPv2 codec-only vector before the Go
implementation. `--check` passes. Codec acceptance of the fake proof in the
codec-only vector is explicitly not MPT authentication.

`dex/clxevidence/rolling.go` adds trusted-parent continuity, exact header/ref/
SignInfo binding, actual 5/7 source QC verification, and the existing descendant
finality rule. It retains the static authenticated source committee and key
epoch; a request cannot register another one. Every supplied header requires
finality, and a target QC by itself is rejected. A compact ref's signed body
commitment attests to that body; the verifier does not reexecute it. The local
builder requires a finalized source block and enforces the existing 1 MiB
source-block bound before deriving the ref. Target and descendant refs also
retain the 1 MiB signed `BodySize` bound.

`VerifyRolling` takes its base from authenticated parent state. An `Anchor`
decoded from a request is not a capability. Ingress `VerifyRollingPayload`
authenticates nonempty header signatures and target MPT paths, but does not
authorize connection to the requested base. Its zero-header path only checks
shape and entry identity; execution still needs the trusted anchor's root.
Same-anchor ranges return a verified range with `Header() == nil`, because a
246-byte anchor cannot reconstruct the original full header. The separately
returned anchor carries the authenticated height/hash/root.

The v1 full-body API retains its codec and verification semantics. The only
shared change is extracting the existing MPT verification into a private helper.

Executed gate:

- [JSONL](results/continuous-g1-evidence-unit.jsonl): full `./dex/clxevidence`
  with `-race`, 17 top-level tests, 131 PASS events, zero FAIL/SKIP, package
  elapsed 10.892 seconds.
- [Metadata](results/continuous-g1-evidence-unit-metadata.json): exact command,
  Go settings, fresh loopback-only namespace, log SHA256, and no Go source
  changes between the captured manifests.
- The tests cover independent goldens; codec/collection/byte limits; exact
  header, ref and SignInfo corruption; missing finality; signed detached fork;
  terminal view gap; source identity/epoch mismatch; partial/corrupt/duplicate
  MPT paths; cursor/domain/amount changes; same-anchor count conflicts;
  same-anchor deferred credit; and the unchanged v1 suite.
- The separate financial tests use real BLS signatures and actual StateDB MPT
  roots over a 258-height unit-generated chain, including deposit changes after
  heights 64 and 257 and cold reexecution. See
  [rolling-financial-review.md](rolling-financial-review.md) for their scope.

This gate does not establish actual process-network progress beyond height 257,
normal RPC relaying, physical power-cut durability, or production safety.
Those require their own run records. Resource-limited normal PoW nonce search
remains NOT_RUN.
