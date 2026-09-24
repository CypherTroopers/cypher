# Fixed-committee key renewal at the G3 boundary

The failed G3 attempt's source WAL was independently reverified from its trusted
genesis:164 segments through CLX255. The
[offline audit log](results/continuous-g3-key-renewal-audit.log),
[reproduction source](results/continuous-g3-key-renewal-audit.go.txt) and
[input digests](results/continuous-g3-key-renewal-audit-metadata.json) preserve
the evidence. Only the public archived manifest's CLX configuration and source
WAL were read; no process, node database or operational data was changed.

CLX255 is a key carrier. Its authenticated473-byte `Header.KeyInfo` creates
keyblock1 `230fb38cd269a5cf9c18cf5ea43a6aa13f7c74fc5e4b344f7a58afa3b28b274f`,
whose parent is the genesis key
`f1b6085cf9ce1fa93489eeaa29814181c716672aa66ab56c5bfaa3e9bf279bd2`.
Its transaction parent is254, and its scheduled time is
2026-09-22T11:40:45Z. The carrier's complete finality proof contains its direct
old-key child256, with consecutive views255/256. The existing deterministic
`Committee.Add(nil,0,"")` transformation reproduces the exact same ordered
committee hash `937847a52940693de71a5c729e5866538478062099c10a7431197fa8ef92524f`.
There is no incoming new member or reward PoW candidate in this carrier.

This is the existing ten-minute fixed-committee keyblock cadence, not a new
public membership epoch and not a numerical256-block cap. Source evidence is
currently configured with only the exact genesis key hash. Its refusal of an
unknown later key is correct; weakening that check would not be a fix. The
archive directly proves the carrier and old child256. That block256's finality
needs a later new-key descendant is inferred from the subsequent authentication
failure and CLX progress logs; a complete header257 was not retained in this
public archive and is not presented as independently reverified here.

Relevant source boundaries:

* `params/protocol_params.go:62`: ten-minute keyblock cadence.
* `reconfig/keyblock.go:157`: deterministic parent-time cadence and zero-time
  genesis bootstrap exception; `:531` constructs the next key header; `:609`
  applies the existing in-committee transformation.
* `reconfig/txblock.go:2615`: fixed mode still schedules key proposals.
* `reconfig/fhs_key_activation_proof.go:13`: activation requires the complete
  old-key descendant chain and consecutive terminal views.
* `core/fhs_commit_proof.go:176`: after activation, an old-key QC is accepted
  only when it is an exact authenticated activation descendant, rather than
  through a general height or time grace period.
* `dex/clxevidence/finality.go:120`: the current static verifier requires an
  exact authorized historical key hash and interval.

Required extension: retain an authenticated current source-key context in each
new anchor, including only the bounded still-pending old activation QC IDs.
Authenticate each new carrier under the previous key and require the exact
same ordered fixed committee. Process long lags through multiple short ranges;
do not attach a growing genesis-to-current key history to every update. The
old246-byte anchor and proof codecs must keep their original interpretation.
Unknown membership/order changes remain explicit failures. The implementation
must include genuine old/new boundary, altered carrier/key body, missing or
single QC, wrong parent, restart and repeated-renewal tests before the long G3
network gate is rerun.
