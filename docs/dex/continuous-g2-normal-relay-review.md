# G2 normal CLI relay gate

`TestFHSNativeContinuousRelayShort` passed in73.31s using separately built
normal `cypher` commands in a fresh loopback-only user/network namespace.
`continuous-g2-normal-relay-short-2.log` is the complete unedited result; binary
SHA256 values are in `continuous-g2-normal-relay-short-binaries.sha256`.
Trial1 failed before network initialization because the standalone test binary
was launched outside its Go package directory (`../genesis.json` was absent).
Trial2 used the required `reconfig` cwd. This was a runner error, not a protocol
regression. Old logs contain raw Hash/Address formatting; subsequent source
uses `.Hex()` for readable identifiers.

The successful run used seven independent CLX processes, an ordinary Common
RPC/proof source following the actual ETH protocol, six normal Common parents
with their own DEX sidecars, and two independent normal relay CLI processes.
The seventh DEX key was registered but never activated. Test control submitted
four native funding TXs and signed market actions; it supplied no CDXA proof,
native checkpoint call, claim call, chain import or state repair.

Observed financial path: trader100 + trader100 + support20 + insurance5 were
finalized at real CLX heights1/3/5/7. The relays fetched authenticated CLX finality
and MPT evidence over ordinary Common HTTP, submitted CDXA, then the signed
price/withdrawal/Noop actions produced DEX checkpoints1..3. Native relay work
included two anchor submissions, three distinct accepted checkpoints plus one
exact replay, one withdrawal claim plus one exact replay. The last native head
was22 and the next unused DEX action height was5. The unique withdrawal paid10
CLX exactly once; custody225 became215. Final buckets were trader190, support20,
insurance5 and zero unconsumed/fees/dust/withdrawals/rewards.

The independent observer checked every canonical TX, wallet nonce, all seven
receipts, state root, header gas, native bucket movement, existing Common20%
gas reward and burn. Total gas cost was0.121500576 CLX, Common reward
0.0243001152 and burn0.0972004608, paid only by the actual user/relay gas accounts.
CLX engine instance/action/inbox metrics remained0/0/0. The source followed
height22 through ordinary ETH. Largest native calldata was14,360 bytes with
seven source headers and1,239 MPT bytes; existing limits were unchanged.

One relay had observed the claim's business completion but still reported
`completed_pending_nonce` when stopped: the other relay had already paid the
claim and its own duplicate finalized at CLX22. The independent canonical
observer verified that nonce consumption and idempotent receipt. This limited
short test did not demonstrate journal observation reaching `complete` after
that final duplicate; the long scenario explicitly waits for both relays to
consume authenticated nonce observations before its final shutdown.

The long>=257-height scenario, late seventh-validator bootstrap, multi-period
rewards, cold DEX absence beyond64 heights, CLX outage and independent DEX-OFF
Common restart are separate G3 gates, not outcomes of this short test. Later
source changes (readable logging, parent ETH connections and relay hardening)
require the final runner's source-manifest-controlled regression pass.
