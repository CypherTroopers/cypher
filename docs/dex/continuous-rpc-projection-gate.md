# Continuous Common RPC observation gate

Trial14 reached CLX754, DEX finalized/CLX accepted109, all72 payments,
custody295CLX and both relay journals freshly authenticated (410 jobs total).
It then failed the existing Common parent RPC comparison. That failure remains
FAIL; the subsequent late DEX OFF Common sync/restart gate was not executed.

The old test decoded `RPCMarshalHeader` into `types.Header` and recomputed its
hash. The RPC projection omits Common admission/reward commitments and KeyInfo;
it can also normalize baseFee. It is not the complete canonical hash preimage.
An isolated overlay test using the real RPC marshaler reproduces a different
recomputed hash while the explicit RPC hash, state root and gas are correct.
Trial14 did not retain its raw parent RPC response, so its individual differing
field cannot be recovered from that run's generic failure message.

The test now requires explicit RPC hash, number, parentHash, stateRoot,
transactionsRoot, receiptsRoot and gasUsed and compares them with an already
canonical block from the independently synchronized source. Missing/null fields
and modified values fail, including on zero-gas blocks. This projection is only
a consistency observation, never CLX finality or a replacement for header/FHS
authentication. All transaction receipt comparisons remain. No production RPC,
header encoding, source proof, consensus or synchronization behavior changes.

The short ordinary ETH source test exercises the projection after its existing
six deposits. Its fixture peer capacity becomes two (CLX source and late Common).
It stops only its seven owned CLX producers, observes a stable source head and
calls the unchanged late DEX OFF Common full block/receipt/native-state sync and
same-DB restart gate. It does not import blocks or repair peer heads itself.
Neither the 65/75-second sync bounds nor the long-run 45-minute/120-second bounds
change. Projection and late-sync success in this short gate does not retroactively
turn Trial14 or the full long-run requirement into PASS.
