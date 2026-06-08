Validators and Common Miners

Overview

Validator nodes are responsible for consensus and finality.

They create blocks, verify blocks, run HotStuff, and decide the final state of the chain.

Validator RPC endpoints do not need to be public. Validators can focus only on block production, verification, and finalization.

Common miners are responsible for public RPC access and transaction admission.

Users send transactions to common miner RPC endpoints. The common miner accepts the transaction, creates a signed CommonTxAdmission record, and relays it to the validator leader.

Common miners do not replace validator consensus. They add a public transaction admission layer in front of the validator network.

Simple Difference

Validators finalize blocks.

Common miners receive user transactions through public RPC and prove that they admitted them.

Common RPC Reward Rule

When a transaction admitted by a common miner is included in a finalized block, the actual transaction fee is split:

20% → common RPC miner reward
80% → burned

The actual transaction fee is calculated from the real execution result:

actualTxFee = gasUsed × effectiveGasPrice
commonRpcReward = actualTxFee / 5
commonRpcBurn = actualTxFee - commonRpcReward

The validator verifies the reward values during state processing.

If the CommonTxReward does not match the actual gas used and effective gas price, the block is rejected.

Example

For a normal transfer:

gasUsed = 21000
effectiveGasPrice = 1,000,000,000 wei

Total transaction fee:

21000 × 1,000,000,000
= 21,000,000,000,000 wei
= 0.000021 CPH

Common miner reward:

20% = 4,200,000,000,000 wei
    = 0.0000042 CPH

Burn:

80% = 16,800,000,000,000 wei
    = 0.0000168 CPH

RPC Output

Common RPC admission and reward information can be checked through:

eth_getTransactionReceipt
eth_getTransactionByHash

JavaScript console equivalents:

eth.getTransactionReceipt(txHash)
eth.getTransaction(txHash)

Main additional fields:

commonRpcMiner
commonRpcReward
commonRpcBurn
commonTxAdmissionRoot
commonTxRewardRoot
commonTxAdmissionChainId
commonTxAdmissionKeyBlockNumber
commonTxAdmissionTxBlockNumber
commonTxAdmissionTimestamp
commonTxAdmissionSignature

Test Commands

Set RPC endpoint and transaction hash:

RPC_URL="http://167.86.76.166:8000"
TX_HASH="0x372a90af5f5c688699d435997859a87698125c4d356b72ff7d69ae1a65652073"

Check transaction receipt:

curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$TX_HASH\"],\"id\":1}" | jq

Check transaction details:
'''
curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\":[\"$TX_HASH\"],\"id\":1}" | jq
'''
Check common miner balance: ```
MINER_ADDR="0x946d4abb364716fd2f8403df28fa4f2b5e953d62"
curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$MINER_ADDR\",\"latest\"],\"id\":1}" | jq
 ```
For one normal transfer with gasUsed = 21000 and effectiveGasPrice = 1 gwei, the expected common miner balance increase is:

4,200,000,000,000 wei
= 0.0000042 CPH

Notes

This feature does not make common miners validator consensus members.

Common miners only provide public RPC transaction admission and receive a fee share when their admitted transaction is included in a finalized block.

Validators still verify all admission records, reward records, roots, signatures, chain ID, and final state before accepting the block.
