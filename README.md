P1
<img width="1125" height="766" alt="image" src="https://github.com/user-attachments/assets/d3756e28-600d-4069-85a6-c5edb1447fe4" />
P2
<img width="1125" height="220" alt="image" src="https://github.com/user-attachments/assets/769b629a-b101-424d-930d-ac442529262b" />
P3
<img width="1125" height="310" alt="image" src="https://github.com/user-attachments/assets/b8133a8f-97fa-4ac3-80b6-9487bcad20be" />
P4
<img width="1125" height="1789" alt="image" src="https://github.com/user-attachments/assets/c04b21af-04c3-499e-a6c5-41a83fd3e9bc" />


## Dual HotStuff Consensus Architecture

This branch introduces a two-layer consensus architecture that combines:

* the main Validator HotStuff, where the Validator Committee makes the final decision; and
* the Common Approval HotStuff, where the Common Miner Committee pre-approves TxBlocks.

In other words, the Common Committee acts as the TxBlock approval layer, while the Validator Committee remains the finalization layer.

Transaction Flow

1. A user sends a transaction.
2. The Validator leader creates a TxBlock.
3. The TxBlock is sent to the Common Approval Committee.
4. The Common Committee signs and approves the TxBlock using a HotStuff-style approval process.
5. A Common Approval proof is attached to the TxBlock.
6. Validator HotStuff verifies the TxBlock and its Common Approval proof.
7. The Validator Committee finalizes the block.

This design adds a TxBlock approval committee formed by Common Miners on top of the traditional Validator Committee HotStuff finalization.

The Validator Committee is responsible for the final safety and finalization of the network. The Common Committee provides a pre-approval proof for TxBlocks before they are finalized by validators.

The Common Committee members are recorded as a snapshot inside each KeyBlock. Because of this, every node can verify TxBlocks using the same committee information. This prevents committee mismatch between nodes and keeps TxBlock verification deterministic.

This creates a Dual HotStuff structure where validator stability is preserved, while Common Miners can also participate in the block approval process.

## Validator Committee

* 1 leader + 6 committee members
* Fixed committee members
* Leader fallback support
* 1 KeyBlock every 10 minutes
* KeyBlock reward: 100,000 coins

## Common Committee

* 1 leader + 6 committee members
* Index 0 is always active as the fallback Common node
* Reward per TxBlock approval: 1,000 coins
* Committee members are dynamically selected every 10 minutes from healthy Common Miners
* Selection is based on good Common Miner status, such as availability, connectivity, and participation

## Simple Analogy

* Validator Committee = the headquarters that gives the final approval
* Common Committee = the field team that checks the block first
* KeyBlock = the team roster for that period
* TxBlock = the actual transaction block
* Common Approval Proof = the field team’s approval stamp


## Common Approval rewards are paid only to the committee members whose signatures are included in the approval mask

If the normal threshold is reached within the collection window, all signers(MAX7 commmon commitee) included in the mask receive the TxBlock approval reward.

If the normal threshold is not reached within 100ms, the current Common Committee leader may create a fallback approval with its own signature. In that case, only the leader receives the TxBlock approval reward.

If the Common leader is unavailable, the bootstrap approver at index 0 can be used as an emergency fallback. In that case, only the bootstrap approver receives the reward.

