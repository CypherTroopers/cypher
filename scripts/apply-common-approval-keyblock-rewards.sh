#!/usr/bin/env bash
set -euo pipefail

KEYBLOCK_GO="reconfig/keyblock.go"
CONSENSUS_GO="consensus/colossusX/consensus.go"

if [[ ! -f "$KEYBLOCK_GO" || ! -f "$CONSENSUS_GO" ]]; then
  echo "Run this script from repository root" >&2
  exit 1
fi

python3 - <<'PY'
from pathlib import Path

keyblock = Path("reconfig/keyblock.go")
text = keyblock.read_text()

# Verify reward summary on received keyblocks.
old = '''	if err := verifyKeyBlockMinInterval(keyblock, curKeyblock); err != nil {
			return err
		}
		return nil
	}'''
new = '''	if err := verifyKeyBlockMinInterval(keyblock, curKeyblock); err != nil {
			return err
		}
		if err := keyS.verifyCommonApprovalRewardSummary(keyblock, curKeyblock.T_Number()+1, keyblock.T_Number()); err != nil {
			return err
		}
		return nil
	}'''
if old in text and new not in text:
    text = text.replace(old, new, 1)

old = '''	if !keyblock.TypeCheck(kbc.CurrentBlock().T_Number()) {
		return fmt.Errorf("verifyKeyBlock, check failed, current keynumber:%d,keyblock T_Number:%d", kbc.CurrentBlockN(), keyblock.T_Number())
	}

	keyType := keyblock.BlockType()'''
new = '''	if !keyblock.TypeCheck(kbc.CurrentBlock().T_Number()) {
		return fmt.Errorf("verifyKeyBlock, check failed, current keynumber:%d,keyblock T_Number:%d", kbc.CurrentBlockN(), keyblock.T_Number())
	}
	if err := keyS.verifyCommonApprovalRewardSummary(keyblock, curKeyblock.T_Number()+1, keyblock.T_Number()); err != nil {
		return err
	}

	keyType := keyblock.BlockType()'''
if old in text and new not in text:
    text = text.replace(old, new, 1)

# Attach reward summary when proposing a KeyBlock.
old = '''	keyblock := types.NewKeyBlock(header)
	keyblock = keyblock.WithBody(mb.In().Public, mb.In().CoinBase, outerPublic, outerCoinBase, mb.Leader().Public, mb.Leader().CoinBase)
	log.Info("tryProposalChangeCommittee", "committeeHash", header.CommitteeHash, "leader", keyblock.LeaderPubKey(), "outerCoinBase", outerCoinBase)'''
new = '''	keyblock := types.NewKeyBlock(header)
	keyblock = keyblock.WithBody(mb.In().Public, mb.In().CoinBase, outerPublic, outerCoinBase, mb.Leader().Public, mb.Leader().CoinBase)
	if rewards, err := keyS.buildCommonApprovalRewardSummary(curKeyBlock.T_Number()+1, header.T_Number); err != nil {
		return nil, nil, nil, err
	} else {
		keyblock.SetCommonApprovalRewards(rewards)
		log.Info("common approval reward summary attached", "keyBlock", header.Number.Uint64(), "fromTx", curKeyBlock.T_Number()+1, "toTx", header.T_Number, "rewards", rewards)
	}
	log.Info("tryProposalChangeCommittee", "committeeHash", header.CommitteeHash, "leader", keyblock.LeaderPubKey(), "outerCoinBase", outerCoinBase)'''
if old in text and new not in text:
    text = text.replace(old, new, 1)

keyblock.write_text(text)

consensus = Path("consensus/colossusX/consensus.go")
text = consensus.read_text()

# IMPORTANT: undo the previous unsafe wiring. ApplyKeyblockPowRewardByKeyInfo can
# be reached from tx-block verification paths, so CommonApproval signer rewards
# must not be added there.
unsafe = '''	keyblock := types.DecodeToKeyBlock(keyInfo)
	ApplyKeyblockPowReward(state, keyblock)
	ApplyCommonApprovalSignerRewards(state, keyblock)
}'''
safe = '''	keyblock := types.DecodeToKeyBlock(keyInfo)
	ApplyKeyblockPowReward(state, keyblock)
}'''
if unsafe in text:
    text = text.replace(unsafe, safe, 1)

# Apply CommonApproval signer rewards only inside the explicit Key_Block
# finalization branches, reading the KeyBlock reward summary already embedded in
# header.KeyInfo. This keeps tx-block verification roots unchanged.
old = '''	if header.BlockType == types.Key_Block {
		ApplyKeyblockPowRewardByKeyInfo(state, header.KeyInfo)
	}'''
new = '''	if header.BlockType == types.Key_Block {
		ApplyKeyblockPowRewardByKeyInfo(state, header.KeyInfo)
		keyblock := types.DecodeToKeyBlock(header.KeyInfo)
		ApplyCommonApprovalSignerRewards(state, keyblock)
	}'''
if old in text and new not in text:
    text = text.replace(old, new, 2)

consensus.write_text(text)
PY

gofmt -w "$KEYBLOCK_GO" "$CONSENSUS_GO" reconfig/common_approval_rewards.go consensus/colossusX/rewards.go core/types/keyblock.go

echo "CommonApproval KeyBlock reward wiring applied safely."
