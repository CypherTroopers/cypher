#!/usr/bin/env bash
set -euo pipefail

KEYBLOCK_GO="reconfig/keyblock.go"
TXBLOCK_GO="reconfig/txblock.go"
CONSENSUS_GO="consensus/colossusX/consensus.go"

if [[ ! -f "$KEYBLOCK_GO" || ! -f "$TXBLOCK_GO" || ! -f "$CONSENSUS_GO" ]]; then
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

# The Key_Block tx-block proposal path builds its root manually, without going
# through consensus.FinalizeAndAssemble. It must therefore apply exactly the same
# CommonApproval signer reward as validators apply during verification.
txblock = Path("reconfig/txblock.go")
text = txblock.read_text()
old = '''	colossusX.AccumulateRewards(txS.bc.Config(), work.publicState, header, nil)
	colossusX.ApplyKeyblockPowReward(work.publicState, keyblock)
	header.Root = work.publicState.IntermediateRoot(false)'''
new = '''	colossusX.AccumulateRewards(txS.bc.Config(), work.publicState, header, nil)
	colossusX.ApplyKeyblockPowReward(work.publicState, keyblock)
	colossusX.ApplyCommonApprovalSignerRewards(work.publicState, keyblock)
	header.Root = work.publicState.IntermediateRoot(false)'''
if old in text and new not in text:
    text = text.replace(old, new, 1)
txblock.write_text(text)

consensus = Path("consensus/colossusX/consensus.go")
text = consensus.read_text()

# Keep ApplyKeyblockPowRewardByKeyInfo limited to legacy/common PoW reward only.
# It is used from existing paths and should not hide CommonApproval reward side effects.
unsafe_func = '''	keyblock := types.DecodeToKeyBlock(keyInfo)
	ApplyKeyblockPowReward(state, keyblock)
	ApplyCommonApprovalSignerRewards(state, keyblock)
}'''
safe_func = '''	keyblock := types.DecodeToKeyBlock(keyInfo)
	ApplyKeyblockPowReward(state, keyblock)
}'''
text = text.replace(unsafe_func, safe_func)

# Validators/importers verify Key_Block tx-blocks through consensus finalization.
# Match the proposal path above by applying CommonApproval signer rewards only in
# the explicit Key_Block branches.
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

gofmt -w "$KEYBLOCK_GO" "$TXBLOCK_GO" "$CONSENSUS_GO" reconfig/common_approval_rewards.go consensus/colossusX/rewards.go core/types/keyblock.go

echo "CommonApproval KeyBlock reward summary and payout wiring applied."
