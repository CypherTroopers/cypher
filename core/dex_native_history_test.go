package core

import (
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/settlement"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func nativeHistoryFixtureProof(t *testing.T, cp protocol.Checkpoint, keys []bls.SecretKey, members []*common.Cnode) []byte {
	t.Helper()
	var frontier protocol.HistoryFrontier
	var ids []protocol.Hash
	var qcs []*hotstuff.SignedState
	for height := uint64(1); height <= 21; height++ {
		if height > 1 {
			id, _ := hotstuff.SignedStateID(qcs[len(qcs)-1])
			ids = append(ids, protocol.Hash(id.Hash()))
			if err := frontier.AppendQCID(ids[len(ids)-1]); err != nil {
				t.Fatal(err)
			}
		}
		root, err := frontier.Root()
		if err != nil {
			t.Fatal(err)
		}
		data, err := protocol.HistoryDataRoot(protocol.Hash{21, byte(height)}, root, frontier.Count)
		if err != nil {
			t.Fatal(err)
		}
		view := height*2 - 1
		if height == 21 {
			view--
		}
		ref := &types.HotstuffProposalRef{Version: types.HotstuffProposalRefVersion, ChainID: cp.ChainID, Number: height, ViewNumber: view, ViewID: common.Hash{byte(view), 57}, LeaderID: bftview.GetNodeID(members[(view-1)%7].Address, members[(view-1)%7].Public), BlockHash: common.Hash{52, byte(height)}, ParentHash: common.Hash{53}, StateRoot: common.Hash(cp.PostRoot), BodyHash: common.Hash(data), BodySize: 8, ExtraHash: types.HotstuffProposalExtraHash(nil), KeyHash: common.Hash(cp.Domain().EpochKey()), Time: height}
		if height == 1 {
			hash, err := cp.Hash()
			if err != nil {
				t.Fatal(err)
			}
			ref.BlockHash = common.Hash(hash)
			ref.BodyHash = common.Hash(cp.DataRoot)
		} else {
			parent, _ := types.DecodeHotstuffProposalRef(qcs[len(qcs)-1].State)
			ref.ParentHash = parent.BlockHash
			ref.ParentQCID = common.Hash(ids[len(ids)-1])
		}
		qcs = append(qcs, nativeRollbackQC(t, keys, ref))
	}
	path, err := protocol.BuildHistoryProof(ids[:19], 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := checkpoint.EncodeProofV2(checkpoint.Proof{Target: qcs[0], Descendants: []*hotstuff.SignedState{qcs[19], qcs[20]}, History: &checkpoint.HistoryWitness{Count: 19, ActionRoot: protocol.Hash{21, 20}, Siblings: path}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Signed normal CLX transactions execute through ApplyTransaction and EVM. The
// registered fixture keys make genuine FHS/MPT proofs; this is UNIT, not LIVE or
// a substitute for replaying the DEX financial engine in its separate domain.
func TestDEXNativeHistorySignedTXCheckpointClaimReplayAndGas(t *testing.T) {
	f := newNativeTXVersionFixture(t, 0, 5)
	initial := new(big.Int).Set(f.st.GetBalance(f.sender))
	chain, legacyCall, claim := nativeRollbackCheckpoint(t, f)
	call, err := protocol.DecodeNativeCall(legacyCall)
	if err != nil {
		t.Fatal(err)
	}
	cp, finance, _, _, err := protocol.DecodeNativeCheckpoint(call.Body)
	if err != nil {
		t.Fatal(err)
	}
	cp.DataSchema = 6
	empty, err := (protocol.HistoryFrontier{}).Root()
	if err != nil {
		t.Fatal(err)
	}
	cp.DataRoot, err = protocol.HistoryDataRoot(protocol.Hash{21, 1}, empty, 0)
	if err != nil {
		t.Fatal(err)
	}
	var keys []bls.SecretKey
	var members []*common.Cnode
	for i := 0; i < 7; i++ {
		var key bls.SecretKey
		if err := key.SetDecString(fmt.Sprint(801 + i)); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
		node := f.config.GenCommittee[i]
		members = append(members, &node)
	}
	proof := nativeHistoryFixtureProof(t, cp, keys, members)
	verifier, err := clxevidence.New(clxevidence.Config{ChainID: f.config.ChainID.Uint64(), Genesis: f.chain.genesis.Header(), ChainConfig: f.config, Seed: f.config.FairHotstuffSeed, DEXID: cp.DEXID, Custody: params.DEXSettlementAddress, Epochs: []clxevidence.CommitteeEpoch{{First: 1, End: ^uint64(0), KeyHash: chain.key, Members: members}}})
	if err != nil {
		t.Fatal(err)
	}
	base, err := verifier.BootstrapAnchor()
	if err != nil {
		t.Fatal(err)
	}
	baseID, err := base.ID()
	if err != nil {
		t.Fatal(err)
	}
	witness, err := clxevidence.BuildHeaderWitness(f.config.ChainID.Uint64(), chain.anchor)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := clxevidence.BuildRollingEvidence(baseID, []clxevidence.HeaderWitness{witness}, f.st, nil, params.DEXSettlementAddress)
	if err != nil {
		t.Fatal(err)
	}
	anchorCall, err := settlement.EncodeNativeAnchorUpdate(evidence, nil)
	if err != nil {
		t.Fatal(err)
	}
	gasCost := new(big.Int).Sub(initial, f.st.GetBalance(f.sender))
	gasCost.Sub(gasCost, big.NewInt(100))
	apply := func(raw []byte, gas uint64, success bool) *types.Receipt {
		t.Helper()
		nonce := f.st.GetNonce(f.sender)
		tx := f.tx(t, nonce, new(big.Int), gas, raw)
		f.st.Prepare(tx.Hash(), common.Hash{111}, int(nonce))
		var used uint64
		author := common.Address{33}
		receipt, err := ApplyTransaction(f.config, chain, &author, new(GasPool).AddGas(f.header.GasLimit), f.st, f.header, tx, &used, vm.Config{})
		if err != nil || receipt == nil || (receipt.Status == types.ReceiptStatusSuccessful) != success || receipt.GasUsed <= params.TxGas || f.st.GetNonce(f.sender) != nonce+1 {
			t.Fatal("signed native result/nonce/gas", receipt, err)
		}
		gasCost.Add(gasCost, new(big.Int).Mul(new(big.Int).SetUint64(receipt.GasUsed), tx.GasPrice()))
		return receipt
	}
	apply(anchorCall, 16000000, true)
	rolling, err := settlement.ReadNativeRollingStatus(f.st, params.DEXSettlementAddress)
	if err != nil || rolling.ConfirmedThrough != 1 {
		t.Fatal("normal TX did not confirm sourceanchor", rolling, err)
	}
	badProof, err := checkpoint.DecodeProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	badProof.History.Siblings[0][0] ^= 1
	badEncoded, err := checkpoint.EncodeProofV2(badProof)
	if err != nil {
		t.Fatal(err)
	}
	badCall, err := protocol.EncodeNativeCheckpoint(cp, finance, badEncoded, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, buckets, surplus, err := settlement.NativeStatus(f.st, params.DEXSettlementAddress)
	if err != nil {
		t.Fatal(err)
	}
	badReceipt := apply(badCall, 16000000, false)
	after, bucketsAfter, surplusAfter, err := settlement.NativeStatus(f.st, params.DEXSettlementAddress)
	if err != nil || before != after || !reflect.DeepEqual(buckets, bucketsAfter) || surplus != surplusAfter || len(badReceipt.Logs) != 0 || f.st.GetBalance(params.DEXSettlementAddress).Cmp(big.NewInt(100)) != 0 {
		t.Fatal("bad ancestry moved native funds/reservations", err)
	}
	cpCall, err := protocol.EncodeNativeCheckpoint(cp, finance, proof, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The compact certificate still pays the regular bounded native gas. OOG
	// consumes the signed TX nonce/gas but cannot leave an inbox/reserve write.
	oogReceipt := apply(cpCall, 1000000, false)
	after, bucketsAfter, surplusAfter, err = settlement.NativeStatus(f.st, params.DEXSettlementAddress)
	if err != nil || before != after || !reflect.DeepEqual(buckets, bucketsAfter) || surplus != surplusAfter || len(oogReceipt.Logs) != 0 || oogReceipt.GasUsed != 1000000 {
		t.Fatal("checkpoint OOG retained settlement state", err)
	}
	receipt := apply(cpCall, 16000000, true)
	if len(receipt.Logs) != 1 || receipt.Logs[0].Topics[0] != settlement.NativeCheckpointTopic {
		t.Fatal("checkpoint receipt")
	}
	apply(cpCall, 16000000, true)
	status, buckets, _, err := settlement.NativeStatus(f.st, params.DEXSettlementAddress)
	if err != nil || status.Sequence != 1 || status.InboxCursor != 1 || buckets[settlement.Trader].Big().Cmp(big.NewInt(90)) != 0 || buckets[settlement.Withdrawals].Big().Cmp(big.NewInt(10)) != 0 {
		t.Fatal("native checkpoint/replay accounting", err)
	}
	claimCall, err := protocol.EncodeNativeClaim(claim, 0, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	apply(claimCall, 600000, true)
	root, err := f.st.Commit(true)
	if err != nil {
		t.Fatal(err)
	}
	db := f.st.Database()
	if err = db.TrieDB().Commit(root, false, nil); err != nil {
		t.Fatal(err)
	}
	f.st, err = state.New(root, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	apply(claimCall, 600000, true)
	status, buckets, _, err = settlement.NativeStatus(f.st, params.DEXSettlementAddress)
	if err != nil || status.Sequence != 1 || buckets[settlement.Withdrawals] != (protocol.Amount{}) || f.st.GetBalance(common.Address(claim.Recipient)).Cmp(big.NewInt(10)) != 0 || f.st.GetBalance(params.DEXSettlementAddress).Cmp(big.NewInt(90)) != 0 {
		t.Fatal("claim cold replay paid twice", err)
	}
	wantSender := new(big.Int).Sub(initial, big.NewInt(100))
	wantSender.Sub(wantSender, gasCost)
	if f.st.GetBalance(f.sender).Cmp(wantSender) != 0 {
		t.Fatal("normal nonce/gas debits differ from receipts")
	}
	t.Logf("signed native schema6 TXs: deposit100, custody90, claim10; bad proof reverted; duplicate checkpoint/claim +cold reopen did not pay twice; proof bytes=%d; sender gas cost=%s", len(proof), gasCost)
}
