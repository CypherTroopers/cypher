package core

import (
	"errors"
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
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/trie"
)

// These are real native signed-TX executions and real CLX/DEX QC + state-proof
// codecs. The unit fixture owns the seven registered keys; it is not a network
// finality experiment. No accepted checkpoint, entry or nullifier is injected.
type nativeRollbackChain struct {
	nativeTXChain
	anchor *types.Block
	key    common.Hash
}

func (c nativeRollbackChain) DEXGenesisKeyHash() common.Hash { return c.key }
func (c nativeRollbackChain) GetHeader(hash common.Hash, n uint64) *types.Header {
	if c.anchor != nil && n == c.anchor.NumberU64() && hash == c.anchor.Hash() {
		return c.anchor.Header()
	}
	return c.nativeTXChain.GetHeader(hash, n)
}

func nativeRollbackQC(t *testing.T, keys []bls.SecretKey, ref *types.HotstuffProposalRef) *hotstuff.SignedState {
	t.Helper()
	raw := ref.EncodeToBytes()
	var aggregate *bls.Sign
	for i := 0; i < 5; i++ {
		sig, err := hotstuff.SignFHSSignatureWithContext(&keys[i], keys[i].GetPublicKey(), raw, ref.ChainID, hotstuff.MsgVotePrepare, ref.ViewID, ref.LeaderID)
		if err != nil {
			t.Fatal(err)
		}
		if aggregate == nil {
			aggregate = sig
		} else {
			aggregate.Add(sig)
		}
	}
	return &hotstuff.SignedState{State: raw, Sign: aggregate.Serialize(), Mask: []byte{31}, ViewID: ref.ViewID, LeaderID: ref.LeaderID, Number: ref.ViewNumber}
}

func nativeRollbackCheckpoint(t *testing.T, f *nativeTXFixture) (nativeRollbackChain, []byte, protocol.Claim) {
	t.Helper()
	var keys []bls.SecretKey
	var members []*common.Cnode
	for i := 0; i < 7; i++ {
		var key bls.SecretKey
		if err := key.SetDecString(fmt.Sprint(801 + i)); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
		node := f.config.GenCommittee[i]
		if node.Public != key.GetPublicKey().SerializeToHexStr() {
			t.Fatal("native fixture key mismatch")
		}
		members = append(members, &node)
	}
	committee := (&bftview.Committee{List: members}).RlpHash()
	keyBlock := (&GenesisKey{Config: f.config, Difficulty: big.NewInt(1)}).ToBlock()
	chain := nativeRollbackChain{nativeTXChain: f.chain, key: keyBlock.Hash()}
	deposit, _ := (protocol.NativeCall{Operation: protocol.NativeDeposit}).Encode()
	tx := f.tx(t, 0, big.NewInt(100), 600000, deposit)
	receipt, err := f.apply(t, tx, vm.Config{})
	if err != nil || receipt == nil || receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatal("native deposit prerequisite", receipt, err)
	}
	entry, err := settlement.ReadNativeEntry(f.st, params.DEXSettlementAddress, 0)
	if err != nil {
		t.Fatal(err)
	}
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
	header := types.CopyHeader(f.header)
	header.Root, header.KeyHash, header.GasUsed = root, chain.key, receipt.GasUsed
	block := types.NewBlock(header, types.Transactions{tx}, nil, types.Receipts{receipt}, new(trie.Trie))
	leader := func(view uint64) string {
		index, err := clxevidence.LeaderIndex(f.config.FairHotstuffSeed, f.config.ChainID.Uint64(), view, committee)
		if err != nil {
			t.Fatal(err)
		}
		return bftview.GetNodeID(members[index].Address, members[index].Public)
	}
	ref, err := types.NewHotstuffProposalRefFromUnsignedBlockWithCommitments(f.config.ChainID.Uint64(), 1, common.Hash{1}, leader(1), block, types.HotstuffProposalExtraHash(nil), common.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	qc := nativeRollbackQC(t, keys, ref)
	block.SetFHSSignature(qc.Sign, qc.Mask, qc.ViewID, qc.LeaderID, qc.Number, ref.ExtraHash, ref.ParentQCID)
	child := *ref
	child.Number, child.ViewNumber, child.ViewID = 2, 2, common.Hash{2}
	child.ParentHash, child.BlockHash, child.LeaderID = ref.BlockHash, common.Hash{80}, leader(2)
	parentID, _ := hotstuff.SignedStateID(qc)
	child.ParentQCID = parentID.Hash()
	childQC, err := hotstuff.EncodeSignedState(nativeRollbackQC(t, keys, &child))
	if err != nil {
		t.Fatal(err)
	}
	finality, err := rlp.EncodeToBytes(struct {
		Version uint32
		QCs     [][]byte
	}{2, [][]byte{childQC}})
	if err != nil {
		t.Fatal(err)
	}
	if err = block.SetFHSFinalityProof(finality); err != nil {
		t.Fatal(err)
	}
	chain.anchor = block
	evidence, err := clxevidence.BuildRangeEvidence([][]byte{block.EncodeToBytes()}, f.st, []protocol.InboxEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	encodedEvidence, err := clxevidence.EncodeRangeEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	domain := protocol.Domain{Version: 1, ChainID: f.config.ChainID.Uint64(), Genesis: protocol.Hash(f.chain.genesis.Hash()), DEXID: protocol.Hash(f.config.DEXDevnet.DEXID), Epoch: 1, Committee: protocol.Hash(committee)}
	claim := protocol.Claim{Domain: domain, Sequence: 1, Kind: protocol.Withdrawal, ID: protocol.Hash{71}, Owner: [20]byte(f.sender), Recipient: [20]byte{19: 201}, Amount: protocol.Amount{31: 10}}
	leaf, err := claim.Hash()
	if err != nil {
		t.Fatal(err)
	}
	withdrawalRoot, _, err := protocol.BuildCountedTree([]protocol.Hash{leaf})
	if err != nil {
		t.Fatal(err)
	}
	status, _, _, err := settlement.NativeStatus(f.st, params.DEXSettlementAddress)
	if err != nil {
		t.Fatal(err)
	}
	inboxRoot, err := protocol.InboxEntriesRoot([]protocol.InboxEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	finance := protocol.FinanceSummary{Version: 1, Domain: domain, Custody: [20]byte(params.DEXSettlementAddress), Sequence: 1, DepositTotal: entry.Amount, WithdrawalTotal: claim.Amount}
	funding, err := finance.Hash()
	if err != nil {
		t.Fatal(err)
	}
	cp := protocol.Checkpoint{Version: 1, ProofMode: 1, ChainID: domain.ChainID, Genesis: domain.Genesis, DEXID: domain.DEXID, Epoch: 1, Committee: domain.Committee, Sequence: 1, PreRoot: status.Root, PostRoot: protocol.Hash{91}, FirstBlock: 1, LastBlock: 1, CLXHeight: 1, CLXHash: protocol.Hash(block.Hash()), InboxEnd: 1, InboxRoot: inboxRoot, WithdrawalRoot: withdrawalRoot, WithdrawalTotal: claim.Amount, FundingRef: funding, DataRoot: protocol.Hash{92}, DataSchema: 3}
	hash, err := cp.Hash()
	if err != nil {
		t.Fatal(err)
	}
	dexRef := &types.HotstuffProposalRef{Version: types.HotstuffProposalRefVersion, ChainID: domain.ChainID, Number: 1, ViewNumber: 1, ViewID: common.Hash{3}, LeaderID: bftview.GetNodeID(members[0].Address, members[0].Public), BlockHash: common.Hash(hash), ParentHash: common.Hash{93}, StateRoot: common.Hash(cp.PostRoot), BodyHash: common.Hash(cp.DataRoot), BodySize: 8, ExtraHash: types.HotstuffProposalExtraHash(nil), KeyHash: common.Hash(domain.EpochKey()), Time: 1}
	dexQC := nativeRollbackQC(t, keys, dexRef)
	dexParentID, _ := hotstuff.SignedStateID(dexQC)
	dexRef.Number, dexRef.Time, dexRef.ViewNumber, dexRef.ViewID = 2, 2, 2, common.Hash{4}
	dexRef.LeaderID = bftview.GetNodeID(members[1].Address, members[1].Public)
	dexRef.ParentHash, dexRef.BlockHash, dexRef.ParentQCID = dexRef.BlockHash, common.Hash{94}, dexParentID.Hash()
	dexProof, err := checkpoint.EncodeProof(checkpoint.Proof{Target: dexQC, Descendants: []*hotstuff.SignedState{nativeRollbackQC(t, keys, dexRef)}})
	if err != nil {
		t.Fatal(err)
	}
	call, err := protocol.EncodeNativeCheckpoint(cp, finance, dexProof, encodedEvidence)
	if err != nil {
		t.Fatal(err)
	}
	f.header = &types.Header{Number: big.NewInt(2), ParentHash: block.Hash(), GasLimit: 64000000, Difficulty: big.NewInt(1), Time: 2}
	return chain, call, claim
}

// Observe the real native event after its state writes, then exhaust the normal
// runtime access recorder with reads. This test-only fault does not replace any
// authentication, transfer or snapshot operation in the production path.
type nativeRollbackLogObserver struct {
	vm.StateDB
	afterLog func(*types.Log)
}

func (o *nativeRollbackLogObserver) AddLog(log *types.Log) {
	o.StateDB.AddLog(log)
	o.afterLog(log)
}

func TestDEXNativeCheckpointAndClaimOuterResourceRollback(t *testing.T) {
	f := newNativeTXFixture(t, 1000)
	chain, checkpointCall, claim := nativeRollbackCheckpoint(t, f)
	claimCall, err := protocol.EncodeNativeClaim(claim, 0, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	nullifier, _ := claim.Nullifier()
	nullSlot := common.Hash(protocol.Digest("common-dex/settlement/nullifier/v1", nullifier[:]))
	for _, tc := range []struct {
		name string
		call []byte
		gas  uint64
	}{
		{"checkpoint", checkpointCall, 16000000},
		{"claim", claimCall, 500000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			beforeRoot := f.st.Copy().IntermediateRoot(true)
			beforeStatus, beforeBuckets, beforeSurplus, err := settlement.NativeStatus(f.st, params.DEXSettlementAddress)
			if err != nil {
				t.Fatal(err)
			}
			beforeNonce := f.st.GetNonce(f.sender)
			tx := f.tx(t, beforeNonce, new(big.Int), tc.gas, tc.call)
			f.st.Prepare(tx.Hash(), common.Hash{101}, int(beforeNonce))
			observed := false
			observer := &nativeRollbackLogObserver{StateDB: f.st}
			recorder := newEVMMVCCRecorder(observer)
			observer.afterLog = func(log *types.Log) {
				status, buckets, _, err := settlement.NativeStatus(f.st, params.DEXSettlementAddress)
				if err != nil || len(f.st.GetLogs(tx.Hash())) != 1 || status.Sequence != 1 || status.InboxCursor != 1 {
					t.Fatal("fault was not reached after native writes/log", status, err)
				}
				if tc.name == "checkpoint" {
					if log.Topics[0] != settlement.NativeCheckpointTopic || buckets[settlement.Withdrawals] != claim.Amount || buckets[settlement.Unconsumed] != (protocol.Amount{}) {
						t.Fatal("fault preceded checkpoint reservation")
					}
				} else if log.Topics[0] != settlement.NativeClaimTopic || buckets[settlement.Withdrawals] != (protocol.Amount{}) || f.st.GetState(params.DEXSettlementAddress, nullSlot) == (common.Hash{}) || f.st.GetBalance(common.Address(claim.Recipient)).Cmp(claim.Amount.Big()) != 0 {
					t.Fatal("fault preceded native transfer/nullifier")
				}
				observed = true
				for i := uint64(0); i <= f.config.NativeParallel.MaxAccessesPerTransaction; i++ {
					recorder.GetState(params.DEXSettlementAddress, common.BigToHash(new(big.Int).SetUint64(1<<32+i)))
				}
			}
			gasPool := new(GasPool).AddGas(f.header.GasLimit)
			var gasUsed uint64
			author := common.Address{33}
			receipt, err := applyTransactionWithEVMState(f.config, chain, &author, gasPool, f.st, recorder, f.header, tx, &gasUsed, vm.Config{})
			if !observed || !errors.Is(err, ErrEVMRuntimeAccessLimitExceeded) || receipt != nil {
				t.Fatal("expected post-write outer resource failure", observed, receipt, err)
			}
			afterStatus, afterBuckets, afterSurplus, err := settlement.NativeStatus(f.st, params.DEXSettlementAddress)
			if err != nil || afterStatus != beforeStatus || !reflect.DeepEqual(afterBuckets, beforeBuckets) || afterSurplus != beforeSurplus || f.st.Copy().IntermediateRoot(true) != beforeRoot || f.st.GetNonce(f.sender) != beforeNonce || len(f.st.GetLogs(tx.Hash())) != 0 || gasUsed != 0 || gasPool.Gas() != f.header.GasLimit {
				t.Fatal("outer failure retained native state/logs/fees/nonce/gas", err)
			}
			// Retry the same signed TX without the fault: restored nonce, anchor,
			// reservation and nullifier must permit a first successful execution.
			f.st.Prepare(tx.Hash(), common.Hash{101}, int(beforeNonce))
			receipt, err = ApplyTransaction(f.config, chain, &author, gasPool, f.st, f.header, tx, &gasUsed, vm.Config{})
			if err != nil || receipt == nil || receipt.Status != types.ReceiptStatusSuccessful || len(receipt.Logs) != 1 {
				t.Fatal("retry after outer rollback failed", receipt, err)
			}
			if tc.name == "claim" && (len(receipt.Logs[0].Data) != 33 || receipt.Logs[0].Data[32] != 0 || f.st.GetBalance(common.Address(claim.Recipient)).Cmp(claim.Amount.Big()) != 0) {
				t.Fatal("rollback consumed claim nullifier or paid twice")
			}
			t.Logf("native %s: authenticated writes observed, runtime access failure rolled back full state/log/gas; identical signed TX retry passed", tc.name)
		})
	}
}
