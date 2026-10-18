package reconfig

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/ethdb/leveldb"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/trie"
)

// Reuse the slot-clock fixture with funded, independently admitted transfers.
// Construction executes once to establish the signed state/receipt commitments;
// the replay tests compare another real execution against those commitments.
func newFHSReplayRecordFixture(t *testing.T) (*fhsEpochTestFixture, *fhsCertifiedProposal, *fhsCertifiedProposal, common.Address, common.Address) {
	t.Helper()
	fixture, sender, recipient, _ := newFHSReplayFundedFixture(t, nil)
	parent := newFHSReplayTransferProposal(t, fixture, nil, 0, 10, 401)
	child := newFHSReplayTransferProposal(t, fixture, parent, 1, 11, 403)
	return fixture, parent, child, sender, recipient
}

func newFHSReplayFundedFixture(t *testing.T, shared ethdb.Database) (*fhsEpochTestFixture, common.Address, common.Address, func()) {
	t.Helper()
	key, err := crypto.HexToECDSA("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	sender, recipient := crypto.PubkeyToAddress(key.PublicKey), common.HexToAddress("0x7304301")
	alloc := core.GenesisAlloc{
		sender:    {Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)},
		recipient: {Code: []byte{0x60, 0x00, 0x60, 0x00, 0xa0, 0x00}}, // Emit one empty LOG0 per transfer.
		common.HexToAddress("0x7304303"): {Balance: big.NewInt(1), Code: []byte{0x60, 0x2a, 0x00},
			Storage: map[common.Hash]common.Hash{common.HexToHash("0x01"): common.HexToHash("0x2a")}},
	}
	fixture, _, _, closeChain := newFHSSlotReplayFixtureWithDatabase(t, shared, alloc, shared != nil)
	return fixture, sender, recipient, closeChain
}

func newFHSReplayTransferProposal(t *testing.T, fixture *fhsEpochTestFixture, parent *fhsCertifiedProposal, nonce, view, slot uint64) *fhsCertifiedProposal {
	t.Helper()
	s, bc := fixture.service, fixture.service.bc
	key, err := crypto.HexToECDSA("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	sender, recipient := crypto.PubkeyToAddress(key.PublicKey), common.HexToAddress("0x7304301")
	base := bc.Genesis()
	var input *state.StateDB
	if parent == nil {
		input, err = bc.StateAt(base.Root())
	} else {
		base, input = parent.verified.Block, parent.verified.StateDB.Copy()
	}
	if err != nil {
		t.Fatal(err)
	}
	const transferGas = params.TxGas + 2*3 + 375 // Intrinsic gas, two PUSH1, and LOG0.
	tx, err := types.SignTx(types.NewTransaction(nonce, recipient, big.NewInt(7), transferGas, big.NewInt(1_000_000_000), nil), types.LatestSignerForChainID(s.chainConfig.ChainID), key)
	if err != nil {
		t.Fatal(err)
	}
	header := &types.Header{ParentHash: base.Hash(), Number: new(big.Int).Add(base.Number(), big.NewInt(1)), Root: base.Root(),
		Difficulty: big.NewInt(1), GasLimit: base.GasLimit(), BaseFee: big.NewInt(params.FixedBaseFeePerGas), KeyHash: fixture.current.Hash(), BlockType: types.SlowTx_Block}
	header.SetFHSSlot(slot)
	batch := &types.CommonTxAdmissionBatch{Version: types.CommonRPCVersionV2, ChainID: new(big.Int).Set(s.chainConfig.ChainID),
		GenesisHash: bc.Genesis().Hash(), Miner: sender, RewardRecipient: common.HexToAddress("0x7304302"),
		KeyBlockNumber: fixture.current.NumberU64(), Timestamp: header.Time, TxHashes: []common.Hash{tx.Hash()}}
	batch.TxRoot = types.DeriveCommonTxAdmissionTxRoot(batch.TxHashes)
	batch.AdmissionID = types.CommonTxAdmissionID(batch)
	batch.Signature, err = crypto.Sign(types.CommonTxAdmissionSigningHash(batch).Bytes(), key)
	if err != nil {
		t.Fatal(err)
	}
	txs, batches, refs := types.Transactions{tx}, []*types.CommonTxAdmissionBatch{batch}, []types.CommonTxAdmissionRef{{}}
	rewards, err := buildCommonTxRewards(txs, types.Receipts{{GasUsed: transferGas}}, batches, refs, header.BaseFee)
	if err != nil {
		t.Fatal(err)
	}
	block := types.NewBlock(header, txs, nil, nil, new(trie.Trie))
	block.AttachCommonTxData(batches, refs, rewards)
	receipts, _, gas, err := bc.Processor().Process(block, input, vm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	header = block.Header()
	header.Root, header.GasUsed = input.IntermediateRoot(true), gas
	block = types.NewBlock(header, txs, nil, receipts, new(trie.Trie))
	block.AttachCommonTxData(batches, refs, rewards)
	return newFHSSlotReplayProposal(t, fixture, parent, view, slot, block)
}

func TestFHSReplayRecordNonGenesisCheckpointPhysicalRestart(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "shared-chain-key-wal")
	store, err := leveldb.New(directory, 1, 8, "")
	if err != nil {
		t.Fatal(err)
	}
	db := rawdb.NewDatabase(store)
	fixture, sender, recipient, closeChain := newFHSReplayFundedFixture(t, db)
	s := fixture.service
	if !s.chainConfig.FixedCommittee {
		t.Fatal("physical checkpoint fixture must use the fixed-committee genesis profile")
	}
	canonical := newFHSReplayTransferProposal(t, fixture, nil, 0, 10, 401)
	finalizer := newFHSReplayTransferProposal(t, fixture, canonical, 1, 11, 403)
	// Commit a private state copy. Every certified state remains caller-owned.
	committing := *canonical.verified
	committing.StateDB = canonical.verified.StateDB.Copy()
	committing.Block = types.DecodeToBlock(s.proposalBodies[canonical.ref.ProposalID()].EncodedBlock)
	committing.Block.SetFHSSignature(canonical.qc.Sign, canonical.qc.Mask, canonical.qc.ViewID, canonical.qc.LeaderID, canonical.qc.Number, canonical.ref.ExtraHash, canonical.ref.ParentQCID)
	if _, err := s.bc.CommitFHSVerifiedProposal(&committing, finalizer.qc, false); err != nil {
		t.Fatalf("finalize nonempty checkpoint block: %v", err)
	}
	if s.bc.CurrentBlockN() != 1 || s.bc.CurrentBlock().Root() == s.bc.Genesis().Root() || canonical.verified.StateDB.GetNonce(sender) != 1 {
		t.Fatal("fixture did not preserve a nonempty canonical checkpoint and its certified state")
	}
	canonicalBytes := s.bc.CurrentBlock().EncodeToBytes()
	// The suffix binds another valid QC for the already finalized payload.
	// Replay must retain the canonical block's original QC and finality proof.
	recertified := newFHSSlotReplayProposal(t, fixture, nil, 17, 401, types.DecodeToBlock(s.proposalBodies[canonical.ref.ProposalID()].EncodedBlock))
	// Continue the uninterrupted reference from the canonical root, just as a
	// normal canonical continuation does. Speculative StateDB copies also carry
	// transient prior-block log indexes, which are not part of a checkpoint.
	boundary := *recertified
	boundaryVerified := *recertified.verified
	boundaryVerified.StateDB, err = s.bc.StateAt(canonical.ref.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	boundary.verified = &boundaryVerified
	first := newFHSReplayTransferProposal(t, fixture, &boundary, 1, 18, 403)
	second := newFHSReplayTransferProposal(t, fixture, first, 2, 19, 404)
	if recertified.ref.BlockHash != canonical.ref.BlockHash || recertified.ref.ProposalID() == canonical.ref.ProposalID() {
		t.Fatal("fixture did not recertify the canonical payload in another view")
	}
	for _, record := range []*fhsCertifiedProposal{recertified, first, second} {
		body := s.proposalBodies[record.ref.ProposalID()]
		receipt, err := s.promoteFHSProposalContent(context.Background(), record.ref, body, record.qc, 1<<20)
		if err != nil || !receipt.matches(s.fhsStore, record.ref, body, record.qc) {
			t.Fatalf("promote exact proposal %d: receipt=%v err=%v", record.ref.Number, receipt, err)
		}
		if err := receipt.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.adoptFHSHighQC(second.qc, false, false); err != nil {
		t.Fatalf("persist suffix watermark in the shared database: %v", err)
	}
	if s.bc.CurrentBlockN() != 1 {
		t.Fatal("content promotion or watermark publication committed the suffix")
	}
	if _, err := state.New(canonical.ref.StateRoot, state.NewDatabase(db), nil); err == nil {
		t.Fatal("checkpoint root was already flushed; fixture does not exercise dirty-state persistence")
	}
	checkpoint, err := s.bc.BeginFHSCheckpoint(context.Background(), canonical.ref.BlockHash,
		core.FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 4 << 20, MaxHistoryBlocks: 16, MaxKeyBlocks: 16})
	if err != nil {
		t.Fatal(err)
	}
	var progress core.FHSCheckpointProgress
	for calls := 0; calls < 512 && !progress.Ready; calls++ {
		before := progress
		progress, err = checkpoint.Step(context.Background(), 1, 1<<20)
		if err != nil {
			t.Fatalf("checkpoint step %d: %v", calls, err)
		}
		if calls > 0 && (progress.Nodes-before.Nodes > 1 || progress.Bytes-before.Bytes > 1<<20) {
			t.Fatal("checkpoint step exceeded the caller's record or byte allowance")
		}
	}
	checkpoint.Close()
	if !progress.Ready || progress.Anchor.Number != 1 || progress.Anchor.BlockHash != canonical.ref.BlockHash {
		t.Fatalf("non-genesis checkpoint not ready: %+v", progress)
	}
	// Inspect through a fresh state cache before Stop can flush recent roots.
	diskState, err := state.New(progress.Anchor.StateRoot, state.NewDatabase(db), nil)
	if err != nil || diskState.GetNonce(sender) != 1 || diskState.GetBalance(recipient).Cmp(big.NewInt(7)) != 0 || diskState.Error() != nil {
		t.Fatalf("checkpoint did not persist its state before shutdown: %v", err)
	}
	contract := common.HexToAddress("0x7304303")
	if !bytes.Equal(diskState.GetCode(contract), []byte{0x60, 0x2a, 0x00}) || diskState.GetState(contract, common.HexToHash("0x01")) != common.HexToHash("0x2a") {
		t.Fatal("checkpoint did not retain account code and storage closure")
	}
	if s.fhsStore.db != db || fixture.db != db {
		t.Fatal("chain, key history, and WAL do not share the physical database")
	}
	closeChain()
	store, err = leveldb.New(directory, 1, 8, "")
	if err != nil {
		t.Fatalf("reopen physical database: %v", err)
	}
	reopened := rawdb.NewDatabase(store)
	bc, kbc, _ := openFHSSlotReplayChain(t, reopened, s.chainConfig)
	if bc == s.bc || kbc == s.kbc || !bytes.Equal(bc.CurrentBlock().EncodeToBytes(), canonicalBytes) {
		t.Fatal("fresh chain runtime changed the persisted canonical payload or finality metadata")
	}
	restarted := &Service{chainConfig: s.chainConfig, bc: bc, kbc: kbc, netService: &netService{},
		fhsStore:       newFHSSafetyStoreForConfig(reopened, s.ChainID(), bc.Genesis().Hash(), s.chainConfig),
		proposalBodies: make(map[common.Hash]*proposalBodyMsg), verifiedProposalByID: make(map[common.Hash]*core.VerifiedProposal),
		fhsCertifiedByHash: make(map[common.Hash]*fhsCertifiedProposal), fhsCertifiedByID: make(map[common.Hash]*fhsCertifiedProposal),
		currentView: bftview.View{TxHash: bc.CurrentBlock().Hash(), TxNumber: bc.CurrentBlockN(), KeyHash: kbc.CurrentBlock().Hash(), CommitteeHash: fixture.committee.RlpHash()}}
	restarted.txService = &txService{bc: bc, kbc: kbc, config: s.chainConfig, proposedChain: newProposedChain(), mux: new(event.TypeMux)}
	restarted.txService.proposedChain.clear(bc.CurrentBlock())
	t.Cleanup(restarted.txService.mux.Stop)
	ready, err := bc.FHSCheckpointAnchor()
	if err != nil || ready != progress.Anchor {
		t.Fatalf("reopened checkpoint anchor: %+v err=%v", ready, err)
	}
	safety, highestHash, err := restarted.fhsStore.snapshot()
	if err != nil || safety == nil || highestHash != second.ref.BlockHash || !hotstuff.SignedStateSemanticEqual(safety.HighestQC, second.qc) {
		t.Fatalf("reopened shared safety WAL: hash=%s err=%v", highestHash, err)
	}
	anchor, err := restarted.newFHSReplayAnchor(&ready, safety.HighestQC)
	if err != nil {
		t.Fatal(err)
	}
	if anchor.parentQCID == first.ref.ParentQCID || anchor.parentNumber != 1 {
		t.Fatal("replay fixture lost its alternate-QC canonical boundary")
	}
	var parent *core.VerifiedProposal
	var restored []*core.VerifiedProposal
	for index, original := range []*fhsCertifiedProposal{first, second} {
		ref, body, found, err := restarted.readFHSDurableProposalBody(original.ref.ProposalID())
		if err != nil || !found {
			t.Fatalf("read reopened exact proposal %d: found=%v err=%v", index, found, err)
		}
		encoded, err := rawdb.ReadFHSCertificate(reopened, ref.ProposalID())
		if err != nil {
			t.Fatal(err)
		}
		var certificate fhsDiskCertificate
		if err := rlp.DecodeBytes(encoded, &certificate); err != nil || certificate.ProposalID != ref.ProposalID() || !hotstuff.SignedStateSemanticEqual(certificate.QC, original.qc) {
			t.Fatalf("read reopened exact QC %d: %v", index, err)
		}
		got, usage, err := restarted.replayFHSCertifiedRecord(context.Background(), anchor, ref, certificate.QC, body, parent, restarted.fhsReplayLimits())
		if err != nil || got == nil || usage.Blocks != 1 || usage.BodyBytes != ref.BodySize || usage.ParentStateCopies != uint64(index) {
			t.Fatalf("replay reopened record %d: result=%v usage=%+v err=%v", index, got, usage, err)
		}
		want := original.verified
		view := got.StateDB.Copy()
		if len(got.Logs) != 1 || len(got.Receipts) != 1 || len(got.Receipts[0].Logs) != 1 || got.Receipts[0].Status != types.ReceiptStatusSuccessful {
			t.Fatalf("reopened record %d did not execute its LOG0 transfer successfully", index)
		}
		if got.StateDB == want.StateDB || got.BlockHash() != want.BlockHash() || got.ParentRoot != want.ParentRoot || got.UsedGas != want.UsedGas ||
			!reflect.DeepEqual(got.Receipts, want.Receipts) || !reflect.DeepEqual(got.Logs, want.Logs) || view.IntermediateRoot(true) != ref.StateRoot ||
			view.GetNonce(sender) != uint64(index+2) || view.GetBalance(recipient).Cmp(big.NewInt(int64(7*(index+2)))) != 0 {
			t.Fatalf("reopened record %d differs from uninterrupted execution", index)
		}
		restored, parent = append(restored, got), got
	}
	if anchor.completed != 2 || restored[0].StateDB.GetNonce(sender) != 2 || bc.CurrentBlockN() != 1 || !bytes.Equal(bc.CurrentBlock().EncodeToBytes(), canonicalBytes) {
		t.Fatal("suffix replay consumed its parent or changed the canonical checkpoint")
	}
	// The new runtime can commit a returned nonempty state through the original
	// proof gate; the next replay result and original certified copies survive.
	committing = *restored[0]
	committing.StateDB, committing.Block = restored[0].StateDB.Copy(), restored[0].Block.CopyOrg()
	committing.Block.SetFHSSignature(first.qc.Sign, first.qc.Mask, first.qc.ViewID, first.qc.LeaderID, first.qc.Number, first.ref.ExtraHash, first.ref.ParentQCID)
	if _, err := bc.CommitFHSVerifiedProposal(&committing, second.qc, false); err != nil {
		t.Fatalf("commit reopened replay result: %v", err)
	}
	if bc.CurrentBlock().Hash() != first.ref.BlockHash || restored[0].StateDB.GetNonce(sender) != 2 || restored[1].StateDB.GetNonce(sender) != 3 {
		t.Fatal("committing a private returned-state copy consumed another committable result")
	}
	retained, err := bc.FHSCheckpointAnchor()
	if err != nil || retained != ready {
		t.Fatalf("canonical advance discarded the retained checkpoint: %+v err=%v", retained, err)
	}
	if _, err := restarted.newFHSReplayAnchor(&retained, second.qc); !errors.Is(err, errFHSReplayStale) {
		t.Fatalf("historical checkpoint needs unsupported canonical-delta replay: %v", err)
	}
}

func TestFHSReplayRecordIncompleteCheckpointPhysicalControlledClose(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "incomplete-shared-checkpoint")
	store, err := leveldb.New(directory, 1, 8, "")
	if err != nil {
		t.Fatal(err)
	}
	db := rawdb.NewDatabase(store)
	fixture, sender, recipient, closeChain := newFHSReplayFundedFixture(t, db)
	s := fixture.service
	if !s.chainConfig.FixedCommittee || s.fhsStore.db != db || fixture.db != db {
		t.Fatal("incomplete-checkpoint fixture must share one fixed-committee database")
	}
	limits := core.FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 4 << 20, MaxHistoryBlocks: 16, MaxKeyBlocks: 16}
	complete := func(bc *core.BlockChain, hash common.Hash) core.FHSCheckpointAnchor {
		t.Helper()
		job, err := bc.BeginFHSCheckpoint(context.Background(), hash, limits)
		if err != nil {
			t.Fatal(err)
		}
		defer job.Close()
		for calls := 0; calls < 512; calls++ {
			progress, err := job.Step(context.Background(), 1, 1<<20)
			if err != nil {
				t.Fatalf("complete checkpoint step %d: %v", calls, err)
			}
			if progress.Ready {
				return progress.Anchor
			}
		}
		t.Fatal("small checkpoint did not reach READY within its fixture bound")
		return core.FHSCheckpointAnchor{}
	}
	oldAnchor := complete(s.bc, s.bc.Genesis().Hash())
	oldReady, err := rawdb.ReadFHSCheckpointReady(db)
	if err != nil || len(oldReady) == 0 || oldAnchor.Number != 0 {
		t.Fatalf("seed acknowledged genesis checkpoint: anchor=%+v err=%v", oldAnchor, err)
	}
	canonical := newFHSReplayTransferProposal(t, fixture, nil, 0, 10, 401)
	finalizer := newFHSReplayTransferProposal(t, fixture, canonical, 1, 11, 403)
	committing := *canonical.verified
	committing.StateDB = canonical.verified.StateDB.Copy()
	committing.Block = types.DecodeToBlock(s.proposalBodies[canonical.ref.ProposalID()].EncodedBlock)
	committing.Block.SetFHSSignature(canonical.qc.Sign, canonical.qc.Mask, canonical.qc.ViewID, canonical.qc.LeaderID, canonical.qc.Number, canonical.ref.ExtraHash, canonical.ref.ParentQCID)
	if _, err := s.bc.CommitFHSVerifiedProposal(&committing, finalizer.qc, false); err != nil {
		t.Fatalf("finalize incomplete-checkpoint target: %v", err)
	}
	canonicalBytes := s.bc.CurrentBlock().EncodeToBytes()
	job, err := s.bc.BeginFHSCheckpoint(context.Background(), canonical.ref.BlockHash, limits)
	if err != nil {
		t.Fatal(err)
	}
	for calls := 0; calls < 2; calls++ {
		progress, err := job.Step(context.Background(), 1, 1<<20)
		if err != nil || progress.Ready || progress.Anchor.Number != 1 {
			job.Close()
			t.Fatalf("incomplete checkpoint step %d: progress=%+v err=%v", calls, progress, err)
		}
	}
	job.Close()
	if canonical.verified.StateDB.GetNonce(sender) != 1 {
		t.Fatal("incomplete checkpoint consumed its caller-owned certified state")
	}
	// This is a controlled close before READY, not a power-loss simulation.
	// Stop may flush recent state, but cannot acknowledge an unfinished job.
	closeChain()
	store, err = leveldb.New(directory, 1, 8, "")
	if err != nil {
		t.Fatalf("reopen incomplete checkpoint database: %v", err)
	}
	reopened := rawdb.NewDatabase(store)
	bc, kbc, _ := openFHSSlotReplayChain(t, reopened, s.chainConfig)
	if bc == s.bc || kbc == s.kbc || bc.CurrentBlockN() != 1 || !bytes.Equal(bc.CurrentBlock().EncodeToBytes(), canonicalBytes) {
		t.Fatal("controlled reopen did not restore the unchanged canonical target")
	}
	selected, err := bc.FHSCheckpointAnchor()
	if err != nil || selected != oldAnchor {
		t.Fatalf("incomplete checkpoint replaced the acknowledged anchor after reopen: %+v err=%v", selected, err)
	}
	restoredReady, err := rawdb.ReadFHSCheckpointReady(reopened)
	if err != nil || !bytes.Equal(restoredReady, oldReady) {
		t.Fatalf("controlled close published incomplete non-genesis READY bytes: %v", err)
	}
	retried := complete(bc, canonical.ref.BlockHash)
	selected, err = bc.FHSCheckpointAnchor()
	if err != nil || selected != retried || selected.Number != 1 || selected.BlockHash != canonical.ref.BlockHash || selected.StateRoot != canonical.ref.StateRoot {
		t.Fatalf("explicit checkpoint retry did not become acknowledged: %+v err=%v", selected, err)
	}
	diskState, err := state.New(selected.StateRoot, state.NewDatabase(reopened), nil)
	if err != nil || diskState.GetNonce(sender) != 1 || diskState.GetBalance(recipient).Cmp(big.NewInt(7)) != 0 || diskState.Error() != nil {
		t.Fatalf("retried checkpoint source state unavailable: %v", err)
	}
}

func TestFHSReplayRecordNonemptyDifferentialAndCommit(t *testing.T) {
	fixture, parent, child, sender, recipient := newFHSReplayRecordFixture(t)
	s := fixture.service
	checkpoint, err := s.bc.BeginFHSCheckpoint(context.Background(), s.bc.Genesis().Hash(), core.FHSCheckpointLimits{MaxNodes: 10000, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer checkpoint.Close()
	var ready core.FHSCheckpointProgress
	for calls := 0; calls < 64 && !ready.Ready; calls++ {
		ready, err = checkpoint.Step(context.Background(), 1, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !ready.Ready {
		t.Fatal("genesis checkpoint did not complete within the small fixture bound")
	}
	anchor, err := s.newFHSReplayAnchor(&ready.Anchor, child.qc)
	if err != nil {
		t.Fatal(err)
	}
	first, usage, err := s.replayFHSCertifiedRecord(context.Background(), anchor, parent.ref, parent.qc, s.proposalBodies[parent.ref.ProposalID()], nil, s.fhsReplayLimits())
	if err != nil || usage.Blocks != 1 || usage.BodyBytes != parent.ref.BodySize || usage.ParentStateCopies != 0 {
		t.Fatalf("first replay: usage=%+v err=%v", usage, err)
	}
	parentState := first.StateDB
	second, usage, err := s.replayFHSCertifiedRecord(context.Background(), anchor, child.ref, child.qc, s.proposalBodies[child.ref.ProposalID()], first, s.fhsReplayLimits())
	if err != nil || usage.Blocks != 1 || usage.ParentStateCopies != 1 || anchor.completed != 2 {
		t.Fatalf("second replay: usage=%+v err=%v", usage, err)
	}
	for index, pair := range [][2]*core.VerifiedProposal{{parent.verified, first}, {child.verified, second}} {
		want, got := pair[0], pair[1]
		if want.StateDB == got.StateDB || want.BlockHash() != got.BlockHash() || want.UsedGas != got.UsedGas ||
			want.ParentRoot != got.ParentRoot || !reflect.DeepEqual(want.Receipts, got.Receipts) || !reflect.DeepEqual(want.Logs, got.Logs) {
			t.Fatalf("replay %d differs from original execution", index)
		}
		view := got.StateDB.Copy()
		if view.IntermediateRoot(true) != got.Block.Root() || view.GetNonce(sender) != uint64(index+1) || view.GetBalance(recipient).Cmp(big.NewInt(int64(7*(index+1)))) != 0 {
			t.Fatalf("replay %d returned the wrong state", index)
		}
	}
	if first.StateDB != parentState || first.StateDB.GetNonce(sender) != 1 || parent.verified.StateDB.GetNonce(sender) != 1 || s.bc.CurrentBlockN() != 0 {
		t.Fatal("child replay consumed/mutated a committable parent or published canonical state")
	}
	// Commit the returned nonempty result through the unchanged proof gate.
	first.Block.SetFHSSignature(parent.qc.Sign, parent.qc.Mask, parent.qc.ViewID, parent.qc.LeaderID, parent.qc.Number, parent.ref.ExtraHash, parent.ref.ParentQCID)
	if _, err := s.bc.CommitFHSVerifiedProposal(first, child.qc, false); err != nil {
		t.Fatalf("commit reconstructed nonempty parent: %v", err)
	}
	if s.bc.CurrentBlock().Hash() != parent.ref.BlockHash {
		t.Fatal("reconstructed state did not become canonical")
	}
	if _, _, err := s.replayFHSCertifiedRecord(context.Background(), anchor, child.ref, child.qc, s.proposalBodies[child.ref.ProposalID()], first, s.fhsReplayLimits()); !errors.Is(err, errFHSReplayStale) {
		t.Fatalf("old cursor after canonical advance = %v", err)
	}
}

type fhsReplayCancelTrace struct {
	*vm.StructLogger
	cancel context.CancelFunc
}

func (trace *fhsReplayCancelTrace) CaptureEnd(_ []byte, _ uint64, _ time.Duration, _ error) error {
	if trace.cancel != nil {
		trace.cancel()
	}
	return nil
}

func TestFHSReplayRecordCancellationAfterExecution(t *testing.T) {
	fixture, parent, child, sender, _ := newFHSReplayRecordFixture(t)
	s := fixture.service
	previous := s.bc
	previous.Stop()
	trace := &fhsReplayCancelTrace{StructLogger: vm.NewStructLogger(nil)}
	bc, err := core.NewBlockChain(fixture.db, nil, s.chainConfig, previous.Engine(), vm.Config{Debug: true, Tracer: trace}, nil, nil, s.kbc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bc.Stop)
	s.bc, s.txService.bc = bc, bc
	anchor, err := s.newFHSReplayAnchor(nil, child.qc)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := s.replayFHSCertifiedRecord(context.Background(), anchor, parent.ref, parent.qc, s.proposalBodies[parent.ref.ProposalID()], nil, s.fhsReplayLimits())
	if err != nil {
		t.Fatal(err)
	}
	before, parentState := *anchor, first.StateDB
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	trace.cancel = cancel // Cancel when the real EVM call completes.
	result, usage, err := s.replayFHSCertifiedRecord(ctx, anchor, child.ref, child.qc, s.proposalBodies[child.ref.ProposalID()], first, s.fhsReplayLimits())
	if !errors.Is(err, context.Canceled) || result != nil || usage.ParentStateCopies != 1 || usage.Blocks != 0 || *anchor != before ||
		first.StateDB != parentState || parentState.GetNonce(sender) != 1 || s.bc.CurrentBlockN() != 0 {
		t.Fatalf("cancel after execution: result=%v usage=%+v err=%v", result, usage, err)
	}
	trace.cancel = nil
	if result, usage, err := s.replayFHSCertifiedRecord(context.Background(), anchor, child.ref, child.qc, s.proposalBodies[child.ref.ProposalID()], first, s.fhsReplayLimits()); err != nil || result == nil || usage.Blocks != 1 {
		t.Fatalf("retry after cancellation: result=%v usage=%+v err=%v", result, usage, err)
	}
}

func TestFHSReplayRecordFailuresPreserveParentAndProgress(t *testing.T) {
	fixture, parent, child, sender, _ := newFHSReplayRecordFixture(t)
	s := fixture.service
	anchor, err := s.newFHSReplayAnchor(nil, child.qc)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := s.replayFHSCertifiedRecord(context.Background(), anchor, parent.ref, parent.qc, s.proposalBodies[parent.ref.ProposalID()], nil, s.fhsReplayLimits())
	if err != nil {
		t.Fatal(err)
	}
	stateBefore, progressBefore := first.StateDB, *anchor
	body := s.proposalBodies[child.ref.ProposalID()]
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct {
		name   string
		ctx    context.Context
		body   *proposalBodyMsg
		parent *core.VerifiedProposal
		limits fhsReplayLimits
		want   error
	}{
		{"cancelled", cancelled, body, first, s.fhsReplayLimits(), context.Canceled},
		{"missing body", context.Background(), nil, first, s.fhsReplayLimits(), errFHSReplayMissingData},
		{"missing parent", context.Background(), body, nil, s.fhsReplayLimits(), errFHSReplayMissingData},
		{"body budget", context.Background(), body, first, fhsReplayLimits{MaxBlocks: 1, MaxBodyBytes: child.ref.BodySize - 1, MaxProofBytes: s.fhsReplayLimits().MaxProofBytes}, errFHSReplayBudget},
		{"proof budget", context.Background(), body, first, fhsReplayLimits{MaxBlocks: 1, MaxBodyBytes: child.ref.BodySize, MaxProofBytes: 1}, errFHSReplayBudget},
		{"block budget", context.Background(), body, first, fhsReplayLimits{}, errFHSReplayBudget},
	} {
		t.Run(test.name, func(t *testing.T) {
			verified, usage, err := s.replayFHSCertifiedRecord(test.ctx, anchor, child.ref, child.qc, test.body, test.parent, test.limits)
			if !errors.Is(err, test.want) || verified != nil || usage.Blocks != 0 || *anchor != progressBefore {
				t.Fatalf("result=%v usage=%+v err=%v", verified, usage, err)
			}
		})
	}
	missingState := *first
	missingState.StateDB = nil
	if _, _, err := s.replayFHSCertifiedRecord(context.Background(), anchor, child.ref, child.qc, body, &missingState, s.fhsReplayLimits()); !errors.Is(err, errFHSReplayMissingData) {
		t.Fatalf("missing nonempty StateDB = %v", err)
	}
	corrupt := cloneProposalBodyMsg(body)
	corrupt.EncodedBlock[len(corrupt.EncodedBlock)-1] ^= 1
	if _, _, err := s.replayFHSCertifiedRecord(context.Background(), anchor, child.ref, child.qc, corrupt, first, s.fhsReplayLimits()); !errors.Is(err, errFHSReplayInvalid) {
		t.Fatalf("corrupt exact content = %v", err)
	}
	if first.StateDB != stateBefore || first.StateDB.GetNonce(sender) != 1 || *anchor != progressBefore || s.bc.CurrentBlockN() != 0 {
		t.Fatal("failed replay consumed parent state or advanced progress")
	}
	// The original supplied nonempty parent remains committable after failures.
	first.Block.SetFHSSignature(parent.qc.Sign, parent.qc.Mask, parent.qc.ViewID, parent.qc.LeaderID, parent.qc.Number, parent.ref.ExtraHash, parent.ref.ParentQCID)
	if _, err := s.bc.CommitFHSVerifiedProposal(first, child.qc, false); err != nil {
		t.Fatalf("commit parent after failed reconstruction: %v", err)
	}
}

func TestFHSReplayRecordEmptyParentWithoutState(t *testing.T) {
	fixture, _, _ := newFHSSlotReplayFixture(t)
	s := fixture.service
	parent := newFHSSlotReplayProposal(t, fixture, nil, 10, 401, nil)
	child := newFHSSlotReplayProposal(t, fixture, parent, 11, 403, nil)
	anchor, err := s.newFHSReplayAnchor(nil, child.qc)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := s.replayFHSCertifiedRecord(context.Background(), anchor, parent.ref, parent.qc, s.proposalBodies[parent.ref.ProposalID()], nil, s.fhsReplayLimits())
	if err != nil {
		t.Fatal(err)
	}
	first.StateDB = nil // Empty parent root is still present in the canonical trie DB.
	second, usage, err := s.replayFHSCertifiedRecord(context.Background(), anchor, child.ref, child.qc, s.proposalBodies[child.ref.ProposalID()], first, s.fhsReplayLimits())
	if err != nil || second == nil || second.StateDB == nil || usage.Blocks != 1 || first.StateDB != nil {
		t.Fatalf("empty-parent fallback: result=%v usage=%+v err=%v", second, usage, err)
	}
	if !bytes.Equal(second.Block.Header().Extra, child.verified.Block.Header().Extra) {
		t.Fatal("replay changed the exact slot envelope")
	}
}

func TestFHSReplayRecordCanonicalParentRecertification(t *testing.T) {
	fixture, _, _ := newFHSSlotReplayFixture(t)
	s := fixture.service
	parent := newFHSSlotReplayProposal(t, fixture, nil, 10, 401, nil)
	firstChild := newFHSSlotReplayProposal(t, fixture, parent, 11, 403, nil)
	unsigned := types.DecodeToBlock(s.proposalBodies[parent.ref.ProposalID()].EncodedBlock)
	parent.verified.Block.SetFHSSignature(parent.qc.Sign, parent.qc.Mask, parent.qc.ViewID, parent.qc.LeaderID, parent.qc.Number, parent.ref.ExtraHash, parent.ref.ParentQCID)
	if _, err := s.bc.CommitFHSVerifiedProposal(parent.verified, firstChild.qc, false); err != nil {
		t.Fatal(err)
	}
	recertified := newFHSSlotReplayProposal(t, fixture, nil, 17, 401, unsigned)
	child := newFHSSlotReplayProposal(t, fixture, recertified, 18, 403, nil)
	anchor, err := s.newFHSReplayAnchor(nil, child.qc)
	if err != nil {
		t.Fatal(err)
	}
	if child.ref.ParentQCID == anchor.parentQCID {
		t.Fatal("fixture did not use a different certification of the canonical payload")
	}
	result, usage, err := s.replayFHSCertifiedRecord(context.Background(), anchor, child.ref, child.qc, s.proposalBodies[child.ref.ProposalID()], nil, s.fhsReplayLimits())
	if err != nil || result == nil || usage.Blocks != 1 || result.ParentHash != parent.ref.BlockHash {
		t.Fatalf("canonical recertification boundary: result=%v usage=%+v err=%v", result, usage, err)
	}
}

func reloadBranchSafetyState(t *testing.T, s *Service) (*hotstuff.FHSSafetyState, common.Hash) {
	t.Helper()
	reloaded := newFHSSafetyStore(s.fhsStore.db, s.fhsStore.chainID, s.fhsStore.genesisHash)
	state, hash, err := reloaded.snapshot()
	if err != nil {
		t.Fatalf("reload safety WAL: %v", err)
	}
	return state, hash
}

func resetBranchSafetyRuntime(s *Service) {
	s.fhsStore = newFHSSafetyStore(s.fhsStore.db, s.fhsStore.chainID, s.fhsStore.genesisHash)
	s.fhsHighest, s.fhsSelectedParent, s.fhsParentSelected = nil, nil, false
	s.fhsCertifiedByHash = make(map[common.Hash]*fhsCertifiedProposal)
	s.fhsCertifiedByID = make(map[common.Hash]*fhsCertifiedProposal)
	s.verifiedProposalByID = make(map[common.Hash]*core.VerifiedProposal)
	s.proposalBodies = make(map[common.Hash]*proposalBodyMsg)
	canonical := s.bc.CurrentBlock()
	s.txService.proposedChain.clear(canonical)
	s.currentView.TxHash, s.currentView.TxNumber = canonical.Hash(), canonical.NumberU64()
}

func persistBranchSafetyBodies(t *testing.T, s *Service, certificates ...*fhsCertifiedProposal) {
	t.Helper()
	for _, certificate := range certificates {
		if err := s.persistFHSProposalData(certificate.ref, s.proposalBodies[certificate.ref.ProposalID()]); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFHSBranchRecoveryCommitsEarlierConsecutivePair(t *testing.T) {
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	a := f.proposal(t, nil, 1, 'a')
	b := f.proposal(t, a, 2, 'b')
	c := f.proposal(t, b, 5, 'c')
	persistBranchSafetyBodies(t, s, a, b, c)
	if err := s.adoptFHSHighQC(c.qc, false, false); err != nil {
		t.Fatal(err)
	}
	resetBranchSafetyRuntime(s)
	if err := s.loadFHSWAL(); err != nil {
		t.Fatalf("restore gapped certified chain: %v", err)
	}
	if s.bc.CurrentBlock().Hash() != a.ref.BlockHash || !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), c.qc) {
		t.Fatal("restart did not finish the earlier consecutive-view decision")
	}
}

func TestFHSBranchRecoveryRetainsObservationOutsideCanonicalExecution(t *testing.T) {
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	observation := f.proposal(t, nil, 20, 'o')
	b := f.proposal(t, nil, 10, 'b')
	c := f.proposal(t, b, 11, 'c')
	persistBranchSafetyBodies(t, s, observation, b, c)
	for _, certificate := range []*fhsCertifiedProposal{observation, c} {
		if err := s.adoptFHSHighQC(certificate.qc, false, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.commitFHS2ChainForCertified(c.qc); err != nil {
		t.Fatal(err)
	}
	if s.bc.CurrentBlock().Hash() != b.ref.BlockHash || !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), observation.qc) {
		t.Fatal("fixture did not retain the observed watermark beside the canonical proof")
	}
	resetBranchSafetyRuntime(s)
	if err := s.loadFHSWAL(); err != nil {
		t.Fatalf("an obsolete execution branch prevented canonical recovery: %v", err)
	}
	if s.GetCurrentView().TxHash != b.ref.BlockHash || !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), observation.qc) {
		t.Fatal("recovery confused the advertised observation with the canonical execution parent")
	}
}

func TestFHSBranchMissingContentRecoveryKeepsConsensusGated(t *testing.T) {
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	a := f.proposal(t, nil, 10, 'a')
	if err := s.adoptFHSHighQC(a.qc, false, false); err != nil {
		t.Fatal(err)
	}
	// Certificate and maximum are durable, while the asynchronous body write
	// was interrupted. Restart may advertise the QC but cannot execute it yet.
	if err := rawdb.DeleteFHSProposal(s.fhsStore.db, a.ref.ProposalID()); err != nil {
		t.Fatal(err)
	}
	resetBranchSafetyRuntime(s)
	if err := s.loadFHSWAL(); err != nil {
		t.Fatal(err)
	}
	if !s.hasDeferredFHSRecovery() || !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), a.qc) || s.HasValidatedFHSCertificate(a.qc) {
		t.Fatal("recovery did not distinguish an observed QC from validated content")
	}
	atomic.StoreInt32(&s.runningState, 1)
	t.Cleanup(func() { atomic.StoreInt32(&s.runningState, 0) })
	atomic.StoreInt32(&s.fhsRecoveryRetryQueued, 1) // Suppress a timer in the manually driven recovery loop.
	s.attemptDeferredFHSRecovery()
	if !s.hasDeferredFHSRecovery() || s.fhsHighest != nil || s.bc.CurrentBlockN() != 0 {
		t.Fatal("advertised WAL watermark incorrectly completed missing-content recovery")
	}
}

func TestFHSBranchCanonicalRecertificationPersistsBeforeSelection(t *testing.T) {
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	a := f.proposal(t, nil, 10, 'a')
	b := f.proposal(t, a, 11, 'b')
	if err := s.adoptFHSHighQC(b.qc, false, false); err != nil {
		t.Fatal(err)
	}
	if err := s.commitFHS2ChainForCertified(b.qc); err != nil {
		t.Fatal(err)
	}
	ref := *a.ref
	ref.ViewNumber, ref.ViewID = 20, common.HexToHash("0xc020")
	qc := &hotstuff.SignedState{State: ref.EncodeToBytes(), Number: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID, Mask: []byte{0x1f}}
	var aggregate *bls.Sign
	for i := 0; i < 5; i++ {
		signature, err := hotstuff.SignFHSSignatureWithContext(&f.keys[i], f.public[i], qc.State, s.ChainID(), hotstuff.MsgVotePrepare, qc.ViewID, qc.LeaderID)
		if err != nil {
			t.Fatal(err)
		}
		if aggregate == nil {
			aggregate = signature
		} else {
			aggregate.Add(signature)
		}
	}
	qc.Sign = aggregate.Serialize()
	if s.HasValidatedFHSCertificate(qc) {
		t.Fatal("canonical block hash bypassed observation of a new certificate")
	}
	if err := s.SelectFHSProposalParent(qc); !errors.Is(err, hotstuff.ErrProposalValidationPending) {
		t.Fatalf("canonical recertification selected without persisting parent watermark: %v", err)
	}
	key := hotstuff.FHSHighQCValidationKey{TargetView: 21, SelectProposalParent: true}
	output, err := s.stageFHSHighQC(context.Background(), key, qc, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.installStagedFHSHighQC(output, false, false); err != nil {
		t.Fatal(err)
	}
	state, hash := reloadBranchSafetyState(t, s)
	if !hotstuff.SignedStateSemanticEqual(state.HighestQC, qc) || hash != a.ref.BlockHash ||
		!hotstuff.SignedStateSemanticEqual(s.SelectedFHSProposalParent(), qc) {
		t.Fatal("canonical certificate selection did not retain its durable observation")
	}
}

func TestFHSBranchSelectionStagesLowerSiblingWithoutDowngradingWAL(t *testing.T) {
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	lower := f.proposal(t, nil, 10, 'a')
	higher := f.proposal(t, nil, 11, 'b')
	if err := s.adoptFHSHighQC(higher.qc, false, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SelectFHSProposalParent(lower.qc); !errors.Is(err, hotstuff.ErrProposalValidationPending) {
		t.Fatalf("uncached quorum parent must stage before selection: %v", err)
	}
	if !hotstuff.SignedStateSemanticEqual(s.SelectedFHSProposalParent(), higher.qc) {
		t.Fatal("unvalidated lower parent changed execution parent")
	}
	id, err := hotstuff.SignedStateID(lower.qc)
	if err != nil {
		t.Fatal(err)
	}
	key := hotstuff.FHSHighQCValidationKey{QCID: id.Hash(), TargetView: 12, SelectProposalParent: true}
	output, err := s.stageFHSHighQC(context.Background(), key, lower.qc, 0, 0)
	if err != nil {
		t.Fatalf("stage lower certified sibling: %v", err)
	}
	if s.HasValidatedFHSCertificate(lower.qc) || !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), higher.qc) {
		t.Fatal("background staging published certificate state")
	}
	result := &hotstuff.FHSHighQCValidationResult{Key: key, ApplicationData: output}
	if err := s.ApplyFHSHighQCValidation(result); err != nil {
		t.Fatalf("apply lower quorum parent: %v", err)
	}
	s.FinishFHSHighQCValidation(result)
	if !hotstuff.SignedStateSemanticEqual(s.SelectedFHSProposalParent(), lower.qc) || s.GetCurrentView().TxHash != lower.ref.BlockHash {
		t.Fatal("quorum-selected lower parent did not become the execution parent")
	}
	// Read the actual LevelDB bytes through a fresh store before the vote. The
	// observed maximum remains the report watermark while the lower QC and its
	// body are available for the selected execution branch.
	state, hash := reloadBranchSafetyState(t, s)
	if !hotstuff.SignedStateSemanticEqual(state.HighestQC, higher.qc) || hash != higher.ref.BlockHash {
		t.Fatal("selecting lower parent downgraded durable observed maximum")
	}
	if encoded, err := rawdb.ReadFHSCertificate(s.fhsStore.db, lower.ref.ProposalID()); err != nil || len(encoded) == 0 {
		t.Fatalf("selected parent was not durable before voting: bytes=%d err=%v", len(encoded), err)
	}
	child := f.proposal(t, lower, 12, 'c')
	if err := s.validateFHSProposalParent(child.ref, lower.qc); err != nil {
		t.Fatalf("child of selected lower parent was rejected: %v", err)
	}
	encoded := child.ref.EncodeToBytes()
	vote := &hotstuff.PersistedVote{ViewNumber: child.ref.ViewNumber, ViewID: child.ref.ViewID, LeaderID: child.ref.LeaderID,
		ProposalID: child.ref.ProposalID(), ProposalRef: encoded, ProposalRefHash: hotstuff.StateDigest(encoded)}
	if err := s.PersistFHSVote(vote); err != nil {
		t.Fatalf("vote for quorum-selected sibling: %v", err)
	}
	state, hash = reloadBranchSafetyState(t, s)
	if !hotstuff.SignedStateSemanticEqual(state.HighestQC, higher.qc) || hash != higher.ref.BlockHash ||
		state.LastVote == nil || state.LastVote.ProposalID != child.ref.ProposalID() {
		t.Fatal("fresh WAL read lost observed maximum or selected-branch vote")
	}
	wal, ok := s.fhsStore.db.(*leveldb.Database)
	if !ok {
		t.Fatal("branch regression requires the real LevelDB WAL")
	}
	path, chainID, genesisHash := wal.Path(), s.fhsStore.chainID, s.fhsStore.genesisHash
	if err := wal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := leveldb.New(path, 1, 8, "")
	if err != nil {
		t.Fatalf("reopen selected-branch WAL: %v", err)
	}
	t.Cleanup(func() { reopened.Close() })
	s.fhsStore = newFHSSafetyStore(reopened, chainID, genesisHash)
	state, hash = reloadBranchSafetyState(t, s)
	if !hotstuff.SignedStateSemanticEqual(state.HighestQC, higher.qc) || hash != higher.ref.BlockHash ||
		state.LastVote == nil || state.LastVote.ProposalID != child.ref.ProposalID() {
		t.Fatal("reopened LevelDB lost observed maximum or selected-branch vote")
	}
}

func TestFHSBranchSelectionFailurePreservesExecutionState(t *testing.T) {
	for _, scenario := range []string{"invalid_signature", "missing_certificate", "missing_ancestor"} {
		t.Run(scenario, func(t *testing.T) {
			f := newConvergenceFixture(t)
			s := f.replicas[0]
			selected := f.proposal(t, nil, 20, 'h')
			ancestor := f.proposal(t, nil, 10, 'a')
			candidate := f.proposal(t, ancestor, 11, 'c')
			if err := s.adoptFHSHighQC(selected.qc, false, false); err != nil {
				t.Fatal(err)
			}
			if err := s.SelectFHSProposalParent(selected.qc); err != nil {
				t.Fatal(err)
			}
			qc := hotstuff.CloneSignedState(candidate.qc)
			switch scenario {
			case "invalid_signature":
				qc.Sign[0] ^= 1
			case "missing_ancestor":
				// Model a missing cached ancestor without forging either certificate.
				// Selection must preflight the whole branch before publishing a head.
				s.fhsCertifiedByHash[candidate.ref.BlockHash] = candidate
				s.fhsCertifiedByID[candidate.ref.ProposalID()] = candidate
			}
			before := s.GetCurrentView()
			beforeParent := s.txService.currentProposalParent().Hash()
			if err := s.SelectFHSProposalParent(qc); err == nil {
				t.Fatal("invalid or incomplete parent was selected")
			}
			after := s.GetCurrentView()
			if !hotstuff.SignedStateSemanticEqual(s.SelectedFHSProposalParent(), selected.qc) ||
				after.TxHash != before.TxHash || after.TxNumber != before.TxNumber ||
				s.txService.currentProposalParent().Hash() != beforeParent {
				t.Fatal("failed selection partially changed execution state")
			}
		})
	}
}

func TestFHSBranchRawObservationPreservesQuorumSelectedParent(t *testing.T) {
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	selected := f.proposal(t, nil, 10, 'a')
	private := f.proposal(t, nil, 11, 'b')
	if err := s.adoptFHSHighQC(selected.qc, false, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SelectFHSProposalParent(selected.qc); err != nil {
		t.Fatal(err)
	}
	// The replica is already in view 12 when a private view-11 QC arrives.
	// Learning it must update future NewView reports without invalidating the
	// current view's previously verified quorum choice.
	s.currentView.ViewNumber = 11
	if err := s.adoptFHSHighQC(private.qc, false, false); err != nil {
		t.Fatal(err)
	}
	if !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), private.qc) ||
		!hotstuff.SignedStateSemanticEqual(s.SelectedFHSProposalParent(), selected.qc) ||
		s.GetCurrentView().TxHash != selected.ref.BlockHash {
		t.Fatal("private QC replaced a quorum-authorized execution parent")
	}
	child := f.proposal(t, selected, 12, 'c')
	if err := s.validateFHSProposalParent(child.ref, selected.qc); err != nil {
		t.Fatalf("private QC vetoed the quorum-selected child: %v", err)
	}
}

func TestFHSBranchSameBlockRecertifiedInHigherView(t *testing.T) {
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	old := f.proposal(t, nil, 10, 'a')
	newer := f.proposal(t, nil, 11, 'a')
	if old.ref.BlockHash != newer.ref.BlockHash || old.ref.ProposalID() == newer.ref.ProposalID() {
		t.Fatal("fixture must repropose the same block with distinct view-bound proposal identities")
	}
	if err := s.adoptFHSHighQC(old.qc, false, false); err != nil {
		t.Fatal(err)
	}
	if err := s.adoptFHSHighQC(newer.qc, false, false); err != nil {
		t.Fatalf("a valid later QC for the same uncommitted block cannot converge: %v", err)
	}
	if err := s.SelectFHSProposalParent(newer.qc); err != nil {
		t.Fatalf("select recertified block: %v", err)
	}
	child := f.proposal(t, newer, 12, 'c')
	if err := s.validateFHSProposalParent(child.ref, newer.qc); err != nil {
		t.Fatalf("child binding the later certificate was rejected: %v", err)
	}
	state, hash := reloadBranchSafetyState(t, s)
	if !hotstuff.SignedStateSemanticEqual(state.HighestQC, newer.qc) || hash != newer.ref.BlockHash {
		t.Fatal("durable maximum did not retain the later certificate identity")
	}
	olderChild := f.proposal(t, old, 13, 'd')
	for _, candidate := range []*fhsCertifiedProposal{child, olderChild} {
		if err := s.adoptFHSHighQC(candidate.qc, false, false); err != nil {
			t.Fatalf("adopt child with an exact earlier certificate binding: %v", err)
		}
	}
	if parent := fhsCertifiedParent(s.fhsCertifiedByID, olderChild); parent == nil || !hotstuff.SignedStateSemanticEqual(parent.qc, old.qc) {
		t.Fatal("a later certification replaced an earlier child's parent identity")
	}
	if target := fhs2ChainCommitTarget(s.fhsCertifiedByID, child); target == nil || !hotstuff.SignedStateSemanticEqual(target.qc, newer.qc) {
		t.Fatal("finality selected the wrong certificate for a recertified block")
	}
	for _, certificate := range []*fhsCertifiedProposal{old, newer} {
		if encoded, err := rawdb.ReadFHSCertificate(s.fhsStore.db, certificate.ref.ProposalID()); err != nil || len(encoded) == 0 {
			t.Fatalf("lost distinct durable certificate: bytes=%d err=%v", len(encoded), err)
		}
	}
}

func TestFHSBranchFsyncFailurePublishesNoPartialCertificateState(t *testing.T) {
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	old := f.proposal(t, nil, 10, 'a')
	newer := f.proposal(t, nil, 11, 'b')
	if err := s.adoptFHSHighQC(old.qc, false, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SelectFHSProposalParent(old.qc); err != nil {
		t.Fatal(err)
	}
	output, err := s.stageFHSHighQC(context.Background(), hotstuff.FHSHighQCValidationKey{SelectProposalParent: true}, newer.qc, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	before := s.GetCurrentView()
	beforeHashes, beforeIDs, beforeVerified := len(s.fhsCertifiedByHash), len(s.fhsCertifiedByID), len(s.verifiedProposalByID)
	underlying := s.fhsStore.db
	s.fhsStore.db = &failingSyncStore{KeyValueStore: underlying}
	err = s.installStagedFHSHighQC(output, false, false)
	s.fhsStore.db = underlying
	if err == nil || !strings.Contains(err.Error(), "injected fsync failure") {
		t.Fatalf("wanted injected durable-write failure, got %v", err)
	}
	state, hash := reloadBranchSafetyState(t, s)
	if !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), old.qc) || !hotstuff.SignedStateSemanticEqual(state.HighestQC, old.qc) ||
		hash != old.ref.BlockHash || !hotstuff.SignedStateSemanticEqual(s.SelectedFHSProposalParent(), old.qc) ||
		s.GetCurrentView().TxHash != before.TxHash || len(s.fhsCertifiedByHash) != beforeHashes ||
		len(s.fhsCertifiedByID) != beforeIDs || len(s.verifiedProposalByID) != beforeVerified {
		t.Fatal("failed fsync published partial branch, maximum, or execution state")
	}
	if encoded, err := rawdb.ReadFHSCertificate(underlying, newer.ref.ProposalID()); err != nil || len(encoded) != 0 {
		t.Fatalf("failed fsync left durable certificate: bytes=%d err=%v", len(encoded), err)
	}
	// An uncertain synchronous write is fail-stop for this store instance.
	// Merely restoring the transport cannot clear that safety guard; recovery
	// must reread the durable state through a new store, as a restart would.
	if err := s.installStagedFHSHighQC(output, false, false); err == nil {
		t.Fatal("failed safety store resumed without recovery")
	}
	s.fhsStore = newFHSSafetyStore(underlying, s.fhsStore.chainID, s.fhsStore.genesisHash)
	if err := s.installStagedFHSHighQC(output, false, false); err != nil {
		t.Fatalf("retrying the same verified branch after store recovery failed: %v", err)
	}
	if !hotstuff.SignedStateSemanticEqual(s.HighestCertified(), newer.qc) || !hotstuff.SignedStateSemanticEqual(s.SelectedFHSProposalParent(), newer.qc) {
		t.Fatal("successful retry did not publish the complete branch")
	}
}
