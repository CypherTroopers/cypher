package core

import (
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	lru "github.com/hashicorp/golang-lru"
)

func TestInsertChainRetriesFHSPublicationBusyAfterUnlock(t *testing.T) {
	bc := &BlockChain{}
	release := make(chan struct{})
	waiting := make(chan struct{})
	var calls, waits int32
	bc.fhsSyncWaitPublication = func() {
		atomic.AddInt32(&waits, 1)
		close(waiting)
		<-release
	}

	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := bc.insertChainWithFHSPublicationRetry(func() (int, error) {
			if atomic.AddInt32(&calls, 1) == 1 {
				return 3, ErrFHSFinalizedSyncPublicationBusy
			}
			return 7, nil
		})
		done <- result{n: n, err: err}
	}()

	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("insertion did not wait after the retryable publication conflict")
	}
	// The live publication must be able to take chainmu while the importer is
	// waiting; otherwise this retry path recreates the original ABBA deadlock.
	chainLockAvailable := make(chan struct{})
	go func() {
		bc.chainmu.Lock()
		bc.chainmu.Unlock()
		close(chainLockAvailable)
	}()
	select {
	case <-chainLockAvailable:
	case <-time.After(time.Second):
		t.Fatal("chainmu remained locked while waiting for the publication barrier")
	}
	close(release)
	released = true

	select {
	case got := <-done:
		if got.err != nil || got.n != 7 {
			t.Fatalf("retry result = (%d, %v), want (7, nil)", got.n, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("insertion did not retry after publication release")
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("insertion calls = %d, want 2", got)
	}
	if got := atomic.LoadInt32(&waits); got != 1 {
		t.Fatalf("publication waits = %d, want 1", got)
	}
}

func TestInsertChainDoesNotRetryNonBusyError(t *testing.T) {
	bc := &BlockChain{}
	var calls, waits int32
	bc.fhsSyncWaitPublication = func() { atomic.AddInt32(&waits, 1) }
	wantErr := errors.New("invalid proof")
	n, err := bc.insertChainWithFHSPublicationRetry(func() (int, error) {
		atomic.AddInt32(&calls, 1)
		return 4, wantErr
	})
	if n != 4 || !errors.Is(err, wantErr) {
		t.Fatalf("non-busy result = (%d, %v), want (4, %v)", n, err, wantErr)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("insertion calls = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&waits); got != 0 {
		t.Fatalf("publication waits = %d, want 0", got)
	}
}

func TestFHSFinalizedSyncLifecycleRejectsPartialHooks(t *testing.T) {
	bc := &BlockChain{
		fhsSyncBeforeKeyCommit: func(*types.Block, *hotstuff.SignedState) (bool, error) {
			return true, nil
		},
	}
	block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1)})
	_, err := bc.commitFHSSyncVerifiedProposal(
		&VerifiedProposal{Block: block},
		&hotstuff.SignedState{},
	)
	if err == nil || err.Error() != "incomplete Fair HotStuff finalized sync key lifecycle" {
		t.Fatalf("partial lifecycle error = %v", err)
	}
}

func makeFHSCommitProofValidator(t *testing.T) (*BlockValidator, []bls.SecretKey, []*bls.PublicKey, common.Hash) {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { _ = db.Close() })
	secrets := make([]bls.SecretKey, 7)
	public := make([]*bls.PublicKey, 7)
	committee := &bftview.Committee{List: make([]*common.Cnode, 7)}
	for index := range secrets {
		secrets[index].SetByCSPRNG()
		public[index] = secrets[index].GetPublicKey()
		committee.List[index] = &common.Cnode{
			Address: fmt.Sprintf("validator-%d:7101", index),
			Public:  public[index].SerializeToHexStr(),
		}
	}
	keyBlock := types.NewKeyBlock(&types.KeyBlockHeader{
		Difficulty:    big.NewInt(1),
		Number:        big.NewInt(0),
		Time:          1,
		CommitteeHash: committee.RlpHash(),
	})
	rawdb.WriteKeyBlock(db, keyBlock)
	rawdb.WriteKeyBlockHash(db, keyBlock.Hash(), 0)
	rawdb.WriteHeadKeyBlockHash(db, keyBlock.Hash())
	bftview.SetCommitteeConfig(db, nil, nil)
	if !bftview.WriteCommittee(0, keyBlock.Hash(), committee) {
		t.Fatal("store FHS proof committee")
	}
	numberCache, _ := lru.New(headerCacheLimit)
	headerCache, _ := lru.New(headerCacheLimit)
	blockCache, _ := lru.New(blockCacheLimit)
	kbc := &KeyBlockChain{
		db:         db,
		blockCache: blockCache,
		khc: &KeyHeaderChain{
			chainDb:     db,
			headerCache: headerCache,
			numberCache: numberCache,
		},
	}
	kbc.currentBlock.Store(keyBlock)
	config := &params.ChainConfig{ChainID: big.NewInt(10101919), FairHotstuff: true}
	bc := &BlockChain{chainConfig: config, db: db, keyBlockChain: kbc}
	validator := NewBlockValidator(config, bc, nil)
	bc.validator = validator
	return validator, secrets, public, keyBlock.Hash()
}

func makeFHSCommitProofQC(t *testing.T, block *types.Block, view uint64, leader string, parentQCID common.Hash, secrets []bls.SecretKey, public []*bls.PublicKey) (*types.HotstuffProposalRef, *hotstuff.SignedState) {
	t.Helper()
	viewID := common.BigToHash(new(big.Int).SetUint64(view))
	unsigned := block.CopyOrg()
	encoded := unsigned.EncodeToBytes()
	ref, err := types.NewHotstuffProposalRefWithCommitments(
		10101919, view, viewID, leader, unsigned, encoded,
		types.HotstuffProposalExtraHash(nil), parentQCID,
	)
	if err != nil {
		t.Fatal(err)
	}
	state := ref.EncodeToBytes()
	var aggregate *bls.Sign
	for index := 0; index < 5; index++ {
		signature, err := hotstuff.SignFHSSignatureWithContext(&secrets[index], public[index], state, 10101919, hotstuff.MsgVotePrepare, viewID, leader)
		if err != nil {
			t.Fatal(err)
		}
		if aggregate == nil {
			aggregate = signature
		} else {
			aggregate.Add(signature)
		}
	}
	qc := &hotstuff.SignedState{
		State:    state,
		Sign:     aggregate.Serialize(),
		Mask:     []byte{0x1f},
		ViewID:   viewID,
		LeaderID: leader,
		Number:   view,
	}
	return ref, qc
}

func TestVerifyFHS2ChainCommitProofRequiresDirectChildQC(t *testing.T) {
	validator, secrets, public, keyHash := makeFHSCommitProofValidator(t)
	target := types.NewBlockWithHeader(&types.Header{
		ParentHash: common.HexToHash("0x01"),
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		BlockType:  types.FastTx_Block,
		KeyHash:    keyHash,
	})
	targetRef, targetQC := makeFHSCommitProofQC(t, target, 10, "leader-10", common.Hash{}, secrets, public)
	target.SetFHSSignature(targetQC.Sign, targetQC.Mask, targetQC.ViewID, targetQC.LeaderID, targetQC.Number, targetRef.ExtraHash, targetRef.ParentQCID)
	targetID, err := hotstuff.SignedStateID(targetQC)
	if err != nil {
		t.Fatal(err)
	}
	child := types.NewBlockWithHeader(&types.Header{
		ParentHash: target.Hash(),
		Number:     big.NewInt(2),
		Difficulty: big.NewInt(1),
		BlockType:  types.FastTx_Block,
		KeyHash:    keyHash,
	})
	_, childQC := makeFHSCommitProofQC(t, child, 14, "leader-14", targetID.Hash(), secrets, public)
	if err := validator.VerifyFHS2ChainCommitProof(target, childQC); err != nil {
		t.Fatalf("valid direct-child QC proof rejected: %v", err)
	}

	_, wrongParentQC := makeFHSCommitProofQC(t, child, 15, "leader-15", common.HexToHash("0xdead"), secrets, public)
	if err := validator.VerifyFHS2ChainCommitProof(target, wrongParentQC); err == nil {
		t.Fatal("child QC without the exact target QC identity was accepted")
	}
	if err := validator.VerifyFHS2ChainCommitProof(target, targetQC); err == nil {
		t.Fatal("target's own one-chain QC was accepted as a 2-chain finality proof")
	}
	tampered := hotstuff.CloneSignedState(childQC)
	tampered.Sign[0] ^= 0xff
	if err := validator.VerifyFHS2ChainCommitProof(target, tampered); err == nil {
		t.Fatal("tampered child QC was accepted as a finality proof")
	}

	encoded, err := encodeFHSFinalityProof(childQC)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.SetFHSFinalityProof(encoded); err != nil {
		t.Fatal(err)
	}
	decoded, present, err := decodeFHSFinalityProof(target)
	if err != nil || !present {
		t.Fatalf("decode valid embedded proof: present=%v err=%v", present, err)
	}
	if err := validator.VerifyFHS2ChainCommitProof(target, decoded); err != nil {
		t.Fatalf("valid embedded direct-child QC rejected: %v", err)
	}

	malformed := target.WithSeal(target.Header())
	if err := malformed.SetFHSFinalityProof([]byte{0xff}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeFHSFinalityProof(malformed); err == nil {
		t.Fatal("malformed embedded finality proof was accepted")
	}

}

func TestVerifyFHS2ChainCommitProofBindsPipelinedKeyCarrierHeight(t *testing.T) {
	validator, secrets, public, oldKeyHash := makeFHSCommitProofValidator(t)
	makeTarget := func(tNumber uint64) (*types.Block, *hotstuff.SignedState) {
		keyBlock := types.NewKeyBlock(&types.KeyBlockHeader{
			ParentHash: oldKeyHash,
			Number:     big.NewInt(1),
			Difficulty: big.NewInt(1),
			Time:       2,
			T_Number:   tNumber,
		})
		target := types.NewBlockWithHeader(&types.Header{
			ParentHash: common.HexToHash("0x03"),
			Number:     big.NewInt(4),
			Difficulty: big.NewInt(1),
			BlockType:  types.Key_Block,
			KeyHash:    oldKeyHash,
		})
		target.SetKeyblock(keyBlock)
		targetRef, targetQC := makeFHSCommitProofQC(t, target, 39, "leader-39", common.Hash{}, secrets, public)
		target.SetFHSSignature(targetQC.Sign, targetQC.Mask, targetQC.ViewID, targetQC.LeaderID, targetQC.Number, targetRef.ExtraHash, targetRef.ParentQCID)
		return target, targetQC
	}
	makeChildQC := func(target *types.Block, targetQC *hotstuff.SignedState) *hotstuff.SignedState {
		targetID, err := hotstuff.SignedStateID(targetQC)
		if err != nil {
			t.Fatal(err)
		}
		child := types.NewBlockWithHeader(&types.Header{
			ParentHash: target.Hash(),
			Number:     big.NewInt(5),
			Difficulty: big.NewInt(1),
			BlockType:  types.FastTx_Block,
			KeyHash:    oldKeyHash,
		})
		_, qc := makeFHSCommitProofQC(t, child, 40, "leader-40", targetID.Hash(), secrets, public)
		return qc
	}

	staleTarget, staleQC := makeTarget(2) // canonical head, not proposal parent
	if err := validator.VerifyFHS2ChainCommitProof(staleTarget, makeChildQC(staleTarget, staleQC)); err == nil {
		t.Fatal("child QC accepted a key carrier whose T_Number omitted the certified parent")
	}

	validTarget, validQC := makeTarget(3) // exact parent of carrier tx block #4
	if err := validator.VerifyFHS2ChainCommitProof(validTarget, makeChildQC(validTarget, validQC)); err != nil {
		t.Fatalf("valid pipelined key carrier proof rejected: %v", err)
	}
}
