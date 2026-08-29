package core

import (
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/ethdb/memorydb"
)

func resetCommonRPCAdmissionTestState(t *testing.T) (common.Address, *big.Int) {
	t.Helper()

	commonRPCAdmissions = sync.Map{}
	atomic.StoreInt64(&commonRPCAdmissionCount, 0)
	atomic.StoreInt64(&commonRPCAdmissionLastCleanup, 0)
	SetCommonRPCAdmissionDatabase(nil)

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	miner := crypto.PubkeyToAddress(key.PublicKey)
	SetCommonRPCAdmissionSigner(func(admission *types.CommonTxAdmission) error {
		hash := types.CommonTxAdmissionSigningHash(admission)
		sig, err := crypto.Sign(hash.Bytes(), key)
		if err != nil {
			return err
		}
		admission.Signature = sig
		return nil
	})
	return miner, big.NewInt(1)
}

func signedCommonRPCAdmissionForTest(t *testing.T, tx *types.Transaction, miner common.Address, chainID *big.Int, keyBlockNumber uint64, timestamp uint64) *types.CommonTxAdmission {
	t.Helper()

	admission, err := SignAndRecordCommonRPCAdmission(tx.Hash(), miner, chainID, keyBlockNumber, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	return admission
}

func hasCommonRPCAdmissionForTx(admissions []*types.CommonTxAdmission, tx *types.Transaction) bool {
	for _, admission := range admissions {
		if admission != nil && admission.TxHash == tx.Hash() {
			return true
		}
	}
	return false
}

func TestBuildCommonTxAdmissionsKeyBlockTimestampGrace(t *testing.T) {
	miner, chainID := resetCommonRPCAdmissionTestState(t)
	blockKey := uint64(7)
	blockTime := uint64(10000)
	graceSeconds := commonRPCAdmissionDurationSeconds(commonRPCAdmissionBoundaryGrace)

	currentTx := types.NewTransaction(0, common.Address{1}, big.NewInt(1), 21000, big.NewInt(1), nil)
	previousGraceTx := types.NewTransaction(1, common.Address{2}, big.NewInt(1), 21000, big.NewInt(1), nil)
	previousStaleTx := types.NewTransaction(2, common.Address{3}, big.NewInt(1), 21000, big.NewInt(1), nil)
	futureTx := types.NewTransaction(3, common.Address{4}, big.NewInt(1), 21000, big.NewInt(1), nil)

	signedCommonRPCAdmissionForTest(t, currentTx, miner, chainID, blockKey, blockTime-10)
	signedCommonRPCAdmissionForTest(t, previousGraceTx, miner, chainID, blockKey-1, blockTime-graceSeconds)
	signedCommonRPCAdmissionForTest(t, previousStaleTx, miner, chainID, blockKey-1, blockTime-graceSeconds-1)
	signedCommonRPCAdmissionForTest(t, futureTx, miner, chainID, blockKey+1, blockTime)

	admissions := BuildCommonTxAdmissions(
		types.Transactions{currentTx, previousGraceTx, previousStaleTx, futureTx},
		blockKey,
		42,
		blockTime,
	)
	if len(admissions) != 2 {
		t.Fatalf("unexpected admission count: got %d want 2", len(admissions))
	}
	if !hasCommonRPCAdmissionForTx(admissions, currentTx) {
		t.Fatalf("missing current key block admission")
	}
	if !hasCommonRPCAdmissionForTx(admissions, previousGraceTx) {
		t.Fatalf("missing previous key block admission inside grace")
	}
	if hasCommonRPCAdmissionForTx(admissions, previousStaleTx) {
		t.Fatalf("included previous key block admission outside grace")
	}
	if hasCommonRPCAdmissionForTx(admissions, futureTx) {
		t.Fatalf("included future key block admission")
	}
	for _, admission := range admissions {
		if admission.TxBlockNumber != 0 {
			t.Fatalf("tx block number was mutated before finalization: %d", admission.TxBlockNumber)
		}
	}
}

func TestValidateCommonRPCAdmissionRejectsNonZeroTxBlockNumber(t *testing.T) {
	miner, chainID := resetCommonRPCAdmissionTestState(t)
	tx := types.NewTransaction(0, common.Address{1}, big.NewInt(1), 21000, big.NewInt(1), nil)
	admission := signedCommonRPCAdmissionForTest(t, tx, miner, chainID, 3, 100)
	admission.TxBlockNumber = 9

	err := validateCommonRPCAdmissionForBlock(admission, 3, 10, 100)
	if err == nil {
		t.Fatalf("expected non-zero tx block number to be rejected")
	}
	if !strings.Contains(err.Error(), "tx block number") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildCommonAdmissionIndexRejectsBoundaryInvalidAdmission(t *testing.T) {
	miner, chainID := resetCommonRPCAdmissionTestState(t)
	tx := types.NewTransaction(0, common.Address{1}, big.NewInt(1), 21000, big.NewInt(1), nil)
	blockKey := uint64(4)
	blockTime := uint64(10000)
	staleTimestamp := blockTime - commonRPCAdmissionDurationSeconds(commonRPCAdmissionBoundaryGrace) - 1
	admission := signedCommonRPCAdmissionForTest(t, tx, miner, chainID, blockKey-1, staleTimestamp)

	_, err := buildCommonAdmissionIndex([]*types.CommonTxAdmission{admission}, chainID, blockKey, 20, blockTime)
	if err == nil {
		t.Fatalf("expected stale cross-key admission to be rejected")
	}
	if !strings.Contains(err.Error(), "outside grace") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCommonRPCAdmissionPersistsAcrossMemoryReset(t *testing.T) {
	miner, chainID := resetCommonRPCAdmissionTestState(t)
	db := memorydb.New()
	SetCommonRPCAdmissionDatabase(db)
	t.Cleanup(func() {
		SetCommonRPCAdmissionDatabase(nil)
		_ = db.Close()
	})

	tx := types.NewTransaction(0, common.Address{9}, big.NewInt(1), 21000, big.NewInt(1), nil)
	signedCommonRPCAdmissionForTest(t, tx, miner, chainID, 3, uint64(time.Now().Unix()))

	commonRPCAdmissions = sync.Map{}
	atomic.StoreInt64(&commonRPCAdmissionCount, 0)

	loaded := CommonRPCAdmissionsForTransactions(types.Transactions{tx})
	if len(loaded) != 1 || loaded[0] == nil || loaded[0].TxHash != tx.Hash() {
		t.Fatalf("persisted admissions = %#v, want sidecar for %s", loaded, tx.Hash())
	}

	DropCommonRPCAdmissions(types.Transactions{tx})
	commonRPCAdmissions = sync.Map{}
	atomic.StoreInt64(&commonRPCAdmissionCount, 0)
	if loaded := CommonRPCAdmissionsForTransactions(types.Transactions{tx}); len(loaded) != 0 {
		t.Fatalf("finalized admission remained persisted: %#v", loaded)
	}
}
