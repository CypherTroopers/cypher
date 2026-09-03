package downloader

import (
	"bytes"
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/trie"
)

func downloaderBlobBodyFixture(t *testing.T, marker byte) (*types.Transaction, *types.BlobTxSidecar) {
	t.Helper()

	var commitment types.KZGCommitment
	commitment[0], commitment[len(commitment)-1] = marker, marker^0xff
	var proof types.KZGProof
	proof[0] = marker
	blob := make(types.Blob, 1<<17)
	blob[0], blob[len(blob)-1] = marker, marker^0xff
	sidecar := types.NewBlobTxSidecar(
		types.BlobSidecarVersion0,
		[]types.Blob{blob},
		[]types.KZGCommitment{commitment},
		[]types.KZGProof{proof},
	)
	tx := types.NewTx(&types.BlobTx{
		ChainID:    big.NewInt(777),
		Nonce:      9,
		GasTipCap:  big.NewInt(2),
		GasFeeCap:  big.NewInt(30),
		Gas:        100_000,
		To:         common.HexToAddress("0x1000000000000000000000000000000000000001"),
		Value:      big.NewInt(11),
		Data:       []byte{0xca, 0xfe},
		AccessList: types.AccessList{},
		BlobFeeCap: big.NewInt(3),
		BlobHashes: sidecar.BlobHashes(),
		V:          new(big.Int),
		R:          big.NewInt(1),
		S:          big.NewInt(1),
	})
	body := &types.Body{Transactions: types.Transactions{tx}, BlobSidecars: []*types.BlobTxSidecar{sidecar}}
	if err := body.ValidateBlobSidecars(); err != nil {
		t.Fatalf("fixture is not a structurally valid version-0 blob body: %v", err)
	}
	return tx, sidecar
}

func downloaderCommonTxBodyFixture(txHash common.Hash) ([]*types.CommonTxAdmissionBatch, []types.CommonTxAdmissionRef, []*types.CommonTxReward) {
	batch := &types.CommonTxAdmissionBatch{
		ChainID:        big.NewInt(777),
		GenesisHash:    common.HexToHash("0x1111"),
		Miner:          common.HexToAddress("0x2000000000000000000000000000000000000002"),
		KeyBlockNumber: 7,
		Timestamp:      1_725_000_123,
		TxHashes:       []common.Hash{txHash},
		Signature:      bytes.Repeat([]byte{0x5a}, 65),
	}
	batch.TxRoot = types.DeriveCommonTxAdmissionTxRoot(batch.TxHashes)
	batch.AdmissionID = types.CommonTxAdmissionID(batch)
	refs := []types.CommonTxAdmissionRef{{Batch: 0, Item: 0}}
	rewards := []*types.CommonTxReward{{
		TxHash:         txHash,
		Approver:       common.HexToAddress("0x3000000000000000000000000000000000000003"),
		ApproverReward: big.NewInt(17),
		Burn:           big.NewInt(3),
	}}
	return []*types.CommonTxAdmissionBatch{batch}, refs, rewards
}

func downloaderBodyHeader(tx *types.Transaction, batches []*types.CommonTxAdmissionBatch, refs []types.CommonTxAdmissionRef, rewards []*types.CommonTxReward) *types.Header {
	return &types.Header{
		ParentHash:            common.HexToHash("0x1234"),
		Root:                  common.HexToHash("0x5678"),
		Difficulty:            big.NewInt(1),
		Number:                big.NewInt(20),
		GasLimit:              30_000_000,
		BlockType:             types.FastTx_Block,
		TxHash:                types.DeriveSha(types.Transactions{tx}, new(trie.Trie)),
		UncleHash:             types.EmptyUncleHash,
		CommonTxAdmissionRoot: types.DeriveCommonTxAdmissionRoot(batches, refs),
		CommonTxRewardRoot:    types.DeriveCommonTxRewardRoot(rewards),
	}
}

func TestBlockFromFetchResultPreservesCanonicalBodySidecars(t *testing.T) {
	tx, sidecar := downloaderBlobBodyFixture(t, 0x42)
	wantEnvelope, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	wantHash := tx.Hash()
	batches, refs, rewards := downloaderCommonTxBodyFixture(wantHash)
	body := &types.Body{
		Transactions:             types.Transactions{tx},
		BlobSidecars:             []*types.BlobTxSidecar{sidecar},
		CommonTxAdmissionBatches: batches,
		CommonTxAdmissionRefs:    refs,
		CommonTxRewards:          rewards,
	}
	header := downloaderBodyHeader(tx, batches, refs, rewards)

	block, err := blockFromFetchResult(&fetchResult{Header: header, Body: body})
	if err != nil {
		t.Fatalf("reconstruct canonical six-field body: %v", err)
	}
	if tx.BlobSidecar() != nil {
		t.Fatal("reconstruction mutated the canonical input transaction")
	}
	if len(block.Transactions()) != 1 || block.Transactions()[0].Hash() != wantHash {
		t.Fatalf("reconstructed transaction hash = %v, want %s", block.Transactions(), wantHash)
	}
	gotEnvelope, err := block.Transactions()[0].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotEnvelope, wantEnvelope) {
		t.Fatalf("reconstructed execution envelope changed\n have: %x\n want: %x", gotEnvelope, wantEnvelope)
	}
	gotSidecars := block.BlobSidecars()
	if len(gotSidecars) != 1 || gotSidecars[0] == nil || gotSidecars[0].Version != types.BlobSidecarVersion0 {
		t.Fatalf("reconstructed blob sidecars = %#v", gotSidecars)
	}
	if gotSidecars[0].Blobs[0][0] != 0x42 || gotSidecars[0].Commitments[0] != sidecar.Commitments[0] || gotSidecars[0].Proofs[0] != sidecar.Proofs[0] {
		t.Fatal("reconstructed block changed the blob sidecar")
	}
	if block.Transactions()[0].BlobSidecar() == nil {
		t.Fatal("reconstructed BlobTx did not receive its body sidecar")
	}
	if !reflect.DeepEqual(block.CommonTxAdmissionBatches(), batches) {
		t.Fatalf("reconstructed admission batches = %#v, want %#v", block.CommonTxAdmissionBatches(), batches)
	}
	if !reflect.DeepEqual(block.CommonTxAdmissionRefs(), refs) {
		t.Fatalf("reconstructed admission refs = %#v, want %#v", block.CommonTxAdmissionRefs(), refs)
	}
	if !reflect.DeepEqual(block.CommonTxRewards(), rewards) {
		t.Fatalf("reconstructed rewards = %#v, want %#v", block.CommonTxRewards(), rewards)
	}
	if gotHeader := block.Header(); gotHeader.TxHash != header.TxHash || gotHeader.CommonTxAdmissionRoot != header.CommonTxAdmissionRoot || gotHeader.CommonTxRewardRoot != header.CommonTxRewardRoot {
		t.Fatal("reconstruction changed the header's body commitments")
	}
}

func TestDownloaderQueuePreservesCanonicalSixFieldBody(t *testing.T) {
	tx, sidecar := downloaderBlobBodyFixture(t, 0x47)
	batches, refs, rewards := downloaderCommonTxBodyFixture(tx.Hash())
	body := &types.Body{
		Transactions:             types.Transactions{tx},
		BlobSidecars:             []*types.BlobTxSidecar{sidecar},
		CommonTxAdmissionBatches: batches,
		CommonTxAdmissionRefs:    refs,
		CommonTxRewards:          rewards,
	}
	header := downloaderBodyHeader(tx, batches, refs, rewards)
	queue := newQueue(2)
	queue.Prepare(header.Number.Uint64(), FullSync)
	if scheduled := queue.Schedule([]*types.Header{header}, header.Number.Uint64()); len(scheduled) != 1 {
		t.Fatalf("scheduled headers = %d, want 1", len(scheduled))
	}
	peer := &peerConnection{id: "blob-body-peer", lacking: make(map[common.Hash]struct{})}
	request, _, throttled := queue.ReserveBodies(peer, 1)
	if request == nil || len(request.Headers) != 1 || throttled {
		t.Fatalf("body reservation = %#v, throttled=%t", request, throttled)
	}

	accepted, err := queue.DeliverBodies(peer.id, []*types.Body{body})
	if err != nil {
		t.Fatalf("deliver canonical six-field body: %v", err)
	}
	if accepted != 1 {
		t.Fatalf("accepted bodies = %d, want 1", accepted)
	}
	results := queue.Results(false)
	if len(results) != 1 || results[0].Body == nil {
		t.Fatalf("completed fetch results = %#v, want one body", results)
	}
	resultBody := results[0].Body
	if resultBody.Transactions[0].BlobSidecar() != nil {
		t.Fatal("queue changed the canonical execution transaction")
	}
	if !reflect.DeepEqual(resultBody.BlobSidecars, body.BlobSidecars) ||
		!reflect.DeepEqual(resultBody.CommonTxAdmissionBatches, batches) ||
		!reflect.DeepEqual(resultBody.CommonTxAdmissionRefs, refs) ||
		!reflect.DeepEqual(resultBody.CommonTxRewards, rewards) {
		t.Fatal("queue dropped or changed a canonical body field")
	}

	block, err := blockFromFetchResult(results[0])
	if err != nil {
		t.Fatalf("reconstruct delivered body: %v", err)
	}
	if len(block.BlobSidecars()) != 1 || block.Transactions()[0].BlobSidecar() == nil || block.Transactions()[0].Hash() != tx.Hash() {
		t.Fatal("delivered body lost its BlobTx identity or sidecar during block reconstruction")
	}
	if !reflect.DeepEqual(block.CommonTxAdmissionBatches(), batches) ||
		!reflect.DeepEqual(block.CommonTxAdmissionRefs(), refs) ||
		!reflect.DeepEqual(block.CommonTxRewards(), rewards) {
		t.Fatal("delivered body lost CommonTx sidecars during block reconstruction")
	}
}

func TestBlockFromFetchResultRejectsMismatchedBlobSidecar(t *testing.T) {
	tx, _ := downloaderBlobBodyFixture(t, 0x51)
	_, mismatched := downloaderBlobBodyFixture(t, 0x52)
	body := &types.Body{
		Transactions: types.Transactions{tx},
		BlobSidecars: []*types.BlobTxSidecar{mismatched},
	}
	header := &types.Header{Difficulty: big.NewInt(1), Number: big.NewInt(20)}

	if _, err := blockFromFetchResult(&fetchResult{Header: header, Body: body}); !errors.Is(err, types.ErrBlobVersionedHashMismatch) {
		t.Fatalf("mismatched sidecar error = %v, want %v", err, types.ErrBlobVersionedHashMismatch)
	}
}
