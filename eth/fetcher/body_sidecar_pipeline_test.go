package fetcher

import (
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/trie"
)

const bodySidecarPipelineTestTimeout = 3 * time.Second

func testFetcherV0BlobTransaction() (*types.Transaction, *types.BlobTxSidecar) {
	var (
		commitment types.KZGCommitment
		proof      types.KZGProof
	)
	commitment[len(commitment)-1] = 0x42
	proof[len(proof)-1] = 0x24
	blob := make(types.Blob, params.BlobTxBlobGasPerBlob)
	blob[0] = 0x7a
	sidecar := &types.BlobTxSidecar{
		Version:     types.BlobSidecarVersion0,
		Blobs:       []types.Blob{blob},
		Commitments: []types.KZGCommitment{commitment},
		Proofs:      []types.KZGProof{proof},
	}
	tx := types.NewTx(&types.BlobTx{
		ChainID:    big.NewInt(777),
		Nonce:      3,
		GasTipCap:  big.NewInt(1),
		GasFeeCap:  big.NewInt(10),
		Gas:        100_000,
		To:         common.HexToAddress("0x1000000000000000000000000000000000000001"),
		Value:      big.NewInt(2),
		BlobFeeCap: big.NewInt(1),
		BlobHashes: sidecar.BlobHashes(),
		V:          new(big.Int),
		R:          big.NewInt(1),
		S:          big.NewInt(1),
	})
	return tx, sidecar
}

func testFetcherBlobBody() (*types.Body, *types.Header, *types.Block) {
	tx, sidecar := testFetcherV0BlobTransaction()
	batch := &types.CommonTxAdmissionBatch{
		ChainID:        big.NewInt(777),
		GenesisHash:    common.HexToHash("0x01"),
		Miner:          common.HexToAddress("0x2000000000000000000000000000000000000002"),
		KeyBlockNumber: 4,
		Timestamp:      1_750_000_000,
		TxHashes:       []common.Hash{tx.Hash()},
		Signature:      []byte{0x01},
	}
	batch.TxRoot = types.DeriveCommonTxAdmissionTxRoot(batch.TxHashes)
	batch.AdmissionID = common.HexToHash("0x02")
	ref := types.CommonTxAdmissionRef{Batch: 0, Item: 0}
	reward := &types.CommonTxReward{
		TxHash:         tx.Hash(),
		Approver:       common.HexToAddress("0x3000000000000000000000000000000000000003"),
		ApproverReward: big.NewInt(7),
		Burn:           big.NewInt(1),
	}
	uncle := &types.Header{
		ParentHash:  common.HexToHash("0x03"),
		UncleHash:   types.EmptyUncleHash,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
		Difficulty:  big.NewInt(1),
		Number:      big.NewInt(0),
		GasLimit:    30_000_000,
		BaseFee:     big.NewInt(1),
		BlockType:   types.FastTx_Block,
	}
	body := &types.Body{
		Transactions:             types.Transactions{tx},
		BlobSidecars:             []*types.BlobTxSidecar{sidecar},
		Uncles:                   []*types.Header{uncle},
		CommonTxAdmissionBatches: []*types.CommonTxAdmissionBatch{batch},
		CommonTxAdmissionRefs:    []types.CommonTxAdmissionRef{ref},
		CommonTxRewards:          []*types.CommonTxReward{reward},
	}
	parent := types.NewBlockWithHeader(&types.Header{
		UncleHash:   types.EmptyUncleHash,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
		Difficulty:  big.NewInt(1),
		Number:      big.NewInt(0),
		GasLimit:    30_000_000,
		BaseFee:     big.NewInt(1),
		BlockType:   types.FastTx_Block,
	})
	header := &types.Header{
		ParentHash:            parent.Hash(),
		UncleHash:             types.CalcUncleHash(body.Uncles),
		Root:                  common.HexToHash("0x04"),
		TxHash:                types.DeriveSha(types.Transactions(body.Transactions), new(trie.Trie)),
		ReceiptHash:           types.EmptyRootHash,
		Difficulty:            big.NewInt(1),
		Number:                big.NewInt(1),
		GasLimit:              30_000_000,
		GasUsed:               tx.Gas(),
		Time:                  1_750_000_001,
		BaseFee:               big.NewInt(1),
		CommonTxAdmissionRoot: types.DeriveCommonTxAdmissionRoot(body.CommonTxAdmissionBatches, body.CommonTxAdmissionRefs),
		CommonTxRewardRoot:    types.DeriveCommonTxRewardRoot(body.CommonTxRewards),
		BlockType:             types.FastTx_Block,
	}
	return body, header, parent
}

func testFetcherForCompletingBody(parent *types.Block, header *types.Header, peer string) (*BlockFetcher, <-chan types.Blocks, <-chan common.Hash) {
	imports := make(chan types.Blocks, 2)
	cleaned := make(chan common.Hash, 2)
	fetcher := NewBlockFetcher(
		false,
		func(common.Hash) *types.Header { return nil },
		func(hash common.Hash) *types.Block {
			if hash == parent.Hash() {
				return parent
			}
			return nil
		},
		func(*types.Header) error { return nil },
		func(*types.Block, bool) {},
		func() uint64 { return parent.NumberU64() },
		func([]*types.Header) (int, error) { return 0, nil },
		func(blocks types.Blocks) (int, error) {
			imports <- append(types.Blocks(nil), blocks...)
			return len(blocks), nil
		},
		func(string) {},
	)
	fetcher.completing[header.Hash()] = &blockAnnounce{
		origin: peer,
		header: header,
		time:   time.Now(),
	}
	fetcher.announceChangeHook = func(hash common.Hash, added bool) {
		if !added {
			cleaned <- hash
		}
	}
	fetcher.Start()
	return fetcher, imports, cleaned
}

func TestFilterBodiesReconstructsRequestedBlobBlockAtomically(t *testing.T) {
	body, header, parent := testFetcherBlobBody()
	const peer = "blob-peer"
	fetcher, imports, cleaned := testFetcherForCompletingBody(parent, header, peer)
	defer fetcher.Stop()

	unknown := new(types.Body)
	remaining := fetcher.FilterBodies(peer, []*types.Body{unknown, body}, time.Now())
	if len(remaining) != 1 || remaining[0] != unknown {
		t.Fatalf("remaining bodies = %#v, want only the unrelated body", remaining)
	}

	var imported *types.Block
	select {
	case blocks := <-imports:
		if len(blocks) != 1 {
			t.Fatalf("import callback received %d blocks, want 1", len(blocks))
		}
		imported = blocks[0]
	case <-time.After(bodySidecarPipelineTestTimeout):
		t.Fatal("timed out waiting for reconstructed block import")
	}
	if imported.Hash() != header.Hash() {
		t.Fatalf("imported block hash = %s, want %s", imported.Hash(), header.Hash())
	}
	if len(imported.Transactions()) != 1 || imported.Transactions()[0].Hash() != body.Transactions[0].Hash() {
		t.Fatal("imported block did not preserve the requested blob transaction")
	}
	if imported.Transactions()[0].BlobSidecar() == nil {
		t.Fatal("imported blob transaction has no attached sidecar")
	}
	if got := imported.BlobSidecars(); len(got) != 1 || !reflect.DeepEqual(got[0], body.BlobSidecars[0]) {
		t.Fatal("imported block did not preserve the authenticated v0 blob sidecar")
	}
	if len(imported.Uncles()) != 1 || imported.Uncles()[0].Hash() != body.Uncles[0].Hash() {
		t.Fatal("imported block did not preserve the body uncle")
	}
	if !reflect.DeepEqual(imported.CommonTxAdmissionBatches(), body.CommonTxAdmissionBatches) ||
		!reflect.DeepEqual(imported.CommonTxAdmissionRefs(), body.CommonTxAdmissionRefs) ||
		!reflect.DeepEqual(imported.CommonTxRewards(), body.CommonTxRewards) {
		t.Fatal("imported block did not preserve the atomic six-field body metadata")
	}

	select {
	case hash := <-cleaned:
		if hash != header.Hash() {
			t.Fatalf("cleaned request hash = %s, want %s", hash, header.Hash())
		}
	case <-time.After(bodySidecarPipelineTestTimeout):
		t.Fatal("timed out waiting for completed request cleanup")
	}
}

func TestFilterBodiesDoesNotImportMismatchedBlobSidecar(t *testing.T) {
	body, header, parent := testFetcherBlobBody()
	body.BlobSidecars[0] = body.BlobSidecars[0].Copy()
	body.BlobSidecars[0].Commitments[0][0] ^= 0xff

	const peer = "bad-blob-peer"
	fetcher, imports, _ := testFetcherForCompletingBody(parent, header, peer)
	defer fetcher.Stop()

	remaining := fetcher.FilterBodies(peer, []*types.Body{body}, time.Now())
	if len(remaining) != 1 || remaining[0] != body {
		t.Fatalf("remaining bodies = %#v, want rejected body returned unchanged", remaining)
	}
	select {
	case blocks := <-imports:
		t.Fatalf("mismatched sidecar reached import callback with %d blocks", len(blocks))
	case <-time.After(100 * time.Millisecond):
	}
}
