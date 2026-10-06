package types

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/rlp"
)

func testBlockBlobSidecar(marker byte) (*Transaction, *BlobTxSidecar) {
	commitment := testKZGCommitment(marker)
	blob := make(Blob, 1<<17)
	blob[0] = marker
	sidecar := &BlobTxSidecar{
		Blobs:       []Blob{blob},
		Commitments: []KZGCommitment{commitment},
		Proofs:      []KZGProof{{marker}},
	}
	return testBlobTxWithHash(KZGToVersionedHash(commitment)), sidecar
}

func testBlobBlockHeader() *Header {
	return &Header{
		ParentHash: common.HexToHash("0x101"),
		Root:       common.HexToHash("0x102"),
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(1),
		GasLimit:   30_000_000,
		BlockType:  FastTx_Block,
	}
}

func TestBlobBlockBodyRLPRoundTripAttachesSidecars(t *testing.T) {
	blobTx, sidecar := testBlockBlobSidecar(1)
	legacy := NewTransaction(0, common.HexToAddress("0x1234"), big.NewInt(1), 21_000, big.NewInt(1), nil)
	block, err := NewBlockWithHeader(testBlobBlockHeader()).WithBodyAndBlobSidecars(
		Transactions{legacy, blobTx}, nil, []*BlobTxSidecar{sidecar},
	)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := blobTx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	encoded := block.EncodeToBytes()
	if len(encoded) == 0 {
		t.Fatal("blob block did not encode")
	}
	decoded := DecodeToBlock(encoded)
	if decoded == nil {
		t.Fatal("blob block did not decode")
	}
	if len(decoded.BlobSidecars()) != 1 || decoded.Transactions()[1].BlobSidecar() == nil {
		t.Fatal("decoded block did not reattach its blob sidecar")
	}
	if got, err := decoded.Transactions()[1].MarshalBinary(); err != nil || !bytes.Equal(got, canonical) {
		t.Fatalf("decoded execution envelope changed: got %x err %v want %x", got, err, canonical)
	}
	if decoded.Transactions()[1].Hash() != blobTx.Hash() {
		t.Fatal("sidecar changed the decoded transaction hash")
	}
	if reencoded := decoded.EncodeToBytes(); !bytes.Equal(reencoded, encoded) {
		t.Fatal("blob block RLP did not round-trip canonically")
	}

	bodyEncoded, err := rlp.EncodeToBytes(block.Body())
	if err != nil {
		t.Fatal(err)
	}
	var body Body
	if err := rlp.DecodeBytes(bodyEncoded, &body); err != nil {
		t.Fatal(err)
	}
	if len(body.BlobSidecars) != 1 || body.Transactions[1].BlobSidecar() == nil {
		t.Fatal("stored body RLP did not reattach its blob sidecar")
	}
}

func TestBlobBlockConstructionRejectsMissingMismatchedAndUnexpectedSidecars(t *testing.T) {
	blobTx, sidecar := testBlockBlobSidecar(2)
	base := NewBlockWithHeader(testBlobBlockHeader())

	if _, err := base.WithBodyAndBlobSidecars(Transactions{blobTx}, nil, nil); !errors.Is(err, ErrBlockBlobSidecarCountMismatch) {
		t.Fatalf("missing sidecar error = %v", err)
	}
	if _, err := base.WithBodyAndBlobSidecars(Transactions{blobTx}, nil, []*BlobTxSidecar{nil}); !errors.Is(err, ErrBlobSidecarMissing) {
		t.Fatalf("nil sidecar error = %v", err)
	}
	if _, err := base.WithBodyAndBlobSidecars(Transactions{blobTx}, nil, []*BlobTxSidecar{sidecar, sidecar}); !errors.Is(err, ErrBlockBlobSidecarCountMismatch) {
		t.Fatalf("sidecar count error = %v", err)
	}
	legacy := NewTransaction(0, common.Address{1}, new(big.Int), 21_000, big.NewInt(1), nil)
	if _, err := base.WithBodyAndBlobSidecars(Transactions{legacy}, nil, []*BlobTxSidecar{sidecar}); !errors.Is(err, ErrBlobTxSidecarOnNonBlobTx) {
		t.Fatalf("sidecar on non-blob error = %v", err)
	}

	malformed, err := rlp.EncodeToBytes(extblock{
		Header: testBlobBlockHeader(), Txs: Transactions{blobTx}, BlobSidecars: nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded Block
	if err := rlp.DecodeBytes(malformed, &decoded); !errors.Is(err, ErrBlockBlobSidecarCountMismatch) {
		t.Fatalf("malformed block decode error = %v", err)
	}
}

func TestBlobBlockCopiesSidecarsAcrossConstructionAndCopies(t *testing.T) {
	blobTx, sidecar := testBlockBlobSidecar(3)
	block, err := NewBlockWithHeader(testBlobBlockHeader()).WithBodyAndBlobSidecars(
		Transactions{blobTx}, nil, []*BlobTxSidecar{sidecar},
	)
	if err != nil {
		t.Fatal(err)
	}
	sidecar.Blobs[0][0] = 0xff
	if got := block.BlobSidecars()[0].Blobs[0][0]; got != 3 {
		t.Fatalf("constructor retained caller blob storage: got %x", got)
	}

	accessorCopy := block.BlobSidecars()
	accessorCopy[0].Blobs[0][0] = 0xee
	if got := block.BlobSidecars()[0].Blobs[0][0]; got != 3 {
		t.Fatalf("BlobSidecars accessor exposed block storage: got %x", got)
	}

	sealed := block.WithSeal(block.Header())
	unsigned := block.CopyOrg()
	body := block.Body()
	withBody := NewBlockWithHeader(block.Header()).WithBody(block.Transactions(), block.Uncles())
	block.Transactions()[0].BlobSidecar().Blobs[0][0] = 0xdd
	for name, got := range map[string]byte{
		"WithSeal": sealed.BlobSidecars()[0].Blobs[0][0],
		"CopyOrg":  unsigned.BlobSidecars()[0].Blobs[0][0],
		"Body":     body.BlobSidecars[0].Blobs[0][0],
		"WithBody": withBody.BlobSidecars()[0].Blobs[0][0],
	} {
		if got != 3 {
			t.Fatalf("%s retained source sidecar storage: got %x", name, got)
		}
	}
}

func TestHotstuffBodyCommitmentIncludesBlobSidecars(t *testing.T) {
	blobTx, sidecarA := testBlockBlobSidecar(4)
	sidecarB := sidecarA.Copy()
	sidecarB.Proofs[0][0] ^= 0xff
	base := NewBlockWithHeader(testBlobBlockHeader())
	blockA, err := base.WithBodyAndBlobSidecars(Transactions{blobTx}, nil, []*BlobTxSidecar{sidecarA})
	if err != nil {
		t.Fatal(err)
	}
	blockB, err := base.WithBodyAndBlobSidecars(Transactions{blobTx}, nil, []*BlobTxSidecar{sidecarB})
	if err != nil {
		t.Fatal(err)
	}
	if blockA.Hash() != blockB.Hash() || blockA.Transactions()[0].Hash() != blockB.Transactions()[0].Hash() {
		t.Fatal("sidecar unexpectedly changed header or transaction hash")
	}
	hashA, _, err := blockA.unsignedHotstuffProposalBodyCommitment()
	if err != nil {
		t.Fatal(err)
	}
	hashB, _, err := blockB.unsignedHotstuffProposalBodyCommitment()
	if err != nil {
		t.Fatal(err)
	}
	if hashA == hashB {
		t.Fatal("HotStuff proposal body commitment omitted blob sidecar bytes")
	}
}
