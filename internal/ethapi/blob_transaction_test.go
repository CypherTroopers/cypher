package ethapi

import (
	"bytes"
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/types"
	kzg "github.com/cypherium/cypher/crypto/kzg4844"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

func managedBlobTestArgs() SendTxArgs {
	to := common.HexToAddress("0x4844000000000000000000000000000000000003")
	txType := hexutil.Uint64(types.BlobTxType)
	nonce := hexutil.Uint64(0)
	gas := hexutil.Uint64(100_000)
	feeCap := (*hexutil.Big)(big.NewInt(20))
	tipCap := (*hexutil.Big)(big.NewInt(1))
	blobFeeCap := (*hexutil.Big)(big.NewInt(2))
	var blob kzg.Blob
	for offset, scalar := 0, byte(1); offset < len(blob); offset, scalar = offset+32, scalar+1 {
		blob[offset+31] = scalar
		if scalar == 250 {
			scalar = 0
		}
	}
	return SendTxArgs{
		From: common.HexToAddress("0x4844000000000000000000000000000000000001"),
		To:   &to, Type: &txType, Nonce: &nonce, Gas: &gas,
		MaxFeePerGas: feeCap, MaxPriorityFeePerGas: tipCap,
		MaxFeePerBlobGas: blobFeeCap, Blobs: []kzg.Blob{blob},
	}
}

func TestFillTransactionBuildsVerifiedPooledBlobSidecar(t *testing.T) {
	args := managedBlobTestArgs()
	api := NewPublicTransactionPoolAPI(newLondonAPITestBackend(), new(AddrLocker))
	result, err := api.FillTransaction(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	if result.Tx.Type() != types.BlobTxType || result.Tx.BlobSidecar() == nil {
		t.Fatalf("filled transaction did not retain type-3 sidecar: %#v", result.Tx)
	}
	if err := result.Tx.VerifyBlobSidecar(result.Tx.BlobSidecar(), types.KZGBlobVerifier{}); err != nil {
		t.Fatalf("filled sidecar verification failed: %v", err)
	}
	canonical, err := result.Tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(result.Raw, canonical) {
		t.Fatal("eth_fillTransaction returned sidecar-free canonical bytes for a blob transaction")
	}
	want, err := result.Tx.MarshalPooledBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Raw, want) {
		t.Fatal("eth_fillTransaction raw bytes do not match the EIP-4844 pooled envelope")
	}
	var decoded types.Transaction
	if err := decoded.UnmarshalBinary(result.Raw); err != nil {
		t.Fatalf("decode pooled blob transaction: %v", err)
	}
	if decoded.BlobSidecar() == nil || decoded.Hash() != result.Tx.Hash() {
		t.Fatal("pooled blob transaction lost its sidecar or changed execution hash")
	}
}

func TestManagedBlobSidecarRejectsMismatchedCountsAndProof(t *testing.T) {
	args := managedBlobTestArgs()
	args.Commitments = make([]kzg.Commitment, 2)
	if err := args.setBlobSidecarDefaults(context.Background(), types.BlobSidecarVersion0); err == nil || !strings.Contains(err.Error(), "commitment count") {
		t.Fatalf("commitment mismatch error = %v", err)
	}

	args = managedBlobTestArgs()
	if err := args.setBlobSidecarDefaults(context.Background(), types.BlobSidecarVersion0); err != nil {
		t.Fatal(err)
	}
	args.Proofs[0][0] ^= 0x01
	if err := args.setBlobSidecarDefaults(context.Background(), types.BlobSidecarVersion0); err == nil || !strings.Contains(err.Error(), "verify blob proof") {
		t.Fatalf("invalid proof error = %v", err)
	}
}

func TestManagedBlobTransactionRequiresPropagationBlobs(t *testing.T) {
	args := managedBlobTestArgs()
	args.Blobs = nil
	args.Commitments = nil
	args.Proofs = nil
	args.BlobVersionedHashes = []common.Hash{{types.BlobCommitmentVersionKZG}}
	if err := args.setBlobSidecarDefaults(context.Background(), types.BlobSidecarVersion0); err == nil || !strings.Contains(err.Error(), "requires blobs") {
		t.Fatalf("missing blobs error = %v", err)
	}
}

func TestFillTransactionBuildsOsakaCellProofSidecar(t *testing.T) {
	args := managedBlobTestArgs()
	backend := newLondonAPITestBackend()
	zero := uint64(0)
	modern := backend.config.ModernForkConfig()
	modern.CancunTime = &zero
	modern.PragueTime = &zero
	modern.OsakaTime = &zero
	api := NewPublicTransactionPoolAPI(backend, new(AddrLocker))
	result, err := api.FillTransaction(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	sidecar := result.Tx.BlobSidecar()
	if sidecar == nil || sidecar.Version != types.BlobSidecarVersion1 {
		t.Fatalf("Osaka sidecar version = %#v", sidecar)
	}
	if got, want := len(sidecar.Proofs), kzg.CellProofsPerBlob*len(sidecar.Blobs); got != want {
		t.Fatalf("Osaka proof count = %d, want %d", got, want)
	}
	if err := result.Tx.VerifyBlobSidecarVersion(sidecar, types.BlobSidecarVersion1, types.KZGBlobVerifier{}); err != nil {
		t.Fatalf("filled Osaka sidecar verification failed: %v", err)
	}
	var fields []rlp.RawValue
	if err := rlp.DecodeBytes(result.Raw[1:], &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 5 {
		t.Fatalf("Osaka RPC returned %d-field pooled wrapper, want 5", len(fields))
	}
}

func TestRPCTxFeeCapIncludesBlobFee(t *testing.T) {
	// Each component is below one ether, but their combined maximum exposure is
	// above the configured one-ether RPC safety cap.
	executionPrice := new(big.Int).Div(big.NewInt(params.Ether), big.NewInt(4))
	blobPrice := new(big.Int).Div(big.NewInt(params.Ether), big.NewInt(2))
	if err := checkTxFeeWithBlob(executionPrice, 3, blobPrice, 1, 1); err == nil {
		t.Fatal("combined execution and blob fee above RPC cap was accepted")
	}
	if err := checkTxFeeWithBlob(executionPrice, 1, blobPrice, 1, 1); err != nil {
		t.Fatalf("combined fee below RPC cap was rejected: %v", err)
	}
}
