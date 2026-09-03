package ethclient

import (
	"bytes"
	"context"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/rpc"
)

type sendRawTransactionCapture struct {
	raw []hexutil.Bytes
}

func (c *sendRawTransactionCapture) SendRawTransaction(_ context.Context, raw hexutil.Bytes) error {
	c.raw = append(c.raw, append(hexutil.Bytes(nil), raw...))
	return nil
}

func TestSendTransactionUsesCanonicalEIP2718Envelope(t *testing.T) {
	capture := new(sendRawTransactionCapture)
	server := rpc.NewServer()
	if err := server.RegisterName("eth", capture); err != nil {
		t.Fatal(err)
	}
	rpcClient := rpc.DialInProc(server)
	client := NewClient(rpcClient)
	t.Cleanup(func() {
		client.Close()
		server.Stop()
	})

	chainID := big.NewInt(1)
	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	transactions := types.Transactions{
		types.NewTransaction(0, to, new(big.Int), 21_000, big.NewInt(1), nil),
		types.NewTx(&types.AccessListTx{ChainID: chainID, GasPrice: big.NewInt(1), Gas: 21_000, To: &to, Value: new(big.Int)}),
		types.NewTx(&types.DynamicFeeTx{ChainID: chainID, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 21_000, To: &to, Value: new(big.Int)}),
		types.NewTx(&types.BlobTx{ChainID: chainID, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 21_000, To: to, Value: new(big.Int), BlobFeeCap: big.NewInt(1), BlobHashes: []common.Hash{{types.BlobCommitmentVersionKZG}}}),
		types.NewTx(&types.SetCodeTx{ChainID: chainID, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 21_000, To: to, Value: new(big.Int)}),
	}
	for _, tx := range transactions {
		capture.raw = nil
		if err := client.SendTransaction(context.Background(), tx); err != nil {
			t.Fatalf("type %#x send failed: %v", tx.Type(), err)
		}
		want, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if len(capture.raw) != 1 || !bytes.Equal(capture.raw[0], want) {
			t.Fatalf("type %#x raw RPC payload = %x, want canonical %x", tx.Type(), capture.raw, want)
		}
		if tx.Type() != types.LegacyTxType && (len(capture.raw[0]) == 0 || capture.raw[0][0] != tx.Type()) {
			t.Fatalf("type %#x payload is not a canonical typed envelope: %x", tx.Type(), capture.raw[0])
		}
	}
}

func TestSendTransactionPreservesBlobPooledSidecar(t *testing.T) {
	capture := new(sendRawTransactionCapture)
	server := rpc.NewServer()
	if err := server.RegisterName("eth", capture); err != nil {
		t.Fatal(err)
	}
	rpcClient := rpc.DialInProc(server)
	client := NewClient(rpcClient)
	t.Cleanup(func() {
		client.Close()
		server.Stop()
	})

	to := common.HexToAddress("0x4844000000000000000000000000000000000003")
	var commitment types.KZGCommitment
	commitment[0] = 1
	sidecar := &types.BlobTxSidecar{
		Blobs:       []types.Blob{make(types.Blob, 131072)},
		Commitments: []types.KZGCommitment{commitment},
		Proofs:      []types.KZGProof{{}},
	}
	tx := types.NewTx(&types.BlobTx{
		ChainID: big.NewInt(1), GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 100_000,
		To: to, Value: new(big.Int), BlobFeeCap: big.NewInt(1), BlobHashes: sidecar.BlobHashes(),
	}).WithBlobSidecar(sidecar)

	if err := client.SendTransaction(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	want, err := tx.MarshalPooledBinary()
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(want, canonical) {
		t.Fatal("test type-3 pooled envelope unexpectedly omitted its sidecar")
	}
	if len(capture.raw) != 1 || !bytes.Equal(capture.raw[0], want) {
		t.Fatal("ethclient sent a sidecar-free type-3 transaction")
	}
}
