package eth

import (
	"bytes"
	"math/big"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/rlp"
)

func TestBlockBodiesMsgDecodesStoredSixFieldBody(t *testing.T) {
	tx := types.NewTransaction(
		7,
		common.HexToAddress("0x1000000000000000000000000000000000000001"),
		big.NewInt(23),
		21_000,
		big.NewInt(2_000_000_000),
		[]byte{0xca, 0xfe},
	)
	batch := &types.CommonTxAdmissionBatch{
		ChainID:        big.NewInt(777),
		GenesisHash:    common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		Miner:          common.HexToAddress("0x2000000000000000000000000000000000000002"),
		KeyBlockNumber: 19,
		Timestamp:      1_725_000_123,
		TxHashes:       []common.Hash{tx.Hash()},
		Signature:      bytes.Repeat([]byte{0x5a}, 65),
	}
	batch.TxRoot = types.DeriveCommonTxAdmissionTxRoot(batch.TxHashes)
	batch.AdmissionID = types.CommonTxAdmissionID(batch)
	reference := types.CommonTxAdmissionRef{Batch: 0, Item: 0}
	reward := &types.CommonTxReward{
		TxHash:         tx.Hash(),
		Approver:       common.HexToAddress("0x3000000000000000000000000000000000000003"),
		ApproverReward: big.NewInt(17),
		Burn:           big.NewInt(3),
	}
	body := &types.Body{
		Transactions:             types.Transactions{tx},
		BlobSidecars:             nil,
		Uncles:                   nil,
		CommonTxAdmissionBatches: []*types.CommonTxAdmissionBatch{batch},
		CommonTxAdmissionRefs:    []types.CommonTxAdmissionRef{reference},
		CommonTxRewards:          []*types.CommonTxReward{reward},
	}

	storedBody, err := rlp.EncodeToBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	var storedFields []rlp.RawValue
	if err := rlp.DecodeBytes(storedBody, &storedFields); err != nil {
		t.Fatal(err)
	}
	if len(storedFields) != 6 {
		t.Fatalf("stored body field count = %d, want 6", len(storedFields))
	}
	if !bytes.Equal(storedFields[1], []byte{0xc0}) {
		t.Fatalf("empty BlobSidecars field = %x, want c0", []byte(storedFields[1]))
	}

	payload, err := rlp.EncodeToBytes([]rlp.RawValue{storedBody})
	if err != nil {
		t.Fatal(err)
	}
	msg := p2p.Msg{Code: BlockBodiesMsg, Size: uint32(len(payload)), Payload: bytes.NewReader(payload)}
	var decoded blockBodiesData
	if err := msg.Decode(&decoded); err != nil {
		t.Fatalf("six-field stored body was rejected by BlockBodiesMsg decoder: %v", err)
	}
	if len(decoded) != 1 || decoded[0] == nil {
		t.Fatalf("decoded body count = %d, want one non-nil body", len(decoded))
	}
	got := decoded[0]
	if len(got.Transactions) != 1 || got.Transactions[0].Hash() != tx.Hash() {
		t.Fatal("transaction was not preserved")
	}
	if len(got.Uncles) != 0 {
		t.Fatalf("uncles length = %d, want 0", len(got.Uncles))
	}
	if len(got.CommonTxAdmissionBatches) != 1 || got.CommonTxAdmissionBatches[0].GenesisHash != batch.GenesisHash || got.CommonTxAdmissionBatches[0].AdmissionID != batch.AdmissionID {
		t.Fatal("common transaction admission batch was not preserved")
	}
	if len(got.CommonTxAdmissionRefs) != 1 || got.CommonTxAdmissionRefs[0] != reference {
		t.Fatalf("common transaction admission refs = %#v, want %#v", got.CommonTxAdmissionRefs, []types.CommonTxAdmissionRef{reference})
	}
	if len(got.CommonTxRewards) != 1 || got.CommonTxRewards[0].TxHash != reward.TxHash || got.CommonTxRewards[0].ApproverReward.Cmp(reward.ApproverReward) != 0 || got.CommonTxRewards[0].Burn.Cmp(reward.Burn) != 0 {
		t.Fatal("common transaction reward was not preserved")
	}

	reencoded, err := rlp.EncodeToBytes(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, storedBody) {
		t.Fatalf("BlockBodiesMsg body did not preserve the six-field wire body\n have: %x\n want: %x", reencoded, storedBody)
	}
}

func TestBlockBodiesMsgPreservesBlobSidecarsForBlockReconstruction(t *testing.T) {
	tests := []struct {
		name    string
		version byte
		newTx   func(*testing.T) *types.Transaction
	}{
		{
			name:    "v0",
			version: types.BlobSidecarVersion0,
			newTx: func(t *testing.T) *types.Transaction {
				return testTxQUICBlobTransaction(t, false)
			},
		},
		{
			name:    "v1",
			version: types.BlobSidecarVersion1,
			newTx:   testTxQUICOsakaBlobTransaction,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tx := test.newTx(t)
			originalSidecar := tx.BlobSidecar()
			if originalSidecar == nil || originalSidecar.Version != test.version {
				t.Fatalf("fixture sidecar version = %v, want %d", originalSidecar, test.version)
			}
			storedBody, err := rlp.EncodeToBytes(&types.Body{
				Transactions: types.Transactions{tx},
				BlobSidecars: []*types.BlobTxSidecar{originalSidecar},
			})
			if err != nil {
				t.Fatal(err)
			}
			payload, err := rlp.EncodeToBytes([]rlp.RawValue{storedBody})
			if err != nil {
				t.Fatal(err)
			}
			msg := p2p.Msg{Code: BlockBodiesMsg, Size: uint32(len(payload)), Payload: bytes.NewReader(payload)}
			var decoded blockBodiesData
			if err := msg.Decode(&decoded); err != nil {
				t.Fatalf("six-field blob body was rejected by BlockBodiesMsg decoder: %v", err)
			}
			if len(decoded) != 1 || decoded[0] == nil {
				t.Fatalf("decoded body count = %d, want one non-nil body", len(decoded))
			}
			got := decoded[0]
			if len(got.Transactions) != 1 || got.Transactions[0].Hash() != tx.Hash() {
				t.Fatal("blob transaction execution envelope was not preserved")
			}
			sidecars := got.BlobSidecars
			if len(sidecars) != 1 || sidecars[0] == nil {
				t.Fatalf("decoded BlobSidecars = %#v, want one non-nil sidecar", sidecars)
			}
			if sidecars[0].Version != test.version {
				t.Fatalf("decoded sidecar version = %d, want %d", sidecars[0].Version, test.version)
			}
			if !reflect.DeepEqual(sidecars[0], originalSidecar) {
				t.Fatal("BlockBodiesMsg decode changed the authenticated blob sidecar")
			}

			block, err := types.NewBlockWithHeader(&types.Header{
				Number:   big.NewInt(20),
				GasLimit: 30_000_000,
				BaseFee:  big.NewInt(1),
			}).WithBodyAndBlobSidecars(got.Transactions, got.Uncles, sidecars)
			if err != nil {
				t.Fatalf("WithBodyAndBlobSidecars rejected decoded body: %v", err)
			}
			if len(block.BlobSidecars()) != 1 || len(block.Transactions()) != 1 || block.Transactions()[0].BlobSidecar() == nil {
				t.Fatal("block reconstruction did not reattach the decoded blob sidecar")
			}
			if block.Transactions()[0].Hash() != tx.Hash() || block.Transactions()[0].BlobSidecar().Version != test.version {
				t.Fatal("block reconstruction changed the blob transaction or sidecar version")
			}
			if err := types.VerifyBlobSidecarsForVersion(block.Transactions(), test.version, types.KZGBlobVerifier{}); err != nil {
				t.Fatalf("decoded %s sidecar failed fork-versioned KZG verification: %v", test.name, err)
			}
		})
	}
}
