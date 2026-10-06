// Copyright 2026 Cypher browser contributors.
// SPDX-License-Identifier: LGPL-3.0-or-later

package types

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"reflect"
	"sync"
	"testing"

	"github.com/cypherium/cypher/common"
	kzg4844 "github.com/cypherium/cypher/crypto/kzg4844"
	"github.com/cypherium/cypher/rlp"
)

func browserEncodingTestHeader() *Header {
	return &Header{
		ParentHash: common.Hash{1}, UncleHash: common.Hash{2}, Coinbase: common.Address{3},
		Root: common.Hash{4}, TxHash: common.Hash{5}, ReceiptHash: common.Hash{6}, Bloom: Bloom{7},
		Difficulty: big.NewInt(8), Number: big.NewInt(9), GasLimit: 10, GasUsed: 11, Time: 12,
		Extra: []byte{13, 14}, MixDigest: common.Hash{15}, Nonce: BlockNonce{16}, BaseFee: big.NewInt(17),
		WithdrawalsHash: common.Hash{18}, BlobGasUsed: 19, ExcessBlobGas: 20,
		ParentBeaconRoot: common.Hash{21}, RequestsHash: common.Hash{22},
		CommonTxAdmissionRoot: common.Hash{23}, CommonTxRewardRoot: common.Hash{24},
		BlockType: 25, KeyHash: common.Hash{26}, KeyInfo: []byte{27, 28},
		SignInfo: SignInfo{Signature: []byte{29}, Exceptions: []byte{30}, ViewID: common.Hash{31},
			LeaderID: "test-leader", ViewNumber: 32, ExtraHash: common.Hash{33}, ParentQCID: common.Hash{34}, FHSFinalityProof: []byte{35, 36}},
	}
}

func browserEncodingTestBlock() *Block {
	return &Block{header: browserEncodingTestHeader(),
		uncles: []*Header{browserEncodingTestHeader()},
		commonTxAdmissionBatches: []*CommonTxAdmissionBatch{{Version: CommonRPCVersionV2,
			ChainID: big.NewInt(1), GenesisHash: common.Hash{2}, TxRoot: common.Hash{3}, AdmissionID: common.Hash{4},
			Miner: common.Address{5}, RewardRecipient: common.Address{6}, KeyBlockNumber: 7, Timestamp: 8,
			TxHashes: []common.Hash{{9}, {10}}, Signature: []byte{11, 12}}},
		commonTxAdmissionRefs: []CommonTxAdmissionRef{{Batch: 1, Item: 2}, {Batch: 3, Item: 4}},
		commonTxRewards: []*CommonTxReward{{Version: CommonRPCVersionV2, TxHash: common.Hash{1},
			Approver: common.Address{2}, RewardRecipient: common.Address{3}, ApproverReward: big.NewInt(4), Burn: big.NewInt(5)}},
	}
}

func browserAssertCanonical(t *testing.T, b *Block) []byte {
	t.Helper()
	var expected bytes.Buffer
	if err := b.EncodeRLP(&expected); err != nil {
		t.Fatalf("existing encoder: %v", err)
	}
	var actual bytes.Buffer
	if err := b.EncodeBrowserRLP(context.Background(), &actual, BrowserBlockEncodingLimits{}); err != nil {
		t.Fatalf("bounded encoder: %v", err)
	}
	if !bytes.Equal(expected.Bytes(), actual.Bytes()) {
		t.Fatalf("canonical bytes differ: existing=%x bounded=%x", expected.Bytes(), actual.Bytes())
	}
	size, err := b.BrowserBlockRLPSize(context.Background(), BrowserBlockEncodingLimits{})
	if err != nil || size != uint64(actual.Len()) {
		t.Fatalf("size=%d error=%v actual=%d", size, err, actual.Len())
	}
	return actual.Bytes()
}

func TestBrowserBoundedCanonicalAllExecutionTypes(t *testing.T) {
	to := common.Address{20}
	access := AccessList{{Address: common.Address{21}, StorageKeys: []common.Hash{{22}, {23}}}}
	for _, n := range []int{0, 1, 55, 56, 255, 256} {
		b := browserEncodingTestBlock()
		data := bytes.Repeat([]byte{0x7f}, n)
		b.transactions = Transactions{
			{data: &txdata{AccountNonce: 1, Price: big.NewInt(2), GasLimit: 3, Recipient: &to, Amount: big.NewInt(4), Payload: data, V: big.NewInt(27), R: big.NewInt(6), S: big.NewInt(7)}},
			{data: &AccessListTx{ChainID: big.NewInt(1), Nonce: 2, GasPrice: big.NewInt(3), Gas: 4, To: &to, Value: big.NewInt(5), Data: data, AccessList: access, V: big.NewInt(1), R: big.NewInt(6), S: big.NewInt(7)}},
			{data: &DynamicFeeTx{ChainID: big.NewInt(1), Nonce: 2, GasTipCap: big.NewInt(3), GasFeeCap: big.NewInt(4), Gas: 5, To: nil, Value: big.NewInt(6), Data: data, AccessList: access, V: big.NewInt(0), R: big.NewInt(7), S: big.NewInt(8)}},
			{data: &SetCodeTx{ChainID: big.NewInt(1), Nonce: 2, GasTipCap: big.NewInt(3), GasFeeCap: big.NewInt(4), Gas: 5, To: to, Value: big.NewInt(6), Data: data, AccessList: access,
				AuthList: []SetCodeAuthorization{{ChainID: big.NewInt(7), Address: common.Address{8}, Nonce: 9, V: big.NewInt(1), R: big.NewInt(10), S: big.NewInt(11)}}, V: big.NewInt(0), R: big.NewInt(12), S: big.NewInt(13)}},
		}
		encoded := browserAssertCanonical(t, b)
		var components []rlp.RawValue
		if err := rlp.DecodeBytes(encoded, &components); err != nil || len(components) != 7 {
			t.Fatalf("lost external block component: %d %v", len(components), err)
		}
		var decodedHeader Header
		if err := rlp.DecodeBytes(components[0], &decodedHeader); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decodedHeader.SignInfo.FHSFinalityProof, b.header.SignInfo.FHSFinalityProof) || decodedHeader.SignInfo.ExtraHash != b.header.SignInfo.ExtraHash || decodedHeader.SignInfo.ParentQCID != b.header.SignInfo.ParentQCID {
			t.Fatal("lost FHS signature metadata")
		}
	}
}

func TestBrowserBoundedBlobSidecarsCanonical(t *testing.T) {
	for _, version := range []byte{BlobSidecarVersion0, BlobSidecarVersion1} {
		b := browserEncodingTestBlock()
		proofs := 1
		if version == BlobSidecarVersion1 {
			proofs = BlobCellProofsPerBlob
		}
		s := &BlobTxSidecar{Version: version, Blobs: []Blob{make(Blob, len(kzg4844.Blob{}))}, Commitments: []KZGCommitment{{1, 2, 3}}, Proofs: make([]KZGProof, proofs)}
		s.Blobs[0][0] = 42
		s.Blobs[0][len(s.Blobs[0])-1] = 43
		s.Proofs[proofs-1][47] = 44
		b.transactions = Transactions{{data: &BlobTx{ChainID: big.NewInt(1), Nonce: 19, GasTipCap: big.NewInt(2), GasFeeCap: big.NewInt(3), Gas: 4, To: common.Address{5}, Value: big.NewInt(6),
			Data: []byte{7}, AccessList: AccessList{{Address: common.Address{20}, StorageKeys: []common.Hash{{21}, {22}}}}, BlobFeeCap: big.NewInt(8), BlobHashes: []common.Hash{KZGToVersionedHash(s.Commitments[0])},
			Sidecar: s, V: big.NewInt(1), R: big.NewInt(23), S: big.NewInt(24)}}}
		b.blobSidecars = []*BlobTxSidecar{s}
		browserAssertCanonical(t, b)
		// Bound checks precede commitment hashing and output. No 32MiB fixture.
		var w bytes.Buffer
		if err := b.EncodeBrowserRLP(context.Background(), &w, BrowserBlockEncodingLimits{MaxFieldBytes: 1024}); !errors.Is(err, ErrBrowserBlockLimit) || w.Len() != 0 {
			t.Fatalf("blob admission must fail before writing: %v bytes=%d", err, w.Len())
		}
	}
}

func TestBrowserBoundedNilAndIntegerCanonical(t *testing.T) {
	b := browserEncodingTestBlock()
	b.header.BaseFee = nil
	b.header.Difficulty = nil
	b.header.Number = nil
	b.header.SignInfo.LeaderID = "a"
	b.transactions = Transactions{{data: &txdata{}}}
	b.commonTxAdmissionBatches[0].ChainID = nil
	b.commonTxRewards[0].ApproverReward = nil
	b.commonTxRewards[0].Burn = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	browserAssertCanonical(t, b)
	// Nil big.Int and integer zero have the same canonical empty-string encoding.
	b.header.BaseFee = new(big.Int)
	b.header.Difficulty = new(big.Int)
	b.header.Number = new(big.Int)
	b.transactions[0].data.(*txdata).Price = new(big.Int)
	browserAssertCanonical(t, b)
}

func TestBrowserBoundedNumericPrefixBoundaries(t *testing.T) {
	for _, n := range []uint64{0, 1, 127, 128, 255, 256, 65535, 65536, ^uint64(0)} {
		b := browserEncodingTestBlock()
		b.header.Time = n
		b.header.SignInfo.ViewNumber = n
		b.header.Difficulty = new(big.Int).SetUint64(n)
		b.header.BaseFee = new(big.Int).SetUint64(n)
		browserAssertCanonical(t, b)
	}
}

func TestBrowserBoundedBlobMismatchBeforeOutput(t *testing.T) {
	b := browserEncodingTestBlock()
	s := &BlobTxSidecar{Blobs: []Blob{make(Blob, len(kzg4844.Blob{}))}, Commitments: []KZGCommitment{{1}}, Proofs: []KZGProof{{2}}}
	b.transactions = Transactions{{data: &BlobTx{BlobHashes: []common.Hash{{3}}}}}
	b.blobSidecars = []*BlobTxSidecar{s}
	var w bytes.Buffer
	if err := b.EncodeBrowserRLP(context.Background(), &w, BrowserBlockEncodingLimits{}); !errors.Is(err, ErrBrowserBlockShape) || w.Len() != 0 {
		t.Fatalf("commitment mismatch: %v written=%d", err, w.Len())
	}
}

func TestBrowserBoundedEmptySidecarMatchesPinnedSchema(t *testing.T) {
	for _, version := range []byte{BlobSidecarVersion0, BlobSidecarVersion1} {
		b := browserEncodingTestBlock()
		s := &BlobTxSidecar{Version: version}
		b.transactions = Transactions{{data: &BlobTx{Sidecar: s}}}
		b.blobSidecars = []*BlobTxSidecar{s}
		browserAssertCanonical(t, b)
	}
}

func TestBrowserBoundedAuthorizationParityMatchesPinnedCheck(t *testing.T) {
	for _, n := range []int64{0, 1, 255, 256} {
		b := browserEncodingTestBlock()
		tx := &Transaction{data: &SetCodeTx{AuthList: []SetCodeAuthorization{{V: big.NewInt(n)}}}}
		b.transactions = Transactions{tx}
		existing := tx.ValidateIntegerBounds()
		var w bytes.Buffer
		bounded := b.EncodeBrowserRLP(context.Background(), &w, BrowserBlockEncodingLimits{})
		if (existing == nil) != (bounded == nil) {
			t.Fatalf("parity bounds differ for %d: existing=%v bounded=%v", n, existing, bounded)
		}
		if n > 255 && (!errors.Is(bounded, ErrBrowserBlockShape) || w.Len() != 0) {
			t.Fatalf("wide parity must fail before writing: %v", bounded)
		}
		if existing == nil {
			browserAssertCanonical(t, b)
		}
	}
}

type browserChunkWriter struct {
	calls, max       int
	postCancelWrites int
	cancelled        bool
	cancel           context.CancelFunc
}

func (w *browserChunkWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.cancelled {
		w.postCancelWrites++
	}
	if len(p) > w.max {
		w.max = len(p)
	}
	if w.cancel != nil && len(p) == browserRLPWriteChunk {
		w.cancel()
		w.cancelled = true
	}
	return len(p), nil
}

func TestBrowserBoundedChunkCancellation(t *testing.T) {
	b := browserEncodingTestBlock()
	b.transactions = Transactions{{data: &txdata{Payload: make([]byte, 100000)}}}
	ctx, cancel := context.WithCancel(context.Background())
	w := &browserChunkWriter{cancel: cancel}
	if err := b.EncodeBrowserRLP(ctx, w, BrowserBlockEncodingLimits{}); !errors.Is(err, context.Canceled) || w.max != browserRLPWriteChunk || w.postCancelWrites != 0 {
		t.Fatalf("chunk cancellation: %v max=%d writes-after-cancel=%d", err, w.max, w.postCancelWrites)
	}
	w = &browserChunkWriter{}
	if err := b.EncodeBrowserRLP(context.Background(), w, BrowserBlockEncodingLimits{}); err != nil || w.max > browserRLPWriteChunk {
		t.Fatalf("chunk limit: %v max=%d", err, w.max)
	}
}

func TestBrowserBoundedAggregateAcrossSiblingLists(t *testing.T) {
	b := browserEncodingTestBlock()
	// All seven sibling components together have 106 charged RLP nodes.
	var accepted bytes.Buffer
	if err := b.EncodeBrowserRLP(context.Background(), &accepted, BrowserBlockEncodingLimits{MaxElements: 106}); err != nil {
		t.Fatalf("exact aggregate boundary should pass: %v", err)
	}
	var rejected bytes.Buffer
	if err := b.EncodeBrowserRLP(context.Background(), &rejected, BrowserBlockEncodingLimits{MaxElements: 105}); !errors.Is(err, ErrBrowserBlockLimit) || rejected.Len() != 0 {
		t.Fatalf("aggregate overflow must precede writes: %v bytes=%d", err, rejected.Len())
	}
}

type browserUnknownTx struct{ TxData }

func TestBrowserBoundedRejectsBeforeWriting(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(*Block)
		limits BrowserBlockEncodingLimits
		want   error
	}{
		{"late-signature-field-budget", func(b *Block) { b.uncles[0].SignInfo.FHSFinalityProof = make([]byte, 257) }, BrowserBlockEncodingLimits{MaxFieldBytes: 256}, ErrBrowserBlockLimit},
		{"encoded-byte-budget", func(b *Block) {}, BrowserBlockEncodingLimits{MaxEncodedBytes: 64}, ErrBrowserBlockLimit},
		{"aggregate-elements", func(b *Block) {}, BrowserBlockEncodingLimits{MaxElements: 8}, ErrBrowserBlockLimit},
		{"loosen-limit", func(b *Block) {}, BrowserBlockEncodingLimits{MaxElements: 65537}, ErrBrowserBlockLimit},
		{"nil-header", func(b *Block) { b.header = nil }, BrowserBlockEncodingLimits{}, ErrBrowserBlockShape},
		{"nil-tx", func(b *Block) { b.transactions = Transactions{nil} }, BrowserBlockEncodingLimits{}, ErrBrowserBlockShape},
		{"typed-nil", func(b *Block) { b.transactions = Transactions{{data: (*AccessListTx)(nil)}} }, BrowserBlockEncodingLimits{}, ErrBrowserBlockShape},
		{"negative", func(b *Block) { b.commonTxRewards[0].Burn = big.NewInt(-1) }, BrowserBlockEncodingLimits{}, ErrBrowserBlockShape},
		{"wide-int", func(b *Block) { b.header.BaseFee = new(big.Int).Lsh(big.NewInt(1), 256) }, BrowserBlockEncodingLimits{}, ErrBrowserBlockShape},
		{"recipient-rule", func(b *Block) { b.commonTxRewards[0].RewardRecipient = b.commonTxRewards[0].Approver }, BrowserBlockEncodingLimits{}, ErrBrowserBlockShape},
		{"retired-common-version", func(b *Block) { b.commonTxRewards[0].Version = 1 }, BrowserBlockEncodingLimits{}, ErrBrowserBlockUnsupported},
		{"retired-native", func(b *Block) { b.transactions = Transactions{{data: &NativeTxV1{}}} }, BrowserBlockEncodingLimits{}, ErrBrowserBlockUnsupported},
		{"unknown-type-no-dispatch", func(b *Block) { b.transactions = Transactions{{data: &browserUnknownTx{}}} }, BrowserBlockEncodingLimits{}, ErrBrowserBlockUnsupported},
		{"sidecar-on-no-blob", func(b *Block) { b.blobSidecars = []*BlobTxSidecar{{Version: BlobSidecarVersion0}} }, BrowserBlockEncodingLimits{}, ErrBrowserBlockShape},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := browserEncodingTestBlock()
			tc.edit(b)
			var w bytes.Buffer
			if err := b.EncodeBrowserRLP(context.Background(), &w, tc.limits); !errors.Is(err, tc.want) || w.Len() != 0 {
				t.Fatalf("err=%v want=%v written=%d", err, tc.want, w.Len())
			}
		})
	}
}

type browserFailingWriter struct {
	calls  int
	err    error
	short  bool
	cancel context.CancelFunc
}

func (w *browserFailingWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.cancel != nil {
		w.cancel()
		return len(p), nil
	}
	if w.short {
		return len(p) - 1, nil
	}
	return 0, w.err
}

func TestBrowserBoundedWriterFailureAndCancellation(t *testing.T) {
	b := browserEncodingTestBlock()
	sentinel := errors.New("owned writer failure")
	for _, short := range []bool{false, true} {
		w := &browserFailingWriter{short: short, err: sentinel}
		want := sentinel
		if short {
			want = io.ErrShortWrite
		}
		if err := b.EncodeBrowserRLP(context.Background(), w, BrowserBlockEncodingLimits{}); !errors.Is(err, want) || w.calls != 1 {
			t.Fatalf("write failure must be sticky: %v calls=%d", err, w.calls)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &browserFailingWriter{cancel: cancel}
	if err := b.EncodeBrowserRLP(ctx, w, BrowserBlockEncodingLimits{}); !errors.Is(err, context.Canceled) || w.calls != 1 {
		t.Fatalf("cancel after prefix: %v calls=%d", err, w.calls)
	}
	var buf bytes.Buffer
	if err := b.EncodeBrowserRLP(ctx, &buf, BrowserBlockEncodingLimits{}); !errors.Is(err, context.Canceled) || buf.Len() != 0 {
		t.Fatalf("pre-cancelled must not write: %v", err)
	}
}

func TestBrowserBoundedConcurrentImmutableInput(t *testing.T) {
	b := browserEncodingTestBlock()
	var expected bytes.Buffer
	if err := b.EncodeRLP(&expected); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			var output bytes.Buffer
			if err := b.EncodeBrowserRLP(context.Background(), &output, BrowserBlockEncodingLimits{}); err != nil || !bytes.Equal(output.Bytes(), expected.Bytes()) {
				t.Errorf("immutable concurrent input: %v", err)
			}
		}()
	}
	group.Wait()
}

func TestBrowserBoundedKeyBodyTagWhitespaceCompatibility(t *testing.T) {
	// Only the separator inside two preexisting metadata tag literals changed.
	// A dynamic old tag keeps that malformed historical spelling out of Go field
	// declarations, while testing its actual reflect/JSON/RLP behavior.
	body := KeyBlockBody{LeaderPubKey: "example-leader", LeaderAddress: "leader-address",
		InPubKey: "example-in", InAddress: "in-address", OutPubKey: "example-out", OutAddress: "out-address"}
	current := reflect.TypeOf(body)
	fields := make([]reflect.StructField, current.NumField())
	for i := range fields {
		fields[i] = current.Field(i)
		fields[i].Offset = 0
		fields[i].Index = nil
		name := fields[i].Name
		if name == "InPubKey" || name == "OutPubKey" {
			old := string(fields[i].Tag)
			// The original separator was 12 ASCII spaces followed by one TAB.
			jsonName := fields[i].Tag.Get("json")
			old = "json:\"" + jsonName + "\"            " + "\t" + "gencodec:\"required\""
			fields[i].Tag = reflect.StructTag(old)
			if fields[i].Tag.Get("json") != current.Field(i).Tag.Get("json") || fields[i].Tag.Get("rlp") != current.Field(i).Tag.Get("rlp") {
				t.Fatal("JSON or RLP tag names changed")
			}
			if current.Field(i).Tag.Get("gencodec") != "required" {
				t.Fatal("corrected generation metadata is not readable")
			}
		}
	}
	oldValue := reflect.New(reflect.StructOf(fields)).Elem()
	for i := 0; i < current.NumField(); i++ {
		oldValue.Field(i).Set(reflect.ValueOf(body).Field(i))
	}
	beforeJSON, err := json.Marshal(oldValue.Interface())
	if err != nil {
		t.Fatal(err)
	}
	afterJSON, err := json.Marshal(body)
	if err != nil || !bytes.Equal(beforeJSON, afterJSON) {
		t.Fatalf("JSON changed: %v before=%s after=%s", err, beforeJSON, afterJSON)
	}
	beforeRLP, err := rlp.EncodeToBytes(oldValue.Interface())
	if err != nil {
		t.Fatal(err)
	}
	afterRLP, err := rlp.EncodeToBytes(body)
	if err != nil || !bytes.Equal(beforeRLP, afterRLP) {
		t.Fatalf("RLP changed: %v", err)
	}
}
