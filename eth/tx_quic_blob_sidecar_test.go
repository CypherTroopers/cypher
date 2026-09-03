package eth

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	kzg "github.com/cypherium/cypher/crypto/kzg4844"
	"github.com/cypherium/cypher/ethdb/memorydb"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

func testTxQUICValidBlobTuple(t *testing.T) (types.Blob, types.KZGCommitment, types.KZGProof) {
	t.Helper()
	var blob kzg.Blob
	for offset, scalar := 0, byte(1); offset < len(blob); offset, scalar = offset+32, scalar+1 {
		// Every field element stays well below the BLS12-381 modulus.
		blob[offset+31] = scalar
		if scalar == 250 {
			scalar = 0
		}
	}
	commitment, err := kzg.BlobToCommitment(&blob)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := kzg.ComputeBlobProof(&blob, commitment)
	if err != nil {
		t.Fatal(err)
	}
	wireBlob := make(types.Blob, len(blob))
	copy(wireBlob, blob[:])
	var wireCommitment types.KZGCommitment
	copy(wireCommitment[:], commitment[:])
	var wireProof types.KZGProof
	copy(wireProof[:], proof[:])
	return wireBlob, wireCommitment, wireProof
}

func testTxQUICBlobTransaction(t *testing.T, invalidProof bool) *types.Transaction {
	t.Helper()
	blob, commitment, proof := testTxQUICValidBlobTuple(t)
	if invalidProof {
		proof[0] ^= 0xff
	}
	sidecar := &types.BlobTxSidecar{
		Blobs:       []types.Blob{blob},
		Commitments: []types.KZGCommitment{commitment},
		Proofs:      []types.KZGProof{proof},
	}
	to := common.HexToAddress("0x4844000000000000000000000000000000000003")
	return types.NewTx(&types.BlobTx{
		ChainID:    big.NewInt(1337),
		Nonce:      1,
		GasTipCap:  big.NewInt(1),
		GasFeeCap:  big.NewInt(2),
		Gas:        100_000,
		To:         to,
		Value:      new(big.Int),
		BlobFeeCap: big.NewInt(2),
		BlobHashes: sidecar.BlobHashes(),
		V:          new(big.Int),
		R:          new(big.Int),
		S:          new(big.Int),
	}).WithBlobSidecar(sidecar)
}

func testTxQUICOsakaBlobTransaction(t *testing.T) *types.Transaction {
	t.Helper()
	tx := testTxQUICBlobTransaction(t, false)
	sidecar := tx.BlobSidecar().Copy()
	var blob kzg.Blob
	copy(blob[:], sidecar.Blobs[0])
	proofs, err := kzg.ComputeCellProofs(&blob)
	if err != nil {
		t.Fatal(err)
	}
	sidecar.Version = types.BlobSidecarVersion1
	sidecar.Proofs = make([]types.KZGProof, len(proofs))
	for i := range proofs {
		sidecar.Proofs[i] = types.KZGProof(proofs[i])
	}
	return tx.WithBlobSidecar(sidecar)
}

func TestTxQUICBlobSidecarRoundTripOwnsDurableBytes(t *testing.T) {
	config := testTxQUICConfig()
	tx := testTxQUICBlobTransaction(t, false)
	item, err := newTxQUICItem(0, tx)
	if err != nil {
		t.Fatal(err)
	}
	batch, _, err := newTxQUICBatch(config.ChainID, config.GenesisHash, testTxQUICCertificate(t, config, tx), []*txQUICItem{item})
	if err != nil {
		t.Fatal(err)
	}
	if batch.Items[0].Tx.BlobSidecar() != nil || batch.Items[0].BlobSidecar == nil {
		t.Fatal("TxQUIC item did not separate execution envelope and blob sidecar")
	}
	original := batch.Items[0].BlobSidecar.Blobs[0][31]
	tx.BlobSidecar().Blobs[0][31] ^= 0x01
	if batch.Items[0].BlobSidecar.Blobs[0][31] != original {
		t.Fatal("durable batch retained the caller's mutable sidecar")
	}

	payload, err := rlp.EncodeToBytes(batch)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(payload)) >= txQUICMicroBatchMaxStoredBytes || len(payload) <= int(params.BlobTxBlobGasPerBlob) {
		t.Fatalf("sidecar-aware batch size = %d", len(payload))
	}
	decoded, _, err := decodeTxQUICBatch(payload)
	if err != nil {
		t.Fatal(err)
	}
	txs, err := packetItemsToTxs(&txQUICPacket{Items: decoded.Items})
	if err != nil {
		t.Fatal(err)
	}
	if txs[0].BlobSidecar() == nil || txs[0].BlobSidecar().Blobs[0][31] != original {
		t.Fatal("decoded TxQUIC item did not reattach the sidecar")
	}
	txs[0].BlobSidecar().Blobs[0][31] ^= 0x01
	if decoded.Items[0].BlobSidecar.Blobs[0][31] != original {
		t.Fatal("pool publication transaction aliases the durable sidecar")
	}

	packet := testTxQUICPacketFromBatch(config, decoded, common.HexToAddress("0x1000000000000000000000000000000000000001"), 1, uint64(time.Now().Unix()))
	walBytes, err := rlp.EncodeToBytes(&txIngressWALInboundReceivedPayload{Packet: *packet})
	if err != nil {
		t.Fatal(err)
	}
	var restored txIngressWALInboundReceivedPayload
	if err := rlp.DecodeBytes(walBytes, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Packet.Items[0].BlobSidecar == nil || restored.Packet.Items[0].BlobSidecar.Blobs[0][31] != original {
		t.Fatal("unified ingress WAL dropped the blob sidecar")
	}

	store := NewTxQUICIngressStore(memorydb.New(), config)
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ack := testTxQUICAck(t, packet, []int{0}, nil, nil)
	if _, err := store.StoreSync(context.Background(), packet, ack); err != nil {
		store.Stop()
		t.Fatal(err)
	}
	resolved, err := store.ResolveTransaction(tx.Hash())
	store.Stop()
	if err != nil || resolved == nil || resolved.BlobSidecar() == nil || resolved.BlobSidecar().Blobs[0][31] != original {
		t.Fatalf("durable ingress sidecar resolve = %v err=%v", resolved, err)
	}

	wal := newTxIngressWAL(memorydb.New(), config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := wal.appendInboundReceived(context.Background(), packet); err != nil {
		wal.Stop()
		t.Fatal(err)
	}
	foundSidecar := false
	if err := wal.Replay(func(frame *txIngressWALFrame) error {
		if frame.Kind != txIngressWALInboundReceived {
			return nil
		}
		var event txIngressWALInboundReceivedPayload
		if err := rlp.DecodeBytes(frame.Payload, &event); err != nil {
			return err
		}
		foundSidecar = len(event.Packet.Items) == 1 && event.Packet.Items[0].BlobSidecar != nil
		return nil
	}); err != nil {
		wal.Stop()
		t.Fatal(err)
	}
	wal.Stop()
	if !foundSidecar {
		t.Fatal("unified ingress WAL replay dropped the blob sidecar")
	}
}

func TestTxQUICBlobSidecarStructuralRejections(t *testing.T) {
	config := testTxQUICConfig()
	blobTx := testTxQUICBlobTransaction(t, false)
	bare := blobTx.WithBlobSidecar(nil)
	if _, err := newTxQUICItem(0, bare); !errors.Is(err, types.ErrBlobSidecarMissing) {
		t.Fatalf("missing sidecar error = %v", err)
	}
	bareCertificate := testTxQUICCertificate(t, config, bare)
	if _, _, err := txQUICItemCommitments(bareCertificate, []*txQUICItem{{AdmissionIndex: 0, Tx: bare}}); !errors.Is(err, types.ErrBlobSidecarMissing) {
		t.Fatalf("wire missing sidecar error = %v", err)
	}
	if _, _, err := txQUICItemCommitments(bareCertificate, []*txQUICItem{{AdmissionIndex: 0, Tx: blobTx}}); err == nil {
		t.Fatal("embedded pooled sidecar was accepted as a TxQUIC item")
	}

	legacy := testTxQUICTransaction(4844, 0)
	legacyCertificate := testTxQUICCertificate(t, config, legacy)
	if _, _, err := txQUICItemCommitments(legacyCertificate, []*txQUICItem{{AdmissionIndex: 0, Tx: legacy, BlobSidecar: blobTx.BlobSidecar().Copy()}}); !errors.Is(err, types.ErrBlobTxSidecarOnNonBlobTx) {
		t.Fatalf("non-blob sidecar error = %v", err)
	}

	badShape := blobTx.BlobSidecar().Copy()
	badShape.Blobs[0] = badShape.Blobs[0][:len(badShape.Blobs[0])-1]
	if _, _, err := txQUICItemCommitments(bareCertificate, []*txQUICItem{{AdmissionIndex: 0, Tx: bare, BlobSidecar: badShape}}); !errors.Is(err, types.ErrBlobSidecarInvalidBlobLength) {
		t.Fatalf("invalid blob length error = %v", err)
	}
}

func TestTxQUICBlobSidecarBytesBindBatchIdentityAndKZG(t *testing.T) {
	config := testTxQUICConfig()
	tx := testTxQUICBlobTransaction(t, false)
	certificate := testTxQUICCertificate(t, config, tx)
	valid, validIDs, err := newTxQUICBatch(config.ChainID, config.GenesisHash, certificate, []*txQUICItem{{AdmissionIndex: 0, Tx: tx}})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyTxQUICPacketBlobSidecars(&txQUICPacket{Items: valid.Items}); err != nil {
		t.Fatalf("valid sidecar failed KZG verification: %v", err)
	}

	tamperedItem, err := copyTxQUICItem(valid.Items[0])
	if err != nil {
		t.Fatal(err)
	}
	tamperedItem.BlobSidecar.Blobs[0][31] ^= 0x01
	tampered, tamperedIDs, err := newTxQUICBatch(config.ChainID, config.GenesisHash, certificate, []*txQUICItem{tamperedItem})
	if err != nil {
		t.Fatal(err)
	}
	if tampered.BatchID == valid.BatchID || tampered.TxRoot == valid.TxRoot || tamperedIDs[0] == validIDs[0] {
		t.Fatal("sidecar mutation did not change TxQUIC commitments")
	}
	if err := verifyTxQUICPacketBlobSidecars(&txQUICPacket{Items: tampered.Items}); err == nil {
		t.Fatal("real KZG verifier accepted a mutated blob")
	}
	tampered.BatchID = valid.BatchID
	tampered.TxRoot = valid.TxRoot
	if _, err := validateTxQUICBatch(tampered); err == nil {
		t.Fatal("sidecar mutation survived the original BatchID")
	}

	tamperedProof, err := copyTxQUICItem(valid.Items[0])
	if err != nil {
		t.Fatal(err)
	}
	tamperedProof.BlobSidecar.Proofs[0][0] ^= 0xff
	proofBatch, proofIDs, err := newTxQUICBatch(config.ChainID, config.GenesisHash, certificate, []*txQUICItem{tamperedProof})
	if err != nil {
		t.Fatal(err)
	}
	if proofBatch.BatchID == valid.BatchID || proofBatch.TxRoot == valid.TxRoot || proofIDs[0] == validIDs[0] {
		t.Fatal("proof mutation did not change TxQUIC commitments")
	}
	if err := verifyTxQUICPacketBlobSidecars(&txQUICPacket{Items: proofBatch.Items}); err == nil {
		t.Fatal("real KZG verifier accepted a mutated proof")
	}
}

func TestTxQUICOsakaIngressRejectsV0BeforeDurability(t *testing.T) {
	config := testTxQUICConfig()
	config.BridgeEnabled = true
	zero := uint64(0)
	chainConfig := *params.TestChainConfig
	chainConfig.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0), CancunTime: &zero, PragueTime: &zero, OsakaTime: &zero,
	})
	t.Cleanup(func() { chainConfig.SetModernForkConfig(nil) })
	stateDB, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	head := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0), Time: 0, GasLimit: 30_000_000, BaseFee: big.NewInt(1)})
	poolConfig := core.DefaultTxPoolConfig
	poolConfig.Journal = ""
	pool := core.NewTxPool(poolConfig, &chainConfig, &testTxQUICPoolChain{block: head, state: stateDB})
	t.Cleanup(pool.Stop)
	wal := newTxIngressWAL(memorydb.New(), config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wal.Stop)
	q := &TxQUICIngress{
		config: config,
		txpool: pool,
		wal:    wal,
		outbox: NewTxOutbox(memorydb.New(), config),
	}

	v0tx := testTxQUICBlobTransaction(t, false)
	v0, err := newTxQUICItem(0, v0tx)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.verifyTxQUICPacketBlobSidecars(&txQUICPacket{Items: []*txQUICItem{v0}}); !errors.Is(err, types.ErrBlobSidecarVersionMismatch) {
		t.Fatalf("Osaka QUIC accepted v0 sidecar: %v", err)
	}
	certificate := testTxQUICCertificate(t, config, v0tx)
	admissions := []core.CommonRPCAdmissionResult{{Batch: certificate, Item: 0, Updated: true}}
	if _, err := q.persistVerifiedLocalTxsIntent(context.Background(), types.Transactions{v0tx}, admissions, nil); !errors.Is(err, types.ErrBlobSidecarVersionMismatch) {
		t.Fatalf("Osaka unified WAL accepted v0 sidecar: %v", err)
	}
	frames := 0
	if err := wal.Replay(func(*txIngressWALFrame) error {
		frames++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if frames != 0 {
		t.Fatalf("rejected Osaka v0 sidecar created %d WAL frames", frames)
	}

	v1tx := testTxQUICOsakaBlobTransaction(t)
	v1, err := newTxQUICItem(0, v1tx)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.verifyTxQUICPacketBlobSidecars(&txQUICPacket{Items: []*txQUICItem{v1}}); err != nil {
		t.Fatalf("Osaka QUIC rejected v1 sidecar: %v", err)
	}
	if _, err := q.persistVerifiedLocalTxsIntent(context.Background(), types.Transactions{v1tx}, admissions, nil); err != nil {
		t.Fatalf("Osaka unified WAL rejected v1 sidecar: %v", err)
	}
}

func TestTxQUICInvalidKnownHashSidecarNeverReachesWAL(t *testing.T) {
	config := testTxQUICConfig()
	config.BridgeEnabled = true
	valid := testTxQUICBlobTransaction(t, false)
	badSidecar := valid.BlobSidecar().Copy()
	badSidecar.Proofs[0][0] ^= 0xff
	invalid := valid.WithBlobSidecar(badSidecar)
	if invalid.Hash() != valid.Hash() {
		t.Fatal("sidecar-only mutation changed the execution transaction hash")
	}
	certificate := testTxQUICCertificate(t, config, valid)
	admissions := []core.CommonRPCAdmissionResult{{Batch: certificate, Item: 0, Updated: true}}

	wal := newTxIngressWAL(memorydb.New(), config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer wal.Stop()
	q := &TxQUICIngress{
		config: config,
		wal:    wal,
		outbox: NewTxOutbox(memorydb.New(), config),
	}
	if _, err := q.persistVerifiedLocalTxsIntent(context.Background(), types.Transactions{invalid}, admissions, nil); err == nil {
		t.Fatal("local WAL accepted an invalid sidecar for an existing execution hash")
	}

	batch, _, err := newTxQUICBatch(config.ChainID, config.GenesisHash, certificate, []*txQUICItem{{AdmissionIndex: 0, Tx: invalid}})
	if err != nil {
		t.Fatal(err)
	}
	packet := testTxQUICPacketFromBatch(config, batch, common.HexToAddress("0x9000000000000000000000000000000000000009"), 1, uint64(time.Now().Unix()))
	if err := q.appendKZGVerifiedInboundReceived(context.Background(), packet); err == nil {
		t.Fatal("authenticated receiver boundary persisted an invalid known-hash sidecar")
	}

	frames := 0
	if err := wal.Replay(func(*txIngressWALFrame) error {
		frames++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if frames != 0 {
		t.Fatalf("invalid sidecar created %d unified WAL frames", frames)
	}

	set, err := q.persistVerifiedLocalTxsIntent(context.Background(), types.Transactions{valid}, admissions, nil)
	if err != nil {
		t.Fatalf("valid local blob intent was rejected: %v", err)
	}
	if len(set.batches) != 1 || len(set.batches[0].Items) != 1 || set.batches[0].Items[0].BlobSidecar == nil {
		t.Fatal("valid local WAL intent dropped its blob sidecar")
	}
	localIntents := 0
	if err := wal.Replay(func(frame *txIngressWALFrame) error {
		if frame.Kind != txIngressWALLocalIntent {
			return nil
		}
		batch, _, err := decodeTxQUICBatch(frame.Payload)
		if err != nil {
			return err
		}
		if len(batch.Items) != 1 || batch.Items[0].BlobSidecar == nil {
			return errors.New("replayed local blob intent has no sidecar")
		}
		localIntents++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if localIntents != 1 {
		t.Fatalf("valid local blob WAL intents = %d, want 1", localIntents)
	}
}

func TestTxQUICWALRestoreRejectsInvalidCommittedBlobSidecar(t *testing.T) {
	config := testTxQUICConfig()
	valid := testTxQUICBlobTransaction(t, false)
	badSidecar := valid.BlobSidecar().Copy()
	badSidecar.Proofs[0][0] ^= 0xff
	invalid := valid.WithBlobSidecar(badSidecar)
	certificate := testTxQUICCertificate(t, config, valid)
	item, err := newTxQUICItem(0, invalid)
	if err != nil {
		t.Fatal(err)
	}
	batch, _, err := newTxQUICBatch(config.ChainID, config.GenesisHash, certificate, []*txQUICItem{item})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := rlp.EncodeToBytes(batch)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("local intent", func(t *testing.T) {
		wal := newTxIngressWAL(memorydb.New(), config)
		if err := wal.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer wal.Stop()
		if _, err := wal.appendLocalIntent(context.Background(), batch); err != nil {
			t.Fatal(err)
		}
		q := &TxQUICIngress{config: config, wal: wal, outbox: NewTxOutbox(memorydb.New(), config)}
		if err := q.replayWALOutboxProjection(); err == nil {
			t.Fatal("local WAL restore accepted an invalid KZG proof")
		}
	})

	t.Run("outbox projection", func(t *testing.T) {
		wal := newTxIngressWAL(memorydb.New(), config)
		if err := wal.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer wal.Stop()
		record := TxOutboxRecord{BatchID: batch.BatchID, Payload: payload, CreatedAt: uint64(time.Now().UnixNano())}
		if err := wal.appendOutbox(context.Background(), txIngressWALOutboxEnqueued, record, txOutboxRetryState{}); err != nil {
			t.Fatal(err)
		}
		outboxDB := memorydb.New()
		q := &TxQUICIngress{config: config, wal: wal, outbox: NewTxOutbox(outboxDB, config)}
		if err := q.replayWALOutboxProjection(); err == nil {
			t.Fatal("outbox WAL restore accepted an invalid KZG proof")
		}
		if has, err := outboxDB.Has(txOutboxRecordKey(batch.BatchID)); err != nil || has {
			t.Fatalf("invalid sidecar reached the outbox projection: has=%t err=%v", has, err)
		}
	})

	t.Run("inbound projection", func(t *testing.T) {
		wal := newTxIngressWAL(memorydb.New(), config)
		if err := wal.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer wal.Stop()
		packet := testTxQUICPacketFromBatch(config, batch, common.HexToAddress("0x9100000000000000000000000000000000000009"), 1, uint64(time.Now().Unix()))
		if err := wal.appendInboundReceived(context.Background(), packet); err != nil {
			t.Fatal(err)
		}
		ingressDB := memorydb.New()
		q := &TxQUICIngress{config: config, ctx: context.Background(), wal: wal, ingress: NewTxQUICIngressStore(ingressDB, config)}
		if err := q.replayWALInboundProjection(); err == nil {
			t.Fatal("inbound WAL restore accepted an invalid KZG proof")
		}
		if ingressDB.Len() != 0 {
			t.Fatalf("invalid sidecar materialized %d inbound projection records", ingressDB.Len())
		}
	})
}

func TestTxQUICNonBlobItemIdentityAndNilSidecarRemainStable(t *testing.T) {
	config := testTxQUICConfig()
	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	txs := []*types.Transaction{
		testTxQUICTransaction(700, 0),
		types.NewTx(&types.AccessListTx{ChainID: big.NewInt(1337), Nonce: 701, GasPrice: big.NewInt(1), Gas: 100_000, To: &to, Value: new(big.Int), V: new(big.Int), R: new(big.Int), S: new(big.Int)}),
		types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(1337), Nonce: 702, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 100_000, To: &to, Value: new(big.Int), V: new(big.Int), R: new(big.Int), S: new(big.Int)}),
		types.NewTx(&types.SetCodeTx{ChainID: big.NewInt(1337), Nonce: 703, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 100_000, To: to, Value: new(big.Int), V: new(big.Int), R: new(big.Int), S: new(big.Int)}),
	}
	for _, tx := range txs {
		t.Run(string(rune('0'+tx.Type())), func(t *testing.T) {
			certificate := testTxQUICCertificate(t, config, tx)
			item, err := newTxQUICItem(0, tx)
			if err != nil {
				t.Fatal(err)
			}
			ids, _, err := txQUICItemCommitments(certificate, []*txQUICItem{item})
			if err != nil {
				t.Fatal(err)
			}
			oldLeaf, err := txQUICRLPHash([]interface{}{txQUICTxLeafDomain, uint32(0), uint16(0), tx.Hash()})
			if err != nil {
				t.Fatal(err)
			}
			oldID, err := txQUICRLPHash([]interface{}{txQUICItemDomain, uint32(0), uint16(0), oldLeaf})
			if err != nil {
				t.Fatal(err)
			}
			if ids[0] != oldID {
				t.Fatalf("type %d ItemID changed: have %s want %s", tx.Type(), ids[0], oldID)
			}
			encoded, err := rlp.EncodeToBytes(item)
			if err != nil {
				t.Fatal(err)
			}
			var decoded txQUICItem
			if err := rlp.DecodeBytes(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.BlobSidecar != nil || decoded.Tx == nil || decoded.Tx.Hash() != tx.Hash() {
				t.Fatalf("type %d nil-sidecar roundtrip changed the item", tx.Type())
			}
		})
	}
}

func TestTxQUICKZGIsDeferredUntilAfterPacketAuthentication(t *testing.T) {
	config := testTxQUICConfig()
	tx := testTxQUICBlobTransaction(t, true)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	packet := testTxQUICPacket(t, config, sender, 9, tx)
	packet.Signature, err = crypto.Sign(packet.signingHash().Bytes(), key)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := rlp.EncodeToBytes(packet)
	if err != nil {
		t.Fatal(err)
	}
	ingress := &TxQUICIngress{config: config, signers: map[common.Address]struct{}{sender: {}}}
	authenticated, recovered, err := ingress.decodeAndAuthenticateEnvelope(payload)
	if err != nil || recovered != sender {
		t.Fatalf("structurally valid packet did not reach the authenticated boundary: signer=%s err=%v", recovered, err)
	}
	if err := verifyTxQUICPacketBlobSidecars(authenticated); err == nil {
		t.Fatal("post-authentication KZG gate accepted an invalid proof")
	}

	packet.Signature[0] ^= 0x01
	badPayload, err := rlp.EncodeToBytes(packet)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ingress.decodeAndAuthenticateEnvelope(badPayload); err == nil {
		t.Fatal("invalid packet signature reached the authenticated boundary")
	}
}

func TestTxQUICBridgeAccountingIncludesExactBlobSidecarBytes(t *testing.T) {
	config := testTxQUICConfig()
	tx := testTxQUICBlobTransaction(t, false)
	item, err := newTxQUICItem(0, tx)
	if err != nil {
		t.Fatal(err)
	}
	want, err := rlp.EncodeToBytes(item)
	if err != nil {
		t.Fatal(err)
	}
	got, err := txQUICBridgeItemRawSize(tx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got != int64(len(want)) || got <= int64(params.BlobTxBlobGasPerBlob) {
		t.Fatalf("blob item accounting = %d, canonical encoding = %d", got, len(want))
	}
	request, err := newTxQUICBridgeRequest(testTxQUICCertificate(t, config, tx), []txQUICBridgeItem{{tx: tx}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if request.rawBytes <= got || request.rawBytes > txQUICMicroBatchMaxStoredBytes {
		t.Fatalf("sidecar-aware bridge request bytes = %d item=%d", request.rawBytes, got)
	}
	owned := request.items[0].blobSidecar.Blobs[0][31]
	tx.BlobSidecar().Blobs[0][31] ^= 0x01
	if request.items[0].blobSidecar.Blobs[0][31] != owned {
		t.Fatal("durable bridge queue aliases the caller's mutable blob bytes")
	}
}
