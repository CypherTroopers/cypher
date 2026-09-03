// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package eth

import (
	"bytes"
	"container/heap"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mathbig "math/big"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	cyphercrypto "github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/metrics"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
	rnetnetwork "github.com/cypherium/cypher/rnet/network"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/sha3"
)

const (
	txQUICProtocolName = "cypher-tx-quic"

	txQUICBatchDomain       = "CPH_TXQUIC_BATCH"
	txQUICPacketDomain      = "CPH_TXQUIC_PACKET"
	txQUICTxLeafDomain      = "CPH_TXQUIC_TX_LEAF"
	txQUICBlobSidecarDomain = "CPH_TXQUIC_BLOB_SIDECAR"
	txQUICItemDomain        = "CPH_TXQUIC_ITEM"
	txQUICTxRootDomain      = "CPH_TXQUIC_TX_ROOT"
	txQUICCertificateDomain = "CPH_TXQUIC_ADMISSION_CERTIFICATE"
	txQUICSenderEpochDomain = "CPH_TXQUIC_SENDER_EPOCH"
	txQUICAckDomain         = "CPH_TXQUIC_DURABLE_ACK"
	txQUICTLSIdentityDomain = "CPH_TXQUIC_TLS_IDENTITY"

	// TxQUIC uses fixed, bounded micro-batches. Burst capacity comes from the
	// durable queue and concurrent batches, not from unbounded packet growth.
	txQUICMicroBatchMaxTxs          = 512
	txQUICMicroBatchMaxWireBytes    = int64(4 * 1024 * 1024)
	txQUICMicroBatchEnvelopeReserve = int64(1024)
	txQUICMicroBatchMaxStoredBytes  = txQUICMicroBatchMaxWireBytes - txQUICMicroBatchEnvelopeReserve

	txQUICForwardIdleTimeout         = 60 * time.Second
	txQUICForwardKeepAlivePeriod     = 10 * time.Second
	txQUICHandshakeIdleTimeout       = 3 * time.Second
	txQUICRouteRefreshTimeout        = 2 * time.Second
	txQUICTLSRouteRefreshInterval    = 250 * time.Millisecond
	txQUICIngressMaintenance         = time.Second
	txQUICIngressMaintenanceRecords  = 256
	txQUICIngressMaintenanceBytes    = int64(4 * 1024 * 1024)
	txQUICMaxPermanentReasonBytes    = 256
	txQUICMaxReplayWindow            = uint64(1 << 20)
	txQUICMaxIngressWorkers          = 1024
	txQUICMaxConnectionSlots         = 65536
	txQUICMaxAdvertisedStreamProduct = int64(65536)
	txQUICMaxInflightPayloadBytes    = int64(1024 * 1024 * 1024)
	txQUICMaxRateBucketEntries       = 1_000_000
	txQUICMaxBridgeWorkers           = 1024
	txQUICMaxBridgeQueueItems        = 4_000_000
	txQUICMaxBridgeQueueBytes        = int64(1024 * 1024 * 1024)
	txQUICMaxOutboxRecords           = 1_000_000
	// Outbox capacity is disk-backed and includes a 128 KiB reservation for
	// committee placement metadata on every record. Keep this independent from
	// the 1 GiB in-memory bridge/in-flight ceilings: the standard 1,048,576-TX
	// burst can be split into 131,072 eight-TX durable records.
	txQUICMaxOutboxBytes    = int64(32 * 1024 * 1024 * 1024)
	txQUICMaxCommitRequests = 4096
	txQUICMaxCommitBytes    = int64(256 * 1024 * 1024)
)

var (
	txQUICIngressConnMeter     = metrics.GetOrRegisterMeter("txquic/ingress/conns", metrics.DefaultRegistry)
	txQUICIngressStreamMeter   = metrics.GetOrRegisterMeter("txquic/ingress/streams", metrics.DefaultRegistry)
	txQUICIngressAcceptedMeter = metrics.GetOrRegisterMeter("txquic/ingress/accepted", metrics.DefaultRegistry)
	txQUICIngressRejectedMeter = metrics.GetOrRegisterMeter("txquic/ingress/rejected", metrics.DefaultRegistry)
	txQUICIngressForwardMeter  = metrics.GetOrRegisterMeter("txquic/ingress/forwarded", metrics.DefaultRegistry)
	txQUICIngressAuthFailMeter = metrics.GetOrRegisterMeter("txquic/ingress/authfail", metrics.DefaultRegistry)
)

type txQUICRateBucket struct {
	tokens   int
	last     time.Time
	lastSeen time.Time
}

type txQUICItem struct {
	AdmissionIndex uint16
	Tx             *types.Transaction
	BlobSidecar    *types.BlobTxSidecar `rlp:"nil"`
}

type txQUICPacket struct {
	ChainID       uint64
	GenesisHash   common.Hash
	KeyNumber     uint64
	CommitteeHash common.Hash
	BatchID       common.Hash
	Sender        common.Address
	SenderEpoch   common.Hash
	Nonce         uint64
	Timestamp     uint64
	TxRoot        common.Hash
	Certificate   *types.CommonTxAdmissionBatch
	Items         []*txQUICItem
	Signature     []byte
}

// txQUICBatch is the durable sender representation. The transport envelope is
// deliberately absent: retries use a fresh timestamp and persistently
// allocated nonce without changing the semantic BatchID.
type txQUICBatch struct {
	ChainID     uint64
	GenesisHash common.Hash
	BatchID     common.Hash
	TxRoot      common.Hash
	Certificate *types.CommonTxAdmissionBatch
	Items       []*txQUICItem
}

type txQUICSigningData struct {
	Domain          string
	ChainID         uint64
	GenesisHash     common.Hash
	KeyNumber       uint64
	CommitteeHash   common.Hash
	BatchID         common.Hash
	Sender          common.Address
	SenderEpoch     common.Hash
	Nonce           uint64
	Timestamp       uint64
	TxRoot          common.Hash
	AdmissionID     common.Hash
	CertificateHash common.Hash
	ItemCount       uint32
}

type txQUICAck struct {
	ChainID            uint64
	GenesisHash        common.Hash
	KeyNumber          uint64
	CommitteeHash      common.Hash
	BatchID            common.Hash
	Sender             common.Address
	SenderEpoch        common.Hash
	Nonce              uint64
	ItemCount          uint32
	DurableBitmap      []byte
	RetryableBitmap    []byte
	PermanentErrors    []txQUICPermanentError
	CommitteePublicKey []byte
	Signature          []byte
}

type txQUICPermanentError struct {
	Index  uint32
	ItemID common.Hash
	Code   uint16
	Reason string
}

const (
	txQUICPermanentInvalidTransaction  uint16 = 1
	txQUICPermanentInvalidAdmission    uint16 = 2
	txQUICPermanentObsoleteTransaction uint16 = 3
)

const (
	txQUICRejectPermanent uint = 1
	txQUICRejectRetryable uint = 2
)

func validTxQUICPermanentCode(code uint16) bool {
	switch code {
	case txQUICPermanentInvalidTransaction, txQUICPermanentInvalidAdmission, txQUICPermanentObsoleteTransaction:
		return true
	default:
		return false
	}
}

// txQUICTransactionReject is a machine-readable transaction-pool result. The
// sender uses Class to distinguish an invalid transaction from a temporary
// node-local condition that may succeed at another committee endpoint.
type txQUICTransactionReject struct {
	Hash   common.Hash
	Reason string
	Class  uint
}

type txQUICAckExpectation struct {
	chainID         uint64
	genesisHash     common.Hash
	keyNumber       uint64
	committeeHash   common.Hash
	batchID         common.Hash
	sender          common.Address
	senderEpoch     common.Hash
	nonce           uint64
	admissionID     common.Hash
	certificateHash common.Hash
	itemIDs         []common.Hash
	txHashes        []common.Hash
}

// TxQUICFHSRoute is the eth-layer projection of reconfig's authoritative FHS
// route. LeaderAddress is the committee rnet endpoint; TxQUIC applies its own
// PortOffset when building the QUIC destination.
type TxQUICFHSRoute struct {
	ProposalView        uint64
	KeyNumber           uint64
	CommitteeHash       common.Hash
	LeaderIndex         uint
	LeaderAddress       string
	CommitteeAddresses  []string
	CommitteePublicKeys []string
}

type TxQUICFHSRouteProvider func() (TxQUICFHSRoute, error)

type txQUICFHSRouteResult struct {
	route txQUICFHSRouteCache
	err   error
}

type txQUICFHSRouteCache struct {
	ProposalView        uint64
	KeyNumber           uint64
	CommitteeHash       common.Hash
	LeaderIndex         uint
	Endpoint            string
	CommitteeEndpoints  []string
	CommitteePublicKeys [][]byte
}

func txQUICRLPHash(value interface{}) (common.Hash, error) {
	encoded, err := rlp.EncodeToBytes(value)
	if err != nil {
		return common.Hash{}, err
	}
	return cyphercrypto.Keccak256Hash(encoded), nil
}

func txQUICCertificateHash(certificate *types.CommonTxAdmissionBatch) (common.Hash, error) {
	if certificate == nil {
		return common.Hash{}, fmt.Errorf("missing txquic admission certificate")
	}
	return txQUICRLPHash([]interface{}{txQUICCertificateDomain, certificate})
}

// validateTxQUICCertificateStructure checks every field committed by the
// certificate without doing ECDSA recovery. The trusted local enqueue path has
// already verified the certificate in core; network and disk restore paths call
// core.VerifyAndStoreCommonRPCAdmissionBatch exactly once instead.
func validateTxQUICCertificateStructure(certificate *types.CommonTxAdmissionBatch, chainID uint64, genesisHash common.Hash) error {
	if certificate == nil {
		return fmt.Errorf("missing txquic admission certificate")
	}
	if certificate.ChainID == nil || !certificate.ChainID.IsUint64() || certificate.ChainID.Uint64() != chainID {
		return fmt.Errorf("txquic admission certificate chain mismatch")
	}
	if certificate.GenesisHash != genesisHash || genesisHash == (common.Hash{}) {
		return fmt.Errorf("txquic admission certificate genesis mismatch")
	}
	if certificate.Miner == (common.Address{}) || certificate.Timestamp == 0 {
		return fmt.Errorf("incomplete txquic admission certificate")
	}
	if len(certificate.TxHashes) == 0 || len(certificate.TxHashes) > types.MaxCommonTxAdmissionBatchItems {
		return fmt.Errorf("invalid txquic admission certificate transaction count %d", len(certificate.TxHashes))
	}
	seen := make(map[common.Hash]struct{}, len(certificate.TxHashes))
	for index, hash := range certificate.TxHashes {
		if hash == (common.Hash{}) {
			return fmt.Errorf("empty txquic admission transaction hash at %d", index)
		}
		if _, duplicate := seen[hash]; duplicate {
			return fmt.Errorf("duplicate txquic admission transaction %s", hash)
		}
		seen[hash] = struct{}{}
	}
	if certificate.TxRoot != types.DeriveCommonTxAdmissionTxRoot(certificate.TxHashes) {
		return fmt.Errorf("txquic admission certificate transaction root mismatch")
	}
	if certificate.AdmissionID != types.CommonTxAdmissionID(certificate) {
		return fmt.Errorf("txquic admission certificate id mismatch")
	}
	if len(certificate.Signature) != cyphercrypto.SignatureLength {
		return fmt.Errorf("txquic admission certificate signature length is %d", len(certificate.Signature))
	}
	return nil
}

// newTxQUICItem moves an EIP-4844 sidecar out of the execution transaction and
// into the durable transport item. Transaction hashes remain canonical while
// every mutable sidecar byte is owned by the item.
func newTxQUICItem(admissionIndex uint16, tx *types.Transaction) (*txQUICItem, error) {
	return newTxQUICItemWithSidecar(admissionIndex, tx, nil)
}

func newTxQUICItemWithSidecar(admissionIndex uint16, tx *types.Transaction, supplied *types.BlobTxSidecar) (*txQUICItem, error) {
	if tx == nil {
		return nil, fmt.Errorf("txquic transaction is nil")
	}
	if tx.Type() != types.BlobTxType {
		if supplied != nil {
			return nil, types.ErrBlobTxSidecarOnNonBlobTx
		}
		return &txQUICItem{AdmissionIndex: admissionIndex, Tx: tx}, nil
	}
	sidecar := supplied
	if supplied != nil && tx.BlobSidecar() != nil {
		return nil, fmt.Errorf("txquic blob transaction has two sidecar sources")
	}
	if sidecar == nil {
		sidecar = tx.BlobSidecar()
	}
	item := &txQUICItem{
		AdmissionIndex: admissionIndex,
		Tx:             tx.WithBlobSidecar(nil),
		BlobSidecar:    sidecar.Copy(),
	}
	if err := validateTxQUICItem(item); err != nil {
		return nil, err
	}
	return item, nil
}

// validateTxQUICItem performs only bounded structural and commitment checks.
// It deliberately does not invoke KZG, because network callers must first pass
// packet signature authentication and rate limiting.
func validateTxQUICItem(item *txQUICItem) error {
	if item == nil || item.Tx == nil {
		return fmt.Errorf("txquic item has no transaction")
	}
	if item.Tx.Type() != types.BlobTxType {
		if item.BlobSidecar != nil {
			return types.ErrBlobTxSidecarOnNonBlobTx
		}
		return nil
	}
	// Pooled wrappers embedded in Tx would create two possible sidecar sources.
	// TxQUIC has one canonical representation: execution envelope plus this
	// item's separately committed sidecar.
	if item.Tx.BlobSidecar() != nil {
		return fmt.Errorf("txquic blob transaction embeds a pooled sidecar")
	}
	if item.BlobSidecar == nil {
		return types.ErrBlobSidecarMissing
	}
	if err := item.Tx.ValidateBlobTx(params.BlobTxMaxBlobs, nil); err != nil {
		return err
	}
	if err := item.Tx.ValidateBlobSidecar(item.BlobSidecar); err != nil {
		return err
	}
	if len(item.BlobSidecar.Blobs) > params.BlobTxMaxBlobs {
		return types.ErrBlobTxTooManyBlobs
	}
	for index, blob := range item.BlobSidecar.Blobs {
		if len(blob) != int(params.BlobTxBlobGasPerBlob) {
			return fmt.Errorf("%w at index %d: have %d want %d", types.ErrBlobSidecarInvalidBlobLength, index, len(blob), params.BlobTxBlobGasPerBlob)
		}
	}
	return nil
}

func copyTxQUICItem(item *txQUICItem) (*txQUICItem, error) {
	if err := validateTxQUICItem(item); err != nil {
		return nil, err
	}
	return newTxQUICItemWithSidecar(item.AdmissionIndex, item.Tx, item.BlobSidecar)
}

func canonicalizeTxQUICItems(items []*txQUICItem) ([]*txQUICItem, error) {
	canonical := make([]*txQUICItem, len(items))
	for index, item := range items {
		if item == nil || item.Tx == nil {
			return nil, fmt.Errorf("txquic item %d has no transaction", index)
		}
		owned, err := newTxQUICItemWithSidecar(item.AdmissionIndex, item.Tx, item.BlobSidecar)
		if err != nil {
			return nil, fmt.Errorf("txquic item %d: %w", index, err)
		}
		canonical[index] = owned
	}
	return canonical, nil
}

func txQUICBlobSidecarHash(sidecar *types.BlobTxSidecar) (common.Hash, error) {
	if sidecar == nil {
		return common.Hash{}, nil
	}
	// Stream the potentially multi-megabyte sidecar into Keccak instead of
	// allocating a second full encoded copy merely to commit it.
	hasher := sha3.NewLegacyKeccak256()
	if err := rlp.Encode(hasher, []interface{}{txQUICBlobSidecarDomain, sidecar}); err != nil {
		return common.Hash{}, err
	}
	var digest common.Hash
	copy(digest[:], hasher.Sum(nil))
	return digest, nil
}

func txQUICItemCommitment(certificate *types.CommonTxAdmissionBatch, item *txQUICItem, position uint32) (common.Hash, common.Hash, common.Hash, error) {
	if err := validateTxQUICItem(item); err != nil {
		return common.Hash{}, common.Hash{}, common.Hash{}, err
	}
	txHash := item.Tx.Hash()
	if certificate == nil || int(item.AdmissionIndex) >= len(certificate.TxHashes) || certificate.TxHashes[item.AdmissionIndex] != txHash {
		return common.Hash{}, common.Hash{}, common.Hash{}, fmt.Errorf("txquic item does not match admission certificate index %d", item.AdmissionIndex)
	}
	sidecarHash, err := txQUICBlobSidecarHash(item.BlobSidecar)
	if err != nil {
		return common.Hash{}, common.Hash{}, common.Hash{}, err
	}
	var txLeaf common.Hash
	if item.BlobSidecar == nil {
		// Preserve the established type 0/1/2/4 identity exactly. Only type 3
		// extends the leaf schema with a separately domain-separated DA hash.
		txLeaf, err = txQUICRLPHash([]interface{}{txQUICTxLeafDomain, position, item.AdmissionIndex, txHash})
	} else {
		txLeaf, err = txQUICRLPHash([]interface{}{txQUICTxLeafDomain, position, item.AdmissionIndex, txHash, sidecarHash})
	}
	if err != nil {
		return common.Hash{}, common.Hash{}, common.Hash{}, err
	}
	itemID, err := txQUICRLPHash([]interface{}{txQUICItemDomain, position, item.AdmissionIndex, txLeaf})
	if err != nil {
		return common.Hash{}, common.Hash{}, common.Hash{}, err
	}
	return itemID, txLeaf, txHash, nil
}

func txQUICItemCommitments(certificate *types.CommonTxAdmissionBatch, items []*txQUICItem) ([]common.Hash, common.Hash, error) {
	if len(items) == 0 || len(items) > int(^uint32(0)) {
		return nil, common.Hash{}, fmt.Errorf("invalid txquic item count %d", len(items))
	}
	if certificate == nil || len(certificate.TxHashes) == 0 || len(certificate.TxHashes) > types.MaxCommonTxAdmissionBatchItems {
		return nil, common.Hash{}, fmt.Errorf("invalid txquic admission certificate")
	}
	itemIDs := make([]common.Hash, len(items))
	txLeaves := make([]common.Hash, len(items))
	seenTxs := make(map[common.Hash]struct{}, len(items))
	seenIndexes := make(map[uint16]struct{}, len(items))
	type nativeReplayIdentity struct {
		payer    common.Address
		sequence uint64
	}
	var seenNativeReplay map[nativeReplayIdentity]struct{}
	for index, item := range items {
		itemID, txLeaf, txHash, err := txQUICItemCommitment(certificate, item, uint32(index))
		if err != nil {
			return nil, common.Hash{}, fmt.Errorf("txquic item %d: %w", index, err)
		}
		if _, duplicate := seenTxs[txHash]; duplicate {
			return nil, common.Hash{}, fmt.Errorf("duplicate txquic transaction %s", txHash)
		}
		seenTxs[txHash] = struct{}{}
		if item.Tx.Type() == types.NativeTxType {
			if seenNativeReplay == nil {
				seenNativeReplay = make(map[nativeReplayIdentity]struct{}, len(items))
			}
			identity := nativeReplayIdentity{payer: item.Tx.Payer(), sequence: item.Tx.ReplaySequence()}
			if _, duplicate := seenNativeReplay[identity]; duplicate {
				return nil, common.Hash{}, fmt.Errorf("duplicate txquic native replay identity %s/%d", identity.payer, identity.sequence)
			}
			seenNativeReplay[identity] = struct{}{}
		}
		if _, duplicate := seenIndexes[item.AdmissionIndex]; duplicate {
			return nil, common.Hash{}, fmt.Errorf("duplicate txquic admission index %d", item.AdmissionIndex)
		}
		seenIndexes[item.AdmissionIndex] = struct{}{}
		txLeaves[index] = txLeaf
		itemIDs[index] = itemID
	}
	txRoot, err := txQUICRLPHash([]interface{}{txQUICTxRootDomain, txLeaves})
	if err != nil {
		return nil, common.Hash{}, err
	}
	return itemIDs, txRoot, nil
}

func txQUICSemanticBatchID(chainID uint64, genesisHash common.Hash, admissionID, certificateHash common.Hash, itemCount int, txRoot common.Hash) (common.Hash, error) {
	if chainID == 0 || genesisHash == (common.Hash{}) || admissionID == (common.Hash{}) || certificateHash == (common.Hash{}) || itemCount <= 0 || itemCount > int(^uint32(0)) {
		return common.Hash{}, fmt.Errorf("invalid txquic batch identity context")
	}
	return txQUICRLPHash([]interface{}{txQUICBatchDomain, chainID, genesisHash, admissionID, certificateHash, uint32(itemCount), txRoot})
}

func newTxQUICBatch(chainID uint64, genesisHash common.Hash, certificate *types.CommonTxAdmissionBatch, items []*txQUICItem) (*txQUICBatch, []common.Hash, error) {
	ownedItems, err := canonicalizeTxQUICItems(items)
	if err != nil {
		return nil, nil, err
	}
	itemIDs, txRoot, err := txQUICItemCommitments(certificate, ownedItems)
	if err != nil {
		return nil, nil, err
	}
	certificateHash, err := txQUICCertificateHash(certificate)
	if err != nil {
		return nil, nil, err
	}
	batchID, err := txQUICSemanticBatchID(chainID, genesisHash, certificate.AdmissionID, certificateHash, len(items), txRoot)
	if err != nil {
		return nil, nil, err
	}
	return &txQUICBatch{
		ChainID: chainID, GenesisHash: genesisHash, BatchID: batchID,
		TxRoot: txRoot, Certificate: copyCommonTxAdmissionBatchForQUIC(certificate), Items: ownedItems,
	}, itemIDs, nil
}

func validateTxQUICBatch(batch *txQUICBatch) ([]common.Hash, error) {
	if batch == nil {
		return nil, fmt.Errorf("nil txquic batch")
	}
	itemIDs, txRoot, err := txQUICItemCommitments(batch.Certificate, batch.Items)
	if err != nil {
		return nil, err
	}
	certificateHash, err := txQUICCertificateHash(batch.Certificate)
	if err != nil {
		return nil, err
	}
	batchID, err := txQUICSemanticBatchID(batch.ChainID, batch.GenesisHash, batch.Certificate.AdmissionID, certificateHash, len(batch.Items), txRoot)
	if err != nil {
		return nil, err
	}
	if batch.TxRoot != txRoot || batch.BatchID != batchID {
		return nil, fmt.Errorf("txquic batch commitment mismatch")
	}
	return itemIDs, nil
}

func decodeTxQUICBatch(payload []byte) (*txQUICBatch, []common.Hash, error) {
	var batch txQUICBatch
	if err := rlp.DecodeBytes(payload, &batch); err != nil {
		return nil, nil, fmt.Errorf("decode txquic batch: %w", err)
	}
	itemIDs, err := validateTxQUICBatch(&batch)
	if err != nil {
		return nil, nil, err
	}
	return &batch, itemIDs, nil
}

func txQUICSenderEpoch(chainID uint64, genesisHash common.Hash, sender common.Address) common.Hash {
	epoch, _ := txQUICRLPHash([]interface{}{txQUICSenderEpochDomain, chainID, genesisHash, sender})
	return epoch
}

func newTxQUICAckExpectation(packet *txQUICPacket) (txQUICAckExpectation, error) {
	if packet == nil {
		return txQUICAckExpectation{}, fmt.Errorf("nil txquic packet")
	}
	if packet.ChainID == 0 || packet.GenesisHash == (common.Hash{}) || packet.Sender == (common.Address{}) ||
		packet.SenderEpoch != txQUICSenderEpoch(packet.ChainID, packet.GenesisHash, packet.Sender) || packet.Nonce == 0 || packet.Timestamp == 0 {
		return txQUICAckExpectation{}, fmt.Errorf("incomplete txquic packet envelope")
	}
	itemIDs, txRoot, err := txQUICItemCommitments(packet.Certificate, packet.Items)
	if err != nil {
		return txQUICAckExpectation{}, err
	}
	certificateHash, err := txQUICCertificateHash(packet.Certificate)
	if err != nil {
		return txQUICAckExpectation{}, err
	}
	batchID, err := txQUICSemanticBatchID(packet.ChainID, packet.GenesisHash, packet.Certificate.AdmissionID, certificateHash, len(packet.Items), txRoot)
	if err != nil {
		return txQUICAckExpectation{}, err
	}
	if packet.BatchID != batchID || packet.TxRoot != txRoot {
		return txQUICAckExpectation{}, fmt.Errorf("txquic packet commitment mismatch")
	}
	if packet.CommitteeHash == (common.Hash{}) {
		return txQUICAckExpectation{}, fmt.Errorf("incomplete txquic committee generation")
	}
	return txQUICAckExpectation{
		chainID: packet.ChainID, genesisHash: packet.GenesisHash,
		keyNumber: packet.KeyNumber, committeeHash: packet.CommitteeHash, batchID: packet.BatchID,
		sender: packet.Sender, senderEpoch: packet.SenderEpoch, nonce: packet.Nonce,
		admissionID: packet.Certificate.AdmissionID, certificateHash: certificateHash,
		itemIDs: itemIDs, txHashes: func() []common.Hash {
			hashes := make([]common.Hash, len(packet.Items))
			for index, item := range packet.Items {
				hashes[index] = item.Tx.Hash()
			}
			return hashes
		}(),
	}, nil
}

func txQUICAckExpectationFromPayload(payload []byte) (txQUICAckExpectation, error) {
	var packet txQUICPacket
	if err := rlp.DecodeBytes(payload, &packet); err != nil {
		return txQUICAckExpectation{}, fmt.Errorf("decode txquic packet: %w", err)
	}
	return newTxQUICAckExpectation(&packet)
}

func txQUICBitmapBytes(itemCount int) int {
	return (itemCount + 7) / 8
}

func txQUICAckMaxEncodedBytes(itemCount int) int64 {
	if itemCount <= 0 || itemCount > txQUICMicroBatchMaxTxs {
		return 0
	}
	// Fixed identity/signature fields plus a conservative per-item allowance
	// for two bitmaps or one permanent error containing a bounded reason.
	return 4096 + int64(itemCount)*(txQUICMaxPermanentReasonBytes+256)
}

func txQUICBitmapHas(bitmap []byte, index int) bool {
	return index >= 0 && index/8 < len(bitmap) && bitmap[index/8]&(byte(1)<<uint(index%8)) != 0
}

func txQUICBitmapSet(bitmap []byte, index int) {
	if index >= 0 && index/8 < len(bitmap) {
		bitmap[index/8] |= byte(1) << uint(index%8)
	}
}

func txQUICBitmapClear(bitmap []byte, index int) {
	if index >= 0 && index/8 < len(bitmap) {
		bitmap[index/8] &^= byte(1) << uint(index%8)
	}
}

func txQUICBitmapEmpty(bitmap []byte) bool {
	for _, value := range bitmap {
		if value != 0 {
			return false
		}
	}
	return true
}

func txQUICReceiptPlacementComplete(receipt *txQUICAckReceipt) bool {
	return receipt != nil && txQUICBitmapEmpty(receipt.Ack.RetryableBitmap)
}

func txQUICBitmapPaddingZero(bitmap []byte, itemCount int) bool {
	if itemCount < 0 || len(bitmap) != txQUICBitmapBytes(itemCount) {
		return false
	}
	if itemCount == 0 || itemCount%8 == 0 {
		return true
	}
	unusedMask := byte(0xff << uint(itemCount%8))
	return bitmap[len(bitmap)-1]&unusedMask == 0
}

type txQUICRemoteRejectError struct {
	endpoint string
	rejects  []txQUICTransactionReject
	ack      *txQUICAck
}

func (e *txQUICRemoteRejectError) Error() string {
	if e == nil {
		return "txquic remote transaction rejected"
	}
	const maxReportedRejects = 8
	reasons := make([]string, 0, maxReportedRejects+1)
	for index, reject := range e.rejects {
		if index == maxReportedRejects {
			reasons = append(reasons, fmt.Sprintf("and %d more", len(e.rejects)-index))
			break
		}
		reasons = append(reasons, fmt.Sprintf("%s: %s", reject.Hash, reject.Reason))
	}
	return fmt.Sprintf("txquic remote transaction rejected by %s: %s", e.endpoint, strings.Join(reasons, "; "))
}

// Retryable reports whether the authenticated bitmap contains any item that
// the receiver explicitly asked the sender to retain and retry.
func (e *txQUICRemoteRejectError) Retryable() bool {
	return e != nil && e.ack != nil && !txQUICBitmapEmpty(e.ack.RetryableBitmap)
}

type txQUICBridgeItem struct {
	tx             *types.Transaction
	blobSidecar    *types.BlobTxSidecar
	admissionIndex uint16
	am             *accounts.Manager
	request        *txQUICBridgeRequest
	rawBytes       int64
}

// txQUICBridgeRequest joins the durability result of items originating from
// one RPC call. Items from multiple calls may share an outbox packet, but each
// caller returns only after every one of its items is synchronously persisted.
type txQUICBridgeRequest struct {
	mu          sync.Mutex
	certificate *types.CommonTxAdmissionBatch
	items       []txQUICBridgeItem
	am          *accounts.Manager
	remaining   int
	rawBytes    int64
	result      error
	completed   bool
	walOwned    bool
	done        chan struct{}
}

func newTxQUICBridgeRequest(certificate *types.CommonTxAdmissionBatch, items []txQUICBridgeItem, am *accounts.Manager) (*txQUICBridgeRequest, error) {
	if certificate == nil {
		return nil, fmt.Errorf("missing txquic admission certificate")
	}
	copied := append([]txQUICBridgeItem(nil), items...)
	durableItems := make([]*txQUICItem, len(copied))
	var itemBytes int64
	for i := range copied {
		durableItem, err := newTxQUICItemWithSidecar(copied[i].admissionIndex, copied[i].tx, copied[i].blobSidecar)
		if err != nil {
			return nil, fmt.Errorf("copy txquic durable bridge item %d: %w", i, err)
		}
		encodedSize, err := txQUICItemRawSize(durableItem)
		if err != nil {
			return nil, fmt.Errorf("size txquic durable bridge item %d: %w", i, err)
		}
		// The queue owns the sidecar independently of the RPC decoder and caller.
		copied[i].tx = durableItem.Tx
		copied[i].blobSidecar = durableItem.BlobSidecar
		copied[i].rawBytes = encodedSize
		if copied[i].rawBytes <= 0 || itemBytes > int64(^uint64(0)>>1)-copied[i].rawBytes {
			return nil, fmt.Errorf("invalid txquic durable bridge item byte size")
		}
		itemBytes += copied[i].rawBytes
		durableItems[i] = durableItem
	}
	if _, _, err := txQUICItemCommitments(certificate, durableItems); err != nil {
		return nil, err
	}
	encodedRequest, err := rlp.EncodeToBytes([]interface{}{certificate, durableItems})
	if err != nil {
		return nil, fmt.Errorf("encode txquic durable bridge request: %w", err)
	}
	rawBytes := int64(len(encodedRequest))
	if len(copied) == 0 || rawBytes <= 0 {
		return nil, fmt.Errorf("empty txquic durable bridge request")
	}
	// Capacity accounts for the shared certificate and list framing exactly
	// once. Attribute shared bytes to the first item so recursive payload
	// splitting can release the original request's reservation item by item.
	if rawBytes < itemBytes {
		return nil, fmt.Errorf("invalid txquic durable bridge request size")
	}
	copied[0].rawBytes += rawBytes - itemBytes
	r := &txQUICBridgeRequest{
		certificate: copyCommonTxAdmissionBatchForQUIC(certificate),
		items:       copied, am: am, remaining: len(copied), rawBytes: rawBytes, done: make(chan struct{}),
	}
	for i := range r.items {
		r.items[i].request = r
	}
	return r, nil
}

func txQUICBridgeItemRawSize(tx *types.Transaction, admissionIndex uint16) (int64, error) {
	item, err := newTxQUICItem(admissionIndex, tx)
	if err != nil {
		return 0, err
	}
	return txQUICItemRawSize(item)
}

func txQUICItemRawSize(item *txQUICItem) (int64, error) {
	if err := validateTxQUICItem(item); err != nil {
		return 0, err
	}
	maxSize := uint64(^uint64(0) >> 1)
	txSize := uint64(item.Tx.Size())
	if txSize == 0 || txSize > maxSize-16 {
		return 0, fmt.Errorf("invalid transaction encoding size")
	}
	if item.Tx.Type() != types.LegacyTxType {
		// Typed execution envelopes are nested as one RLP byte string. Blob data
		// is separately encoded below and is never part of Transaction.Size.
		txSize = txQUICByteStringSize(txSize)
	}
	indexSize := uint64(1)
	if item.AdmissionIndex > 0x7f {
		indexSize = 2
	}
	if item.AdmissionIndex > 0xff {
		indexSize = 3
	}
	sidecarSize, err := txQUICBlobSidecarRLPSize(item.BlobSidecar)
	if err != nil {
		return 0, err
	}
	if indexSize > maxSize-txSize || sidecarSize > maxSize-indexSize-txSize {
		return 0, fmt.Errorf("transaction item encoding is too large")
	}
	total := rlp.ListSize(indexSize + txSize + sidecarSize)
	if total == 0 || total > maxSize {
		return 0, fmt.Errorf("transaction item encoding is too large")
	}
	return int64(total), nil
}

func txQUICBlobSidecarRLPSize(sidecar *types.BlobTxSidecar) (uint64, error) {
	if sidecar == nil {
		// rlp:"nil" uses the empty-list marker for a nil pointer to a struct.
		return 1, nil
	}
	maxSize := uint64(^uint64(0) >> 1)
	var blobContent uint64
	for _, blob := range sidecar.Blobs {
		encoded := txQUICByteStringSize(uint64(len(blob)))
		if encoded > maxSize-blobContent {
			return 0, fmt.Errorf("blob sidecar encoding is too large")
		}
		blobContent += encoded
	}
	blobs := rlp.ListSize(blobContent)
	commitments := rlp.ListSize(uint64(len(sidecar.Commitments)) * txQUICByteStringSize(uint64(len(types.KZGCommitment{}))))
	proofs := rlp.ListSize(uint64(len(sidecar.Proofs)) * txQUICByteStringSize(uint64(len(types.KZGProof{}))))
	// Supported wrapper versions 0 and 1 are both encoded as one RLP byte
	// (0 as the empty-string marker and 1 as itself). validateTxQUICItem has
	// already rejected every other version before this sizing path.
	version := uint64(1)
	if commitments > maxSize-blobs || proofs > maxSize-blobs-commitments || version > maxSize-blobs-commitments-proofs {
		return 0, fmt.Errorf("blob sidecar encoding is too large")
	}
	total := rlp.ListSize(version + blobs + commitments + proofs)
	if total == 0 || total > maxSize {
		return 0, fmt.Errorf("blob sidecar encoding is too large")
	}
	return total, nil
}

func txQUICByteStringSize(content uint64) uint64 {
	if content <= 55 {
		return content + 1
	}
	lengthBytes := uint64(0)
	for size := content; size > 0; size >>= 8 {
		lengthBytes++
	}
	return 1 + lengthBytes + content
}

func (r *txQUICBridgeRequest) complete(items int, err error) {
	if r == nil || items <= 0 {
		return
	}
	r.mu.Lock()
	if r.completed {
		r.mu.Unlock()
		return
	}
	if err != nil && r.result == nil {
		r.result = err
	}
	if items > r.remaining {
		items = r.remaining
	}
	r.remaining -= items
	if r.remaining != 0 {
		r.mu.Unlock()
		return
	}
	r.completed = true
	r.mu.Unlock()
	close(r.done)
}

func (r *txQUICBridgeRequest) err() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.result
}

type txQUICForwardClient struct {
	endpoint        string
	receiptIdentity common.Hash
	tlsGeneration   common.Hash

	closed     atomic.Bool
	mu         sync.Mutex
	conn       *quic.Conn
	dialing    chan struct{}
	dialCancel context.CancelFunc
}

type txQUICTLSCertificateResult struct {
	certificate tls.Certificate
	err         error
}

type txQUICTLSIdentity struct {
	ChainID       uint64
	GenesisHash   common.Hash
	KeyNumber     uint64
	CommitteeHash common.Hash
	Endpoint      string
}

type txQUICAckReceipt struct {
	Endpoint string
	Identity common.Hash
	Ack      txQUICAck
}

type txQUICPermanentReceiptCount struct {
	count   int
	outcome txQUICPermanentError
}

type txQUICReceiptAccumulator struct {
	expectation txQUICAckExpectation
	quorum      int
	identities  map[common.Hash]struct{}
	durable     []int
	permanent   []map[uint16]*txQUICPermanentReceiptCount
}

func newTxQUICReceiptAccumulator(expectation txQUICAckExpectation, quorum int) (*txQUICReceiptAccumulator, error) {
	if quorum <= 0 || len(expectation.itemIDs) == 0 {
		return nil, fmt.Errorf("invalid txquic receipt quorum")
	}
	return &txQUICReceiptAccumulator{
		expectation: expectation,
		quorum:      quorum,
		identities:  make(map[common.Hash]struct{}),
		durable:     make([]int, len(expectation.itemIDs)),
		permanent:   make([]map[uint16]*txQUICPermanentReceiptCount, len(expectation.itemIDs)),
	}, nil
}

func (a *txQUICReceiptAccumulator) add(receipt *txQUICAckReceipt) (bool, error) {
	if a == nil || receipt == nil || receipt.Identity == (common.Hash{}) {
		return false, fmt.Errorf("invalid txquic receipt identity")
	}
	identity := txQUICReceiptIdentity(receipt.Ack.CommitteePublicKey)
	if identity == (common.Hash{}) || receipt.Identity != identity {
		return false, fmt.Errorf("txquic receipt identity does not match its committee key")
	}
	if _, duplicate := a.identities[receipt.Identity]; duplicate {
		return false, nil
	}
	if err := validateTxQUICAckOutcome(&receipt.Ack, a.expectation); err != nil {
		return false, err
	}
	a.identities[receipt.Identity] = struct{}{}
	permanentByIndex := make(map[uint32]txQUICPermanentError, len(receipt.Ack.PermanentErrors))
	for _, outcome := range receipt.Ack.PermanentErrors {
		permanentByIndex[outcome.Index] = outcome
	}
	for index := range a.expectation.itemIDs {
		if txQUICBitmapHas(receipt.Ack.DurableBitmap, index) {
			a.durable[index]++
			continue
		}
		outcome, ok := permanentByIndex[uint32(index)]
		if !ok {
			continue
		}
		if a.permanent[index] == nil {
			a.permanent[index] = make(map[uint16]*txQUICPermanentReceiptCount)
		}
		count := a.permanent[index][outcome.Code]
		if count == nil {
			count = &txQUICPermanentReceiptCount{outcome: outcome}
			a.permanent[index][outcome.Code] = count
		}
		count.count++
		if outcome.Reason < count.outcome.Reason {
			count.outcome = outcome
		}
	}
	return true, nil
}

func (a *txQUICReceiptAccumulator) outcome() (txQUICAck, bool) {
	ack := txQUICAck{
		ChainID: a.expectation.chainID, GenesisHash: a.expectation.genesisHash,
		KeyNumber: a.expectation.keyNumber, CommitteeHash: a.expectation.committeeHash, BatchID: a.expectation.batchID,
		Sender: a.expectation.sender, SenderEpoch: a.expectation.senderEpoch, Nonce: a.expectation.nonce,
		ItemCount: uint32(len(a.expectation.itemIDs)), DurableBitmap: make([]byte, txQUICBitmapBytes(len(a.expectation.itemIDs))),
		RetryableBitmap: make([]byte, txQUICBitmapBytes(len(a.expectation.itemIDs))),
	}
	complete := true
	for index := range a.expectation.itemIDs {
		if a.durable[index] >= a.quorum {
			txQUICBitmapSet(ack.DurableBitmap, index)
			continue
		}
		var selected *txQUICPermanentReceiptCount
		for _, count := range a.permanent[index] {
			if count.count < a.quorum {
				continue
			}
			if selected == nil || count.outcome.Code < selected.outcome.Code {
				selected = count
			}
		}
		if selected != nil {
			ack.PermanentErrors = append(ack.PermanentErrors, selected.outcome)
			continue
		}
		txQUICBitmapSet(ack.RetryableBitmap, index)
		complete = false
	}
	return ack, complete
}

// receiptsNeeded returns the minimum number of additional terminal receipts
// that could complete every unresolved item. Retryable votes do not count:
// another committee identity must still report a durable or matching permanent
// outcome for that item.
func (a *txQUICReceiptAccumulator) receiptsNeeded() int {
	if a == nil {
		return 0
	}
	needed := 0
	for index := range a.expectation.itemIDs {
		best := a.durable[index]
		for _, count := range a.permanent[index] {
			if count != nil && count.count > best {
				best = count.count
			}
		}
		if missing := a.quorum - best; missing > needed {
			needed = missing
		}
	}
	return needed
}

func txQUICOutcomeError(endpoint string, ack txQUICAck, expectation txQUICAckExpectation) error {
	rejects := make([]txQUICTransactionReject, 0)
	for index := range expectation.itemIDs {
		if txQUICBitmapHas(ack.RetryableBitmap, index) {
			rejects = append(rejects, txQUICTransactionReject{
				Hash: expectation.txHashes[index], Reason: "committee receipt quorum is incomplete", Class: txQUICRejectRetryable,
			})
		}
	}
	for _, permanent := range ack.PermanentErrors {
		rejects = append(rejects, txQUICTransactionReject{
			Hash: expectation.txHashes[permanent.Index], Reason: permanent.Reason, Class: txQUICRejectPermanent,
		})
	}
	if len(rejects) == 0 {
		return nil
	}
	ackCopy := copyTxQUICAck(ack)
	return &txQUICRemoteRejectError{endpoint: endpoint, rejects: rejects, ack: &ackCopy}
}

type txQUICReceiptForwarder func(context.Context, string, []byte) (*txQUICAckReceipt, error)

// txQUICPropagateAttemptCancellation binds placement to the foreground attempt
// until detach returns. The mutex linearizes a deadline callback that has
// already started with the quorum handoff, preventing a revoked callback from
// canceling receiver ACK reads after background ownership has begun.
func txQUICPropagateAttemptCancellation(attempt context.Context, cancel context.CancelFunc) (detach func()) {
	var mu sync.Mutex
	attemptOwnsPlacement := true
	stop := context.AfterFunc(attempt, func() {
		mu.Lock()
		defer mu.Unlock()
		if attemptOwnsPlacement {
			cancel()
		}
	})
	return func() {
		mu.Lock()
		attemptOwnsPlacement = false
		stop()
		mu.Unlock()
	}
}

type txQUICForwardResult struct {
	endpoint string
	receipt  *txQUICAckReceipt
	err      error
}

// txOutboxPlacementState is the durable second stage of an outbox record. A
// quorum is sufficient for foreground availability, but the record is not
// removable until every canonical committee endpoint has returned an
// authenticated terminal outcome. QuorumEstablished is the fsynced trusted
// promotion boundary: an item-wise quorum can legitimately set it while fewer
// than q endpoints have terminal outcomes for the whole batch. Keeping the
// complete endpoint/key vectors binds the bitmap to one exact committee
// generation across process restarts.
type txOutboxPlacementState struct {
	KeyNumber         uint64
	CommitteeHash     common.Hash
	Endpoints         []string
	PublicKeys        [][]byte
	QuorumEstablished bool
	CompletedBitmap   []byte
	NextEndpoint      uint32
}

func newTxOutboxPlacementState(route txQUICFHSRouteCache) (txOutboxPlacementState, error) {
	endpoints := make([]string, len(route.CommitteeEndpoints))
	for index, endpoint := range route.CommitteeEndpoints {
		endpoints[index] = canonicalTxQUICEndpoint(endpoint)
	}
	state := txOutboxPlacementState{
		KeyNumber:       route.KeyNumber,
		CommitteeHash:   route.CommitteeHash,
		Endpoints:       endpoints,
		PublicKeys:      cloneTxQUICPublicKeys(route.CommitteePublicKeys),
		CompletedBitmap: make([]byte, txQUICBitmapBytes(len(route.CommitteeEndpoints))),
	}
	if err := validateTxOutboxPlacementState(state, false); err != nil {
		return txOutboxPlacementState{}, err
	}
	return state, nil
}

func cloneTxOutboxPlacementState(state txOutboxPlacementState) txOutboxPlacementState {
	state.Endpoints = append([]string(nil), state.Endpoints...)
	state.PublicKeys = cloneTxQUICPublicKeys(state.PublicKeys)
	state.CompletedBitmap = append([]byte(nil), state.CompletedBitmap...)
	return state
}

func validateTxOutboxPlacementState(state txOutboxPlacementState, allowComplete bool) error {
	committeeSize := len(state.Endpoints)
	if state.CommitteeHash == (common.Hash{}) || committeeSize < 4 || committeeSize > params.MaxFairHotstuffCommitteeSize ||
		(committeeSize-1)%3 != 0 || len(state.PublicKeys) != committeeSize ||
		!txQUICBitmapPaddingZero(state.CompletedBitmap, committeeSize) || state.NextEndpoint >= uint32(committeeSize) {
		return fmt.Errorf("invalid tx outbox committee placement state")
	}
	seenEndpoints := make(map[string]struct{}, committeeSize)
	seenKeys := make(map[string]struct{}, committeeSize)
	for index, endpoint := range state.Endpoints {
		canonical := canonicalTxQUICEndpoint(endpoint)
		_, _, validEndpoint := splitHostPortLoose(endpoint)
		if canonical == "" || canonical != endpoint || len(endpoint) > 512 || !validEndpoint {
			return fmt.Errorf("invalid tx outbox placement endpoint at %d", index)
		}
		if _, duplicate := seenEndpoints[canonical]; duplicate {
			return fmt.Errorf("duplicate tx outbox placement endpoint %q", endpoint)
		}
		seenEndpoints[canonical] = struct{}{}
		public := bls.GetPublicKey(state.PublicKeys[index])
		if public == nil || !bytes.Equal(public.Serialize(), state.PublicKeys[index]) {
			return fmt.Errorf("invalid tx outbox placement committee key at %d", index)
		}
		keyID := string(state.PublicKeys[index])
		if _, duplicate := seenKeys[keyID]; duplicate {
			return fmt.Errorf("duplicate tx outbox placement committee key at %d", index)
		}
		seenKeys[keyID] = struct{}{}
	}
	if !allowComplete && state.complete() {
		return fmt.Errorf("completed tx outbox placement state must be removed")
	}
	return nil
}

func validatePersistedTxOutboxPlacementState(state txOutboxPlacementState) error {
	if err := validateTxOutboxPlacementState(state, false); err != nil {
		return err
	}
	if !state.QuorumEstablished {
		return fmt.Errorf("tx outbox placement state has no trusted item-wise quorum promotion")
	}
	return nil
}

func (state txOutboxPlacementState) present() bool {
	return state.CommitteeHash != (common.Hash{})
}

func (state txOutboxPlacementState) complete() bool {
	if len(state.Endpoints) == 0 || !txQUICBitmapPaddingZero(state.CompletedBitmap, len(state.Endpoints)) {
		return false
	}
	for index := range state.Endpoints {
		if !txQUICBitmapHas(state.CompletedBitmap, index) {
			return false
		}
	}
	return true
}

func (state txOutboxPlacementState) matchesRoute(route txQUICFHSRouteCache) bool {
	if !state.present() || state.KeyNumber != route.KeyNumber || state.CommitteeHash != route.CommitteeHash ||
		len(state.Endpoints) != len(route.CommitteeEndpoints) || len(state.PublicKeys) != len(route.CommitteePublicKeys) {
		return false
	}
	for index := range state.Endpoints {
		if state.Endpoints[index] != canonicalTxQUICEndpoint(route.CommitteeEndpoints[index]) ||
			!bytes.Equal(state.PublicKeys[index], route.CommitteePublicKeys[index]) {
			return false
		}
	}
	return true
}

func (state txOutboxPlacementState) nextPending() (int, bool) {
	if len(state.Endpoints) == 0 || state.NextEndpoint >= uint32(len(state.Endpoints)) {
		return 0, false
	}
	for offset := 0; offset < len(state.Endpoints); offset++ {
		index := (int(state.NextEndpoint) + offset) % len(state.Endpoints)
		if !txQUICBitmapHas(state.CompletedBitmap, index) {
			return index, true
		}
	}
	return 0, false
}

func (state *txOutboxPlacementState) recordResult(index int, completed bool) {
	if state == nil || index < 0 || index >= len(state.Endpoints) {
		return
	}
	if completed {
		txQUICBitmapSet(state.CompletedBitmap, index)
	}
	state.NextEndpoint = uint32((index + 1) % len(state.Endpoints))
}

// txOutboxPlacementPendingError is a successful foreground quorum whose
// residual endpoint placement is already synchronous in the outbox record.
// Retry controls whether the scheduler should apply delivery backoff (a failed
// tail attempt) or immediately drain another endpoint (new/progressed state).
type txOutboxPlacementPendingError struct {
	Retry bool
	Cause error
}

func (e *txOutboxPlacementPendingError) Error() string {
	if e == nil || e.Cause == nil {
		return "txquic committee tail placement is pending"
	}
	return fmt.Sprintf("txquic committee tail placement is pending: %v", e.Cause)
}

// txQUICBackgroundForward is a best-effort accelerator for endpoint requests
// that were still in flight when a durable quorum completed. Correctness does
// not depend on this bounded channel: the outbox placement stage is fsynced
// first and its workers retry every endpoint not represented in the bitmap.
type txQUICBackgroundForward struct {
	payload   []byte
	endpoints []string
	results   <-chan txQUICForwardResult
	pending   int
	cancel    context.CancelFunc
}

type TxQUICIngress struct {
	config      TxQUICConfig
	txpool      *core.TxPool
	liveIngress *txLiveIngressScheduler
	poolIngress *txPoolIngressScheduler
	outbox      *TxOutbox
	ingress     *TxQUICIngressStore
	wal         *txIngressWAL
	am          *accounts.Manager
	canonicalTx func(common.Hash) bool
	finalizedTx func(common.Hash) bool
	obsoleteTxs func(types.Transactions) []bool

	ctx    context.Context
	cancel context.CancelFunc

	listener         *quic.Listener
	transport        *quic.Transport
	packetConn       net.PacketConn
	http3Server      *http3.Server
	http3Handler     http.Handler
	receiptPublicKey func() ([]byte, error)
	receiptSigner    func(uint64, common.Hash, []byte) ([]byte, error)
	tlsRefresh       chan struct{}
	tlsMu            sync.Mutex
	tlsCertificate   tls.Certificate
	tlsGeneration    common.Hash
	tlsRouteChecked  time.Time
	tlsRouteErr      error

	allowNets []*net.IPNet
	allowIPs  map[string]struct{}
	allowErr  error
	signers   map[common.Address]struct{}

	wg        sync.WaitGroup
	connSem   chan struct{}
	streamSem chan struct{}

	rateMu     sync.Mutex
	buckets    map[string]*txQUICRateBucket
	rateLastGC time.Time

	inflightPayloadMu    sync.Mutex
	inflightPayloadBytes int64
	inflightPayloadLimit int64

	verifyAdmission func(*types.CommonTxAdmissionBatch, *mathbig.Int, common.Hash) ([]core.CommonRPCAdmissionResult, error)
	hasAdmission    func(common.Hash) bool

	durableQueue               chan *txQUICBridgeRequest
	durableSlots               chan struct{}
	durableCapacityMu          sync.Mutex
	durableBytes               int64
	durableBytesLimit          int64
	durableCapacityCh          chan struct{}
	backgroundForwards         chan txQUICBackgroundForward
	backgroundForwardMu        sync.RWMutex
	backgroundForwardAccepting bool
	bridgeAcceptMu             sync.RWMutex
	bridgeAccepting            bool
	forwardCursor              uint64

	forwardClients sync.Map // map[string]*txQUICForwardClient

	routeRefreshMu  sync.Mutex
	routeMu         sync.RWMutex
	routeProvider   TxQUICFHSRouteProvider
	routeGeneration uint64
	routeRefresh    chan struct{}
	routeCache      txQUICFHSRouteCache
	ingressCursor   []byte
}

func (config *TxQUICConfig) ApplyFixedCommitteeAutoRole(chainConfig *params.ChainConfig) {
	if config == nil || !config.AutoRole || chainConfig == nil || !chainConfig.FairHotstuff || len(chainConfig.GenCommittee) == 0 {
		return
	}
	if config.PortOffset == 0 {
		config.PortOffset = 2000
	}
	localRnetPort, err := strconv.Atoi(chainConfig.RnetPort)
	if err != nil || localRnetPort <= 0 {
		return
	}
	localIndex := -1
	for i := 0; i < len(chainConfig.GenCommittee); i++ {
		node, ok := chainConfig.GenCommittee[i]
		if !ok {
			continue
		}
		_, port, ok := splitHostPortLoose(node.Address)
		if !ok {
			continue
		}
		if port == localRnetPort {
			localIndex = i
			break
		}
	}
	if localIndex >= 0 {
		config.Enabled = true
		config.BridgeEnabled = false
		config.HTTP3Enabled = false
		config.Port = localRnetPort + config.PortOffset
		// Every authenticated FHS committee member is a transaction ingress.
		// Leader election controls proposal authority, not mempool admission.
		log.Info("TxQUIC auto role: validator ingress", "committeeIndex", localIndex, "rnetPort", localRnetPort, "txquicPort", config.Port)
		return
	}

	config.Enabled = false
	config.BridgeEnabled = true
	// CurrentFHSRoute is the only endpoint source. A stale genesis/static list
	// cannot define a Byzantine quorum and is therefore not retained as fallback.
	log.Info("TxQUIC auto role: common RPC FHS bridge", "http3rpc", config.HTTP3Enabled)
}

func (config *TxQUICConfig) ApplyHTTP3RPCDefaults(httpHost string, httpPort int) {
	if config == nil || !config.HTTP3Enabled {
		return
	}
	if config.HTTP3Addr == "" {
		if httpHost != "" {
			config.HTTP3Addr = httpHost
		} else {
			config.HTTP3Addr = "0.0.0.0"
		}
	}
	if config.HTTP3Port == 0 {
		if httpPort > 0 {
			config.HTTP3Port = httpPort
		} else {
			config.HTTP3Port = 8545
		}
	}
}

func NewTxQUICIngress(config TxQUICConfig, txpool *core.TxPool) *TxQUICIngress {
	applyTxQUICDefaults(&config)
	ctx, cancel := context.WithCancel(context.Background())
	connectionSlots := minPositiveInt(config.MaxIncomingConns, txQUICMaxConnectionSlots)
	ingressWorkers := minPositiveInt(config.IngressWorkers, txQUICMaxIngressWorkers)
	q := &TxQUICIngress{
		config:               config,
		txpool:               txpool,
		ctx:                  ctx,
		cancel:               cancel,
		connSem:              make(chan struct{}, connectionSlots),
		streamSem:            make(chan struct{}, ingressWorkers),
		inflightPayloadLimit: config.MaxInflightPayloadBytes,
		tlsRefresh:           make(chan struct{}, 1),
		routeRefresh:         make(chan struct{}, 1),
		buckets:              make(map[string]*txQUICRateBucket),
		allowIPs:             make(map[string]struct{}),
		signers:              make(map[common.Address]struct{}),
	}
	if txpool != nil {
		q.liveIngress = newTxLiveIngressScheduler(txLiveIngressSchedulerConfigFor(config))
		q.poolIngress = newTxPoolIngressScheduler(txpool, txPoolIngressSchedulerConfigFor(config))
	}
	if config.BridgeEnabled {
		bridgeWorkers := minPositiveInt(config.BridgeWorkers, txQUICMaxBridgeWorkers)
		bridgeQueueItems := minPositiveInt(config.BridgeQueueSize, txQUICMaxBridgeQueueItems)
		durableQueueSize := bridgeWorkers * 64
		if durableQueueSize < 64 {
			durableQueueSize = 64
		}
		if durableQueueSize > bridgeQueueItems {
			durableQueueSize = bridgeQueueItems
		}
		q.durableQueue = make(chan *txQUICBridgeRequest, durableQueueSize)
		q.durableSlots = make(chan struct{}, bridgeQueueItems)
		q.durableBytesLimit = config.BridgeQueueMaxBytes
		q.durableCapacityCh = make(chan struct{})
		q.backgroundForwards = make(chan txQUICBackgroundForward, 16)
	}
	q.allowErr = q.parseAllowlist()
	q.parseSigners()
	return q
}

func minPositiveInt(value, maximum int) int {
	if value <= 0 {
		return 1
	}
	if value > maximum {
		return maximum
	}
	return value
}

func validateTxQUICRuntimeLimits(config TxQUICConfig) error {
	if config.ReplayWindow < 64 || config.ReplayWindow > txQUICMaxReplayWindow || config.ReplayWindow%8 != 0 {
		return fmt.Errorf("txquic replay window must be a multiple of 8 in [64,%d]", txQUICMaxReplayWindow)
	}
	if config.IngressWorkers <= 0 || config.IngressWorkers > txQUICMaxIngressWorkers ||
		config.MaxIncomingConns <= 0 || config.MaxIncomingConns > txQUICMaxConnectionSlots ||
		config.MaxIncomingStreams <= 0 || config.MaxIncomingStreams > txQUICMaxConnectionSlots {
		return fmt.Errorf("txquic ingress concurrency exceeds its safe bound")
	}
	if config.MaxIncomingConns > config.IngressWorkers || config.MaxIncomingStreams > int64(config.IngressWorkers) ||
		config.MaxIncomingStreams > int64(^uint64(0)>>1)/int64(config.MaxIncomingConns) ||
		config.MaxIncomingStreams*int64(config.MaxIncomingConns) > txQUICMaxAdvertisedStreamProduct {
		return fmt.Errorf("txquic connection and stream product is not bounded by ingress workers")
	}
	maxWorkerPayloadBytes := int64(config.IngressWorkers) * txQUICMicroBatchMaxWireBytes
	if config.MaxInflightPayloadBytes < txQUICMicroBatchMaxWireBytes ||
		config.MaxInflightPayloadBytes > maxWorkerPayloadBytes || config.MaxInflightPayloadBytes > txQUICMaxInflightPayloadBytes {
		return fmt.Errorf("txquic in-flight payload byte limit is outside its worker bound")
	}
	if config.RateBucketMaxEntries <= 0 || config.RateBucketMaxEntries > txQUICMaxRateBucketEntries ||
		config.RateBucketIdleTTL < time.Second || config.RateBucketIdleTTL > 24*time.Hour {
		return fmt.Errorf("txquic rate bucket retention is outside its safe bound")
	}
	if config.BridgeWorkers <= 0 || config.BridgeWorkers > txQUICMaxBridgeWorkers ||
		config.OutboxWorkers <= 0 || config.OutboxWorkers > txQUICMaxBridgeWorkers ||
		config.BridgeQueueSize <= 0 || config.BridgeQueueSize > txQUICMaxBridgeQueueItems ||
		config.BridgeQueueMaxBytes <= 0 || config.BridgeQueueMaxBytes > txQUICMaxBridgeQueueBytes {
		return fmt.Errorf("txquic bridge concurrency exceeds its safe bound")
	}
	if config.OutboxMaxRecords <= 0 || config.OutboxMaxRecords > txQUICMaxOutboxRecords ||
		config.OutboxMaxBytes <= 0 || config.OutboxMaxBytes > txQUICMaxOutboxBytes {
		return fmt.Errorf("txquic durable storage exceeds its safe bound")
	}
	if config.IngressCommitMaxRequests <= 0 || config.IngressCommitMaxRequests > txQUICMaxCommitRequests ||
		config.IngressCommitMaxBytes < txQUICMicroBatchMaxWireBytes || config.IngressCommitMaxBytes > txQUICMaxCommitBytes ||
		config.IngressCommitInterval <= 0 || config.IngressCommitInterval > time.Second {
		return fmt.Errorf("txquic ingress group commit configuration is outside its safe bound")
	}
	if config.MaxClockSkew <= 0 || config.MaxPacketAge <= 0 || config.NonceReservation == 0 || config.NonceReservation > txQUICMaxReplayWindow ||
		config.IngressAckRetention < config.MaxPacketAge || config.IngressAckRetention > 30*24*time.Hour {
		return fmt.Errorf("txquic replay or retention configuration is outside its safe bound")
	}
	if config.ForwardTimeout <= 0 || config.ForwardHedgeDelay <= 0 || config.ForwardHedgeDelay > config.ForwardTimeout {
		return fmt.Errorf("txquic forwarding timeout or hedge delay is outside its safe bound")
	}
	return nil
}

func applyTxQUICDefaults(config *TxQUICConfig) {
	if config.Addr == "" {
		config.Addr = "0.0.0.0"
	}
	if config.Port == 0 {
		config.Port = 4444
	}
	if config.PortOffset == 0 {
		config.PortOffset = 2000
	}
	if config.BridgeQueueSize <= 0 {
		config.BridgeQueueSize = int(params.NativeParallelHardMaxTransactions)
	}
	if config.BridgeQueueMaxBytes <= 0 {
		config.BridgeQueueMaxBytes = defaultTxQUICBridgeQueueMaxBytes
	}
	if config.OutboxMaxRecords <= 0 {
		config.OutboxMaxRecords = defaultTxOutboxMaxRecords
	}
	if config.OutboxMaxBytes <= 0 {
		config.OutboxMaxBytes = defaultTxOutboxMaxBytes
	}
	if config.BridgeWorkers <= 0 {
		config.BridgeWorkers = defaultTxQUICBridgeWorkers
	}
	if config.OutboxWorkers <= 0 {
		config.OutboxWorkers = defaultTxOutboxWorkers
	}
	if config.OutboxRetryMin <= 0 {
		config.OutboxRetryMin = defaultTxOutboxRetryMin
	}
	if config.OutboxRetryMax < config.OutboxRetryMin {
		config.OutboxRetryMax = defaultTxOutboxRetryMax
	}
	if config.BridgeBatchInterval <= 0 {
		config.BridgeBatchInterval = 10 * time.Millisecond
	}
	if config.IngressWorkers <= 0 {
		config.IngressWorkers = defaultTxQUICIngressWorkers
	}
	if config.MaxIncomingStreams <= 0 {
		config.MaxIncomingStreams = int64(config.IngressWorkers)
	}
	if config.MaxIncomingConns <= 0 {
		config.MaxIncomingConns = config.IngressWorkers
	}
	if config.MaxInflightPayloadBytes <= 0 {
		config.MaxInflightPayloadBytes = defaultTxQUICMaxInflightPayloadBytes
		maxWorkerPayloadBytes := int64(config.IngressWorkers) * txQUICMicroBatchMaxWireBytes
		if config.MaxInflightPayloadBytes > maxWorkerPayloadBytes {
			config.MaxInflightPayloadBytes = maxWorkerPayloadBytes
		}
	}
	if config.ReadTimeout <= 0 {
		config.ReadTimeout = 5 * time.Second
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = 5 * time.Second
	}
	if config.ForwardTimeout <= 0 {
		config.ForwardTimeout = 3 * time.Second
	}
	if config.ForwardHedgeDelay <= 0 {
		config.ForwardHedgeDelay = 100 * time.Millisecond
		if config.ForwardHedgeDelay > config.ForwardTimeout {
			config.ForwardHedgeDelay = config.ForwardTimeout / 4
			if config.ForwardHedgeDelay <= 0 {
				config.ForwardHedgeDelay = time.Millisecond
			}
		}
	}
	if config.MaxTxsPerIPPerSecond <= 0 {
		config.MaxTxsPerIPPerSecond = 500000
	}
	if config.BurstTxsPerIP <= 0 {
		config.BurstTxsPerIP = 1000000
	}
	if config.RateBucketMaxEntries <= 0 {
		config.RateBucketMaxEntries = 65536
	}
	if config.RateBucketIdleTTL <= 0 {
		config.RateBucketIdleTTL = 10 * time.Minute
	}
	if config.ReplayWindow == 0 {
		config.ReplayWindow = 65536
	}
	if config.MaxClockSkew <= 0 {
		config.MaxClockSkew = 30 * time.Second
	}
	if config.MaxPacketAge <= 0 {
		config.MaxPacketAge = 10 * time.Minute
	}
	if config.NonceReservation == 0 {
		config.NonceReservation = 4096
	}
	if config.IngressCommitInterval <= 0 {
		config.IngressCommitInterval = time.Millisecond
	}
	if config.IngressCommitMaxRequests <= 0 {
		config.IngressCommitMaxRequests = 64
	}
	if config.IngressCommitMaxBytes <= 0 {
		config.IngressCommitMaxBytes = 16 * 1024 * 1024
	}
	if config.IngressAckRetention <= 0 {
		config.IngressAckRetention = 10 * time.Minute
	}
}

func (q *TxQUICIngress) SetHTTP3RPCHandler(handler http.Handler) { q.http3Handler = handler }

func (q *TxQUICIngress) SetDurableOutbox(outbox *TxOutbox, am *accounts.Manager) {
	if q == nil {
		return
	}
	q.outbox = outbox
	q.am = am
	if outbox != nil && q.wal == nil {
		q.wal = newTxIngressWAL(outbox.db, q.config)
		q.bindIngressWALLookups()
	}
}

func (q *TxQUICIngress) SetDurableIngress(ingress *TxQUICIngressStore) {
	if q == nil {
		return
	}
	q.ingress = ingress
	if ingress != nil && q.wal == nil {
		q.wal = newTxIngressWAL(ingress.db, q.config)
		q.bindIngressWALLookups()
	}
}

// SetIngressWALDatabase selects the role-independent, node-global transaction
// ingress log. Production nodes always provide the same dedicated database for
// bridge-only, receiver-only, and dual-role configurations so a role change
// cannot silently start from an empty authority. Store-local fallbacks above
// exist only for embedders and focused tests.
func (q *TxQUICIngress) SetIngressWALDatabase(db ethdb.KeyValueStore) {
	if q == nil || db == nil {
		return
	}
	q.wal = newTxIngressWAL(db, q.config)
	q.bindIngressWALLookups()
}

func (q *TxQUICIngress) SetCanonicalTxLookup(lookup func(common.Hash) bool) {
	if q == nil {
		return
	}
	q.canonicalTx = lookup
}

func (q *TxQUICIngress) SetFinalizedTxLookup(lookup func(common.Hash) bool) {
	if q == nil {
		return
	}
	q.finalizedTx = lookup
	q.bindIngressWALLookups()
}

func (q *TxQUICIngress) SetObsoleteTxLookup(lookup func(types.Transactions) []bool) {
	if q == nil {
		return
	}
	q.obsoleteTxs = lookup
	q.bindIngressWALLookups()
}

func (q *TxQUICIngress) bindIngressWALLookups() {
	if q != nil && q.wal != nil {
		q.wal.setTransactionLookups(q.finalizedTx, q.obsoleteTxs)
	}
}

func (q *TxQUICIngress) obsoleteTransactions(txs types.Transactions) []bool {
	results := make([]bool, len(txs))
	if q == nil || q.obsoleteTxs == nil || len(txs) == 0 {
		return results
	}
	resolved := q.obsoleteTxs(txs)
	if len(resolved) != len(txs) {
		log.Error("TxQUIC obsolete transaction lookup returned an invalid result count", "have", len(resolved), "want", len(txs))
		return results
	}
	copy(results, resolved)
	return results
}

func (q *TxQUICIngress) SetFHSRouteProvider(provider TxQUICFHSRouteProvider) {
	if q == nil {
		return
	}
	q.routeRefreshMu.Lock()
	q.routeMu.Lock()
	q.routeProvider = provider
	q.routeGeneration++
	q.routeRefresh = make(chan struct{}, 1)
	q.routeCache = txQUICFHSRouteCache{}
	q.routeMu.Unlock()
	connections := q.detachForwardClientsOutsideLocked(txQUICFHSRouteCache{})
	q.routeRefreshMu.Unlock()
	closeTxQUICConnections(connections)
	if provider != nil {
		if route, err := q.refreshFHSRouteCache(); err != nil {
			log.Debug("TxQUIC initial FHS route is not ready", "err", err)
		} else {
			log.Info("TxQUIC connected to Fair HotStuff route provider",
				"proposalView", route.ProposalView,
				"leaderIndex", route.LeaderIndex,
				"endpoint", route.Endpoint)
		}
	}
}

func (q *TxQUICIngress) ResolveTransaction(hash common.Hash) (*types.Transaction, error) {
	if q == nil || q.ingress == nil {
		return nil, nil
	}
	return q.ingress.ResolveTransaction(hash)
}

// SetFHSReceiptSigner binds durable acknowledgements to the validator's
// consensus BLS identity. The same callback attests the node's short-lived TLS
// key, while ACK signatures make one committee member exactly one receipt vote.
func (q *TxQUICIngress) SetFHSReceiptSigner(publicKey func() ([]byte, error), signer func(uint64, common.Hash, []byte) ([]byte, error)) error {
	if q == nil {
		return fmt.Errorf("nil txquic ingress")
	}
	if publicKey == nil || signer == nil {
		return fmt.Errorf("invalid Fair HotStuff receipt signer")
	}
	q.receiptPublicKey = publicKey
	q.receiptSigner = signer
	return nil
}

func (q *TxQUICIngress) Start() error {
	if err := q.validateSecurityConfig(); err != nil {
		q.Stop()
		return err
	}
	if q.wal == nil {
		switch {
		case q.ingress != nil:
			q.wal = newTxIngressWAL(q.ingress.db, q.config)
		case q.outbox != nil:
			q.wal = newTxIngressWAL(q.outbox.db, q.config)
		}
	}
	if q.wal != nil {
		q.bindIngressWALLookups()
		if err := q.wal.Start(q.ctx); err != nil {
			q.Stop()
			return err
		}
		if q.outbox != nil {
			q.outbox.wal = q.wal
		}
		if q.outbox != nil {
			identity := txQUICDatabaseIdentity{ChainID: q.config.ChainID, GenesisHash: q.config.GenesisHash}
			if err := ensureTxQUICDatabaseIdentity(q.outbox.db, txOutboxIdentityKey, identity); err != nil {
				q.Stop()
				return err
			}
		}
		if err := q.replayWALOutboxProjection(); err != nil {
			q.Stop()
			return err
		}
	}
	if q.config.BridgeEnabled {
		q.startBackgroundForwardWorkers()
		if err := q.outbox.Start(q.ctx, q.deliverOutboxPayload, q.restoreOutboxPayload); err != nil {
			q.Stop()
			return err
		}
	}
	if q.config.BridgeEnabled {
		q.startBridgeWorkers()
		q.bridgeAcceptMu.Lock()
		q.bridgeAccepting = true
		q.bridgeAcceptMu.Unlock()
		if err := q.replayWALLocalIntents(); err != nil {
			q.Stop()
			return err
		}
	}
	if q.config.Enabled {
		if q.txpool == nil {
			q.Stop()
			return fmt.Errorf("txquic ingress requires txpool")
		}
		if q.ingress != nil {
			if err := q.ingress.Start(q.ctx); err != nil {
				q.Stop()
				return err
			}
			if err := q.replayWALInboundProjection(); err != nil {
				q.Stop()
				return err
			}
			if err := q.restoreDurableIngress(); err != nil {
				q.Stop()
				return err
			}
			q.wg.Add(1)
			go q.maintainDurableIngress()
		}
	}
	// Recovery above deliberately publishes directly into TxPool. Only after
	// every durable prefix is reconciled do live RPC and QUIC producers share
	// the bounded node-global full-pipeline gate and pool scheduler.
	if q.liveIngress != nil {
		if err := q.liveIngress.Start(); err != nil {
			q.Stop()
			return err
		}
	}
	if q.poolIngress != nil {
		if err := q.poolIngress.Start(q.ctx); err != nil {
			q.Stop()
			return err
		}
	}
	if err := q.startHTTP3RPC(); err != nil {
		q.Stop()
		return err
	}
	if !q.config.Enabled {
		if q.config.BridgeEnabled {
			log.Info("TxQUIC bridge enabled", "queue", q.config.BridgeQueueSize, "queueBytes", q.config.BridgeQueueMaxBytes, "batch", txQUICMicroBatchMaxTxs, "wireBytes", txQUICMicroBatchMaxWireBytes, "interval", q.config.BridgeBatchInterval)
		}
		return nil
	}
	addr := txQUICJoinHostPort(q.config.Addr, q.config.Port)
	packetConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		q.Stop()
		return err
	}
	transport := &quic.Transport{
		Conn: packetConn,
		// Require Retry before allocating a bounded handshake slot, preventing
		// spoofed Initial packets from consuming TLS/BLS verification work.
		VerifySourceAddress: func(net.Addr) bool { return true },
		ConnContext:         q.handshakeContext,
	}
	listener, err := transport.Listen(&tls.Config{
		NextProtos:             []string{txQUICProtocolName},
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			certificate, err := q.serverCertificate(hello.Context())
			if err != nil {
				return nil, err
			}
			return &certificate, nil
		},
	}, &quic.Config{
		HandshakeIdleTimeout: txQUICHandshakeIdleTimeout,
		MaxIncomingStreams:   q.config.MaxIncomingStreams,
		KeepAlivePeriod:      txQUICForwardKeepAlivePeriod,
		MaxIdleTimeout:       txQUICForwardIdleTimeout,
	})
	if err != nil {
		_ = transport.Close()
		_ = packetConn.Close()
		q.Stop()
		return err
	}
	q.listener = listener
	q.transport = transport
	q.packetConn = packetConn
	log.Info("Started QUIC tx ingress", "addr", addr, "protocol", txQUICProtocolName)
	q.wg.Add(1)
	go q.acceptLoop()
	return nil
}

func (q *TxQUICIngress) validateSecurityConfig() error {
	if q == nil {
		return fmt.Errorf("nil txquic ingress")
	}
	if !q.config.Enabled && !q.config.BridgeEnabled && !q.config.HTTP3Enabled {
		return nil
	}
	if !q.config.FairHotstuff {
		return fmt.Errorf("TxQUIC is available only with Fair HotStuff")
	}
	if q.config.ChainID == 0 || q.config.GenesisHash == (common.Hash{}) {
		return fmt.Errorf("txquic requires a non-zero chain ID and genesis hash")
	}
	if err := validateTxQUICRuntimeLimits(q.config); err != nil {
		return err
	}
	if q.allowErr != nil {
		return q.allowErr
	}
	q.routeMu.RLock()
	hasRouteProvider := q.routeProvider != nil
	q.routeMu.RUnlock()
	if (q.config.Enabled || q.config.BridgeEnabled) && !hasRouteProvider {
		return fmt.Errorf("Fair HotStuff TxQUIC requires the canonical committee provider")
	}
	if q.config.Enabled {
		if q.ingress == nil {
			return fmt.Errorf("txquic ingress requires durable storage")
		}
		if len(q.allowIPs) == 0 && len(q.allowNets) == 0 {
			return fmt.Errorf("txquic ingress requires an explicit source IP allowlist")
		}
		if q.canonicalTx == nil || q.finalizedTx == nil || q.obsoleteTxs == nil {
			return fmt.Errorf("txquic ingress requires canonical and finalized transaction state lookups")
		}
		if len(q.signers) == 0 {
			return fmt.Errorf("txquic ingress requires a non-empty signer allowlist")
		}
		if _, invalid := q.signers[common.Address{}]; invalid {
			return fmt.Errorf("txquic signer allowlist contains the zero address")
		}
		if q.config.FairHotstuff && (q.receiptPublicKey == nil || q.receiptSigner == nil) {
			return fmt.Errorf("Fair HotStuff TxQUIC ingress requires a committee BLS receipt signer")
		}
	}
	if q.config.BridgeEnabled {
		if q.outbox == nil {
			return fmt.Errorf("txquic bridge requires a durable outbox")
		}
		if q.am == nil {
			return fmt.Errorf("txquic bridge requires an account manager")
		}
	}
	return nil
}

func (q *TxQUICIngress) Stop() {
	q.backgroundForwardMu.Lock()
	q.backgroundForwardAccepting = false
	q.backgroundForwardMu.Unlock()
	if q.cancel != nil {
		q.cancel()
	}
	if q.liveIngress != nil {
		q.liveIngress.Stop()
	}
	if q.poolIngress != nil {
		q.poolIngress.Stop()
	}
	q.bridgeAcceptMu.Lock()
	q.bridgeAccepting = false
	q.bridgeAcceptMu.Unlock()
	if q.outbox != nil {
		q.outbox.Stop()
	}
	if q.ingress != nil {
		q.ingress.Stop()
	}
	if q.wal != nil {
		q.wal.Stop()
	}
	if q.listener != nil {
		_ = q.listener.Close()
	}
	// A Transport created around an application-owned PacketConn doesn't own or
	// close that socket. Close both explicitly so pending handshakes and active
	// connections release their ConnContext admission slots before wg.Wait.
	if q.transport != nil {
		_ = q.transport.Close()
	}
	if q.packetConn != nil {
		_ = q.packetConn.Close()
	}
	if q.http3Server != nil {
		_ = q.http3Server.Close()
	}
	q.forwardClients.Range(func(_, value interface{}) bool {
		if client, ok := value.(*txQUICForwardClient); ok && client != nil {
			client.close()
		}
		return true
	})
	q.wg.Wait()
	q.failQueuedDurableRequests(errors.New("txquic bridge stopped before durable persistence"))
	log.Info("Stopped QUIC tx ingress")
}

// EnqueueLocalTxsWithAdmissions accepts transactions into the bounded bridge
// queue. It blocks for queue capacity instead of silently dropping traffic.
func (q *TxQUICIngress) EnqueueLocalTxsWithAdmissions(ctx context.Context, txs []*types.Transaction, admissions []core.CommonRPCAdmissionResult, am *accounts.Manager) error {
	return q.enqueueLocalTxsWithAdmissions(ctx, txs, admissions, am, false)
}

// enqueueVerifiedLocalTxsWithAdmissions is the internal RPC fast path for
// admissions returned directly by core.SignAndRecordCommonRPCAdmissions.
// Those functions have already recovered the signer and durably stored the
// admission. Callers crossing a network or disk boundary must use the exported
// validating method above instead.
func (q *TxQUICIngress) enqueueVerifiedLocalTxsWithAdmissions(ctx context.Context, txs []*types.Transaction, admissions []core.CommonRPCAdmissionResult, am *accounts.Manager) error {
	return q.enqueueLocalTxsWithAdmissions(ctx, txs, admissions, am, true)
}

func (q *TxQUICIngress) enqueueLocalTxsWithAdmissions(ctx context.Context, txs []*types.Transaction, admissions []core.CommonRPCAdmissionResult, am *accounts.Manager, signaturesVerified bool) error {
	if q == nil {
		return fmt.Errorf("txquic ingress is nil")
	}
	if !q.config.BridgeEnabled || q.durableQueue == nil || q.outbox == nil {
		return fmt.Errorf("txquic bridge is not enabled")
	}
	if len(txs) == 0 || len(admissions) != len(txs) {
		if len(txs) == 0 {
			return fmt.Errorf("no txs to enqueue")
		}
		return fmt.Errorf("txquic transactions/admissions length mismatch: txs=%d admissions=%d", len(txs), len(admissions))
	}
	if len(txs) > txQUICMaxBridgeQueueItems {
		return fmt.Errorf("txquic enqueue count exceeds bounded bridge limit: count=%d limit=%d", len(txs), txQUICMaxBridgeQueueItems)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if am == nil {
		am = q.am
	}
	groups, err := q.txQUICBridgeGroups(txs, admissions, am, signaturesVerified)
	if err != nil {
		return err
	}
	for _, group := range groups {
		if err := q.enqueueDurableBridgeRequest(ctx, group.certificate, group.items, am); err != nil {
			return err
		}
	}
	return nil
}

type txQUICCertificateGroup struct {
	certificate *types.CommonTxAdmissionBatch
	fingerprint common.Hash
	items       []txQUICBridgeItem
}

type txQUICValidatedCertificate struct {
	certificate *types.CommonTxAdmissionBatch
	fingerprint common.Hash
}

func (q *TxQUICIngress) txQUICBridgeGroups(txs []*types.Transaction, admissions []core.CommonRPCAdmissionResult, am *accounts.Manager, signaturesVerified bool) ([]*txQUICCertificateGroup, error) {
	groups := make([]*txQUICCertificateGroup, 0, (len(txs)+txQUICMicroBatchMaxTxs-1)/txQUICMicroBatchMaxTxs)
	groupByAdmissionID := make(map[common.Hash]*txQUICCertificateGroup)
	// A batch RPC returns one immutable certificate pointer for every item in
	// the signed admission. Validating and hashing that 512-item certificate
	// for each of its 512 transactions turns a bounded micro-batch into O(n²)
	// work before it can even enter the durable queue. Cache only by object
	// identity: a distinct object that claims the same AdmissionID still goes
	// through full structural validation and fingerprint comparison below.
	validatedByPointer := make(map[*types.CommonTxAdmissionBatch]txQUICValidatedCertificate)
	seenTxs := make(map[common.Hash]struct{}, len(txs))
	verifiedCertificates := make(map[common.Hash]struct{})
	for index, tx := range txs {
		if tx == nil {
			return nil, fmt.Errorf("txquic transaction %d is nil", index)
		}
		hash := tx.Hash()
		if _, duplicate := seenTxs[hash]; duplicate {
			return nil, fmt.Errorf("duplicate TxQUIC transaction %s", hash)
		}
		seenTxs[hash] = struct{}{}
		result := admissions[index]
		sourceCertificate := result.Batch
		validated, cached := validatedByPointer[sourceCertificate]
		if !cached {
			certificate := copyCommonTxAdmissionBatchForQUIC(sourceCertificate)
			if err := validateTxQUICCertificateStructure(certificate, q.config.ChainID, q.config.GenesisHash); err != nil {
				return nil, fmt.Errorf("invalid TxQUIC admission certificate for %s: %w", hash, err)
			}
			fingerprint, err := txQUICCertificateHash(certificate)
			if err != nil {
				return nil, err
			}
			if !signaturesVerified {
				if _, verified := verifiedCertificates[fingerprint]; !verified {
					if err := types.VerifyCommonTxAdmissionSignature(certificate); err != nil {
						return nil, fmt.Errorf("invalid TxQUIC admission certificate %s: %w", certificate.AdmissionID, err)
					}
					verifiedCertificates[fingerprint] = struct{}{}
				}
			}
			validated = txQUICValidatedCertificate{certificate: certificate, fingerprint: fingerprint}
			validatedByPointer[sourceCertificate] = validated
		}
		certificate := validated.certificate
		if int(result.Item) >= len(certificate.TxHashes) || certificate.TxHashes[result.Item] != hash {
			return nil, fmt.Errorf("TxQUIC transaction %s does not match admission index %d", hash, result.Item)
		}
		bridgeTx := tx
		var bridgeSidecar *types.BlobTxSidecar
		if tx.Type() == types.BlobTxType {
			// Certificate authentication is deliberately completed before KZG.
			// Canonicalize and own the exact sidecar bytes first, closing the
			// caller-mutation window between verification and WAL/outbox storage.
			owned, err := newTxQUICItem(result.Item, tx)
			if err != nil {
				return nil, fmt.Errorf("invalid TxQUIC blob transaction %s: %w", hash, err)
			}
			attached := owned.Tx.WithBlobSidecar(owned.BlobSidecar)
			if err := q.verifyTxQUICBlobTransactions(types.Transactions{attached}); err != nil {
				return nil, fmt.Errorf("invalid TxQUIC blob sidecar for %s: %w", hash, err)
			}
			bridgeTx, bridgeSidecar = owned.Tx, owned.BlobSidecar
		}
		group := groupByAdmissionID[certificate.AdmissionID]
		if group == nil {
			group = &txQUICCertificateGroup{certificate: certificate, fingerprint: validated.fingerprint}
			groupByAdmissionID[certificate.AdmissionID] = group
			groups = append(groups, group)
		} else if group.fingerprint != validated.fingerprint {
			return nil, fmt.Errorf("conflicting TxQUIC certificates share admission id %s", certificate.AdmissionID)
		}
		group.items = append(group.items, txQUICBridgeItem{tx: bridgeTx, blobSidecar: bridgeSidecar, admissionIndex: result.Item, am: am})
	}
	for _, group := range groups {
		if len(group.items) > q.durableBatchTxLimit() {
			return nil, fmt.Errorf("txquic admission certificate item count exceeds limit: count=%d limit=%d", len(group.items), q.durableBatchTxLimit())
		}
	}
	return groups, nil
}

func (q *TxQUICIngress) durableBatchTxLimit() int {
	return txQUICMicroBatchMaxTxs
}

func (q *TxQUICIngress) durableBatchByteLimit() int64 {
	return txQUICMicroBatchMaxStoredBytes
}

func (q *TxQUICIngress) enqueueDurableBridgeRequest(ctx context.Context, certificate *types.CommonTxAdmissionBatch, items []txQUICBridgeItem, am *accounts.Manager) error {
	return q.enqueueDurableBridgeRequestOwned(ctx, certificate, items, am, false)
}

func (q *TxQUICIngress) enqueueDurableBridgeRequestOwned(ctx context.Context, certificate *types.CommonTxAdmissionBatch, items []txQUICBridgeItem, am *accounts.Manager, walOwned bool) error {
	if q.durableQueue == nil || q.durableSlots == nil {
		return fmt.Errorf("txquic durable bridge queue is unavailable")
	}
	request, err := newTxQUICBridgeRequest(certificate, items, am)
	if err != nil {
		return err
	}
	request.walOwned = walOwned
	q.bridgeAcceptMu.RLock()
	if !q.bridgeAccepting {
		q.bridgeAcceptMu.RUnlock()
		return fmt.Errorf("txquic durable bridge is not accepting requests")
	}
	if err := q.acquireDurableBridgeCapacity(ctx, len(request.items), request.rawBytes); err != nil {
		q.bridgeAcceptMu.RUnlock()
		return err
	}
	select {
	case q.durableQueue <- request:
		q.bridgeAcceptMu.RUnlock()
	case <-ctx.Done():
		q.releaseDurableBridgeCapacity(len(request.items), request.rawBytes)
		q.bridgeAcceptMu.RUnlock()
		return fmt.Errorf("txquic durable bridge enqueue: %w", ctx.Err())
	case <-q.ctx.Done():
		q.releaseDurableBridgeCapacity(len(request.items), request.rawBytes)
		q.bridgeAcceptMu.RUnlock()
		return fmt.Errorf("txquic durable bridge stopped before enqueue")
	}

	select {
	case <-request.done:
		return request.err()
	case <-ctx.Done():
		// The worker deliberately continues the accepted durability operation.
		// The disconnected caller receives no success and may safely retry.
		return fmt.Errorf("txquic durable bridge request canceled after enqueue: %w", ctx.Err())
	case <-q.ctx.Done():
		return fmt.Errorf("txquic durable bridge stopped before request completion")
	}
}

func (q *TxQUICIngress) acquireDurableBridgeCapacity(ctx context.Context, items int, rawBytes int64) error {
	if q == nil || q.durableSlots == nil || items <= 0 || rawBytes <= 0 || q.durableBytesLimit <= 0 || q.durableCapacityCh == nil {
		return fmt.Errorf("txquic durable bridge capacity is unavailable")
	}
	if items > cap(q.durableSlots) {
		return fmt.Errorf("txquic durable bridge request exceeds item capacity: count=%d limit=%d", items, cap(q.durableSlots))
	}
	if rawBytes > q.durableBytesLimit {
		return fmt.Errorf("txquic durable bridge request exceeds byte capacity: size=%d limit=%d", rawBytes, q.durableBytesLimit)
	}
	for {
		q.durableCapacityMu.Lock()
		itemsAvailable := len(q.durableSlots) <= cap(q.durableSlots)-items
		bytesAvailable := q.durableBytes <= q.durableBytesLimit-rawBytes
		if itemsAvailable && bytesAvailable {
			for i := 0; i < items; i++ {
				q.durableSlots <- struct{}{}
			}
			q.durableBytes += rawBytes
			q.durableCapacityMu.Unlock()
			return nil
		}
		changed := q.durableCapacityCh
		q.durableCapacityMu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			if !bytesAvailable {
				return fmt.Errorf("txquic durable bridge byte capacity wait: %w", ctx.Err())
			}
			return fmt.Errorf("txquic durable bridge item capacity wait: %w", ctx.Err())
		case <-q.ctx.Done():
			return fmt.Errorf("txquic durable bridge stopped while waiting for capacity")
		}
	}
}

func (q *TxQUICIngress) releaseDurableBridgeCapacity(items int, rawBytes int64) {
	if q == nil || items <= 0 || rawBytes <= 0 {
		return
	}
	q.durableCapacityMu.Lock()
	if items > len(q.durableSlots) {
		log.Error("TxQUIC durable bridge item accounting underflow", "release", items, "held", len(q.durableSlots))
		items = len(q.durableSlots)
	}
	if rawBytes > q.durableBytes {
		log.Error("TxQUIC durable bridge raw-byte accounting underflow", "release", rawBytes, "held", q.durableBytes)
		rawBytes = q.durableBytes
	}
	for i := 0; i < items; i++ {
		<-q.durableSlots
	}
	q.durableBytes -= rawBytes
	if q.durableCapacityCh != nil {
		close(q.durableCapacityCh)
		q.durableCapacityCh = make(chan struct{})
	}
	q.durableCapacityMu.Unlock()
}

func (q *TxQUICIngress) pendingDurableBridgeBytes() int64 {
	if q == nil {
		return 0
	}
	q.durableCapacityMu.Lock()
	defer q.durableCapacityMu.Unlock()
	return q.durableBytes
}

func (q *TxQUICIngress) deliverOutboxPayload(ctx context.Context, payload []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	batch, _, err := decodeTxQUICBatch(payload)
	if err != nil {
		return err
	}
	if q == nil || q.outbox == nil {
		return fmt.Errorf("txquic durable outbox is unavailable")
	}
	placement, hasPlacement, err := q.outbox.placementForBatch(batch.BatchID, payload)
	if err != nil {
		return err
	}
	if hasPlacement {
		route, routeErr := q.refreshFHSRouteCacheContext(ctx)
		if routeErr != nil {
			return fmt.Errorf("resolve durable TxQUIC placement generation: %w", routeErr)
		}
		if placement.matchesRoute(route) {
			return q.deliverOutboxPlacement(ctx, batch, placement)
		}
		// A retired generation cannot acknowledge a fresh envelope. Retain the
		// semantic batch and establish quorum in the new canonical committee;
		// its checkpoint atomically replaces the obsolete endpoint bitmap.
		log.Debug("TxQUIC outbox placement generation changed; re-establishing quorum",
			"batch", batch.BatchID, "oldKeyNumber", placement.KeyNumber, "newKeyNumber", route.KeyNumber)
	}
	return q.deliverInitialOutboxBatch(ctx, batch, payload)
}

func (q *TxQUICIngress) deliverInitialOutboxBatch(ctx context.Context, batch *txQUICBatch, payload []byte) error {
	wirePayload, err := q.encodeSignedTxQUICPacket(batch, q.am)
	if err != nil {
		return err
	}
	// One worker attempt has one deadline across the whole endpoint set. A
	// failed committee must not occupy an outbox worker for N endpoint timeouts.
	attemptTimeout := q.config.ForwardTimeout
	if attemptTimeout <= 0 {
		attemptTimeout = 3 * time.Second
	}
	attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	forwarded, requiredDelivered, rejectErr := q.routeBridgePayloadContext(attemptCtx, wirePayload)
	if rejectErr != nil {
		return rejectErr
	}
	if !requiredDelivered {
		return fmt.Errorf("no required TxQUIC endpoint acknowledged outbox payload")
	}
	txQUICIngressForwardMeter.Mark(int64(forwarded))
	log.Debug("TxQUIC outbox delivered batch", "forwarded", forwarded, "bytes", len(payload))
	return nil
}

func (q *TxQUICIngress) deliverOutboxPlacement(ctx context.Context, batch *txQUICBatch, placement txOutboxPlacementState) error {
	if q == nil || q.outbox == nil || batch == nil {
		return fmt.Errorf("invalid durable TxQUIC placement delivery")
	}
	if err := validatePersistedTxOutboxPlacementState(placement); err != nil {
		return err
	}
	wirePayload, err := q.encodeSignedTxQUICPacket(batch, q.am)
	if err != nil {
		return err
	}
	return q.deliverOutboxPlacementWith(ctx, batch.BatchID, wirePayload, placement, q.forwardPayloadReceiptContext)
}

func (q *TxQUICIngress) deliverOutboxPlacementWith(ctx context.Context, batchID common.Hash, wirePayload []byte, placement txOutboxPlacementState, forward txQUICReceiptForwarder) error {
	if q == nil || q.outbox == nil || batchID == (common.Hash{}) || len(wirePayload) == 0 || forward == nil {
		return fmt.Errorf("invalid durable TxQUIC placement attempt")
	}
	if err := validatePersistedTxOutboxPlacementState(placement); err != nil {
		return err
	}
	index, pending := placement.nextPending()
	if !pending {
		return nil
	}
	expectation, err := txQUICAckExpectationFromPayload(wirePayload)
	if err != nil {
		return err
	}
	if expectation.keyNumber != placement.KeyNumber || expectation.committeeHash != placement.CommitteeHash {
		return fmt.Errorf("canonical TxQUIC committee changed while preparing tail placement")
	}
	attemptTimeout := q.config.ForwardTimeout
	if attemptTimeout <= 0 {
		attemptTimeout = 3 * time.Second
	}
	attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
	receipt, forwardErr := forward(attemptCtx, placement.Endpoints[index], wirePayload)
	cancel()
	currentRoute, routeErr := q.refreshFHSRouteCacheContext(ctx)
	if routeErr != nil {
		return &txOutboxPlacementPendingError{Retry: true, Cause: fmt.Errorf("revalidate canonical TxQUIC placement generation after endpoint receipt: %w", routeErr)}
	}
	if !placement.matchesRoute(currentRoute) {
		return &txOutboxPlacementPendingError{Retry: true, Cause: fmt.Errorf("canonical TxQUIC committee changed after endpoint receipt")}
	}
	completed := txQUICReceiptPlacementComplete(receipt)
	updated := cloneTxOutboxPlacementState(placement)
	updated.recordResult(index, completed)
	if updated.complete() {
		txQUICIngressForwardMeter.Mark(1)
		log.Debug("TxQUIC outbox completed committee tail placement", "batch", batchID, "endpoint", placement.Endpoints[index])
		return nil
	}
	if err := q.outbox.checkpointPlacementSync(batchID, updated, completed); err != nil {
		return err
	}
	if completed {
		txQUICIngressForwardMeter.Mark(1)
		log.Debug("TxQUIC outbox checkpointed committee tail placement", "batch", batchID, "endpoint", placement.Endpoints[index])
		return &txOutboxPlacementPendingError{}
	}
	if forwardErr == nil {
		forwardErr = fmt.Errorf("endpoint returned a retryable placement outcome")
	}
	return &txOutboxPlacementPendingError{Retry: true, Cause: forwardErr}
}

func (q *TxQUICIngress) restoreOutboxPayload(payload []byte) error {
	batch, _, err := decodeTxQUICBatch(payload)
	if err != nil {
		return err
	}
	if batch.ChainID != q.config.ChainID || batch.GenesisHash != q.config.GenesisHash {
		return fmt.Errorf("restore TxQUIC outbox batch belongs to another chain")
	}
	txs, err := packetItemsToTxs(&txQUICPacket{Certificate: batch.Certificate, Items: batch.Items})
	if err != nil {
		return err
	}
	if err := q.verifyTxQUICBlobTransactions(txs); err != nil {
		return fmt.Errorf("restore TxQUIC outbox blob sidecars: %w", err)
	}
	// Restore sidecars before publishing transactions into the pool. Adding a
	// transaction can synchronously enqueue its NewTx event, and consumers of
	// that event must already be able to resolve the admission sidecar.
	if err := q.verifyAndStoreAdmissionCertificate(batch.Certificate, batch.Items, false); err != nil {
		return fmt.Errorf("restore TxQUIC outbox admission %s: %w", batch.Certificate.AdmissionID, err)
	}
	if q.txpool != nil && len(txs) > 0 {
		results := q.txpool.AddLocalsAsync(txs)
		for i, result := range results {
			if result == nil || errors.Is(result, core.ErrAlreadyKnown) || errors.Is(result, core.ErrNonceTooLow) {
				continue
			}
			var hash common.Hash
			if i < len(txs) && txs[i] != nil {
				hash = txs[i].Hash()
			}
			log.Warn("Failed to restore local transaction from TxQUIC outbox", "tx", hash, "err", result)
		}
	}
	return nil
}

func (q *TxQUICIngress) restoreDurableIngress() error {
	return q.ingress.Restore(q.restoreDurableIngressPayloads)
}

func (q *TxQUICIngress) restoreDurableIngressPayloads(certificate *types.CommonTxAdmissionBatch, items []*txQUICItem) error {
	if err := q.verifyAndStoreAdmissionCertificate(certificate, items, false); err != nil {
		return fmt.Errorf("restore durable ingress admission %s: %w", certificate.AdmissionID, err)
	}
	return q.publishDurableIngressPayloads(items)
}

func (q *TxQUICIngress) publishDurableIngressPayloads(items []*txQUICItem) error {
	if len(items) == 0 {
		return nil
	}
	txs, err := packetItemsToTxs(&txQUICPacket{Items: items})
	if err != nil {
		return fmt.Errorf("restore durable ingress transactions: %w", err)
	}
	if err := q.verifyTxQUICBlobTransactions(txs); err != nil {
		return fmt.Errorf("restore durable ingress blob sidecars: %w", err)
	}
	if q.txpool == nil {
		return nil
	}
	results := q.txpool.AddRemotes(txs)
	for index, result := range results {
		if result == nil || errors.Is(result, core.ErrAlreadyKnown) || errors.Is(result, core.ErrNonceTooLow) {
			continue
		}
		var hash common.Hash
		if index < len(txs) && txs[index] != nil {
			hash = txs[index].Hash()
		}
		log.Warn("Failed to restore remote transaction from durable TxQUIC ingress", "tx", hash, "err", result)
	}
	return nil
}

func (q *TxQUICIngress) maintainDurableIngress() {
	defer q.wg.Done()
	ticker := time.NewTicker(txQUICIngressMaintenance)
	defer ticker.Stop()
	for {
		select {
		case <-q.ctx.Done():
			return
		case <-ticker.C:
			pruned, err := q.maintainDurableIngressPage()
			// Stop cancels the ingress lifecycle before its durable store. If the
			// ticker wins the select race with that cancellation, the maintenance
			// call can observe the store shutting down and return its local
			// "not running" error instead of context.Canceled. Treat every error
			// after lifecycle cancellation as normal shutdown so clean PM2 stops
			// do not emit misleading durability failures.
			if errors.Is(err, context.Canceled) || q.ctx.Err() != nil {
				return
			}
			if err != nil {
				log.Error("Failed to maintain durable TxQUIC ingress", "err", err)
			} else if pruned > 0 {
				log.Debug("Pruned finalized durable TxQUIC ingress", "records", pruned)
			}
		}
	}
}

func (q *TxQUICIngress) maintainDurableIngressPage() (int, error) {
	if q.ingress == nil || q.txpool == nil {
		return 0, nil
	}
	pruned := 0
	next, done, err := q.ingress.ScanPage(
		q.ctx,
		q.ingressCursor,
		txQUICIngressMaintenanceRecords,
		txQUICIngressMaintenanceBytes,
		func(manifest *txQUICIngressManifest) error {
			items, err := q.ingress.PendingItems(manifest.BatchID)
			if err != nil {
				return err
			}
			txs := make(types.Transactions, len(items))
			for index, item := range items {
				if item == nil || item.Tx == nil {
					return fmt.Errorf("invalid pending txquic ingress item")
				}
				txs[index] = item.Tx
			}
			resolved := make(map[common.Hash]struct{}, len(items))
			obsoleteIndexes := make([]int, 0, len(items))
			obsoleteCandidates := make(types.Transactions, 0, len(items))
			for index, tx := range txs {
				hash := tx.Hash()
				if q.finalizedTx != nil && q.finalizedTx(hash) {
					resolved[hash] = struct{}{}
					continue
				}
				obsoleteIndexes = append(obsoleteIndexes, index)
				obsoleteCandidates = append(obsoleteCandidates, tx)
			}
			for resultIndex, isObsolete := range q.obsoleteTransactions(obsoleteCandidates) {
				if isObsolete && resultIndex < len(obsoleteIndexes) {
					resolved[txs[obsoleteIndexes[resultIndex]].Hash()] = struct{}{}
				}
			}
			restoreItems := make([]*txQUICItem, 0, len(items))
			restoreAdmission := false
			for _, item := range items {
				hash := item.Tx.Hash()
				if _, terminal := resolved[hash]; terminal {
					continue
				}
				if q.canonicalTx != nil && q.canonicalTx(hash) {
					continue
				}
				hasAdmission := core.HasCommonRPCAdmission(hash)
				if !q.txpool.Has(hash) || !hasAdmission {
					restoreItems = append(restoreItems, item)
					restoreAdmission = restoreAdmission || !hasAdmission
				}
			}
			if restoreAdmission {
				if err := q.verifyAndStoreAdmissionCertificate(manifest.Certificate, restoreItems, false); err != nil {
					return err
				}
			}
			if err := q.publishDurableIngressPayloads(restoreItems); err != nil {
				return err
			}
			removed, err := q.ingress.CompactFinalized(manifest.BatchID, func(hash common.Hash) bool {
				_, ok := resolved[hash]
				return ok
			}, time.Now())
			pruned += removed
			return err
		},
	)
	if err != nil {
		return 0, err
	}
	if done {
		q.ingressCursor = nil
	} else {
		q.ingressCursor = next
	}
	return pruned, nil
}

func (q *TxQUICIngress) cachedFHSRoute() txQUICFHSRouteCache {
	if q == nil {
		return txQUICFHSRouteCache{}
	}
	q.routeMu.RLock()
	route := q.routeCache
	route.CommitteeEndpoints = append([]string(nil), route.CommitteeEndpoints...)
	route.CommitteePublicKeys = cloneTxQUICPublicKeys(route.CommitteePublicKeys)
	q.routeMu.RUnlock()
	return route
}

func cloneTxQUICPublicKeys(keys [][]byte) [][]byte {
	cloned := make([][]byte, len(keys))
	for index := range keys {
		cloned[index] = append([]byte(nil), keys[index]...)
	}
	return cloned
}

func (q *TxQUICIngress) refreshFHSRouteCache() (txQUICFHSRouteCache, error) {
	if q == nil {
		return txQUICFHSRouteCache{}, fmt.Errorf("nil txquic ingress")
	}
	ctx, cancel := context.WithTimeout(context.Background(), txQUICRouteRefreshTimeout)
	defer cancel()
	if q.ctx != nil {
		stopNodeCancel := context.AfterFunc(q.ctx, cancel)
		defer stopNodeCancel()
	}
	return q.refreshFHSRouteCacheContext(ctx)
}

func (q *TxQUICIngress) refreshFHSRouteCacheContext(parent context.Context) (txQUICFHSRouteCache, error) {
	if q == nil {
		return txQUICFHSRouteCache{}, fmt.Errorf("nil txquic ingress")
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, txQUICRouteRefreshTimeout)
	defer cancel()
	if q.ctx != nil {
		stopNodeCancel := context.AfterFunc(q.ctx, cancel)
		defer stopNodeCancel()
	}

	var provider TxQUICFHSRouteProvider
	var generation uint64
	var refresh chan struct{}
	for {
		q.routeMu.Lock()
		if q.routeRefresh == nil {
			q.routeRefresh = make(chan struct{}, 1)
		}
		provider = q.routeProvider
		generation = q.routeGeneration
		refresh = q.routeRefresh
		q.routeMu.Unlock()
		if provider == nil {
			return q.cachedFHSRoute(), fmt.Errorf("Fair HotStuff route provider is not connected")
		}
		select {
		case refresh <- struct{}{}:
		case <-ctx.Done():
			return q.cachedFHSRoute(), ctx.Err()
		}
		// A provider replacement installs a new generation and gate. Never let a
		// waiter that raced replacement invoke or publish the retired provider.
		q.routeMu.RLock()
		current := q.routeGeneration == generation && q.routeRefresh == refresh
		q.routeMu.RUnlock()
		if current {
			break
		}
		<-refresh
	}
	select {
	case <-ctx.Done():
		<-refresh
		return q.cachedFHSRoute(), ctx.Err()
	default:
	}

	result := make(chan txQUICFHSRouteResult, 1)
	go func() {
		provided, err := provider()
		var route txQUICFHSRouteCache
		if err == nil {
			route, err = q.validateAndPublishFHSRoute(provided, generation)
		} else {
			route = q.cachedFHSRoute()
		}
		<-refresh
		result <- txQUICFHSRouteResult{route: route, err: err}
	}()
	select {
	case refreshed := <-result:
		return refreshed.route, refreshed.err
	case <-ctx.Done():
		return q.cachedFHSRoute(), ctx.Err()
	}
}

func (q *TxQUICIngress) validateAndPublishFHSRoute(provided TxQUICFHSRoute, generation uint64) (txQUICFHSRouteCache, error) {
	committeeSize := len(provided.CommitteeAddresses)
	if provided.ProposalView == 0 || provided.CommitteeHash == (common.Hash{}) || strings.TrimSpace(provided.LeaderAddress) == "" ||
		committeeSize < 4 || committeeSize > params.MaxFairHotstuffCommitteeSize || (committeeSize-1)%3 != 0 || len(provided.CommitteePublicKeys) != committeeSize {
		return q.cachedFHSRoute(), fmt.Errorf("Fair HotStuff route provider returned an incomplete route")
	}
	if provided.LeaderIndex >= uint(len(provided.CommitteeAddresses)) || provided.CommitteeAddresses[provided.LeaderIndex] != provided.LeaderAddress {
		return q.cachedFHSRoute(), fmt.Errorf("Fair HotStuff route leader is outside its committee")
	}
	endpoint, ok := txQUICEndpointFromCommitteeAddress(provided.LeaderAddress, q.config.PortOffset)
	if !ok {
		return q.cachedFHSRoute(), fmt.Errorf("invalid Fair HotStuff leader address %q", provided.LeaderAddress)
	}
	committeeEndpoints := make([]string, len(provided.CommitteeAddresses))
	committeePublicKeys := make([][]byte, len(provided.CommitteeAddresses))
	seenEndpoints := make(map[string]struct{}, len(provided.CommitteeAddresses))
	seenPublicKeys := make(map[string]struct{}, len(provided.CommitteeAddresses))
	for index, address := range provided.CommitteeAddresses {
		memberEndpoint, valid := txQUICEndpointFromCommitteeAddress(address, q.config.PortOffset)
		if !valid {
			return q.cachedFHSRoute(), fmt.Errorf("invalid Fair HotStuff committee address %q", address)
		}
		key := strings.ToLower(memberEndpoint)
		if _, duplicate := seenEndpoints[key]; duplicate {
			return q.cachedFHSRoute(), fmt.Errorf("duplicate Fair HotStuff committee TxQUIC endpoint %q", memberEndpoint)
		}
		seenEndpoints[key] = struct{}{}
		committeeEndpoints[index] = memberEndpoint
		encodedPublic := common.FromHex(provided.CommitteePublicKeys[index])
		public := bls.GetPublicKey(encodedPublic)
		if public == nil || !bytes.Equal(public.Serialize(), encodedPublic) {
			return q.cachedFHSRoute(), fmt.Errorf("invalid Fair HotStuff committee BLS key at index %d", index)
		}
		publicID := string(encodedPublic)
		if _, duplicate := seenPublicKeys[publicID]; duplicate {
			return q.cachedFHSRoute(), fmt.Errorf("duplicate Fair HotStuff committee BLS key at index %d", index)
		}
		seenPublicKeys[publicID] = struct{}{}
		committeePublicKeys[index] = append([]byte(nil), encodedPublic...)
	}
	incoming := txQUICFHSRouteCache{
		ProposalView:        provided.ProposalView,
		KeyNumber:           provided.KeyNumber,
		CommitteeHash:       provided.CommitteeHash,
		LeaderIndex:         provided.LeaderIndex,
		Endpoint:            endpoint,
		CommitteeEndpoints:  committeeEndpoints,
		CommitteePublicKeys: committeePublicKeys,
	}

	q.routeRefreshMu.Lock()
	q.routeMu.Lock()
	if q.routeGeneration != generation {
		q.routeMu.Unlock()
		q.routeRefreshMu.Unlock()
		return q.cachedFHSRoute(), fmt.Errorf("Fair HotStuff route provider changed during refresh")
	}
	// This is the local consensus service, not a network redirect. Its validated
	// snapshot is authoritative even when recovery or a key-block reorg moves
	// the height/view backwards.
	q.routeCache = incoming
	result := q.routeCache
	result.CommitteeEndpoints = append([]string(nil), result.CommitteeEndpoints...)
	result.CommitteePublicKeys = cloneTxQUICPublicKeys(result.CommitteePublicKeys)
	q.routeMu.Unlock()
	// Enforce the canonical endpoint set on every refresh. Client registration
	// takes routeRefreshMu too, so an old-route sender cannot insert a detached
	// connection after this sweep has completed.
	connections := q.detachForwardClientsOutsideLocked(result)
	q.routeRefreshMu.Unlock()
	closeTxQUICConnections(connections)
	return result, nil
}

func (q *TxQUICIngress) closeForwardClientsOutside(route txQUICFHSRouteCache) {
	if q == nil {
		return
	}
	q.routeRefreshMu.Lock()
	connections := q.detachForwardClientsOutsideLocked(route)
	q.routeRefreshMu.Unlock()
	closeTxQUICConnections(connections)
}

// detachForwardClientsOutsideLocked serializes with client registration but
// never waits for QUIC network shutdown. The caller must hold routeRefreshMu.
func (q *TxQUICIngress) detachForwardClientsOutsideLocked(route txQUICFHSRouteCache) []*quic.Conn {
	type allowedClient struct {
		receiptIdentity common.Hash
		tlsGeneration   common.Hash
	}
	connections := make([]*quic.Conn, 0)
	allowed := make(map[string]allowedClient, len(route.CommitteeEndpoints))
	if len(route.CommitteeEndpoints) == len(route.CommitteePublicKeys) {
		for index, endpoint := range route.CommitteeEndpoints {
			_, generation, err := txQUICTLSIdentityPayload(q.config, route.KeyNumber, route.CommitteeHash, endpoint)
			if err != nil {
				continue
			}
			allowed[canonicalTxQUICEndpoint(endpoint)] = allowedClient{
				receiptIdentity: txQUICReceiptIdentity(route.CommitteePublicKeys[index]),
				tlsGeneration:   generation,
			}
		}
	}
	q.forwardClients.Range(func(key, value interface{}) bool {
		endpoint, endpointOK := key.(string)
		client, clientOK := value.(*txQUICForwardClient)
		if !endpointOK || !clientOK || client == nil {
			q.forwardClients.CompareAndDelete(key, value)
			return true
		}
		canonicalEndpoint := canonicalTxQUICEndpoint(endpoint)
		expected, keep := allowed[canonicalEndpoint]
		if endpoint == canonicalEndpoint && canonicalTxQUICEndpoint(client.endpoint) == canonicalEndpoint &&
			keep && expected.receiptIdentity != (common.Hash{}) && expected.tlsGeneration != (common.Hash{}) &&
			client.receiptIdentity == expected.receiptIdentity && client.tlsGeneration == expected.tlsGeneration {
			return true
		}
		if q.forwardClients.CompareAndDelete(key, value) {
			if conn := client.retire(); conn != nil {
				connections = append(connections, conn)
			}
		}
		return true
	})
	return connections
}

func closeTxQUICConnections(connections []*quic.Conn) {
	for _, conn := range connections {
		if conn == nil {
			continue
		}
		select {
		case <-conn.Context().Done():
			continue
		default:
		}
		// quic-go's CloseWithError waits for the connection context. Route
		// publication must not wait on a peer; the number of detached clients is
		// bounded by the canonical committee size.
		go func(conn *quic.Conn) {
			_ = conn.CloseWithError(0, "committee route changed")
		}(conn)
	}
}

func (q *TxQUICIngress) fhsExpectedReceiptKey(endpoint string, keyNumber uint64, committeeHash common.Hash) ([]byte, error) {
	route := q.cachedFHSRoute()
	if len(route.CommitteeEndpoints) == 0 || len(route.CommitteeEndpoints) != len(route.CommitteePublicKeys) {
		return nil, fmt.Errorf("canonical Fair HotStuff receipt identities are unavailable")
	}
	if route.KeyNumber != keyNumber || route.CommitteeHash != committeeHash {
		return nil, fmt.Errorf("canonical Fair HotStuff receipt generation changed")
	}
	for index, memberEndpoint := range route.CommitteeEndpoints {
		if strings.EqualFold(memberEndpoint, endpoint) {
			return append([]byte(nil), route.CommitteePublicKeys[index]...), nil
		}
	}
	return nil, fmt.Errorf("txquic endpoint %q is outside the canonical Fair HotStuff committee", endpoint)
}

func canonicalTxQUICEndpoint(endpoint string) string {
	return strings.ToLower(strings.TrimSpace(endpoint))
}

func txQUICTLSIdentityPayload(config TxQUICConfig, keyNumber uint64, committeeHash common.Hash, endpoint string) ([]byte, common.Hash, error) {
	canonicalEndpoint := canonicalTxQUICEndpoint(endpoint)
	if config.ChainID == 0 || config.GenesisHash == (common.Hash{}) || committeeHash == (common.Hash{}) || canonicalEndpoint == "" {
		return nil, common.Hash{}, fmt.Errorf("invalid txquic TLS identity")
	}
	payload, err := rlp.EncodeToBytes(txQUICTLSIdentity{
		ChainID:       config.ChainID,
		GenesisHash:   config.GenesisHash,
		KeyNumber:     keyNumber,
		CommitteeHash: committeeHash,
		Endpoint:      canonicalEndpoint,
	})
	if err != nil {
		return nil, common.Hash{}, err
	}
	digest := sha256.Sum256(payload)
	return payload, common.BytesToHash(digest[:]), nil
}

func txQUICReceiptIdentity(publicKey []byte) common.Hash {
	if len(publicKey) == 0 {
		return common.Hash{}
	}
	identity := sha256.Sum256(publicKey)
	return common.BytesToHash(identity[:])
}

// txQUICReceiptQuorum is 2f+1 for a committee that tolerates
// f=floor((n-1)/3) Byzantine members. Compact proposals assume committee-wide
// data availability, so f+1 ingress receipts are insufficient: an adversary
// could leave too few honest holders to reconstruct a burst without making
// the leader a body server. A sender may compact an outbox item only after this
// many distinct validator consensus BLS keys report the same terminal result.
func txQUICReceiptQuorum(nodes int) int {
	if nodes <= 0 {
		return 0
	}
	faults := (nodes - 1) / 3
	return 2*faults + 1
}

func rotateTxQUICCommitteeTail(endpoints []string, cursor uint64) []string {
	rotated := append([]string(nil), endpoints...)
	if len(endpoints) <= 2 {
		return rotated
	}
	tailSize := len(endpoints) - 1
	start := int(cursor % uint64(tailSize))
	copy(rotated[1:], endpoints[1+start:])
	copy(rotated[1+tailSize-start:], endpoints[1:1+start])
	return rotated
}

// forwardFHSQuorumPayload gathers item-wise durable receipts from distinct
// committee consensus identities. It starts only a quorum-sized window and opens a
// replacement request when an endpoint fails or returns an unresolved item,
// avoiding unconditional whole-committee fanout.
func (q *TxQUICIngress) forwardFHSQuorumPayload(ctx context.Context, payload []byte) (int, error) {
	var persist func(common.Hash, txOutboxPlacementState, txQUICAck) error
	if q != nil && q.outbox != nil {
		persist = func(batchID common.Hash, state txOutboxPlacementState, aggregate txQUICAck) error {
			return q.outbox.promotePlacementSync(batchID, state, aggregate)
		}
	}
	return q.forwardFHSQuorumPayloadWithPersistence(ctx, payload, q.forwardPayloadReceiptContext, persist)
}

func (q *TxQUICIngress) forwardFHSQuorumPayloadWith(ctx context.Context, payload []byte, forward txQUICReceiptForwarder) (int, error) {
	return q.forwardFHSQuorumPayloadWithPersistence(ctx, payload, forward, nil)
}

func (q *TxQUICIngress) forwardFHSQuorumPayloadWithPersistence(ctx context.Context, payload []byte, forward txQUICReceiptForwarder, persist func(common.Hash, txOutboxPlacementState, txQUICAck) error) (int, error) {
	if q == nil {
		return 0, fmt.Errorf("nil txquic ingress")
	}
	if forward == nil {
		return 0, fmt.Errorf("nil txquic receipt forwarder")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && q.config.ForwardTimeout > 0 {
		var cancelDeadline context.CancelFunc
		ctx, cancelDeadline = context.WithTimeout(ctx, q.config.ForwardTimeout)
		defer cancelDeadline()
	}

	// Endpoint work follows the outbox attempt only until a durable quorum is
	// available. The placement bitmap is fsynced before any best-effort handoff;
	// after that point already-launched requests may finish in the fixed worker
	// pool while the durable outbox remains the restart-safe owner.
	placementParent := q.ctx
	if placementParent == nil {
		placementParent = context.Background()
	}
	placementCtx, cancelPlacement := context.WithCancel(placementParent)
	detachAttemptCancellation := txQUICPropagateAttemptCancellation(ctx, cancelPlacement)
	placementHandedOff := false
	defer func() {
		detachAttemptCancellation()
		if !placementHandedOff {
			cancelPlacement()
		}
	}()

	startRoute, routeErr := q.refreshFHSRouteCacheContext(ctx)
	if routeErr != nil {
		return 0, fmt.Errorf("canonical Fair HotStuff committee is unavailable: %w", routeErr)
	}
	if startRoute.CommitteeHash == (common.Hash{}) || len(startRoute.CommitteeEndpoints) == 0 ||
		len(startRoute.CommitteePublicKeys) != len(startRoute.CommitteeEndpoints) {
		return 0, fmt.Errorf("canonical Fair HotStuff committee snapshot is incomplete")
	}
	placement, err := newTxOutboxPlacementState(startRoute)
	if err != nil {
		return 0, err
	}
	placementIndex := make(map[string]int, len(placement.Endpoints))
	for index, endpoint := range placement.Endpoints {
		placementIndex[endpoint] = index
	}
	// Prefer the current leader for latency, then use each remaining canonical
	// committee endpoint exactly once. No static/genesis fallback participates
	// in the quorum denominator.
	endpoints := make([]string, 0, len(startRoute.CommitteeEndpoints))
	endpoints = append(endpoints, startRoute.Endpoint)
	for _, endpoint := range startRoute.CommitteeEndpoints {
		if !strings.EqualFold(endpoint, startRoute.Endpoint) {
			endpoints = append(endpoints, endpoint)
		}
	}
	if len(endpoints) != len(startRoute.CommitteeEndpoints) {
		return 0, fmt.Errorf("canonical Fair HotStuff committee endpoint set is inconsistent")
	}
	ensureCommitteeUnchanged := func() error {
		current, refreshErr := q.refreshFHSRouteCacheContext(ctx)
		if refreshErr != nil {
			return fmt.Errorf("revalidate Fair HotStuff committee: %w", refreshErr)
		}
		if current.KeyNumber != startRoute.KeyNumber || current.CommitteeHash != startRoute.CommitteeHash {
			return fmt.Errorf("Fair HotStuff committee changed while collecting receipts")
		}
		return nil
	}
	if len(endpoints) > 1 {
		// The current leader remains the latency-first endpoint. Rotate only
		// the non-leader tail so repeated bursts distribute fallback load
		// without delaying the leader behind an arbitrary committee member.
		cursor := atomic.AddUint64(&q.forwardCursor, 1) - 1
		endpoints = rotateTxQUICCommitteeTail(endpoints, cursor)
	}

	expectation, err := txQUICAckExpectationFromPayload(payload)
	if err != nil {
		return 0, err
	}
	if expectation.keyNumber != startRoute.KeyNumber || expectation.committeeHash != startRoute.CommitteeHash {
		return 0, fmt.Errorf("txquic packet does not target the current Fair HotStuff committee generation")
	}
	quorum := txQUICReceiptQuorum(len(endpoints))
	accumulator, err := newTxQUICReceiptAccumulator(expectation, quorum)
	if err != nil {
		return 0, err
	}
	results := make(chan txQUICForwardResult, len(endpoints))
	launched, inFlight := 0, 0
	defer func() {
		if placementHandedOff {
			return
		}
		cancelPlacement()
		for inFlight > 0 {
			<-results
			inFlight--
		}
	}()
	launch := func(endpoint string) {
		launched++
		inFlight++
		go func() {
			receipt, forwardErr := forward(placementCtx, endpoint, payload)
			results <- txQUICForwardResult{endpoint: endpoint, receipt: receipt, err: forwardErr}
		}()
	}
	initial := quorum
	if initial > len(endpoints) {
		initial = len(endpoints)
	}
	for launched < initial {
		launch(endpoints[launched])
	}
	hedgeTimer := time.NewTimer(time.Hour)
	if !hedgeTimer.Stop() {
		<-hedgeTimer.C
	}
	defer hedgeTimer.Stop()
	var hedgeC <-chan time.Time
	stopHedge := func() {
		if hedgeC == nil {
			return
		}
		if !hedgeTimer.Stop() {
			select {
			case <-hedgeTimer.C:
			default:
			}
		}
		hedgeC = nil
	}
	armHedge := func() {
		if hedgeC != nil || launched >= len(endpoints) || inFlight == 0 {
			return
		}
		hedgeTimer.Reset(q.config.ForwardHedgeDelay)
		hedgeC = hedgeTimer.C
	}
	armHedge()

	errs := make([]string, 0, len(endpoints))
	retryEndpoints := make([]string, 0, len(endpoints))
	distinctReceipts := 0
	for inFlight > 0 {
		select {
		case <-ctx.Done():
			ack, _ := accumulator.outcome()
			if distinctReceipts > 0 {
				if err := ensureCommitteeUnchanged(); err != nil {
					return distinctReceipts, err
				}
				return distinctReceipts, txQUICOutcomeError("Fair HotStuff receipt quorum", ack, expectation)
			}
			return 0, fmt.Errorf("txquic committee receipt collection stopped: %w", ctx.Err())
		case <-hedgeC:
			// Stagger exactly one spare at a time. If it also stalls, the timer
			// is re-armed; healthy all-success batches finish before this fires.
			hedgeC = nil
			if launched < len(endpoints) {
				launch(endpoints[launched])
			}
			armHedge()
		case response := <-results:
			stopHedge()
			inFlight--
			placed := false
			if response.receipt != nil {
				added, addErr := accumulator.add(response.receipt)
				if addErr != nil {
					errs = append(errs, fmt.Sprintf("%s: %v", response.endpoint, addErr))
				} else {
					placed = txQUICReceiptPlacementComplete(response.receipt)
					if added {
						distinctReceipts++
					}
				}
			}
			if !placed {
				retryEndpoints = append(retryEndpoints, response.endpoint)
			} else if index, exists := placementIndex[canonicalTxQUICEndpoint(response.endpoint)]; exists {
				txQUICBitmapSet(placement.CompletedBitmap, index)
			}
			if response.err != nil && response.receipt == nil {
				errs = append(errs, fmt.Sprintf("%s: %v", response.endpoint, response.err))
			}
			ack, complete := accumulator.outcome()
			if complete {
				if err := ensureCommitteeUnchanged(); err != nil {
					return distinctReceipts, err
				}
				if persist != nil && !placement.complete() {
					if err := persist(expectation.batchID, placement, ack); err != nil {
						return distinctReceipts, fmt.Errorf("persist TxQUIC committee tail placement: %w", err)
					}
				}
				remaining := append([]string(nil), retryEndpoints...)
				remaining = append(remaining, endpoints[launched:]...)
				if inFlight > 0 || len(remaining) > 0 {
					// Detach the already-durable committee placement from the outbox
					// attempt before it returns and cancels its deadline context.
					detachAttemptCancellation()
					job := txQUICBackgroundForward{
						payload: payload, endpoints: remaining, results: results,
						pending: inFlight, cancel: cancelPlacement,
					}
					if q.enqueueBackgroundForward(job) {
						placementHandedOff = true
					} else {
						cancelPlacement()
					}
				}
				if persist != nil && !placement.complete() {
					return distinctReceipts, &txOutboxPlacementPendingError{}
				}
				return distinctReceipts, txQUICOutcomeError("Fair HotStuff receipt quorum", ack, expectation)
			}
			// Keep only the number of requests that can still be required for
			// terminal quorum. Launching one replacement after every successful
			// partial response turns q initial requests into as many as 2q-1 even
			// when all validators accept the whole batch.
			needed := accumulator.receiptsNeeded()
			for launched < len(endpoints) && inFlight < needed {
				launch(endpoints[launched])
			}
			armHedge()
		}
	}
	ack, _ := accumulator.outcome()
	if distinctReceipts > 0 {
		if err := ensureCommitteeUnchanged(); err != nil {
			return distinctReceipts, err
		}
		return distinctReceipts, txQUICOutcomeError("Fair HotStuff receipt quorum", ack, expectation)
	}
	if len(errs) == 0 {
		return 0, fmt.Errorf("no distinct Fair HotStuff committee receipt was returned")
	}
	return 0, fmt.Errorf("all txquic committee receipt requests failed: %s", strings.Join(errs, "; "))
}

func (q *TxQUICIngress) startBridgeWorkers() {
	for i := 0; i < q.config.BridgeWorkers; i++ {
		q.wg.Add(1)
		go q.durableBridgeWorker(i)
	}
}

func (q *TxQUICIngress) startBackgroundForwardWorkers() {
	if q == nil || q.backgroundForwards == nil {
		return
	}
	q.backgroundForwardMu.Lock()
	if q.ctx == nil || q.ctx.Err() != nil {
		q.backgroundForwardMu.Unlock()
		return
	}
	q.backgroundForwardAccepting = true
	workers := minPositiveInt(q.config.BridgeWorkers, 4)
	for worker := 0; worker < workers; worker++ {
		q.wg.Add(1)
		go q.backgroundForwardWorker()
	}
	// Stop takes the same lock before canceling q.ctx and waiting on q.wg.
	// Keep worker registration inside the critical section so Add can never
	// race a zero-counter Wait during a concurrent lifecycle shutdown.
	q.backgroundForwardMu.Unlock()
}

// enqueueBackgroundForward transfers ownership of job.cancel on success. A
// false result leaves cancellation with the caller, keeping overload bounded.
func (q *TxQUICIngress) enqueueBackgroundForward(job txQUICBackgroundForward) bool {
	if q == nil || q.backgroundForwards == nil || len(job.payload) == 0 || job.pending < 0 ||
		(job.pending == 0 && len(job.endpoints) == 0) || (job.pending > 0 && job.results == nil) {
		return false
	}
	job.payload = append([]byte(nil), job.payload...)
	job.endpoints = append([]string(nil), job.endpoints...)
	q.backgroundForwardMu.RLock()
	defer q.backgroundForwardMu.RUnlock()
	if !q.backgroundForwardAccepting || q.ctx == nil || q.ctx.Err() != nil {
		return false
	}
	select {
	case q.backgroundForwards <- job:
		return true
	case <-q.ctx.Done():
		return false
	default:
		log.Debug("TxQUIC background committee placement accelerator is full; durable outbox retains tail", "endpoints", len(job.endpoints), "pending", job.pending, "bytes", len(job.payload))
		return false
	}
}

func (q *TxQUICIngress) backgroundForwardWorker() {
	defer q.wg.Done()
	for {
		select {
		case <-q.ctx.Done():
			q.drainBackgroundForwardQueue()
			return
		case job := <-q.backgroundForwards:
			if !q.completeBackgroundForward(job, q.forwardPayloadReceiptContext) {
				q.drainBackgroundForwardQueue()
				return
			}
		}
	}
}

func (q *TxQUICIngress) drainBackgroundForwardQueue() {
	for {
		select {
		case job := <-q.backgroundForwards:
			q.completeBackgroundForward(job, q.forwardPayloadReceiptContext)
		default:
			return
		}
	}
}

func (q *TxQUICIngress) completeBackgroundForward(job txQUICBackgroundForward, forward txQUICReceiptForwarder) bool {
	cancel := job.cancel
	cancelPlacement := func() {
		if cancel != nil {
			cancel()
			cancel = nil
		}
	}
	defer cancelPlacement()
	if q == nil || q.ctx == nil || forward == nil || job.pending < 0 || (job.pending > 0 && job.results == nil) {
		return false
	}
	retryEndpoints := append([]string(nil), job.endpoints...)
	pending := job.pending
	for pending > 0 {
		select {
		case response := <-job.results:
			pending--
			// forwardPayloadReceiptContext returns a non-nil receipt only after
			// TLS, committee identity, ACK structure, and BLS verification. An
			// authenticated terminal reject is therefore also a completed
			// placement, but any retryable item requires another endpoint attempt.
			if !txQUICReceiptPlacementComplete(response.receipt) {
				retryEndpoints = append(retryEndpoints, response.endpoint)
			}
		case <-q.ctx.Done():
			cancelPlacement()
			for pending > 0 {
				<-job.results
				pending--
			}
			return false
		}
	}
	cancelPlacement()
	for _, endpoint := range retryEndpoints {
		if q.ctx.Err() != nil {
			return false
		}
		if _, err := forward(q.ctx, endpoint, job.payload); err != nil {
			log.Debug("TxQUIC background committee placement failed", "endpoint", endpoint, "err", err)
		}
	}
	return true
}

func (q *TxQUICIngress) durableBridgeWorker(id int) {
	defer q.wg.Done()
	for {
		select {
		case <-q.ctx.Done():
			q.failQueuedDurableRequests(errors.New("txquic bridge stopped before durable persistence"))
			return

		case request := <-q.durableQueue:
			if request == nil || len(request.items) == 0 {
				continue
			}
			q.persistDurableBridgeItems(request.certificate, request.items, request.am, request.walOwned)
		}
	}
}

func (q *TxQUICIngress) persistDurableBridgeItems(certificate *types.CommonTxAdmissionBatch, items []txQUICBridgeItem, am *accounts.Manager, walOwned bool) {
	if len(items) == 0 {
		return
	}
	payload, err := q.encodeVerifiedTxBatch(certificate, items)
	if err != nil {
		q.finishDurableBridgeItems(items, err)
		return
	}
	if int64(len(payload)) > q.durableBatchByteLimit() {
		if len(items) == 1 {
			q.finishDurableBridgeItems(items, fmt.Errorf("txquic durable transaction exceeds payload limit: size=%d limit=%d", len(payload), q.durableBatchByteLimit()))
			return
		}
		middle := len(items) / 2
		q.persistDurableBridgeItems(certificate, items[:middle], am, walOwned)
		q.persistDurableBridgeItems(certificate, items[middle:], am, walOwned)
		return
	}
	storeCtx := q.ctx
	cancel := func() {}
	if q.config.ForwardTimeout > 0 {
		storeCtx, cancel = context.WithTimeout(q.ctx, q.config.ForwardTimeout)
	}
	if walOwned {
		_, err = q.outbox.storeWALOwnedVerifiedSync(storeCtx, payload)
	} else {
		_, err = q.outbox.storeVerifiedSync(storeCtx, payload)
	}
	cancel()
	q.finishDurableBridgeItems(items, err)
}

func (q *TxQUICIngress) finishDurableBridgeItems(items []txQUICBridgeItem, err error) {
	requests := make(map[*txQUICBridgeRequest]int)
	completedItems := 0
	var completedBytes int64
	for _, item := range items {
		if item.request == nil {
			continue
		}
		requests[item.request]++
		completedItems++
		completedBytes += item.rawBytes
	}
	q.releaseDurableBridgeCapacity(completedItems, completedBytes)
	for request, count := range requests {
		request.complete(count, err)
	}
}

func (q *TxQUICIngress) failQueuedDurableRequests(err error) {
	if q == nil || q.durableQueue == nil {
		return
	}
	for {
		select {
		case request := <-q.durableQueue:
			if request != nil {
				q.finishDurableBridgeItems(request.items, err)
			}
		default:
			return
		}
	}
}

func (q *TxQUICIngress) encodeVerifiedTxBatch(certificate *types.CommonTxAdmissionBatch, bridgeItems []txQUICBridgeItem) ([]byte, error) {
	batch, err := q.buildTxBatch(certificate, bridgeItems)
	if err != nil {
		return nil, err
	}
	return rlp.EncodeToBytes(batch)
}

func (q *TxQUICIngress) buildTxBatch(certificate *types.CommonTxAdmissionBatch, bridgeItems []txQUICBridgeItem) (*txQUICBatch, error) {
	if len(bridgeItems) == 0 {
		return nil, fmt.Errorf("no txs to encode")
	}
	if q == nil || q.config.ChainID == 0 || q.config.GenesisHash == (common.Hash{}) {
		return nil, fmt.Errorf("txquic chain identity is unavailable")
	}

	if err := validateTxQUICCertificateStructure(certificate, q.config.ChainID, q.config.GenesisHash); err != nil {
		return nil, err
	}
	items := make([]*txQUICItem, len(bridgeItems))
	for index, item := range bridgeItems {
		if item.tx == nil {
			return nil, fmt.Errorf("nil TxQUIC transaction at %d", index)
		}
		owned, err := newTxQUICItemWithSidecar(item.admissionIndex, item.tx, item.blobSidecar)
		if err != nil {
			return nil, fmt.Errorf("invalid TxQUIC transaction at %d: %w", index, err)
		}
		items[index] = owned
	}
	batch, _, err := newTxQUICBatch(q.config.ChainID, q.config.GenesisHash, certificate, items)
	if err != nil {
		return nil, err
	}
	return batch, nil
}

func (q *TxQUICIngress) encodeSignedTxQUICPacket(batch *txQUICBatch, am *accounts.Manager) ([]byte, error) {
	if _, err := validateTxQUICBatch(batch); err != nil {
		return nil, err
	}
	route, err := q.refreshFHSRouteCache()
	if err != nil {
		return nil, fmt.Errorf("resolve txquic committee generation: %w", err)
	}
	if route.CommitteeHash == (common.Hash{}) || len(route.CommitteeEndpoints) == 0 || len(route.CommitteeEndpoints) != len(route.CommitteePublicKeys) {
		return nil, fmt.Errorf("canonical Fair HotStuff committee generation is incomplete")
	}
	sender := bftview.GetServerCoinBase()
	if sender == (common.Address{}) {
		return nil, fmt.Errorf("txquic bridge signer coinbase is empty")
	}
	if _, allowed := q.signers[sender]; !allowed {
		return nil, fmt.Errorf("txquic bridge signer %s is not genesis-authorized", sender)
	}
	if am == nil {
		am = q.am
	}
	if am == nil {
		return nil, fmt.Errorf("txquic bridge account manager is nil")
	}
	epoch := txQUICSenderEpoch(batch.ChainID, batch.GenesisHash, sender)
	if q.outbox == nil {
		return nil, fmt.Errorf("txquic durable outbox is unavailable for nonce allocation")
	}
	nonce, err := q.outbox.NextNonce(sender, epoch)
	if err != nil {
		return nil, err
	}
	pkt := &txQUICPacket{
		ChainID: batch.ChainID, GenesisHash: batch.GenesisHash,
		KeyNumber: route.KeyNumber, CommitteeHash: route.CommitteeHash, BatchID: batch.BatchID,
		Sender: sender, SenderEpoch: epoch, Nonce: nonce, Timestamp: uint64(time.Now().Unix()),
		TxRoot: batch.TxRoot, Certificate: copyCommonTxAdmissionBatchForQUIC(batch.Certificate), Items: batch.Items,
	}
	payload, err := pkt.signingPayload()
	if err != nil {
		return nil, err
	}
	account := accounts.Account{Address: sender}
	wallet, err := am.Find(account)
	if err != nil {
		return nil, err
	}
	sig, err := wallet.SignData(account, accounts.MimetypeDataWithValidator, payload)
	if err != nil {
		return nil, err
	}
	pkt.Signature = sig
	wire, err := rlp.EncodeToBytes(pkt)
	if err != nil {
		return nil, err
	}
	if int64(len(wire)) > txQUICMicroBatchMaxWireBytes {
		return nil, fmt.Errorf("txquic wire packet exceeds micro-batch limit: size=%d limit=%d", len(wire), txQUICMicroBatchMaxWireBytes)
	}
	return wire, nil
}

func (q *TxQUICIngress) startHTTP3RPC() error {
	if !q.config.HTTP3Enabled || q.http3Handler == nil {
		return nil
	}
	cert, err := q.http3Certificate()
	if err != nil {
		return err
	}
	addr := txQUICJoinHostPort(q.config.HTTP3Addr, q.config.HTTP3Port)
	q.http3Server = &http3.Server{Addr: addr, Handler: q.http3Handler, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}}
	q.wg.Add(1)
	go func() {
		defer q.wg.Done()
		log.Info("Started HTTP/3 JSON-RPC", "addr", addr)
		if err := q.http3Server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case <-q.ctx.Done():
			default:
				log.Error("HTTP/3 JSON-RPC stopped with error", "err", err)
			}
		}
	}()
	return nil
}

func (q *TxQUICIngress) acceptLoop() {
	defer q.wg.Done()
	for {
		conn, err := q.listener.Accept(q.ctx)
		if err != nil {
			select {
			case <-q.ctx.Done():
				return
			default:
				log.Debug("QUIC tx ingress accept failed", "err", err)
				continue
			}
		}
		txQUICIngressConnMeter.Mark(1)
		q.wg.Add(1)
		go q.handleConn(conn)
	}
}

// handshakeContext applies the IP allowlist and the global connection bound
// before TLS certificate generation or BLS verification. Start configures QUIC
// Retry for every unvalidated address, so only a return-routable source may
// consume one of these slots. The QUIC-owned context is cancelled on handshake
// failure and remains live until an accepted connection closes.
func (q *TxQUICIngress) handshakeContext(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
	if q == nil || ctx == nil || info == nil || info.RemoteAddr == nil {
		return nil, fmt.Errorf("invalid txquic handshake context")
	}
	if !info.AddrVerified {
		return nil, fmt.Errorf("txquic source address was not verified")
	}
	if !q.allowed(info.RemoteAddr) {
		return nil, fmt.Errorf("txquic source address is not allowed")
	}
	if q.ctx != nil {
		select {
		case <-q.ctx.Done():
			return nil, fmt.Errorf("txquic ingress is stopping")
		default:
		}
	}
	if q.connSem == nil {
		return nil, fmt.Errorf("txquic connection admission is unavailable")
	}
	select {
	case q.connSem <- struct{}{}:
		context.AfterFunc(ctx, func() { <-q.connSem })
		return ctx, nil
	default:
		return nil, fmt.Errorf("too many txquic connections")
	}
}

func (q *TxQUICIngress) handleConn(conn *quic.Conn) {
	defer q.wg.Done()
	defer func() { _ = conn.CloseWithError(0, "closed") }()
	remote := conn.RemoteAddr()
	for {
		stream, err := conn.AcceptStream(q.ctx)
		if err != nil {
			select {
			case <-q.ctx.Done():
				return
			default:
				log.Debug("QUIC tx ingress stream accept failed", "remote", remote, "err", err)
				return
			}
		}
		if q.tryAcquireIngressWorker() {
			txQUICIngressStreamMeter.Mark(1)
			q.wg.Add(1)
			go q.handleStream(remote, stream)
			continue
		}
		select {
		case <-q.ctx.Done():
			stream.CancelRead(0)
			stream.CancelWrite(0)
			return
		default:
			// Never let an accepted stream wait while holding QUIC receive state.
			// The sender retains its durable outbox record and retries later.
			stream.CancelRead(1)
			stream.CancelWrite(1)
		}
	}
}

func (q *TxQUICIngress) handleStream(remote net.Addr, stream *quic.Stream) {
	defer q.wg.Done()
	defer q.releaseIngressWorker()
	defer stream.Close()
	_ = stream.SetReadDeadline(time.Now().Add(q.config.ReadTimeout))
	maxPayload := txQUICMicroBatchMaxWireBytes
	payloadBytes, err := readTxQUICPayloadSize(stream, maxPayload)
	if err != nil {
		log.Warn("TxQUIC payload header read failed", "remote", remote, "err", err)
		return
	}
	if !q.tryAcquireInflightPayload(payloadBytes) {
		log.Warn("TxQUIC in-flight payload byte limit reached", "remote", remote, "payload", payloadBytes, "limit", q.inflightPayloadLimit)
		stream.CancelRead(1)
		stream.CancelWrite(1)
		return
	}
	defer q.releaseInflightPayload(payloadBytes)
	payload := make([]byte, int(payloadBytes))
	if _, err := io.ReadFull(stream, payload); err != nil {
		log.Warn("TxQUIC stream payload read failed", "remote", remote, "payload", payloadBytes, "err", err)
		return
	}
	var trailing [1]byte
	if n, err := stream.Read(trailing[:]); n != 0 || !errors.Is(err, io.EOF) {
		log.Warn("TxQUIC framed payload has trailing bytes", "remote", remote, "payload", payloadBytes, "trailing", n, "err", err)
		return
	}
	packet, signer, err := q.decodeAndAuthenticateEnvelope(payload)
	if err != nil {
		txQUICIngressAuthFailMeter.Mark(1)
		log.Warn("TxQUIC decode/auth failed", "remote", remote, "payload", len(payload), "err", err)
		return
	}
	maxBatchItems := txQUICMicroBatchMaxTxs
	if len(packet.Items) > maxBatchItems {
		log.Warn("TxQUIC batch too large", "remote", remote, "items", len(packet.Items), "limit", maxBatchItems)
		return
	}
	// Charge authenticated senders before committee resolution, commitment
	// hashing, admission signature checks, or database access. Internet clients
	// without an allowed packet key cannot consume those expensive paths.
	if !q.takeTokens(remote, len(packet.Items)) {
		log.Warn("TxQUIC rate limited", "remote", remote, "batch", packet.BatchID, "items", len(packet.Items))
		return
	}
	// Authenticated live RPC and QUIC work shares one fair weighted gate before
	// committee resolution, admission verification, WAL fsync, projection,
	// TxPool publication, and ACK persistence. Startup replay never enters this
	// path and therefore cannot deadlock behind live pressure.
	if q.liveIngress == nil {
		log.Error("Node-global live transaction ingress scheduler is unavailable", "remote", remote, "batch", packet.BatchID)
		return
	}
	liveTimeout := q.config.ForwardTimeout
	if liveTimeout <= 0 {
		liveTimeout = 15 * time.Second
	}
	liveCtx, cancelLive := context.WithTimeout(q.ctx, liveTimeout)
	releaseLive, err := q.liveIngress.Acquire(liveCtx, txPoolIngressQUIC, len(packet.Items), payloadBytes)
	cancelLive()
	if err != nil {
		log.Warn("TxQUIC live ingress scheduler rejected packet", "remote", remote, "batch", packet.BatchID, "items", len(packet.Items), "err", err)
		return
	}
	defer releaseLive()
	if err := q.validateAuthenticatedPacket(packet); err != nil {
		txQUICIngressAuthFailMeter.Mark(1)
		log.Warn("TxQUIC authenticated packet validation failed", "remote", remote, "batch", packet.BatchID, "err", err)
		return
	}
	if q.ingress == nil {
		log.Error("TxQUIC durable ingress store is unavailable")
		return
	}
	unlockIngress := q.ingress.LockPacket(packet)
	defer unlockIngress()
	cached, complete, err := q.ingress.LookupPacket(packet, time.Now())
	if err != nil {
		log.Warn("TxQUIC replay or durable lookup rejected packet", "remote", remote, "batch", packet.BatchID, "err", err)
		return
	}
	if complete {
		log.Debug("TxQUIC durable ingress duplicate acknowledged", "remote", remote, "signer", signer, "batch", packet.BatchID, "items", len(packet.Items))
		q.writeAck(stream, cached)
		return
	}
	durableCertificate := cached.ItemCount == uint32(len(packet.Items))
	if !durableCertificate {
		if err := types.VerifyCommonTxAdmissionSignature(packet.Certificate); err != nil {
			log.Warn("TxQUIC admission signature verification failed; withholding WAL ownership and ACK", "remote", remote, "batch", packet.BatchID, "err", err)
			return
		}
	}
	// This is the ownership handoff. A crash after this fsync is resumed from
	// the WAL; only after it succeeds may admission indexes or the txpool become
	// visible to the rest of the node. The combined helper makes real KZG a
	// non-bypassable precondition of that first durable write.
	if err := q.appendKZGVerifiedInboundReceived(q.ctx, packet); err != nil {
		log.Error("TxQUIC blob verification or received-record WAL persistence failed; withholding ACK", "remote", remote, "batch", packet.BatchID, "err", err)
		return
	}
	if err := q.verifyAndStoreAdmissionCertificate(packet.Certificate, packet.Items, durableCertificate); err != nil {
		log.Warn("TxQUIC admission certificate verification or storage failed; withholding ACK", "remote", remote, "batch", packet.BatchID, "err", err)
		return
	}
	ack := q.processTxQUICIngressPacketVerifiedScheduled(packet, nil)
	if err := q.wal.appendInboundOutcome(q.ctx, packet, ack); err != nil {
		log.Error("TxQUIC outcome WAL persistence failed; withholding ACK", "remote", remote, "batch", packet.BatchID, "items", len(packet.Items), "err", err)
		return
	}
	ack, err = q.ingress.StoreSyncLocked(q.ctx, packet, ack)
	if err != nil {
		log.Error("TxQUIC durable ingress persistence failed; withholding ACK", "remote", remote, "batch", packet.BatchID, "items", len(packet.Items), "err", err)
		return
	}
	if err := q.wal.appendInboundApplied(q.ctx, packet); err != nil {
		log.Error("TxQUIC applied-record WAL persistence failed; withholding ACK", "remote", remote, "batch", packet.BatchID, "items", len(packet.Items), "err", err)
		return
	}
	markTxQUICAckMetrics(ack)
	log.Debug("QUIC ingress processed", "remote", remote, "signer", signer, "batch", packet.BatchID, "items", len(packet.Items))
	q.writeAck(stream, ack)
}

// verifyAndStoreAdmissionCertificate reuses verification only after LookupPacket
// proved that the exact certificate is already in the synchronous ingress WAL.
// A missing process-local index forces the full core trust-boundary path again.
// Startup restore always calls this with durableVerified=false before accepting
// network traffic, so disk state is never promoted without ECDSA recovery.
func (q *TxQUICIngress) verifyAndStoreAdmissionCertificate(certificate *types.CommonTxAdmissionBatch, items []*txQUICItem, durableVerified bool) error {
	if q == nil || certificate == nil {
		return fmt.Errorf("missing txquic admission certificate")
	}
	if durableVerified {
		allPresent := true
		for _, item := range items {
			if item == nil || item.Tx == nil {
				allPresent = false
				break
			}
			hash := item.Tx.Hash()
			hasAdmission := core.HasCommonRPCAdmission
			if q.hasAdmission != nil {
				hasAdmission = q.hasAdmission
			}
			if hasAdmission(hash) {
				continue
			}
			if q.finalizedTx != nil && q.finalizedTx(hash) {
				continue
			}
			allPresent = false
			break
		}
		if allPresent {
			return nil
		}
	}
	verify := core.VerifyAndStoreCommonRPCAdmissionBatch
	if q.verifyAdmission != nil {
		verify = q.verifyAdmission
	}
	_, err := verify(certificate, new(mathbig.Int).SetUint64(q.config.ChainID), q.config.GenesisHash)
	return err
}

func (q *TxQUICIngress) processTxQUICIngressPacket(packet *txQUICPacket) txQUICAck {
	admissionErr := q.verifyAndStoreAdmissionCertificate(packet.Certificate, packet.Items, false)
	return q.processTxQUICIngressPacketVerified(packet, admissionErr)
}

func (q *TxQUICIngress) processTxQUICIngressPacketVerified(packet *txQUICPacket, admissionErr error) txQUICAck {
	return q.processTxQUICIngressPacketVerifiedWithScheduler(packet, admissionErr, false)
}

// processTxQUICIngressPacketVerifiedScheduled is the live network path. Its
// caller has already fsynced InboundReceived, so the bounded node-global
// scheduler may now publish to TxPool. Startup recovery uses the direct helper
// above and cannot be delayed by live RPC/QUIC queue pressure.
func (q *TxQUICIngress) processTxQUICIngressPacketVerifiedScheduled(packet *txQUICPacket, admissionErr error) txQUICAck {
	return q.processTxQUICIngressPacketVerifiedWithScheduler(packet, admissionErr, true)
}

func (q *TxQUICIngress) processTxQUICIngressPacketVerifiedWithScheduler(packet *txQUICPacket, admissionErr error, scheduled bool) txQUICAck {
	itemCount := len(packet.Items)
	ack := txQUICAck{
		ChainID: packet.ChainID, GenesisHash: packet.GenesisHash,
		KeyNumber: packet.KeyNumber, CommitteeHash: packet.CommitteeHash, BatchID: packet.BatchID,
		Sender: packet.Sender, SenderEpoch: packet.SenderEpoch, Nonce: packet.Nonce,
		ItemCount: uint32(itemCount), DurableBitmap: make([]byte, txQUICBitmapBytes(itemCount)),
		RetryableBitmap: make([]byte, txQUICBitmapBytes(itemCount)),
	}
	txs, itemErr := packetItemsToTxs(packet)
	if itemErr != nil {
		if admissionErr == nil {
			admissionErr = itemErr
		}
		txs = make(types.Transactions, itemCount)
	}
	// TxQUIC already delivers each transaction and admission to a 2f+1
	// committee quorum and persists the outcome before ACK. Re-broadcasting the
	// same admission from every receiver creates quadratic committee traffic
	// during bursts and adds no availability. Admission-only eth/p2p ingress is
	// removed, so this authenticated packet is the sole network trust boundary.
	// Do not publish a transaction before its mandatory admission sidecar has
	// passed verification and durable storage. Otherwise a malformed or
	// ambiguously persisted sidecar can leak the transaction into the pool even
	// though this packet item is rejected.
	insertTxs := make([]*types.Transaction, 0, itemCount)
	insertIndexes := make([]int, 0, itemCount)
	if admissionErr == nil {
		for index, tx := range txs {
			insertTxs = append(insertTxs, tx)
			insertIndexes = append(insertIndexes, index)
		}
	}
	var insertErrors []error
	if len(insertTxs) > 0 {
		if scheduled {
			var scheduleErr error
			if q.poolIngress == nil {
				scheduleErr = errors.New("node-global transaction ingress scheduler is unavailable")
			} else {
				insertErrors, scheduleErr = q.poolIngress.Submit(q.ctx, txPoolIngressQUIC, insertTxs)
			}
			if scheduleErr != nil {
				insertErrors = make([]error, len(insertTxs))
				for index := range insertErrors {
					insertErrors[index] = fmt.Errorf("%w: schedule durable TxQUIC pool publication: %v", core.ErrTxPoolOverflow, scheduleErr)
				}
			}
		} else if q.txpool == nil {
			insertErrors = make([]error, len(insertTxs))
			for index := range insertErrors {
				insertErrors[index] = errors.New("transaction pool is unavailable")
			}
		} else {
			insertErrors = q.txpool.AddRemotes(insertTxs)
		}
	}
	insertErrorsByItem := make([]error, itemCount)
	for resultIndex, itemIndex := range insertIndexes {
		if resultIndex < len(insertErrors) {
			insertErrorsByItem[itemIndex] = insertErrors[resultIndex]
		} else {
			insertErrorsByItem[itemIndex] = fmt.Errorf("transaction pool returned no result")
		}
	}
	exactCanonical := make([]bool, itemCount)
	obsolete := make([]bool, itemCount)
	obsoleteIndexes := make([]int, 0)
	obsoleteCandidates := make(types.Transactions, 0)
	for index, insertErr := range insertErrorsByItem {
		if !errors.Is(insertErr, core.ErrNonceTooLow) {
			continue
		}
		tx := packet.Items[index].Tx
		if q.canonicalTx != nil && q.canonicalTx(tx.Hash()) {
			exactCanonical[index] = true
			continue
		}
		obsoleteIndexes = append(obsoleteIndexes, index)
		obsoleteCandidates = append(obsoleteCandidates, tx)
	}
	for resultIndex, isObsolete := range q.obsoleteTransactions(obsoleteCandidates) {
		if resultIndex < len(obsoleteIndexes) {
			obsolete[obsoleteIndexes[resultIndex]] = isObsolete
		}
	}
	itemIDs, _, _ := txQUICItemCommitments(packet.Certificate, packet.Items)
	for index := range packet.Items {
		if admissionErr != nil {
			if errors.Is(admissionErr, core.ErrInvalidCommonRPCAdmission) {
				reason := admissionErr.Error()
				if len(reason) > txQUICMaxPermanentReasonBytes {
					reason = reason[:txQUICMaxPermanentReasonBytes]
				}
				ack.PermanentErrors = append(ack.PermanentErrors, txQUICPermanentError{
					Index: uint32(index), ItemID: itemIDs[index], Code: txQUICPermanentInvalidAdmission, Reason: reason,
				})
			} else {
				txQUICBitmapSet(ack.RetryableBitmap, index)
			}
			continue
		}
		insertErr := insertErrorsByItem[index]
		if insertErr == nil || errors.Is(insertErr, core.ErrAlreadyKnown) {
			txQUICBitmapSet(ack.DurableBitmap, index)
			continue
		}
		if errors.Is(insertErr, core.ErrNonceTooLow) {
			if exactCanonical[index] {
				txQUICBitmapSet(ack.DurableBitmap, index)
				continue
			}
			if obsolete[index] {
				ack.PermanentErrors = append(ack.PermanentErrors, txQUICPermanentError{
					Index: uint32(index), ItemID: itemIDs[index], Code: txQUICPermanentObsoleteTransaction,
					Reason: "finalized sender nonce exceeds transaction nonce",
				})
				continue
			}
		}
		if classifyTxQUICInsertError(insertErr) == txQUICRejectRetryable {
			txQUICBitmapSet(ack.RetryableBitmap, index)
			continue
		}
		reason := insertErr.Error()
		if len(reason) > txQUICMaxPermanentReasonBytes {
			reason = reason[:txQUICMaxPermanentReasonBytes]
		}
		ack.PermanentErrors = append(ack.PermanentErrors, txQUICPermanentError{
			Index: uint32(index), ItemID: itemIDs[index], Code: txQUICPermanentInvalidTransaction, Reason: reason,
		})
	}
	return ack
}

func markTxQUICAckMetrics(ack txQUICAck) {
	accepted, rejected := int64(0), int64(len(ack.PermanentErrors))
	for index := 0; index < int(ack.ItemCount); index++ {
		if txQUICBitmapHas(ack.DurableBitmap, index) {
			accepted++
		}
		if txQUICBitmapHas(ack.RetryableBitmap, index) {
			rejected++
		}
	}
	if accepted > 0 {
		txQUICIngressAcceptedMeter.Mark(accepted)
	}
	if rejected > 0 {
		txQUICIngressRejectedMeter.Mark(rejected)
	}
}

func classifyTxQUICInsertError(err error) uint {
	if err == nil || errors.Is(err, core.ErrAlreadyKnown) {
		return 0
	}
	// These depend on pool capacity, local pricing, account state, or the
	// current block and may succeed at another committee node or after retry.
	for _, retryable := range []error{
		core.ErrNonceTooLow,
		core.ErrTxPoolOverflow,
		core.ErrUnderpriced,
		core.ErrReplaceUnderpriced,
		core.ErrNonceTooFarInFuture,
		core.ErrNonceTooHigh,
		core.ErrInsufficientFunds,
		core.ErrInsufficientFundsForTransfer,
		core.ErrGasFeeCapTooLow,
		core.ErrBlobFeeCapTooLow,
		core.ErrGasLimitReached,
		core.ErrGasLimit,
		core.ErrOversizedData,
		core.ErrNativeReplaySequenceReserved,
	} {
		if errors.Is(err, retryable) {
			return txQUICRejectRetryable
		}
	}
	// Only invariants that cannot become valid under another pool policy, state,
	// block limit, or future fork rule are terminal. Durable manifests are reused
	// across committee generations, so policy- or fork-dependent errors must
	// remain retryable even when every current validator reports them.
	for _, permanent := range []error{
		core.ErrInvalidSender,
		core.ErrNegativeValue,
		core.ErrGasTipAboveFeeCap,
		core.ErrGasUintOverflow,
	} {
		if errors.Is(err, permanent) {
			return txQUICRejectPermanent
		}
	}
	// Unknown/internal pool failures are safer to retry than to discard.
	return txQUICRejectRetryable
}

func (q *TxQUICIngress) routeBridgePayloadContext(ctx context.Context, payload []byte) (forwarded int, requiredDelivered bool, rejectErr error) {
	if !q.config.FairHotstuff {
		return 0, false, nil
	}
	forwarded, err := q.forwardFHSQuorumPayload(ctx, payload)
	if err == nil {
		log.Debug("TxQUIC FHS bridge reached durable receipt quorum", "receipts", forwarded)
		return forwarded, true, nil
	}
	var placementPending *txOutboxPlacementPendingError
	if errors.As(err, &placementPending) && placementPending != nil {
		log.Debug("TxQUIC FHS bridge reached durable receipt quorum; tail placement persisted", "receipts", forwarded)
		return forwarded, true, placementPending
	}
	var rejected *txQUICRemoteRejectError
	if errors.As(err, &rejected) {
		return forwarded, false, rejected
	}
	log.Debug("TxQUIC FHS committee receipt quorum failed", "receipts", forwarded, "err", err)
	return forwarded, false, nil
}

func (q *TxQUICIngress) forwardPayloadReceiptContext(ctx context.Context, endpoint string, payload []byte) (*txQUICAckReceipt, error) {
	if q == nil {
		return nil, fmt.Errorf("nil txquic ingress")
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("empty txquic endpoint")
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty txquic payload")
	}
	expectation, err := txQUICAckExpectationFromPayload(payload)
	if err != nil {
		return nil, err
	}
	// Serialize route validation and client registration with route publication
	// and cleanup. The network request itself runs without this lock.
	q.routeRefreshMu.Lock()
	expectedPublicKey, err := q.fhsExpectedReceiptKey(endpoint, expectation.keyNumber, expectation.committeeHash)
	if err != nil {
		q.routeRefreshMu.Unlock()
		return nil, err
	}
	clientKey := canonicalTxQUICEndpoint(endpoint)
	expectedIdentity := txQUICReceiptIdentity(expectedPublicKey)
	_, tlsGeneration, err := txQUICTLSIdentityPayload(q.config, expectation.keyNumber, expectation.committeeHash, endpoint)
	if err != nil {
		q.routeRefreshMu.Unlock()
		return nil, err
	}
	if clientKey == "" || expectedIdentity == (common.Hash{}) || tlsGeneration == (common.Hash{}) {
		q.routeRefreshMu.Unlock()
		return nil, fmt.Errorf("invalid canonical txquic endpoint identity")
	}
	var client *txQUICForwardClient
	connections := make([]*quic.Conn, 0, 1)
	for {
		value, _ := q.forwardClients.LoadOrStore(clientKey, &txQUICForwardClient{endpoint: endpoint, receiptIdentity: expectedIdentity, tlsGeneration: tlsGeneration})
		var ok bool
		client, ok = value.(*txQUICForwardClient)
		if !ok || client == nil {
			q.forwardClients.CompareAndDelete(clientKey, value)
			continue
		}
		if !client.closed.Load() && client.receiptIdentity == expectedIdentity && client.tlsGeneration == tlsGeneration {
			break
		}
		if q.forwardClients.CompareAndDelete(clientKey, value) {
			if conn := client.retire(); conn != nil {
				connections = append(connections, conn)
			}
		}
	}
	q.routeRefreshMu.Unlock()
	closeTxQUICConnections(connections)
	return client.sendReceipt(ctx, q, payload, expectation, expectedPublicKey)
}

func (c *txQUICForwardClient) getConn(q *TxQUICIngress, ctx context.Context, keyNumber uint64, committeeHash common.Hash, expectedPublicKey []byte) (*quic.Conn, error) {
	if c.closed.Load() {
		return nil, fmt.Errorf("txquic forward client for %s is closed", c.endpoint)
	}
	tlsIdentity, generation, err := txQUICTLSIdentityPayload(q.config, keyNumber, committeeHash, c.endpoint)
	if err != nil {
		return nil, err
	}
	if generation != c.tlsGeneration || txQUICReceiptIdentity(expectedPublicKey) != c.receiptIdentity {
		return nil, fmt.Errorf("txquic forward client identity changed")
	}
	handshakeTimeout := q.config.ForwardTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = 3 * time.Second
	}

	tlsConfig, err := q.clientTLSConfig(tlsIdentity, expectedPublicKey)
	if err != nil {
		return nil, err
	}
	for {
		c.mu.Lock()
		if c.closed.Load() {
			c.mu.Unlock()
			return nil, fmt.Errorf("txquic forward client for %s is closed", c.endpoint)
		}
		if c.conn != nil {
			select {
			case <-c.conn.Context().Done():
				c.conn = nil
			default:
				conn := c.conn
				c.mu.Unlock()
				return conn, nil
			}
		}
		if c.dialing != nil {
			dialing := c.dialing
			c.mu.Unlock()
			select {
			case <-dialing:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		dialing := make(chan struct{})
		dialCtx, cancelDial := context.WithCancel(ctx)
		c.dialing = dialing
		c.dialCancel = cancelDial
		c.mu.Unlock()

		// Never hold c.mu across network I/O. Committee rotation can now retire
		// a stale client immediately even while this bounded dial is in flight.
		conn, dialErr := quic.DialAddr(dialCtx, c.endpoint, tlsConfig, &quic.Config{
			HandshakeIdleTimeout: handshakeTimeout,
			MaxIdleTimeout:       txQUICForwardIdleTimeout,
			KeepAlivePeriod:      txQUICForwardKeepAlivePeriod,
		})
		cancelDial()
		c.mu.Lock()
		if c.dialing == dialing {
			c.dialing = nil
			c.dialCancel = nil
			close(dialing)
		}
		if dialErr != nil {
			c.mu.Unlock()
			return nil, dialErr
		}
		if c.closed.Load() {
			c.mu.Unlock()
			_ = conn.CloseWithError(0, "committee route changed")
			return nil, fmt.Errorf("txquic forward client for %s was closed during dial", c.endpoint)
		}
		c.conn = conn
		c.mu.Unlock()
		return conn, nil
	}
}

func (c *txQUICForwardClient) sendReceipt(parent context.Context, q *TxQUICIngress, payload []byte, expectation txQUICAckExpectation, expectedPublicKey []byte) (*txQUICAckReceipt, error) {
	timeout := endpointForwardTimeout(q.config.ForwardTimeout, q.config.ReadTimeout, q.config.WriteTimeout)
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if q.ctx != nil {
		stopNodeCancel := context.AfterFunc(q.ctx, cancel)
		defer stopNodeCancel()
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := c.getConn(q, ctx, expectation.keyNumber, expectation.committeeHash, expectedPublicKey)
		if err != nil {
			return nil, err
		}

		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			c.forgetIfClosed(conn)
			lastErr = err
			continue
		}
		stopStream := context.AfterFunc(ctx, func() {
			stream.CancelRead(0)
			stream.CancelWrite(0)
		})

		_ = stream.SetWriteDeadline(time.Now().Add(q.config.WriteTimeout))
		if err := writeFullTxQUIC(stream, payload); err != nil {
			stopStream()
			stream.CancelRead(0)
			stream.CancelWrite(0)
			_ = stream.Close()
			c.forgetIfClosed(conn)
			lastErr = err
			continue
		}

		if err := stream.Close(); err != nil {
			stopStream()
			stream.CancelRead(0)
			stream.CancelWrite(0)
			c.forgetIfClosed(conn)
			lastErr = err
			continue
		}

		_ = stream.SetReadDeadline(time.Now().Add(q.config.ReadTimeout))
		ack, err := readTxQUICAck(stream, len(expectation.itemIDs))
		if err != nil {
			stopStream()
			stream.CancelRead(0)
			stream.CancelWrite(0)
			c.forgetIfClosed(conn)
			lastErr = fmt.Errorf("txquic ack read failed from %s: %w", c.endpoint, err)
			continue
		}

		connectionState := conn.ConnectionState().TLS
		if len(connectionState.PeerCertificates) == 0 {
			stopStream()
			return nil, fmt.Errorf("txquic TLS peer certificate missing from %s", c.endpoint)
		}
		validationErr := validateTxQUICAck(c.endpoint, ack, expectation, expectedPublicKey)
		if validationErr != nil {
			stopStream()
			var rejected *txQUICRemoteRejectError
			if !errors.As(validationErr, &rejected) || rejected == nil || rejected.ack == nil {
				return nil, validationErr
			}
		}
		if len(ack.CommitteePublicKey) == 0 {
			stopStream()
			return nil, fmt.Errorf("txquic committee receipt identity is empty from %s", c.endpoint)
		}
		receipt := &txQUICAckReceipt{Endpoint: c.endpoint, Identity: txQUICReceiptIdentity(ack.CommitteePublicKey), Ack: copyTxQUICAck(*ack)}
		stopStream()
		return receipt, validationErr
	}

	return nil, lastErr
}

func validateTxQUICAck(endpoint string, ack *txQUICAck, expectation txQUICAckExpectation, expectedPublicKey []byte) error {
	if ack == nil {
		return fmt.Errorf("nil txquic ack from %s", endpoint)
	}
	if ack.ChainID != expectation.chainID || ack.GenesisHash != expectation.genesisHash ||
		ack.KeyNumber != expectation.keyNumber || ack.CommitteeHash != expectation.committeeHash ||
		ack.BatchID != expectation.batchID || ack.Sender != expectation.sender ||
		ack.SenderEpoch != expectation.senderEpoch || ack.Nonce != expectation.nonce ||
		ack.ItemCount != uint32(len(expectation.itemIDs)) {
		return fmt.Errorf("txquic ack identity mismatch from %s", endpoint)
	}
	bitmapBytes := txQUICBitmapBytes(len(expectation.itemIDs))
	if len(ack.DurableBitmap) != bitmapBytes || len(ack.RetryableBitmap) != bitmapBytes {
		return fmt.Errorf("txquic ack bitmap length mismatch from %s", endpoint)
	}
	if len(expectation.itemIDs)%8 != 0 && bitmapBytes > 0 {
		unusedMask := byte(0xff << uint(len(expectation.itemIDs)%8))
		if ack.DurableBitmap[bitmapBytes-1]&unusedMask != 0 || ack.RetryableBitmap[bitmapBytes-1]&unusedMask != 0 {
			return fmt.Errorf("txquic ack bitmap padding is non-zero from %s", endpoint)
		}
	}
	covered := make([]bool, len(expectation.itemIDs))
	rejects := make([]txQUICTransactionReject, 0)
	for index := range expectation.itemIDs {
		durable := txQUICBitmapHas(ack.DurableBitmap, index)
		retryable := txQUICBitmapHas(ack.RetryableBitmap, index)
		if durable && retryable {
			return fmt.Errorf("txquic ack overlaps durable and retryable item %d from %s", index, endpoint)
		}
		if durable {
			covered[index] = true
		}
		if retryable {
			covered[index] = true
			rejects = append(rejects, txQUICTransactionReject{Hash: expectation.txHashes[index], Reason: "receiver temporarily rejected transaction", Class: txQUICRejectRetryable})
		}
	}
	for _, permanent := range ack.PermanentErrors {
		index := int(permanent.Index)
		if index < 0 || index >= len(expectation.itemIDs) || covered[index] {
			return fmt.Errorf("txquic ack has duplicate or invalid permanent item %d from %s", permanent.Index, endpoint)
		}
		if permanent.ItemID != expectation.itemIDs[index] {
			return fmt.Errorf("txquic ack permanent item identity mismatch at %d from %s", index, endpoint)
		}
		if !validTxQUICPermanentCode(permanent.Code) {
			return fmt.Errorf("txquic ack permanent error code %d is invalid from %s", permanent.Code, endpoint)
		}
		reason := strings.TrimSpace(permanent.Reason)
		if reason == "" || len(reason) > txQUICMaxPermanentReasonBytes {
			return fmt.Errorf("txquic ack permanent reason is invalid at %d from %s", index, endpoint)
		}
		covered[index] = true
		rejects = append(rejects, txQUICTransactionReject{Hash: expectation.txHashes[index], Reason: reason, Class: txQUICRejectPermanent})
	}
	for index, outcome := range covered {
		if !outcome {
			return fmt.Errorf("txquic ack omitted item %d from %s", index, endpoint)
		}
	}
	if err := verifyTxQUICAckSignature(expectedPublicKey, ack); err != nil {
		return fmt.Errorf("txquic ACK authentication failed from %s: %w", endpoint, err)
	}
	if len(rejects) != 0 {
		ackCopy := copyTxQUICAck(*ack)
		return &txQUICRemoteRejectError{endpoint: endpoint, rejects: rejects, ack: &ackCopy}
	}
	return nil
}

func copyTxQUICAck(ack txQUICAck) txQUICAck {
	ack.DurableBitmap = append([]byte(nil), ack.DurableBitmap...)
	ack.RetryableBitmap = append([]byte(nil), ack.RetryableBitmap...)
	ack.PermanentErrors = append([]txQUICPermanentError(nil), ack.PermanentErrors...)
	ack.CommitteePublicKey = append([]byte(nil), ack.CommitteePublicKey...)
	ack.Signature = append([]byte(nil), ack.Signature...)
	return ack
}

func readTxQUICAck(reader io.Reader, itemCount int) (*txQUICAck, error) {
	maxBytes := txQUICAckMaxEncodedBytes(itemCount)
	if reader == nil || maxBytes == 0 {
		return nil, fmt.Errorf("invalid txquic ACK read context")
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(encoded)) > maxBytes {
		return nil, fmt.Errorf("txquic ACK exceeds %d bytes", maxBytes)
	}
	var ack txQUICAck
	if err := rlp.DecodeBytes(encoded, &ack); err != nil {
		return nil, err
	}
	return &ack, nil
}

func readTxQUICPayloadSize(reader io.Reader, maxBytes int64) (int64, error) {
	if reader == nil || maxBytes <= 0 || maxBytes > int64(^uint32(0)) {
		return 0, fmt.Errorf("invalid txquic payload read context")
	}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, err
	}
	size := int64(binary.BigEndian.Uint32(header[:]))
	if size <= 0 || size > maxBytes {
		return 0, fmt.Errorf("txquic payload length %d exceeds bound %d", size, maxBytes)
	}
	return size, nil
}

func writeFullTxQUIC(w io.Writer, payload []byte) error {
	if w == nil || len(payload) == 0 || uint64(len(payload)) > uint64(^uint32(0)) {
		return fmt.Errorf("invalid txquic framed payload size %d", len(payload))
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeFullTxQUICBytes(w, header[:]); err != nil {
		return err
	}
	return writeFullTxQUICBytes(w, payload)
}

func writeFullTxQUICBytes(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := w.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

// forgetIfClosed removes a connection only when QUIC has declared the shared
// connection dead. A timeout or decode failure on one stream must not close
// the connection underneath other in-flight outbox workers.
func (c *txQUICForwardClient) forgetIfClosed(conn *quic.Conn) {
	if conn == nil {
		return
	}
	select {
	case <-conn.Context().Done():
		c.mu.Lock()
		if c.conn == conn {
			c.conn = nil
		}
		c.mu.Unlock()
	default:
	}
}

func (c *txQUICForwardClient) close() {
	conn := c.retire()
	if conn != nil {
		_ = conn.CloseWithError(0, "closed")
	}
}

// retire prevents new work, cancels an in-flight handshake, wakes all dial
// waiters, and detaches an established connection without waiting for QUIC's
// synchronous CloseWithError. Callers may therefore retire clients while the
// route publication lock is held, then close the returned connection outside
// that lock.
func (c *txQUICForwardClient) retire() *quic.Conn {
	if c == nil || !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	c.mu.Lock()
	cancel := c.dialCancel
	c.dialCancel = nil
	if c.dialing != nil {
		close(c.dialing)
		c.dialing = nil
	}
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return conn
}

func endpointForwardTimeout(forwardTimeout time.Duration, readTimeout time.Duration, writeTimeout time.Duration) time.Duration {
	total := forwardTimeout
	if total <= 0 {
		total = 3 * time.Second
	}
	if readTimeout > 0 {
		total += readTimeout
	}
	if writeTimeout > 0 {
		total += writeTimeout
	}
	return total
}

func (q *TxQUICIngress) decodeAndAuthenticateEnvelope(payload []byte) (*txQUICPacket, common.Address, error) {
	var pkt txQUICPacket
	if err := rlp.DecodeBytes(payload, &pkt); err != nil {
		return nil, common.Address{}, fmt.Errorf("decode txquic packet: %w", err)
	}
	if pkt.ChainID != q.config.ChainID || pkt.GenesisHash != q.config.GenesisHash {
		return nil, common.Address{}, fmt.Errorf("txquic packet chain identity mismatch")
	}
	signer, err := q.verifyPacket(&pkt)
	if err != nil {
		return nil, signer, err
	}
	return &pkt, signer, nil
}

func (q *TxQUICIngress) validateAuthenticatedPacket(pkt *txQUICPacket) error {
	if pkt == nil {
		return fmt.Errorf("nil txquic packet")
	}
	if err := validateTxQUICPublicTransactionTypes(pkt.Items); err != nil {
		return err
	}
	route, err := q.refreshFHSRouteCache()
	if err != nil {
		return fmt.Errorf("resolve current Fair HotStuff committee: %w", err)
	}
	if pkt.KeyNumber != route.KeyNumber || pkt.CommitteeHash != route.CommitteeHash {
		return fmt.Errorf("txquic packet committee generation mismatch")
	}
	if _, err := newTxQUICAckExpectation(pkt); err != nil {
		return err
	}
	if err := validateTxQUICCertificateStructure(pkt.Certificate, pkt.ChainID, pkt.GenesisHash); err != nil {
		return err
	}
	return nil
}

func validateTxQUICPublicTransactionTypes(items []*txQUICItem) error {
	for index, item := range items {
		if item == nil || item.Tx == nil || !item.Tx.IsInitialized() {
			continue
		}
		if item.Tx.Type() > types.SetCodeTxType {
			return fmt.Errorf("txquic item %d has unsupported transaction type %#x", index, item.Tx.Type())
		}
	}
	return nil
}

func packetItemsToTxs(pkt *txQUICPacket) ([]*types.Transaction, error) {
	if pkt == nil || len(pkt.Items) == 0 {
		return nil, fmt.Errorf("empty txquic packet items")
	}
	if err := validateTxQUICPublicTransactionTypes(pkt.Items); err != nil {
		return nil, err
	}
	txs := make([]*types.Transaction, len(pkt.Items))
	for i, item := range pkt.Items {
		if err := validateTxQUICItem(item); err != nil {
			return nil, fmt.Errorf("txquic item %d: %w", i, err)
		}
		if item.Tx.Type() == types.BlobTxType {
			txs[i] = item.Tx.WithBlobSidecar(item.BlobSidecar)
		} else {
			txs[i] = item.Tx
		}
	}
	return txs, nil
}

func verifyTxQUICBlobTransactions(txs types.Transactions) error {
	return types.VerifyBlobSidecars(txs, types.KZGBlobVerifier{})
}

func (q *TxQUICIngress) verifyTxQUICBlobTransactions(txs types.Transactions) error {
	if q != nil && q.txpool != nil {
		return types.VerifyBlobSidecarsForVersion(txs, q.txpool.ActiveBlobSidecarVersion(), types.KZGBlobVerifier{})
	}
	return verifyTxQUICBlobTransactions(txs)
}

func verifyTxQUICPacketBlobSidecars(pkt *txQUICPacket) error {
	txs, err := packetItemsToTxs(pkt)
	if err != nil {
		return err
	}
	return verifyTxQUICBlobTransactions(txs)
}

func verifyTxQUICBatchBlobSidecars(batch *txQUICBatch) error {
	if batch == nil {
		return fmt.Errorf("nil txquic batch")
	}
	return verifyTxQUICPacketBlobSidecars(&txQUICPacket{Certificate: batch.Certificate, Items: batch.Items})
}

func (q *TxQUICIngress) verifyTxQUICPacketBlobSidecars(pkt *txQUICPacket) error {
	txs, err := packetItemsToTxs(pkt)
	if err != nil {
		return err
	}
	return q.verifyTxQUICBlobTransactions(txs)
}

func (q *TxQUICIngress) verifyTxQUICBatchBlobSidecars(batch *txQUICBatch) error {
	if batch == nil {
		return fmt.Errorf("nil txquic batch")
	}
	return q.verifyTxQUICPacketBlobSidecars(&txQUICPacket{Certificate: batch.Certificate, Items: batch.Items})
}

// appendKZGVerifiedInboundReceived is the receiver ownership boundary. Its
// caller has already authenticated the packet and admission certificate. No
// sidecar can enter the unified WAL, TxPool, or a durable ACK without passing
// the real KZG verifier; exact durable retries are handled before this method.
func (q *TxQUICIngress) appendKZGVerifiedInboundReceived(ctx context.Context, pkt *txQUICPacket) error {
	if q == nil || q.wal == nil {
		return fmt.Errorf("TxQUIC unified ingress WAL is unavailable")
	}
	txs, err := packetItemsToTxs(pkt)
	if err != nil {
		return err
	}
	if err := q.verifyTxQUICBlobTransactions(txs); err != nil {
		return fmt.Errorf("verify TxQUIC blob sidecars: %w", err)
	}
	return q.wal.appendInboundReceived(ctx, pkt)
}

func (q *TxQUICIngress) verifyPacket(pkt *txQUICPacket) (common.Address, error) {
	if pkt == nil || len(pkt.Signature) != cyphercrypto.SignatureLength {
		return common.Address{}, fmt.Errorf("invalid ingress signature length")
	}
	hash := pkt.signingHash()
	pub, err := cyphercrypto.SigToPub(hash.Bytes(), pkt.Signature)
	if err != nil {
		return common.Address{}, err
	}
	pubBytes := cyphercrypto.FromECDSAPub(pub)
	if len(pubBytes) == 0 {
		return common.Address{}, fmt.Errorf("invalid ingress signer pubkey")
	}
	signer := common.BytesToAddress(cyphercrypto.Keccak256(pubBytes[1:])[12:])
	if signer != pkt.Sender {
		return signer, fmt.Errorf("ingress signer mismatch")
	}
	if _, ok := q.signers[signer]; !ok {
		return signer, fmt.Errorf("ingress signer not allowed")
	}
	return signer, nil
}

func (p *txQUICPacket) signingPayload() ([]byte, error) {
	if p == nil || p.CommitteeHash == (common.Hash{}) || len(p.Items) == 0 || len(p.Items) > int(^uint32(0)) {
		return nil, fmt.Errorf("invalid txquic packet")
	}
	certificateHash, err := txQUICCertificateHash(p.Certificate)
	if err != nil {
		return nil, err
	}
	return rlp.EncodeToBytes(txQUICSigningData{
		Domain: txQUICPacketDomain, ChainID: p.ChainID, GenesisHash: p.GenesisHash,
		KeyNumber: p.KeyNumber, CommitteeHash: p.CommitteeHash,
		BatchID: p.BatchID, Sender: p.Sender, SenderEpoch: p.SenderEpoch,
		Nonce: p.Nonce, Timestamp: p.Timestamp, TxRoot: p.TxRoot,
		AdmissionID: p.Certificate.AdmissionID, CertificateHash: certificateHash, ItemCount: uint32(len(p.Items)),
	})
}

func (p *txQUICPacket) signingHash() common.Hash {
	enc, _ := p.signingPayload()
	return cyphercrypto.Keccak256Hash(enc)
}

func (ack *txQUICAck) signingPayload() ([]byte, error) {
	if ack == nil || ack.CommitteeHash == (common.Hash{}) || ack.BatchID == (common.Hash{}) || ack.ItemCount == 0 {
		return nil, fmt.Errorf("invalid txquic acknowledgement")
	}
	return rlp.EncodeToBytes([]interface{}{
		txQUICAckDomain, ack.ChainID, ack.GenesisHash, ack.KeyNumber, ack.CommitteeHash, ack.BatchID, ack.Sender,
		ack.SenderEpoch, ack.Nonce, ack.CommitteePublicKey, ack.ItemCount, ack.DurableBitmap,
		ack.RetryableBitmap, ack.PermanentErrors,
	})
}

func txQUICAckDigest(ack *txQUICAck) ([]byte, error) {
	payload, err := ack.signingPayload()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	return digest[:], nil
}

func verifyTxQUICAckSignature(expectedPublicKey []byte, ack *txQUICAck) error {
	if ack == nil || len(expectedPublicKey) == 0 || len(ack.Signature) == 0 || !bytes.Equal(ack.CommitteePublicKey, expectedPublicKey) {
		return fmt.Errorf("missing txquic ACK signer")
	}
	public := bls.GetPublicKey(ack.CommitteePublicKey)
	if public == nil || !bytes.Equal(public.Serialize(), ack.CommitteePublicKey) {
		return fmt.Errorf("invalid txquic committee ACK public key")
	}
	var signature bls.Sign
	if err := signature.Deserialize(ack.Signature); err != nil {
		return fmt.Errorf("invalid txquic committee ACK signature encoding: %w", err)
	}
	digest, err := txQUICAckDigest(ack)
	if err != nil {
		return err
	}
	if !signature.VerifyHash(public, digest) {
		return fmt.Errorf("invalid txquic committee ACK signature")
	}
	return nil
}

func (q *TxQUICIngress) writeAck(stream *quic.Stream, ack txQUICAck) {
	signed, err := q.signAck(ack)
	if err != nil {
		log.Error("TxQUIC ACK signing failed; withholding acknowledgement", "batch", ack.BatchID, "err", err)
		stream.CancelWrite(1)
		return
	}
	_ = stream.SetWriteDeadline(time.Now().Add(q.config.WriteTimeout))
	if err := rlp.Encode(stream, &signed); err != nil {
		log.Warn("TxQUIC ack encode failed", "batch", signed.BatchID, "items", signed.ItemCount, "err", err)
	}
}

func (q *TxQUICIngress) signAck(ack txQUICAck) (txQUICAck, error) {
	if q == nil || ack.BatchID == (common.Hash{}) {
		return txQUICAck{}, fmt.Errorf("invalid TxQUIC acknowledgement")
	}
	if q.receiptPublicKey == nil || q.receiptSigner == nil {
		return txQUICAck{}, fmt.Errorf("TxQUIC committee ACK signer is unavailable")
	}
	route, err := q.refreshFHSRouteCache()
	if err != nil {
		return txQUICAck{}, fmt.Errorf("resolve TxQUIC committee before ACK signing: %w", err)
	}
	if route.KeyNumber != ack.KeyNumber || route.CommitteeHash != ack.CommitteeHash {
		return txQUICAck{}, fmt.Errorf("TxQUIC committee changed before ACK signing")
	}
	publicKey, err := q.receiptPublicKey()
	if err != nil {
		return txQUICAck{}, fmt.Errorf("resolve TxQUIC committee ACK identity: %w", err)
	}
	public := bls.GetPublicKey(publicKey)
	if public == nil || !bytes.Equal(public.Serialize(), publicKey) {
		return txQUICAck{}, fmt.Errorf("TxQUIC committee ACK identity is invalid")
	}
	ack.CommitteePublicKey = append(ack.CommitteePublicKey[:0], publicKey...)
	ack.Signature = nil
	digest, err := txQUICAckDigest(&ack)
	if err != nil {
		return txQUICAck{}, err
	}
	signature, err := q.receiptSigner(ack.KeyNumber, ack.CommitteeHash, digest)
	if err != nil {
		return txQUICAck{}, err
	}
	ack.Signature = append(ack.Signature[:0], signature...)
	if err := verifyTxQUICAckSignature(publicKey, &ack); err != nil {
		return txQUICAck{}, fmt.Errorf("TxQUIC ACK signer returned an invalid signature: %w", err)
	}
	return ack, nil
}

func (q *TxQUICIngress) serverCertificate(ctx context.Context) (tls.Certificate, error) {
	if q == nil || q.receiptPublicKey == nil || q.receiptSigner == nil {
		return tls.Certificate{}, fmt.Errorf("txquic TLS committee signer is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now()
	if certificate, err, ready := q.cachedServerCertificate(now); ready {
		return certificate, err
	}
	q.tlsMu.Lock()
	if q.tlsRefresh == nil {
		q.tlsRefresh = make(chan struct{}, 1)
	}
	refresh := q.tlsRefresh
	q.tlsMu.Unlock()
	var nodeDone <-chan struct{}
	if q.ctx != nil {
		nodeDone = q.ctx.Done()
	}
	// At most one route-provider call can be in flight. Waiting handshakes are
	// context-cancellable, and a provider that stops responding can strand only
	// that one builder rather than an unbounded set of TLS goroutines.
	select {
	case refresh <- struct{}{}:
	case <-ctx.Done():
		return tls.Certificate{}, ctx.Err()
	case <-nodeDone:
		return tls.Certificate{}, fmt.Errorf("txquic ingress is stopping")
	}
	select {
	case <-ctx.Done():
		<-refresh
		return tls.Certificate{}, ctx.Err()
	case <-nodeDone:
		<-refresh
		return tls.Certificate{}, fmt.Errorf("txquic ingress is stopping")
	default:
	}
	now = time.Now()
	if certificate, err, ready := q.cachedServerCertificate(now); ready {
		<-refresh
		return certificate, err
	}
	result := make(chan txQUICTLSCertificateResult, 1)
	go func() {
		certificate, err := q.buildServerCertificate(ctx)
		<-refresh
		result <- txQUICTLSCertificateResult{certificate: certificate, err: err}
	}()
	select {
	case built := <-result:
		return built.certificate, built.err
	case <-ctx.Done():
		return tls.Certificate{}, ctx.Err()
	case <-nodeDone:
		return tls.Certificate{}, fmt.Errorf("txquic ingress is stopping")
	}
}

func (q *TxQUICIngress) buildServerCertificate(ctx context.Context) (tls.Certificate, error) {
	fail := func(err error) (tls.Certificate, error) {
		q.tlsMu.Lock()
		q.tlsRouteChecked = time.Now()
		q.tlsRouteErr = err
		q.tlsMu.Unlock()
		return tls.Certificate{}, err
	}
	route, err := q.refreshFHSRouteCacheContext(ctx)
	if err != nil {
		return fail(fmt.Errorf("resolve txquic TLS committee identity: %w", err))
	}
	publicKey, err := q.receiptPublicKey()
	if err != nil {
		return fail(err)
	}
	localEndpoint := ""
	for index, candidate := range route.CommitteePublicKeys {
		if !bytes.Equal(candidate, publicKey) {
			continue
		}
		if localEndpoint != "" || index >= len(route.CommitteeEndpoints) {
			return fail(fmt.Errorf("txquic TLS signer has an ambiguous committee endpoint"))
		}
		localEndpoint = route.CommitteeEndpoints[index]
	}
	if localEndpoint == "" {
		return fail(fmt.Errorf("txquic TLS signer is outside the active committee"))
	}
	_, localPort, err := net.SplitHostPort(localEndpoint)
	if err != nil || localPort != strconv.Itoa(q.config.Port) {
		return fail(fmt.Errorf("txquic TLS committee endpoint does not match the local ingress port"))
	}
	identity, generation, err := txQUICTLSIdentityPayload(q.config, route.KeyNumber, route.CommitteeHash, localEndpoint)
	if err != nil {
		return fail(err)
	}

	q.tlsMu.Lock()
	if q.tlsGeneration == generation && q.tlsCertificate.Leaf != nil && time.Until(q.tlsCertificate.Leaf.NotAfter) >= time.Hour {
		certificate := q.tlsCertificate
		q.tlsRouteChecked = time.Now()
		q.tlsRouteErr = nil
		q.tlsMu.Unlock()
		return certificate, nil
	}
	q.tlsMu.Unlock()
	certificate, err := rnetnetwork.GenerateBLSTLSCertificate(txQUICTLSIdentityDomain, identity, publicKey, func(digest []byte) ([]byte, error) {
		return q.receiptSigner(route.KeyNumber, route.CommitteeHash, digest)
	})
	if err != nil {
		return fail(fmt.Errorf("attest txquic TLS certificate: %w", err))
	}
	q.tlsMu.Lock()
	q.tlsCertificate = certificate
	q.tlsGeneration = generation
	q.tlsRouteChecked = time.Now()
	q.tlsRouteErr = nil
	q.tlsMu.Unlock()
	return certificate, nil
}

func (q *TxQUICIngress) cachedServerCertificate(now time.Time) (tls.Certificate, error, bool) {
	q.tlsMu.Lock()
	defer q.tlsMu.Unlock()
	if q.tlsRouteChecked.IsZero() || !now.Before(q.tlsRouteChecked.Add(txQUICTLSRouteRefreshInterval)) {
		return tls.Certificate{}, nil, false
	}
	if q.tlsRouteErr != nil {
		return tls.Certificate{}, q.tlsRouteErr, true
	}
	if q.tlsCertificate.Leaf == nil || time.Until(q.tlsCertificate.Leaf.NotAfter) < time.Hour {
		return tls.Certificate{}, nil, false
	}
	return q.tlsCertificate, nil, true
}

func (q *TxQUICIngress) http3Certificate() (tls.Certificate, error) {
	if q.config.HTTP3CertFile != "" || q.config.HTTP3KeyFile != "" {
		if q.config.HTTP3CertFile == "" || q.config.HTTP3KeyFile == "" {
			return tls.Certificate{}, fmt.Errorf("http3 rpc cert and key must both be set")
		}
		return tls.LoadX509KeyPair(q.config.HTTP3CertFile, q.config.HTTP3KeyFile)
	}
	return tls.Certificate{}, fmt.Errorf("http3 rpc requires a static TLS certificate and key")
}

func (q *TxQUICIngress) clientTLSConfig(identity, expectedPublicKey []byte) (*tls.Config, error) {
	if q == nil || len(identity) == 0 || len(expectedPublicKey) == 0 {
		return nil, fmt.Errorf("txquic TLS identity is unavailable")
	}
	return &tls.Config{
		NextProtos:             []string{txQUICProtocolName},
		MinVersion:             tls.VersionTLS13,
		InsecureSkipVerify:     true, // Replaced by the mandatory committee-BLS verifier below.
		SessionTicketsDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			raw := make([][]byte, 0, len(state.PeerCertificates))
			for _, certificate := range state.PeerCertificates {
				if certificate != nil {
					raw = append(raw, certificate.Raw)
				}
			}
			return rnetnetwork.VerifyBLSTLSCertificate(raw, txQUICTLSIdentityDomain, identity, expectedPublicKey)
		},
	}, nil
}

func (q *TxQUICIngress) parseAllowlist() error {
	for i, configured := range q.config.AllowIPs {
		entry := strings.TrimSpace(configured)
		if entry == "" {
			return fmt.Errorf("txquic IP allowlist entry %d is empty", i)
		}
		if strings.Contains(entry, "/") {
			_, ipnet, err := net.ParseCIDR(entry)
			if err != nil {
				return fmt.Errorf("invalid txquic IP allowlist CIDR %q at entry %d: %w", entry, i, err)
			}
			q.allowNets = append(q.allowNets, ipnet)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return fmt.Errorf("invalid txquic IP allowlist address %q at entry %d", entry, i)
		}
		q.allowIPs[ip.String()] = struct{}{}
	}
	return nil
}

func (q *TxQUICIngress) parseSigners() {
	for _, signer := range q.config.AllowedSigners {
		q.signers[signer] = struct{}{}
	}
}

func (q *TxQUICIngress) allowed(addr net.Addr) bool {
	if len(q.allowIPs) == 0 && len(q.allowNets) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if _, ok := q.allowIPs[ip.String()]; ok {
		return true
	}
	for _, ipnet := range q.allowNets {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func (q *TxQUICIngress) tryAcquireInflightPayload(bytes int64) bool {
	if q == nil || bytes <= 0 {
		return false
	}
	q.inflightPayloadMu.Lock()
	defer q.inflightPayloadMu.Unlock()
	if q.inflightPayloadLimit <= 0 || bytes > q.inflightPayloadLimit-q.inflightPayloadBytes {
		return false
	}
	q.inflightPayloadBytes += bytes
	return true
}

func (q *TxQUICIngress) tryAcquireIngressWorker() bool {
	if q == nil || q.streamSem == nil {
		return false
	}
	select {
	case q.streamSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (q *TxQUICIngress) releaseIngressWorker() {
	if q == nil || q.streamSem == nil {
		return
	}
	select {
	case <-q.streamSem:
	default:
	}
}

func (q *TxQUICIngress) releaseInflightPayload(bytes int64) {
	if q == nil || bytes <= 0 {
		return
	}
	q.inflightPayloadMu.Lock()
	q.inflightPayloadBytes -= bytes
	if q.inflightPayloadBytes < 0 {
		q.inflightPayloadBytes = 0
	}
	q.inflightPayloadMu.Unlock()
}

func (q *TxQUICIngress) pendingInflightPayloadBytes() int64 {
	if q == nil {
		return 0
	}
	q.inflightPayloadMu.Lock()
	defer q.inflightPayloadMu.Unlock()
	return q.inflightPayloadBytes
}

func (q *TxQUICIngress) takeTokens(addr net.Addr, n int) bool {
	if q == nil || addr == nil || n <= 0 || q.config.MaxTxsPerIPPerSecond <= 0 || n > q.config.BurstTxsPerIP {
		return false
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	q.rateMu.Lock()
	defer q.rateMu.Unlock()
	now := time.Now()
	q.gcRateBucketsLocked(now, false)
	b := q.buckets[host]
	if b == nil {
		if len(q.buckets) >= q.config.RateBucketMaxEntries {
			q.gcRateBucketsLocked(now, true)
			if len(q.buckets) >= q.config.RateBucketMaxEntries {
				return false
			}
		}
		b = &txQUICRateBucket{tokens: q.config.BurstTxsPerIP, last: now, lastSeen: now}
		q.buckets[host] = b
	}
	b.lastSeen = now
	refillAfter := time.Duration(float64(time.Second) * float64(q.config.BurstTxsPerIP-b.tokens) / float64(q.config.MaxTxsPerIPPerSecond))
	if b.tokens >= q.config.BurstTxsPerIP || now.Sub(b.last) >= refillAfter {
		b.tokens = q.config.BurstTxsPerIP
		b.last = now
	} else if refill := int(now.Sub(b.last).Seconds() * float64(q.config.MaxTxsPerIPPerSecond)); refill > 0 {
		b.tokens += refill
		b.last = now
	}
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

func (q *TxQUICIngress) gcRateBucketsLocked(now time.Time, force bool) {
	if q.config.RateBucketIdleTTL <= 0 {
		return
	}
	interval := q.config.RateBucketIdleTTL / 2
	if interval > time.Minute {
		interval = time.Minute
	}
	if interval < time.Second {
		interval = time.Second
	}
	if !force && !q.rateLastGC.IsZero() && now.Sub(q.rateLastGC) < interval {
		return
	}
	for host, bucket := range q.buckets {
		if bucket == nil || now.Sub(bucket.lastSeen) >= q.config.RateBucketIdleTTL {
			delete(q.buckets, host)
		}
	}
	q.rateLastGC = now
}

func copyCommonTxAdmissionBatchForQUIC(admission *types.CommonTxAdmissionBatch) *types.CommonTxAdmissionBatch {
	if admission == nil {
		return nil
	}
	cpy := *admission
	if admission.ChainID != nil {
		cpy.ChainID = new(mathbig.Int).Set(admission.ChainID)
	}
	if len(admission.Signature) > 0 {
		cpy.Signature = append([]byte(nil), admission.Signature...)
	}
	if len(admission.TxHashes) > 0 {
		cpy.TxHashes = append([]common.Hash(nil), admission.TxHashes...)
	}
	return &cpy
}

func txQUICEndpointFromCommitteeAddress(address string, offset int) (string, bool) {
	host, port, ok := splitHostPortLoose(address)
	if !ok {
		return "", false
	}
	return net.JoinHostPort(host, strconv.Itoa(port+offset)), true
}

func splitHostPortLoose(address string) (string, int, bool) {
	address = strings.TrimSpace(address)
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		if strings.Count(address, ":") != 1 {
			return "", 0, false
		}
		idx := strings.LastIndex(address, ":")
		if idx <= 0 || idx == len(address)-1 {
			return "", 0, false
		}
		host = address[:idx]
		portText = address[idx+1:]
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 {
		return "", 0, false
	}
	return host, port, true
}

func txQUICJoinHostPort(host string, port int) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

const (
	// Hold the byte envelope for a five-second 200k TPS burst without changing
	// the fixed 512-item/4 MiB wire micro-batch bound. The independent 1 GiB
	// runtime ceiling still prevents configuration from becoming unbounded.
	defaultTxQUICBridgeQueueMaxBytes     = int64(256 * 1024 * 1024)
	defaultTxQUICBridgeWorkers           = 64
	defaultTxQUICIngressWorkers          = 256
	defaultTxQUICMaxInflightPayloadBytes = int64(512 * 1024 * 1024)
	defaultTxOutboxMaxRecords            = 1_000_000
	defaultTxOutboxMaxBytes              = int64(32 * 1024 * 1024 * 1024)
	defaultTxOutboxWorkers               = 64
	defaultTxOutboxRetryMin              = 50 * time.Millisecond
	defaultTxOutboxRetryMax              = 30 * time.Second
	txOutboxCommitInterval               = time.Millisecond
	txOutboxCommitMaxRequests            = 64
	txOutboxCommitMaxBytes               = int64(16 * 1024 * 1024)
	txOutboxLifecycleStripes             = 4096
	// Every admitted record reserves enough durable capacity for the largest
	// valid committee snapshot and bitmap before it can reach quorum. This
	// prevents a full payload-only outbox from deadlocking at stage promotion
	// and keeps endpoint metadata inside OutboxMaxBytes rather than merely
	// bounding the in-memory scheduler.
	txOutboxPlacementReserveBytes = int64(128 * 1024)
)

var (
	txOutboxIdentityKey     = []byte("cypher-txquic-outbox/identity")
	txOutboxRecordPrefix    = []byte("cypher-txquic-outbox/record/")
	txOutboxRetryPrefix     = []byte("cypher-txquic-outbox/retry/")
	txOutboxNoncePrefix     = []byte("cypher-txquic-outbox/nonce/")
	txIngressIdentityKey    = []byte("cypher-txquic-ingress/identity")
	txIngressManifestPrefix = []byte("cypher-txquic-ingress/manifest/")
	txIngressItemPrefix     = []byte("cypher-txquic-ingress/item/")
	txIngressTxPrefix       = []byte("cypher-txquic-ingress/tx/")
	txIngressReplayPrefix   = []byte("cypher-txquic-ingress/replay/")
	txIngressNoncePrefix    = []byte("cypher-txquic-ingress/nonce/")

	txOutboxPendingGauge  = metrics.NewRegisteredGauge("txquic/outbox/pending", nil)
	txOutboxBytesGauge    = metrics.NewRegisteredGauge("txquic/outbox/bytes", nil)
	txOutboxStoredMeter   = metrics.NewRegisteredMeter("txquic/outbox/stored", nil)
	txOutboxReplayMeter   = metrics.NewRegisteredMeter("txquic/outbox/replayed", nil)
	txOutboxRetryMeter    = metrics.NewRegisteredMeter("txquic/outbox/retries", nil)
	txOutboxCommitGroups  = metrics.NewRegisteredMeter("txquic/outbox/commit/groups", nil)
	txOutboxCommitEntries = metrics.NewRegisteredMeter("txquic/outbox/commit/requests", nil)
	txOutboxCommitBytes   = metrics.NewRegisteredMeter("txquic/outbox/commit/bytes", nil)
	txOutboxCommitQueue   = metrics.NewRegisteredTimer("txquic/outbox/commit/queue", nil)
	txOutboxCommitFsync   = metrics.NewRegisteredTimer("txquic/outbox/commit/fsync", nil)
	txOutboxCommitTotal   = metrics.NewRegisteredTimer("txquic/outbox/commit/total", nil)
	txIngressPendingGauge = metrics.NewRegisteredGauge("txquic/ingress/wal/pending", nil)
	txIngressBytesGauge   = metrics.NewRegisteredGauge("txquic/ingress/wal/bytes", nil)
	txIngressStoredMeter  = metrics.NewRegisteredMeter("txquic/ingress/wal/stored", nil)
	txIngressReplayMeter  = metrics.NewRegisteredMeter("txquic/ingress/wal/replayed", nil)
)

// TxOutboxRecord contains a semantic batch, never a replayable transport
// envelope. Every delivery attempt obtains a durable nonce and signs a fresh
// packet.
type TxOutboxRecord struct {
	BatchID   common.Hash
	Payload   []byte
	CreatedAt uint64
	Placement txOutboxPlacementState
}

// txOutboxRetryState is deliberately separate from TxOutboxRecord so updating
// backoff metadata never rewrites a multi-megabyte payload.
type txOutboxRetryState struct {
	Attempts  uint32
	NextRetry uint64
	LastError string
}

type txQUICDatabaseIdentity struct {
	ChainID     uint64
	GenesisHash common.Hash
}

type txQUICIngressManifest struct {
	ChainID         uint64
	GenesisHash     common.Hash
	BatchID         common.Hash
	TxRoot          common.Hash
	Certificate     *types.CommonTxAdmissionBatch
	ItemIDs         []common.Hash
	DurableBitmap   []byte
	RetryableBitmap []byte
	PermanentErrors []txQUICPermanentError
	PendingBitmap   []byte
	CreatedAt       uint64
	CompletedAt     uint64
}

type txQUICIngressItemRecord struct {
	BatchID common.Hash
	Index   uint32
	Item    *txQUICItem
}

type txQUICReplayState struct {
	Sender  common.Address
	Epoch   common.Hash
	Floor   uint64
	Highest uint64
	Seen    []byte
}

type txIngressCommitRequest struct {
	packet *txQUICPacket
	ack    txQUICAck
	bytes  int64
	result chan txIngressCommitResult
}

type txIngressCommitResult struct {
	ack txQUICAck
	err error
}

// TxQUICIngressStore persists replay state, batch outcome manifests and each
// accepted item in one group fsync before a signed ACK may leave the node.
type TxQUICIngressStore struct {
	db     ethdb.KeyValueStore
	config TxQUICConfig

	maxRecords        int
	maxBytes          int64
	commitInterval    time.Duration
	commitMaxRequests int
	commitMaxBytes    int64

	mu         sync.Mutex
	started    bool
	stopped    bool
	poison     error
	records    int
	bytes      int64
	ctx        context.Context
	cancel     context.CancelFunc
	commitCh   chan *txIngressCommitRequest
	wg         sync.WaitGroup
	batchLocks [256]sync.Mutex
	nonceLocks [256]sync.Mutex
}

type txOutboxNonceState struct {
	Sender          common.Address
	Epoch           common.Hash
	ReservedThrough uint64
}

type txOutboxNonceRange struct {
	next uint64
	end  uint64
}

type txOutboxDeliveryResult struct {
	record *TxOutboxRecord
	err    error
}

type txOutboxCommitRequest struct {
	batchID       common.Hash
	payload       []byte
	encoded       []byte
	bytes         int64
	reservedBytes int64
	walOwned      bool
	queued        time.Time
	result        chan txOutboxCommitResult
}

type txOutboxCommitResult struct {
	err          error
	waitForSpace <-chan struct{}
}

type txOutboxScheduleItem struct {
	batchID common.Hash
	due     uint64
}

type txOutboxScheduleHeap []txOutboxScheduleItem

func (h txOutboxScheduleHeap) Len() int { return len(h) }
func (h txOutboxScheduleHeap) Less(i, j int) bool {
	if h[i].due != h[j].due {
		return h[i].due < h[j].due
	}
	return bytes.Compare(h[i].batchID[:], h[j].batchID[:]) < 0
}
func (h txOutboxScheduleHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *txOutboxScheduleHeap) Push(value interface{}) {
	*h = append(*h, value.(txOutboxScheduleItem))
}
func (h *txOutboxScheduleHeap) Pop() interface{} {
	old := *h
	last := len(old) - 1
	value := old[last]
	old[last] = txOutboxScheduleItem{}
	*h = old[:last]
	return value
}

type TxOutbox struct {
	db ethdb.KeyValueStore
	// wal is shared with the receiver ingress store in dual-role nodes. The
	// outbox database below is a rebuildable delivery index, not a competing
	// durability boundary.
	wal *txIngressWAL

	maxRecords int
	maxBytes   int64
	workers    int
	retryMin   time.Duration
	retryMax   time.Duration
	config     TxQUICConfig

	commitInterval    time.Duration
	commitMaxRequests int
	commitMaxBytes    int64
	commitCh          chan *txOutboxCommitRequest
	lifecycle         [txOutboxLifecycleStripes]sync.Mutex
	lifecycleWG       sync.WaitGroup
	admissionMu       sync.Mutex

	mu                    sync.Mutex
	started               bool
	stopped               bool
	poison                error
	records               int
	bytes                 int64
	reservedRecords       int
	reservedBytes         int64
	reservations          map[common.Hash]int64
	inFlight              map[common.Hash]struct{}
	schedule              txOutboxScheduleHeap
	scheduled             map[common.Hash]uint64
	notify                chan struct{}
	space                 chan struct{}
	jobs                  chan *TxOutboxRecord
	results               chan txOutboxDeliveryResult
	ctx                   context.Context
	cancel                context.CancelFunc
	wg                    sync.WaitGroup
	stopDone              chan struct{}
	stopStarted           bool
	storeAdmissionClosed  bool
	activeStores          int
	activeStoresDone      chan struct{}
	commitAdmissionClosed bool
	commitProducers       int
	commitProducersDone   chan struct{}
	deliver               func(context.Context, []byte) error
	restore               func([]byte) error
	nonceRanges           map[string]*txOutboxNonceRange
}

func txOutboxLifecycleStripe(batchID common.Hash) int {
	return int(binary.BigEndian.Uint16(batchID[:2])) & (txOutboxLifecycleStripes - 1)
}

// lockLifecycle serializes the WAL->projection sequence for the same semantic
// batch while retaining parallelism across 4K independent hash stripes. This
// prevents a concurrent enqueue from committing its WAL record before an ACK
// delete but its mutable projection after that delete (or the inverse).
func (o *TxOutbox) lockLifecycle(batchIDs ...common.Hash) func() {
	indices := make([]int, 0, len(batchIDs))
	for _, batchID := range batchIDs {
		index := txOutboxLifecycleStripe(batchID)
		duplicate := false
		for _, existing := range indices {
			if existing == index {
				duplicate = true
				break
			}
		}
		if !duplicate {
			indices = append(indices, index)
		}
	}
	sort.Ints(indices)
	for _, index := range indices {
		o.lifecycle[index].Lock()
	}
	return func() {
		for index := len(indices) - 1; index >= 0; index-- {
			o.lifecycle[indices[index]].Unlock()
		}
	}
}

// backgroundIOContext snapshots the lifetime used by a durable lifecycle
// mutation without retaining the global scheduler/accounting lock across WAL
// or database I/O. The caller already owns the relevant lifecycle stripe.
func (o *TxOutbox) backgroundIOContext() (context.Context, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.poison != nil {
		return nil, fmt.Errorf("tx outbox is poisoned until restart: %w", o.poison)
	}
	if !o.started || o.stopped {
		return nil, errors.New("tx outbox is not running")
	}
	return o.ctx, nil
}

func (o *TxOutbox) backgroundIOComplete() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.poison != nil {
		return fmt.Errorf("tx outbox is poisoned until restart: %w", o.poison)
	}
	return nil
}

func (o *TxOutbox) poisonBackgroundIO(err error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.poison == nil {
		o.poison = err
	}
	return o.poison
}

func NewTxQUICIngressStore(db ethdb.KeyValueStore, config TxQUICConfig) *TxQUICIngressStore {
	maxRecords := config.OutboxMaxRecords
	if maxRecords <= 0 {
		maxRecords = defaultTxOutboxMaxRecords
	}
	maxBytes := config.OutboxMaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultTxOutboxMaxBytes
	}
	applyTxQUICDefaults(&config)
	commitQueueRequests := minPositiveInt(config.IngressCommitMaxRequests, txQUICMaxCommitRequests)
	return &TxQUICIngressStore{
		db: db, config: config, maxRecords: maxRecords, maxBytes: maxBytes,
		commitInterval:    config.IngressCommitInterval,
		commitMaxRequests: config.IngressCommitMaxRequests,
		commitMaxBytes:    config.IngressCommitMaxBytes,
		commitCh:          make(chan *txIngressCommitRequest, commitQueueRequests*4),
	}
}

func txQUICIngressManifestKey(batchID common.Hash) []byte {
	key := make([]byte, len(txIngressManifestPrefix)+common.HashLength)
	copy(key, txIngressManifestPrefix)
	copy(key[len(txIngressManifestPrefix):], batchID[:])
	return key
}

func txQUICIngressItemKey(batchID common.Hash, index uint32) []byte {
	key := make([]byte, len(txIngressItemPrefix)+common.HashLength+4)
	copy(key, txIngressItemPrefix)
	copy(key[len(txIngressItemPrefix):], batchID[:])
	binary.BigEndian.PutUint32(key[len(txIngressItemPrefix)+common.HashLength:], index)
	return key
}

func txQUICReplayKey(sender common.Address, epoch common.Hash) []byte {
	key := make([]byte, len(txIngressReplayPrefix)+common.AddressLength+common.HashLength)
	copy(key, txIngressReplayPrefix)
	copy(key[len(txIngressReplayPrefix):], sender[:])
	copy(key[len(txIngressReplayPrefix)+common.AddressLength:], epoch[:])
	return key
}

func txQUICIngressNonceKey(sender common.Address, epoch common.Hash, nonce uint64) []byte {
	key := make([]byte, len(txIngressNoncePrefix)+common.AddressLength+common.HashLength+8)
	copy(key, txIngressNoncePrefix)
	copy(key[len(txIngressNoncePrefix):], sender[:])
	copy(key[len(txIngressNoncePrefix)+common.AddressLength:], epoch[:])
	binary.BigEndian.PutUint64(key[len(key)-8:], nonce)
	return key
}

func txQUICIngressTxKey(hash common.Hash) []byte {
	key := make([]byte, len(txIngressTxPrefix)+common.HashLength)
	copy(key, txIngressTxPrefix)
	copy(key[len(txIngressTxPrefix):], hash[:])
	return key
}

func txQUICIngressTxLocation(batchID common.Hash, index uint32) []byte {
	value := make([]byte, common.HashLength+4)
	copy(value, batchID[:])
	binary.BigEndian.PutUint32(value[common.HashLength:], index)
	return value
}

func decodeTxQUICIngressTxLocation(value []byte) (common.Hash, uint32, error) {
	if len(value) != common.HashLength+4 {
		return common.Hash{}, 0, fmt.Errorf("invalid txquic ingress transaction location")
	}
	batchID := common.BytesToHash(value[:common.HashLength])
	index := binary.BigEndian.Uint32(value[common.HashLength:])
	if batchID == (common.Hash{}) {
		return common.Hash{}, 0, fmt.Errorf("empty txquic ingress transaction batch")
	}
	return batchID, index, nil
}

func ensureTxQUICDatabaseIdentity(db ethdb.KeyValueStore, key []byte, identity txQUICDatabaseIdentity) error {
	if db == nil || identity.ChainID == 0 || identity.GenesisHash == (common.Hash{}) {
		return fmt.Errorf("invalid txquic database identity")
	}
	has, err := db.Has(key)
	if err != nil {
		return err
	}
	if has {
		encoded, err := db.Get(key)
		if err != nil {
			return err
		}
		var stored txQUICDatabaseIdentity
		if err := rlp.DecodeBytes(encoded, &stored); err != nil || stored != identity {
			return fmt.Errorf("txquic database belongs to a different or obsolete chain")
		}
		return nil
	}
	iterator := db.NewIterator(nil, nil)
	nonEmpty := iterator.Next()
	iteratorErr := iterator.Error()
	iterator.Release()
	if iteratorErr != nil {
		return fmt.Errorf("inspect txquic database identity: %w", iteratorErr)
	}
	if nonEmpty {
		// The unified WAL is deliberately started before its rebuildable
		// ingress/outbox index. A matching WAL identity is sufficient to add the
		// legacy index identity without mistaking the WAL records for an obsolete
		// database.
		if raw, walErr := db.Get(txIngressWALIdentityKey); walErr == nil {
			var walIdentity txIngressWALIdentity
			if decodeErr := rlp.DecodeBytes(raw, &walIdentity); decodeErr == nil &&
				walIdentity.Version == txIngressWALVersion && walIdentity.ChainID == identity.ChainID && walIdentity.GenesisHash == identity.GenesisHash {
				nonEmpty = false
			}
		}
		if nonEmpty {
			return fmt.Errorf("txquic database has no current chain identity; reset it with genesis")
		}
	}
	encoded, err := rlp.EncodeToBytes(&identity)
	if err != nil {
		return err
	}
	batch := db.NewBatch()
	if err := batch.Put(key, encoded); err != nil {
		return err
	}
	syncBatch, ok := batch.(ethdb.SyncBatch)
	if !ok {
		return fmt.Errorf("txquic database does not support synchronous batches")
	}
	if err := syncBatch.WriteSync(); err != nil {
		return fmt.Errorf("persist txquic database identity: %w", err)
	}
	return nil
}

func validateTxQUICDatabaseKeys(db ethdb.KeyValueStore, identityKey []byte, prefixes ...[]byte) error {
	iterator := db.NewIterator(nil, nil)
	defer iterator.Release()
	for iterator.Next() {
		key := iterator.Key()
		if bytes.Equal(key, identityKey) {
			continue
		}
		known := false
		for _, prefix := range prefixes {
			if bytes.HasPrefix(key, prefix) {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("txquic database contains an unknown or obsolete key")
		}
	}
	return iterator.Error()
}

func (s *TxQUICIngressStore) Start(parent context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("txquic ingress database is unavailable")
	}
	if err := validateTxQUICRuntimeLimits(s.config); err != nil {
		return err
	}
	identity := txQUICDatabaseIdentity{ChainID: s.config.ChainID, GenesisHash: s.config.GenesisHash}
	if err := ensureTxQUICDatabaseIdentity(s.db, txIngressIdentityKey, identity); err != nil {
		return err
	}
	s.mu.Lock()
	if s.started || s.stopped {
		s.mu.Unlock()
		return fmt.Errorf("txquic ingress store cannot be started")
	}
	if parent == nil {
		parent = context.Background()
	}
	s.ctx, s.cancel = context.WithCancel(parent)
	s.started = true
	s.mu.Unlock()
	s.wg.Add(1)
	go s.commitLoop()
	return nil
}

func (s *TxQUICIngressStore) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
}

func (s *TxQUICIngressStore) LockPacket(packet *txQUICPacket) func() {
	if s == nil || packet == nil {
		return func() {}
	}
	nonceHash, _ := txQUICRLPHash([]interface{}{packet.Sender, packet.SenderEpoch, packet.Nonce})
	nonceLock := &s.nonceLocks[int(nonceHash[0])]
	batchLock := &s.batchLocks[int(packet.BatchID[0])]
	nonceLock.Lock()
	batchLock.Lock()
	return func() {
		batchLock.Unlock()
		nonceLock.Unlock()
	}
}

func (s *TxQUICIngressStore) poisonErrLocked() error {
	if s.poison != nil {
		return fmt.Errorf("txquic ingress store is poisoned until restart: %w", s.poison)
	}
	if !s.started || s.stopped {
		return fmt.Errorf("txquic ingress store is not running")
	}
	return nil
}

func (s *TxQUICIngressStore) readManifest(batchID common.Hash) (*txQUICIngressManifest, []byte, error) {
	key := txQUICIngressManifestKey(batchID)
	has, err := s.db.Has(key)
	if err != nil || !has {
		return nil, nil, err
	}
	encoded, err := s.db.Get(key)
	if err != nil {
		return nil, nil, err
	}
	manifest, err := decodeTxQUICIngressManifest(key, encoded)
	if err == nil && (manifest.ChainID != s.config.ChainID || manifest.GenesisHash != s.config.GenesisHash) {
		return nil, nil, fmt.Errorf("txquic ingress manifest belongs to another chain")
	}
	return manifest, encoded, err
}

func decodeTxQUICIngressManifest(key, encoded []byte) (*txQUICIngressManifest, error) {
	if len(key) != len(txIngressManifestPrefix)+common.HashLength {
		return nil, fmt.Errorf("invalid txquic ingress manifest key length %d", len(key))
	}
	var manifest txQUICIngressManifest
	if err := rlp.DecodeBytes(encoded, &manifest); err != nil {
		return nil, fmt.Errorf("decode txquic ingress manifest: %w", err)
	}
	keyID := common.BytesToHash(key[len(txIngressManifestPrefix):])
	count := len(manifest.ItemIDs)
	bitmapBytes := txQUICBitmapBytes(count)
	if manifest.ChainID == 0 || manifest.GenesisHash == (common.Hash{}) || manifest.BatchID != keyID || count == 0 ||
		len(manifest.DurableBitmap) != bitmapBytes || len(manifest.RetryableBitmap) != bitmapBytes || len(manifest.PendingBitmap) != bitmapBytes ||
		manifest.CreatedAt == 0 || (manifest.CompletedAt != 0 && manifest.CompletedAt < manifest.CreatedAt) {
		return nil, fmt.Errorf("invalid txquic ingress manifest identity for %s", keyID)
	}
	if err := validateTxQUICCertificateStructure(manifest.Certificate, manifest.ChainID, manifest.GenesisHash); err != nil {
		return nil, fmt.Errorf("invalid txquic ingress certificate for %s: %w", keyID, err)
	}
	certificateHash, err := txQUICCertificateHash(manifest.Certificate)
	if err != nil {
		return nil, err
	}
	batchID, err := txQUICSemanticBatchID(manifest.ChainID, manifest.GenesisHash, manifest.Certificate.AdmissionID, certificateHash, count, manifest.TxRoot)
	if err != nil || batchID != manifest.BatchID {
		return nil, fmt.Errorf("invalid txquic ingress manifest commitment for %s", keyID)
	}
	if !txQUICBitmapPaddingZero(manifest.DurableBitmap, count) ||
		!txQUICBitmapPaddingZero(manifest.RetryableBitmap, count) ||
		!txQUICBitmapPaddingZero(manifest.PendingBitmap, count) {
		return nil, fmt.Errorf("txquic ingress manifest has non-zero bitmap padding for %s", keyID)
	}
	covered := make([]bool, count)
	seenItemIDs := make(map[common.Hash]struct{}, count)
	for index := 0; index < count; index++ {
		itemID := manifest.ItemIDs[index]
		if itemID == (common.Hash{}) {
			return nil, fmt.Errorf("txquic ingress manifest item %d has an empty identity", index)
		}
		if _, duplicate := seenItemIDs[itemID]; duplicate {
			return nil, fmt.Errorf("txquic ingress manifest item %d has a duplicate identity", index)
		}
		seenItemIDs[itemID] = struct{}{}
		durable := txQUICBitmapHas(manifest.DurableBitmap, index)
		retryable := txQUICBitmapHas(manifest.RetryableBitmap, index)
		if durable && retryable {
			return nil, fmt.Errorf("txquic ingress manifest item %d has overlapping outcomes", index)
		}
		covered[index] = durable || retryable
		if txQUICBitmapHas(manifest.PendingBitmap, index) && !txQUICBitmapHas(manifest.DurableBitmap, index) {
			return nil, fmt.Errorf("txquic ingress manifest pending item %d is not durable", index)
		}
	}
	lastPermanent := -1
	for _, permanent := range manifest.PermanentErrors {
		index := int(permanent.Index)
		if index < 0 || index >= count || index <= lastPermanent || covered[index] || permanent.ItemID != manifest.ItemIDs[index] {
			return nil, fmt.Errorf("txquic ingress manifest has an invalid permanent outcome at %d", permanent.Index)
		}
		if !validTxQUICPermanentCode(permanent.Code) {
			return nil, fmt.Errorf("txquic ingress manifest has invalid permanent code %d", permanent.Code)
		}
		if reason := strings.TrimSpace(permanent.Reason); reason == "" || len(permanent.Reason) > txQUICMaxPermanentReasonBytes {
			return nil, fmt.Errorf("txquic ingress manifest has invalid permanent reason at %d", permanent.Index)
		}
		covered[index] = true
		lastPermanent = index
	}
	for index, outcome := range covered {
		if !outcome {
			return nil, fmt.Errorf("txquic ingress manifest omitted item %d", index)
		}
	}
	complete := txQUICBitmapEmpty(manifest.PendingBitmap)
	if (manifest.CompletedAt != 0) != complete {
		return nil, fmt.Errorf("txquic ingress manifest completion state is inconsistent for %s", keyID)
	}
	return &manifest, nil
}

func ackFromManifest(packet *txQUICPacket, manifest *txQUICIngressManifest) txQUICAck {
	return txQUICAck{
		ChainID: packet.ChainID, GenesisHash: packet.GenesisHash,
		KeyNumber: packet.KeyNumber, CommitteeHash: packet.CommitteeHash, BatchID: packet.BatchID,
		Sender: packet.Sender, SenderEpoch: packet.SenderEpoch, Nonce: packet.Nonce,
		ItemCount:       uint32(len(manifest.ItemIDs)),
		DurableBitmap:   append([]byte(nil), manifest.DurableBitmap...),
		RetryableBitmap: append([]byte(nil), manifest.RetryableBitmap...),
		PermanentErrors: append([]txQUICPermanentError(nil), manifest.PermanentErrors...),
	}
}

func (s *TxQUICIngressStore) LookupPacket(packet *txQUICPacket, now time.Time) (txQUICAck, bool, error) {
	if s == nil || s.db == nil || packet == nil {
		return txQUICAck{}, false, errors.New("txquic ingress database is unavailable")
	}
	expectation, err := newTxQUICAckExpectation(packet)
	if err != nil {
		return txQUICAck{}, false, err
	}
	if packet.ChainID != s.config.ChainID || packet.GenesisHash != s.config.GenesisHash || packet.SenderEpoch != txQUICSenderEpoch(packet.ChainID, packet.GenesisHash, packet.Sender) {
		return txQUICAck{}, false, fmt.Errorf("txquic packet chain or sender identity mismatch")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.poisonErrLocked(); err != nil {
		return txQUICAck{}, false, err
	}
	nonceKey := txQUICIngressNonceKey(packet.Sender, packet.SenderEpoch, packet.Nonce)
	nonceKnown, err := s.db.Has(nonceKey)
	if err != nil {
		return txQUICAck{}, false, err
	}
	if nonceKnown {
		mapped, err := s.db.Get(nonceKey)
		if err != nil || len(mapped) != common.HashLength {
			return txQUICAck{}, false, fmt.Errorf("invalid txquic replay nonce mapping")
		}
		if common.BytesToHash(mapped) != packet.BatchID {
			return txQUICAck{}, false, fmt.Errorf("txquic nonce replayed with a different batch")
		}
	} else {
		packetTime := time.Unix(int64(packet.Timestamp), 0)
		if packetTime.After(now.Add(s.config.MaxClockSkew)) || packetTime.Before(now.Add(-s.config.MaxPacketAge)) {
			return txQUICAck{}, false, fmt.Errorf("txquic packet timestamp is outside the accepted window")
		}
		state, err := s.readReplayState(packet.Sender, packet.SenderEpoch)
		if err != nil {
			return txQUICAck{}, false, err
		}
		if state != nil {
			if packet.Nonce < state.Floor {
				return txQUICAck{}, false, fmt.Errorf("txquic nonce is below the replay window")
			}
			if packet.Nonce <= state.Highest && txQUICBitmapHas(state.Seen, int(packet.Nonce%s.config.ReplayWindow)) {
				return txQUICAck{}, false, fmt.Errorf("txquic replay state is missing its nonce mapping")
			}
		}
	}
	manifest, _, err := s.readManifest(packet.BatchID)
	if err != nil {
		return txQUICAck{}, false, err
	}
	if manifest == nil {
		if nonceKnown {
			return txQUICAck{}, false, fmt.Errorf("txquic replay refers to an expired acknowledgement")
		}
		return txQUICAck{}, false, nil
	}
	manifestCertificateHash, err := txQUICCertificateHash(manifest.Certificate)
	if err != nil {
		return txQUICAck{}, false, err
	}
	if manifest.ChainID != expectation.chainID || manifest.GenesisHash != expectation.genesisHash ||
		manifest.TxRoot != packet.TxRoot || manifest.Certificate.AdmissionID != expectation.admissionID ||
		manifestCertificateHash != expectation.certificateHash || len(manifest.ItemIDs) != len(expectation.itemIDs) {
		return txQUICAck{}, false, fmt.Errorf("txquic semantic BatchID collision")
	}
	for index := range manifest.ItemIDs {
		if manifest.ItemIDs[index] != expectation.itemIDs[index] {
			return txQUICAck{}, false, fmt.Errorf("txquic semantic BatchID item collision")
		}
	}
	ack := ackFromManifest(packet, manifest)
	return ack, nonceKnown && txQUICBitmapEmpty(manifest.RetryableBitmap), nil
}

func (s *TxQUICIngressStore) StoreSync(ctx context.Context, packet *txQUICPacket, ack txQUICAck) (txQUICAck, error) {
	unlock := s.LockPacket(packet)
	defer unlock()
	if cached, complete, err := s.LookupPacket(packet, time.Now()); err != nil {
		return txQUICAck{}, err
	} else if complete {
		return cached, nil
	}
	return s.StoreSyncLocked(ctx, packet, ack)
}

func (s *TxQUICIngressStore) StoreSyncLocked(ctx context.Context, packet *txQUICPacket, ack txQUICAck) (txQUICAck, error) {
	if s == nil || s.db == nil || packet == nil {
		return txQUICAck{}, errors.New("txquic ingress database is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	encoded, err := rlp.EncodeToBytes([]interface{}{packet.Certificate, packet.Items})
	if err != nil {
		return txQUICAck{}, err
	}
	if int64(len(encoded)) > s.commitMaxBytes {
		return txQUICAck{}, fmt.Errorf("txquic ingress commit request exceeds byte limit: bytes=%d limit=%d", len(encoded), s.commitMaxBytes)
	}
	request := &txIngressCommitRequest{packet: packet, ack: ack, bytes: int64(len(encoded)), result: make(chan txIngressCommitResult, 1)}
	s.mu.Lock()
	storeErr := s.poisonErrLocked()
	s.mu.Unlock()
	if storeErr != nil {
		return txQUICAck{}, storeErr
	}
	select {
	case s.commitCh <- request:
	case <-ctx.Done():
		return txQUICAck{}, ctx.Err()
	case <-s.ctx.Done():
		return txQUICAck{}, fmt.Errorf("txquic ingress store stopped")
	}
	select {
	case result := <-request.result:
		return result.ack, result.err
	case <-ctx.Done():
		return txQUICAck{}, ctx.Err()
	case <-s.ctx.Done():
		return txQUICAck{}, fmt.Errorf("txquic ingress store stopped")
	}
}

func (s *TxQUICIngressStore) commitLoop() {
	defer s.wg.Done()
	var carry *txIngressCommitRequest
	for {
		first := carry
		carry = nil
		if first != nil {
			select {
			case <-s.ctx.Done():
				first.result <- txIngressCommitResult{err: fmt.Errorf("txquic ingress store stopped")}
				s.failQueuedCommits(fmt.Errorf("txquic ingress store stopped"))
				return
			default:
			}
		}
		if first == nil {
			select {
			case <-s.ctx.Done():
				s.failQueuedCommits(fmt.Errorf("txquic ingress store stopped"))
				return
			case first = <-s.commitCh:
				if first == nil {
					continue
				}
			}
		}
		if first.bytes <= 0 || first.bytes > s.commitMaxBytes {
			first.result <- txIngressCommitResult{err: fmt.Errorf("txquic ingress commit request has invalid byte size %d", first.bytes)}
			continue
		}
		group := []*txIngressCommitRequest{first}
		bytesUsed := first.bytes
		timer := time.NewTimer(s.commitInterval)
	collect:
		for len(group) < s.commitMaxRequests {
			select {
			case request := <-s.commitCh:
				if request != nil {
					if request.bytes <= 0 || request.bytes > s.commitMaxBytes {
						request.result <- txIngressCommitResult{err: fmt.Errorf("txquic ingress commit request has invalid byte size %d", request.bytes)}
						continue
					}
					if bytesUsed > s.commitMaxBytes-request.bytes {
						carry = request
						break collect
					}
					group = append(group, request)
					bytesUsed += request.bytes
				}
			case <-timer.C:
				break collect
			case <-s.ctx.Done():
				break collect
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		s.commitIngressRequests(group)
	}
}

func (s *TxQUICIngressStore) failQueuedCommits(err error) {
	for {
		select {
		case request := <-s.commitCh:
			if request != nil {
				request.result <- txIngressCommitResult{err: err}
			}
		default:
			return
		}
	}
}

func (s *TxQUICIngressStore) commitIngressRequests(requests []*txIngressCommitRequest) {
	if len(requests) <= 1 {
		s.commitIngressRequestBatch(requests)
		return
	}
	safe, isolated, err := s.partitionIngressReplayGroups(requests)
	if err != nil {
		for _, request := range requests {
			request.result <- txIngressCommitResult{err: err}
		}
		return
	}
	if len(safe) > 0 {
		s.commitIngressRequestBatch(safe)
	}
	for _, group := range isolated {
		// Newest-first ensures an old request that falls behind the resulting
		// replay window is rejected without ever receiving a durable ACK.
		for _, request := range group {
			s.commitIngressRequestBatch([]*txIngressCommitRequest{request})
		}
	}
}

func (s *TxQUICIngressStore) commitIngressRequestBatch(requests []*txIngressCommitRequest) {
	if len(requests) == 0 {
		return
	}
	results := make([]txIngressCommitResult, len(requests))
	s.mu.Lock()
	if err := s.poisonErrLocked(); err != nil {
		s.mu.Unlock()
		for _, request := range requests {
			request.result <- txIngressCommitResult{err: err}
		}
		return
	}
	batch := s.db.NewBatch()
	projectedRecords, projectedBytes := s.records, s.bytes
	replayCache := make(map[string]*txQUICReplayState)
	txLocationCache := make(map[string][]byte)
	for requestIndex, request := range requests {
		merged, recordsDelta, bytesDelta, err := s.prepareIngressCommit(batch, request.packet, request.ack, replayCache, txLocationCache)
		if err != nil {
			results[requestIndex].err = err
			continue
		}
		projectedRecords += recordsDelta
		projectedBytes += bytesDelta
		results[requestIndex].ack = merged
	}
	for _, result := range results {
		if result.err != nil {
			s.mu.Unlock()
			for index, request := range requests {
				if results[index].err == nil {
					results[index].err = result.err
				}
				request.result <- results[index]
			}
			return
		}
	}
	if projectedRecords > s.maxRecords || projectedBytes > s.maxBytes {
		err := fmt.Errorf("txquic ingress WAL capacity exceeded: records=%d/%d bytes=%d/%d", projectedRecords, s.maxRecords, projectedBytes, s.maxBytes)
		s.mu.Unlock()
		for _, request := range requests {
			request.result <- txIngressCommitResult{err: err}
		}
		return
	}
	syncBatch, ok := batch.(ethdb.SyncBatch)
	if !ok {
		err := fmt.Errorf("txquic ingress database does not support synchronous batches")
		s.poison = err
		s.mu.Unlock()
		for _, request := range requests {
			request.result <- txIngressCommitResult{err: err}
		}
		return
	}
	if err := syncBatch.WriteSync(); err != nil {
		s.poison = fmt.Errorf("ambiguous ingress group fsync failure: %w", err)
		poison := s.poison
		s.mu.Unlock()
		for _, request := range requests {
			request.result <- txIngressCommitResult{err: poison}
		}
		return
	}
	s.records, s.bytes = projectedRecords, projectedBytes
	s.updateGaugesLocked()
	s.mu.Unlock()
	txIngressStoredMeter.Mark(int64(len(requests)))
	for index, request := range requests {
		request.result <- results[index]
	}
}

func (s *TxQUICIngressStore) partitionIngressReplayGroups(requests []*txIngressCommitRequest) ([]*txIngressCommitRequest, [][]*txIngressCommitRequest, error) {
	type replayGroup struct {
		sender   common.Address
		epoch    common.Hash
		requests []*txIngressCommitRequest
	}
	groups := make(map[string]*replayGroup)
	for _, request := range requests {
		if request == nil || request.packet == nil {
			return nil, nil, fmt.Errorf("nil txquic ingress commit request")
		}
		packet := request.packet
		if packet.ChainID != s.config.ChainID || packet.GenesisHash != s.config.GenesisHash || packet.Sender == (common.Address{}) ||
			packet.SenderEpoch != txQUICSenderEpoch(packet.ChainID, packet.GenesisHash, packet.Sender) || packet.Nonce == 0 {
			return nil, nil, fmt.Errorf("invalid txquic ingress commit envelope")
		}
		keyBytes := txQUICReplayKey(packet.Sender, packet.SenderEpoch)
		key := string(keyBytes)
		group := groups[key]
		if group == nil {
			group = &replayGroup{sender: packet.Sender, epoch: packet.SenderEpoch}
			groups[key] = group
		}
		group.requests = append(group.requests, request)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.poisonErrLocked(); err != nil {
		return nil, nil, err
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	safe := make([]*txIngressCommitRequest, 0, len(requests))
	isolated := make([][]*txIngressCommitRequest, 0)
	for _, key := range keys {
		group := groups[key]
		sort.SliceStable(group.requests, func(i, j int) bool {
			return group.requests[i].packet.Nonce < group.requests[j].packet.Nonce
		})
		state, err := s.readReplayState(group.sender, group.epoch)
		if err != nil {
			return nil, nil, err
		}
		var highest uint64
		if state == nil {
			highest = group.requests[0].packet.Nonce
		} else {
			highest = state.Highest
		}
		previous := uint64(0)
		needsIsolation := false
		for _, request := range group.requests {
			nonce := request.packet.Nonce
			if nonce == previous {
				needsIsolation = true
				break
			}
			previous = nonce
			if nonce <= highest {
				continue
			}
			highest = nonce
		}
		if !needsIsolation {
			floor := uint64(1)
			if highest >= s.config.ReplayWindow {
				floor = highest - s.config.ReplayWindow + 1
			}
			for _, request := range group.requests {
				if request.packet.Nonce < floor {
					needsIsolation = true
					break
				}
			}
		}
		if needsIsolation {
			sort.SliceStable(group.requests, func(i, j int) bool {
				return group.requests[i].packet.Nonce > group.requests[j].packet.Nonce
			})
			isolated = append(isolated, group.requests)
			continue
		}
		safe = append(safe, group.requests...)
	}
	return safe, isolated, nil
}

func (s *TxQUICIngressStore) prepareIngressCommit(batch ethdb.Batch, packet *txQUICPacket, candidate txQUICAck, replayCache map[string]*txQUICReplayState, txLocationCache map[string][]byte) (txQUICAck, int, int64, error) {
	if packet.ChainID != s.config.ChainID || packet.GenesisHash != s.config.GenesisHash || packet.SenderEpoch != txQUICSenderEpoch(packet.ChainID, packet.GenesisHash, packet.Sender) {
		return txQUICAck{}, 0, 0, fmt.Errorf("txquic packet chain or sender identity mismatch")
	}
	expectation, err := newTxQUICAckExpectation(packet)
	if err != nil {
		return txQUICAck{}, 0, 0, err
	}
	if err := validateTxQUICAckOutcome(&candidate, expectation); err != nil {
		return txQUICAck{}, 0, 0, err
	}
	if err := s.prepareReplayCommit(batch, packet, replayCache); err != nil {
		return txQUICAck{}, 0, 0, err
	}
	manifest, oldEncoded, err := s.readManifest(packet.BatchID)
	if err != nil {
		return txQUICAck{}, 0, 0, err
	}
	newRecord := manifest == nil
	if newRecord {
		manifest = &txQUICIngressManifest{
			ChainID: packet.ChainID, GenesisHash: packet.GenesisHash, BatchID: packet.BatchID,
			TxRoot: packet.TxRoot, Certificate: copyCommonTxAdmissionBatchForQUIC(packet.Certificate),
			ItemIDs:       append([]common.Hash(nil), expectation.itemIDs...),
			DurableBitmap: make([]byte, len(candidate.DurableBitmap)), RetryableBitmap: make([]byte, len(candidate.RetryableBitmap)),
			PendingBitmap: make([]byte, len(candidate.DurableBitmap)), CreatedAt: uint64(time.Now().UnixNano()),
		}
	} else {
		manifestCertificateHash, hashErr := txQUICCertificateHash(manifest.Certificate)
		if hashErr != nil || manifest.ChainID != packet.ChainID || manifest.GenesisHash != packet.GenesisHash ||
			manifest.TxRoot != packet.TxRoot || manifest.Certificate.AdmissionID != expectation.admissionID ||
			manifestCertificateHash != expectation.certificateHash || len(manifest.ItemIDs) != len(expectation.itemIDs) {
			return txQUICAck{}, 0, 0, fmt.Errorf("txquic semantic BatchID collision")
		}
	}
	for index := range manifest.ItemIDs {
		if manifest.ItemIDs[index] != expectation.itemIDs[index] {
			return txQUICAck{}, 0, 0, fmt.Errorf("txquic semantic BatchID item collision at %d", index)
		}
	}
	existingPermanent := make(map[uint32]txQUICPermanentError, len(manifest.PermanentErrors))
	for _, permanent := range manifest.PermanentErrors {
		existingPermanent[permanent.Index] = permanent
	}
	candidatePermanent := make(map[uint32]txQUICPermanentError, len(candidate.PermanentErrors))
	for _, permanent := range candidate.PermanentErrors {
		candidatePermanent[permanent.Index] = permanent
	}
	newPermanent := make([]txQUICPermanentError, 0)
	bytesDelta := -int64(len(oldEncoded))
	for index := range expectation.itemIDs {
		if txQUICBitmapHas(manifest.DurableBitmap, index) {
			continue
		}
		if permanent, ok := existingPermanent[uint32(index)]; ok {
			newPermanent = append(newPermanent, permanent)
			continue
		}
		if txQUICBitmapHas(candidate.DurableBitmap, index) {
			txQUICBitmapSet(manifest.DurableBitmap, index)
			txQUICBitmapClear(manifest.RetryableBitmap, index)
			txQUICBitmapSet(manifest.PendingBitmap, index)
			itemRecord := txQUICIngressItemRecord{BatchID: packet.BatchID, Index: uint32(index), Item: packet.Items[index]}
			encodedItem, err := rlp.EncodeToBytes(&itemRecord)
			if err != nil {
				return txQUICAck{}, 0, 0, err
			}
			itemKey := txQUICIngressItemKey(packet.BatchID, uint32(index))
			hasItem, err := s.db.Has(itemKey)
			if err != nil {
				return txQUICAck{}, 0, 0, err
			}
			if !hasItem {
				bytesDelta += int64(len(encodedItem))
			}
			if err := batch.Put(itemKey, encodedItem); err != nil {
				return txQUICAck{}, 0, 0, err
			}
			txHash := packet.Items[index].Tx.Hash()
			locationKey := txQUICIngressTxKey(txHash)
			cacheKey := string(locationKey)
			oldLocation, cached := txLocationCache[cacheKey]
			if !cached {
				hasLocation, err := s.db.Has(locationKey)
				if err != nil {
					return txQUICAck{}, 0, 0, err
				}
				if hasLocation {
					oldLocation, err = s.db.Get(locationKey)
					if err != nil {
						return txQUICAck{}, 0, 0, err
					}
					oldLocation = append([]byte(nil), oldLocation...)
				}
			}
			location := txQUICIngressTxLocation(packet.BatchID, uint32(index))
			if err := batch.Put(locationKey, location); err != nil {
				return txQUICAck{}, 0, 0, err
			}
			bytesDelta += int64(len(location) - len(oldLocation))
			txLocationCache[cacheKey] = location
			continue
		}
		if permanent, ok := candidatePermanent[uint32(index)]; ok {
			txQUICBitmapClear(manifest.RetryableBitmap, index)
			newPermanent = append(newPermanent, permanent)
			continue
		}
		txQUICBitmapSet(manifest.RetryableBitmap, index)
	}
	for _, permanent := range manifest.PermanentErrors {
		if txQUICBitmapHas(manifest.DurableBitmap, int(permanent.Index)) {
			continue
		}
		if _, exists := existingPermanent[permanent.Index]; exists {
			found := false
			for _, kept := range newPermanent {
				if kept.Index == permanent.Index {
					found = true
					break
				}
			}
			if !found {
				newPermanent = append(newPermanent, permanent)
			}
		}
	}
	manifest.PermanentErrors = newPermanent
	if txQUICBitmapEmpty(manifest.PendingBitmap) {
		if manifest.CompletedAt == 0 {
			manifest.CompletedAt = uint64(time.Now().UnixNano())
		}
	} else {
		manifest.CompletedAt = 0
	}
	encodedManifest, err := rlp.EncodeToBytes(manifest)
	if err != nil {
		return txQUICAck{}, 0, 0, err
	}
	bytesDelta += int64(len(encodedManifest))
	if err := batch.Put(txQUICIngressManifestKey(packet.BatchID), encodedManifest); err != nil {
		return txQUICAck{}, 0, 0, err
	}
	return ackFromManifest(packet, manifest), func() int {
		if newRecord {
			return 1
		}
		return 0
	}(), bytesDelta, nil
}

func validateTxQUICAckOutcome(ack *txQUICAck, expectation txQUICAckExpectation) error {
	if ack == nil || ack.ChainID != expectation.chainID || ack.GenesisHash != expectation.genesisHash || ack.BatchID != expectation.batchID ||
		ack.KeyNumber != expectation.keyNumber || ack.CommitteeHash != expectation.committeeHash ||
		ack.Sender != expectation.sender || ack.SenderEpoch != expectation.senderEpoch || ack.Nonce != expectation.nonce || ack.ItemCount != uint32(len(expectation.itemIDs)) {
		return fmt.Errorf("txquic acknowledgement identity mismatch")
	}
	bitmapBytes := txQUICBitmapBytes(len(expectation.itemIDs))
	if len(ack.DurableBitmap) != bitmapBytes || len(ack.RetryableBitmap) != bitmapBytes {
		return fmt.Errorf("txquic acknowledgement bitmap length mismatch")
	}
	if !txQUICBitmapPaddingZero(ack.DurableBitmap, len(expectation.itemIDs)) ||
		!txQUICBitmapPaddingZero(ack.RetryableBitmap, len(expectation.itemIDs)) {
		return fmt.Errorf("txquic acknowledgement bitmap padding is non-zero")
	}
	covered := make([]bool, len(expectation.itemIDs))
	for index := range covered {
		durable, retryable := txQUICBitmapHas(ack.DurableBitmap, index), txQUICBitmapHas(ack.RetryableBitmap, index)
		if durable && retryable {
			return fmt.Errorf("txquic acknowledgement outcome overlap")
		}
		covered[index] = durable || retryable
	}
	for _, permanent := range ack.PermanentErrors {
		index := int(permanent.Index)
		if index < 0 || index >= len(covered) || covered[index] || permanent.ItemID != expectation.itemIDs[index] || strings.TrimSpace(permanent.Reason) == "" || len(permanent.Reason) > txQUICMaxPermanentReasonBytes {
			return fmt.Errorf("invalid txquic permanent acknowledgement outcome")
		}
		if !validTxQUICPermanentCode(permanent.Code) {
			return fmt.Errorf("invalid txquic permanent acknowledgement code")
		}
		covered[index] = true
	}
	for _, outcome := range covered {
		if !outcome {
			return fmt.Errorf("txquic acknowledgement omitted an item")
		}
	}
	return nil
}

func (s *TxQUICIngressStore) readReplayState(sender common.Address, epoch common.Hash) (*txQUICReplayState, error) {
	key := txQUICReplayKey(sender, epoch)
	has, err := s.db.Has(key)
	if err != nil || !has {
		return nil, err
	}
	encoded, err := s.db.Get(key)
	if err != nil {
		return nil, err
	}
	var state txQUICReplayState
	if err := rlp.DecodeBytes(encoded, &state); err != nil {
		return nil, err
	}
	expectedFloor := uint64(1)
	if state.Highest >= s.config.ReplayWindow {
		expectedFloor = state.Highest - s.config.ReplayWindow + 1
	}
	if state.Sender != sender || state.Epoch != epoch || epoch != txQUICSenderEpoch(s.config.ChainID, s.config.GenesisHash, sender) ||
		len(state.Seen) != txQUICBitmapBytes(int(s.config.ReplayWindow)) ||
		state.Highest == 0 || state.Floor != expectedFloor || !txQUICBitmapPaddingZero(state.Seen, int(s.config.ReplayWindow)) ||
		!txQUICBitmapHas(state.Seen, int(state.Highest%s.config.ReplayWindow)) {
		return nil, fmt.Errorf("invalid txquic replay state")
	}
	return &state, nil
}

func (s *TxQUICIngressStore) prepareReplayCommit(batch ethdb.Batch, packet *txQUICPacket, cache map[string]*txQUICReplayState) error {
	nonceKey := txQUICIngressNonceKey(packet.Sender, packet.SenderEpoch, packet.Nonce)
	has, err := s.db.Has(nonceKey)
	if err != nil {
		return err
	}
	if has {
		mapped, err := s.db.Get(nonceKey)
		if err != nil {
			return err
		}
		if len(mapped) != common.HashLength || common.BytesToHash(mapped) != packet.BatchID {
			return fmt.Errorf("txquic nonce collision")
		}
		return nil
	}
	now := time.Now()
	packetTime := time.Unix(int64(packet.Timestamp), 0)
	if packetTime.After(now.Add(s.config.MaxClockSkew)) || packetTime.Before(now.Add(-s.config.MaxPacketAge)) {
		return fmt.Errorf("txquic packet timestamp is outside the accepted window")
	}
	cacheKey := string(txQUICReplayKey(packet.Sender, packet.SenderEpoch))
	state, cached := cache[cacheKey]
	if !cached {
		state, err = s.readReplayState(packet.Sender, packet.SenderEpoch)
		if err != nil {
			return err
		}
		if state == nil {
			floor := uint64(1)
			if packet.Nonce >= s.config.ReplayWindow {
				floor = packet.Nonce - s.config.ReplayWindow + 1
			}
			state = &txQUICReplayState{
				Sender: packet.Sender, Epoch: packet.SenderEpoch, Floor: floor, Highest: packet.Nonce,
				Seen: make([]byte, txQUICBitmapBytes(int(s.config.ReplayWindow))),
			}
			txQUICBitmapSet(state.Seen, int(packet.Nonce%s.config.ReplayWindow))
			encodedState, err := rlp.EncodeToBytes(state)
			if err != nil {
				return err
			}
			if err := batch.Put(txQUICReplayKey(packet.Sender, packet.SenderEpoch), encodedState); err != nil {
				return err
			}
			if err := batch.Put(nonceKey, packet.BatchID[:]); err != nil {
				return err
			}
			cache[cacheKey] = state
			return nil
		}
		cache[cacheKey] = state
	}
	if packet.Nonce < state.Floor {
		return fmt.Errorf("txquic nonce is below replay window")
	}
	oldFloor := state.Floor
	if packet.Nonce > state.Highest {
		oldHighest := state.Highest
		state.Highest = packet.Nonce
		newFloor := uint64(1)
		if state.Highest >= s.config.ReplayWindow {
			newFloor = state.Highest - s.config.ReplayWindow + 1
		}
		if newFloor > oldHighest {
			// A large authenticated jump invalidates the entire old window. Delete
			// at most ReplayWindow mappings; never loop across the numeric gap.
			for nonce := oldFloor; ; nonce++ {
				if err := batch.Delete(txQUICIngressNonceKey(packet.Sender, packet.SenderEpoch, nonce)); err != nil {
					return err
				}
				if nonce == oldHighest {
					break
				}
			}
			clear(state.Seen)
		} else {
			for nonce := oldFloor; nonce < newFloor; nonce++ {
				txQUICBitmapClear(state.Seen, int(nonce%s.config.ReplayWindow))
				if err := batch.Delete(txQUICIngressNonceKey(packet.Sender, packet.SenderEpoch, nonce)); err != nil {
					return err
				}
			}
		}
		state.Floor = newFloor
	}
	bitIndex := int(packet.Nonce % s.config.ReplayWindow)
	if txQUICBitmapHas(state.Seen, bitIndex) {
		return fmt.Errorf("txquic nonce replay collision")
	}
	txQUICBitmapSet(state.Seen, bitIndex)
	encodedState, err := rlp.EncodeToBytes(state)
	if err != nil {
		return err
	}
	if err := batch.Put(txQUICReplayKey(packet.Sender, packet.SenderEpoch), encodedState); err != nil {
		return err
	}
	if err := batch.Put(nonceKey, packet.BatchID[:]); err != nil {
		return err
	}
	return nil
}

func (s *TxQUICIngressStore) Restore(restore func(*types.CommonTxAdmissionBatch, []*txQUICItem) error) error {
	if s == nil || s.db == nil {
		return errors.New("txquic ingress database is unavailable")
	}
	iterator := s.db.NewIterator(txIngressManifestPrefix, nil)
	defer iterator.Release()
	records, totalBytes := 0, int64(0)
	for iterator.Next() {
		if records >= s.maxRecords {
			return fmt.Errorf("txquic ingress WAL capacity exceeded: records=%d/%d bytes=%d/%d", records+1, s.maxRecords, totalBytes, s.maxBytes)
		}
		key, value := append([]byte(nil), iterator.Key()...), append([]byte(nil), iterator.Value()...)
		manifest, err := decodeTxQUICIngressManifest(key, value)
		if err != nil {
			return err
		}
		if manifest.ChainID != s.config.ChainID || manifest.GenesisHash != s.config.GenesisHash {
			return fmt.Errorf("txquic ingress manifest belongs to another chain")
		}
		maxTimestamp := uint64(time.Now().Add(s.config.MaxClockSkew).UnixNano())
		if manifest.CreatedAt > maxTimestamp || manifest.CompletedAt > maxTimestamp {
			return fmt.Errorf("txquic ingress manifest timestamp is in the future")
		}
		records, totalBytes, err = advanceTxQUICDurableCapacity("txquic ingress WAL", records, totalBytes, 1, int64(len(value)), s.maxRecords, s.maxBytes)
		if err != nil {
			return err
		}
		for index := range manifest.ItemIDs {
			if !txQUICBitmapHas(manifest.PendingBitmap, index) {
				continue
			}
			itemKey := txQUICIngressItemKey(manifest.BatchID, uint32(index))
			encodedItem, err := s.db.Get(itemKey)
			if err != nil {
				return fmt.Errorf("missing txquic ingress item %s/%d: %w", manifest.BatchID, index, err)
			}
			if _, err := decodeTxQUICIngressItem(itemKey, encodedItem, manifest); err != nil {
				return err
			}
			records, totalBytes, err = advanceTxQUICDurableCapacity("txquic ingress WAL", records, totalBytes, 0, int64(len(encodedItem)), s.maxRecords, s.maxBytes)
			if err != nil {
				return err
			}
		}
	}
	if err := iterator.Error(); err != nil {
		return err
	}
	itemIterator := s.db.NewIterator(txIngressItemPrefix, nil)
	defer itemIterator.Release()
	for itemIterator.Next() {
		key := append([]byte(nil), itemIterator.Key()...)
		if len(key) != len(txIngressItemPrefix)+common.HashLength+4 {
			return fmt.Errorf("invalid or obsolete txquic ingress item key")
		}
		batchID := common.BytesToHash(key[len(txIngressItemPrefix) : len(txIngressItemPrefix)+common.HashLength])
		index := binary.BigEndian.Uint32(key[len(key)-4:])
		manifest, _, err := s.readManifest(batchID)
		if err != nil {
			return err
		}
		if manifest == nil || int(index) >= len(manifest.ItemIDs) || !txQUICBitmapHas(manifest.PendingBitmap, int(index)) {
			return fmt.Errorf("orphan txquic ingress item %s/%d", batchID, index)
		}
		if _, err := decodeTxQUICIngressItem(key, append([]byte(nil), itemIterator.Value()...), manifest); err != nil {
			return err
		}
	}
	if err := itemIterator.Error(); err != nil {
		return err
	}
	txIterator := s.db.NewIterator(txIngressTxPrefix, nil)
	defer txIterator.Release()
	for txIterator.Next() {
		key := append([]byte(nil), txIterator.Key()...)
		value := append([]byte(nil), txIterator.Value()...)
		if len(key) != len(txIngressTxPrefix)+common.HashLength {
			return fmt.Errorf("invalid txquic ingress transaction index key")
		}
		txHash := common.BytesToHash(key[len(txIngressTxPrefix):])
		batchID, index, err := decodeTxQUICIngressTxLocation(value)
		if err != nil {
			return err
		}
		manifest, _, err := s.readManifest(batchID)
		if err != nil {
			return err
		}
		if manifest == nil || int(index) >= len(manifest.ItemIDs) || !txQUICBitmapHas(manifest.PendingBitmap, int(index)) {
			return fmt.Errorf("dangling txquic ingress transaction index for %s", txHash)
		}
		itemKey := txQUICIngressItemKey(batchID, index)
		encodedItem, err := s.db.Get(itemKey)
		if err != nil {
			return fmt.Errorf("missing indexed txquic ingress item %s/%d: %w", batchID, index, err)
		}
		item, err := decodeTxQUICIngressItem(itemKey, encodedItem, manifest)
		if err != nil {
			return err
		}
		if item.Tx == nil || item.Tx.Hash() != txHash {
			return fmt.Errorf("txquic ingress transaction index hash mismatch")
		}
		records, totalBytes, err = advanceTxQUICDurableCapacity("txquic ingress WAL", records, totalBytes, 0, int64(len(value)), s.maxRecords, s.maxBytes)
		if err != nil {
			return err
		}
	}
	if err := txIterator.Error(); err != nil {
		return err
	}
	if err := s.validateReplayWAL(); err != nil {
		return err
	}
	if err := validateTxQUICDatabaseKeys(s.db, txIngressIdentityKey,
		txIngressManifestPrefix, txIngressItemPrefix, txIngressTxPrefix, txIngressReplayPrefix, txIngressNoncePrefix,
		txIngressWALIdentityKey, txIngressWALManifestKey, txIngressWALTailKey, txIngressWALRecordPrefix, txIngressWALEventPrefix, txIngressWALGenerationPrefix,
	); err != nil {
		return err
	}
	if restore != nil {
		restoreIterator := s.db.NewIterator(txIngressManifestPrefix, nil)
		defer restoreIterator.Release()
		for restoreIterator.Next() {
			key, value := append([]byte(nil), restoreIterator.Key()...), append([]byte(nil), restoreIterator.Value()...)
			manifest, err := decodeTxQUICIngressManifest(key, value)
			if err != nil {
				return err
			}
			items := make([]*txQUICItem, 0, len(manifest.ItemIDs))
			for index := range manifest.ItemIDs {
				if !txQUICBitmapHas(manifest.PendingBitmap, index) {
					continue
				}
				itemKey := txQUICIngressItemKey(manifest.BatchID, uint32(index))
				encodedItem, err := s.db.Get(itemKey)
				if err != nil {
					return err
				}
				item, err := decodeTxQUICIngressItem(itemKey, encodedItem, manifest)
				if err != nil {
					return err
				}
				items = append(items, item)
			}
			if err := restore(copyCommonTxAdmissionBatchForQUIC(manifest.Certificate), items); err != nil {
				return fmt.Errorf("restore txquic ingress batch %s: %w", manifest.BatchID, err)
			}
		}
		if err := restoreIterator.Error(); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.records, s.bytes = records, totalBytes
	s.updateGaugesLocked()
	s.mu.Unlock()
	if records > 0 {
		txIngressReplayMeter.Mark(int64(records))
	}
	return nil
}

func (s *TxQUICIngressStore) validateReplayWAL() error {
	replayStates := make(map[string]*txQUICReplayState)
	replayIterator := s.db.NewIterator(txIngressReplayPrefix, nil)
	defer replayIterator.Release()
	for replayIterator.Next() {
		key := append([]byte(nil), replayIterator.Key()...)
		if len(key) != len(txIngressReplayPrefix)+common.AddressLength+common.HashLength {
			return fmt.Errorf("invalid txquic replay state key")
		}
		sender := common.BytesToAddress(key[len(txIngressReplayPrefix) : len(txIngressReplayPrefix)+common.AddressLength])
		epoch := common.BytesToHash(key[len(txIngressReplayPrefix)+common.AddressLength:])
		if sender == (common.Address{}) || epoch != txQUICSenderEpoch(s.config.ChainID, s.config.GenesisHash, sender) {
			return fmt.Errorf("invalid txquic replay state identity")
		}
		state, err := s.readReplayState(sender, epoch)
		if err != nil {
			return err
		}
		if state == nil {
			return fmt.Errorf("missing txquic replay state")
		}
		replayStates[string(key)] = state
		activeBits := make([]byte, len(state.Seen))
		for nonce := state.Floor; ; nonce++ {
			bit := int(nonce % s.config.ReplayWindow)
			txQUICBitmapSet(activeBits, bit)
			if txQUICBitmapHas(state.Seen, bit) {
				mapped, err := s.db.Get(txQUICIngressNonceKey(sender, epoch, nonce))
				if err != nil {
					return fmt.Errorf("missing txquic replay nonce mapping for %s/%d: %w", sender, nonce, err)
				}
				if len(mapped) != common.HashLength || common.BytesToHash(mapped) == (common.Hash{}) {
					return fmt.Errorf("invalid txquic replay nonce mapping for %s/%d", sender, nonce)
				}
			}
			if nonce == state.Highest {
				break
			}
		}
		for index := range state.Seen {
			if state.Seen[index]&^activeBits[index] != 0 {
				return fmt.Errorf("txquic replay bitmap contains a bit outside its active window")
			}
		}
	}
	if err := replayIterator.Error(); err != nil {
		return err
	}

	nonceIterator := s.db.NewIterator(txIngressNoncePrefix, nil)
	defer nonceIterator.Release()
	for nonceIterator.Next() {
		key := append([]byte(nil), nonceIterator.Key()...)
		if len(key) != len(txIngressNoncePrefix)+common.AddressLength+common.HashLength+8 {
			return fmt.Errorf("invalid txquic replay nonce key")
		}
		offset := len(txIngressNoncePrefix)
		sender := common.BytesToAddress(key[offset : offset+common.AddressLength])
		offset += common.AddressLength
		epoch := common.BytesToHash(key[offset : offset+common.HashLength])
		nonce := binary.BigEndian.Uint64(key[len(key)-8:])
		mapped := append([]byte(nil), nonceIterator.Value()...)
		if sender == (common.Address{}) || nonce == 0 || epoch != txQUICSenderEpoch(s.config.ChainID, s.config.GenesisHash, sender) ||
			len(mapped) != common.HashLength || common.BytesToHash(mapped) == (common.Hash{}) {
			return fmt.Errorf("invalid txquic replay nonce identity")
		}
		state := replayStates[string(txQUICReplayKey(sender, epoch))]
		if state == nil || nonce < state.Floor || nonce > state.Highest || !txQUICBitmapHas(state.Seen, int(nonce%s.config.ReplayWindow)) {
			return fmt.Errorf("orphan txquic replay nonce mapping for %s/%d", sender, nonce)
		}
	}
	if err := nonceIterator.Error(); err != nil {
		return err
	}
	return nil
}

func decodeTxQUICIngressItem(key, encoded []byte, manifest *txQUICIngressManifest) (*txQUICItem, error) {
	if len(key) != len(txIngressItemPrefix)+common.HashLength+4 || manifest == nil {
		return nil, fmt.Errorf("invalid txquic ingress item key")
	}
	var record txQUICIngressItemRecord
	if err := rlp.DecodeBytes(encoded, &record); err != nil {
		return nil, err
	}
	keyBatch := common.BytesToHash(key[len(txIngressItemPrefix) : len(txIngressItemPrefix)+common.HashLength])
	keyIndex := binary.BigEndian.Uint32(key[len(key)-4:])
	if record.BatchID != keyBatch || record.BatchID != manifest.BatchID || record.Index != keyIndex || int(record.Index) >= len(manifest.ItemIDs) || record.Item == nil || record.Item.Tx == nil {
		return nil, fmt.Errorf("invalid txquic ingress item identity")
	}
	// Rebuild the position-bound transaction and sidecar commitment recorded by
	// the manifest. This also rejects missing, duplicate-source, malformed, or
	// non-blob sidecars before startup restore can publish the item.
	itemID, _, _, err := txQUICItemCommitment(manifest.Certificate, record.Item, record.Index)
	if err != nil {
		return nil, err
	}
	if itemID != manifest.ItemIDs[record.Index] {
		return nil, fmt.Errorf("txquic ingress item commitment mismatch")
	}
	return record.Item, nil
}

func (s *TxQUICIngressStore) ScanPage(ctx context.Context, after []byte, maxRecords int, maxBytes int64, visit func(*txQUICIngressManifest) error) ([]byte, bool, error) {
	if s == nil || s.db == nil || visit == nil {
		return nil, true, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if maxRecords <= 0 {
		maxRecords = txQUICIngressMaintenanceRecords
	}
	if maxBytes <= 0 {
		maxBytes = txQUICIngressMaintenanceBytes
	}
	iterator := s.db.NewIterator(txIngressManifestPrefix, after)
	defer iterator.Release()
	var last []byte
	records := 0
	bytesUsed := int64(0)
	for iterator.Next() {
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		default:
		}
		key := append([]byte(nil), iterator.Key()...)
		if len(key) != len(txIngressManifestPrefix)+common.HashLength {
			return nil, false, fmt.Errorf("invalid txquic ingress manifest key")
		}
		suffix := key[len(txIngressManifestPrefix):]
		if len(after) > 0 && bytes.Equal(suffix, after) {
			continue
		}
		value := append([]byte(nil), iterator.Value()...)
		manifest, err := decodeTxQUICIngressManifest(key, value)
		if err != nil {
			return nil, false, err
		}
		if err := visit(manifest); err != nil {
			return nil, false, err
		}
		last = append(last[:0], suffix...)
		records++
		bytesUsed += int64(len(value))
		if records >= maxRecords || bytesUsed >= maxBytes {
			return last, false, nil
		}
	}
	if err := iterator.Error(); err != nil {
		return nil, false, err
	}
	return nil, true, nil
}

func (s *TxQUICIngressStore) PendingItems(batchID common.Hash) ([]*txQUICItem, error) {
	manifest, _, err := s.readManifest(batchID)
	if err != nil || manifest == nil {
		return nil, err
	}
	items := make([]*txQUICItem, 0)
	for index := range manifest.ItemIDs {
		if !txQUICBitmapHas(manifest.PendingBitmap, index) {
			continue
		}
		key := txQUICIngressItemKey(batchID, uint32(index))
		encoded, err := s.db.Get(key)
		if err != nil {
			return nil, err
		}
		item, err := decodeTxQUICIngressItem(key, encoded, manifest)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

// ResolveTransaction returns a transaction that is still durably retained by
// the ingress WAL. The hash index, manifest pending bit, item record and item
// commitment are checked under the store lock so compaction cannot turn one
// lookup into a mixed-generation read.
func (s *TxQUICIngressStore) ResolveTransaction(hash common.Hash) (*types.Transaction, error) {
	if s == nil || s.db == nil || hash == (common.Hash{}) {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.poisonErrLocked(); err != nil {
		return nil, err
	}
	indexKey := txQUICIngressTxKey(hash)
	has, err := s.db.Has(indexKey)
	if err != nil || !has {
		return nil, err
	}
	location, err := s.db.Get(indexKey)
	if err != nil {
		return nil, err
	}
	batchID, index, err := decodeTxQUICIngressTxLocation(location)
	if err != nil {
		return nil, err
	}
	manifest, _, err := s.readManifest(batchID)
	if err != nil {
		return nil, err
	}
	if manifest == nil || int(index) >= len(manifest.ItemIDs) || !txQUICBitmapHas(manifest.PendingBitmap, int(index)) {
		return nil, fmt.Errorf("dangling txquic ingress transaction index for %s", hash)
	}
	itemKey := txQUICIngressItemKey(batchID, index)
	encodedItem, err := s.db.Get(itemKey)
	if err != nil {
		return nil, fmt.Errorf("read indexed txquic ingress transaction %s: %w", hash, err)
	}
	item, err := decodeTxQUICIngressItem(itemKey, encodedItem, manifest)
	if err != nil {
		return nil, err
	}
	if item.Tx == nil || item.Tx.Hash() != hash {
		return nil, fmt.Errorf("txquic ingress transaction index hash mismatch")
	}
	txs, err := packetItemsToTxs(&txQUICPacket{Items: []*txQUICItem{item}})
	if err != nil {
		return nil, err
	}
	return txs[0], nil
}

func (s *TxQUICIngressStore) CompactFinalized(batchID common.Hash, finalized func(common.Hash) bool, now time.Time) (int, error) {
	if s == nil {
		return 0, nil
	}
	lock := &s.batchLocks[int(batchID[0])]
	lock.Lock()
	defer lock.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.poisonErrLocked(); err != nil {
		return 0, err
	}
	manifest, oldManifest, err := s.readManifest(batchID)
	if err != nil || manifest == nil {
		return 0, err
	}
	batch := s.db.NewBatch()
	removed := 0
	bytesDelta := int64(0)
	for index := range manifest.ItemIDs {
		if !txQUICBitmapHas(manifest.PendingBitmap, index) {
			continue
		}
		key := txQUICIngressItemKey(batchID, uint32(index))
		encoded, err := s.db.Get(key)
		if err != nil {
			return 0, err
		}
		item, err := decodeTxQUICIngressItem(key, encoded, manifest)
		if err != nil {
			return 0, err
		}
		if item.Tx == nil || finalized == nil || !finalized(item.Tx.Hash()) {
			continue
		}
		if err := batch.Delete(key); err != nil {
			return 0, err
		}
		txHash := item.Tx.Hash()
		indexKey := txQUICIngressTxKey(txHash)
		hasIndex, err := s.db.Has(indexKey)
		if err != nil {
			return 0, err
		}
		if hasIndex {
			location, err := s.db.Get(indexKey)
			if err != nil {
				return 0, err
			}
			if bytes.Equal(location, txQUICIngressTxLocation(batchID, uint32(index))) {
				if err := batch.Delete(indexKey); err != nil {
					return 0, err
				}
				bytesDelta -= int64(len(location))
			}
		}
		txQUICBitmapClear(manifest.PendingBitmap, index)
		bytesDelta -= int64(len(encoded))
		removed++
	}
	if removed == 0 {
		if manifest.CompletedAt > 0 && now.Sub(time.Unix(0, int64(manifest.CompletedAt))) >= s.config.IngressAckRetention {
			if err := batch.Delete(txQUICIngressManifestKey(batchID)); err != nil {
				return 0, err
			}
			if err := batch.Write(); err != nil {
				return 0, err
			}
			s.records--
			s.bytes -= int64(len(oldManifest))
			if s.records < 0 {
				s.records = 0
			}
			if s.bytes < 0 {
				s.bytes = 0
			}
			s.updateGaugesLocked()
		}
		return 0, nil
	}
	if txQUICBitmapEmpty(manifest.PendingBitmap) && manifest.CompletedAt == 0 {
		manifest.CompletedAt = uint64(now.UnixNano())
	}
	encodedManifest, err := rlp.EncodeToBytes(manifest)
	if err != nil {
		return 0, err
	}
	bytesDelta += int64(len(encodedManifest) - len(oldManifest))
	if err := batch.Put(txQUICIngressManifestKey(batchID), encodedManifest); err != nil {
		return 0, err
	}
	if err := batch.Write(); err != nil {
		return 0, err
	}
	s.bytes += bytesDelta
	if s.bytes < 0 {
		s.bytes = 0
	}
	s.updateGaugesLocked()
	return removed, nil
}

func (s *TxQUICIngressStore) Pending() (int, int64) {
	if s == nil {
		return 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records, s.bytes
}

func (s *TxQUICIngressStore) updateGaugesLocked() {
	txIngressPendingGauge.Update(int64(s.records))
	txIngressBytesGauge.Update(s.bytes)
}

func NewTxOutbox(db ethdb.KeyValueStore, config TxQUICConfig) *TxOutbox {
	applyTxQUICDefaults(&config)
	workers := config.OutboxWorkers
	if workers <= 0 {
		workers = defaultTxOutboxWorkers
	}
	if workers > txQUICMaxBridgeWorkers {
		workers = txQUICMaxBridgeWorkers
	}
	maxRecords := config.OutboxMaxRecords
	if maxRecords <= 0 {
		maxRecords = defaultTxOutboxMaxRecords
	}
	maxBytes := config.OutboxMaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultTxOutboxMaxBytes
	}
	retryMin := config.OutboxRetryMin
	if retryMin <= 0 {
		retryMin = defaultTxOutboxRetryMin
	}
	retryMax := config.OutboxRetryMax
	if retryMax < retryMin {
		retryMax = defaultTxOutboxRetryMax
	}
	return &TxOutbox{
		db:                db,
		maxRecords:        maxRecords,
		maxBytes:          maxBytes,
		workers:           workers,
		retryMin:          retryMin,
		retryMax:          retryMax,
		config:            config,
		commitInterval:    txOutboxCommitInterval,
		commitMaxRequests: txOutboxCommitMaxRequests,
		commitMaxBytes:    txOutboxCommitMaxBytes,
		commitCh:          make(chan *txOutboxCommitRequest, txOutboxCommitMaxRequests),
		inFlight:          make(map[common.Hash]struct{}),
		scheduled:         make(map[common.Hash]uint64),
		notify:            make(chan struct{}, 1),
		space:             make(chan struct{}),
		jobs:              make(chan *TxOutboxRecord, workers),
		results:           make(chan txOutboxDeliveryResult, workers),
		stopDone:          make(chan struct{}),
		nonceRanges:       make(map[string]*txOutboxNonceRange),
		reservations:      make(map[common.Hash]int64),
	}
}

func txOutboxRecordKey(batchID common.Hash) []byte {
	key := make([]byte, len(txOutboxRecordPrefix)+len(batchID))
	copy(key, txOutboxRecordPrefix)
	copy(key[len(txOutboxRecordPrefix):], batchID[:])
	return key
}

func txOutboxRetryKey(batchID common.Hash) []byte {
	key := make([]byte, len(txOutboxRetryPrefix)+len(batchID))
	copy(key, txOutboxRetryPrefix)
	copy(key[len(txOutboxRetryPrefix):], batchID[:])
	return key
}

func txOutboxNonceKey(sender common.Address, epoch common.Hash) []byte {
	key := make([]byte, len(txOutboxNoncePrefix)+common.AddressLength+common.HashLength)
	copy(key, txOutboxNoncePrefix)
	copy(key[len(txOutboxNoncePrefix):], sender[:])
	copy(key[len(txOutboxNoncePrefix)+common.AddressLength:], epoch[:])
	return key
}

func txOutboxBatchID(payload []byte) common.Hash {
	batch, _, err := decodeTxQUICBatch(payload)
	if err != nil {
		return common.Hash{}
	}
	return batch.BatchID
}

func (o *TxOutbox) placementForBatch(batchID common.Hash, payload []byte) (txOutboxPlacementState, bool, error) {
	if o == nil || o.db == nil || batchID == (common.Hash{}) || len(payload) == 0 {
		return txOutboxPlacementState{}, false, fmt.Errorf("invalid tx outbox placement lookup")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.poison != nil {
		return txOutboxPlacementState{}, false, fmt.Errorf("tx outbox is poisoned until restart: %w", o.poison)
	}
	encoded, err := o.db.Get(txOutboxRecordKey(batchID))
	if err != nil {
		return txOutboxPlacementState{}, false, err
	}
	var record TxOutboxRecord
	if err := rlp.DecodeBytes(encoded, &record); err != nil {
		return txOutboxPlacementState{}, false, fmt.Errorf("decode tx outbox placement record %s: %w", batchID, err)
	}
	if record.BatchID != batchID || !bytes.Equal(record.Payload, payload) {
		return txOutboxPlacementState{}, false, fmt.Errorf("tx outbox placement record %s changed during delivery", batchID)
	}
	if !record.Placement.present() {
		return txOutboxPlacementState{}, false, nil
	}
	if err := validatePersistedTxOutboxPlacementState(record.Placement); err != nil {
		return txOutboxPlacementState{}, false, err
	}
	return cloneTxOutboxPlacementState(record.Placement), true, nil
}

// validateTxOutboxQuorumPromotion binds the trusted accumulator outcome to the
// exact semantic record and committee generation being promoted. The aggregate
// intentionally contains no endpoint signature: distinct authenticated
// receipts have already been checked by txQUICReceiptAccumulator. Consequently
// this validator is used only by promotePlacementSync, never by a network or
// restart decode path.
func validateTxOutboxQuorumPromotion(record *TxOutboxRecord, state txOutboxPlacementState, aggregate txQUICAck) error {
	if record == nil || record.BatchID == (common.Hash{}) || len(record.Payload) == 0 {
		return fmt.Errorf("invalid tx outbox quorum promotion record")
	}
	if state.QuorumEstablished {
		return fmt.Errorf("tx outbox quorum promotion marker must be set by the durable writer")
	}
	if err := validateTxOutboxPlacementState(state, false); err != nil {
		return err
	}
	if len(aggregate.CommitteePublicKey) != 0 || len(aggregate.Signature) != 0 {
		return fmt.Errorf("tx outbox quorum promotion requires an accumulator aggregate")
	}
	if aggregate.Sender == (common.Address{}) || aggregate.Nonce == 0 {
		return fmt.Errorf("tx outbox quorum promotion has an incomplete transport identity")
	}
	batch, itemIDs, err := decodeTxQUICBatch(record.Payload)
	if err != nil {
		return fmt.Errorf("decode tx outbox quorum promotion batch: %w", err)
	}
	if batch.BatchID != record.BatchID {
		return fmt.Errorf("tx outbox quorum promotion batch identity mismatch")
	}
	certificateHash, err := txQUICCertificateHash(batch.Certificate)
	if err != nil {
		return err
	}
	txHashes := make([]common.Hash, len(batch.Items))
	for index, item := range batch.Items {
		if item == nil || item.Tx == nil {
			return fmt.Errorf("tx outbox quorum promotion item %d is incomplete", index)
		}
		txHashes[index] = item.Tx.Hash()
	}
	expectation := txQUICAckExpectation{
		chainID: batch.ChainID, genesisHash: batch.GenesisHash,
		keyNumber: state.KeyNumber, committeeHash: state.CommitteeHash, batchID: batch.BatchID,
		sender: aggregate.Sender, senderEpoch: txQUICSenderEpoch(batch.ChainID, batch.GenesisHash, aggregate.Sender), nonce: aggregate.Nonce,
		admissionID: batch.Certificate.AdmissionID, certificateHash: certificateHash,
		itemIDs: itemIDs, txHashes: txHashes,
	}
	if err := validateTxQUICAckOutcome(&aggregate, expectation); err != nil {
		return fmt.Errorf("invalid tx outbox item-wise quorum aggregate: %w", err)
	}
	if !txQUICBitmapEmpty(aggregate.RetryableBitmap) {
		return fmt.Errorf("tx outbox item-wise quorum aggregate is incomplete")
	}
	return nil
}

func sameTxOutboxPlacementGeneration(left, right txOutboxPlacementState) bool {
	if left.KeyNumber != right.KeyNumber || left.CommitteeHash != right.CommitteeHash ||
		len(left.Endpoints) != len(right.Endpoints) || len(left.PublicKeys) != len(right.PublicKeys) {
		return false
	}
	for index := range left.Endpoints {
		if left.Endpoints[index] != right.Endpoints[index] || !bytes.Equal(left.PublicKeys[index], right.PublicKeys[index]) {
			return false
		}
	}
	return true
}

func (o *TxOutbox) readPlacementRecord(batchID common.Hash) (TxOutboxRecord, error) {
	key := txOutboxRecordKey(batchID)
	encoded, err := o.db.Get(key)
	if err != nil {
		return TxOutboxRecord{}, fmt.Errorf("read tx outbox placement record %s: %w", batchID, err)
	}
	var record TxOutboxRecord
	if err := rlp.DecodeBytes(encoded, &record); err != nil || record.BatchID != batchID || txOutboxBatchID(record.Payload) != batchID {
		return TxOutboxRecord{}, fmt.Errorf("invalid tx outbox placement record %s", batchID)
	}
	return record, nil
}

// writePlacementSync changes only the delivery stage of an existing record.
// The caller holds the record's lifecycle stripe, which preserves per-batch
// WAL->projection ordering while allowing unrelated batches to join WAL group
// commits and complete their projection I/O concurrently. The fixed
// reservation means even a completely full outbox can cross the quorum
// boundary without allocating unaccounted capacity; an ambiguous fsync
// poisons the live instance before it can delete or reinterpret original work.
func (o *TxOutbox) writePlacementSync(ctx context.Context, record TxOutboxRecord, state txOutboxPlacementState, clearRetry bool) error {
	key := txOutboxRecordKey(record.BatchID)
	baseRecord := record
	baseRecord.Placement = txOutboxPlacementState{}
	baseEncoded, err := rlp.EncodeToBytes(&baseRecord)
	if err != nil {
		return err
	}
	record.Placement = cloneTxOutboxPlacementState(state)
	updated, err := rlp.EncodeToBytes(&record)
	if err != nil {
		return err
	}
	if len(updated) < len(baseEncoded) || int64(len(updated)-len(baseEncoded)) > txOutboxPlacementReserveBytes {
		return fmt.Errorf("tx outbox placement metadata exceeds its reserved capacity")
	}
	if int64(len(key)+len(updated)) > o.commitMaxBytes {
		return fmt.Errorf("tx outbox placement checkpoint exceeds commit byte limit")
	}
	if o.wal != nil {
		var retry txOutboxRetryState
		if !clearRetry {
			retry, err = o.readRetry(record.BatchID)
			if err != nil {
				return err
			}
		}
		if err := o.wal.appendOutbox(ctx, txIngressWALOutboxState, record, retry); err != nil {
			return fmt.Errorf("persist tx outbox placement in unified ingress WAL: %w", err)
		}
	}
	write := o.db.NewBatch()
	if err := write.Put(key, updated); err != nil {
		return err
	}
	if clearRetry {
		if err := write.Delete(txOutboxRetryKey(record.BatchID)); err != nil {
			return err
		}
	}
	syncBatch, ok := write.(ethdb.SyncBatch)
	if !ok {
		return fmt.Errorf("tx outbox database does not support synchronous batches")
	}
	if err := syncBatch.WriteSync(); err != nil {
		return o.poisonBackgroundIO(fmt.Errorf("ambiguous committee placement fsync failure: %w", err))
	}
	return o.backgroundIOComplete()
}

// promotePlacementSync is the sole false-to-true transition for the persisted
// QuorumEstablished marker. Its aggregate argument is produced only after the
// authenticated receipt accumulator proves a terminal item-wise quorum.
func (o *TxOutbox) promotePlacementSync(batchID common.Hash, state txOutboxPlacementState, aggregate txQUICAck) error {
	if o == nil || o.db == nil || batchID == (common.Hash{}) {
		return fmt.Errorf("tx outbox database is unavailable for committee placement")
	}
	unlockLifecycle := o.lockLifecycle(batchID)
	defer unlockLifecycle()
	ctx, err := o.backgroundIOContext()
	if err != nil {
		return err
	}
	record, err := o.readPlacementRecord(batchID)
	if err != nil {
		return err
	}
	if err := validateTxOutboxQuorumPromotion(&record, state, aggregate); err != nil {
		return err
	}
	promoted := cloneTxOutboxPlacementState(state)
	promoted.QuorumEstablished = true
	return o.writePlacementSync(ctx, record, promoted, true)
}

// checkpointPlacementSync advances only a previously trusted placement stage.
// It cannot create the quorum marker, change generations, or clear a completed
// endpoint bit, so decoded disk or network values cannot bypass promotion.
func (o *TxOutbox) checkpointPlacementSync(batchID common.Hash, state txOutboxPlacementState, clearRetry bool) error {
	if o == nil || o.db == nil || batchID == (common.Hash{}) {
		return fmt.Errorf("tx outbox database is unavailable for committee placement")
	}
	if err := validatePersistedTxOutboxPlacementState(state); err != nil {
		return err
	}
	unlockLifecycle := o.lockLifecycle(batchID)
	defer unlockLifecycle()
	ctx, err := o.backgroundIOContext()
	if err != nil {
		return err
	}
	record, err := o.readPlacementRecord(batchID)
	if err != nil {
		return err
	}
	if err := validatePersistedTxOutboxPlacementState(record.Placement); err != nil {
		return fmt.Errorf("invalid existing tx outbox placement state: %w", err)
	}
	if !sameTxOutboxPlacementGeneration(record.Placement, state) {
		return fmt.Errorf("tx outbox placement generation changed during checkpoint")
	}
	for index := range state.Endpoints {
		if txQUICBitmapHas(record.Placement.CompletedBitmap, index) && !txQUICBitmapHas(state.CompletedBitmap, index) {
			return fmt.Errorf("tx outbox placement checkpoint cleared completed endpoint %d", index)
		}
	}
	return o.writePlacementSync(ctx, record, state, clearRetry)
}

func (o *TxOutbox) Start(parent context.Context, deliver func(context.Context, []byte) error, restore func([]byte) error) error {
	if o == nil || o.db == nil {
		return errors.New("tx outbox database is unavailable")
	}
	if deliver == nil {
		return errors.New("tx outbox delivery callback is unavailable")
	}
	if err := validateTxQUICRuntimeLimits(o.config); err != nil {
		return err
	}
	if err := ensureTxQUICDatabaseIdentity(o.db, txOutboxIdentityKey, txQUICDatabaseIdentity{ChainID: o.config.ChainID, GenesisHash: o.config.GenesisHash}); err != nil {
		return err
	}
	o.mu.Lock()
	if o.started {
		o.mu.Unlock()
		return errors.New("tx outbox already started")
	}
	if o.stopped {
		o.mu.Unlock()
		return errors.New("tx outbox is stopped")
	}
	if parent == nil {
		parent = context.Background()
	}
	o.ctx, o.cancel = context.WithCancel(parent)
	o.deliver = deliver
	o.restore = restore
	o.schedule = nil
	o.scheduled = make(map[common.Hash]uint64)
	o.mu.Unlock()
	o.admissionMu.Lock()
	o.storeAdmissionClosed = false
	o.commitAdmissionClosed = false
	o.activeStores = 0
	o.activeStoresDone = nil
	o.commitProducers = 0
	o.commitProducersDone = nil
	o.admissionMu.Unlock()

	records, totalBytes, err := o.scanRecords(restore)
	if err != nil {
		o.cancel()
		return err
	}
	o.mu.Lock()
	o.records = records
	o.bytes = totalBytes
	o.started = true
	o.mu.Unlock()
	o.updateGauges()
	if records > 0 {
		txOutboxReplayMeter.Mark(int64(records))
	}

	o.wg.Add(1)
	go o.commitLoop()
	for i := 0; i < o.workers; i++ {
		o.wg.Add(1)
		go o.worker()
	}
	o.wg.Add(1)
	go o.scheduler()
	o.signal(o.notify)
	log.Info("Started durable TxQUIC outbox", "records", records, "bytes", totalBytes, "workers", o.workers)
	return nil
}

func (o *TxOutbox) beginStore() error {
	o.admissionMu.Lock()
	if o.storeAdmissionClosed {
		o.admissionMu.Unlock()
		return errors.New("tx outbox is not running")
	}
	o.activeStores++
	o.admissionMu.Unlock()
	o.mu.Lock()
	if o.poison != nil {
		err := fmt.Errorf("tx outbox is poisoned until restart: %w", o.poison)
		o.mu.Unlock()
		o.endStore()
		return err
	}
	if !o.started || o.stopped || o.ctx == nil || o.ctx.Err() != nil {
		o.mu.Unlock()
		o.endStore()
		return errors.New("tx outbox is not running")
	}
	o.mu.Unlock()
	return nil
}

func (o *TxOutbox) endStore() {
	o.admissionMu.Lock()
	defer o.admissionMu.Unlock()
	if o.activeStores < 1 {
		return
	}
	o.activeStores--
	if o.storeAdmissionClosed && o.activeStores == 0 && o.activeStoresDone != nil {
		close(o.activeStoresDone)
		o.activeStoresDone = nil
	}
}

func (o *TxOutbox) beginCommitProducer() (<-chan struct{}, error) {
	o.admissionMu.Lock()
	if o.commitAdmissionClosed {
		o.admissionMu.Unlock()
		return nil, errors.New("tx outbox is not running")
	}
	o.commitProducers++
	o.admissionMu.Unlock()
	o.mu.Lock()
	if o.poison != nil {
		err := fmt.Errorf("tx outbox is poisoned until restart: %w", o.poison)
		o.mu.Unlock()
		o.endCommitProducer()
		return nil, err
	}
	if !o.started || o.stopped || o.ctx == nil || o.ctx.Err() != nil {
		o.mu.Unlock()
		o.endCommitProducer()
		return nil, errors.New("tx outbox is not running")
	}
	storeDone := o.ctx.Done()
	o.mu.Unlock()
	return storeDone, nil
}

func (o *TxOutbox) endCommitProducer() {
	o.admissionMu.Lock()
	defer o.admissionMu.Unlock()
	if o.commitProducers < 1 {
		return
	}
	o.commitProducers--
	if o.commitAdmissionClosed && o.commitProducers == 0 && o.commitProducersDone != nil {
		close(o.commitProducersDone)
		o.commitProducersDone = nil
	}
}

// closeAdmissionsLocked prevents a producer from being created after the
// commit loop's final drain. Callers waiting on the returned channels observe
// all producers/stores that crossed admission before it closed.
func (o *TxOutbox) closeAdmissionsLocked() (<-chan struct{}, <-chan struct{}) {
	o.storeAdmissionClosed = true
	if o.activeStores > 0 && o.activeStoresDone == nil {
		o.activeStoresDone = make(chan struct{})
	}
	o.commitAdmissionClosed = true
	if o.commitProducers > 0 && o.commitProducersDone == nil {
		o.commitProducersDone = make(chan struct{})
	}
	return o.commitProducersDone, o.activeStoresDone
}

func (o *TxOutbox) closeCommitAdmissionAndWait() {
	o.admissionMu.Lock()
	producersDone, _ := o.closeAdmissionsLocked()
	o.admissionMu.Unlock()
	if producersDone != nil {
		<-producersDone
	}
}

func (o *TxOutbox) Stop() {
	if o == nil {
		return
	}
	o.admissionMu.Lock()
	if o.stopStarted {
		stopDone := o.stopDone
		o.admissionMu.Unlock()
		if stopDone != nil {
			<-stopDone
		}
		return
	}
	o.stopStarted = true
	_, activeStoresDone := o.closeAdmissionsLocked()
	stopDone := o.stopDone
	o.admissionMu.Unlock()
	o.mu.Lock()
	o.stopped = true
	cancel := o.cancel
	o.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	o.wg.Wait()
	if activeStoresDone != nil {
		<-activeStoresDone
	}
	// A canceled caller may have handed lifecycle ownership to the commit
	// result waiter. Store admission is closed and drained above, so no Add can
	// race this final wait.
	o.lifecycleWG.Wait()
	if stopDone != nil {
		close(stopDone)
	}
	log.Info("Stopped durable TxQUIC outbox")
}

// StoreSync persists a semantic batch before RPC success. Delivery attempts
// allocate a fresh durable nonce and sign an envelope around this batch. Exact
// batches are idempotent; collisions and corrupt records are never overwritten.
func (o *TxOutbox) StoreSync(ctx context.Context, payload []byte) (common.Hash, error) {
	return o.storeSync(ctx, payload, false, false, nil)
}

// storeVerifiedSync is restricted to the local bridge worker. Every admission
// in its payload was either returned directly by core's signing boundary or
// verified by EnqueueLocalTxsWithAdmissions before it entered the queue. Disk
// restore separately repeats full signature validation before replay.
func (o *TxOutbox) storeVerifiedSync(ctx context.Context, payload []byte) (common.Hash, error) {
	return o.storeSync(ctx, payload, true, false, nil)
}

// storeWALOwnedVerifiedSync materializes a local-RPC outcome already owned by
// a fsynced local-intent/outcome pair. It must not duplicate transaction bytes
// in another WAL enqueue record.
func (o *TxOutbox) storeWALOwnedVerifiedSync(ctx context.Context, payload []byte) (common.Hash, error) {
	return o.storeSync(ctx, payload, true, true, nil)
}

// storeLocalOutcomeVerifiedSync makes capacity admission part of the local-RPC
// durability transaction. The callback appends the authoritative local outcome
// only after an outbox slot has been reserved and while the semantic lifecycle
// stripe remains held. A crash can therefore never leave more replayable local
// outcomes than the projection can materialize.
func (o *TxOutbox) storeLocalOutcomeVerifiedSync(ctx context.Context, payload []byte, appendOutcome func(context.Context) error) (common.Hash, error) {
	if appendOutcome == nil {
		return common.Hash{}, errors.New("missing local ingress outcome callback")
	}
	return o.storeSync(ctx, payload, true, true, appendOutcome)
}

func (o *TxOutbox) storeSync(ctx context.Context, payload []byte, signaturesVerified bool, walAlreadyOwned bool, beforeProjection func(context.Context) error) (common.Hash, error) {
	if o == nil || o.db == nil {
		return common.Hash{}, errors.New("tx outbox database is unavailable")
	}
	if walAlreadyOwned && o.wal == nil {
		return common.Hash{}, errors.New("tx outbox has no unified WAL ownership")
	}
	if len(payload) == 0 {
		return common.Hash{}, errors.New("empty tx outbox payload")
	}
	semanticBatch, _, err := decodeTxQUICBatch(payload)
	if err != nil {
		return common.Hash{}, fmt.Errorf("invalid tx outbox payload: %w", err)
	}
	if semanticBatch.ChainID != o.config.ChainID || semanticBatch.GenesisHash != o.config.GenesisHash {
		return common.Hash{}, fmt.Errorf("tx outbox batch belongs to another chain")
	}
	if int64(len(payload)) > txQUICMicroBatchMaxStoredBytes {
		return common.Hash{}, fmt.Errorf("tx outbox batch exceeds stored micro-batch limit: size=%d limit=%d", len(payload), txQUICMicroBatchMaxStoredBytes)
	}
	if _, err := packetItemsToTxs(&txQUICPacket{Certificate: semanticBatch.Certificate, Items: semanticBatch.Items}); err != nil {
		return common.Hash{}, fmt.Errorf("invalid tx outbox batch contents: %w", err)
	}
	if err := validateTxQUICCertificateStructure(semanticBatch.Certificate, semanticBatch.ChainID, semanticBatch.GenesisHash); err != nil {
		return common.Hash{}, fmt.Errorf("invalid tx outbox admission: %w", err)
	}
	if !signaturesVerified {
		if err := types.VerifyCommonTxAdmissionSignature(semanticBatch.Certificate); err != nil {
			return common.Hash{}, fmt.Errorf("invalid tx outbox admission: %w", err)
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := o.beginStore(); err != nil {
		return common.Hash{}, err
	}
	defer o.endStore()
	batchID := semanticBatch.BatchID
	var unlockLifecycle func()
	lifecycleOwned := false
	defer func() {
		if lifecycleOwned && unlockLifecycle != nil {
			unlockLifecycle()
		}
	}()
	createdAt := txOutboxStableCreatedAt(semanticBatch.Certificate)
	record := &TxOutboxRecord{
		BatchID:   batchID,
		Payload:   append([]byte(nil), payload...),
		CreatedAt: createdAt,
	}
	encoded, err := rlp.EncodeToBytes(record)
	if err != nil {
		return common.Hash{}, err
	}
	key := txOutboxRecordKey(batchID)
	commitBytes := int64(len(key) + len(encoded))
	if commitBytes > o.commitMaxBytes {
		return common.Hash{}, fmt.Errorf("tx outbox commit request exceeds byte limit: bytes=%d limit=%d", commitBytes, o.commitMaxBytes)
	}
	capacityBytes, err := txOutboxRecordCapacityBytes(payload)
	if err != nil {
		return common.Hash{}, err
	}
	if o.maxRecords < 1 || capacityBytes > o.maxBytes {
		return common.Hash{}, fmt.Errorf("tx outbox capacity exceeded: records=0+1/%d bytes=0+%d/%d", o.maxRecords, capacityBytes, o.maxBytes)
	}
	// The authoritative record lookup and the non-blocking reservation attempt
	// are serialized by the lifecycle stripe. If capacity is full, release the
	// stripe before waiting so an ACK/delete on that stripe can free the slot;
	// after every wake the DB and capacity state are revalidated from scratch.
	for {
		unlockLifecycle = o.lockLifecycle(batchID)
		lifecycleOwned = true
		o.mu.Lock()
		if o.poison != nil {
			err := o.poison
			o.mu.Unlock()
			return common.Hash{}, fmt.Errorf("tx outbox is poisoned until restart: %w", err)
		}
		if !o.started || o.stopped || o.ctx == nil || o.ctx.Err() != nil {
			o.mu.Unlock()
			return common.Hash{}, errors.New("tx outbox is not running")
		}
		hasRecord, err := o.db.Has(key)
		if err != nil {
			o.mu.Unlock()
			return common.Hash{}, err
		}
		if hasRecord {
			existing, err := o.db.Get(key)
			if err != nil {
				o.mu.Unlock()
				return common.Hash{}, err
			}
			var stored TxOutboxRecord
			if err := rlp.DecodeBytes(existing, &stored); err != nil || stored.BatchID != batchID || !bytes.Equal(stored.Payload, payload) {
				o.mu.Unlock()
				return common.Hash{}, fmt.Errorf("tx outbox batch identity collision for %s", batchID)
			}
			if _, err := o.readRetry(batchID); err != nil {
				o.mu.Unlock()
				return common.Hash{}, fmt.Errorf("read existing tx outbox retry state %s: %w", batchID, err)
			}
			durableCtx := o.ctx
			o.mu.Unlock()
			// An already materialized exact batch consumes no new capacity, but a
			// new local intent still needs its own durable completion record.
			if beforeProjection != nil {
				if err := beforeProjection(durableCtx); err != nil {
					return common.Hash{}, err
				}
			}
			return batchID, nil
		}
		if _, exists := o.reservations[batchID]; exists {
			o.mu.Unlock()
			return common.Hash{}, fmt.Errorf("tx outbox capacity is already reserved for %s", batchID)
		}
		usedRecords := o.records + o.reservedRecords
		usedBytes := o.bytes + o.reservedBytes
		if _, _, err := advanceTxQUICDurableCapacity("tx outbox", usedRecords, usedBytes, 1, capacityBytes, o.maxRecords, o.maxBytes); err == nil {
			o.reservations[batchID] = capacityBytes
			o.reservedRecords++
			o.reservedBytes += capacityBytes
			o.mu.Unlock()
			break
		}
		space := o.space
		storeDone := o.ctx.Done()
		o.mu.Unlock()
		unlockLifecycle()
		unlockLifecycle = nil
		lifecycleOwned = false
		select {
		case <-space:
			continue
		case <-ctx.Done():
			return common.Hash{}, fmt.Errorf("tx outbox capacity wait: %w", ctx.Err())
		case <-storeDone:
			return common.Hash{}, errors.New("tx outbox stopped while waiting for capacity")
		}
	}
	reservationOwned := true
	defer func() {
		if reservationOwned {
			_ = o.releaseRecordReservation(batchID, capacityBytes)
		}
	}()
	durableOwnership := walAlreadyOwned
	if beforeProjection != nil {
		// Capacity ownership and lifecycle serialization are established before
		// the local outcome becomes replay authority. Detach this append from
		// the caller deadline for the same reason as an ordinary outbox enqueue.
		if err := beforeProjection(o.ctx); err != nil {
			return common.Hash{}, err
		}
		durableOwnership = true
	}
	if o.wal != nil && !walAlreadyOwned {
		// Capacity is admitted before WAL ownership. Once reserved, detach the
		// durability operation from the request deadline so a timed-out caller
		// cannot leave an unmaterializable enqueue in the authoritative log.
		if err := o.wal.appendOutbox(o.ctx, txIngressWALOutboxEnqueued, *record, txOutboxRetryState{}); err != nil {
			return common.Hash{}, fmt.Errorf("persist tx outbox enqueue in unified ingress WAL: %w", err)
		}
		durableOwnership = true
	}
	request := &txOutboxCommitRequest{
		batchID:       batchID,
		payload:       record.Payload,
		encoded:       encoded,
		bytes:         commitBytes,
		reservedBytes: capacityBytes,
		walOwned:      durableOwnership,
	}
	for {
		storeDone, err := o.beginCommitProducer()
		if err != nil {
			return common.Hash{}, err
		}
		request.result = make(chan txOutboxCommitResult, 1)
		request.queued = time.Now()
		enqueued := false
		select {
		case o.commitCh <- request:
			enqueued = true
		case <-storeDone:
		}
		o.endCommitProducer()
		if !enqueued {
			return common.Hash{}, errors.New("tx outbox stopped before durable commit")
		}
		reservationOwned = false // commitRequests now owns the reservation
		var result txOutboxCommitResult
		select {
		case result = <-request.result:
		case <-ctx.Done():
			// Once queued, persistence is detached from the request context. The
			// lifecycle stripe must follow that ownership too; otherwise an ACK
			// delete could overtake the background projection commit and invert
			// WAL order versus mutable-DB order.
			resultCh := request.result
			o.lifecycleWG.Add(1)
			lifecycleOwned = false
			go func() {
				defer o.lifecycleWG.Done()
				<-resultCh
				unlockLifecycle()
			}()
			return common.Hash{}, ctx.Err()
		case <-storeDone:
			resultCh := request.result
			o.lifecycleWG.Add(1)
			lifecycleOwned = false
			go func() {
				defer o.lifecycleWG.Done()
				<-resultCh
				unlockLifecycle()
			}()
			return common.Hash{}, errors.New("tx outbox stopped during durable commit")
		}
		if result.err != nil {
			return common.Hash{}, result.err
		}
		if result.waitForSpace == nil {
			return batchID, nil
		}
		select {
		case <-result.waitForSpace:
		case <-ctx.Done():
			return common.Hash{}, fmt.Errorf("tx outbox capacity wait: %w", ctx.Err())
		case <-storeDone:
			return common.Hash{}, errors.New("tx outbox stopped while waiting for capacity")
		}
	}
}

func (o *TxOutbox) commitLoop() {
	defer o.wg.Done()
	stopErr := errors.New("tx outbox stopped before durable commit")
	var carry *txOutboxCommitRequest
	for {
		first := carry
		carry = nil
		if first != nil {
			select {
			case <-o.ctx.Done():
				o.closeCommitAdmissionAndWait()
				o.failCommitRequests([]*txOutboxCommitRequest{first}, stopErr, false)
				o.failQueuedCommits(stopErr)
				return
			default:
			}
		}
		if first == nil {
			select {
			case <-o.ctx.Done():
				o.closeCommitAdmissionAndWait()
				o.failQueuedCommits(stopErr)
				return
			case first = <-o.commitCh:
				if first == nil {
					continue
				}
			}
		}
		if first.bytes <= 0 || first.bytes > o.commitMaxBytes {
			o.failCommitRequests([]*txOutboxCommitRequest{first}, fmt.Errorf("tx outbox commit request has invalid byte size %d", first.bytes), true)
			continue
		}
		group := []*txOutboxCommitRequest{first}
		bytesUsed := first.bytes
		timer := time.NewTimer(o.commitInterval)
		stopping := false
	collect:
		for len(group) < o.commitMaxRequests {
			select {
			case request := <-o.commitCh:
				if request == nil {
					continue
				}
				if request.bytes <= 0 || request.bytes > o.commitMaxBytes {
					o.failCommitRequests([]*txOutboxCommitRequest{request}, fmt.Errorf("tx outbox commit request has invalid byte size %d", request.bytes), true)
					continue
				}
				if bytesUsed > o.commitMaxBytes-request.bytes {
					carry = request
					break collect
				}
				group = append(group, request)
				bytesUsed += request.bytes
			case <-timer.C:
				break collect
			case <-o.ctx.Done():
				stopping = true
				break collect
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		if !stopping {
			select {
			case <-o.ctx.Done():
				stopping = true
			default:
			}
		}
		if stopping {
			o.closeCommitAdmissionAndWait()
			o.failCommitRequests(group, stopErr, false)
			if carry != nil {
				o.failCommitRequests([]*txOutboxCommitRequest{carry}, stopErr, false)
				carry = nil
			}
			o.failQueuedCommits(stopErr)
			return
		}
		o.commitRequests(group)
	}
}

func (o *TxOutbox) failQueuedCommits(err error) {
	requests := make([]*txOutboxCommitRequest, 0, len(o.commitCh))
	for {
		select {
		case request := <-o.commitCh:
			if request != nil {
				requests = append(requests, request)
			}
		default:
			o.failCommitRequests(requests, err, false)
			return
		}
	}
}

// failCommitRequests resolves reservation ownership exactly once. Projection
// failures after WAL ownership are fail-closed: their logical capacity remains
// charged until restart replay rebuilds the authoritative set. Shutdown closes
// producer/store admission first, so its abandoned live reservations are safe
// to refund while the WAL remains the restart authority.
func (o *TxOutbox) failCommitRequests(requests []*txOutboxCommitRequest, failure error, retainWALOwned bool) {
	if len(requests) == 0 {
		return
	}
	o.mu.Lock()
	resultErr := failure
	if retainWALOwned {
		for _, request := range requests {
			if request != nil && request.walOwned {
				if o.poison == nil {
					o.poison = fmt.Errorf("tx outbox projection failed after durable WAL ownership: %w", failure)
				}
				resultErr = o.poison
				break
			}
		}
	}
	for _, request := range requests {
		if request == nil || request.reservedBytes <= 0 || (retainWALOwned && request.walOwned) {
			continue
		}
		if err := o.releaseRecordReservationLocked(request.batchID, request.reservedBytes, true); err != nil && o.poison == nil {
			o.poison = err
			resultErr = err
		}
	}
	o.mu.Unlock()
	for _, request := range requests {
		if request != nil && request.result != nil {
			request.result <- txOutboxCommitResult{err: resultErr}
		}
	}
}

func (o *TxOutbox) commitRequests(requests []*txOutboxCommitRequest) {
	if len(requests) == 0 {
		return
	}
	started := time.Now()
	defer txOutboxCommitTotal.UpdateSince(started)
	txOutboxCommitGroups.Mark(1)
	txOutboxCommitEntries.Mark(int64(len(requests)))
	for _, request := range requests {
		if request != nil && !request.queued.IsZero() {
			txOutboxCommitQueue.Update(started.Sub(request.queued))
		}
	}
	results := make([]txOutboxCommitResult, len(requests))
	newRecords := make([]*txOutboxCommitRequest, 0, len(requests))
	newRecordSet := make(map[*txOutboxCommitRequest]struct{}, len(requests))
	staged := make(map[common.Hash]*txOutboxCommitRequest)

	o.mu.Lock()
	if o.poison != nil || !o.started || o.stopped {
		var err error
		retainWALOwned := false
		if o.poison != nil {
			err = fmt.Errorf("tx outbox is poisoned until restart: %w", o.poison)
			retainWALOwned = true
		} else {
			err = errors.New("tx outbox is not running")
		}
		o.mu.Unlock()
		o.failCommitRequests(requests, err, retainWALOwned)
		return
	}
	batch := o.db.NewBatch()
	projectedRecords, projectedBytes := o.records, o.bytes
	var fatalErr error
	for index, request := range requests {
		if request == nil || request.batchID == (common.Hash{}) || len(request.payload) == 0 || len(request.encoded) == 0 {
			fatalErr = errors.New("invalid tx outbox commit request")
			break
		}
		if request.reservedBytes > 0 && o.reservations[request.batchID] != request.reservedBytes {
			fatalErr = fmt.Errorf("tx outbox commit reservation mismatch for %s", request.batchID)
			break
		}
		if pending := staged[request.batchID]; pending != nil {
			if !bytes.Equal(pending.payload, request.payload) {
				err := fmt.Errorf("tx outbox batch identity collision for %s", request.batchID)
				if request.walOwned {
					fatalErr = err
					break
				}
				results[index].err = err
			}
			continue
		}
		key := txOutboxRecordKey(request.batchID)
		has, err := o.db.Has(key)
		if err != nil {
			fatalErr = fmt.Errorf("check tx outbox batch %s: %w", request.batchID, err)
			break
		}
		if has {
			existing, err := o.db.Get(key)
			if err != nil {
				fatalErr = fmt.Errorf("read tx outbox batch %s: %w", request.batchID, err)
				break
			}
			var stored TxOutboxRecord
			if err := rlp.DecodeBytes(existing, &stored); err != nil {
				err = fmt.Errorf("decode existing tx outbox batch %s: %w", request.batchID, err)
				if request.walOwned {
					fatalErr = err
					break
				}
				results[index].err = err
				continue
			}
			if stored.BatchID != request.batchID || !bytes.Equal(stored.Payload, request.payload) {
				err := fmt.Errorf("tx outbox batch identity collision for %s", request.batchID)
				if request.walOwned {
					fatalErr = err
					break
				}
				results[index].err = err
				continue
			}
			if _, err := o.readRetry(request.batchID); err != nil {
				err = fmt.Errorf("read existing tx outbox retry state %s: %w", request.batchID, err)
				if request.walOwned {
					fatalErr = err
					break
				}
				results[index].err = err
			}
			continue
		}
		capacityBytes, err := txOutboxRecordCapacityBytes(request.payload)
		if err != nil {
			if request.walOwned {
				fatalErr = err
				break
			}
			results[index].err = err
			continue
		}
		var nextRecords int
		var nextBytes int64
		if request.reservedBytes > 0 {
			nextRecords, nextBytes = projectedRecords+1, projectedBytes+request.reservedBytes
			if request.reservedBytes != capacityBytes || nextRecords > o.maxRecords || nextBytes > o.maxBytes {
				fatalErr = fmt.Errorf("invalid reserved tx outbox capacity for %s", request.batchID)
				break
			}
		} else {
			nextRecords, nextBytes, err = advanceTxQUICDurableCapacity(
				"tx outbox", projectedRecords, projectedBytes, 1, capacityBytes, o.maxRecords, o.maxBytes,
			)
			if err != nil {
				results[index].waitForSpace = o.space
				continue
			}
		}
		if err := batch.Put(key, request.encoded); err != nil {
			fatalErr = err
			break
		}
		projectedRecords, projectedBytes = nextRecords, nextBytes
		staged[request.batchID] = request
		newRecords = append(newRecords, request)
		newRecordSet[request] = struct{}{}
	}
	if fatalErr != nil {
		o.mu.Unlock()
		o.failCommitRequests(requests, fatalErr, true)
		return
	}
	var (
		committedBytes int64
		fsyncElapsed   time.Duration
	)
	if len(newRecords) > 0 {
		syncBatch, ok := batch.(ethdb.SyncBatch)
		if !ok {
			err := errors.New("tx outbox database does not support synchronous batches")
			o.mu.Unlock()
			o.failCommitRequests(requests, err, true)
			return
		}
		fsyncStarted := time.Now()
		if err := syncBatch.WriteSync(); err != nil {
			fsyncElapsed = time.Since(fsyncStarted)
			txOutboxCommitFsync.Update(fsyncElapsed)
			failure := fmt.Errorf("ambiguous outbox group fsync failure: %w", err)
			o.poison = failure
			o.mu.Unlock()
			o.failCommitRequests(requests, failure, true)
			return
		}
		fsyncElapsed = time.Since(fsyncStarted)
		txOutboxCommitFsync.Update(fsyncElapsed)
		o.records, o.bytes = projectedRecords, projectedBytes
		for _, request := range newRecords {
			committedBytes += request.bytes
			o.scheduleRecordLocked(request.batchID, 0)
		}
		o.updateGaugesLocked()
	}
	for _, request := range requests {
		if request == nil || request.reservedBytes <= 0 {
			continue
		}
		_, materialized := newRecordSet[request]
		if err := o.releaseRecordReservationLocked(request.batchID, request.reservedBytes, !materialized); err != nil {
			o.poison = err
		}
	}
	o.mu.Unlock()

	if len(newRecords) > 0 {
		txOutboxCommitBytes.Mark(committedBytes)
		txOutboxStoredMeter.Mark(int64(len(newRecords)))
		o.signal(o.notify)
	}
	log.Debug("TxQUIC outbox group committed",
		"requests", len(requests), "stored", len(newRecords), "bytes", committedBytes,
		"fsync", fsyncElapsed, "total", time.Since(started))
	for index, request := range requests {
		request.result <- results[index]
	}
}

// NextNonce reserves nonce ranges synchronously before use. A crash may leave
// gaps, but a signed nonce is never reused after restart.
func (o *TxOutbox) NextNonce(sender common.Address, epoch common.Hash) (uint64, error) {
	if o == nil || o.db == nil || sender == (common.Address{}) || epoch == (common.Hash{}) {
		return 0, fmt.Errorf("invalid txquic nonce allocation context")
	}
	key := txOutboxNonceKey(sender, epoch)
	rangeKey := string(key)
	// A nonce stream has the same WAL->projection ordering requirement as a
	// batch lifecycle. Hashing its namespaced durable key onto the existing
	// stripes serializes one sender/epoch while independent streams remain able
	// to share WAL group commits.
	unlockLifecycle := o.lockLifecycle(cyphercrypto.Keccak256Hash(key))
	defer unlockLifecycle()
	o.mu.Lock()
	if o.poison != nil {
		err := o.poison
		o.mu.Unlock()
		return 0, fmt.Errorf("tx outbox is poisoned until restart: %w", err)
	}
	if !o.started || o.stopped {
		o.mu.Unlock()
		return 0, fmt.Errorf("tx outbox is not running")
	}
	if available := o.nonceRanges[rangeKey]; available != nil && available.next <= available.end {
		nonce := available.next
		available.next++
		o.mu.Unlock()
		return nonce, nil
	}
	durableCtx := o.ctx
	o.mu.Unlock()
	state := txOutboxNonceState{Sender: sender, Epoch: epoch}
	has, err := o.db.Has(key)
	if err != nil {
		return 0, err
	}
	if has {
		encoded, err := o.db.Get(key)
		if err != nil {
			return 0, err
		}
		if err := rlp.DecodeBytes(encoded, &state); err != nil || state.Sender != sender || state.Epoch != epoch {
			return 0, fmt.Errorf("invalid txquic outbox nonce state")
		}
	}
	reservation := o.config.NonceReservation
	if reservation == 0 || state.ReservedThrough > ^uint64(0)-reservation {
		return 0, fmt.Errorf("txquic sender nonce exhausted")
	}
	first := state.ReservedThrough + 1
	state.ReservedThrough += reservation
	encoded, err := rlp.EncodeToBytes(&state)
	if err != nil {
		return 0, err
	}
	if o.wal != nil {
		if err := o.wal.appendOutboxNonce(durableCtx, state); err != nil {
			return 0, fmt.Errorf("persist tx outbox nonce reservation in unified ingress WAL: %w", err)
		}
	}
	batch := o.db.NewBatch()
	if err := batch.Put(key, encoded); err != nil {
		return 0, err
	}
	syncBatch, ok := batch.(ethdb.SyncBatch)
	if !ok {
		return 0, fmt.Errorf("tx outbox database does not support synchronous batches")
	}
	if err := syncBatch.WriteSync(); err != nil {
		return 0, o.poisonBackgroundIO(fmt.Errorf("ambiguous nonce reservation fsync failure: %w", err))
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.poison != nil {
		return 0, fmt.Errorf("tx outbox is poisoned until restart: %w", o.poison)
	}
	if !o.started || o.stopped {
		// The durable reservation remains authoritative and intentionally creates
		// a gap. Restart recovers ReservedThrough before issuing another nonce.
		return 0, fmt.Errorf("tx outbox is not running")
	}
	o.nonceRanges[rangeKey] = &txOutboxNonceRange{next: first + 1, end: state.ReservedThrough}
	return first, nil
}

func advanceTxQUICDurableCapacity(scope string, records int, bytes int64, recordDelta int, byteDelta int64, maxRecords int, maxBytes int64) (int, int64, error) {
	if records < 0 || bytes < 0 || recordDelta < 0 || byteDelta < 0 || maxRecords < 0 || maxBytes < 0 ||
		records > maxRecords || recordDelta > maxRecords-records || bytes > maxBytes || byteDelta > maxBytes-bytes {
		return records, bytes, fmt.Errorf("%s capacity exceeded: records=%d+%d/%d bytes=%d+%d/%d",
			scope, records, recordDelta, maxRecords, bytes, byteDelta, maxBytes)
	}
	return records + recordDelta, bytes + byteDelta, nil
}

func txOutboxRecordCapacityBytes(payload []byte) (int64, error) {
	if len(payload) == 0 || int64(len(payload)) > int64(^uint64(0)>>1)-txOutboxPlacementReserveBytes {
		return 0, fmt.Errorf("invalid tx outbox record capacity")
	}
	return int64(len(payload)) + txOutboxPlacementReserveBytes, nil
}

func (o *TxOutbox) releaseRecordReservationLocked(batchID common.Hash, capacityBytes int64, signal bool) error {
	reserved, exists := o.reservations[batchID]
	if !exists || reserved != capacityBytes || o.reservedRecords < 1 || o.reservedBytes < capacityBytes {
		return fmt.Errorf("tx outbox reservation mismatch for %s", batchID)
	}
	delete(o.reservations, batchID)
	o.reservedRecords--
	o.reservedBytes -= capacityBytes
	if signal {
		close(o.space)
		o.space = make(chan struct{})
	}
	return nil
}

func (o *TxOutbox) releaseRecordReservation(batchID common.Hash, capacityBytes int64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.releaseRecordReservationLocked(batchID, capacityBytes, true)
}

func (o *TxOutbox) scanRecords(restore func([]byte) error) (int, int64, error) {
	iterator := o.db.NewIterator(txOutboxRecordPrefix, nil)
	defer iterator.Release()
	var (
		records    int
		totalBytes int64
	)
	for iterator.Next() {
		if records >= o.maxRecords {
			return 0, 0, fmt.Errorf("tx outbox capacity exceeded: records=%d/%d bytes=%d/%d", records+1, o.maxRecords, totalBytes, o.maxBytes)
		}
		select {
		case <-o.ctx.Done():
			return 0, 0, o.ctx.Err()
		default:
		}
		key := append([]byte(nil), iterator.Key()...)
		value := append([]byte(nil), iterator.Value()...)
		if len(key) != len(txOutboxRecordPrefix)+common.HashLength {
			return 0, 0, fmt.Errorf("invalid tx outbox record key length %d", len(key))
		}
		var record TxOutboxRecord
		if err := rlp.DecodeBytes(value, &record); err != nil {
			return 0, 0, fmt.Errorf("decode tx outbox record: %w", err)
		}
		keyID := common.BytesToHash(key[len(txOutboxRecordPrefix):])
		maxCreatedAt := uint64(time.Now().Add(o.config.MaxClockSkew).UnixNano())
		if record.BatchID != keyID || record.BatchID != txOutboxBatchID(record.Payload) || record.CreatedAt == 0 || record.CreatedAt > maxCreatedAt {
			return 0, 0, fmt.Errorf("invalid tx outbox record identity for %s", keyID)
		}
		if record.Placement.present() {
			if err := validatePersistedTxOutboxPlacementState(record.Placement); err != nil {
				return 0, 0, fmt.Errorf("invalid tx outbox placement state for %s: %w", keyID, err)
			}
		} else if len(record.Placement.Endpoints) != 0 || len(record.Placement.PublicKeys) != 0 ||
			len(record.Placement.CompletedBitmap) != 0 || record.Placement.NextEndpoint != 0 || record.Placement.KeyNumber != 0 ||
			record.Placement.QuorumEstablished {
			return 0, 0, fmt.Errorf("incomplete tx outbox placement state for %s", keyID)
		}
		if int64(len(record.Payload)) > txQUICMicroBatchMaxStoredBytes {
			return 0, 0, fmt.Errorf("tx outbox batch %s exceeds stored micro-batch limit", keyID)
		}
		capacityBytes, err := txOutboxRecordCapacityBytes(record.Payload)
		if err != nil {
			return 0, 0, err
		}
		nextRecords, nextBytes, err := advanceTxQUICDurableCapacity("tx outbox", records, totalBytes, 1, capacityBytes, o.maxRecords, o.maxBytes)
		if err != nil {
			return 0, 0, err
		}
		records, totalBytes = nextRecords, nextBytes
		batch, _, err := decodeTxQUICBatch(record.Payload)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid tx outbox payload for %s: %w", keyID, err)
		}
		if batch.ChainID != o.config.ChainID || batch.GenesisHash != o.config.GenesisHash {
			return 0, 0, fmt.Errorf("tx outbox batch %s belongs to another chain", keyID)
		}
		if _, err := packetItemsToTxs(&txQUICPacket{Certificate: batch.Certificate, Items: batch.Items}); err != nil {
			return 0, 0, fmt.Errorf("invalid tx outbox batch contents for %s: %w", keyID, err)
		}
		// The first pass validates bounded encoding, commitments, chain identity,
		// and admission shape for the entire database before any callback runs.
		// The second-pass restore callback performs the one full batch signature
		// verification at the disk trust boundary.
		if err := validateTxQUICCertificateStructure(batch.Certificate, batch.ChainID, batch.GenesisHash); err != nil {
			return 0, 0, fmt.Errorf("invalid tx outbox admission for %s: %w", keyID, err)
		}
		if _, err := o.readRetry(record.BatchID); err != nil {
			return 0, 0, fmt.Errorf("invalid tx outbox retry state for %s: %w", keyID, err)
		}
	}
	if err := iterator.Error(); err != nil {
		return 0, 0, err
	}
	retryIterator := o.db.NewIterator(txOutboxRetryPrefix, nil)
	defer retryIterator.Release()
	for retryIterator.Next() {
		key := append([]byte(nil), retryIterator.Key()...)
		if len(key) != len(txOutboxRetryPrefix)+common.HashLength {
			return 0, 0, fmt.Errorf("invalid tx outbox retry key")
		}
		batchID := common.BytesToHash(key[len(txOutboxRetryPrefix):])
		hasRecord, err := o.db.Has(txOutboxRecordKey(batchID))
		if err != nil {
			return 0, 0, err
		}
		if !hasRecord {
			return 0, 0, fmt.Errorf("orphan tx outbox retry state for %s", batchID)
		}
		if _, err := o.readRetry(batchID); err != nil {
			return 0, 0, fmt.Errorf("invalid tx outbox retry state for %s: %w", batchID, err)
		}
	}
	if err := retryIterator.Error(); err != nil {
		return 0, 0, err
	}
	nonceIterator := o.db.NewIterator(txOutboxNoncePrefix, nil)
	defer nonceIterator.Release()
	for nonceIterator.Next() {
		key, value := append([]byte(nil), nonceIterator.Key()...), append([]byte(nil), nonceIterator.Value()...)
		if len(key) != len(txOutboxNoncePrefix)+common.AddressLength+common.HashLength {
			return 0, 0, fmt.Errorf("invalid tx outbox nonce key")
		}
		offset := len(txOutboxNoncePrefix)
		sender := common.BytesToAddress(key[offset : offset+common.AddressLength])
		epoch := common.BytesToHash(key[offset+common.AddressLength:])
		var state txOutboxNonceState
		if err := rlp.DecodeBytes(value, &state); err != nil || sender == (common.Address{}) || state.Sender != sender || state.Epoch != epoch ||
			epoch != txQUICSenderEpoch(o.config.ChainID, o.config.GenesisHash, sender) || state.ReservedThrough == 0 {
			return 0, 0, fmt.Errorf("invalid tx outbox nonce state")
		}
	}
	if err := nonceIterator.Error(); err != nil {
		return 0, 0, err
	}
	if err := validateTxQUICDatabaseKeys(o.db, txOutboxIdentityKey,
		txOutboxRecordPrefix, txOutboxRetryPrefix, txOutboxNoncePrefix,
		txIngressWALIdentityKey, txIngressWALManifestKey, txIngressWALTailKey, txIngressWALRecordPrefix, txIngressWALEventPrefix, txIngressWALGenerationPrefix,
	); err != nil {
		return 0, 0, err
	}

	restoreIterator := o.db.NewIterator(txOutboxRecordPrefix, nil)
	defer restoreIterator.Release()
	for restoreIterator.Next() {
		key, value := append([]byte(nil), restoreIterator.Key()...), append([]byte(nil), restoreIterator.Value()...)
		var record TxOutboxRecord
		if err := rlp.DecodeBytes(value, &record); err != nil {
			return 0, 0, err
		}
		batchID := common.BytesToHash(key[len(txOutboxRecordPrefix):])
		if record.BatchID != batchID {
			return 0, 0, fmt.Errorf("tx outbox record changed during restore")
		}
		if restore != nil {
			if err := restore(record.Payload); err != nil {
				return 0, 0, fmt.Errorf("restore tx outbox batch %s: %w", record.BatchID, err)
			}
		}
		retry, err := o.readRetry(record.BatchID)
		if err != nil {
			return 0, 0, err
		}
		o.mu.Lock()
		o.scheduleRecordLocked(record.BatchID, retry.NextRetry)
		o.mu.Unlock()
	}
	if err := restoreIterator.Error(); err != nil {
		return 0, 0, err
	}
	return records, totalBytes, nil
}

func (o *TxOutbox) scheduler() {
	defer o.wg.Done()
	ticker := time.NewTicker(o.retryMin)
	defer ticker.Stop()
	for {
		o.dispatchDue()
		select {
		case <-o.ctx.Done():
			return
		case result := <-o.results:
			o.finishDelivery(result)
		case <-o.notify:
		case <-ticker.C:
		}
	}
}

func (o *TxOutbox) dispatchDue() {
	now := uint64(time.Now().UnixNano())
	for {
		batchID, ok := o.popDue(now)
		if !ok {
			return
		}
		encoded, err := o.db.Get(txOutboxRecordKey(batchID))
		if err != nil {
			o.releaseAndReschedule(batchID, time.Now().Add(o.retryMin))
			log.Error("Failed to read scheduled TxQUIC outbox record", "batch", batchID, "err", err)
			continue
		}
		var record TxOutboxRecord
		decodeErr := rlp.DecodeBytes(encoded, &record)
		placementErr := error(nil)
		if decodeErr == nil && record.Placement.present() {
			placementErr = validatePersistedTxOutboxPlacementState(record.Placement)
		}
		if decodeErr != nil || placementErr != nil || record.BatchID != batchID || record.BatchID != txOutboxBatchID(record.Payload) {
			o.releaseAndReschedule(batchID, time.Now().Add(o.retryMax))
			log.Error("Corrupt TxQUIC outbox record encountered after startup", "batch", batchID, "decodeErr", decodeErr, "placementErr", placementErr)
			continue
		}
		record.Payload = append([]byte(nil), record.Payload...)
		select {
		case o.jobs <- &record:
		case <-o.ctx.Done():
			o.releaseInFlight(record.BatchID)
			return
		}
	}
}

func (o *TxOutbox) worker() {
	defer o.wg.Done()
	for {
		select {
		case <-o.ctx.Done():
			return
		case record := <-o.jobs:
			if record == nil {
				continue
			}
			err := o.deliver(o.ctx, record.Payload)
			select {
			case o.results <- txOutboxDeliveryResult{record: record, err: err}:
			case <-o.ctx.Done():
				return
			}
		}
	}
}

func (o *TxOutbox) finishDelivery(result txOutboxDeliveryResult) {
	if result.record == nil {
		return
	}
	batchID := result.record.BatchID
	o.mu.Lock()
	if o.poison != nil {
		poison := o.poison
		delete(o.inFlight, batchID)
		o.mu.Unlock()
		log.Error("TxQUIC outbox is poisoned; retaining in-flight batch for restart recovery", "batch", batchID, "err", poison)
		return
	}
	o.mu.Unlock()
	if result.err == nil {
		if err := o.deleteRecord(result.record); err != nil {
			log.Error("Failed to delete acknowledged TxQUIC outbox batch", "batch", result.record.BatchID, "err", err)
			o.releaseAndReschedule(batchID, time.Now().Add(o.retryMin))
			return
		}
		o.releaseInFlight(batchID)
		return
	}
	var placementPending *txOutboxPlacementPendingError
	if errors.As(result.err, &placementPending) && placementPending != nil {
		o.releaseInFlight(batchID)
		if !placementPending.Retry {
			o.scheduleRecord(batchID, 0)
			return
		}
		retry, err := o.updateRetry(batchID, result.err)
		if err != nil {
			log.Error("Failed to update TxQUIC tail-placement retry state", "batch", batchID, "err", err)
			o.scheduleRecord(batchID, uint64(time.Now().Add(o.retryMin).UnixNano()))
			return
		}
		txOutboxRetryMeter.Mark(1)
		o.scheduleRecord(batchID, retry.NextRetry)
		return
	}
	var rejected *txQUICRemoteRejectError
	if errors.As(result.err, &rejected) && rejected != nil && rejected.ack != nil {
		residual, oldDeleted, compactErr := o.compactAcknowledgedRecord(result.record, rejected.ack)
		o.releaseInFlight(batchID)
		if compactErr != nil {
			log.Error("Failed to compact partially acknowledged TxQUIC outbox batch", "batch", batchID, "err", compactErr)
			if residual != nil {
				retry, retryErr := o.updateRetry(residual.BatchID, result.err)
				if retryErr == nil {
					o.scheduleRecord(residual.BatchID, retry.NextRetry)
				}
			}
			if !oldDeleted {
				o.scheduleRecord(batchID, uint64(time.Now().Add(o.retryMin).UnixNano()))
			}
			return
		}
		if residual == nil {
			if len(rejected.rejects) > 0 {
				log.Error("TxQUIC outbox dropped permanently rejected items after authenticated receipt", "batch", batchID, "items", len(rejected.rejects))
			}
			return
		}
		retry, err := o.updateRetry(residual.BatchID, result.err)
		if err != nil {
			log.Error("Failed to update compacted TxQUIC outbox retry state", "batch", residual.BatchID, "err", err)
			o.scheduleRecord(residual.BatchID, uint64(time.Now().Add(o.retryMin).UnixNano()))
			return
		}
		txOutboxRetryMeter.Mark(1)
		o.scheduleRecord(residual.BatchID, retry.NextRetry)
		return
	}
	retry, err := o.updateRetry(result.record.BatchID, result.err)
	if err != nil {
		log.Error("Failed to update TxQUIC outbox retry state", "batch", result.record.BatchID, "err", err)
		o.releaseAndReschedule(batchID, time.Now().Add(o.retryMin))
		return
	}
	o.releaseInFlight(batchID)
	txOutboxRetryMeter.Mark(1)
	o.scheduleRecord(batchID, retry.NextRetry)
}

// compactAcknowledgedRecord removes durable and permanent outcomes from the
// sender payload. A residual record replaces the superseded record and its
// retry metadata in one synchronous batch, so restart observes exactly one
// side of the replacement.
func (o *TxOutbox) compactAcknowledgedRecord(record *TxOutboxRecord, ack *txQUICAck) (*TxOutboxRecord, bool, error) {
	batch, itemIDs, err := decodeTxQUICBatch(record.Payload)
	if err != nil {
		return nil, false, err
	}
	if ack == nil {
		return nil, false, fmt.Errorf("partial ACK does not match outbox batch")
	}
	if ack.Sender == (common.Address{}) || ack.Nonce == 0 || ack.SenderEpoch != txQUICSenderEpoch(batch.ChainID, batch.GenesisHash, ack.Sender) {
		return nil, false, fmt.Errorf("partial ACK has an invalid sender envelope")
	}
	expectation := txQUICAckExpectation{
		chainID: batch.ChainID, genesisHash: batch.GenesisHash, batchID: batch.BatchID,
		keyNumber: ack.KeyNumber, committeeHash: ack.CommitteeHash,
		sender: ack.Sender, senderEpoch: ack.SenderEpoch, nonce: ack.Nonce, itemIDs: itemIDs,
	}
	expectation.admissionID = batch.Certificate.AdmissionID
	expectation.certificateHash, err = txQUICCertificateHash(batch.Certificate)
	if err != nil {
		return nil, false, err
	}
	if err := validateTxQUICAckOutcome(ack, expectation); err != nil {
		return nil, false, fmt.Errorf("invalid partial ACK: %w", err)
	}
	remaining := make([]*txQUICItem, 0, len(batch.Items))
	for index, item := range batch.Items {
		if txQUICBitmapHas(ack.RetryableBitmap, index) {
			remaining = append(remaining, item)
		}
	}
	if len(remaining) == len(batch.Items) {
		return record, false, nil
	}
	if len(remaining) == 0 {
		if err := o.deleteRecord(record); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	}
	residualBatch, _, err := newTxQUICBatch(batch.ChainID, batch.GenesisHash, batch.Certificate, remaining)
	if err != nil {
		return nil, false, err
	}
	payload, err := rlp.EncodeToBytes(residualBatch)
	if err != nil {
		return nil, false, err
	}
	residual := &TxOutboxRecord{BatchID: residualBatch.BatchID, Payload: payload, CreatedAt: record.CreatedAt}
	if residual.BatchID == record.BatchID {
		return nil, false, fmt.Errorf("tx outbox residual retained the superseded batch identity")
	}
	encoded, err := rlp.EncodeToBytes(residual)
	if err != nil {
		return nil, false, err
	}
	if o == nil || o.db == nil {
		return nil, false, fmt.Errorf("tx outbox database is unavailable")
	}
	unlockLifecycle := o.lockLifecycle(record.BatchID, residual.BatchID)
	defer unlockLifecycle()
	durableCtx, err := o.backgroundIOContext()
	if err != nil {
		return nil, false, err
	}
	oldKey := txOutboxRecordKey(record.BatchID)
	oldEncoded, err := o.db.Get(oldKey)
	if err != nil {
		return nil, false, fmt.Errorf("read superseded outbox batch %s: %w", record.BatchID, err)
	}
	var storedOld TxOutboxRecord
	if err := rlp.DecodeBytes(oldEncoded, &storedOld); err != nil || storedOld.BatchID != record.BatchID || !bytes.Equal(storedOld.Payload, record.Payload) {
		return nil, false, fmt.Errorf("superseded outbox batch %s changed before compaction", record.BatchID)
	}

	residualKey := txOutboxRecordKey(residual.BatchID)
	has, err := o.db.Has(residualKey)
	if err != nil {
		return nil, false, err
	}
	newlyStored := !has
	if has {
		existing, err := o.db.Get(residualKey)
		if err != nil {
			return nil, false, err
		}
		var stored TxOutboxRecord
		if err := rlp.DecodeBytes(existing, &stored); err != nil || stored.BatchID != residual.BatchID || !bytes.Equal(stored.Payload, residual.Payload) {
			return nil, false, fmt.Errorf("tx outbox residual batch identity collision")
		}
		// The existing projection is authoritative for placement and creation
		// metadata. WAL the exact stored record, not the freshly synthesized
		// zero-placement residual, so restart replay cannot roll it backward.
		residual = &stored
	} else {
		hasRetry, err := o.db.Has(txOutboxRetryKey(residual.BatchID))
		if err != nil {
			return nil, false, err
		}
		if hasRetry {
			return nil, false, fmt.Errorf("orphan retry state exists for residual outbox batch %s", residual.BatchID)
		}
	}

	oldBytes, err := txOutboxRecordCapacityBytes(record.Payload)
	if err != nil {
		return nil, false, err
	}
	residualBytes, err := txOutboxRecordCapacityBytes(residual.Payload)
	if err != nil {
		return nil, false, err
	}
	// Keep mutable accounting locked only long enough to validate it and reserve
	// any positive byte delta. The old and residual lifecycle stripes keep both
	// identities stable while unrelated records continue making progress.
	var reservedGrowth int64
	o.mu.Lock()
	if o.poison != nil {
		poison := o.poison
		o.mu.Unlock()
		return nil, false, fmt.Errorf("tx outbox is poisoned until restart: %w", poison)
	}
	if o.records < 1 || oldBytes > o.bytes {
		o.mu.Unlock()
		return nil, false, fmt.Errorf("tx outbox accounting does not contain superseded batch %s", record.BatchID)
	}
	if newlyStored {
		if residualBytes > oldBytes {
			reservedGrowth = residualBytes - oldBytes
		}
		usedBytes := o.bytes + o.reservedBytes
		if usedBytes > o.maxBytes || reservedGrowth > o.maxBytes-usedBytes {
			o.mu.Unlock()
			return nil, false, fmt.Errorf("tx outbox replacement capacity exceeded: records=%d/%d bytes=%d+%d/%d",
				o.records, o.maxRecords, usedBytes, reservedGrowth, o.maxBytes)
		}
		o.reservedBytes += reservedGrowth
	} else {
		if o.records < 2 || o.bytes < oldBytes+residualBytes {
			o.mu.Unlock()
			return residual, false, fmt.Errorf("tx outbox accounting does not contain existing residual batch %s", residual.BatchID)
		}
	}
	o.mu.Unlock()
	releaseGrowth := func() {
		if reservedGrowth == 0 {
			return
		}
		o.mu.Lock()
		if o.reservedBytes < reservedGrowth {
			o.poison = fmt.Errorf("tx outbox replacement byte reservation underflow")
		} else {
			o.reservedBytes -= reservedGrowth
		}
		close(o.space)
		o.space = make(chan struct{})
		o.mu.Unlock()
		reservedGrowth = 0
	}
	defer releaseGrowth()

	var replacementMutationID common.Hash
	if o.wal != nil {
		residualRetry, err := o.readRetry(residual.BatchID)
		if err != nil {
			return residual, false, err
		}
		replacementMutationID, err = o.wal.appendOutboxProjectionTracked(durableCtx, txIngressWALOutboxState, *residual, residualRetry, record.BatchID)
		if err != nil {
			return residual, false, fmt.Errorf("persist residual tx outbox replacement in unified ingress WAL: %w", err)
		}
	}

	write := o.db.NewBatch()
	if newlyStored {
		if err := write.Put(residualKey, encoded); err != nil {
			return nil, false, err
		}
	}
	if err := write.Delete(oldKey); err != nil {
		if newlyStored {
			return nil, false, err
		}
		return residual, false, err
	}
	if err := write.Delete(txOutboxRetryKey(record.BatchID)); err != nil {
		if newlyStored {
			return nil, false, err
		}
		return residual, false, err
	}
	syncBatch, ok := write.(ethdb.SyncBatch)
	if !ok {
		if newlyStored {
			return nil, false, fmt.Errorf("tx outbox database does not support synchronous batches")
		}
		return residual, false, fmt.Errorf("tx outbox database does not support synchronous batches")
	}
	if err := syncBatch.WriteSync(); err != nil {
		return nil, false, o.poisonBackgroundIO(fmt.Errorf("ambiguous residual outbox replacement fsync failure: %w", err))
	}
	if o.wal != nil {
		if err := o.wal.appendOutboxApplied(durableCtx, residual.BatchID, replacementMutationID); err != nil {
			return residual, true, o.poisonBackgroundIO(fmt.Errorf("confirm durable residual outbox replacement projection: %w", err))
		}
	}
	o.mu.Lock()
	if o.poison != nil {
		poison := o.poison
		o.mu.Unlock()
		return residual, true, fmt.Errorf("tx outbox is poisoned until restart: %w", poison)
	}
	if o.records < 1 || o.bytes < oldBytes || (!newlyStored && (o.records < 2 || o.bytes < oldBytes+residualBytes)) {
		o.poison = fmt.Errorf("tx outbox accounting changed during residual replacement for %s", record.BatchID)
		poison := o.poison
		o.mu.Unlock()
		return residual, true, poison
	}
	if newlyStored {
		o.bytes = o.bytes - oldBytes + residualBytes
		if reservedGrowth > 0 {
			o.reservedBytes -= reservedGrowth
			reservedGrowth = 0
		}
	} else {
		o.records--
		o.bytes -= oldBytes
	}
	delete(o.scheduled, record.BatchID)
	close(o.space)
	o.space = make(chan struct{})
	o.updateGaugesLocked()
	o.mu.Unlock()
	if newlyStored {
		txOutboxStoredMeter.Mark(1)
	}
	return residual, true, nil
}

func (o *TxOutbox) deleteRecord(record *TxOutboxRecord) error {
	if o == nil || record == nil {
		return errors.New("tx outbox deletion is unavailable")
	}
	unlockLifecycle := o.lockLifecycle(record.BatchID)
	defer unlockLifecycle()
	capacityBytes, err := txOutboxRecordCapacityBytes(record.Payload)
	if err != nil {
		return err
	}
	durableCtx, err := o.backgroundIOContext()
	if err != nil {
		return err
	}
	storedBytes, err := o.db.Get(txOutboxRecordKey(record.BatchID))
	if err != nil {
		return fmt.Errorf("read acknowledged outbox batch %s: %w", record.BatchID, err)
	}
	var stored TxOutboxRecord
	if err := rlp.DecodeBytes(storedBytes, &stored); err != nil || stored.BatchID != record.BatchID || !bytes.Equal(stored.Payload, record.Payload) {
		return fmt.Errorf("acknowledged outbox batch %s changed before deletion", record.BatchID)
	}
	o.mu.Lock()
	if o.records < 1 || o.bytes < capacityBytes {
		o.mu.Unlock()
		return fmt.Errorf("tx outbox accounting does not contain acknowledged batch %s", record.BatchID)
	}
	o.mu.Unlock()
	var deleteMutationID common.Hash
	if o.wal != nil {
		deleteMutationID, err = o.wal.appendOutboxProjectionTracked(durableCtx, txIngressWALOutboxDeleted, *record, txOutboxRetryState{}, common.Hash{})
		if err != nil {
			return fmt.Errorf("persist tx outbox deletion in unified ingress WAL: %w", err)
		}
	}
	batch := o.db.NewBatch()
	if err := batch.Delete(txOutboxRecordKey(record.BatchID)); err != nil {
		return err
	}
	if err := batch.Delete(txOutboxRetryKey(record.BatchID)); err != nil {
		return err
	}
	syncBatch, ok := batch.(ethdb.SyncBatch)
	if !ok {
		return fmt.Errorf("tx outbox database does not support synchronous batches")
	}
	if err := syncBatch.WriteSync(); err != nil {
		return o.poisonBackgroundIO(fmt.Errorf("ambiguous acknowledged outbox delete fsync failure: %w", err))
	}
	if o.wal != nil {
		if err := o.wal.appendOutboxApplied(durableCtx, record.BatchID, deleteMutationID); err != nil {
			return o.poisonBackgroundIO(fmt.Errorf("confirm durable acknowledged outbox delete projection: %w", err))
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.poison != nil {
		return fmt.Errorf("tx outbox is poisoned until restart: %w", o.poison)
	}
	if o.records < 1 || o.bytes < capacityBytes {
		o.poison = fmt.Errorf("tx outbox accounting changed during acknowledged delete for %s", record.BatchID)
		return o.poison
	}
	o.records--
	o.bytes -= capacityBytes
	// Capacity is a condition, not a one-consumer event. Wake every waiter so
	// differently-sized batches can all re-evaluate the newly available space.
	close(o.space)
	o.space = make(chan struct{})
	o.updateGaugesLocked()
	return nil
}

func (o *TxOutbox) updateRetry(batchID common.Hash, deliveryErr error) (txOutboxRetryState, error) {
	unlockLifecycle := o.lockLifecycle(batchID)
	defer unlockLifecycle()
	durableCtx, err := o.backgroundIOContext()
	if err != nil {
		return txOutboxRetryState{}, err
	}
	retry, err := o.readRetry(batchID)
	if err != nil {
		return retry, err
	}
	retry.Attempts++
	retry.LastError = deliveryErr.Error()
	if len(retry.LastError) > 512 {
		retry.LastError = retry.LastError[:512]
	}
	delay := o.retryDelay(retry.Attempts)
	retry.NextRetry = uint64(time.Now().Add(delay).UnixNano())
	encoded, err := rlp.EncodeToBytes(&retry)
	if err != nil {
		return retry, err
	}
	if o.wal != nil {
		record, err := o.readPlacementRecord(batchID)
		if err != nil {
			return retry, err
		}
		if err := o.wal.appendOutbox(durableCtx, txIngressWALOutboxState, record, retry); err != nil {
			return retry, fmt.Errorf("persist tx outbox retry in unified ingress WAL: %w", err)
		}
	}
	if err := o.db.Put(txOutboxRetryKey(batchID), encoded); err != nil {
		return retry, err
	}
	return retry, o.backgroundIOComplete()
}

func (o *TxOutbox) readRetry(batchID common.Hash) (txOutboxRetryState, error) {
	key := txOutboxRetryKey(batchID)
	has, err := o.db.Has(key)
	if err != nil {
		return txOutboxRetryState{}, err
	}
	if !has {
		return txOutboxRetryState{}, nil
	}
	data, err := o.db.Get(key)
	if err != nil {
		return txOutboxRetryState{}, err
	}
	var retry txOutboxRetryState
	if err := rlp.DecodeBytes(data, &retry); err != nil {
		return txOutboxRetryState{}, err
	}
	maxNextRetry := time.Now().Add(o.retryMax + o.config.MaxClockSkew)
	if retry.Attempts == 0 || retry.NextRetry == 0 || strings.TrimSpace(retry.LastError) == "" || len(retry.LastError) > 512 ||
		retry.NextRetry > uint64(maxNextRetry.UnixNano()) {
		return txOutboxRetryState{}, fmt.Errorf("invalid tx outbox retry metadata")
	}
	return retry, nil
}

func (o *TxOutbox) retryDelay(attempt uint32) time.Duration {
	delay := o.retryMin
	for i := uint32(1); i < attempt && delay < o.retryMax; i++ {
		if delay > o.retryMax/2 {
			return o.retryMax
		}
		delay *= 2
	}
	if delay > o.retryMax {
		return o.retryMax
	}
	return delay
}

func (o *TxOutbox) releaseInFlight(batchID common.Hash) {
	o.mu.Lock()
	delete(o.inFlight, batchID)
	o.mu.Unlock()
}

func (o *TxOutbox) scheduleRecord(batchID common.Hash, due uint64) {
	o.mu.Lock()
	if o.poison != nil {
		o.mu.Unlock()
		return
	}
	o.scheduleRecordLocked(batchID, due)
	o.mu.Unlock()
	o.signal(o.notify)
}

func (o *TxOutbox) scheduleRecordLocked(batchID common.Hash, due uint64) {
	o.scheduled[batchID] = due
	heap.Push(&o.schedule, txOutboxScheduleItem{batchID: batchID, due: due})
}

func (o *TxOutbox) popDue(now uint64) (common.Hash, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	var busyItems []txOutboxScheduleItem
	defer func() {
		for _, item := range busyItems {
			heap.Push(&o.schedule, item)
		}
	}()
	if o.poison != nil || len(o.inFlight) >= o.workers {
		return common.Hash{}, false
	}
	for o.schedule.Len() > 0 {
		item := o.schedule[0]
		current, scheduled := o.scheduled[item.batchID]
		if !scheduled || current != item.due {
			heap.Pop(&o.schedule)
			continue
		}
		if item.due > now {
			return common.Hash{}, false
		}
		// A replacement with the same semantic BatchID may be scheduled after
		// its predecessor was durably deleted but before finishDelivery releases
		// the predecessor's in-flight claim. Keep the due entry intact; consuming
		// it without acquiring the claim would strand the replacement until a
		// restart rebuilds the schedule.
		if _, busy := o.inFlight[item.batchID]; busy {
			heap.Pop(&o.schedule)
			busyItems = append(busyItems, item)
			continue
		}
		heap.Pop(&o.schedule)
		delete(o.scheduled, item.batchID)
		o.inFlight[item.batchID] = struct{}{}
		return item.batchID, true
	}
	return common.Hash{}, false
}

func (o *TxOutbox) releaseAndReschedule(batchID common.Hash, due time.Time) {
	o.mu.Lock()
	delete(o.inFlight, batchID)
	if o.poison != nil {
		o.mu.Unlock()
		return
	}
	o.scheduleRecordLocked(batchID, uint64(due.UnixNano()))
	o.mu.Unlock()
	o.signal(o.notify)
}

func (o *TxOutbox) Pending() (int, int64) {
	if o == nil {
		return 0, 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.records, o.bytes
}

func (o *TxOutbox) updateGauges() {
	records, bytes := o.Pending()
	txOutboxPendingGauge.Update(int64(records))
	txOutboxBytesGauge.Update(bytes)
}

func (o *TxOutbox) updateGaugesLocked() {
	txOutboxPendingGauge.Update(int64(o.records))
	txOutboxBytesGauge.Update(o.bytes)
}

func (o *TxOutbox) signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
