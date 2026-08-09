// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package eth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	mathbig "math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/metrics"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	txQUICProtocolName = "cypher-tx-quic/2"
	txQUICPacketV2     = uint(2)

	txQUICForwardIdleTimeout     = 60 * time.Second
	txQUICForwardKeepAlivePeriod = 10 * time.Second
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
	tokens int
	last   time.Time
}

type txQUICItem struct {
	Tx        *types.Transaction
	Admission *types.CommonTxAdmission
}

type txQUICPacket struct {
	Version   uint
	Sender    common.Address
	Nonce     uint64
	Timestamp uint64
	Items     []*txQUICItem
	Signature []byte
}

type txQUICSigningItem struct {
	TxHash          common.Hash
	AdmissionTxHash common.Hash
	AdmissionMiner  common.Address
}

type txQUICSigningData struct {
	Version   uint
	Sender    common.Address
	Nonce     uint64
	Timestamp uint64
	Items     []txQUICSigningItem
}

type txQUICAck struct {
	Version            uint
	Accepted           uint64
	Rejected           uint64
	Forwarded          uint64
	Errors             []string
	Hashes             []common.Hash
	AcceptedTx         uint64
	RejectedTx         uint64
	AcceptedAdmission  uint64
	RejectedAdmission  uint64
	TransactionRejects []txQUICTransactionReject
}

const (
	txQUICRejectPermanent uint = 1
	txQUICRejectRetryable uint = 2
)

// txQUICTransactionReject is a machine-readable transaction-pool result. The
// sender uses Class to distinguish an invalid transaction from a temporary
// node-local condition that may succeed at another committee endpoint.
type txQUICTransactionReject struct {
	Hash   common.Hash
	Reason string
	Class  uint
}

type txQUICAckExpectation struct {
	txHashes   []common.Hash
	admissions uint64
}

func newTxQUICAckExpectation(txs []*types.Transaction, admissions []*types.CommonTxAdmission) txQUICAckExpectation {
	expectation := txQUICAckExpectation{txHashes: make([]common.Hash, 0, len(txs))}
	for _, tx := range txs {
		if tx != nil {
			expectation.txHashes = append(expectation.txHashes, tx.Hash())
		}
	}
	for _, admission := range admissions {
		if admission != nil {
			expectation.admissions++
		}
	}
	return expectation
}

func txQUICAckExpectationFromPayload(payload []byte) (txQUICAckExpectation, error) {
	var packet txQUICPacket
	if err := rlp.DecodeBytes(payload, &packet); err == nil && len(packet.Items) > 0 {
		if packet.Version != txQUICPacketV2 {
			return txQUICAckExpectation{}, fmt.Errorf("unsupported txquic packet version %d", packet.Version)
		}
		txs, admissions, err := packetItemsToTxsAndAdmissions(&packet)
		if err != nil {
			return txQUICAckExpectation{}, err
		}
		return newTxQUICAckExpectation(txs, admissions), nil
	}
	var batch []*types.Transaction
	if err := rlp.DecodeBytes(payload, &batch); err == nil && len(batch) > 0 {
		return newTxQUICAckExpectation(batch, nil), nil
	}
	var single types.Transaction
	if err := rlp.DecodeBytes(payload, &single); err != nil {
		return txQUICAckExpectation{}, fmt.Errorf("decode outbound txquic expectation: %w", err)
	}
	return newTxQUICAckExpectation([]*types.Transaction{&single}, nil), nil
}

type txQUICRemoteRejectError struct {
	endpoint string
	rejects  []txQUICTransactionReject
}

func (e *txQUICRemoteRejectError) Error() string {
	if e == nil {
		return "txquic remote transaction rejected"
	}
	reasons := make([]string, 0, len(e.rejects))
	for _, reject := range e.rejects {
		reasons = append(reasons, fmt.Sprintf("%s: %s", reject.Hash, reject.Reason))
	}
	return fmt.Sprintf("txquic remote transaction rejected by %s: %s", e.endpoint, strings.Join(reasons, "; "))
}

// Retryable reports whether every rejected transaction failed for a temporary
// reason. A mixed batch is deliberately not retried forever because at least
// one transaction can never make the exact-batch acknowledgement succeed.
func (e *txQUICRemoteRejectError) Retryable() bool {
	if e == nil || len(e.rejects) == 0 {
		return false
	}
	for _, reject := range e.rejects {
		if reject.Class != txQUICRejectRetryable {
			return false
		}
	}
	return true
}

type txQUICBridgeItem struct {
	tx        *types.Transaction
	admission *types.CommonTxAdmission
	am        *accounts.Manager
}

type txQUICAdmissionItem struct {
	admission *types.CommonTxAdmission
}

type txQUICForwardClient struct {
	endpoint string

	mu   sync.Mutex
	conn *quic.Conn
}

type TxQUICIngress struct {
	config TxQUICConfig
	txpool *core.TxPool

	ctx    context.Context
	cancel context.CancelFunc

	listener     *quic.Listener
	http3Server  *http3.Server
	http3Handler http.Handler

	allowNets []*net.IPNet
	allowIPs  map[string]struct{}
	signers   map[common.Address]struct{}

	wg      sync.WaitGroup
	connSem chan struct{}

	rateMu  sync.Mutex
	buckets map[string]*txQUICRateBucket

	bridgeQueue    chan txQUICBridgeItem
	admissionQueue chan txQUICAdmissionItem

	outboundNonce uint64

	forwardClients sync.Map // map[string]*txQUICForwardClient
}

func (config *TxQUICConfig) ApplyFixedCommitteeAutoRole(chainConfig *params.ChainConfig) {
	if config == nil || !config.AutoRole || chainConfig == nil || len(chainConfig.GenCommittee) == 0 {
		return
	}
	if !chainConfig.FixedLeader && !chainConfig.FixedCommittee {
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
	for i, node := range chainConfig.GenCommittee {
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
		config.RoutingMode = "local"
		config.LeaderEndpoints = nil
		config.BackupEndpoints = nil
		log.Info("TxQUIC auto role: validator ingress", "committeeIndex", localIndex, "rnetPort", localRnetPort, "txquicPort", config.Port)
		return
	}
	config.Enabled = false
	config.BridgeEnabled = true
	config.HTTP3Enabled = true
	config.RoutingMode = "committee-backup"
	config.LeaderEndpoints = nil
	config.BackupEndpoints = nil
	for i, node := range chainConfig.GenCommittee {
		endpoint, ok := txQUICEndpointFromCommitteeAddress(node.Address, config.PortOffset)
		if !ok {
			continue
		}
		if i == 0 {
			config.LeaderEndpoints = append(config.LeaderEndpoints, endpoint)
		} else {
			config.BackupEndpoints = append(config.BackupEndpoints, endpoint)
		}
	}
	log.Info("TxQUIC auto role: common RPC bridge", "leaders", config.LeaderEndpoints, "backups", len(config.BackupEndpoints), "http3rpc", config.HTTP3Enabled)
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
	q := &TxQUICIngress{
		config:   config,
		txpool:   txpool,
		ctx:      ctx,
		cancel:   cancel,
		connSem:  make(chan struct{}, config.MaxIncomingConns),
		buckets:  make(map[string]*txQUICRateBucket),
		allowIPs: make(map[string]struct{}),
		signers:  make(map[common.Address]struct{}),
	}
	if config.BridgeEnabled {
		q.bridgeQueue = make(chan txQUICBridgeItem, config.BridgeQueueSize)
		q.admissionQueue = make(chan txQUICAdmissionItem, config.BridgeQueueSize)
		core.SetCommonRPCAdmissionDedicatedRelay(q.ForwardAdmissions)
	}
	q.parseAllowlist()
	q.parseSigners()
	return q
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
		config.BridgeQueueSize = 100000
	}
	if config.BridgeWorkers <= 0 {
		config.BridgeWorkers = 1
	}
	if config.BridgeBatchInterval <= 0 {
		config.BridgeBatchInterval = 10 * time.Millisecond
	}
	if config.MaxPayload <= 0 {
		config.MaxPayload = 512 * 1024
	}
	if config.MaxTxsPerBatch <= 0 {
		config.MaxTxsPerBatch = 512
	}
	if config.MaxIncomingStreams <= 0 {
		config.MaxIncomingStreams = 4096
	}
	if config.MaxIncomingConns <= 0 {
		config.MaxIncomingConns = 1024
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
	if config.MaxTxsPerIPPerSecond <= 0 {
		config.MaxTxsPerIPPerSecond = 500000
	}
	if config.BurstTxsPerIP <= 0 {
		config.BurstTxsPerIP = 1000000
	}
	if config.RoutingMode == "" {
		config.RoutingMode = "leader-only"
	}
}

func (q *TxQUICIngress) SetHTTP3RPCHandler(handler http.Handler) { q.http3Handler = handler }

func (q *TxQUICIngress) Start() error {
	if q.config.BridgeEnabled {
		q.startBridgeWorkers()
	}
	if err := q.startHTTP3RPC(); err != nil {
		return err
	}
	if !q.config.Enabled {
		if q.config.BridgeEnabled {
			log.Info("TxQUIC bridge enabled", "routing", q.config.RoutingMode, "leaders", len(q.config.LeaderEndpoints), "backups", len(q.config.BackupEndpoints), "queue", q.config.BridgeQueueSize, "batch", q.config.MaxTxsPerBatch, "interval", q.config.BridgeBatchInterval)
		}
		return nil
	}
	if q.txpool == nil {
		return fmt.Errorf("txquic ingress requires txpool")
	}
	cert, err := q.serverCertificate()
	if err != nil {
		return err
	}
	addr := txQUICJoinHostPort(q.config.Addr, q.config.Port)
	listener, err := quic.ListenAddr(addr, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{txQUICProtocolName}, MinVersion: tls.VersionTLS13}, &quic.Config{MaxIncomingStreams: q.config.MaxIncomingStreams, KeepAlivePeriod: txQUICForwardKeepAlivePeriod, MaxIdleTimeout: txQUICForwardIdleTimeout})
	if err != nil {
		return err
	}
	q.listener = listener
	log.Info("Started QUIC tx ingress", "addr", addr, "routing", q.config.RoutingMode, "auth", q.config.RequireAuth, "ack", q.config.Ack, "leaders", len(q.config.LeaderEndpoints), "backups", len(q.config.BackupEndpoints))
	q.wg.Add(1)
	go q.acceptLoop()
	return nil
}

func (q *TxQUICIngress) Stop() {
	if q.cancel != nil {
		q.cancel()
	}
	if q.listener != nil {
		_ = q.listener.Close()
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
	log.Info("Stopped QUIC tx ingress")
}

func (q *TxQUICIngress) ForwardLocalTxs(txs []*types.Transaction, am *accounts.Manager) {
	q.ForwardLocalTxsWithAdmissions(txs, nil, am)
}

func (q *TxQUICIngress) ForwardLocalTxsWithAdmissions(txs []*types.Transaction, admissions []*types.CommonTxAdmission, am *accounts.Manager) {
	if err := q.EnqueueLocalTxsWithAdmissions(context.Background(), txs, admissions, am); err != nil {
		log.Warn("TxQUIC bridge enqueue failed", "txs", len(txs), "admissions", len(admissions), "err", err)
	}
}

// EnqueueLocalTxsWithAdmissions accepts transactions into the bounded bridge
// queue. It blocks for queue capacity instead of silently dropping traffic.
func (q *TxQUICIngress) EnqueueLocalTxsWithAdmissions(ctx context.Context, txs []*types.Transaction, admissions []*types.CommonTxAdmission, am *accounts.Manager) error {
	if q == nil {
		return fmt.Errorf("txquic ingress is nil")
	}
	if !q.config.BridgeEnabled || q.bridgeQueue == nil {
		return fmt.Errorf("txquic bridge is not enabled")
	}
	if len(txs) == 0 {
		return fmt.Errorf("no txs to enqueue")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	admissionByTx := make(map[common.Hash]*types.CommonTxAdmission)
	for _, admission := range admissions {
		if admission == nil {
			continue
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
			return fmt.Errorf("invalid TxQUIC admission sidecar for %s: %w", admission.TxHash, err)
		}
		admissionByTx[admission.TxHash] = copyCommonTxAdmissionForQUIC(admission)
	}

	enqueued := 0
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		hash := tx.Hash()
		item := txQUICBridgeItem{
			tx:        tx,
			admission: admissionByTx[hash],
			am:        am,
		}
		select {
		case q.bridgeQueue <- item:
			enqueued++
		case <-ctx.Done():
			return fmt.Errorf("txquic bridge enqueue interrupted after %d/%d txs: %w", enqueued, len(txs), ctx.Err())
		case <-q.ctx.Done():
			return fmt.Errorf("txquic bridge stopped after %d/%d txs", enqueued, len(txs))
		}
	}
	if enqueued == 0 {
		return fmt.Errorf("no non-nil txs to enqueue")
	}
	return nil
}

func (q *TxQUICIngress) SendLocalTxsWithAdmissionsSync(ctx context.Context, txs []*types.Transaction, admissions []*types.CommonTxAdmission, am *accounts.Manager) error {
	if q == nil {
		return fmt.Errorf("txquic ingress is nil")
	}
	if !q.config.BridgeEnabled {
		return fmt.Errorf("txquic bridge is not enabled")
	}
	if !q.config.Ack {
		return fmt.Errorf("txquic synchronous forwarding requires acknowledgements")
	}
	if len(txs) == 0 {
		return fmt.Errorf("no txs to forward")
	}

	payload, err := q.encodeTxPayload(txs, admissions, am)
	if err != nil {
		return err
	}

	endpoint, err := q.forwardPayloadSync(ctx, payload)
	if err != nil {
		return fmt.Errorf("txquic sync forward failed: txs=%d admissions=%d err=%w", len(txs), len(admissions), err)
	}

	txQUICIngressForwardMeter.Mark(1)
	log.Debug("TxQUIC bridge sync forwarded tx batch", "txs", len(txs), "admissions", len(admissions), "endpoint", endpoint, "forwarded", 1)
	return nil
}

func (q *TxQUICIngress) forwardPayloadSync(ctx context.Context, payload []byte) (string, error) {
	mode := strings.ToLower(q.config.RoutingMode)
	if mode == "local" || mode == "" {
		return "", fmt.Errorf("txquic sync forward has no remote endpoints in routing mode %q", q.config.RoutingMode)
	}

	endpoints := append([]string{}, q.config.LeaderEndpoints...)
	if mode == "committee-backup" {
		endpoints = append(endpoints, q.config.BackupEndpoints...)
	}
	if len(endpoints) == 0 {
		return "", fmt.Errorf("txquic sync forward has no endpoints")
	}

	errs := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			continue
		}
		if err := q.forwardPayloadContext(ctx, endpoint, payload); err != nil {
			var rejected *txQUICRemoteRejectError
			if errors.As(err, &rejected) {
				if !rejected.Retryable() {
					return "", rejected
				}
				errs = append(errs, fmt.Sprintf("%s: %v", endpoint, rejected))
				log.Debug("TxQUIC sync endpoint temporarily rejected transaction", "endpoint", endpoint, "err", rejected)
				continue
			}
			errs = append(errs, fmt.Sprintf("%s: %v", endpoint, err))
			log.Debug("TxQUIC sync forward failed", "endpoint", endpoint, "err", err)
			continue
		}
		return endpoint, nil
	}

	return "", fmt.Errorf("all endpoints failed: %s", strings.Join(errs, "; "))
}

func (q *TxQUICIngress) ForwardAdmissions(admissions []*types.CommonTxAdmission) {
	if q == nil || !q.config.BridgeEnabled || len(admissions) == 0 || q.admissionQueue == nil {
		return
	}
	for _, admission := range admissions {
		if admission == nil {
			continue
		}
		copy := copyCommonTxAdmissionForQUIC(admission)
		select {
		case q.admissionQueue <- txQUICAdmissionItem{admission: copy}:
		case <-q.ctx.Done():
			return
		}
	}
}

func (q *TxQUICIngress) startBridgeWorkers() {
	if q.bridgeQueue == nil {
		q.bridgeQueue = make(chan txQUICBridgeItem, q.config.BridgeQueueSize)
	}
	if q.admissionQueue == nil {
		q.admissionQueue = make(chan txQUICAdmissionItem, q.config.BridgeQueueSize)
	}
	for i := 0; i < q.config.BridgeWorkers; i++ {
		q.wg.Add(2)
		go q.bridgeWorker(i)
		go q.admissionWorker(i)
	}
}

func (q *TxQUICIngress) bridgeWorker(id int) {
	defer q.wg.Done()
	ticker := time.NewTicker(q.config.BridgeBatchInterval)
	defer ticker.Stop()

	batch := make([]*types.Transaction, 0, q.config.MaxTxsPerBatch)
	admissionBatch := make([]*types.CommonTxAdmission, 0, q.config.MaxTxsPerBatch)
	var am *accounts.Manager

	flush := func() {
		if len(batch) == 0 {
			return
		}
		txs := append([]*types.Transaction(nil), batch...)
		admissions := append([]*types.CommonTxAdmission(nil), admissionBatch...)
		batch = batch[:0]
		admissionBatch = admissionBatch[:0]
		q.forwardBridgeBatchUntilDelivered(txs, admissions, am)
	}

	for {
		select {
		case <-q.ctx.Done():
			flush()
			return

		case item := <-q.bridgeQueue:
			if item.tx == nil {
				continue
			}
			if item.am != nil {
				am = item.am
			}
			batch = append(batch, item.tx)
			if item.admission != nil {
				admissionBatch = append(admissionBatch, copyCommonTxAdmissionForQUIC(item.admission))
			}
			if len(batch) >= q.config.MaxTxsPerBatch {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}

func (q *TxQUICIngress) admissionWorker(id int) {
	defer q.wg.Done()
	ticker := time.NewTicker(q.config.BridgeBatchInterval)
	defer ticker.Stop()
	batch := make([]*types.CommonTxAdmission, 0, q.config.MaxTxsPerBatch)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		admissions := append([]*types.CommonTxAdmission(nil), batch...)
		batch = batch[:0]
		q.forwardAdmissionBatch(admissions)
	}
	for {
		select {
		case <-q.ctx.Done():
			flush()
			return
		case item := <-q.admissionQueue:
			if item.admission == nil {
				continue
			}
			batch = append(batch, item.admission)
			if len(batch) >= q.config.MaxTxsPerBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (q *TxQUICIngress) forwardBridgeBatchUntilDelivered(txs []*types.Transaction, admissions []*types.CommonTxAdmission, am *accounts.Manager) {
	backoff := 50 * time.Millisecond
	payload, err := q.encodeVerifiedTxPayload(txs, admissions, am)
	if err != nil {
		log.Error("TxQUIC bridge encode failed permanently", "err", err, "txs", len(txs), "admissions", len(admissions))
		txQUICIngressRejectedMeter.Mark(int64(len(txs)))
		return
	}
	for {
		forwarded, requiredDelivered, rejectErr := q.routeBridgePayload(payload)
		if rejectErr != nil {
			log.Error("TxQUIC bridge batch rejected permanently", "txs", len(txs), "admissions", len(admissions), "err", rejectErr)
			txQUICIngressRejectedMeter.Mark(int64(len(txs)))
			return
		}
		if requiredDelivered {
			txQUICIngressForwardMeter.Mark(int64(forwarded))
			log.Debug("TxQUIC bridge forwarded tx batch", "txs", len(txs), "admissions", len(admissions), "forwarded", forwarded)
			return
		}
		log.Warn("TxQUIC bridge batch delivery failed; retrying", "txs", len(txs), "admissions", len(admissions), "retryAfter", backoff)
		select {
		case <-time.After(backoff):
		case <-q.ctx.Done():
			return
		}
		if backoff < 2*time.Second {
			backoff *= 2
		}
	}
}

func (q *TxQUICIngress) forwardAdmissionBatch(admissions []*types.CommonTxAdmission) {
	payload, err := q.encodeAdmissionPayload(admissions)
	if err != nil {
		log.Error("TxQUIC admission encode failed permanently", "err", err, "admissions", len(admissions))
		return
	}
	backoff := 50 * time.Millisecond
	for {
		forwarded, requiredDelivered, rejectErr := q.routeBridgePayload(payload)
		if rejectErr != nil {
			log.Error("TxQUIC admission batch rejected permanently", "admissions", len(admissions), "err", rejectErr)
			return
		}
		if requiredDelivered {
			txQUICIngressForwardMeter.Mark(int64(forwarded))
			log.Debug("TxQUIC bridge forwarded admission batch", "admissions", len(admissions), "forwarded", forwarded)
			return
		}
		log.Warn("TxQUIC admission batch delivery failed; retrying", "admissions", len(admissions), "retryAfter", backoff)
		select {
		case <-time.After(backoff):
		case <-q.ctx.Done():
			return
		}
		if backoff < 2*time.Second {
			backoff *= 2
		}
	}
}

func (q *TxQUICIngress) encodeTxPayload(txs []*types.Transaction, admissions []*types.CommonTxAdmission, am *accounts.Manager) ([]byte, error) {
	return q.encodeTxPayloadWithAdmissionValidation(txs, admissions, am, true)
}

func (q *TxQUICIngress) encodeVerifiedTxPayload(txs []*types.Transaction, admissions []*types.CommonTxAdmission, am *accounts.Manager) ([]byte, error) {
	return q.encodeTxPayloadWithAdmissionValidation(txs, admissions, am, false)
}

func (q *TxQUICIngress) encodeTxPayloadWithAdmissionValidation(txs []*types.Transaction, admissions []*types.CommonTxAdmission, am *accounts.Manager, validateAdmissions bool) ([]byte, error) {
	if len(txs) == 0 {
		return nil, fmt.Errorf("no txs to encode")
	}

	admissionByTx := make(map[common.Hash]*types.CommonTxAdmission)
	for _, admission := range admissions {
		if admission == nil {
			continue
		}
		if validateAdmissions {
			if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
				log.Warn("Skip invalid TxQUIC admission sidecar before forward", "tx", admission.TxHash, "miner", admission.Miner, "err", err)
				continue
			}
		}
		if admission.TxHash == (common.Hash{}) || admission.Miner == (common.Address{}) {
			log.Warn("Skip incomplete TxQUIC admission sidecar before forward", "tx", admission.TxHash, "miner", admission.Miner)
			continue
		}
		admissionByTx[admission.TxHash] = copyCommonTxAdmissionForQUIC(admission)
	}

	items := make([]*txQUICItem, 0, len(txs))
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		hash := tx.Hash()
		items = append(items, &txQUICItem{
			Tx:        tx,
			Admission: admissionByTx[hash],
		})
		delete(admissionByTx, hash)
	}

	if len(items) == 0 {
		return nil, fmt.Errorf("no valid txs to encode")
	}

	for txHash, admission := range admissionByTx {
		log.Debug("Skip unmatched TxQUIC admission sidecar", "tx", txHash, "miner", admission.Miner)
	}

	hasAdmission := false
	for _, item := range items {
		if item != nil && item.Admission != nil {
			hasAdmission = true
			break
		}
	}

	if !q.config.RequireAuth && !hasAdmission {
		plainTxs := make([]*types.Transaction, 0, len(items))
		for _, item := range items {
			if item != nil && item.Tx != nil {
				plainTxs = append(plainTxs, item.Tx)
			}
		}
		return rlp.EncodeToBytes(plainTxs)
	}

	sender := bftview.GetServerCoinBase()
	if q.config.RequireAuth {
		if sender == (common.Address{}) {
			return nil, fmt.Errorf("txquic bridge signer coinbase is empty")
		}
		if am == nil {
			return nil, fmt.Errorf("txquic bridge account manager is nil")
		}
	}

	pkt := &txQUICPacket{
		Version:   txQUICPacketV2,
		Sender:    sender,
		Nonce:     atomic.AddUint64(&q.outboundNonce, 1),
		Timestamp: uint64(time.Now().Unix()),
		Items:     items,
	}

	if !q.config.RequireAuth {
		return rlp.EncodeToBytes(pkt)
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
	return rlp.EncodeToBytes(pkt)
}

func (q *TxQUICIngress) encodeAdmissionPayload(admissions []*types.CommonTxAdmission) ([]byte, error) {
	items := make([]*txQUICItem, 0, len(admissions))
	for _, admission := range admissions {
		if admission == nil {
			continue
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
			log.Warn("Skip invalid TxQUIC admission before forward", "tx", admission.TxHash, "miner", admission.Miner, "err", err)
			continue
		}
		items = append(items, &txQUICItem{
			Tx:        nil,
			Admission: copyCommonTxAdmissionForQUIC(admission),
		})
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("no valid admissions to forward")
	}
	pkt := &txQUICPacket{
		Version:   txQUICPacketV2,
		Nonce:     atomic.AddUint64(&q.outboundNonce, 1),
		Timestamp: uint64(time.Now().Unix()),
		Items:     items,
	}
	return rlp.EncodeToBytes(pkt)
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
		remote := conn.RemoteAddr()
		if !q.allowed(remote) {
			_ = conn.CloseWithError(1, "not allowed")
			continue
		}
		select {
		case q.connSem <- struct{}{}:
		default:
			_ = conn.CloseWithError(2, "too many connections")
			continue
		}
		txQUICIngressConnMeter.Mark(1)
		q.wg.Add(1)
		go q.handleConn(conn)
	}
}

func (q *TxQUICIngress) handleConn(conn *quic.Conn) {
	defer q.wg.Done()
	defer func() { <-q.connSem; _ = conn.CloseWithError(0, "closed") }()
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
		txQUICIngressStreamMeter.Mark(1)
		q.wg.Add(1)
		go q.handleStream(remote, stream)
	}
}

func (q *TxQUICIngress) handleStream(remote net.Addr, stream *quic.Stream) {
	defer q.wg.Done()
	defer stream.Close()
	ack := txQUICAck{Version: txQUICPacketV2}
	_ = stream.SetReadDeadline(time.Now().Add(q.config.ReadTimeout))
	payload, err := io.ReadAll(io.LimitReader(stream, q.config.MaxPayload+1))
	if err != nil {
		ack.Errors = append(ack.Errors, err.Error())
		log.Warn("TxQUIC stream read failed", "remote", remote, "err", err)
		q.writeAck(stream, ack)
		return
	}
	if int64(len(payload)) > q.config.MaxPayload {
		ack.Errors = append(ack.Errors, "payload too large")
		log.Warn("TxQUIC payload too large", "remote", remote, "payload", len(payload), "limit", q.config.MaxPayload)
		q.writeAck(stream, ack)
		return
	}
	txs, admissions, signed, signer, err := q.decodeAndAuthenticate(payload)
	if err != nil {
		txQUICIngressAuthFailMeter.Mark(1)
		ack.Errors = append(ack.Errors, err.Error())
		log.Warn("TxQUIC decode/auth failed", "remote", remote, "payload", len(payload), "err", err)
		q.writeAck(stream, ack)
		return
	}
	if len(txs) == 0 && len(admissions) == 0 {
		ack.Errors = append(ack.Errors, "empty txquic payload")
		log.Warn("TxQUIC empty payload", "remote", remote, "payload", len(payload))
		q.writeAck(stream, ack)
		return
	}
	if len(txs) > q.config.MaxTxsPerBatch || len(admissions) > q.config.MaxTxsPerBatch {
		ack.Errors = append(ack.Errors, "batch too large")
		log.Warn("TxQUIC batch too large", "remote", remote, "txs", len(txs), "admissions", len(admissions), "limit", q.config.MaxTxsPerBatch)
		q.writeAck(stream, ack)
		return
	}
	if !q.takeTokens(remote, txQUICRateUnits(len(txs), len(admissions))) {
		ack.Errors = append(ack.Errors, "rate limited")
		log.Warn("TxQUIC rate limited", "remote", remote, "txs", len(txs), "admissions", len(admissions))
		q.writeAck(stream, ack)
		return
	}
	forwarded := q.routePayload(payload)
	acceptedAdmission, rejectedAdmission := q.insertAdmissions(admissions)
	acceptedTx, rejectedTx, hashes, txRejects := q.insertLocal(txs)
	ack.Forwarded = uint64(forwarded)
	ack.Accepted = uint64(acceptedTx + acceptedAdmission)
	ack.Rejected = uint64(rejectedTx + rejectedAdmission)
	ack.Hashes = hashes
	ack.AcceptedTx = uint64(acceptedTx)
	ack.RejectedTx = uint64(rejectedTx)
	ack.AcceptedAdmission = uint64(acceptedAdmission)
	ack.RejectedAdmission = uint64(rejectedAdmission)
	ack.TransactionRejects = txRejects
	if ack.Accepted > 0 {
		txQUICIngressAcceptedMeter.Mark(int64(ack.Accepted))
	}
	if ack.Rejected > 0 {
		txQUICIngressRejectedMeter.Mark(int64(ack.Rejected))
	}
	if ack.Forwarded > 0 {
		txQUICIngressForwardMeter.Mark(int64(ack.Forwarded))
	}
	log.Debug("QUIC ingress processed", "remote", remote, "signed", signed, "signer", signer, "txs", len(txs), "admissions", len(admissions), "acceptedTx", ack.AcceptedTx, "rejectedTx", ack.RejectedTx, "acceptedAdmissions", ack.AcceptedAdmission, "rejectedAdmissions", ack.RejectedAdmission, "forwarded", ack.Forwarded, "txRejects", ack.TransactionRejects)
	q.writeAck(stream, ack)
}

func txQUICRateUnits(txs, admissions int) int {
	if txs > admissions {
		return txs
	}
	return admissions
}

func (q *TxQUICIngress) insertLocal(txs []*types.Transaction) (int, int, []common.Hash, []txQUICTransactionReject) {
	if len(txs) == 0 {
		return 0, 0, nil, nil
	}
	mode := strings.ToLower(q.config.RoutingMode)
	if mode == "leader-only" && len(q.config.LeaderEndpoints) > 0 {
		return 0, 0, nil, nil
	}
	return summarizeTxQUICInsert(txs, q.txpool.AddRemotes(txs))
}

func summarizeTxQUICInsert(txs []*types.Transaction, insertErrors []error) (int, int, []common.Hash, []txQUICTransactionReject) {
	accepted, rejected := 0, 0
	hashes := make([]common.Hash, 0, len(txs))
	rejects := make([]txQUICTransactionReject, 0)
	for i, tx := range txs {
		if tx == nil {
			rejected++
			rejects = append(rejects, txQUICTransactionReject{Reason: fmt.Sprintf("transaction[%d]: nil transaction", i), Class: txQUICRejectPermanent})
			continue
		}
		var err error
		if i < len(insertErrors) {
			err = insertErrors[i]
		} else {
			err = fmt.Errorf("transaction pool returned no result")
		}
		if err == nil || errors.Is(err, core.ErrAlreadyKnown) {
			accepted++
			hashes = append(hashes, tx.Hash())
		} else {
			rejected++
			rejects = append(rejects, txQUICTransactionReject{Hash: tx.Hash(), Reason: err.Error(), Class: classifyTxQUICInsertError(err)})
			log.Info("TxQUIC transaction rejected", "tx", tx.Hash(), "err", err)
		}
	}
	return accepted, rejected, hashes, rejects
}

func classifyTxQUICInsertError(err error) uint {
	if err == nil || errors.Is(err, core.ErrAlreadyKnown) {
		return 0
	}
	// These depend on pool capacity, local pricing, account state, or the
	// current block and may succeed at another committee node or after retry.
	for _, retryable := range []error{
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
	} {
		if errors.Is(err, retryable) {
			return txQUICRejectRetryable
		}
	}
	// These are transaction-intrinsic (or already irreversibly stale).
	for _, permanent := range []error{
		core.ErrNonceTooLow,
		core.ErrInvalidSender,
		core.ErrGasLimit,
		core.ErrNegativeValue,
		core.ErrOversizedData,
		core.ErrInvalidGasPrice,
		core.ErrEtherValueUnsupported,
		core.ErrIntrinsicGas,
		core.ErrGasTipAboveFeeCap,
		core.ErrTipVeryHigh,
		core.ErrFeeCapVeryHigh,
		core.ErrGasUintOverflow,
	} {
		if errors.Is(err, permanent) {
			return txQUICRejectPermanent
		}
	}
	// Unknown/internal pool failures are safer to retry than to discard.
	return txQUICRejectRetryable
}

func (q *TxQUICIngress) insertAdmissions(admissions []*types.CommonTxAdmission) (int, int) {
	accepted, rejected := 0, 0
	for _, admission := range admissions {
		if admission == nil {
			rejected++
			continue
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
			rejected++
			log.Info("TxQUIC admission rejected", "tx", admission.TxHash, "miner", admission.Miner, "err", err)
			continue
		}
		// StoreCommonRPCAdmission returns false for an exact duplicate or a
		// deterministically worse-but-valid sidecar. Delivery is nevertheless
		// idempotently complete, so a lost ACK must not cause infinite retries.
		core.StoreCommonRPCAdmission(admission)
		accepted++
	}
	return accepted, rejected
}

func (q *TxQUICIngress) routePayload(payload []byte) int {
	mode := strings.ToLower(q.config.RoutingMode)
	if mode == "local" || mode == "" {
		return 0
	}
	endpoints := append([]string{}, q.config.LeaderEndpoints...)
	if mode == "committee-backup" {
		endpoints = append(endpoints, q.config.BackupEndpoints...)
	}
	forwarded := 0
	for _, endpoint := range endpoints {
		if err := q.forwardPayload(endpoint, payload); err != nil {
			log.Debug("TxQUIC forward failed", "endpoint", endpoint, "err", err)
			continue
		}
		forwarded++
	}
	return forwarded
}

func (q *TxQUICIngress) routeBridgePayload(payload []byte) (forwarded int, requiredDelivered bool, rejectErr error) {
	mode := strings.ToLower(q.config.RoutingMode)
	if mode == "local" || mode == "" {
		return 0, false, nil
	}
	for _, endpoint := range q.config.LeaderEndpoints {
		if err := q.forwardPayload(endpoint, payload); err != nil {
			var rejected *txQUICRemoteRejectError
			if errors.As(err, &rejected) {
				if !rejected.Retryable() {
					return 0, false, rejected
				}
				log.Debug("TxQUIC leader temporarily rejected transaction", "endpoint", endpoint, "err", rejected)
				continue
			}
			log.Debug("TxQUIC leader forward failed", "endpoint", endpoint, "err", err)
			continue
		}
		// The fixed leader is the required destination. Return immediately so a
		// slow backup cannot stall common RPC admission after leader delivery.
		return 1, true, nil
	}
	for _, endpoint := range q.config.BackupEndpoints {
		if err := q.forwardPayload(endpoint, payload); err != nil {
			var rejected *txQUICRemoteRejectError
			if errors.As(err, &rejected) {
				if !rejected.Retryable() {
					return forwarded, false, rejected
				}
				log.Debug("TxQUIC backup temporarily rejected transaction", "endpoint", endpoint, "err", rejected)
				continue
			}
			log.Debug("TxQUIC backup forward failed", "endpoint", endpoint, "err", err)
			continue
		}
		forwarded++
		if len(q.config.LeaderEndpoints) == 0 {
			requiredDelivered = true
		}
	}
	return forwarded, requiredDelivered, nil
}

func (q *TxQUICIngress) forwardPayload(endpoint string, payload []byte) error {
	return q.forwardPayloadContext(q.ctx, endpoint, payload)
}

func (q *TxQUICIngress) forwardPayloadContext(ctx context.Context, endpoint string, payload []byte) error {
	if q == nil {
		return fmt.Errorf("nil txquic ingress")
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return fmt.Errorf("empty txquic endpoint")
	}
	if len(payload) == 0 {
		return fmt.Errorf("empty txquic payload")
	}
	expectation, err := txQUICAckExpectationFromPayload(payload)
	if err != nil {
		return err
	}

	value, _ := q.forwardClients.LoadOrStore(endpoint, &txQUICForwardClient{endpoint: endpoint})
	client, ok := value.(*txQUICForwardClient)
	if !ok || client == nil {
		return fmt.Errorf("invalid txquic forward client for %s", endpoint)
	}
	return client.send(ctx, q, payload, expectation)
}

func (c *txQUICForwardClient) getConn(q *TxQUICIngress, ctx context.Context) (*quic.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		select {
		case <-c.conn.Context().Done():
			c.conn = nil
		default:
			return c.conn, nil
		}
	}

	handshakeTimeout := q.config.ForwardTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = 3 * time.Second
	}

	conn, err := quic.DialAddr(ctx, c.endpoint, q.clientTLSConfig(), &quic.Config{
		HandshakeIdleTimeout: handshakeTimeout,
		MaxIdleTimeout:       txQUICForwardIdleTimeout,
		KeepAlivePeriod:      txQUICForwardKeepAlivePeriod,
	})
	if err != nil {
		return nil, err
	}

	c.conn = conn
	return conn, nil
}

func (c *txQUICForwardClient) send(parent context.Context, q *TxQUICIngress, payload []byte, expectation txQUICAckExpectation) error {
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
		conn, err := c.getConn(q, ctx)
		if err != nil {
			return err
		}

		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			c.reset(conn)
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
			_ = stream.Close()
			c.reset(conn)
			lastErr = err
			continue
		}

		if err := stream.Close(); err != nil {
			stopStream()
			c.reset(conn)
			lastErr = err
			continue
		}

		if !q.config.Ack {
			stopStream()
			return nil
		}

		_ = stream.SetReadDeadline(time.Now().Add(q.config.ReadTimeout))
		var ack txQUICAck
		if err := rlp.Decode(stream, &ack); err != nil {
			stopStream()
			c.reset(conn)
			lastErr = fmt.Errorf("txquic ack read failed from %s: %w", c.endpoint, err)
			continue
		}

		if err := validateTxQUICAck(c.endpoint, &ack, expectation); err != nil {
			stopStream()
			return err
		}
		stopStream()
		return nil
	}

	return lastErr
}

func validateTxQUICAck(endpoint string, ack *txQUICAck, expectation txQUICAckExpectation) error {
	if ack == nil {
		return fmt.Errorf("nil txquic ack from %s", endpoint)
	}
	if ack.Version != txQUICPacketV2 {
		return fmt.Errorf("unsupported txquic ack version %d from %s", ack.Version, endpoint)
	}
	if ack.Accepted != ack.AcceptedTx+ack.AcceptedAdmission || ack.Rejected != ack.RejectedTx+ack.RejectedAdmission {
		return fmt.Errorf("inconsistent txquic ack counters from %s", endpoint)
	}
	if len(ack.Errors) > 0 {
		return fmt.Errorf("txquic ack errors from %s: %v", endpoint, ack.Errors)
	}
	if uint64(len(ack.Hashes)) != ack.AcceptedTx || uint64(len(ack.TransactionRejects)) != ack.RejectedTx {
		return fmt.Errorf("inconsistent txquic transaction result lengths from %s", endpoint)
	}
	if ack.AcceptedTx+ack.RejectedTx != uint64(len(expectation.txHashes)) {
		return fmt.Errorf("txquic ack did not process every expected transaction from %s: expected=%d accepted=%d rejected=%d forwarded=%d", endpoint, len(expectation.txHashes), ack.AcceptedTx, ack.RejectedTx, ack.Forwarded)
	}
	if ack.AcceptedAdmission+ack.RejectedAdmission != expectation.admissions {
		return fmt.Errorf("txquic ack did not process every expected admission from %s: expected=%d accepted=%d rejected=%d forwarded=%d", endpoint, expectation.admissions, ack.AcceptedAdmission, ack.RejectedAdmission, ack.Forwarded)
	}

	want := make(map[common.Hash]int, len(expectation.txHashes))
	for _, hash := range expectation.txHashes {
		want[hash]++
	}
	for _, hash := range ack.Hashes {
		if want[hash] == 0 {
			return fmt.Errorf("txquic ack contained unexpected transaction hash %s from %s", hash, endpoint)
		}
		want[hash]--
	}
	for _, reject := range ack.TransactionRejects {
		if want[reject.Hash] == 0 {
			return fmt.Errorf("txquic ack rejected unexpected transaction hash %s from %s", reject.Hash, endpoint)
		}
		if reject.Class != txQUICRejectPermanent && reject.Class != txQUICRejectRetryable {
			return fmt.Errorf("txquic ack used invalid rejection class %d for %s from %s", reject.Class, reject.Hash, endpoint)
		}
		if strings.TrimSpace(reject.Reason) == "" {
			return fmt.Errorf("txquic ack omitted rejection reason for %s from %s", reject.Hash, endpoint)
		}
		want[reject.Hash]--
	}
	for hash, count := range want {
		if count != 0 {
			return fmt.Errorf("txquic ack omitted expected transaction hash %s from %s", hash, endpoint)
		}
	}
	if ack.RejectedTx > 0 {
		return &txQUICRemoteRejectError{endpoint: endpoint, rejects: append([]txQUICTransactionReject(nil), ack.TransactionRejects...)}
	}
	if ack.RejectedAdmission > 0 {
		return fmt.Errorf("txquic remote admission rejected by %s: %d admission(s)", endpoint, ack.RejectedAdmission)
	}
	return nil
}

func writeFullTxQUIC(w io.Writer, payload []byte) error {
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

func (c *txQUICForwardClient) reset(conn *quic.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == conn {
		_ = c.conn.CloseWithError(0, "reset")
		c.conn = nil
	}
}

func (c *txQUICForwardClient) close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		_ = c.conn.CloseWithError(0, "closed")
		c.conn = nil
	}
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

func (q *TxQUICIngress) decodeAndAuthenticate(payload []byte) ([]*types.Transaction, []*types.CommonTxAdmission, bool, common.Address, error) {
	var pkt txQUICPacket
	if err := rlp.DecodeBytes(payload, &pkt); err == nil && len(pkt.Items) > 0 {
		if pkt.Version != txQUICPacketV2 {
			return nil, nil, false, common.Address{}, fmt.Errorf("unsupported txquic packet version %d", pkt.Version)
		}
		if isAdmissionOnlyPacket(&pkt) && len(pkt.Signature) == 0 {
			signer, err := verifyAdmissionOnlyPacket(&pkt)
			if err != nil {
				return nil, nil, false, common.Address{}, err
			}
			txs, admissions, err := packetItemsToTxsAndAdmissions(&pkt)
			return txs, admissions, false, signer, err
		}

		signer, err := q.verifyPacket(&pkt)
		if err != nil {
			return nil, nil, true, signer, err
		}
		txs, admissions, err := packetItemsToTxsAndAdmissions(&pkt)
		return txs, admissions, true, signer, err
	}

	if q.config.RequireAuth {
		return nil, nil, false, common.Address{}, fmt.Errorf("unsigned txquic payload rejected")
	}

	var batch []*types.Transaction
	if err := rlp.DecodeBytes(payload, &batch); err == nil {
		return batch, nil, false, common.Address{}, nil
	}

	var single types.Transaction
	if err := rlp.DecodeBytes(payload, &single); err != nil {
		return nil, nil, false, common.Address{}, err
	}
	return []*types.Transaction{&single}, nil, false, common.Address{}, nil
}

func isAdmissionOnlyPacket(pkt *txQUICPacket) bool {
	if pkt == nil || len(pkt.Items) == 0 {
		return false
	}
	for _, item := range pkt.Items {
		if item == nil || item.Tx != nil || item.Admission == nil {
			return false
		}
	}
	return true
}

func verifyAdmissionOnlyPacket(pkt *txQUICPacket) (common.Address, error) {
	var signer common.Address
	if pkt == nil || len(pkt.Items) == 0 {
		return common.Address{}, fmt.Errorf("empty admission-only packet")
	}
	for _, item := range pkt.Items {
		if item == nil {
			return common.Address{}, fmt.Errorf("nil admission-only item")
		}
		if item.Tx != nil {
			return common.Address{}, fmt.Errorf("admission-only packet contains tx")
		}
		if item.Admission == nil {
			return common.Address{}, fmt.Errorf("admission-only packet contains nil admission")
		}
		if err := types.VerifyCommonTxAdmissionSignature(item.Admission); err != nil {
			return common.Address{}, err
		}
		if signer == (common.Address{}) {
			signer = item.Admission.Miner
		}
	}
	if signer == (common.Address{}) {
		return common.Address{}, fmt.Errorf("admission-only packet has no signer")
	}
	return signer, nil
}

func packetItemsToTxsAndAdmissions(pkt *txQUICPacket) ([]*types.Transaction, []*types.CommonTxAdmission, error) {
	if pkt == nil || len(pkt.Items) == 0 {
		return nil, nil, fmt.Errorf("empty txquic packet items")
	}

	txs := make([]*types.Transaction, 0, len(pkt.Items))
	admissions := make([]*types.CommonTxAdmission, 0, len(pkt.Items))

	for i, item := range pkt.Items {
		if item == nil {
			return nil, nil, fmt.Errorf("nil txquic item at index %d", i)
		}
		if item.Tx == nil && item.Admission == nil {
			return nil, nil, fmt.Errorf("empty txquic item at index %d", i)
		}
		if item.Admission != nil {
			if err := types.VerifyCommonTxAdmissionSignature(item.Admission); err != nil {
				return nil, nil, fmt.Errorf("invalid admission at index %d: %w", i, err)
			}
		}
		if item.Tx != nil && item.Admission != nil {
			txHash := item.Tx.Hash()
			if txHash != item.Admission.TxHash {
				return nil, nil, fmt.Errorf("tx/admission mismatch at index %d: tx=%s admission=%s", i, txHash.Hex(), item.Admission.TxHash.Hex())
			}
		}
		if item.Tx != nil {
			txs = append(txs, item.Tx)
		}
		if item.Admission != nil {
			admissions = append(admissions, item.Admission)
		}
	}

	return txs, admissions, nil
}

func (q *TxQUICIngress) verifyPacket(pkt *txQUICPacket) (common.Address, error) {
	if !q.config.RequireAuth {
		return pkt.Sender, nil
	}
	if len(pkt.Signature) != crypto.SignatureLength {
		return common.Address{}, fmt.Errorf("invalid ingress signature length")
	}
	hash := pkt.signingHash()
	pub, err := crypto.SigToPub(hash.Bytes(), pkt.Signature)
	if err != nil {
		return common.Address{}, err
	}
	pubBytes := crypto.FromECDSAPub(pub)
	if len(pubBytes) == 0 {
		return common.Address{}, fmt.Errorf("invalid ingress signer pubkey")
	}
	signer := common.BytesToAddress(crypto.Keccak256(pubBytes[1:])[12:])
	if signer != pkt.Sender {
		return signer, fmt.Errorf("ingress signer mismatch")
	}
	if len(q.signers) > 0 {
		if _, ok := q.signers[signer]; !ok {
			return signer, fmt.Errorf("ingress signer not allowed")
		}
	}
	return signer, nil
}

func (p *txQUICPacket) signingPayload() ([]byte, error) {
	items := make([]txQUICSigningItem, 0, len(p.Items))
	for _, item := range p.Items {
		if item == nil {
			continue
		}

		var signingItem txQUICSigningItem
		if item.Tx != nil {
			signingItem.TxHash = item.Tx.Hash()
		}
		if item.Admission != nil {
			signingItem.AdmissionTxHash = item.Admission.TxHash
			signingItem.AdmissionMiner = item.Admission.Miner
		}
		items = append(items, signingItem)
	}
	return rlp.EncodeToBytes(txQUICSigningData{
		Version:   p.Version,
		Sender:    p.Sender,
		Nonce:     p.Nonce,
		Timestamp: p.Timestamp,
		Items:     items,
	})
}

func (p *txQUICPacket) signingHash() common.Hash {
	enc, _ := p.signingPayload()
	return crypto.Keccak256Hash(enc)
}

func (q *TxQUICIngress) writeAck(stream *quic.Stream, ack txQUICAck) {
	if !q.config.Ack {
		return
	}
	_ = stream.SetWriteDeadline(time.Now().Add(q.config.WriteTimeout))
	if err := rlp.Encode(stream, &ack); err != nil {
		log.Warn("TxQUIC ack encode failed", "accepted", ack.Accepted, "rejected", ack.Rejected, "forwarded", ack.Forwarded, "errors", ack.Errors, "err", err)
	}
}

func (q *TxQUICIngress) serverCertificate() (tls.Certificate, error) {
	if q.config.TLSCertFile != "" || q.config.TLSKeyFile != "" {
		if q.config.TLSCertFile == "" || q.config.TLSKeyFile == "" {
			return tls.Certificate{}, fmt.Errorf("txquic tls cert and key must both be set")
		}
		return tls.LoadX509KeyPair(q.config.TLSCertFile, q.config.TLSKeyFile)
	}
	return generateTxQUICSelfSignedCert()
}

func (q *TxQUICIngress) http3Certificate() (tls.Certificate, error) {
	if q.config.HTTP3CertFile != "" || q.config.HTTP3KeyFile != "" {
		if q.config.HTTP3CertFile == "" || q.config.HTTP3KeyFile == "" {
			return tls.Certificate{}, fmt.Errorf("http3 rpc cert and key must both be set")
		}
		return tls.LoadX509KeyPair(q.config.HTTP3CertFile, q.config.HTTP3KeyFile)
	}
	return q.serverCertificate()
}

func generateTxQUICSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{SerialNumber: mathbig.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func (q *TxQUICIngress) clientTLSConfig() *tls.Config {
	cfg := &tls.Config{NextProtos: []string{txQUICProtocolName}, MinVersion: tls.VersionTLS13, ServerName: q.config.ForwardServerName, InsecureSkipVerify: q.config.ForwardTLSInsecureSkipVerify}
	if q.config.ForwardTLSCAFile == "" {
		return cfg
	}
	pem, err := os.ReadFile(q.config.ForwardTLSCAFile)
	if err != nil {
		return cfg
	}
	pool := x509.NewCertPool()
	if pool.AppendCertsFromPEM(pem) {
		cfg.RootCAs = pool
	}
	return cfg
}

func (q *TxQUICIngress) parseAllowlist() {
	for _, entry := range q.config.AllowIPs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, ipnet, err := net.ParseCIDR(entry); err == nil {
				q.allowNets = append(q.allowNets, ipnet)
			}
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			q.allowIPs[ip.String()] = struct{}{}
		}
	}
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

func (q *TxQUICIngress) takeTokens(addr net.Addr, n int) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	q.rateMu.Lock()
	defer q.rateMu.Unlock()
	now := time.Now()
	b := q.buckets[host]
	if b == nil {
		b = &txQUICRateBucket{tokens: q.config.BurstTxsPerIP, last: now}
		q.buckets[host] = b
	}
	if refill := int(now.Sub(b.last).Seconds() * float64(q.config.MaxTxsPerIPPerSecond)); refill > 0 {
		b.tokens += refill
		if b.tokens > q.config.BurstTxsPerIP {
			b.tokens = q.config.BurstTxsPerIP
		}
		b.last = now
	}
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

func copyCommonTxAdmissionForQUIC(admission *types.CommonTxAdmission) *types.CommonTxAdmission {
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

// broadcastCommonTxAdmissionsDedicated is the admission-only dedicated dispatcher.
// QUIC admission-only forwarding is now handled by TxQUICIngress.ForwardAdmissions
// through core.SetCommonRPCAdmissionDedicatedRelay. If that path is unavailable,
// this dispatcher keeps KCP as the fallback dedicated admission transport.
func (pm *ProtocolManager) broadcastCommonTxAdmissionsDedicated(admissions []*types.CommonTxAdmission) bool {
	return pm.broadcastCommonTxAdmissionsKCPOnly(admissions)
}
