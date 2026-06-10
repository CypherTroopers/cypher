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
	txQUICProtocolName = "cypher-tx-quic/1"
	txQUICPacketV1     = uint(1)
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

type txQUICPacket struct {
	Version    uint
	Sender     common.Address
	Nonce      uint64
	Timestamp  uint64
	Txs        []*types.Transaction
	Admissions []*types.CommonTxAdmission
	Signature  []byte
}

type txQUICSigningData struct {
	Version         uint
	Sender          common.Address
	Nonce           uint64
	Timestamp       uint64
	TxHashes        []common.Hash
	AdmissionHashes []common.Hash
	AdmissionMiners []common.Address
}

type txQUICAck struct {
	Version   uint
	Accepted  uint64
	Rejected  uint64
	Forwarded uint64
	Errors    []string
	Hashes    []common.Hash
}

type txQUICBridgeItem struct {
	tx        *types.Transaction
	admission *types.CommonTxAdmission
	am        *accounts.Manager
}

type txQUICAdmissionItem struct {
	admission *types.CommonTxAdmission
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
		config.MaxTxsPerIPPerSecond = 2000
	}
	if config.BurstTxsPerIP <= 0 {
		config.BurstTxsPerIP = 4000
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
	addr := fmt.Sprintf("%s:%d", q.config.Addr, q.config.Port)
	listener, err := quic.ListenAddr(addr, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{txQUICProtocolName}, MinVersion: tls.VersionTLS13}, &quic.Config{MaxIncomingStreams: q.config.MaxIncomingStreams, KeepAlivePeriod: 10 * time.Second, MaxIdleTimeout: 30 * time.Second})
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
	q.wg.Wait()
	log.Info("Stopped QUIC tx ingress")
}

func (q *TxQUICIngress) ForwardLocalTxs(txs []*types.Transaction, am *accounts.Manager) {
	q.ForwardLocalTxsWithAdmissions(txs, nil, am)
}

func (q *TxQUICIngress) ForwardLocalTxsWithAdmissions(txs []*types.Transaction, admissions []*types.CommonTxAdmission, am *accounts.Manager) {
	if q == nil || !q.config.BridgeEnabled || len(txs) == 0 || q.bridgeQueue == nil {
		return
	}

	admissionByTx := make(map[common.Hash]*types.CommonTxAdmission)
	for _, admission := range admissions {
		if admission == nil {
			continue
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
			log.Warn("Skip invalid TxQUIC admission sidecar before queue", "tx", admission.TxHash, "miner", admission.Miner, "err", err)
			continue
		}
		admissionByTx[admission.TxHash] = copyCommonTxAdmissionForQUIC(admission)
	}

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
		default:
			txQUICIngressRejectedMeter.Mark(1)
			log.Warn("TxQUIC bridge queue full, dropping tx forward", "hash", hash, "hasAdmission", item.admission != nil, "queue", q.config.BridgeQueueSize)
		}
	}
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
		default:
			txQUICIngressRejectedMeter.Mark(1)
			log.Warn("TxQUIC admission queue full, dropping admission forward only", "tx", admission.TxHash, "miner", admission.Miner, "queue", q.config.BridgeQueueSize)
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
		q.forwardBridgeBatch(txs, admissions, am)
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

func (q *TxQUICIngress) forwardBridgeBatch(txs []*types.Transaction, admissions []*types.CommonTxAdmission, am *accounts.Manager) {
	payload, err := q.encodeTxPayload(txs, admissions, am)
	if err != nil {
		log.Debug("TxQUIC bridge encode failed", "err", err, "txs", len(txs), "admissions", len(admissions))
		return
	}
	forwarded := q.routePayload(payload)
	if forwarded > 0 {
		txQUICIngressForwardMeter.Mark(int64(forwarded))
	}
	log.Debug("TxQUIC bridge forwarded tx batch", "txs", len(txs), "admissions", len(admissions), "forwarded", forwarded)
}

func (q *TxQUICIngress) forwardAdmissionBatch(admissions []*types.CommonTxAdmission) {
	payload, err := q.encodeAdmissionPayload(admissions)
	if err != nil {
		log.Debug("TxQUIC admission encode failed", "err", err, "admissions", len(admissions))
		return
	}
	forwarded := q.routePayload(payload)
	if forwarded > 0 {
		txQUICIngressForwardMeter.Mark(int64(forwarded))
	}
	log.Debug("TxQUIC bridge forwarded admission batch", "admissions", len(admissions), "forwarded", forwarded)
}

func (q *TxQUICIngress) encodeTxPayload(txs []*types.Transaction, admissions []*types.CommonTxAdmission, am *accounts.Manager) ([]byte, error) {
	validAdmissions := make([]*types.CommonTxAdmission, 0, len(admissions))
	for _, admission := range admissions {
		if admission == nil {
			continue
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
			log.Warn("Skip invalid TxQUIC admission sidecar before forward", "tx", admission.TxHash, "miner", admission.Miner, "err", err)
			continue
		}
		validAdmissions = append(validAdmissions, copyCommonTxAdmissionForQUIC(admission))
	}

	if !q.config.RequireAuth && len(validAdmissions) == 0 {
		return rlp.EncodeToBytes(txs)
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
		Version:    txQUICPacketV1,
		Sender:     sender,
		Nonce:      atomic.AddUint64(&q.outboundNonce, 1),
		Timestamp:  uint64(time.Now().Unix()),
		Txs:        txs,
		Admissions: validAdmissions,
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
	valid := make([]*types.CommonTxAdmission, 0, len(admissions))
	for _, admission := range admissions {
		if admission == nil {
			continue
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
			log.Warn("Skip invalid TxQUIC admission before forward", "tx", admission.TxHash, "miner", admission.Miner, "err", err)
			continue
		}
		valid = append(valid, copyCommonTxAdmissionForQUIC(admission))
	}
	if len(valid) == 0 {
		return nil, fmt.Errorf("no valid admissions to forward")
	}
	pkt := &txQUICPacket{Version: txQUICPacketV1, Nonce: atomic.AddUint64(&q.outboundNonce, 1), Timestamp: uint64(time.Now().Unix()), Admissions: valid}
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
	addr := fmt.Sprintf("%s:%d", q.config.HTTP3Addr, q.config.HTTP3Port)
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
	ack := txQUICAck{Version: txQUICPacketV1}
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
	if !q.takeTokens(remote, len(txs)+len(admissions)) {
		ack.Errors = append(ack.Errors, "rate limited")
		log.Warn("TxQUIC rate limited", "remote", remote, "txs", len(txs), "admissions", len(admissions))
		q.writeAck(stream, ack)
		return
	}
	forwarded := q.routePayload(payload)
	acceptedAdmission, rejectedAdmission := q.insertAdmissions(admissions)
	acceptedTx, rejectedTx, hashes := q.insertLocal(txs)
	ack.Forwarded = uint64(forwarded)
	ack.Accepted = uint64(acceptedTx + acceptedAdmission)
	ack.Rejected = uint64(rejectedTx + rejectedAdmission)
	ack.Hashes = hashes
	if ack.Accepted > 0 {
		txQUICIngressAcceptedMeter.Mark(int64(ack.Accepted))
	}
	if ack.Rejected > 0 {
		txQUICIngressRejectedMeter.Mark(int64(ack.Rejected))
	}
	if ack.Forwarded > 0 {
		txQUICIngressForwardMeter.Mark(int64(ack.Forwarded))
	}
	log.Debug("QUIC ingress processed", "remote", remote, "signed", signed, "signer", signer, "txs", len(txs), "admissions", len(admissions), "accepted", ack.Accepted, "rejected", ack.Rejected, "forwarded", ack.Forwarded)
	q.writeAck(stream, ack)
}

func (q *TxQUICIngress) insertLocal(txs []*types.Transaction) (int, int, []common.Hash) {
	if len(txs) == 0 {
		return 0, 0, nil
	}
	mode := strings.ToLower(q.config.RoutingMode)
	if mode == "leader-only" && len(q.config.LeaderEndpoints) > 0 {
		return 0, 0, nil
	}
	errs := q.txpool.AddRemotes(txs)
	accepted, rejected := 0, 0
	hashes := make([]common.Hash, 0, len(txs))
	for i, err := range errs {
		if err == nil {
			accepted++
			hashes = append(hashes, txs[i].Hash())
		} else {
			rejected++
		}
	}
	return accepted, rejected, hashes
}

func (q *TxQUICIngress) insertAdmissions(admissions []*types.CommonTxAdmission) (int, int) {
	accepted, rejected := 0, 0
	for _, admission := range admissions {
		if admission == nil {
			continue
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
			rejected++
			log.Warn("Rejected invalid TxQUIC admission", "tx", admission.TxHash, "miner", admission.Miner, "err", err)
			continue
		}
		if core.StoreCommonRPCAdmission(admission) {
			accepted++
		}
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

func (q *TxQUICIngress) forwardPayload(endpoint string, payload []byte) error {
	timeout := endpointForwardTimeout(q.config.ForwardTimeout, q.config.ReadTimeout, q.config.WriteTimeout)
	ctx, cancel := context.WithTimeout(q.ctx, timeout)
	defer cancel()
	conn, err := quic.DialAddr(ctx, endpoint, q.clientTLSConfig(), &quic.Config{MaxIdleTimeout: timeout})
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "done")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	_ = stream.SetWriteDeadline(time.Now().Add(q.config.WriteTimeout))
	if _, err := stream.Write(payload); err != nil {
		_ = stream.Close()
		return err
	}
	if err := stream.Close(); err != nil {
		return err
	}
	if !q.config.Ack {
		return nil
	}
	_ = stream.SetReadDeadline(time.Now().Add(q.config.ReadTimeout))
	var ack txQUICAck
	if err := rlp.Decode(stream, &ack); err != nil {
		return fmt.Errorf("txquic ack read failed from %s: %w", endpoint, err)
	}
	if len(ack.Errors) > 0 {
		return fmt.Errorf("txquic ack errors from %s: %v", endpoint, ack.Errors)
	}
	if ack.Accepted == 0 && ack.Forwarded == 0 {
		return fmt.Errorf("txquic ack no accepted/forwarded from %s: accepted=%d rejected=%d forwarded=%d", endpoint, ack.Accepted, ack.Rejected, ack.Forwarded)
	}
	return nil
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
	if err := rlp.DecodeBytes(payload, &pkt); err == nil && pkt.Version == txQUICPacketV1 && (len(pkt.Txs) > 0 || len(pkt.Admissions) > 0) {
		if len(pkt.Txs) == 0 && len(pkt.Admissions) > 0 && len(pkt.Signature) == 0 {
			signer, err := verifyAdmissionOnlyPacket(&pkt)
			return nil, pkt.Admissions, false, signer, err
		}
		signer, err := q.verifyPacket(&pkt)
		return pkt.Txs, pkt.Admissions, true, signer, err
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

func verifyAdmissionOnlyPacket(pkt *txQUICPacket) (common.Address, error) {
	var signer common.Address
	for _, admission := range pkt.Admissions {
		if admission == nil {
			continue
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
			return common.Address{}, err
		}
		if signer == (common.Address{}) {
			signer = admission.Miner
		}
	}
	return signer, nil
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
	hashes := make([]common.Hash, 0, len(p.Txs))
	for _, tx := range p.Txs {
		if tx != nil {
			hashes = append(hashes, tx.Hash())
		}
	}
	admissionHashes := make([]common.Hash, 0, len(p.Admissions))
	admissionMiners := make([]common.Address, 0, len(p.Admissions))
	for _, admission := range p.Admissions {
		if admission != nil {
			admissionHashes = append(admissionHashes, admission.TxHash)
			admissionMiners = append(admissionMiners, admission.Miner)
		}
	}
	return rlp.EncodeToBytes(txQUICSigningData{Version: p.Version, Sender: p.Sender, Nonce: p.Nonce, Timestamp: p.Timestamp, TxHashes: hashes, AdmissionHashes: admissionHashes, AdmissionMiners: admissionMiners})
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
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
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
