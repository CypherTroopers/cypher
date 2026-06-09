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
	"fmt"
	"io"
	mathbig "math/big"
	"net"
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
	Version   uint
	Sender    common.Address
	Nonce     uint64
	Timestamp uint64
	Txs       []*types.Transaction
	Signature []byte
}

type txQUICSigningData struct {
	Version   uint
	Sender    common.Address
	Nonce     uint64
	Timestamp uint64
	TxHashes  []common.Hash
}

type txQUICAck struct {
	Version   uint
	Accepted  int
	Rejected  int
	Forwarded int
	Errors    []string
	Hashes    []common.Hash
}

type TxQUICIngress struct {
	config TxQUICConfig
	txpool *core.TxPool

	ctx    context.Context
	cancel context.CancelFunc

	listener *quic.Listener

	allowNets []*net.IPNet
	allowIPs  map[string]struct{}
	signers   map[common.Address]struct{}

	wg      sync.WaitGroup
	connSem chan struct{}

	rateMu  sync.Mutex
	buckets map[string]*txQUICRateBucket

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
		config.Port = localRnetPort + config.PortOffset
		config.RoutingMode = "local"
		config.LeaderEndpoints = nil
		config.BackupEndpoints = nil
		log.Info("TxQUIC auto role: validator ingress", "committeeIndex", localIndex, "rnetPort", localRnetPort, "txquicPort", config.Port)
		return
	}
	config.Enabled = false
	config.BridgeEnabled = true
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
	log.Info("TxQUIC auto role: common RPC bridge", "leaders", config.LeaderEndpoints, "backups", len(config.BackupEndpoints))
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

func (q *TxQUICIngress) Start() error {
	if !q.config.Enabled {
		if q.config.BridgeEnabled {
			log.Info("TxQUIC bridge enabled", "routing", q.config.RoutingMode, "leaders", len(q.config.LeaderEndpoints), "backups", len(q.config.BackupEndpoints))
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
	listener, err := quic.ListenAddr(addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{txQUICProtocolName},
		MinVersion:   tls.VersionTLS13,
	}, &quic.Config{
		MaxIncomingStreams: q.config.MaxIncomingStreams,
		KeepAlivePeriod:    10 * time.Second,
		MaxIdleTimeout:     30 * time.Second,
	})
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
	q.wg.Wait()
	log.Info("Stopped QUIC tx ingress")
}

func (q *TxQUICIngress) ForwardLocalTxs(txs []*types.Transaction, am *accounts.Manager) {
	if q == nil || !q.config.BridgeEnabled || len(txs) == 0 {
		return
	}
	payload, err := q.encodeOutboundPayload(txs, am)
	if err != nil {
		log.Debug("TxQUIC bridge encode failed", "err", err, "txs", len(txs))
		return
	}
	go func() {
		forwarded := q.routePayload(payload)
		if forwarded > 0 {
			txQUICIngressForwardMeter.Mark(int64(forwarded))
		}
		log.Debug("TxQUIC bridge forwarded txs", "txs", len(txs), "forwarded", forwarded)
	}()
}

func (q *TxQUICIngress) encodeOutboundPayload(txs []*types.Transaction, am *accounts.Manager) ([]byte, error) {
	if !q.config.RequireAuth {
		return rlp.EncodeToBytes(txs)
	}
	sender := bftview.GetServerCoinBase()
	if sender == (common.Address{}) {
		return nil, fmt.Errorf("txquic bridge signer coinbase is empty")
	}
	if am == nil {
		return nil, fmt.Errorf("txquic bridge account manager is nil")
	}
	pkt := &txQUICPacket{
		Version:   txQUICPacketV1,
		Sender:    sender,
		Nonce:     atomic.AddUint64(&q.outboundNonce, 1),
		Timestamp: uint64(time.Now().Unix()),
		Txs:       txs,
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
	defer func() {
		<-q.connSem
		_ = conn.CloseWithError(0, "closed")
	}()
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
		q.writeAck(stream, ack)
		return
	}
	if int64(len(payload)) > q.config.MaxPayload {
		ack.Errors = append(ack.Errors, "payload too large")
		q.writeAck(stream, ack)
		return
	}

	txs, signed, signer, err := q.decodeAndAuthenticate(payload)
	if err != nil {
		txQUICIngressAuthFailMeter.Mark(1)
		ack.Errors = append(ack.Errors, err.Error())
		q.writeAck(stream, ack)
		return
	}
	if len(txs) == 0 {
		ack.Errors = append(ack.Errors, "empty tx batch")
		q.writeAck(stream, ack)
		return
	}
	if len(txs) > q.config.MaxTxsPerBatch {
		ack.Errors = append(ack.Errors, "batch too large")
		q.writeAck(stream, ack)
		return
	}
	if !q.takeTokens(remote, len(txs)) {
		ack.Errors = append(ack.Errors, "rate limited")
		q.writeAck(stream, ack)
		return
	}

	ack.Forwarded = q.routePayload(payload)
	accepted, rejected, hashes := q.insertLocal(txs)
	ack.Accepted = accepted
	ack.Rejected = rejected
	ack.Hashes = hashes

	if accepted > 0 {
		txQUICIngressAcceptedMeter.Mark(int64(accepted))
	}
	if rejected > 0 {
		txQUICIngressRejectedMeter.Mark(int64(rejected))
	}
	if ack.Forwarded > 0 {
		txQUICIngressForwardMeter.Mark(int64(ack.Forwarded))
	}
	log.Debug("QUIC tx ingress processed", "remote", remote, "signed", signed, "signer", signer, "accepted", accepted, "rejected", rejected, "forwarded", ack.Forwarded)
	q.writeAck(stream, ack)
}

func (q *TxQUICIngress) insertLocal(txs []*types.Transaction) (int, int, []common.Hash) {
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
		if q.forwardPayload(endpoint, payload) == nil {
			forwarded++
		}
	}
	return forwarded
}

func (q *TxQUICIngress) forwardPayload(endpoint string, payload []byte) error {
	ctx, cancel := context.WithTimeout(q.ctx, q.config.ForwardTimeout)
	defer cancel()
	conn, err := quic.DialAddr(ctx, endpoint, q.clientTLSConfig(), &quic.Config{MaxIdleTimeout: q.config.ForwardTimeout})
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "done")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()
	_ = stream.SetWriteDeadline(time.Now().Add(q.config.WriteTimeout))
	_, err = stream.Write(payload)
	return err
}

func (q *TxQUICIngress) decodeAndAuthenticate(payload []byte) ([]*types.Transaction, bool, common.Address, error) {
	var pkt txQUICPacket
	if err := rlp.DecodeBytes(payload, &pkt); err == nil && pkt.Version == txQUICPacketV1 && len(pkt.Txs) > 0 {
		signer, err := q.verifyPacket(&pkt)
		return pkt.Txs, true, signer, err
	}
	if q.config.RequireAuth {
		return nil, false, common.Address{}, fmt.Errorf("unsigned txquic payload rejected")
	}
	var batch []*types.Transaction
	if err := rlp.DecodeBytes(payload, &batch); err == nil {
		return batch, false, common.Address{}, nil
	}
	var single types.Transaction
	if err := rlp.DecodeBytes(payload, &single); err != nil {
		return nil, false, common.Address{}, err
	}
	return []*types.Transaction{&single}, false, common.Address{}, nil
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
	return rlp.EncodeToBytes(txQUICSigningData{Version: p.Version, Sender: p.Sender, Nonce: p.Nonce, Timestamp: p.Timestamp, TxHashes: hashes})
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
	_ = rlp.Encode(stream, &ack)
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
