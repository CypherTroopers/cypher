// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

//go:build txquic
// +build txquic

package eth

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/rlp"
	quic "github.com/quic-go/quic-go"
)

const txQUICProtocolName = "cypher-tx-quic/1"

type txQUICRateBucket struct {
	tokens int
	last   time.Time
}

// TxQUICIngress receives signed transactions over QUIC and inserts them into the normal txpool.
// It does not replace TCP/RLPx header, body, block or peer sync.
type TxQUICIngress struct {
	config TxQUICConfig
	txpool *core.TxPool

	ctx    context.Context
	cancel context.CancelFunc

	listener *quic.Listener

	allowNets []*net.IPNet
	allowIPs  map[string]struct{}

	wg      sync.WaitGroup
	connSem chan struct{}

	rateMu  sync.Mutex
	buckets map[string]*txQUICRateBucket
}

func NewTxQUICIngress(config TxQUICConfig, txpool *core.TxPool) *TxQUICIngress {
	if config.Addr == "" {
		config.Addr = "0.0.0.0"
	}
	if config.Port == 0 {
		config.Port = 4444
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
	if config.MaxTxsPerIPPerSecond <= 0 {
		config.MaxTxsPerIPPerSecond = 2000
	}
	if config.BurstTxsPerIP <= 0 {
		config.BurstTxsPerIP = 4000
	}

	ctx, cancel := context.WithCancel(context.Background())
	q := &TxQUICIngress{
		config:   config,
		txpool:   txpool,
		ctx:      ctx,
		cancel:   cancel,
		connSem:  make(chan struct{}, config.MaxIncomingConns),
		buckets:  make(map[string]*txQUICRateBucket),
		allowIPs: make(map[string]struct{}),
	}
	q.parseAllowlist()
	return q
}

func (q *TxQUICIngress) Start() error {
	if !q.config.Enabled {
		return nil
	}
	if q.txpool == nil {
		return fmt.Errorf("txquic ingress requires txpool")
	}
	if q.config.TLSCertFile == "" || q.config.TLSKeyFile == "" {
		return fmt.Errorf("txquic requires txquic.tlscert and txquic.tlskey in production builds")
	}

	cert, err := tls.LoadX509KeyPair(q.config.TLSCertFile, q.config.TLSKeyFile)
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
		KeepAlivePeriod:   10 * time.Second,
		MaxIdleTimeout:    30 * time.Second,
	})
	if err != nil {
		return err
	}
	q.listener = listener

	log.Info("Started QUIC tx ingress", "addr", addr, "maxPayload", q.config.MaxPayload, "maxTxsPerBatch", q.config.MaxTxsPerBatch, "maxIncomingStreams", q.config.MaxIncomingStreams, "maxIncomingConns", q.config.MaxIncomingConns, "allowlist", len(q.config.AllowIPs))

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
			log.Debug("QUIC tx ingress rejected disallowed remote", "remote", remote)
			_ = conn.CloseWithError(1, "not allowed")
			continue
		}

		select {
		case q.connSem <- struct{}{}:
		default:
			log.Debug("QUIC tx ingress rejected connection, limit reached", "remote", remote)
			_ = conn.CloseWithError(2, "too many connections")
			continue
		}

		q.wg.Add(1)
		go q.handleConn(conn)
	}
}

func (q *TxQUICIngress) handleConn(conn quic.Connection) {
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
		q.wg.Add(1)
		go q.handleStream(remote, stream)
	}
}

func (q *TxQUICIngress) handleStream(remote net.Addr, stream quic.Stream) {
	defer q.wg.Done()
	defer stream.Close()

	_ = stream.SetReadDeadline(time.Now().Add(q.config.ReadTimeout))
	payload, err := io.ReadAll(io.LimitReader(stream, q.config.MaxPayload+1))
	if err != nil {
		log.Debug("QUIC tx ingress read failed", "remote", remote, "err", err)
		return
	}
	if int64(len(payload)) > q.config.MaxPayload {
		log.Debug("QUIC tx ingress payload too large", "remote", remote, "size", len(payload), "limit", q.config.MaxPayload)
		return
	}
	if len(payload) == 0 {
		return
	}

	txs, err := q.decodePayload(payload)
	if err != nil {
		log.Debug("QUIC tx ingress decode failed", "remote", remote, "err", err, "size", len(payload))
		return
	}
	if len(txs) == 0 {
		return
	}
	if len(txs) > q.config.MaxTxsPerBatch {
		log.Debug("QUIC tx ingress batch too large", "remote", remote, "count", len(txs), "limit", q.config.MaxTxsPerBatch)
		return
	}
	if !q.takeTokens(remote, len(txs)) {
		log.Debug("QUIC tx ingress rate limited", "remote", remote, "count", len(txs))
		return
	}

	errs := q.txpool.AddRemotes(txs)
	accepted, rejected := 0, 0
	for _, err := range errs {
		if err == nil {
			accepted++
		} else {
			rejected++
		}
	}
	log.Debug("QUIC tx ingress processed tx batch", "remote", remote, "accepted", accepted, "rejected", rejected)
}

func (q *TxQUICIngress) decodePayload(payload []byte) ([]*types.Transaction, error) {
	var batch []*types.Transaction
	if err := rlp.DecodeBytes(payload, &batch); err == nil {
		return batch, nil
	}

	var single types.Transaction
	if err := rlp.DecodeBytes(payload, &single); err != nil {
		return nil, err
	}
	return []*types.Transaction{&single}, nil
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
			} else {
				log.Warn("Invalid txquic allow CIDR ignored", "entry", entry, "err", err)
			}
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			log.Warn("Invalid txquic allow IP ignored", "entry", entry)
			continue
		}
		q.allowIPs[ip.String()] = struct{}{}
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
