package eth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/ethdb/memorydb"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
	rnetnetwork "github.com/cypherium/cypher/rnet/network"
	quic "github.com/quic-go/quic-go"
)

const testTxQUICKeyNumber uint64 = 7

func testTxQUICCommitteeHash() common.Hash {
	return common.HexToHash("0xa91ad4b707f980bdf13a3f211c779a027821992078a9c605c2387fa12c43d919")
}

func testTxQUICTLSState(t *testing.T, rawCertificates [][]byte) tls.ConnectionState {
	t.Helper()
	certificates := make([]*x509.Certificate, 0, len(rawCertificates))
	for _, raw := range rawCertificates {
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			t.Fatal(err)
		}
		certificates = append(certificates, certificate)
	}
	return tls.ConnectionState{PeerCertificates: certificates}
}

func testTxQUICConfig() TxQUICConfig {
	return TxQUICConfig{
		ChainID:                  1337,
		GenesisHash:              common.HexToHash("0x77c3eab91cb1d386f0946ef6bf4bb723dd47f962f2588ab573f9441f2c681c5b"),
		ReplayWindow:             64,
		MaxClockSkew:             time.Minute,
		MaxPacketAge:             time.Hour,
		NonceReservation:         4,
		IngressCommitInterval:    5 * time.Millisecond,
		IngressCommitMaxRequests: 16,
		IngressCommitMaxBytes:    4 << 20,
		IngressAckRetention:      time.Hour,
		OutboxMaxRecords:         32,
		OutboxMaxBytes:           16 << 20,
		OutboxWorkers:            1,
		OutboxRetryMin:           5 * time.Millisecond,
		OutboxRetryMax:           20 * time.Millisecond,
		BridgeQueueSize:          1024,
		BridgeQueueMaxBytes:      8 << 20,
		BridgeWorkers:            1,
		BridgeBatchInterval:      20 * time.Millisecond,
	}
}

func enableTestTxQUICBackgroundHandoff(t *testing.T, q *TxQUICIngress) {
	t.Helper()
	q.backgroundForwardMu.Lock()
	q.backgroundForwardAccepting = true
	q.backgroundForwardMu.Unlock()
	t.Cleanup(func() {
		q.backgroundForwardMu.Lock()
		q.backgroundForwardAccepting = false
		q.backgroundForwardMu.Unlock()
	})
}

func testTxQUICTransaction(nonce uint64, dataBytes int) *types.Transaction {
	return types.NewTransaction(
		nonce,
		common.HexToAddress("0x1000000000000000000000000000000000000001"),
		big.NewInt(int64(nonce+1)),
		100_000,
		big.NewInt(1),
		make([]byte, dataBytes),
	)
}

func testTxQUICNativeTransaction(payer common.Address, sequence uint64, tag byte) *types.Transaction {
	return types.NewTx(&types.NativeTxV1{
		ChainID:               big.NewInt(1337),
		RecentBlockHash:       common.HexToHash("0x01"),
		RecentBlockNumber:     1,
		ValidUntil:            10,
		Payer:                 payer,
		ReplaySequence:        sequence,
		To:                    payer,
		Value:                 new(big.Int),
		Data:                  []byte{tag},
		MaxFeePerCompute:      big.NewInt(10),
		PriorityFeePerCompute: big.NewInt(1),
		ComputeLimit:          100_000,
		MemoryLimit:           1 << 20,
		LogLimit:              1 << 10,
		OutputLimit:           1 << 10,
		Accesses: []types.NativeAccess{{
			Resource: types.NativeResource{Kind: types.NativeResourceAccount, Address: payer},
			Mode:     types.NativeAccessWrite,
		}},
		V: new(big.Int), R: new(big.Int), S: new(big.Int),
	})
}

type testTxQUICPoolChain struct {
	block *types.Block
	state *state.StateDB
}

func (chain *testTxQUICPoolChain) CurrentBlock() *types.Block {
	return chain.block
}

func (chain *testTxQUICPoolChain) GetBlock(hash common.Hash, number uint64) *types.Block {
	if chain.block.Hash() == hash && chain.block.NumberU64() == number {
		return chain.block
	}
	return nil
}

func (chain *testTxQUICPoolChain) StateAt(common.Hash) (*state.StateDB, error) {
	return chain.state, nil
}

func (chain *testTxQUICPoolChain) SubscribeChainHeadEvent(chan<- core.ChainHeadEvent) event.Subscription {
	return event.NewSubscription(func(quit <-chan struct{}) error {
		<-quit
		return nil
	})
}

func testTxQUICItems(txs ...*types.Transaction) []*txQUICItem {
	items := make([]*txQUICItem, len(txs))
	for index, tx := range txs {
		items[index] = &txQUICItem{AdmissionIndex: uint16(index), Tx: tx}
	}
	return items
}

func testTxQUICCertificate(t *testing.T, config TxQUICConfig, txs ...*types.Transaction) *types.CommonTxAdmissionBatch {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	hashes := make([]common.Hash, len(txs))
	for index, tx := range txs {
		hashes[index] = tx.Hash()
	}
	certificate := &types.CommonTxAdmissionBatch{
		ChainID:        new(big.Int).SetUint64(config.ChainID),
		GenesisHash:    config.GenesisHash,
		Miner:          crypto.PubkeyToAddress(key.PublicKey),
		KeyBlockNumber: testTxQUICKeyNumber,
		Timestamp:      uint64(time.Now().Unix()),
		TxHashes:       hashes,
	}
	certificate.TxRoot = types.DeriveCommonTxAdmissionTxRoot(certificate.TxHashes)
	certificate.AdmissionID = types.CommonTxAdmissionID(certificate)
	certificate.Signature, err = crypto.Sign(types.CommonTxAdmissionSigningHash(certificate).Bytes(), key)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func testTxQUICAdmissionResults(t *testing.T, config TxQUICConfig, txs ...*types.Transaction) []core.CommonRPCAdmissionResult {
	t.Helper()
	certificate := testTxQUICCertificate(t, config, txs...)
	results := make([]core.CommonRPCAdmissionResult, len(txs))
	for index := range txs {
		results[index] = core.CommonRPCAdmissionResult{Batch: certificate, Item: uint16(index), Updated: true}
	}
	return results
}

func testTxQUICBatch(t *testing.T, config TxQUICConfig, txs ...*types.Transaction) *txQUICBatch {
	t.Helper()
	batch, _, err := newTxQUICBatch(config.ChainID, config.GenesisHash, testTxQUICCertificate(t, config, txs...), testTxQUICItems(txs...))
	if err != nil {
		t.Fatal(err)
	}
	return batch
}

func testTxQUICPacketFromBatch(config TxQUICConfig, batch *txQUICBatch, sender common.Address, nonce, timestamp uint64) *txQUICPacket {
	return &txQUICPacket{
		ChainID:       config.ChainID,
		GenesisHash:   config.GenesisHash,
		KeyNumber:     testTxQUICKeyNumber,
		CommitteeHash: testTxQUICCommitteeHash(),
		BatchID:       batch.BatchID,
		Sender:        sender,
		SenderEpoch:   txQUICSenderEpoch(config.ChainID, config.GenesisHash, sender),
		Nonce:         nonce,
		Timestamp:     timestamp,
		TxRoot:        batch.TxRoot,
		Certificate:   copyCommonTxAdmissionBatchForQUIC(batch.Certificate),
		Items:         batch.Items,
	}
}

func testTxQUICPacket(t *testing.T, config TxQUICConfig, sender common.Address, nonce uint64, txs ...*types.Transaction) *txQUICPacket {
	t.Helper()
	return testTxQUICPacketFromBatch(config, testTxQUICBatch(t, config, txs...), sender, nonce, uint64(time.Now().Unix()))
}

func testTxQUICAck(t *testing.T, packet *txQUICPacket, durable, retryable []int, permanent []txQUICPermanentError) txQUICAck {
	t.Helper()
	expectation, err := newTxQUICAckExpectation(packet)
	if err != nil {
		t.Fatal(err)
	}
	ack := txQUICAck{
		ChainID:         expectation.chainID,
		GenesisHash:     expectation.genesisHash,
		KeyNumber:       expectation.keyNumber,
		CommitteeHash:   expectation.committeeHash,
		BatchID:         expectation.batchID,
		Sender:          expectation.sender,
		SenderEpoch:     expectation.senderEpoch,
		Nonce:           expectation.nonce,
		ItemCount:       uint32(len(expectation.itemIDs)),
		DurableBitmap:   make([]byte, txQUICBitmapBytes(len(expectation.itemIDs))),
		RetryableBitmap: make([]byte, txQUICBitmapBytes(len(expectation.itemIDs))),
		PermanentErrors: append([]txQUICPermanentError(nil), permanent...),
	}
	for _, index := range durable {
		txQUICBitmapSet(ack.DurableBitmap, index)
	}
	for _, index := range retryable {
		txQUICBitmapSet(ack.RetryableBitmap, index)
	}
	return ack
}

func cloneTxQUICAck(ack txQUICAck) txQUICAck {
	ack.DurableBitmap = append([]byte(nil), ack.DurableBitmap...)
	ack.RetryableBitmap = append([]byte(nil), ack.RetryableBitmap...)
	ack.PermanentErrors = append([]txQUICPermanentError(nil), ack.PermanentErrors...)
	ack.CommitteePublicKey = append([]byte(nil), ack.CommitteePublicKey...)
	ack.Signature = append([]byte(nil), ack.Signature...)
	return ack
}

func testTxQUICReceipt(endpoint string, committeePublicKey []byte, ack txQUICAck) *txQUICAckReceipt {
	identity := sha256.Sum256(committeePublicKey)
	ack = cloneTxQUICAck(ack)
	ack.CommitteePublicKey = append([]byte(nil), committeePublicKey...)
	return &txQUICAckReceipt{
		Endpoint: endpoint,
		Identity: common.BytesToHash(identity[:]),
		Ack:      ack,
	}
}

func TestTxQUICClientTLSConfigFailsClosedWithoutCommitteeIdentity(t *testing.T) {
	ingress := &TxQUICIngress{}
	config, err := ingress.clientTLSConfig(nil, nil)
	if err == nil || config != nil {
		t.Fatal("clientTLSConfig accepted a missing committee identity")
	}
}

func TestTxQUICClientTLSConfigVerifiesCommitteeAttestation(t *testing.T) {
	config := testTxQUICConfig()
	identity, _, err := txQUICTLSIdentityPayload(config, testTxQUICKeyNumber, testTxQUICCommitteeHash(), "192.0.2.10:4444")
	if err != nil {
		t.Fatal(err)
	}
	secret := new(bls.SecretKey)
	secret.SetByCSPRNG()
	publicKey := secret.GetPublicKey().Serialize()
	certificate, err := rnetnetwork.GenerateBLSTLSCertificate(txQUICTLSIdentityDomain, identity, publicKey, func(digest []byte) ([]byte, error) {
		return secret.SignHash(digest).Serialize(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ingress := &TxQUICIngress{config: config}
	tlsConfig, err := ingress.clientTLSConfig(identity, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 || !tlsConfig.InsecureSkipVerify || tlsConfig.VerifyConnection == nil || !tlsConfig.SessionTicketsDisabled {
		t.Fatal("client TLS config did not install the mandatory TLS 1.3 BLS verifier")
	}
	if len(tlsConfig.NextProtos) != 1 || tlsConfig.NextProtos[0] != txQUICProtocolName {
		t.Fatalf("ALPN protocols = %v, want [%q]", tlsConfig.NextProtos, txQUICProtocolName)
	}
	if err := tlsConfig.VerifyConnection(testTxQUICTLSState(t, certificate.Certificate)); err != nil {
		t.Fatalf("valid committee-attested certificate rejected: %v", err)
	}

	otherIdentity, _, err := txQUICTLSIdentityPayload(config, testTxQUICKeyNumber+1, testTxQUICCommitteeHash(), "192.0.2.10:4444")
	if err != nil {
		t.Fatal(err)
	}
	mismatchConfig, err := ingress.clientTLSConfig(otherIdentity, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := mismatchConfig.VerifyConnection(testTxQUICTLSState(t, certificate.Certificate)); err == nil {
		t.Fatal("certificate from another committee generation was accepted")
	}

	attacker := new(bls.SecretKey)
	attacker.SetByCSPRNG()
	attackerPublic := attacker.GetPublicKey().Serialize()
	attackerCertificate, err := rnetnetwork.GenerateBLSTLSCertificate(txQUICTLSIdentityDomain, identity, attackerPublic, func(digest []byte) ([]byte, error) {
		return attacker.SignHash(digest).Serialize(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tlsConfig.VerifyConnection(testTxQUICTLSState(t, attackerCertificate.Certificate)); err == nil {
		t.Fatal("certificate attested by a non-committee key was accepted")
	}
}

func TestTxQUICHandshakeRejectsWrongCommitteeCertificateBeforeAccept(t *testing.T) {
	config := testTxQUICConfig()
	identity, _, err := txQUICTLSIdentityPayload(config, testTxQUICKeyNumber, testTxQUICCommitteeHash(), "127.0.0.1:4444")
	if err != nil {
		t.Fatal(err)
	}
	committee := new(bls.SecretKey)
	committee.SetByCSPRNG()
	committeePublic := committee.GetPublicKey().Serialize()
	attacker := new(bls.SecretKey)
	attacker.SetByCSPRNG()
	attackerPublic := attacker.GetPublicKey().Serialize()
	attackerCertificate, err := rnetnetwork.GenerateBLSTLSCertificate(txQUICTLSIdentityDomain, identity, attackerPublic, func(digest []byte) ([]byte, error) {
		return attacker.SignHash(digest).Serialize(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates:           []tls.Certificate{attackerCertificate},
		NextProtos:             []string{txQUICProtocolName},
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
	}, &quic.Config{HandshakeIdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	clientTLS, err := (&TxQUICIngress{config: config}).clientTLSConfig(identity, committeePublic)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	accepted := make(chan *quic.Conn, 1)
	go func() {
		conn, _ := listener.Accept(ctx)
		accepted <- conn
	}()
	conn, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLS, &quic.Config{HandshakeIdleTimeout: time.Second})
	if err == nil {
		_ = conn.CloseWithError(0, "unexpected")
		t.Fatal("QUIC handshake accepted a certificate from the wrong committee key")
	}
	select {
	case serverConn := <-accepted:
		if serverConn != nil {
			_ = serverConn.CloseWithError(0, "unexpected")
			t.Fatal("server accepted a connection whose BLS certificate pin failed")
		}
	case <-time.After(100 * time.Millisecond):
	}
}

func TestTxQUICServerCertificatePinsLocalNonLeaderAndBoundsRefresh(t *testing.T) {
	config := testTxQUICConfig()
	config.PortOffset = 2000
	config.Port = 9106
	secrets := make([]*bls.SecretKey, 4)
	publicKeys := make([]string, len(secrets))
	for index := range secrets {
		secrets[index] = new(bls.SecretKey)
		secrets[index].SetByCSPRNG()
		publicKeys[index] = secrets[index].GetPublicKey().SerializeToHexStr()
	}
	localSecret := secrets[2]
	localPublic := localSecret.GetPublicKey().Serialize()
	route := TxQUICFHSRoute{
		ProposalView: 10, KeyNumber: testTxQUICKeyNumber, CommitteeHash: testTxQUICCommitteeHash(),
		LeaderIndex: 1, LeaderAddress: "127.0.0.1:7104",
		CommitteeAddresses:  []string{"127.0.0.1:7102", "127.0.0.1:7104", "127.0.0.1:7106", "127.0.0.1:7108"},
		CommitteePublicKeys: publicKeys,
	}
	var routeCalls atomic.Int32
	var signerCalls atomic.Int32
	q := &TxQUICIngress{config: config}
	q.routeProvider = func() (TxQUICFHSRoute, error) {
		routeCalls.Add(1)
		return route, nil
	}
	if err := q.SetFHSReceiptSigner(func() ([]byte, error) {
		return append([]byte(nil), localPublic...), nil
	}, func(keyNumber uint64, committeeHash common.Hash, digest []byte) ([]byte, error) {
		if keyNumber != route.KeyNumber || committeeHash != route.CommitteeHash {
			return nil, fmt.Errorf("stale TLS signing generation")
		}
		signerCalls.Add(1)
		return localSecret.SignHash(digest).Serialize(), nil
	}); err != nil {
		t.Fatal(err)
	}

	const concurrentHellos = 32
	certificates := make(chan tls.Certificate, concurrentHellos)
	errs := make(chan error, concurrentHellos)
	var wg sync.WaitGroup
	for index := 0; index < concurrentHellos; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			certificate, err := q.serverCertificate(context.Background())
			if err != nil {
				errs <- err
				return
			}
			certificates <- certificate
		}()
	}
	wg.Wait()
	close(errs)
	close(certificates)
	for err := range errs {
		t.Fatal(err)
	}
	var first []byte
	for certificate := range certificates {
		if len(certificate.Certificate) != 1 {
			t.Fatal("attested server certificate chain is not singular")
		}
		if first == nil {
			first = append([]byte(nil), certificate.Certificate[0]...)
		} else if !bytes.Equal(first, certificate.Certificate[0]) {
			t.Fatal("concurrent ClientHello generated multiple TLS credentials")
		}
	}
	if routeCalls.Load() != 1 || signerCalls.Load() != 1 {
		t.Fatalf("concurrent ClientHello route/sign calls = %d/%d, want 1/1", routeCalls.Load(), signerCalls.Load())
	}
	localIdentity, _, err := txQUICTLSIdentityPayload(config, route.KeyNumber, route.CommitteeHash, "127.0.0.1:9106")
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := q.clientTLSConfig(localIdentity, localPublic)
	if err != nil {
		t.Fatal(err)
	}
	if err := clientConfig.VerifyConnection(testTxQUICTLSState(t, [][]byte{first})); err != nil {
		t.Fatalf("non-leader local endpoint identity rejected: %v", err)
	}
	leaderIdentity, _, err := txQUICTLSIdentityPayload(config, route.KeyNumber, route.CommitteeHash, "127.0.0.1:9104")
	if err != nil {
		t.Fatal(err)
	}
	leaderConfig, err := q.clientTLSConfig(leaderIdentity, localPublic)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaderConfig.VerifyConnection(testTxQUICTLSState(t, [][]byte{first})); err == nil {
		t.Fatal("non-leader validator certificate was accepted as the leader endpoint")
	}

	q.tlsMu.Lock()
	q.tlsRouteChecked = time.Now().Add(-txQUICTLSRouteRefreshInterval)
	q.tlsMu.Unlock()
	route.ProposalView++
	route.KeyNumber++
	route.CommitteeHash = common.HexToHash("0x998877")
	rotated, err := q.serverCertificate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, rotated.Certificate[0]) || routeCalls.Load() != 2 || signerCalls.Load() != 2 {
		t.Fatalf("committee rotation did not renew TLS identity: route/sign=%d/%d", routeCalls.Load(), signerCalls.Load())
	}
	rotatedIdentity, _, err := txQUICTLSIdentityPayload(config, route.KeyNumber, route.CommitteeHash, "127.0.0.1:9106")
	if err != nil {
		t.Fatal(err)
	}
	rotatedConfig, err := q.clientTLSConfig(rotatedIdentity, localPublic)
	if err != nil {
		t.Fatal(err)
	}
	if err := rotatedConfig.VerifyConnection(testTxQUICTLSState(t, rotated.Certificate)); err != nil {
		t.Fatalf("rotated committee TLS identity rejected: %v", err)
	}
	if err := rotatedConfig.VerifyConnection(testTxQUICTLSState(t, [][]byte{first})); err == nil {
		t.Fatal("old committee TLS identity survived rotation")
	}
}

func TestTxQUICAllowIPsUnsetPreservesAllowAllBehavior(t *testing.T) {
	config := testTxQUICConfig()
	config.FairHotstuff = true
	config.HTTP3Enabled = true
	q := NewTxQUICIngress(config, nil)

	if err := q.validateSecurityConfig(); err != nil {
		t.Fatalf("unset AllowIPs validation error = %v", err)
	}
	if !q.allowed(&net.TCPAddr{IP: net.ParseIP("203.0.113.25"), Port: 30303}) {
		t.Fatal("unset AllowIPs rejected an address, want current allow-all behavior")
	}
}

func TestTxQUICIngressRequiresExplicitSourceAllowlist(t *testing.T) {
	config := testTxQUICConfig()
	config.Enabled = true
	config.FairHotstuff = true
	q := NewTxQUICIngress(config, nil)
	q.routeProvider = func() (TxQUICFHSRoute, error) { return TxQUICFHSRoute{}, nil }
	q.ingress = &TxQUICIngressStore{}
	err := q.validateSecurityConfig()
	if err == nil || !strings.Contains(err.Error(), "source IP allowlist") {
		t.Fatalf("missing ingress allowlist error = %v", err)
	}
}

func TestTxQUICHandshakeAdmissionPrecedesTLSAndReleasesWithConnection(t *testing.T) {
	if txQUICHandshakeIdleTimeout <= 0 || txQUICHandshakeIdleTimeout > 5*time.Second {
		t.Fatalf("handshake idle timeout = %v, want a positive fail-closed bound of at most 5s", txQUICHandshakeIdleTimeout)
	}
	nodeCtx, stopNode := context.WithCancel(context.Background())
	defer stopNode()
	q := &TxQUICIngress{
		ctx:      nodeCtx,
		connSem:  make(chan struct{}, 1),
		allowIPs: map[string]struct{}{net.ParseIP("127.0.0.1").String(): {}},
	}
	allowed := &quic.ClientInfo{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 30303}, AddrVerified: true}
	unverified := *allowed
	unverified.AddrVerified = false
	if admitted, err := q.handshakeContext(context.Background(), &unverified); err == nil || admitted != nil {
		t.Fatal("unverified QUIC source reached TLS admission")
	}
	disallowed := &quic.ClientInfo{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 30303}, AddrVerified: true}
	if admitted, err := q.handshakeContext(context.Background(), disallowed); err == nil || admitted != nil || len(q.connSem) != 0 {
		t.Fatal("disallowed QUIC source consumed a connection slot")
	}

	firstCtx, closeFirst := context.WithCancel(context.Background())
	if admitted, err := q.handshakeContext(firstCtx, allowed); err != nil || admitted != firstCtx {
		t.Fatalf("verified allowed source rejected: %v", err)
	}
	if len(q.connSem) != 1 {
		t.Fatalf("connection slots in use = %d, want 1", len(q.connSem))
	}
	if admitted, err := q.handshakeContext(context.Background(), allowed); err == nil || admitted != nil {
		t.Fatal("connection bound admitted a second concurrent handshake")
	}
	closeFirst()
	deadline := time.Now().Add(time.Second)
	for len(q.connSem) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(q.connSem) != 0 {
		t.Fatal("connection context cancellation did not release its admission slot")
	}
	finalCtx, closeFinal := context.WithCancel(context.Background())
	if _, err := q.handshakeContext(finalCtx, allowed); err != nil {
		t.Fatalf("released connection slot was not reusable: %v", err)
	}
	closeFinal()
}

func TestTxQUICServerCertificateRefreshWaitIsContextBounded(t *testing.T) {
	config := testTxQUICConfig()
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	q := &TxQUICIngress{config: config, ctx: context.Background()}
	q.routeProvider = func() (TxQUICFHSRoute, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return TxQUICFHSRoute{}, errors.New("route unavailable")
	}
	if err := q.SetFHSReceiptSigner(func() ([]byte, error) { return []byte{1}, nil }, func(uint64, common.Hash, []byte) ([]byte, error) {
		return []byte{1}, nil
	}); err != nil {
		t.Fatal(err)
	}

	firstCtx, cancelFirst := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancelFirst()
	firstDone := make(chan error, 1)
	go func() {
		_, err := q.serverCertificate(firstCtx)
		firstDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("certificate refresh did not call the route provider")
	}
	lockAvailable := make(chan struct{})
	go func() {
		q.routeRefreshMu.Lock()
		q.routeRefreshMu.Unlock()
		close(lockAvailable)
	}()
	select {
	case <-lockAvailable:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("blocked route provider retained the shared route publication lock")
	}
	if err := <-firstDone; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first certificate wait error = %v, want deadline exceeded", err)
	}
	secondCtx, cancelSecond := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancelSecond()
	if _, err := q.serverCertificate(secondCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second certificate wait error = %v, want deadline exceeded", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("blocked route provider calls = %d, want exactly one", calls.Load())
	}
	close(release)
}

func TestTxQUICRouteProviderReplacementBypassesStalledGeneration(t *testing.T) {
	blocked := make(chan struct{})
	release := make(chan struct{})
	q := &TxQUICIngress{config: testTxQUICConfig()}
	q.config.PortOffset = 2000
	q.routeProvider = func() (TxQUICFHSRoute, error) {
		close(blocked)
		<-release
		return TxQUICFHSRoute{}, errors.New("retired provider")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	oldResult := make(chan error, 1)
	go func() {
		_, err := q.refreshFHSRouteCacheContext(ctx)
		oldResult <- err
	}()
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("old route provider did not start")
	}
	if err := <-oldResult; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled old provider error = %v, want deadline exceeded", err)
	}
	q.routeMu.RLock()
	oldRefresh := q.routeRefresh
	q.routeMu.RUnlock()

	publicKeys := make([]string, 4)
	for index := range publicKeys {
		secret := new(bls.SecretKey)
		secret.SetByCSPRNG()
		publicKeys[index] = secret.GetPublicKey().SerializeToHexStr()
	}
	newRoute := TxQUICFHSRoute{
		ProposalView: 2, KeyNumber: 1, CommitteeHash: common.HexToHash("0x9988"), LeaderIndex: 0,
		LeaderAddress:       "127.0.0.1:7102",
		CommitteeAddresses:  []string{"127.0.0.1:7102", "127.0.0.1:7104", "127.0.0.1:7106", "127.0.0.1:7108"},
		CommitteePublicKeys: publicKeys,
	}
	q.SetFHSRouteProvider(func() (TxQUICFHSRoute, error) { return newRoute, nil })
	cached := q.cachedFHSRoute()
	if cached.ProposalView != newRoute.ProposalView || cached.CommitteeHash != newRoute.CommitteeHash {
		t.Fatalf("replacement route was not published: %#v", cached)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for len(oldRefresh) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(oldRefresh) != 0 {
		t.Fatal("retired route provider did not release its generation gate")
	}
	cached = q.cachedFHSRoute()
	if cached.ProposalView != newRoute.ProposalView || cached.CommitteeHash != newRoute.CommitteeHash {
		t.Fatalf("retired provider overwrote the replacement route: %#v", cached)
	}
}

func TestTxQUICClientRetirementCancelsDialAndWakesWaiters(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	config := testTxQUICConfig()
	config.ForwardTimeout = 10 * time.Second
	secret := new(bls.SecretKey)
	secret.SetByCSPRNG()
	publicKey := secret.GetPublicKey().Serialize()
	endpoint := packetConn.LocalAddr().String()
	_, generation, err := txQUICTLSIdentityPayload(config, testTxQUICKeyNumber, testTxQUICCommitteeHash(), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	client := &txQUICForwardClient{
		endpoint:        endpoint,
		receiptIdentity: txQUICReceiptIdentity(publicKey),
		tlsGeneration:   generation,
	}
	q := &TxQUICIngress{config: config}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errs := make(chan error, 2)
	for index := 0; index < 2; index++ {
		go func() {
			_, err := client.getConn(q, ctx, testTxQUICKeyNumber, testTxQUICCommitteeHash(), publicKey)
			errs <- err
		}()
	}
	deadline := time.Now().Add(time.Second)
	for {
		client.mu.Lock()
		dialing := client.dialing != nil
		client.mu.Unlock()
		if dialing || time.Now().After(deadline) {
			if !dialing {
				t.Fatal("forward client did not enter its bounded dial")
			}
			break
		}
		time.Sleep(time.Millisecond)
	}
	retiredAt := time.Now()
	if conn := client.retire(); conn != nil {
		t.Fatal("retiring an in-flight dial unexpectedly detached an established connection")
	}
	for index := 0; index < 2; index++ {
		select {
		case err := <-errs:
			if err == nil {
				t.Fatal("retired forward client returned a usable connection")
			}
		case <-time.After(time.Second):
			t.Fatal("forward dial or waiter was not cancelled by route retirement")
		}
	}
	if elapsed := time.Since(retiredAt); elapsed >= time.Second {
		t.Fatalf("forward client retirement took %v", elapsed)
	}
}

func TestTxQUICAllowIPsRejectsInvalidEntriesBeforeStartup(t *testing.T) {
	tests := []struct {
		name     string
		allowIPs []string
		invalid  string
	}{
		{
			name:     "mixed valid and invalid",
			allowIPs: []string{"192.0.2.10", "not-an-ip-or-cidr"},
			invalid:  "not-an-ip-or-cidr",
		},
		{
			name:     "all invalid",
			allowIPs: []string{"invalid-address", "192.0.2.0/99"},
			invalid:  "invalid-address",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := testTxQUICConfig()
			config.FairHotstuff = true
			config.HTTP3Enabled = true
			config.AllowIPs = test.allowIPs
			q := NewTxQUICIngress(config, nil)

			err := q.validateSecurityConfig()
			if err == nil {
				t.Fatal("invalid AllowIPs passed startup validation")
			}
			if !strings.Contains(err.Error(), test.invalid) {
				t.Fatalf("invalid AllowIPs validation error = %q, want offending entry %q", err, test.invalid)
			}
		})
	}
}

func TestTxQUICAllowIPsAcceptsValidIPAndCIDR(t *testing.T) {
	config := testTxQUICConfig()
	config.FairHotstuff = true
	config.HTTP3Enabled = true
	config.AllowIPs = []string{"192.0.2.10", "2001:db8:abcd::/48"}
	q := NewTxQUICIngress(config, nil)

	if err := q.validateSecurityConfig(); err != nil {
		t.Fatalf("valid AllowIPs validation error = %v", err)
	}
	tests := []struct {
		address string
		want    bool
	}{
		{address: "192.0.2.10", want: true},
		{address: "192.0.2.11", want: false},
		{address: "2001:db8:abcd::42", want: true},
		{address: "2001:db8:abce::42", want: false},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			addr := &net.TCPAddr{IP: net.ParseIP(test.address), Port: 30303}
			if got := q.allowed(addr); got != test.want {
				t.Fatalf("allowed(%s) = %t, want %t", test.address, got, test.want)
			}
		})
	}
}

func TestTxQUICRuntimeLimitsBindConnectionsStreamsWorkersAndPayloadBytes(t *testing.T) {
	zeroDefaults := TxQUICConfig{}
	applyTxQUICDefaults(&zeroDefaults)
	for name, defaults := range map[string]TxQUICConfig{
		"DefaultConfig.TxQUIC": DefaultConfig.TxQUIC,
		"zero-value fallback":  zeroDefaults,
	} {
		if err := validateTxQUICRuntimeLimits(defaults); err != nil {
			t.Fatalf("%s is invalid: %v", name, err)
		}
		if defaults.BridgeQueueSize < 200_000*5 {
			t.Fatalf("%s bridge queue = %d, want at least a five-second 200k TPS envelope", name, defaults.BridgeQueueSize)
		}
		if defaults.BridgeWorkers < 64 || defaults.OutboxWorkers < 64 {
			t.Fatalf("%s bridge/outbox workers = %d/%d, want at least 64/64", name, defaults.BridgeWorkers, defaults.OutboxWorkers)
		}
		if defaults.IngressWorkers < 256 || defaults.MaxIncomingStreams < 256 || defaults.MaxIncomingConns < 256 {
			t.Fatalf("%s ingress workers/streams/connections = %d/%d/%d, want at least 256 each",
				name, defaults.IngressWorkers, defaults.MaxIncomingStreams, defaults.MaxIncomingConns)
		}
		if defaults.MaxInflightPayloadBytes < 512<<20 {
			t.Fatalf("%s in-flight payload bound = %d, want at least 512 MiB", name, defaults.MaxInflightPayloadBytes)
		}
	}

	base := testTxQUICConfig()
	applyTxQUICDefaults(&base)
	if err := validateTxQUICRuntimeLimits(base); err != nil {
		t.Fatalf("default runtime limits are invalid: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*TxQUICConfig)
	}{
		{name: "streams exceed workers", mutate: func(config *TxQUICConfig) { config.MaxIncomingStreams = int64(config.IngressWorkers + 1) }},
		{name: "connections exceed workers", mutate: func(config *TxQUICConfig) { config.MaxIncomingConns = config.IngressWorkers + 1 }},
		{name: "stream product", mutate: func(config *TxQUICConfig) {
			config.IngressWorkers = 1024
			config.MaxIncomingStreams = 257
			config.MaxIncomingConns = 256
		}},
		{name: "payload below one packet", mutate: func(config *TxQUICConfig) { config.MaxInflightPayloadBytes = txQUICMicroBatchMaxWireBytes - 1 }},
		{name: "payload exceeds workers", mutate: func(config *TxQUICConfig) {
			config.MaxInflightPayloadBytes = int64(config.IngressWorkers)*txQUICMicroBatchMaxWireBytes + 1
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.mutate(&config)
			if err := validateTxQUICRuntimeLimits(config); err == nil {
				t.Fatal("unsafe runtime limit was accepted")
			}
		})
	}

	bounded := base
	bounded.IngressWorkers = 1
	bounded.MaxIncomingStreams = 1
	bounded.MaxIncomingConns = 1
	bounded.MaxInflightPayloadBytes = txQUICMicroBatchMaxWireBytes
	q := NewTxQUICIngress(bounded, nil)
	if !q.tryAcquireIngressWorker() || q.tryAcquireIngressWorker() {
		t.Fatal("ingress worker admission did not fail closed at capacity")
	}
	q.releaseIngressWorker()
	first := txQUICMicroBatchMaxWireBytes - 1024
	if !q.tryAcquireInflightPayload(first) || q.tryAcquireInflightPayload(2048) {
		t.Fatal("global in-flight byte admission exceeded its configured bound")
	}
	q.releaseInflightPayload(first)
	if got := q.pendingInflightPayloadBytes(); got != 0 {
		t.Fatalf("in-flight payload bytes after release = %d", got)
	}
}

func TestTxQUICRateBucketsAreBoundedAndIdleEntriesExpire(t *testing.T) {
	config := testTxQUICConfig()
	config.RateBucketMaxEntries = 2
	config.RateBucketIdleTTL = time.Second
	q := NewTxQUICIngress(config, nil)
	addresses := []*net.TCPAddr{
		{IP: net.ParseIP("192.0.2.1"), Port: 1},
		{IP: net.ParseIP("192.0.2.2"), Port: 1},
		{IP: net.ParseIP("192.0.2.3"), Port: 1},
	}
	if !q.takeTokens(addresses[0], 1) || !q.takeTokens(addresses[1], 1) {
		t.Fatal("initial bounded rate buckets were rejected")
	}
	if q.takeTokens(addresses[2], 1) {
		t.Fatal("rate bucket map exceeded its entry bound")
	}
	q.rateMu.Lock()
	q.buckets["192.0.2.1"].lastSeen = time.Now().Add(-2 * config.RateBucketIdleTTL)
	q.rateLastGC = time.Time{}
	q.rateMu.Unlock()
	if !q.takeTokens(addresses[2], 1) {
		t.Fatal("idle rate bucket was not reclaimed")
	}
	q.rateMu.Lock()
	defer q.rateMu.Unlock()
	if len(q.buckets) != config.RateBucketMaxEntries {
		t.Fatalf("rate bucket count = %d, want %d", len(q.buckets), config.RateBucketMaxEntries)
	}
	if _, stale := q.buckets["192.0.2.1"]; stale {
		t.Fatal("idle rate bucket survived TTL collection")
	}
}

func TestTxQUICProtocolNameHasNoGenerationSuffix(t *testing.T) {
	if txQUICProtocolName != "cypher-tx-quic" || strings.Contains(txQUICProtocolName, "/") {
		t.Fatalf("protocol name = %q, want genesis-native cypher-tx-quic", txQUICProtocolName)
	}
}

func TestTxQUICSemanticBatchIDIgnoresEnvelopeAndBindsOrderAndChain(t *testing.T) {
	config := testTxQUICConfig()
	tx1 := testTxQUICTransaction(1, 0)
	tx2 := testTxQUICTransaction(2, 1)
	batch := testTxQUICBatch(t, config, tx1, tx2)
	sender := common.HexToAddress("0x2000000000000000000000000000000000000002")
	first := testTxQUICPacketFromBatch(config, batch, sender, 7, 1_700_000_000)
	second := testTxQUICPacketFromBatch(config, batch, sender, 99, 1_800_000_000)

	firstExpectation, err := newTxQUICAckExpectation(first)
	if err != nil {
		t.Fatal(err)
	}
	secondExpectation, err := newTxQUICAckExpectation(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstExpectation.batchID != secondExpectation.batchID || firstExpectation.batchID != batch.BatchID {
		t.Fatalf("envelope changed semantic batch ID: %s %s %s", firstExpectation.batchID, secondExpectation.batchID, batch.BatchID)
	}
	if first.signingHash() == second.signingHash() {
		t.Fatal("nonce and timestamp did not bind the signed transport envelope")
	}

	reordered := testTxQUICBatch(t, config, tx2, tx1)
	if reordered.BatchID == batch.BatchID {
		t.Fatal("transaction order was not bound into the semantic batch ID")
	}
	differentChain := config
	differentChain.ChainID++
	if got := testTxQUICBatch(t, differentChain, tx1, tx2).BatchID; got == batch.BatchID {
		t.Fatal("chain ID was not bound into the semantic batch ID")
	}
	differentGenesis := config
	differentGenesis.GenesisHash = common.HexToHash("0x99")
	if got := testTxQUICBatch(t, differentGenesis, tx1, tx2).BatchID; got == batch.BatchID {
		t.Fatal("genesis hash was not bound into the semantic batch ID")
	}
}

func TestTxQUICMicroBatchStoresOneCertificateAndOriginalIndexes(t *testing.T) {
	config := testTxQUICConfig()
	txs := make([]*types.Transaction, txQUICMicroBatchMaxTxs)
	for index := range txs {
		txs[index] = testTxQUICTransaction(uint64(10_000+index), 0)
	}
	batch := testTxQUICBatch(t, config, txs...)
	if err := types.VerifyCommonTxAdmissionSignature(batch.Certificate); err != nil {
		t.Fatalf("micro-batch certificate is invalid: %v", err)
	}
	if len(batch.Certificate.TxHashes) != txQUICMicroBatchMaxTxs || len(batch.Items) != txQUICMicroBatchMaxTxs {
		t.Fatalf("micro-batch sizes certificate=%d items=%d", len(batch.Certificate.TxHashes), len(batch.Items))
	}
	for index, item := range batch.Items {
		if item.AdmissionIndex != uint16(index) || item.Tx.Hash() != batch.Certificate.TxHashes[index] {
			t.Fatalf("micro-batch item %d lost its original certificate index", index)
		}
	}
	if batch.BatchID == batch.Certificate.AdmissionID {
		t.Fatal("transport BatchID was conflated with semantic AdmissionID")
	}
	payload, err := rlp.EncodeToBytes(batch)
	if err != nil {
		t.Fatal(err)
	}
	if occurrences := bytes.Count(payload, batch.Certificate.Signature); occurrences != 1 {
		t.Fatalf("certificate signature occurs %d times in packet payload, want exactly once", occurrences)
	}
}

func TestTxQUICStoredBatchReserveCoversMaximumWireEnvelope(t *testing.T) {
	config := testTxQUICConfig()
	batch := testTxQUICBatch(t, config, testTxQUICTransaction(9, 0))
	stored, err := rlp.EncodeToBytes(batch)
	if err != nil {
		t.Fatal(err)
	}
	packet := &txQUICPacket{
		ChainID: ^uint64(0), GenesisHash: common.BytesToHash(bytes.Repeat([]byte{0xff}, common.HashLength)),
		KeyNumber: ^uint64(0), CommitteeHash: common.BytesToHash(bytes.Repeat([]byte{0xfe}, common.HashLength)),
		BatchID: batch.BatchID, Sender: common.BytesToAddress(bytes.Repeat([]byte{0xfd}, common.AddressLength)),
		SenderEpoch: common.BytesToHash(bytes.Repeat([]byte{0xfc}, common.HashLength)), Nonce: ^uint64(0), Timestamp: ^uint64(0),
		TxRoot: batch.TxRoot, Certificate: copyCommonTxAdmissionBatchForQUIC(batch.Certificate), Items: batch.Items,
		Signature: bytes.Repeat([]byte{0xfb}, crypto.SignatureLength),
	}
	wire, err := rlp.EncodeToBytes(packet)
	if err != nil {
		t.Fatal(err)
	}
	overhead := int64(len(wire) - len(stored))
	if overhead <= 0 || overhead > txQUICMicroBatchEnvelopeReserve {
		t.Fatalf("wire envelope overhead=%d reserve=%d", overhead, txQUICMicroBatchEnvelopeReserve)
	}
	if txQUICMicroBatchMaxStoredBytes+overhead > txQUICMicroBatchMaxWireBytes {
		t.Fatalf("stored limit plus envelope exceeds wire limit: stored=%d overhead=%d wire=%d", txQUICMicroBatchMaxStoredBytes, overhead, txQUICMicroBatchMaxWireBytes)
	}
}

func TestValidateTxQUICAckOutcomeRequiresOneStrictOutcomePerItem(t *testing.T) {
	config := testTxQUICConfig()
	sender := common.HexToAddress("0x3000000000000000000000000000000000000003")
	packet := testTxQUICPacket(t, config, sender, 1,
		testTxQUICTransaction(10, 0),
		testTxQUICTransaction(11, 0),
		testTxQUICTransaction(12, 0),
	)
	expectation, err := newTxQUICAckExpectation(packet)
	if err != nil {
		t.Fatal(err)
	}
	valid := testTxQUICAck(t, packet, []int{0}, []int{1}, []txQUICPermanentError{{
		Index: 2, ItemID: expectation.itemIDs[2], Code: txQUICPermanentInvalidTransaction, Reason: "intrinsically invalid",
	}})
	if err := validateTxQUICAckOutcome(&valid, expectation); err != nil {
		t.Fatalf("valid per-item outcome rejected: %v", err)
	}
	invalidAdmission := cloneTxQUICAck(valid)
	invalidAdmission.PermanentErrors[0].Code = txQUICPermanentInvalidAdmission
	invalidAdmission.PermanentErrors[0].Reason = "invalid admission signature"
	if err := validateTxQUICAckOutcome(&invalidAdmission, expectation); err != nil {
		t.Fatalf("permanent invalid-admission outcome rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*txQUICAck)
	}{
		{name: "identity", mutate: func(ack *txQUICAck) { ack.Nonce++ }},
		{name: "key generation", mutate: func(ack *txQUICAck) { ack.KeyNumber++ }},
		{name: "committee generation", mutate: func(ack *txQUICAck) { ack.CommitteeHash = common.HexToHash("0xdead") }},
		{name: "bitmap length", mutate: func(ack *txQUICAck) { ack.DurableBitmap = nil }},
		{name: "overlap", mutate: func(ack *txQUICAck) { txQUICBitmapSet(ack.RetryableBitmap, 0) }},
		{name: "omission", mutate: func(ack *txQUICAck) { ack.PermanentErrors = nil }},
		{name: "duplicate permanent", mutate: func(ack *txQUICAck) { ack.PermanentErrors = append(ack.PermanentErrors, ack.PermanentErrors[0]) }},
		{name: "wrong item identity", mutate: func(ack *txQUICAck) { ack.PermanentErrors[0].ItemID = common.HexToHash("0xdead") }},
		{name: "empty permanent reason", mutate: func(ack *txQUICAck) { ack.PermanentErrors[0].Reason = " " }},
		{name: "unknown permanent code", mutate: func(ack *txQUICAck) { ack.PermanentErrors[0].Code = 99 }},
		{name: "non-zero padding", mutate: func(ack *txQUICAck) { ack.DurableBitmap[0] |= 0x80 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ack := cloneTxQUICAck(valid)
			test.mutate(&ack)
			if err := validateTxQUICAckOutcome(&ack, expectation); err == nil {
				t.Fatal("invalid acknowledgement outcome was accepted")
			}
		})
	}
}

func TestTxQUICCertificateItemsAreFailClosed(t *testing.T) {
	config := testTxQUICConfig()
	tx := testTxQUICTransaction(1, 0)
	certificate := testTxQUICCertificate(t, config, tx)
	valid := []*txQUICItem{{AdmissionIndex: 0, Tx: tx}}
	if _, _, err := txQUICItemCommitments(certificate, valid); err != nil {
		t.Fatalf("valid paired item rejected: %v", err)
	}

	tests := []struct {
		name  string
		items []*txQUICItem
	}{
		{name: "missing transaction", items: []*txQUICItem{{AdmissionIndex: 0}}},
		{name: "nil item", items: []*txQUICItem{nil}},
		{name: "mismatched index", items: []*txQUICItem{{AdmissionIndex: 1, Tx: tx}}},
		{name: "duplicate transaction", items: []*txQUICItem{{AdmissionIndex: 0, Tx: tx}, {AdmissionIndex: 0, Tx: tx}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := txQUICItemCommitments(certificate, test.items); err == nil {
				t.Fatal("invalid Fair HotStuff TxQUIC items were accepted")
			}
		})
	}
}

func TestTxQUICCertificateRejectsDuplicateNativeReplayIdentity(t *testing.T) {
	config := testTxQUICConfig()
	payer := common.HexToAddress("0x1200000000000000000000000000000000000012")
	first := testTxQUICNativeTransaction(payer, 9, 1)
	conflict := testTxQUICNativeTransaction(payer, 9, 2)
	certificate := testTxQUICCertificate(t, config, first, conflict)
	if _, _, err := txQUICItemCommitments(certificate, testTxQUICItems(first, conflict)); err == nil || !strings.Contains(err.Error(), "native replay identity") {
		t.Fatalf("duplicate native replay identity error = %v", err)
	}

	otherPayer := common.HexToAddress("0x1300000000000000000000000000000000000013")
	independent := testTxQUICNativeTransaction(otherPayer, 9, 3)
	certificate = testTxQUICCertificate(t, config, first, independent)
	if _, _, err := txQUICItemCommitments(certificate, testTxQUICItems(first, independent)); err != nil {
		t.Fatalf("payer-scoped replay identities rejected: %v", err)
	}
}

func TestTxQUICPublicIngressRejectsNativeTransactionType(t *testing.T) {
	payer := common.HexToAddress("0x1200000000000000000000000000000000000012")
	native := testTxQUICNativeTransaction(payer, 1, 1)
	if _, err := packetItemsToTxs(&txQUICPacket{Items: testTxQUICItems(native)}); err == nil || !strings.Contains(err.Error(), "unsupported transaction type 0x5") {
		t.Fatalf("public TxQUIC NativeTx error = %v", err)
	}
}

func TestBuildTxBatchRequiresCertificateAndOriginalIndexes(t *testing.T) {
	config := testTxQUICConfig()
	config.FairHotstuff = true
	q := &TxQUICIngress{config: config}
	tx := testTxQUICTransaction(3, 0)

	if _, err := q.buildTxBatch(nil, []txQUICBridgeItem{{tx: tx}}); err == nil {
		t.Fatal("Fair HotStuff batch without an admission was accepted")
	}
	certificate := testTxQUICCertificate(t, config, tx)
	batch, err := q.buildTxBatch(certificate, []txQUICBridgeItem{{tx: tx, admissionIndex: 0}})
	if err != nil {
		t.Fatalf("paired Fair HotStuff batch rejected: %v", err)
	}
	if len(batch.Items) != 1 || batch.Items[0].Tx.Hash() != tx.Hash() || batch.Items[0].AdmissionIndex != 0 || batch.Certificate.AdmissionID != certificate.AdmissionID {
		t.Fatalf("paired batch was not preserved: %#v", batch.Items)
	}
	if _, err := q.buildTxBatch(certificate, []txQUICBridgeItem{{tx: tx, admissionIndex: 1}}); err == nil {
		t.Fatal("out-of-range admission index was accepted")
	}
}

func TestTxQUICIngressRejectsInvalidAdmissionWithoutPublishingTransaction(t *testing.T) {
	config := testTxQUICConfig()
	chainID := new(big.Int).SetUint64(config.ChainID)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	stateDB, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	stateDB.SetBalance(sender, new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether)))

	chainConfig := *params.TestChainConfig
	chainConfig.ChainID = new(big.Int).Set(chainID)
	head := types.NewBlockWithHeader(&types.Header{
		Number:   big.NewInt(0),
		GasLimit: 30_000_000,
		BaseFee:  big.NewInt(1),
		Time:     uint64(time.Now().Unix()),
	})
	poolConfig := core.DefaultTxPoolConfig
	poolConfig.NoLocals = true
	poolConfig.Journal = ""
	pool := core.NewTxPool(poolConfig, &chainConfig, &testTxQUICPoolChain{block: head, state: stateDB})
	t.Cleanup(pool.Stop)

	unsigned := types.NewTransaction(
		0,
		common.HexToAddress("0x1000000000000000000000000000000000000001"),
		big.NewInt(1),
		21_000,
		big.NewInt(params.GWei),
		nil,
	)
	tx, err := types.SignTx(unsigned, types.NewEIP155Signer(chainID), key)
	if err != nil {
		t.Fatal(err)
	}
	newAdmission := func(admissionChainID *big.Int) *types.CommonTxAdmissionBatch {
		admission := &types.CommonTxAdmissionBatch{
			ChainID:        new(big.Int).Set(admissionChainID),
			GenesisHash:    config.GenesisHash,
			Miner:          sender,
			KeyBlockNumber: testTxQUICKeyNumber,
			Timestamp:      uint64(time.Now().Unix()),
			TxHashes:       []common.Hash{tx.Hash()},
		}
		admission.TxRoot = types.DeriveCommonTxAdmissionTxRoot(admission.TxHashes)
		admission.AdmissionID = types.CommonTxAdmissionID(admission)
		return admission
	}
	invalidSignature := newAdmission(chainID)
	invalidSignature.Signature = make([]byte, crypto.SignatureLength)
	wrongChainID := new(big.Int).Add(chainID, big.NewInt(1))
	wrongChain := newAdmission(wrongChainID)
	wrongChain.Signature, err = crypto.Sign(types.CommonTxAdmissionSigningHash(wrongChain).Bytes(), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := types.VerifyCommonTxAdmissionSignature(wrongChain); err != nil {
		t.Fatalf("wrong-chain admission was not otherwise correctly signed: %v", err)
	}

	tests := []struct {
		name      string
		admission *types.CommonTxAdmissionBatch
	}{
		{name: "invalid signature", admission: invalidSignature},
		{name: "valid signature for another chain", admission: wrongChain},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			batch, itemIDs, err := newTxQUICBatch(config.ChainID, config.GenesisHash, test.admission, []*txQUICItem{{AdmissionIndex: 0, Tx: tx}})
			if err != nil {
				t.Fatal(err)
			}
			packet := testTxQUICPacketFromBatch(config, batch, sender, uint64(index+1), uint64(time.Now().Unix()))
			ack := (&TxQUICIngress{config: config, txpool: pool}).processTxQUICIngressPacket(packet)

			if ack.ItemCount != 1 || !txQUICBitmapEmpty(ack.DurableBitmap) || !txQUICBitmapEmpty(ack.RetryableBitmap) {
				t.Fatalf("invalid-admission ACK has non-permanent outcome: %#v", ack)
			}
			if len(ack.PermanentErrors) != 1 {
				t.Fatalf("invalid-admission permanent errors = %#v, want exactly one", ack.PermanentErrors)
			}
			permanent := ack.PermanentErrors[0]
			if permanent.Index != 0 || permanent.ItemID != itemIDs[0] || permanent.Code != txQUICPermanentInvalidAdmission || strings.TrimSpace(permanent.Reason) == "" {
				t.Fatalf("invalid-admission permanent outcome = %#v", permanent)
			}
			expectation, err := newTxQUICAckExpectation(packet)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateTxQUICAckOutcome(&ack, expectation); err != nil {
				t.Fatalf("invalid-admission ACK failed strict validation: %v", err)
			}
			if pool.Has(tx.Hash()) {
				t.Fatal("transaction with an invalid admission was published to the txpool")
			}
		})
	}

	// Prove that the transaction itself is acceptable to this pool. The only
	// difference in the rejected attempts was their invalid admission sidecar.
	insertErrors := pool.AddRemotesSync([]*types.Transaction{tx})
	if len(insertErrors) != 1 || insertErrors[0] != nil {
		t.Fatalf("control transaction was not txpool-valid: %v", insertErrors)
	}
	if !pool.Has(tx.Hash()) {
		t.Fatal("txpool did not retain the valid control transaction")
	}
}

func TestTxQUICDurableCertificateReuseSkipsRecoveryButRestoresMissingIndex(t *testing.T) {
	config := testTxQUICConfig()
	tx := testTxQUICTransaction(991, 0)
	certificate := testTxQUICCertificate(t, config, tx)
	items := []*txQUICItem{{AdmissionIndex: 0, Tx: tx}}
	present := false
	verifyCalls := 0
	q := &TxQUICIngress{
		config: config,
		hasAdmission: func(hash common.Hash) bool {
			return hash == tx.Hash() && present
		},
		verifyAdmission: func(batch *types.CommonTxAdmissionBatch, chainID *big.Int, genesisHash common.Hash) ([]core.CommonRPCAdmissionResult, error) {
			verifyCalls++
			if chainID == nil || chainID.Uint64() != config.ChainID || genesisHash != config.GenesisHash {
				return nil, fmt.Errorf("unexpected admission boundary")
			}
			if err := types.VerifyCommonTxAdmissionSignature(batch); err != nil {
				return nil, err
			}
			present = true
			return []core.CommonRPCAdmissionResult{{Batch: batch, Item: 0, Updated: true}}, nil
		},
	}
	if err := q.verifyAndStoreAdmissionCertificate(certificate, items, false); err != nil || verifyCalls != 1 {
		t.Fatalf("initial certificate verification calls=%d err=%v", verifyCalls, err)
	}
	if err := q.verifyAndStoreAdmissionCertificate(certificate, items, true); err != nil || verifyCalls != 1 {
		t.Fatalf("durable retry repeated certificate recovery: calls=%d err=%v", verifyCalls, err)
	}
	present = false
	if err := q.verifyAndStoreAdmissionCertificate(certificate, items, true); err != nil || verifyCalls != 2 {
		t.Fatalf("missing core index was not re-stored: calls=%d err=%v", verifyCalls, err)
	}
	if err := q.verifyAndStoreAdmissionCertificate(certificate, items, false); err != nil || verifyCalls != 3 {
		t.Fatalf("restart trust boundary reused volatile verification: calls=%d err=%v", verifyCalls, err)
	}
}

func TestTxQUICIngressNonceTooLowOnlyTerminatesProvablyObsoleteTransaction(t *testing.T) {
	config := testTxQUICConfig()
	chainID := new(big.Int).SetUint64(config.ChainID)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	const (
		txNonce    = uint64(4)
		stateNonce = uint64(5)
	)
	unsigned := types.NewTransaction(
		txNonce,
		common.HexToAddress("0x1000000000000000000000000000000000000001"),
		big.NewInt(1),
		21_000,
		big.NewInt(params.GWei),
		nil,
	)
	tx, err := types.SignTx(unsigned, types.NewEIP155Signer(chainID), key)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name             string
		obsolete         bool
		wantRetryable    bool
		wantOutboxRecord bool
	}{
		{
			name:             "replacement or cancel consumed nonce",
			obsolete:         true,
			wantOutboxRecord: false,
		},
		{
			name:             "nonce status unavailable",
			obsolete:         false,
			wantRetryable:    true,
			wantOutboxRecord: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateDB, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
			if err != nil {
				t.Fatal(err)
			}
			stateDB.SetBalance(sender, new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether)))
			stateDB.SetNonce(sender, stateNonce)

			chainConfig := *params.TestChainConfig
			chainConfig.ChainID = new(big.Int).Set(chainID)
			head := types.NewBlockWithHeader(&types.Header{
				Number:   big.NewInt(0),
				GasLimit: 30_000_000,
				BaseFee:  big.NewInt(1),
				Time:     uint64(time.Now().Unix()),
			})
			poolConfig := core.DefaultTxPoolConfig
			poolConfig.NoLocals = true
			poolConfig.Journal = ""
			poolChain := &testTxQUICPoolChain{block: head, state: stateDB}
			pool := core.NewTxPool(poolConfig, &chainConfig, poolChain)
			t.Cleanup(pool.Stop)

			batch := testTxQUICBatch(t, config, tx)
			payload, err := rlp.EncodeToBytes(batch)
			if err != nil {
				t.Fatal(err)
			}
			outboxDB := memorydb.New()
			outbox := NewTxOutbox(outboxDB, config)
			if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
				<-ctx.Done()
				return ctx.Err()
			}, nil); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(outbox.Stop)
			batchID, err := outbox.StoreSync(context.Background(), payload)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := outboxDB.Get(txOutboxRecordKey(batchID))
			if err != nil {
				t.Fatal(err)
			}
			var record TxOutboxRecord
			if err := rlp.DecodeBytes(encoded, &record); err != nil {
				t.Fatal(err)
			}

			packet := testTxQUICPacketFromBatch(
				config,
				batch,
				common.HexToAddress("0x6500000000000000000000000000000000000006"),
				1,
				uint64(time.Now().Unix()),
			)
			predicateCalls := 0
			ingress := &TxQUICIngress{config: config, txpool: pool}
			ingress.SetObsoleteTxLookup(func(candidates types.Transactions) []bool {
				predicateCalls++
				for _, candidate := range candidates {
					if candidate == nil || candidate.Hash() != tx.Hash() {
						t.Fatalf("obsolete predicate received transaction %#v, want %s", candidate, tx.Hash())
					}
				}
				if !test.obsolete {
					return make([]bool, len(candidates))
				}
				return txQUICFinalizedNonceObsolete(poolChain, chainID, candidates)
			})
			ack := ingress.processTxQUICIngressPacket(packet)
			if predicateCalls != 1 {
				t.Fatalf("obsolete predicate calls = %d, want 1 after ErrNonceTooLow", predicateCalls)
			}
			if txQUICBitmapHas(ack.DurableBitmap, 0) {
				t.Fatal("nonce consumed by another hash was reported as durably stored")
			}
			if got := txQUICBitmapHas(ack.RetryableBitmap, 0); got != test.wantRetryable {
				t.Fatalf("retryable outcome = %t, want %t", got, test.wantRetryable)
			}
			if test.obsolete {
				if len(ack.PermanentErrors) != 1 {
					t.Fatalf("obsolete permanent outcomes = %#v, want one", ack.PermanentErrors)
				}
				permanent := ack.PermanentErrors[0]
				expectation, err := newTxQUICAckExpectation(packet)
				if err != nil {
					t.Fatal(err)
				}
				if permanent.Index != 0 || permanent.ItemID != expectation.itemIDs[0] || permanent.Code != txQUICPermanentObsoleteTransaction || strings.TrimSpace(permanent.Reason) == "" {
					t.Fatalf("obsolete permanent outcome = %#v", permanent)
				}
			} else if len(ack.PermanentErrors) != 0 {
				t.Fatalf("unproven obsolete transaction was permanently rejected: %#v", ack.PermanentErrors)
			}
			expectation, err := newTxQUICAckExpectation(packet)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateTxQUICAckOutcome(&ack, expectation); err != nil {
				t.Fatalf("nonce-too-low ACK failed strict validation: %v", err)
			}

			residual, oldDeleted, err := outbox.compactAcknowledgedRecord(&record, &ack)
			if err != nil {
				t.Fatal(err)
			}
			if test.wantOutboxRecord {
				if residual == nil || residual.BatchID != batchID || oldDeleted {
					t.Fatalf("retryable outbox result = residual %#v deleted %t", residual, oldDeleted)
				}
			} else if residual != nil || !oldDeleted {
				t.Fatalf("obsolete outbox result = residual %#v deleted %t", residual, oldDeleted)
			}
			if has, err := outboxDB.Has(txOutboxRecordKey(batchID)); err != nil || has != test.wantOutboxRecord {
				t.Fatalf("outbox old-hash record = has %t err %v, want has %t", has, err, test.wantOutboxRecord)
			}
		})
	}
}

func TestTxQUICReceiptAccumulatorFourEndpointQuorumDeduplicatesCommitteeIdentity(t *testing.T) {
	config := testTxQUICConfig()
	sender := common.HexToAddress("0x3010000000000000000000000000000000000003")
	packet := testTxQUICPacket(t, config, sender, 1, testTxQUICTransaction(13, 0))
	expectation, err := newTxQUICAckExpectation(packet)
	if err != nil {
		t.Fatal(err)
	}
	endpoints := []string{"validator-0", "validator-1", "validator-2", "validator-3"}
	quorum := txQUICReceiptQuorum(len(endpoints))
	if quorum != 3 {
		t.Fatalf("four-validator receipt quorum = %d, want 2f+1 = 3", quorum)
	}
	accumulator, err := newTxQUICReceiptAccumulator(expectation, quorum)
	if err != nil {
		t.Fatal(err)
	}
	durable := testTxQUICAck(t, packet, []int{0}, nil, nil)
	identityA := []byte("validator-a-consensus-key")
	identityB := []byte("validator-b-consensus-key")
	identityC := []byte("validator-c-consensus-key")

	if added, err := accumulator.add(testTxQUICReceipt(endpoints[0], identityA, durable)); err != nil || !added {
		t.Fatalf("first receipt added=%t err=%v", added, err)
	}
	// A second address presenting the same verified committee identity is the same
	// validator identity and therefore cannot manufacture another vote.
	if added, err := accumulator.add(testTxQUICReceipt(endpoints[1], identityA, durable)); err != nil || added {
		t.Fatalf("duplicate committee identity added=%t err=%v", added, err)
	}
	aggregate, complete := accumulator.outcome()
	if complete || txQUICBitmapHas(aggregate.DurableBitmap, 0) || !txQUICBitmapHas(aggregate.RetryableBitmap, 0) {
		t.Fatalf("duplicate committee identity reached quorum: complete=%t ack=%#v", complete, aggregate)
	}

	if added, err := accumulator.add(testTxQUICReceipt(endpoints[2], identityB, durable)); err != nil || !added {
		t.Fatalf("second distinct receipt added=%t err=%v", added, err)
	}
	aggregate, complete = accumulator.outcome()
	if complete || txQUICBitmapHas(aggregate.DurableBitmap, 0) || !txQUICBitmapHas(aggregate.RetryableBitmap, 0) {
		t.Fatalf("two distinct durable receipts reached 2f+1: complete=%t ack=%#v", complete, aggregate)
	}
	if added, err := accumulator.add(testTxQUICReceipt(endpoints[3], identityC, durable)); err != nil || !added {
		t.Fatalf("third distinct receipt added=%t err=%v", added, err)
	}
	aggregate, complete = accumulator.outcome()
	if !complete || !txQUICBitmapHas(aggregate.DurableBitmap, 0) || !txQUICBitmapEmpty(aggregate.RetryableBitmap) || len(aggregate.PermanentErrors) != 0 {
		t.Fatalf("three distinct durable receipts did not finalize: complete=%t ack=%#v", complete, aggregate)
	}
	if err := validateTxQUICAckOutcome(&aggregate, expectation); err != nil {
		t.Fatalf("aggregate durable outcome is invalid: %v", err)
	}
	if err := txQUICOutcomeError("four-validator committee", aggregate, expectation); err != nil {
		t.Fatalf("durable receipt quorum returned an error: %v", err)
	}
}

func TestTxQUICReceiptAccumulatorRejectsIdentityCommitteeKeyMismatch(t *testing.T) {
	config := testTxQUICConfig()
	sender := common.HexToAddress("0x3011000000000000000000000000000000000003")
	packet := testTxQUICPacket(t, config, sender, 1, testTxQUICTransaction(131, 0))
	expectation, err := newTxQUICAckExpectation(packet)
	if err != nil {
		t.Fatal(err)
	}
	accumulator, err := newTxQUICReceiptAccumulator(expectation, txQUICReceiptQuorum(4))
	if err != nil {
		t.Fatal(err)
	}
	receipt := testTxQUICReceipt("validator-0", []byte("validator-a-consensus-key"), testTxQUICAck(t, packet, []int{0}, nil, nil))
	receipt.Ack.CommitteePublicKey = []byte("validator-b-consensus-key")
	if added, err := accumulator.add(receipt); err == nil || added {
		t.Fatalf("identity/key mismatch added=%t err=%v", added, err)
	}
	if aggregate, complete := accumulator.outcome(); complete || !txQUICBitmapHas(aggregate.RetryableBitmap, 0) {
		t.Fatalf("rejected identity/key mismatch affected quorum: complete=%t ack=%#v", complete, aggregate)
	}
}

func TestTxQUICReceiptAccumulatorBoundsAllSuccessHedgingAtQuorum(t *testing.T) {
	config := testTxQUICConfig()
	packet := testTxQUICPacket(t, config, common.HexToAddress("0x3012000000000000000000000000000000000003"), 1, testTxQUICTransaction(132, 0))
	expectation, err := newTxQUICAckExpectation(packet)
	if err != nil {
		t.Fatal(err)
	}
	quorum := txQUICReceiptQuorum(21)
	if quorum != 13 {
		t.Fatalf("21-member receipt quorum = %d, want 13", quorum)
	}
	accumulator, err := newTxQUICReceiptAccumulator(expectation, quorum)
	if err != nil {
		t.Fatal(err)
	}
	if needed := accumulator.receiptsNeeded(); needed != quorum {
		t.Fatalf("empty accumulator needs %d receipts, want %d", needed, quorum)
	}

	// The initial quorum-sized request window still has one request in flight
	// after twelve successful terminal receipts. That one request is sufficient;
	// launching a replacement here is the 2q-1 over-fanout regression.
	inFlight := quorum
	for index := 0; index < quorum-1; index++ {
		inFlight--
		key := []byte(fmt.Sprintf("twenty-one-member-%d", index))
		receipt := testTxQUICReceipt(fmt.Sprintf("validator-%d", index), key, testTxQUICAck(t, packet, []int{0}, nil, nil))
		if added, err := accumulator.add(receipt); err != nil || !added {
			t.Fatalf("terminal receipt %d added=%t err=%v", index, added, err)
		}
	}
	if needed := accumulator.receiptsNeeded(); needed != 1 {
		t.Fatalf("twelve terminal receipts leave %d needed, want 1", needed)
	}
	if inFlight != 1 || inFlight < accumulator.receiptsNeeded() {
		t.Fatalf("quorum window would launch an unnecessary hedge: in-flight %d needed %d", inFlight, accumulator.receiptsNeeded())
	}
	inFlight--
	finalKey := []byte("twenty-one-member-final")
	finalReceipt := testTxQUICReceipt("validator-final", finalKey, testTxQUICAck(t, packet, []int{0}, nil, nil))
	if added, err := accumulator.add(finalReceipt); err != nil || !added {
		t.Fatalf("final terminal receipt added=%t err=%v", added, err)
	}
	if needed := accumulator.receiptsNeeded(); needed != 0 {
		t.Fatalf("receipt quorum still needs %d votes after thirteen successes", needed)
	}
	if aggregate, complete := accumulator.outcome(); !complete || !txQUICBitmapHas(aggregate.DurableBitmap, 0) {
		t.Fatalf("thirteen successful receipts did not complete quorum: complete=%t ack=%#v", complete, aggregate)
	}
}

func TestRotateTxQUICCommitteeTailKeepsLeaderFirst(t *testing.T) {
	endpoints := []string{"leader", "validator-1", "validator-2", "validator-3", "validator-4", "validator-5", "validator-6"}
	for cursor := uint64(0); cursor < 2*uint64(len(endpoints)-1); cursor++ {
		rotated := rotateTxQUICCommitteeTail(endpoints, cursor)
		if len(rotated) != len(endpoints) || rotated[0] != endpoints[0] {
			t.Fatalf("cursor %d route order = %v, leader must remain first", cursor, rotated)
		}
		wantFirstTail := endpoints[1+int(cursor%uint64(len(endpoints)-1))]
		if rotated[1] != wantFirstTail {
			t.Fatalf("cursor %d first nonleader = %s, want %s", cursor, rotated[1], wantFirstTail)
		}
		seen := make(map[string]struct{}, len(rotated))
		for _, endpoint := range rotated {
			seen[endpoint] = struct{}{}
		}
		if len(seen) != len(endpoints) {
			t.Fatalf("cursor %d route order has duplicates: %v", cursor, rotated)
		}
		for _, endpoint := range endpoints {
			if _, ok := seen[endpoint]; !ok {
				t.Fatalf("cursor %d route order omitted %s: %v", cursor, endpoint, rotated)
			}
		}
	}
}

func TestTxQUICQuorumHandoffKeepsHedgedAckReadsAlive(t *testing.T) {
	config := testTxQUICConfig()
	config.BridgeEnabled = true
	config.ForwardTimeout = time.Second
	config.ForwardHedgeDelay = 5 * time.Millisecond
	q := NewTxQUICIngress(config, nil)
	t.Cleanup(q.cancel)
	enableTestTxQUICBackgroundHandoff(t, q)

	const committeeSize = 7
	committeeAddresses := make([]string, committeeSize)
	committeePublicKeys := make([]string, committeeSize)
	for index := 0; index < committeeSize; index++ {
		committeeAddresses[index] = fmt.Sprintf("127.0.0.1:%d", 7102+index*2)
		secret := new(bls.SecretKey)
		secret.SetByCSPRNG()
		committeePublicKeys[index] = secret.GetPublicKey().SerializeToHexStr()
	}
	route := TxQUICFHSRoute{
		ProposalView: 1, KeyNumber: testTxQUICKeyNumber, CommitteeHash: testTxQUICCommitteeHash(),
		LeaderIndex: 0, LeaderAddress: committeeAddresses[0],
		CommitteeAddresses: committeeAddresses, CommitteePublicKeys: committeePublicKeys,
	}
	q.SetFHSRouteProvider(func() (TxQUICFHSRoute, error) { return route, nil })
	cached, err := q.refreshFHSRouteCache()
	if err != nil {
		t.Fatal(err)
	}
	endpointIndex := make(map[string]int, committeeSize)
	publicKeyByEndpoint := make(map[string][]byte, committeeSize)
	for index, endpoint := range cached.CommitteeEndpoints {
		endpointIndex[endpoint] = index
		publicKeyByEndpoint[endpoint] = cached.CommitteePublicKeys[index]
	}

	packet := testTxQUICPacket(t, config, common.HexToAddress("0x3013000000000000000000000000000000000003"), 1, testTxQUICTransaction(133, 0))
	payload, err := rlp.EncodeToBytes(packet)
	if err != nil {
		t.Fatal(err)
	}
	ack := testTxQUICAck(t, packet, []int{0}, nil, nil)
	releaseQuorum := make(chan struct{})
	releaseTail := make(chan struct{})
	allLaunched := make(chan struct{})
	var (
		launchOnce   sync.Once
		callsMu      sync.Mutex
		calls        = make(map[string]int, committeeSize)
		totalCalls   int
		tailCanceled atomic.Int32
	)
	forward := func(ctx context.Context, endpoint string, _ []byte) (*txQUICAckReceipt, error) {
		index, ok := endpointIndex[endpoint]
		if !ok {
			return nil, fmt.Errorf("unexpected endpoint %q", endpoint)
		}
		callsMu.Lock()
		calls[endpoint]++
		totalCalls++
		if totalCalls == committeeSize {
			launchOnce.Do(func() { close(allLaunched) })
		}
		callsMu.Unlock()
		gate := releaseQuorum
		if index >= txQUICReceiptQuorum(committeeSize) {
			gate = releaseTail
		}
		select {
		case <-gate:
			return testTxQUICReceipt(endpoint, publicKeyByEndpoint[endpoint], ack), nil
		case <-ctx.Done():
			if index >= txQUICReceiptQuorum(committeeSize) {
				tailCanceled.Add(1)
			}
			return nil, ctx.Err()
		}
	}

	type quorumResult struct {
		receipts int
		err      error
	}
	quorumDone := make(chan quorumResult, 1)
	go func() {
		receipts, err := q.forwardFHSQuorumPayloadWith(context.Background(), payload, forward)
		quorumDone <- quorumResult{receipts: receipts, err: err}
	}()
	select {
	case <-allLaunched:
	case <-time.After(time.Second):
		t.Fatal("hedging did not launch the full seven-member committee")
	}
	close(releaseQuorum)
	select {
	case result := <-quorumDone:
		if result.err != nil || result.receipts != txQUICReceiptQuorum(committeeSize) {
			t.Fatalf("quorum result = receipts %d err %v", result.receipts, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("durable quorum waited for tail committee ACKs")
	}

	var job txQUICBackgroundForward
	select {
	case job = <-q.backgroundForwards:
	case <-time.After(time.Second):
		t.Fatal("quorum did not hand off in-flight committee placement")
	}
	if job.pending != committeeSize-txQUICReceiptQuorum(committeeSize) || len(job.endpoints) != 0 {
		t.Fatalf("handoff = pending %d endpoints %v", job.pending, job.endpoints)
	}
	select {
	case <-time.After(25 * time.Millisecond):
		if canceled := tailCanceled.Load(); canceled != 0 {
			t.Fatalf("quorum canceled %d in-flight ACK reads", canceled)
		}
	}
	close(releaseTail)
	retries := make([]string, 0)
	if ok := q.completeBackgroundForward(job, func(_ context.Context, endpoint string, _ []byte) (*txQUICAckReceipt, error) {
		retries = append(retries, endpoint)
		return nil, errors.New("unexpected duplicate placement")
	}); !ok {
		t.Fatal("background handoff did not complete")
	}
	if len(retries) != 0 {
		t.Fatalf("successful in-flight endpoints were resent: %v", retries)
	}
	callsMu.Lock()
	defer callsMu.Unlock()
	for endpoint := range endpointIndex {
		if calls[endpoint] != 1 {
			t.Fatalf("endpoint %s calls = %d, want 1", endpoint, calls[endpoint])
		}
	}
}

func TestTxQUICPreQuorumCancelDrainsLaunchedEndpoints(t *testing.T) {
	config := testTxQUICConfig()
	config.BridgeEnabled = true
	config.ForwardTimeout = time.Second
	config.ForwardHedgeDelay = 500 * time.Millisecond
	q := NewTxQUICIngress(config, nil)
	t.Cleanup(q.cancel)

	const committeeSize = 4
	committeeAddresses := make([]string, committeeSize)
	committeePublicKeys := make([]string, committeeSize)
	for index := 0; index < committeeSize; index++ {
		committeeAddresses[index] = fmt.Sprintf("127.0.0.1:%d", 7302+index*2)
		secret := new(bls.SecretKey)
		secret.SetByCSPRNG()
		committeePublicKeys[index] = secret.GetPublicKey().SerializeToHexStr()
	}
	route := TxQUICFHSRoute{
		ProposalView: 1, KeyNumber: testTxQUICKeyNumber, CommitteeHash: testTxQUICCommitteeHash(),
		LeaderIndex: 0, LeaderAddress: committeeAddresses[0],
		CommitteeAddresses: committeeAddresses, CommitteePublicKeys: committeePublicKeys,
	}
	q.SetFHSRouteProvider(func() (TxQUICFHSRoute, error) { return route, nil })
	packet := testTxQUICPacket(t, config, common.HexToAddress("0x3014000000000000000000000000000000000003"), 1, testTxQUICTransaction(134, 0))
	payload, err := rlp.EncodeToBytes(packet)
	if err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{}, txQUICReceiptQuorum(committeeSize))
	var exited atomic.Int32
	forward := func(ctx context.Context, _ string, _ []byte) (*txQUICAckReceipt, error) {
		started <- struct{}{}
		<-ctx.Done()
		time.Sleep(25 * time.Millisecond)
		exited.Add(1)
		return nil, ctx.Err()
	}
	attemptCtx, cancelAttempt := context.WithCancel(context.Background())
	type cancelResult struct {
		receipts int
		err      error
	}
	resultCh := make(chan cancelResult, 1)
	go func() {
		receipts, err := q.forwardFHSQuorumPayloadWith(attemptCtx, payload, forward)
		resultCh <- cancelResult{receipts: receipts, err: err}
	}()
	for startedCount := 0; startedCount < txQUICReceiptQuorum(committeeSize); startedCount++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("pre-quorum endpoint did not launch")
		}
	}
	canceledAt := time.Now()
	cancelAttempt()
	select {
	case result := <-resultCh:
		t.Fatalf("pre-quorum cancel returned before endpoint drain: receipts %d err %v", result.receipts, result.err)
	case <-time.After(15 * time.Millisecond):
	}
	select {
	case result := <-resultCh:
		if result.err == nil || result.receipts != 0 {
			t.Fatalf("pre-quorum cancel result = receipts %d err %v", result.receipts, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("pre-quorum cancel did not finish after endpoint drain")
	}
	if elapsed := time.Since(canceledAt); elapsed < 20*time.Millisecond {
		t.Fatalf("pre-quorum cancel returned before delayed endpoint completion: %v", elapsed)
	}
	if got := exited.Load(); got != int32(txQUICReceiptQuorum(committeeSize)) {
		t.Fatalf("drained endpoint goroutines = %d, want %d", got, txQUICReceiptQuorum(committeeSize))
	}
}

func TestTxQUICBackgroundHandoffRetriesOnlyFailedAndNeverLaunched(t *testing.T) {
	q := NewTxQUICIngress(testTxQUICConfig(), nil)
	t.Cleanup(q.cancel)
	results := make(chan txQUICForwardResult, 2)
	results <- txQUICForwardResult{endpoint: "already-placed", receipt: &txQUICAckReceipt{}}
	results <- txQUICForwardResult{endpoint: "failed-in-flight", err: errors.New("ACK unavailable")}
	var cancelCalls atomic.Int32
	job := txQUICBackgroundForward{
		payload: []byte{1}, endpoints: []string{"never-launched"},
		results: results, pending: 2, cancel: func() { cancelCalls.Add(1) },
	}
	retried := make([]string, 0, 2)
	if ok := q.completeBackgroundForward(job, func(_ context.Context, endpoint string, _ []byte) (*txQUICAckReceipt, error) {
		retried = append(retried, endpoint)
		return &txQUICAckReceipt{}, nil
	}); !ok {
		t.Fatal("background handoff failed")
	}
	want := []string{"never-launched", "failed-in-flight"}
	if fmt.Sprint(retried) != fmt.Sprint(want) {
		t.Fatalf("retried endpoints = %v, want %v", retried, want)
	}
	if calls := cancelCalls.Load(); calls != 1 {
		t.Fatalf("placement cancel calls = %d, want 1", calls)
	}
}

func TestTxQUICBackgroundHandoffRetriesMixedRetryableAck(t *testing.T) {
	q := NewTxQUICIngress(testTxQUICConfig(), nil)
	t.Cleanup(q.cancel)
	results := make(chan txQUICForwardResult, 2)
	results <- txQUICForwardResult{
		endpoint: "durable-and-permanent",
		receipt: &txQUICAckReceipt{Ack: txQUICAck{
			DurableBitmap: []byte{0x01},
			PermanentErrors: []txQUICPermanentError{{
				Index: 1, Code: txQUICPermanentInvalidTransaction, Reason: "terminal",
			}},
		}},
	}
	results <- txQUICForwardResult{
		endpoint: "mixed-retryable",
		receipt: &txQUICAckReceipt{Ack: txQUICAck{
			DurableBitmap:   []byte{0x01},
			RetryableBitmap: []byte{0x02},
		}},
	}
	retried := make([]string, 0, 1)
	if ok := q.completeBackgroundForward(txQUICBackgroundForward{
		payload: []byte{1}, results: results, pending: 2,
	}, func(_ context.Context, endpoint string, _ []byte) (*txQUICAckReceipt, error) {
		retried = append(retried, endpoint)
		return &txQUICAckReceipt{}, nil
	}); !ok {
		t.Fatal("mixed ACK handoff failed")
	}
	if len(retried) != 1 || retried[0] != "mixed-retryable" {
		t.Fatalf("mixed ACK retries = %v, want only mixed-retryable", retried)
	}
}

func TestTxQUICBackgroundHandoffShutdownIsBounded(t *testing.T) {
	config := testTxQUICConfig()
	config.BridgeEnabled = true
	q := NewTxQUICIngress(config, nil)
	q.startBackgroundForwardWorkers()
	results := make(chan txQUICForwardResult, 1)
	endpointDone := make(chan struct{})
	go func() {
		<-q.ctx.Done()
		time.Sleep(25 * time.Millisecond)
		results <- txQUICForwardResult{endpoint: "delayed-after-cancel", err: context.Canceled}
		close(endpointDone)
	}()
	var cancelCalls atomic.Int32
	if ok := q.enqueueBackgroundForward(txQUICBackgroundForward{
		payload: []byte{1}, results: results, pending: 1,
		cancel: func() { cancelCalls.Add(1) },
	}); !ok {
		t.Fatal("failed to enqueue background handoff")
	}
	deadline := time.Now().Add(time.Second)
	for len(q.backgroundForwards) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(q.backgroundForwards) != 0 {
		t.Fatal("background worker did not start draining the handoff")
	}
	stopped := make(chan struct{})
	stopStarted := time.Now()
	go func() {
		q.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("TxQUIC shutdown leaked a background handoff worker")
	}
	select {
	case <-endpointDone:
	default:
		t.Fatal("TxQUIC shutdown returned before the canceled endpoint goroutine exited")
	}
	if elapsed := time.Since(stopStarted); elapsed < 20*time.Millisecond {
		t.Fatalf("TxQUIC shutdown returned before delayed endpoint completion: %v", elapsed)
	}
	if calls := cancelCalls.Load(); calls != 1 {
		t.Fatalf("shutdown placement cancel calls = %d, want 1", calls)
	}
}

func TestTxQUICBackgroundHandoffAttemptCancelRaceIsBounded(t *testing.T) {
	q := NewTxQUICIngress(testTxQUICConfig(), nil)
	defer q.cancel()
	for iteration := 0; iteration < 256; iteration++ {
		attemptCtx, cancelAttempt := context.WithCancel(context.Background())
		placementCtx, cancelPlacement := context.WithCancel(q.ctx)
		var (
			cancelOnce  sync.Once
			cancelCalls atomic.Int32
		)
		ownedCancel := func() {
			cancelOnce.Do(func() {
				cancelCalls.Add(1)
				cancelPlacement()
			})
		}
		detachAttemptCancellation := txQUICPropagateAttemptCancellation(attemptCtx, ownedCancel)
		race := make(chan struct{})
		attemptDone := make(chan struct{})
		go func() {
			<-race
			cancelAttempt()
			close(attemptDone)
		}()
		close(race)
		detachAttemptCancellation()
		<-attemptDone
		select {
		case <-placementCtx.Done():
			// Attempt cancellation won the linearization race.
		default:
			// Detachment won. Once detach returns, the completed attempt
			// callback must never cancel placement later.
			select {
			case <-placementCtx.Done():
				t.Fatalf("iteration %d canceled placement after detachment", iteration)
			default:
			}
		}

		results := make(chan txQUICForwardResult, 1)
		results <- txQUICForwardResult{endpoint: "placed", receipt: &txQUICAckReceipt{}}
		if ok := q.completeBackgroundForward(txQUICBackgroundForward{
			payload: []byte{1}, results: results, pending: 1, cancel: ownedCancel,
		}, func(context.Context, string, []byte) (*txQUICAckReceipt, error) {
			return nil, errors.New("unexpected retry")
		}); !ok {
			t.Fatalf("iteration %d handoff failed", iteration)
		}
		select {
		case <-placementCtx.Done():
		case <-time.After(time.Second):
			t.Fatalf("iteration %d leaked placement context", iteration)
		}
		if calls := cancelCalls.Load(); calls != 1 {
			t.Fatalf("iteration %d effective cancel calls = %d, want 1", iteration, calls)
		}
	}
}

func TestTxQUICBackgroundHandoffQueueSaturationKeepsCancelWithCaller(t *testing.T) {
	config := testTxQUICConfig()
	config.BridgeEnabled = true
	config.ForwardTimeout = time.Second
	config.ForwardHedgeDelay = 5 * time.Millisecond
	q := NewTxQUICIngress(config, nil)
	defer q.cancel()
	enableTestTxQUICBackgroundHandoff(t, q)
	for len(q.backgroundForwards) < cap(q.backgroundForwards) {
		q.backgroundForwards <- txQUICBackgroundForward{payload: []byte{1}, endpoints: []string{"occupied"}}
	}

	const committeeSize = 4
	committeeAddresses := make([]string, committeeSize)
	committeePublicKeys := make([]string, committeeSize)
	for index := 0; index < committeeSize; index++ {
		committeeAddresses[index] = fmt.Sprintf("127.0.0.1:%d", 7502+index*2)
		secret := new(bls.SecretKey)
		secret.SetByCSPRNG()
		committeePublicKeys[index] = secret.GetPublicKey().SerializeToHexStr()
	}
	route := TxQUICFHSRoute{
		ProposalView: 1, KeyNumber: testTxQUICKeyNumber, CommitteeHash: testTxQUICCommitteeHash(),
		LeaderIndex: 0, LeaderAddress: committeeAddresses[0],
		CommitteeAddresses: committeeAddresses, CommitteePublicKeys: committeePublicKeys,
	}
	q.SetFHSRouteProvider(func() (TxQUICFHSRoute, error) { return route, nil })
	cached, err := q.refreshFHSRouteCache()
	if err != nil {
		t.Fatal(err)
	}
	endpointIndex := make(map[string]int, committeeSize)
	publicKeyByEndpoint := make(map[string][]byte, committeeSize)
	for index, endpoint := range cached.CommitteeEndpoints {
		endpointIndex[endpoint] = index
		publicKeyByEndpoint[endpoint] = cached.CommitteePublicKeys[index]
	}
	packet := testTxQUICPacket(t, config, common.HexToAddress("0x3015000000000000000000000000000000000003"), 1, testTxQUICTransaction(135, 0))
	payload, err := rlp.EncodeToBytes(packet)
	if err != nil {
		t.Fatal(err)
	}
	ack := testTxQUICAck(t, packet, []int{0}, nil, nil)
	releaseQuorum := make(chan struct{})
	allLaunched := make(chan struct{})
	tailDone := make(chan struct{})
	var (
		launchOnce sync.Once
		calls      atomic.Int32
	)
	forward := func(ctx context.Context, endpoint string, _ []byte) (*txQUICAckReceipt, error) {
		index, ok := endpointIndex[endpoint]
		if !ok {
			return nil, fmt.Errorf("unexpected endpoint %q", endpoint)
		}
		if calls.Add(1) == committeeSize {
			launchOnce.Do(func() { close(allLaunched) })
		}
		if index == committeeSize-1 {
			<-ctx.Done()
			time.Sleep(25 * time.Millisecond)
			close(tailDone)
			return nil, ctx.Err()
		}
		select {
		case <-releaseQuorum:
			return testTxQUICReceipt(endpoint, publicKeyByEndpoint[endpoint], ack), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	type quorumResult struct {
		receipts int
		err      error
	}
	resultCh := make(chan quorumResult, 1)
	go func() {
		receipts, err := q.forwardFHSQuorumPayloadWith(context.Background(), payload, forward)
		resultCh <- quorumResult{receipts: receipts, err: err}
	}()
	select {
	case <-allLaunched:
	case <-time.After(time.Second):
		t.Fatal("saturation test did not launch the hedged endpoint")
	}
	releasedAt := time.Now()
	close(releaseQuorum)
	select {
	case result := <-resultCh:
		t.Fatalf("saturated handoff returned before canceled endpoint drain: receipts %d err %v", result.receipts, result.err)
	case <-time.After(15 * time.Millisecond):
	}
	select {
	case result := <-resultCh:
		if result.err != nil || result.receipts != txQUICReceiptQuorum(committeeSize) {
			t.Fatalf("saturated handoff result = receipts %d err %v", result.receipts, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("saturated handoff did not finish after endpoint drain")
	}
	select {
	case <-tailDone:
	default:
		t.Fatal("saturated handoff returned before its endpoint goroutine exited")
	}
	if elapsed := time.Since(releasedAt); elapsed < 20*time.Millisecond {
		t.Fatalf("saturated handoff returned before delayed endpoint completion: %v", elapsed)
	}
}

func testTxOutboxPlacementState(t *testing.T, committeeSize int, basePort int) txOutboxPlacementState {
	t.Helper()
	state := txOutboxPlacementState{
		KeyNumber:       testTxQUICKeyNumber,
		CommitteeHash:   testTxQUICCommitteeHash(),
		Endpoints:       make([]string, committeeSize),
		PublicKeys:      make([][]byte, committeeSize),
		CompletedBitmap: make([]byte, txQUICBitmapBytes(committeeSize)),
	}
	for index := 0; index < committeeSize; index++ {
		state.Endpoints[index] = fmt.Sprintf("127.0.0.1:%d", basePort+index)
		secret := new(bls.SecretKey)
		secret.SetByCSPRNG()
		state.PublicKeys[index] = secret.GetPublicKey().Serialize()
	}
	if err := validateTxOutboxPlacementState(state, false); err != nil {
		t.Fatal(err)
	}
	return state
}

func testTxOutboxPromotionAggregate(t *testing.T, config TxQUICConfig, payload []byte, state txOutboxPlacementState) txQUICAck {
	t.Helper()
	batch, _, err := decodeTxQUICBatch(payload)
	if err != nil {
		t.Fatal(err)
	}
	packet := testTxQUICPacketFromBatch(
		config, batch, common.HexToAddress("0x7400000000000000000000000000000000000007"), 1, uint64(time.Now().Unix()),
	)
	packet.KeyNumber = state.KeyNumber
	packet.CommitteeHash = state.CommitteeHash
	durable := make([]int, len(packet.Items))
	for index := range durable {
		durable[index] = index
	}
	return testTxQUICAck(t, packet, durable, nil, nil)
}

func testTxQUICRouteForPlacement(t *testing.T, state txOutboxPlacementState, portOffset int) TxQUICFHSRoute {
	t.Helper()
	addresses := make([]string, len(state.Endpoints))
	publicKeys := make([]string, len(state.PublicKeys))
	for index, endpoint := range state.Endpoints {
		host, portText, err := net.SplitHostPort(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port <= portOffset {
			t.Fatalf("invalid placement endpoint %q for offset %d", endpoint, portOffset)
		}
		addresses[index] = net.JoinHostPort(host, strconv.Itoa(port-portOffset))
		publicKeys[index] = fmt.Sprintf("%x", state.PublicKeys[index])
	}
	return TxQUICFHSRoute{
		ProposalView: 1, KeyNumber: state.KeyNumber, CommitteeHash: state.CommitteeHash,
		LeaderIndex: 0, LeaderAddress: addresses[0],
		CommitteeAddresses: addresses, CommitteePublicKeys: publicKeys,
	}
}

func TestTxQUICQuorumPersistsTailBeforeSaturatedHandoff(t *testing.T) {
	config := testTxQUICConfig()
	config.BridgeEnabled = true
	config.ForwardHedgeDelay = time.Second
	db := memorydb.New()
	outbox := NewTxOutbox(db, config)
	deliveryStarted := make(chan struct{})
	var deliveryOnce sync.Once
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		deliveryOnce.Do(func() { close(deliveryStarted) })
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	defer outbox.Stop()

	batch := testTxQUICBatch(t, config, testTxQUICTransaction(7400, 0))
	payload, err := rlp.EncodeToBytes(batch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.StoreSync(context.Background(), payload); err != nil {
		t.Fatal(err)
	}
	select {
	case <-deliveryStarted:
	case <-time.After(time.Second):
		t.Fatal("outbox record did not enter its foreground delivery attempt")
	}

	q := NewTxQUICIngress(config, nil)
	defer q.cancel()
	q.SetDurableOutbox(outbox, nil)
	enableTestTxQUICBackgroundHandoff(t, q)
	for len(q.backgroundForwards) < cap(q.backgroundForwards) {
		q.backgroundForwards <- txQUICBackgroundForward{payload: []byte{1}, endpoints: []string{"occupied"}}
	}

	const committeeSize = 4
	committeeAddresses := make([]string, committeeSize)
	committeePublicKeys := make([]string, committeeSize)
	for index := 0; index < committeeSize; index++ {
		committeeAddresses[index] = fmt.Sprintf("127.0.0.1:%d", 7702+index*2)
		secret := new(bls.SecretKey)
		secret.SetByCSPRNG()
		committeePublicKeys[index] = secret.GetPublicKey().SerializeToHexStr()
	}
	route := TxQUICFHSRoute{
		ProposalView: 1, KeyNumber: testTxQUICKeyNumber, CommitteeHash: testTxQUICCommitteeHash(),
		LeaderIndex: 0, LeaderAddress: committeeAddresses[0],
		CommitteeAddresses: committeeAddresses, CommitteePublicKeys: committeePublicKeys,
	}
	q.SetFHSRouteProvider(func() (TxQUICFHSRoute, error) { return route, nil })
	cached, err := q.refreshFHSRouteCache()
	if err != nil {
		t.Fatal(err)
	}
	publicKeyByEndpoint := make(map[string][]byte, committeeSize)
	for index, endpoint := range cached.CommitteeEndpoints {
		publicKeyByEndpoint[canonicalTxQUICEndpoint(endpoint)] = cached.CommitteePublicKeys[index]
	}
	packet := testTxQUICPacketFromBatch(
		config, batch, common.HexToAddress("0x7410000000000000000000000000000000000007"), 1, uint64(time.Now().Unix()),
	)
	wirePayload, err := rlp.EncodeToBytes(packet)
	if err != nil {
		t.Fatal(err)
	}
	ack := testTxQUICAck(t, packet, []int{0}, nil, nil)
	forward := func(_ context.Context, endpoint string, _ []byte) (*txQUICAckReceipt, error) {
		key := publicKeyByEndpoint[canonicalTxQUICEndpoint(endpoint)]
		if len(key) == 0 {
			return nil, fmt.Errorf("unexpected endpoint %q", endpoint)
		}
		return testTxQUICReceipt(endpoint, key, ack), nil
	}
	receipts, err := q.forwardFHSQuorumPayloadWithPersistence(
		context.Background(), wirePayload, forward,
		func(batchID common.Hash, state txOutboxPlacementState, aggregate txQUICAck) error {
			return outbox.promotePlacementSync(batchID, state, aggregate)
		},
	)
	var pending *txOutboxPlacementPendingError
	if !errors.As(err, &pending) || receipts != txQUICReceiptQuorum(committeeSize) {
		t.Fatalf("saturated durable handoff = receipts %d err %v", receipts, err)
	}
	persisted, exists, err := outbox.placementForBatch(batch.BatchID, payload)
	if err != nil || !exists {
		t.Fatalf("persisted tail lookup = exists %t err %v", exists, err)
	}
	completed := 0
	for index := range persisted.Endpoints {
		if txQUICBitmapHas(persisted.CompletedBitmap, index) {
			completed++
		}
	}
	if completed != txQUICReceiptQuorum(committeeSize) || persisted.complete() {
		t.Fatalf("persisted saturated placement completed %d/%d endpoints", completed, committeeSize)
	}
	if records, charged := outbox.Pending(); records != 1 || charged != int64(len(payload))+txOutboxPlacementReserveBytes {
		t.Fatalf("durable placement accounting = %d records/%d bytes", records, charged)
	}
}

func TestTxQUICItemWiseQuorumPromotionSurvivesRestartWithTwoCompleteEndpoints(t *testing.T) {
	config := testTxQUICConfig()
	config.ForwardHedgeDelay = time.Millisecond
	db := memorydb.New()
	outbox := NewTxOutbox(db, config)
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}

	batch := testTxQUICBatch(t, config,
		testTxQUICTransaction(7420, 0),
		testTxQUICTransaction(7421, 0),
		testTxQUICTransaction(7422, 0),
	)
	payload, err := rlp.EncodeToBytes(batch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.StoreSync(context.Background(), payload); err != nil {
		t.Fatal(err)
	}

	state := testTxOutboxPlacementState(t, 4, 11800)
	q := NewTxQUICIngress(config, nil)
	defer q.cancel()
	q.SetDurableOutbox(outbox, nil)
	route := testTxQUICRouteForPlacement(t, state, q.config.PortOffset)
	q.SetFHSRouteProvider(func() (TxQUICFHSRoute, error) { return route, nil })
	packet := testTxQUICPacketFromBatch(
		config, batch, common.HexToAddress("0x7420000000000000000000000000000000000007"), 1, uint64(time.Now().Unix()),
	)
	wirePayload, err := rlp.EncodeToBytes(packet)
	if err != nil {
		t.Fatal(err)
	}
	expectation, err := newTxQUICAckExpectation(packet)
	if err != nil {
		t.Fatal(err)
	}
	permanent := []txQUICPermanentError{{
		Index: 1, ItemID: expectation.itemIDs[1], Code: txQUICPermanentInvalidTransaction, Reason: "invalid transaction",
	}}
	receipts := []txQUICAck{
		testTxQUICAck(t, packet, []int{0, 2}, []int{1}, nil),
		testTxQUICAck(t, packet, []int{0, 2}, nil, permanent),
		testTxQUICAck(t, packet, []int{0, 2}, nil, permanent),
		testTxQUICAck(t, packet, nil, []int{0, 2}, permanent),
	}
	endpointIndex := make(map[string]int, len(state.Endpoints))
	for index, endpoint := range state.Endpoints {
		endpointIndex[endpoint] = index
	}
	forward := func(_ context.Context, endpoint string, _ []byte) (*txQUICAckReceipt, error) {
		index, ok := endpointIndex[canonicalTxQUICEndpoint(endpoint)]
		if !ok {
			return nil, fmt.Errorf("unexpected endpoint %q", endpoint)
		}
		return testTxQUICReceipt(endpoint, state.PublicKeys[index], receipts[index]), nil
	}
	count, err := q.forwardFHSQuorumPayloadWithPersistence(
		context.Background(), wirePayload, forward,
		func(batchID common.Hash, placement txOutboxPlacementState, aggregate txQUICAck) error {
			return outbox.promotePlacementSync(batchID, placement, aggregate)
		},
	)
	var pending *txOutboxPlacementPendingError
	if !errors.As(err, &pending) || count != 4 {
		t.Fatalf("mixed item-wise quorum = receipts %d err %v", count, err)
	}
	persisted, exists, err := outbox.placementForBatch(batch.BatchID, payload)
	if err != nil || !exists || !persisted.QuorumEstablished {
		t.Fatalf("mixed item-wise placement = exists %t promoted %t err %v", exists, persisted.QuorumEstablished, err)
	}
	completed := 0
	for index := range persisted.Endpoints {
		if txQUICBitmapHas(persisted.CompletedBitmap, index) {
			completed++
		}
	}
	if completed != 2 || completed >= txQUICReceiptQuorum(len(persisted.Endpoints)) {
		t.Fatalf("mixed item-wise placement completed %d endpoints, want 2 below endpoint quorum", completed)
	}
	outbox.Stop()

	restarted := NewTxOutbox(db, config)
	if err := restarted.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatalf("restart rejected item-wise quorum promotion: %v", err)
	}
	defer restarted.Stop()
	restored, exists, err := restarted.placementForBatch(batch.BatchID, payload)
	if err != nil || !exists || !restored.QuorumEstablished {
		t.Fatalf("restart item-wise placement = exists %t promoted %t err %v", exists, restored.QuorumEstablished, err)
	}
	restoredCompleted := 0
	for index := range restored.Endpoints {
		if txQUICBitmapHas(restored.CompletedBitmap, index) {
			restoredCompleted++
		}
	}
	if restoredCompleted != 2 {
		t.Fatalf("restart recovered %d complete endpoints, want 2", restoredCompleted)
	}
}

func TestTxOutboxPlacementReserveAllowsPromotionAtFullCapacity(t *testing.T) {
	config := testTxQUICConfig()
	payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(7500, 0))
	config.OutboxMaxRecords = 1
	config.OutboxMaxBytes = int64(len(payload)) + txOutboxPlacementReserveBytes
	db := memorydb.New()
	outbox := NewTxOutbox(db, config)
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	defer outbox.Stop()
	batchID, err := outbox.StoreSync(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}

	state := testTxOutboxPlacementState(t, params.MaxFairHotstuffCommitteeSize, 12000)
	for index := range state.Endpoints {
		host := fmt.Sprintf("%03d-%s", index, strings.Repeat("a", 480))
		state.Endpoints[index] = net.JoinHostPort(host, strconv.Itoa(12000+index))
	}
	for index := 0; index < txQUICReceiptQuorum(len(state.Endpoints)); index++ {
		txQUICBitmapSet(state.CompletedBitmap, index)
	}
	if err := validateTxOutboxPlacementState(state, false); err != nil {
		t.Fatal(err)
	}
	baseRecord := testTxOutboxStoredRecord(t, db, batchID)
	baseEncoded, err := rlp.EncodeToBytes(&baseRecord)
	if err != nil {
		t.Fatal(err)
	}
	stagedRecord := baseRecord
	stagedRecord.Placement = state
	stagedRecord.Placement.QuorumEstablished = true
	stagedEncoded, err := rlp.EncodeToBytes(&stagedRecord)
	if err != nil {
		t.Fatal(err)
	}
	if growth := int64(len(stagedEncoded) - len(baseEncoded)); growth <= 0 || growth > txOutboxPlacementReserveBytes {
		t.Fatalf("maximum placement encoding growth = %d, reserve %d", growth, txOutboxPlacementReserveBytes)
	}
	if err := outbox.promotePlacementSync(batchID, state, testTxOutboxPromotionAggregate(t, config, payload, state)); err != nil {
		t.Fatalf("stage promotion at exact reserved capacity failed: %v", err)
	}
	blockedCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err = outbox.StoreSync(blockedCtx, testTxQUICBatchPayload(t, config, testTxQUICTransaction(7501, 0)))
	cancel()
	if err == nil || !strings.Contains(err.Error(), "capacity wait") {
		t.Fatalf("record bypassed placement-reserved capacity: %v", err)
	}
}

func TestTxOutboxPlacementPromotionRequiresTrustedPayloadBoundTerminalAggregate(t *testing.T) {
	config := testTxQUICConfig()
	db := memorydb.New()
	outbox := NewTxOutbox(db, config)
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	defer outbox.Stop()
	payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(7525, 0))
	batchID, err := outbox.StoreSync(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	state := testTxOutboxPlacementState(t, 4, 12300)
	aggregate := testTxOutboxPromotionAggregate(t, config, payload, state)

	preMarked := cloneTxOutboxPlacementState(state)
	preMarked.QuorumEstablished = true
	if err := outbox.promotePlacementSync(batchID, preMarked, aggregate); err == nil || !strings.Contains(err.Error(), "marker must be set by the durable writer") {
		t.Fatalf("caller-forged promotion marker error = %v", err)
	}
	incomplete := cloneTxQUICAck(aggregate)
	txQUICBitmapClear(incomplete.DurableBitmap, 0)
	txQUICBitmapSet(incomplete.RetryableBitmap, 0)
	if err := outbox.promotePlacementSync(batchID, state, incomplete); err == nil || !strings.Contains(err.Error(), "aggregate is incomplete") {
		t.Fatalf("incomplete aggregate promotion error = %v", err)
	}
	wrongBatch := cloneTxQUICAck(aggregate)
	wrongBatch.BatchID = common.HexToHash("0xbad7525")
	if err := outbox.promotePlacementSync(batchID, state, wrongBatch); err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("payload-mismatched aggregate promotion error = %v", err)
	}
	if placement, exists, err := outbox.placementForBatch(batchID, payload); err != nil || exists || placement.present() {
		t.Fatalf("rejected promotion created placement: exists=%t state=%#v err=%v", exists, placement, err)
	}
	if err := outbox.promotePlacementSync(batchID, state, aggregate); err != nil {
		t.Fatalf("trusted terminal aggregate promotion failed: %v", err)
	}
	persisted, exists, err := outbox.placementForBatch(batchID, payload)
	if err != nil || !exists || !persisted.QuorumEstablished {
		t.Fatalf("trusted promotion = exists %t promoted %t err %v", exists, persisted.QuorumEstablished, err)
	}
	for index := range persisted.Endpoints {
		if txQUICBitmapHas(persisted.CompletedBitmap, index) {
			t.Fatalf("trusted item-wise promotion invented endpoint completion at %d", index)
		}
	}
}

func TestTxOutboxAmbiguousPlacementPromotionRecoversOnRestart(t *testing.T) {
	config := testTxQUICConfig()
	base := memorydb.New()
	db := &ambiguousSyncTxQUICDB{KeyValueStore: base}
	outbox := NewTxOutbox(db, config)
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(7550, 0))
	batchID, err := outbox.StoreSync(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	state := testTxOutboxPlacementState(t, 4, 12500)
	for index := 0; index < txQUICReceiptQuorum(len(state.Endpoints)); index++ {
		txQUICBitmapSet(state.CompletedBitmap, index)
	}
	db.failAfterApply.Store(true)
	if err := outbox.promotePlacementSync(batchID, state, testTxOutboxPromotionAggregate(t, config, payload, state)); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous placement promotion error = %v", err)
	}
	outbox.Stop()

	restarted := NewTxOutbox(base, config)
	if err := restarted.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatalf("restart rejected the atomically applied placement stage: %v", err)
	}
	defer restarted.Stop()
	persisted, exists, err := restarted.placementForBatch(batchID, payload)
	if err != nil || !exists {
		t.Fatalf("restart placement lookup = exists %t err %v", exists, err)
	}
	completed := 0
	for index := range persisted.Endpoints {
		if txQUICBitmapHas(persisted.CompletedBitmap, index) {
			completed++
		}
	}
	if completed != txQUICReceiptQuorum(len(state.Endpoints)) {
		t.Fatalf("restart recovered %d completed endpoints, want quorum", completed)
	}
}

func TestTxOutboxAmbiguousAcknowledgedDeletePoisonsUntilRestartScan(t *testing.T) {
	config := testTxQUICConfig()
	base := memorydb.New()
	db := &ambiguousSyncTxQUICDB{KeyValueStore: base}
	outbox := NewTxOutbox(db, config)
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(7575, 0))
	batchID, err := outbox.StoreSync(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	record := testTxOutboxStoredRecord(t, base, batchID)
	wantBytes, err := txOutboxRecordCapacityBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	db.failAfterApply.Store(true)
	if err := outbox.deleteRecord(&record); err == nil || !strings.Contains(err.Error(), "ambiguous acknowledged outbox delete") {
		t.Fatalf("ambiguous acknowledged delete error = %v", err)
	}
	outbox.mu.Lock()
	poison := outbox.poison
	outbox.mu.Unlock()
	if poison == nil {
		t.Fatal("ambiguous acknowledged delete did not poison the live outbox")
	}
	if records, charged := outbox.Pending(); records != 1 || charged != wantBytes {
		t.Fatalf("ambiguous acknowledged delete changed accounting to %d records/%d bytes, want 1/%d", records, charged, wantBytes)
	}
	if has, err := base.Has(txOutboxRecordKey(batchID)); err != nil || has {
		t.Fatalf("applied-then-error delete underlying record = has %t err %v", has, err)
	}
	outbox.Stop()

	restarted := NewTxOutbox(base, config)
	if err := restarted.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatalf("restart scan after ambiguous delete failed: %v", err)
	}
	defer restarted.Stop()
	if records, charged := restarted.Pending(); records != 0 || charged != 0 {
		t.Fatalf("restart scan retained deleted record accounting: %d records/%d bytes", records, charged)
	}
}

func TestTxOutboxRestartDrainsTailWithRotatingCursor(t *testing.T) {
	config := testTxQUICConfig()
	config.OutboxWorkers = 1
	config.OutboxRetryMin = time.Millisecond
	config.OutboxRetryMax = 2 * time.Millisecond
	db := memorydb.New()
	batch := testTxQUICBatch(t, config, testTxQUICTransaction(7600, 0))
	payload, err := rlp.EncodeToBytes(batch)
	if err != nil {
		t.Fatal(err)
	}

	first := NewTxOutbox(db, config)
	if err := first.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := first.StoreSync(context.Background(), payload); err != nil {
		t.Fatal(err)
	}
	state := testTxOutboxPlacementState(t, 7, 13000)
	quorum := txQUICReceiptQuorum(len(state.Endpoints))
	for index := 0; index < quorum; index++ {
		txQUICBitmapSet(state.CompletedBitmap, index)
	}
	state.NextEndpoint = uint32(quorum)
	if err := first.promotePlacementSync(batch.BatchID, state, testTxOutboxPromotionAggregate(t, config, payload, state)); err != nil {
		t.Fatal(err)
	}
	first.Stop()

	packet := testTxQUICPacketFromBatch(
		config, batch, common.HexToAddress("0x7610000000000000000000000000000000000007"), 1, uint64(time.Now().Unix()),
	)
	wirePayload, err := rlp.EncodeToBytes(packet)
	if err != nil {
		t.Fatal(err)
	}
	ack := testTxQUICAck(t, packet, []int{0}, nil, nil)
	second := NewTxOutbox(db, config)
	q := NewTxQUICIngress(config, nil)
	defer q.cancel()
	q.SetDurableOutbox(second, nil)
	currentRoute := testTxQUICRouteForPlacement(t, state, q.config.PortOffset)
	q.SetFHSRouteProvider(func() (TxQUICFHSRoute, error) { return currentRoute, nil })
	var (
		callsMu sync.Mutex
		calls   []string
		failed  bool
	)
	forward := func(_ context.Context, endpoint string, _ []byte) (*txQUICAckReceipt, error) {
		callsMu.Lock()
		calls = append(calls, endpoint)
		if endpoint == state.Endpoints[quorum] && !failed {
			failed = true
			callsMu.Unlock()
			return nil, errors.New("deterministic endpoint outage")
		}
		index := -1
		for candidate, member := range state.Endpoints {
			if member == endpoint {
				index = candidate
				break
			}
		}
		callsMu.Unlock()
		if index < 0 {
			return nil, fmt.Errorf("unexpected endpoint %q", endpoint)
		}
		return testTxQUICReceipt(endpoint, state.PublicKeys[index], ack), nil
	}
	restored := 0
	if err := second.Start(context.Background(), func(ctx context.Context, delivered []byte) error {
		placement, exists, err := second.placementForBatch(batch.BatchID, delivered)
		if err != nil || !exists {
			return fmt.Errorf("restart placement lookup: exists %t err %v", exists, err)
		}
		return q.deliverOutboxPlacementWith(ctx, batch.BatchID, wirePayload, placement, forward)
	}, func(restoredPayload []byte) error {
		restored++
		if !bytes.Equal(restoredPayload, payload) {
			return fmt.Errorf("restored payload changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	defer second.Stop()
	deadline := time.Now().Add(time.Second)
	for {
		has, err := db.Has(txOutboxRecordKey(batch.BatchID))
		if err != nil {
			t.Fatal(err)
		}
		if !has {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("restart did not eventually finish durable committee tail placement")
		}
		time.Sleep(time.Millisecond)
	}
	if restored != 1 {
		t.Fatalf("restart restored %d semantic batches, want 1", restored)
	}
	callsMu.Lock()
	gotCalls := append([]string(nil), calls...)
	callsMu.Unlock()
	wantCalls := []string{state.Endpoints[quorum], state.Endpoints[quorum+1], state.Endpoints[quorum]}
	if fmt.Sprint(gotCalls) != fmt.Sprint(wantCalls) {
		t.Fatalf("restart tail attempts = %v, want rotating eventual delivery %v", gotCalls, wantCalls)
	}
	if records, charged := second.Pending(); records != 0 || charged != 0 {
		t.Fatalf("completed restart tail retained %d records/%d bytes", records, charged)
	}
}

func TestTxOutboxTailReceiptRetainedAcrossCommitteeTransition(t *testing.T) {
	config := testTxQUICConfig()
	db := memorydb.New()
	outbox := NewTxOutbox(db, config)
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	defer outbox.Stop()

	batch := testTxQUICBatch(t, config, testTxQUICTransaction(7650, 0))
	payload, err := rlp.EncodeToBytes(batch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.StoreSync(context.Background(), payload); err != nil {
		t.Fatal(err)
	}
	oldState := testTxOutboxPlacementState(t, 4, 13500)
	for index := 0; index < 3; index++ {
		txQUICBitmapSet(oldState.CompletedBitmap, index)
	}
	oldState.NextEndpoint = 3
	if err := outbox.promotePlacementSync(batch.BatchID, oldState, testTxOutboxPromotionAggregate(t, config, payload, oldState)); err != nil {
		t.Fatal(err)
	}
	persisted, exists, err := outbox.placementForBatch(batch.BatchID, payload)
	if err != nil || !exists {
		t.Fatalf("old placement lookup = exists %t err %v", exists, err)
	}

	q := NewTxQUICIngress(config, nil)
	defer q.cancel()
	q.SetDurableOutbox(outbox, nil)
	oldRoute := testTxQUICRouteForPlacement(t, oldState, q.config.PortOffset)
	newState := testTxOutboxPlacementState(t, 4, 14500)
	newState.KeyNumber = oldState.KeyNumber + 1
	newState.CommitteeHash = common.HexToHash("0xa765000000000000000000000000000000000000000000000000000000000001")
	newRoute := testTxQUICRouteForPlacement(t, newState, q.config.PortOffset)
	var routeMu sync.Mutex
	currentRoute := oldRoute
	q.SetFHSRouteProvider(func() (TxQUICFHSRoute, error) {
		routeMu.Lock()
		defer routeMu.Unlock()
		return currentRoute, nil
	})
	if _, err := q.refreshFHSRouteCache(); err != nil {
		t.Fatal(err)
	}
	packet := testTxQUICPacketFromBatch(
		config, batch, common.HexToAddress("0x7650000000000000000000000000000000000007"), 1, uint64(time.Now().Unix()),
	)
	wirePayload, err := rlp.EncodeToBytes(packet)
	if err != nil {
		t.Fatal(err)
	}
	ack := testTxQUICAck(t, packet, []int{0}, nil, nil)
	forward := func(_ context.Context, endpoint string, _ []byte) (*txQUICAckReceipt, error) {
		if endpoint != oldState.Endpoints[3] {
			return nil, fmt.Errorf("unexpected old-generation endpoint %q", endpoint)
		}
		routeMu.Lock()
		currentRoute = newRoute
		routeMu.Unlock()
		return testTxQUICReceipt(endpoint, oldState.PublicKeys[3], ack), nil
	}
	err = q.deliverOutboxPlacementWith(context.Background(), batch.BatchID, wirePayload, persisted, forward)
	var pending *txOutboxPlacementPendingError
	if !errors.As(err, &pending) || pending == nil || !pending.Retry {
		t.Fatalf("tail ACK across committee transition error = %v, want retryable retained placement", err)
	}
	after, exists, err := outbox.placementForBatch(batch.BatchID, payload)
	if err != nil || !exists {
		t.Fatalf("retained old placement lookup = exists %t err %v", exists, err)
	}
	if txQUICBitmapHas(after.CompletedBitmap, 3) || after.NextEndpoint != oldState.NextEndpoint {
		t.Fatalf("old generation was checkpointed after transition: bitmap=%x cursor=%d", after.CompletedBitmap, after.NextEndpoint)
	}
	has, err := db.Has(txOutboxRecordKey(batch.BatchID))
	if err != nil || !has {
		t.Fatalf("committee transition removed durable semantic record: has=%t err=%v", has, err)
	}
}

func TestTxQUICReceiptAccumulatorSingleByzantinePermanentDoesNotGC(t *testing.T) {
	config := testTxQUICConfig()
	sender := common.HexToAddress("0x3020000000000000000000000000000000000003")
	tx := testTxQUICTransaction(14, 0)
	packet := testTxQUICPacket(t, config, sender, 1, tx)
	expectation, err := newTxQUICAckExpectation(packet)
	if err != nil {
		t.Fatal(err)
	}
	accumulator, err := newTxQUICReceiptAccumulator(expectation, txQUICReceiptQuorum(4))
	if err != nil {
		t.Fatal(err)
	}
	byzantine := testTxQUICAck(t, packet, nil, nil, []txQUICPermanentError{{
		Index: 0, ItemID: expectation.itemIDs[0], Code: txQUICPermanentInvalidTransaction, Reason: "fabricated permanent rejection",
	}})
	identityA := []byte("byzantine-validator-consensus-key")
	if added, err := accumulator.add(testTxQUICReceipt("validator-0", identityA, byzantine)); err != nil || !added {
		t.Fatalf("Byzantine receipt added=%t err=%v", added, err)
	}

	aggregate, complete := accumulator.outcome()
	if complete || len(aggregate.PermanentErrors) != 0 || !txQUICBitmapHas(aggregate.RetryableBitmap, 0) {
		t.Fatalf("one permanent receipt became final: complete=%t ack=%#v", complete, aggregate)
	}
	var rejected *txQUICRemoteRejectError
	if err := txQUICOutcomeError("four-validator committee", aggregate, expectation); !errors.As(err, &rejected) || !rejected.Retryable() {
		t.Fatalf("single permanent receipt error=%v, want retryable quorum-incomplete outcome", err)
	}

	payload, err := rlp.EncodeToBytes(&txQUICBatch{
		ChainID: config.ChainID, GenesisHash: config.GenesisHash, BatchID: packet.BatchID,
		TxRoot: packet.TxRoot, Certificate: packet.Certificate, Items: packet.Items,
	})
	if err != nil {
		t.Fatal(err)
	}
	record := &TxOutboxRecord{BatchID: packet.BatchID, Payload: payload, CreatedAt: 1}
	retained, oldDeleted, err := new(TxOutbox).compactAcknowledgedRecord(record, &aggregate)
	if err != nil {
		t.Fatal(err)
	}
	if oldDeleted || retained != record {
		t.Fatalf("one Byzantine receipt garbage-collected the outbox: retained=%#v oldDeleted=%t", retained, oldDeleted)
	}

	// One honest durable receipt disagrees with the Byzantine vote. Neither
	// outcome has no 2f+1 support, so the sender must still retain the transaction.
	honest := testTxQUICAck(t, packet, []int{0}, nil, nil)
	identityB := []byte("honest-validator-b-consensus-key")
	if added, err := accumulator.add(testTxQUICReceipt("validator-1", identityB, honest)); err != nil || !added {
		t.Fatalf("honest receipt added=%t err=%v", added, err)
	}
	aggregate, complete = accumulator.outcome()
	if complete || !txQUICBitmapHas(aggregate.RetryableBitmap, 0) {
		t.Fatalf("one durable and one permanent vote reached quorum: complete=%t ack=%#v", complete, aggregate)
	}
}

func TestTxQUICReceiptAccumulatorAggregatesFourEndpointsItemWise(t *testing.T) {
	config := testTxQUICConfig()
	sender := common.HexToAddress("0x3030000000000000000000000000000000000003")
	packet := testTxQUICPacket(t, config, sender, 1,
		testTxQUICTransaction(15, 0),
		testTxQUICTransaction(16, 0),
		testTxQUICTransaction(17, 0),
	)
	expectation, err := newTxQUICAckExpectation(packet)
	if err != nil {
		t.Fatal(err)
	}
	accumulator, err := newTxQUICReceiptAccumulator(expectation, txQUICReceiptQuorum(4))
	if err != nil {
		t.Fatal(err)
	}
	permanent := func() []txQUICPermanentError {
		return []txQUICPermanentError{{
			Index: 1, ItemID: expectation.itemIDs[1], Code: txQUICPermanentInvalidTransaction, Reason: "invalid transaction",
		}}
	}
	receipts := []*txQUICAckReceipt{
		testTxQUICReceipt("validator-0", []byte("mixed-validator-0"), testTxQUICAck(t, packet, []int{0, 2}, []int{1}, nil)),
		testTxQUICReceipt("validator-1", []byte("mixed-validator-1"), testTxQUICAck(t, packet, []int{0, 2}, nil, permanent())),
		testTxQUICReceipt("validator-2", []byte("mixed-validator-2"), testTxQUICAck(t, packet, []int{0, 2}, nil, permanent())),
		testTxQUICReceipt("validator-3", []byte("mixed-validator-3"), testTxQUICAck(t, packet, nil, []int{0, 2}, permanent())),
	}
	for index, receipt := range receipts {
		added, err := accumulator.add(receipt)
		if err != nil || !added {
			t.Fatalf("receipt %d added=%t err=%v", index, added, err)
		}
		_, complete := accumulator.outcome()
		if index < len(receipts)-1 && complete {
			t.Fatalf("receipt %d completed the item-wise quorum too early", index)
		}
	}

	aggregate, complete := accumulator.outcome()
	if !complete || !txQUICBitmapHas(aggregate.DurableBitmap, 0) || txQUICBitmapHas(aggregate.DurableBitmap, 1) || !txQUICBitmapHas(aggregate.DurableBitmap, 2) {
		t.Fatalf("item-wise durable aggregate = complete %t ack=%#v", complete, aggregate)
	}
	if !txQUICBitmapEmpty(aggregate.RetryableBitmap) || len(aggregate.PermanentErrors) != 1 {
		t.Fatalf("item-wise terminal aggregate = %#v", aggregate)
	}
	gotPermanent := aggregate.PermanentErrors[0]
	if gotPermanent.Index != 1 || gotPermanent.ItemID != expectation.itemIDs[1] || gotPermanent.Code != txQUICPermanentInvalidTransaction {
		t.Fatalf("item-wise permanent aggregate = %#v", gotPermanent)
	}
	if err := validateTxQUICAckOutcome(&aggregate, expectation); err != nil {
		t.Fatalf("item-wise aggregate is invalid: %v", err)
	}
	var rejected *txQUICRemoteRejectError
	if err := txQUICOutcomeError("four-validator committee", aggregate, expectation); err == nil || !errors.As(err, &rejected) || rejected.Retryable() {
		t.Fatalf("terminal mixed aggregate error=%v, want non-retryable permanent outcome", err)
	}
}

func TestTxQUICPacketSignatureRejectsUnsignedAndMutatedEnvelope(t *testing.T) {
	config := testTxQUICConfig()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	packet := testTxQUICPacket(t, config, sender, 3, testTxQUICTransaction(20, 0))
	packet.Signature, err = crypto.Sign(packet.signingHash().Bytes(), key)
	if err != nil {
		t.Fatal(err)
	}
	ingress := &TxQUICIngress{signers: map[common.Address]struct{}{sender: {}}}
	if recovered, err := ingress.verifyPacket(packet); err != nil || recovered != sender {
		t.Fatalf("valid packet signature recovered %s, err=%v", recovered, err)
	}

	originalTimestamp := packet.Timestamp
	packet.Timestamp++
	if _, err := ingress.verifyPacket(packet); err == nil {
		t.Fatal("packet signature survived a timestamp mutation")
	}
	packet.Timestamp = originalTimestamp
	originalKeyNumber := packet.KeyNumber
	packet.KeyNumber++
	if _, err := ingress.verifyPacket(packet); err == nil {
		t.Fatal("packet signature survived a key-generation mutation")
	}
	packet.KeyNumber = originalKeyNumber
	originalCommitteeHash := packet.CommitteeHash
	packet.CommitteeHash = common.HexToHash("0xdead")
	if _, err := ingress.verifyPacket(packet); err == nil {
		t.Fatal("packet signature survived a committee-generation mutation")
	}
	packet.CommitteeHash = originalCommitteeHash

	packet.Signature[0] ^= 0x01
	if _, err := ingress.verifyPacket(packet); err == nil {
		t.Fatal("mutated packet signature was accepted")
	}
	packet.Signature = nil
	if _, err := ingress.verifyPacket(packet); err == nil {
		t.Fatal("unsigned packet was accepted")
	}
}

func TestTxQUICAckSignatureIsBoundToCanonicalCommitteeMember(t *testing.T) {
	config := testTxQUICConfig()
	sender := common.HexToAddress("0x3100000000000000000000000000000000000003")
	packet := testTxQUICPacket(t, config, sender, 1, testTxQUICTransaction(21, 0))
	ack := testTxQUICAck(t, packet, []int{0}, nil, nil)

	memberSecret, otherSecret := new(bls.SecretKey), new(bls.SecretKey)
	memberSecret.SetByCSPRNG()
	otherSecret.SetByCSPRNG()
	memberPublic := memberSecret.GetPublicKey().Serialize()
	otherPublic := otherSecret.GetPublicKey().Serialize()
	ack.CommitteePublicKey = append([]byte(nil), memberPublic...)
	digest, err := txQUICAckDigest(&ack)
	if err != nil {
		t.Fatal(err)
	}
	ack.Signature = memberSecret.SignHash(digest).Serialize()
	if err := verifyTxQUICAckSignature(memberPublic, &ack); err != nil {
		t.Fatalf("canonical committee member rejected its ACK: %v", err)
	}
	if err := verifyTxQUICAckSignature(otherPublic, &ack); err == nil {
		t.Fatal("ACK from a different committee member was accepted")
	}
	mutated := cloneTxQUICAck(ack)
	mutated.BatchID = common.HexToHash("0xdead")
	if err := verifyTxQUICAckSignature(memberPublic, &mutated); err == nil {
		t.Fatal("ACK signature survived a BatchID mutation")
	}
	mutated = cloneTxQUICAck(ack)
	mutated.KeyNumber++
	if err := verifyTxQUICAckSignature(memberPublic, &mutated); err == nil {
		t.Fatal("ACK signature survived a key-generation mutation")
	}
	mutated = cloneTxQUICAck(ack)
	mutated.CommitteeHash = common.HexToHash("0xbeef")
	if err := verifyTxQUICAckSignature(memberPublic, &mutated); err == nil {
		t.Fatal("ACK signature survived a committee-generation mutation")
	}
}

func TestTxQUICSignAckRejectsStaleGenerationBeforeInvokingSigner(t *testing.T) {
	config := testTxQUICConfig()
	packet := testTxQUICPacket(t, config, common.HexToAddress("0x3101000000000000000000000000000000000003"), 1, testTxQUICTransaction(22, 0))
	ack := testTxQUICAck(t, packet, []int{0}, nil, nil)

	committeeSecrets := make([]*bls.SecretKey, 4)
	committeePublicKeys := make([]string, len(committeeSecrets))
	for index := range committeeSecrets {
		committeeSecrets[index] = new(bls.SecretKey)
		committeeSecrets[index].SetByCSPRNG()
		committeePublicKeys[index] = committeeSecrets[index].GetPublicKey().SerializeToHexStr()
	}
	localSecret := committeeSecrets[2]
	localPublic := localSecret.GetPublicKey().Serialize()
	currentRoute := TxQUICFHSRoute{
		ProposalView:  10,
		KeyNumber:     ack.KeyNumber,
		CommitteeHash: ack.CommitteeHash,
		LeaderIndex:   1,
		LeaderAddress: "127.0.0.1:7104",
		CommitteeAddresses: []string{
			"127.0.0.1:7102", "127.0.0.1:7104", "127.0.0.1:7106", "127.0.0.1:7108",
		},
		CommitteePublicKeys: committeePublicKeys,
	}
	q := &TxQUICIngress{config: TxQUICConfig{PortOffset: 2000}}
	q.SetFHSRouteProvider(func() (TxQUICFHSRoute, error) { return currentRoute, nil })
	publicKeyCalls, signerCalls := 0, 0
	if err := q.SetFHSReceiptSigner(
		func() ([]byte, error) {
			publicKeyCalls++
			return append([]byte(nil), localPublic...), nil
		},
		func(keyNumber uint64, committeeHash common.Hash, digest []byte) ([]byte, error) {
			signerCalls++
			if keyNumber != ack.KeyNumber || committeeHash != ack.CommitteeHash {
				return nil, fmt.Errorf("unexpected signing generation %d/%s", keyNumber, committeeHash)
			}
			return localSecret.SignHash(digest).Serialize(), nil
		},
	); err != nil {
		t.Fatal(err)
	}

	signed, err := q.signAck(ack)
	if err != nil {
		t.Fatalf("current-generation ACK signing failed: %v", err)
	}
	if publicKeyCalls != 1 || signerCalls != 1 {
		t.Fatalf("current-generation signer calls = public key %d, signer %d", publicKeyCalls, signerCalls)
	}
	if !bytes.Equal(signed.CommitteePublicKey, localPublic) {
		t.Fatalf("signed ACK committee key = %x, want local canonical member %x", signed.CommitteePublicKey, localPublic)
	}
	if err := verifyTxQUICAckSignature(localPublic, &signed); err != nil {
		t.Fatalf("current-generation ACK signature is invalid: %v", err)
	}

	currentRoute.ProposalView++
	currentRoute.KeyNumber++
	currentRoute.CommitteeHash = common.HexToHash("0x987654321")
	if _, err := q.signAck(ack); err == nil || !strings.Contains(err.Error(), "committee changed before ACK signing") {
		t.Fatalf("stale-generation ACK signing error = %v", err)
	}
	if publicKeyCalls != 1 || signerCalls != 1 {
		t.Fatalf("stale-generation ACK reached signer callbacks: public key %d, signer %d", publicKeyCalls, signerCalls)
	}
	cached := q.cachedFHSRoute()
	if cached.KeyNumber != currentRoute.KeyNumber || cached.CommitteeHash != currentRoute.CommitteeHash {
		t.Fatalf("canonical route did not switch generations: cached %d/%s, want %d/%s", cached.KeyNumber, cached.CommitteeHash, currentRoute.KeyNumber, currentRoute.CommitteeHash)
	}
}

func TestReadTxQUICAckRejectsOversizeAndTrailingData(t *testing.T) {
	config := testTxQUICConfig()
	packet := testTxQUICPacket(t, config, common.HexToAddress("0x3110000000000000000000000000000000000003"), 1, testTxQUICTransaction(22, 0))
	ack := testTxQUICAck(t, packet, []int{0}, nil, nil)
	encoded, err := rlp.EncodeToBytes(&ack)
	if err != nil {
		t.Fatal(err)
	}
	trailing := append(append([]byte(nil), encoded...), 0x80)
	if _, err := readTxQUICAck(bytes.NewReader(trailing), len(packet.Items)); err == nil {
		t.Fatal("ACK with a trailing RLP value was accepted")
	}

	maxBytes := txQUICAckMaxEncodedBytes(len(packet.Items))
	if maxBytes <= 0 {
		t.Fatalf("invalid ACK bound %d", maxBytes)
	}
	oversize := make([]byte, int(maxBytes)+1)
	if _, err := readTxQUICAck(bytes.NewReader(oversize), len(packet.Items)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized ACK error = %v", err)
	}
}

func TestClassifyTxQUICInsertErrorRetriesPolicyAndForkDependentFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "block gas limit", err: core.ErrGasLimit},
		{name: "node data policy", err: core.ErrOversizedData},
		{name: "private gas policy", err: core.ErrInvalidGasPrice},
		{name: "private value policy", err: core.ErrEtherValueUnsupported},
		{name: "fork intrinsic gas", err: core.ErrIntrinsicGas},
		{name: "future transaction type", err: core.ErrTxTypeNotSupported},
		{name: "blob availability policy", err: core.ErrBlobDAUnavailable},
		{name: "payer sequence pending elsewhere", err: core.ErrNativeReplaySequenceReserved},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrapped := fmt.Errorf("receiver policy: %w", test.err)
			if got := classifyTxQUICInsertError(wrapped); got != txQUICRejectRetryable {
				t.Fatalf("classification = %d, want retryable (%d)", got, txQUICRejectRetryable)
			}
		})
	}
}

func TestTxQUICDatabaseIdentityFailsClosed(t *testing.T) {
	config := testTxQUICConfig()
	identity := txQUICDatabaseIdentity{ChainID: config.ChainID, GenesisHash: config.GenesisHash}
	db := memorydb.New()
	key := []byte("test/identity")
	if err := ensureTxQUICDatabaseIdentity(db, key, identity); err != nil {
		t.Fatal(err)
	}
	if err := ensureTxQUICDatabaseIdentity(db, key, identity); err != nil {
		t.Fatalf("same database identity was not idempotent: %v", err)
	}
	wrong := identity
	wrong.GenesisHash = common.HexToHash("0xbeef")
	if err := ensureTxQUICDatabaseIdentity(db, key, wrong); err == nil || !strings.Contains(err.Error(), "different or obsolete chain") {
		t.Fatalf("identity mismatch error = %v", err)
	}

	unidentified := memorydb.New()
	if err := unidentified.Put([]byte("orphaned-record"), []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := ensureTxQUICDatabaseIdentity(unidentified, key, identity); err == nil || !strings.Contains(err.Error(), "reset it with genesis") {
		t.Fatalf("unidentified non-empty database error = %v", err)
	}
	if err := ensureTxQUICDatabaseIdentity(memorydb.New(), key, txQUICDatabaseIdentity{}); err == nil {
		t.Fatal("zero chain identity was accepted")
	}
}

type countingTxQUICDB struct {
	ethdb.KeyValueStore
	syncWrites   atomic.Int32
	maxSyncBytes atomic.Int64
}

type countingTxQUICBatch struct {
	ethdb.Batch
	syncWrites   *atomic.Int32
	maxSyncBytes *atomic.Int64
	bytes        int64
}

type ambiguousSyncTxQUICDB struct {
	ethdb.KeyValueStore
	failAfterApply atomic.Bool
}

type ambiguousSyncTxQUICBatch struct {
	ethdb.Batch
	failAfterApply *atomic.Bool
}

type blockingSyncTxQUICDB struct {
	ethdb.KeyValueStore
	block   atomic.Bool
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type blockingSyncTxQUICBatch struct {
	ethdb.Batch
	db *blockingSyncTxQUICDB
}

type failingDeleteTxQUICDB struct {
	ethdb.KeyValueStore
	failDelete atomic.Bool
}

type failingDeleteTxQUICBatch struct {
	ethdb.Batch
	failDelete *atomic.Bool
}

type blockingHasTxQUICDB struct {
	ethdb.KeyValueStore
	target  []byte
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (db *blockingHasTxQUICDB) Has(key []byte) (bool, error) {
	if bytes.Equal(key, db.target) {
		db.once.Do(func() { close(db.entered) })
		<-db.release
	}
	return db.KeyValueStore.Has(key)
}

type failingPutTxQUICDB struct {
	ethdb.KeyValueStore
	failRecordPut atomic.Bool
}

type failingPutTxQUICBatch struct {
	ethdb.Batch
	failRecordPut *atomic.Bool
}

func (db *failingPutTxQUICDB) NewBatch() ethdb.Batch {
	return &failingPutTxQUICBatch{Batch: db.KeyValueStore.NewBatch(), failRecordPut: &db.failRecordPut}
}

func (batch *failingPutTxQUICBatch) Put(key, value []byte) error {
	if batch.failRecordPut.Load() && bytes.HasPrefix(key, txOutboxRecordPrefix) {
		return errors.New("simulated deterministic outbox projection put failure")
	}
	return batch.Batch.Put(key, value)
}

func (batch *failingPutTxQUICBatch) WriteSync() error {
	syncBatch, ok := batch.Batch.(ethdb.SyncBatch)
	if !ok {
		return errors.New("underlying test database has no synchronous batch")
	}
	return syncBatch.WriteSync()
}

type recordedTxQUICBatchOperation struct {
	kind string
	key  []byte
}

type recordingSyncTxQUICDB struct {
	ethdb.KeyValueStore
	mu     sync.Mutex
	writes [][]recordedTxQUICBatchOperation
}

type recordingSyncTxQUICBatch struct {
	ethdb.Batch
	db  *recordingSyncTxQUICDB
	ops []recordedTxQUICBatchOperation
}

func (db *recordingSyncTxQUICDB) NewBatch() ethdb.Batch {
	return &recordingSyncTxQUICBatch{Batch: db.KeyValueStore.NewBatch(), db: db}
}

func (batch *recordingSyncTxQUICBatch) Put(key []byte, value []byte) error {
	if err := batch.Batch.Put(key, value); err != nil {
		return err
	}
	batch.ops = append(batch.ops, recordedTxQUICBatchOperation{kind: "put", key: append([]byte(nil), key...)})
	return nil
}

func (batch *recordingSyncTxQUICBatch) Delete(key []byte) error {
	if err := batch.Batch.Delete(key); err != nil {
		return err
	}
	batch.ops = append(batch.ops, recordedTxQUICBatchOperation{kind: "delete", key: append([]byte(nil), key...)})
	return nil
}

func (batch *recordingSyncTxQUICBatch) WriteSync() error {
	syncBatch, ok := batch.Batch.(ethdb.SyncBatch)
	if !ok {
		return errors.New("underlying test database has no synchronous batch")
	}
	if err := syncBatch.WriteSync(); err != nil {
		return err
	}
	batch.db.mu.Lock()
	batch.db.writes = append(batch.db.writes, append([]recordedTxQUICBatchOperation(nil), batch.ops...))
	batch.db.mu.Unlock()
	return nil
}

func (db *recordingSyncTxQUICDB) resetWrites() {
	db.mu.Lock()
	db.writes = nil
	db.mu.Unlock()
}

func (db *recordingSyncTxQUICDB) recordedWrites() [][]recordedTxQUICBatchOperation {
	db.mu.Lock()
	defer db.mu.Unlock()
	writes := make([][]recordedTxQUICBatchOperation, len(db.writes))
	for index := range db.writes {
		writes[index] = append([]recordedTxQUICBatchOperation(nil), db.writes[index]...)
	}
	return writes
}

func (db *failingDeleteTxQUICDB) NewBatch() ethdb.Batch {
	return &failingDeleteTxQUICBatch{Batch: db.KeyValueStore.NewBatch(), failDelete: &db.failDelete}
}

func (batch *failingDeleteTxQUICBatch) Delete(key []byte) error {
	if batch.failDelete.Load() {
		return errors.New("simulated deterministic batch delete failure")
	}
	return batch.Batch.Delete(key)
}

func (batch *failingDeleteTxQUICBatch) WriteSync() error {
	syncBatch, ok := batch.Batch.(ethdb.SyncBatch)
	if !ok {
		return errors.New("underlying test database has no synchronous batch")
	}
	return syncBatch.WriteSync()
}

func (db *blockingSyncTxQUICDB) NewBatch() ethdb.Batch {
	return &blockingSyncTxQUICBatch{Batch: db.KeyValueStore.NewBatch(), db: db}
}

func (batch *blockingSyncTxQUICBatch) WriteSync() error {
	if batch.db.block.Load() {
		batch.db.once.Do(func() { close(batch.db.started) })
		<-batch.db.release
	}
	syncBatch, ok := batch.Batch.(ethdb.SyncBatch)
	if !ok {
		return errors.New("underlying test database has no synchronous batch")
	}
	return syncBatch.WriteSync()
}

func (db *ambiguousSyncTxQUICDB) NewBatch() ethdb.Batch {
	return &ambiguousSyncTxQUICBatch{Batch: db.KeyValueStore.NewBatch(), failAfterApply: &db.failAfterApply}
}

func (batch *ambiguousSyncTxQUICBatch) WriteSync() error {
	syncBatch, ok := batch.Batch.(ethdb.SyncBatch)
	if !ok {
		return errors.New("underlying test database has no synchronous batch")
	}
	if err := syncBatch.WriteSync(); err != nil {
		return err
	}
	if batch.failAfterApply.Load() {
		return errors.New("simulated ambiguous fsync result")
	}
	return nil
}

func (db *countingTxQUICDB) NewBatch() ethdb.Batch {
	return &countingTxQUICBatch{
		Batch: db.KeyValueStore.NewBatch(), syncWrites: &db.syncWrites, maxSyncBytes: &db.maxSyncBytes,
	}
}

func (batch *countingTxQUICBatch) Put(key []byte, value []byte) error {
	if err := batch.Batch.Put(key, value); err != nil {
		return err
	}
	batch.bytes += int64(len(key) + len(value))
	return nil
}

func (batch *countingTxQUICBatch) WriteSync() error {
	syncBatch, ok := batch.Batch.(ethdb.SyncBatch)
	if !ok {
		return errors.New("underlying test database has no synchronous batch")
	}
	if err := syncBatch.WriteSync(); err != nil {
		return err
	}
	batch.syncWrites.Add(1)
	for current := batch.maxSyncBytes.Load(); batch.bytes > current; current = batch.maxSyncBytes.Load() {
		if batch.maxSyncBytes.CompareAndSwap(current, batch.bytes) {
			break
		}
	}
	return nil
}

func TestTxQUICIngressGroupCommitUsesOneSynchronousBatch(t *testing.T) {
	config := testTxQUICConfig()
	config.IngressCommitInterval = 100 * time.Millisecond
	config.IngressCommitMaxRequests = 8
	db := &countingTxQUICDB{KeyValueStore: memorydb.New()}
	store := NewTxQUICIngressStore(db, config)
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer store.Stop()
	db.syncWrites.Store(0) // Exclude the one-time chain identity write.

	sender := common.HexToAddress("0x4000000000000000000000000000000000000004")
	packets := make([]*txQUICPacket, 4)
	acks := make([]txQUICAck, len(packets))
	for index := range packets {
		packets[index] = testTxQUICPacket(t, config, sender, uint64(index+1), testTxQUICTransaction(uint64(30+index), 0))
		acks[index] = testTxQUICAck(t, packets[index], []int{0}, nil, nil)
	}

	start := make(chan struct{})
	errs := make(chan error, len(packets))
	var group sync.WaitGroup
	for index := range packets {
		packet, ack := packets[index], acks[index]
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := store.StoreSyncLocked(context.Background(), packet, ack)
			errs <- err
		}()
	}
	close(start)
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("grouped ingress commit failed: %v", err)
		}
	}
	if writes := db.syncWrites.Load(); writes != 1 {
		t.Fatalf("receiver group commit used %d synchronous batches, want 1", writes)
	}
	if records, _ := store.Pending(); records != len(packets) {
		t.Fatalf("receiver group commit persisted %d manifests, want %d", records, len(packets))
	}
	for _, packet := range packets {
		resolved, err := store.ResolveTransaction(packet.Items[0].Tx.Hash())
		if err != nil || resolved == nil || resolved.Hash() != packet.Items[0].Tx.Hash() {
			t.Fatalf("group-committed transaction resolve = %v err %v", resolved, err)
		}
	}
}

func TestTxQUICIngressGroupCommitNeverOvershootsByteLimit(t *testing.T) {
	config := testTxQUICConfig()
	config.IngressCommitInterval = 100 * time.Millisecond
	config.IngressCommitMaxRequests = 8
	config.IngressCommitMaxBytes = txQUICMicroBatchMaxWireBytes
	db := &countingTxQUICDB{KeyValueStore: memorydb.New()}
	store := NewTxQUICIngressStore(db, config)
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer store.Stop()
	db.syncWrites.Store(0)

	sender := common.HexToAddress("0x4010000000000000000000000000000000000004")
	packets := []*txQUICPacket{
		testTxQUICPacket(t, config, sender, 1, testTxQUICTransaction(301, 2*1024*1024+64*1024)),
		testTxQUICPacket(t, config, sender, 2, testTxQUICTransaction(302, 2*1024*1024+64*1024)),
	}
	requestBytes := make([]int, len(packets))
	for index, packet := range packets {
		encoded, err := rlp.EncodeToBytes([]interface{}{packet.Certificate, packet.Items})
		if err != nil {
			t.Fatal(err)
		}
		requestBytes[index] = len(encoded)
		if int64(requestBytes[index]) > config.IngressCommitMaxBytes {
			t.Fatalf("test request %d exceeds single-request bound", index)
		}
	}
	if int64(requestBytes[0]+requestBytes[1]) <= config.IngressCommitMaxBytes {
		t.Fatalf("test requests do not exceed group byte bound: %v", requestBytes)
	}

	start := make(chan struct{})
	errs := make(chan error, len(packets))
	var group sync.WaitGroup
	for _, packet := range packets {
		packet := packet
		ack := testTxQUICAck(t, packet, []int{0}, nil, nil)
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := store.StoreSyncLocked(context.Background(), packet, ack)
			errs <- err
		}()
	}
	close(start)
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("byte-bounded group commit failed: %v", err)
		}
	}
	if writes := db.syncWrites.Load(); writes != 2 {
		t.Fatalf("byte-bounded group commit used %d sync writes, want 2", writes)
	}
}

func TestTxQUICIngressReplayWindowIsolationDoesNotDisableOtherGroupCommit(t *testing.T) {
	config := testTxQUICConfig()
	config.IngressCommitInterval = 500 * time.Millisecond
	config.IngressCommitMaxRequests = 64
	config.OutboxMaxRecords = 128
	db := &countingTxQUICDB{KeyValueStore: memorydb.New()}
	store := NewTxQUICIngressStore(db, config)
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer store.Stop()

	conflictSender := common.HexToAddress("0x4100000000000000000000000000000000000004")
	seed := testTxQUICPacket(t, config, conflictSender, 1, testTxQUICTransaction(100, 0))
	if _, err := store.StoreSync(context.Background(), seed, testTxQUICAck(t, seed, []int{0}, nil, nil)); err != nil {
		t.Fatal(err)
	}
	db.syncWrites.Store(0)

	type result struct {
		kind string
		err  error
	}
	results := make(chan result, 64)
	start := make(chan struct{})
	var group sync.WaitGroup
	for index := 0; index < 62; index++ {
		sender := common.BigToAddress(big.NewInt(int64(10_000 + index)))
		packet := testTxQUICPacket(t, config, sender, 1, testTxQUICTransaction(uint64(200+index), 0))
		ack := testTxQUICAck(t, packet, []int{0}, nil, nil)
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := store.StoreSyncLocked(context.Background(), packet, ack)
			results <- result{kind: "unrelated", err: err}
		}()
	}
	oldPacket := testTxQUICPacket(t, config, conflictSender, 2, testTxQUICTransaction(998, 0))
	oldAck := testTxQUICAck(t, oldPacket, []int{0}, nil, nil)
	group.Add(1)
	go func() {
		defer group.Done()
		<-start
		_, err := store.StoreSyncLocked(context.Background(), oldPacket, oldAck)
		results <- result{kind: "old", err: err}
	}()
	newestPacket := testTxQUICPacket(t, config, conflictSender, 1<<40, testTxQUICTransaction(999, 0))
	newestAck := testTxQUICAck(t, newestPacket, []int{0}, nil, nil)
	group.Add(1)
	go func() {
		defer group.Done()
		<-start
		_, err := store.StoreSyncLocked(context.Background(), newestPacket, newestAck)
		results <- result{kind: "newest", err: err}
	}()
	close(start)
	group.Wait()
	close(results)

	for result := range results {
		switch result.kind {
		case "old":
			if result.err == nil || !strings.Contains(result.err.Error(), "below replay window") {
				t.Fatalf("old isolated replay result = %v", result.err)
			}
		case "newest":
			if result.err != nil {
				t.Fatalf("newest isolated replay request failed: %v", result.err)
			}
		case "unrelated":
			if result.err != nil {
				t.Fatalf("unrelated grouped request failed: %v", result.err)
			}
		default:
			t.Fatalf("unexpected grouped result kind %q", result.kind)
		}
	}
	if writes := db.syncWrites.Load(); writes != 2 {
		t.Fatalf("replay isolation used %d synchronous writes, want one grouped write plus one newest-window write", writes)
	}
	if cached, complete, err := store.LookupPacket(newestPacket, time.Now()); err != nil || !complete || cached.BatchID != newestPacket.BatchID {
		t.Fatalf("newest replay lookup = complete %t batch %s err %v", complete, cached.BatchID, err)
	}
	if _, _, err := store.LookupPacket(oldPacket, time.Now()); err == nil || !strings.Contains(err.Error(), "below the replay window") {
		t.Fatalf("old replay lookup error = %v", err)
	}
}

func TestTxQUICIngressReplaySameBatchAndNonceSurvivesRestart(t *testing.T) {
	config := testTxQUICConfig()
	db := memorydb.New()
	sender := common.HexToAddress("0x5000000000000000000000000000000000000005")
	packet := testTxQUICPacket(t, config, sender, 1, testTxQUICTransaction(40, 0))
	ack := testTxQUICAck(t, packet, []int{0}, nil, nil)

	first := NewTxQUICIngressStore(db, config)
	if err := first.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := first.StoreSync(context.Background(), packet, ack); err != nil {
		t.Fatal(err)
	}
	replay := *packet
	replay.Timestamp = 1 // A known nonce/batch maps to its durable outcome, not a fresh envelope timestamp.
	if cached, complete, err := first.LookupPacket(&replay, time.Now()); err != nil || !complete || cached.BatchID != packet.BatchID {
		t.Fatalf("same nonce/batch replay = complete %t batch %s err %v", complete, cached.BatchID, err)
	}
	different := testTxQUICPacket(t, config, sender, packet.Nonce, testTxQUICTransaction(41, 0))
	if _, _, err := first.LookupPacket(different, time.Now()); err == nil || !strings.Contains(err.Error(), "different batch") {
		t.Fatalf("same nonce/different batch error = %v", err)
	}
	first.Stop()

	second := NewTxQUICIngressStore(db, config)
	if err := second.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer second.Stop()
	restored := 0
	if err := second.Restore(func(_ *types.CommonTxAdmissionBatch, items []*txQUICItem) error {
		restored += len(items)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if restored != 1 {
		t.Fatalf("restored durable items = %d, want 1", restored)
	}
	if resolved, err := second.ResolveTransaction(packet.Items[0].Tx.Hash()); err != nil || resolved == nil || resolved.Hash() != packet.Items[0].Tx.Hash() {
		t.Fatalf("restart transaction resolve = %v err %v", resolved, err)
	}
	if cached, complete, err := second.LookupPacket(&replay, time.Now()); err != nil || !complete || cached.BatchID != packet.BatchID {
		t.Fatalf("restart replay = complete %t batch %s err %v", complete, cached.BatchID, err)
	}
	if _, _, err := second.LookupPacket(different, time.Now()); err == nil || !strings.Contains(err.Error(), "different batch") {
		t.Fatalf("restart nonce collision error = %v", err)
	}
}

func TestTxQUICIngressReplayAcceptsHugeNonceJumpsAndCompactsOldWindow(t *testing.T) {
	config := testTxQUICConfig()
	db := memorydb.New()
	store := NewTxQUICIngressStore(db, config)
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A fresh sender may already have reserved and consumed a very high nonce
	// before this receiver first sees it. Initializing that replay window must
	// not scan from nonce one to the received value.
	hugeSender := common.HexToAddress("0x5100000000000000000000000000000000000005")
	hugeNonce := ^uint64(0) - 1024
	hugePacket := testTxQUICPacket(t, config, hugeSender, hugeNonce, testTxQUICTransaction(42, 0))
	hugeAck := testTxQUICAck(t, hugePacket, []int{0}, nil, nil)
	hugeResult := make(chan error, 1)
	go func() {
		_, err := store.StoreSync(context.Background(), hugePacket, hugeAck)
		hugeResult <- err
	}()
	select {
	case err := <-hugeResult:
		if err != nil {
			store.Stop()
			t.Fatalf("fresh huge nonce was rejected: %v", err)
		}
	case <-time.After(2 * time.Second):
		// Do not wait on Stop here: an accidental nonce-linear loop is exactly
		// what this timeout is intended to expose.
		t.Fatal("fresh huge nonce initialization did not complete in constant work")
	}
	defer store.Stop()
	state, err := store.readReplayState(hugeSender, hugePacket.SenderEpoch)
	if err != nil {
		t.Fatal(err)
	}
	wantFloor := hugeNonce - config.ReplayWindow + 1
	if state == nil || state.Highest != hugeNonce || state.Floor != wantFloor {
		t.Fatalf("huge nonce replay state = %#v, want highest %d floor %d", state, hugeNonce, wantFloor)
	}
	if !txQUICBitmapHas(state.Seen, int(hugeNonce%config.ReplayWindow)) {
		t.Fatal("fresh huge nonce is missing from the replay bitmap")
	}

	// A later authenticated jump may be arbitrarily large too. It advances the
	// bounded replay window and removes every obsolete nonce-to-batch mapping.
	jumpSender := common.HexToAddress("0x5200000000000000000000000000000000000005")
	firstNonce := uint64(10)
	first := testTxQUICPacket(t, config, jumpSender, firstNonce, testTxQUICTransaction(43, 0))
	if _, err := store.StoreSync(context.Background(), first, testTxQUICAck(t, first, []int{0}, nil, nil)); err != nil {
		t.Fatal(err)
	}
	oldMapping := txQUICIngressNonceKey(first.Sender, first.SenderEpoch, first.Nonce)
	if has, err := db.Has(oldMapping); err != nil || !has {
		t.Fatalf("initial nonce mapping = has %t err %v", has, err)
	}
	jumpNonce := uint64(1 << 40)
	jump := testTxQUICPacket(t, config, jumpSender, jumpNonce, testTxQUICTransaction(44, 0))
	if _, err := store.StoreSync(context.Background(), jump, testTxQUICAck(t, jump, []int{0}, nil, nil)); err != nil {
		t.Fatalf("authenticated huge nonce jump was rejected: %v", err)
	}
	state, err = store.readReplayState(jumpSender, jump.SenderEpoch)
	if err != nil {
		t.Fatal(err)
	}
	wantFloor = jumpNonce - config.ReplayWindow + 1
	if state == nil || state.Highest != jumpNonce || state.Floor != wantFloor {
		t.Fatalf("jump replay state = %#v, want highest %d floor %d", state, jumpNonce, wantFloor)
	}
	seen := 0
	for bit := 0; bit < int(config.ReplayWindow); bit++ {
		if !txQUICBitmapHas(state.Seen, bit) {
			continue
		}
		seen++
		if bit != int(jumpNonce%config.ReplayWindow) {
			t.Fatalf("obsolete replay bitmap bit %d survived huge jump", bit)
		}
	}
	if seen != 1 {
		t.Fatalf("huge jump replay bitmap has %d set bits, want one", seen)
	}
	if has, err := db.Has(oldMapping); err != nil || has {
		t.Fatalf("obsolete nonce mapping survived huge jump: has %t err %v", has, err)
	}
	if mapped, err := db.Get(txQUICIngressNonceKey(jump.Sender, jump.SenderEpoch, jump.Nonce)); err != nil || common.BytesToHash(mapped) != jump.BatchID {
		t.Fatalf("huge jump nonce mapping = %x err %v, want batch %s", mapped, err, jump.BatchID)
	}
	if _, _, err := store.LookupPacket(first, time.Now()); err == nil || !strings.Contains(err.Error(), "below the replay window") {
		t.Fatalf("obsolete packet lookup error = %v", err)
	}
}

func TestTxQUICIngressAmbiguousSyncPoisonsUntilValidatedRestart(t *testing.T) {
	config := testTxQUICConfig()
	base := memorydb.New()
	db := &ambiguousSyncTxQUICDB{KeyValueStore: base}
	store := NewTxQUICIngressStore(db, config)
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	db.failAfterApply.Store(true)
	sender := common.HexToAddress("0x5300000000000000000000000000000000000005")
	packet := testTxQUICPacket(t, config, sender, 1, testTxQUICTransaction(45, 0))
	ack := testTxQUICAck(t, packet, []int{0}, nil, nil)
	if _, err := store.StoreSync(context.Background(), packet, ack); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous ingress fsync error = %v", err)
	}
	if _, _, err := store.LookupPacket(packet, time.Now()); err == nil || !strings.Contains(err.Error(), "poisoned") {
		t.Fatalf("poisoned ingress lookup error = %v", err)
	}
	store.Stop()

	restarted := NewTxQUICIngressStore(base, config)
	if err := restarted.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer restarted.Stop()
	restored := 0
	if err := restarted.Restore(func(_ *types.CommonTxAdmissionBatch, items []*txQUICItem) error { restored += len(items); return nil }); err != nil {
		t.Fatalf("restart could not validate applied WAL: %v", err)
	}
	if restored != 1 {
		t.Fatalf("restart restored %d items, want one", restored)
	}
}

func TestTxQUICIngressRestoreFailsClosedAtPersistedCapacityBoundary(t *testing.T) {
	config := testTxQUICConfig()
	db := memorydb.New()
	first := NewTxQUICIngressStore(db, config)
	if err := first.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		sender := common.BigToAddress(big.NewInt(int64(0x5100 + index)))
		packet := testTxQUICPacket(t, config, sender, 1, testTxQUICTransaction(uint64(4100+index), 256))
		if _, err := first.StoreSync(context.Background(), packet, testTxQUICAck(t, packet, []int{0}, nil, nil)); err != nil {
			t.Fatal(err)
		}
	}
	records, storedBytes := first.Pending()
	first.Stop()
	if records != 2 || storedBytes <= 1 {
		t.Fatalf("test ingress WAL accounting = %d records/%d bytes", records, storedBytes)
	}

	restore := func(maxRecords int, maxBytes int64) (int, error) {
		bounded := config
		bounded.OutboxMaxRecords = maxRecords
		bounded.OutboxMaxBytes = maxBytes
		store := NewTxQUICIngressStore(db, bounded)
		if err := store.Start(context.Background()); err != nil {
			return 0, err
		}
		callbacks := 0
		err := store.Restore(func(*types.CommonTxAdmissionBatch, []*txQUICItem) error {
			callbacks++
			return nil
		})
		store.Stop()
		return callbacks, err
	}

	callbacks, err := restore(records, storedBytes)
	if err != nil || callbacks != 2 {
		t.Fatalf("exact ingress WAL capacity restore = callbacks %d err %v", callbacks, err)
	}
	callbacks, err = restore(records, storedBytes-1)
	if err == nil || !strings.Contains(err.Error(), "capacity") || callbacks != 0 {
		t.Fatalf("one-byte ingress WAL overflow = callbacks %d err %v", callbacks, err)
	}
	callbacks, err = restore(records-1, storedBytes)
	if err == nil || !strings.Contains(err.Error(), "capacity") || callbacks != 0 {
		t.Fatalf("one-record ingress WAL overflow = callbacks %d err %v", callbacks, err)
	}
}

func TestTxQUICIngressRestoreRejectsOrphanAndReplayCorruptionBeforeCallbacks(t *testing.T) {
	config := testTxQUICConfig()
	t.Run("orphan item", func(t *testing.T) {
		db := memorydb.New()
		first := NewTxQUICIngressStore(db, config)
		if err := first.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		first.Stop()
		orphanKey := txQUICIngressItemKey(common.HexToHash("0x1234"), 0)
		if err := db.Put(orphanKey, []byte{0xc0}); err != nil {
			t.Fatal(err)
		}
		second := NewTxQUICIngressStore(db, config)
		if err := second.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer second.Stop()
		callbacks := 0
		if err := second.Restore(func(*types.CommonTxAdmissionBatch, []*txQUICItem) error { callbacks++; return nil }); err == nil || !strings.Contains(err.Error(), "orphan") {
			t.Fatalf("orphan item restore error = %v", err)
		}
		if callbacks != 0 {
			t.Fatalf("corrupt WAL invoked %d restore callbacks", callbacks)
		}
	})

	t.Run("missing nonce mapping", func(t *testing.T) {
		db := memorydb.New()
		sender := common.HexToAddress("0x5400000000000000000000000000000000000005")
		packet := testTxQUICPacket(t, config, sender, 1, testTxQUICTransaction(46, 0))
		first := NewTxQUICIngressStore(db, config)
		if err := first.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := first.StoreSync(context.Background(), packet, testTxQUICAck(t, packet, []int{0}, nil, nil)); err != nil {
			t.Fatal(err)
		}
		first.Stop()
		if err := db.Delete(txQUICIngressNonceKey(sender, packet.SenderEpoch, packet.Nonce)); err != nil {
			t.Fatal(err)
		}
		second := NewTxQUICIngressStore(db, config)
		if err := second.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer second.Stop()
		callbacks := 0
		if err := second.Restore(func(*types.CommonTxAdmissionBatch, []*txQUICItem) error { callbacks++; return nil }); err == nil || !strings.Contains(err.Error(), "missing txquic replay nonce") {
			t.Fatalf("missing replay mapping restore error = %v", err)
		}
		if callbacks != 0 {
			t.Fatalf("corrupt replay WAL invoked %d restore callbacks", callbacks)
		}
	})

	t.Run("dangling transaction index", func(t *testing.T) {
		db := memorydb.New()
		first := NewTxQUICIngressStore(db, config)
		if err := first.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		first.Stop()
		hash := common.HexToHash("0x9876")
		if err := db.Put(txQUICIngressTxKey(hash), txQUICIngressTxLocation(common.HexToHash("0x1234"), 0)); err != nil {
			t.Fatal(err)
		}
		second := NewTxQUICIngressStore(db, config)
		if err := second.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer second.Stop()
		callbacks := 0
		if err := second.Restore(func(*types.CommonTxAdmissionBatch, []*txQUICItem) error { callbacks++; return nil }); err == nil || !strings.Contains(err.Error(), "dangling") {
			t.Fatalf("dangling transaction index restore error = %v", err)
		}
		if callbacks != 0 {
			t.Fatalf("dangling transaction index invoked %d callbacks", callbacks)
		}
	})
}

func TestTxQUICIngressCompactFinalizedRemovesItemsIndividually(t *testing.T) {
	config := testTxQUICConfig()
	store := NewTxQUICIngressStore(memorydb.New(), config)
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer store.Stop()

	sender := common.HexToAddress("0x6000000000000000000000000000000000000006")
	txs := []*types.Transaction{
		testTxQUICTransaction(50, 0),
		testTxQUICTransaction(51, 0),
		testTxQUICTransaction(52, 0),
	}
	packet := testTxQUICPacket(t, config, sender, 1, txs...)
	ack := testTxQUICAck(t, packet, []int{0, 1, 2}, nil, nil)
	if _, err := store.StoreSync(context.Background(), packet, ack); err != nil {
		t.Fatal(err)
	}

	finalized := map[common.Hash]bool{txs[0].Hash(): true}
	if removed, err := store.CompactFinalized(packet.BatchID, func(hash common.Hash) bool { return finalized[hash] }, time.Now()); err != nil || removed != 1 {
		t.Fatalf("first item compaction removed %d, err=%v", removed, err)
	}
	pending, err := store.PendingItems(packet.BatchID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 || pending[0].Tx.Hash() != txs[1].Hash() || pending[1].Tx.Hash() != txs[2].Hash() {
		t.Fatalf("pending items after first compaction = %#v", pending)
	}
	if pending[0].AdmissionIndex != 1 || pending[1].AdmissionIndex != 2 {
		t.Fatalf("per-item GC changed original admission indexes: %d %d", pending[0].AdmissionIndex, pending[1].AdmissionIndex)
	}
	manifest, _, err := store.readManifest(packet.BatchID)
	if err != nil || manifest == nil || manifest.Certificate == nil || manifest.Certificate.AdmissionID != packet.Certificate.AdmissionID {
		t.Fatalf("per-item GC did not retain the shared certificate: manifest=%#v err=%v", manifest, err)
	}
	if resolved, err := store.ResolveTransaction(txs[0].Hash()); err != nil || resolved != nil {
		t.Fatalf("compacted transaction still resolves: %v err %v", resolved, err)
	}
	if resolved, err := store.ResolveTransaction(txs[1].Hash()); err != nil || resolved == nil || resolved.Hash() != txs[1].Hash() {
		t.Fatalf("pending transaction no longer resolves: %v err %v", resolved, err)
	}

	finalized[txs[2].Hash()] = true
	if removed, err := store.CompactFinalized(packet.BatchID, func(hash common.Hash) bool { return finalized[hash] }, time.Now()); err != nil || removed != 1 {
		t.Fatalf("second item compaction removed %d, err=%v", removed, err)
	}
	pending, err = store.PendingItems(packet.BatchID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Tx.Hash() != txs[1].Hash() {
		t.Fatalf("per-item compaction retained %#v, want only %s", pending, txs[1].Hash())
	}
}

func TestTxQUICIngressDuplicateTransactionIndexSurvivesOlderBatchCompaction(t *testing.T) {
	config := testTxQUICConfig()
	store := NewTxQUICIngressStore(memorydb.New(), config)
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer store.Stop()
	sender := common.HexToAddress("0x6010000000000000000000000000000000000006")
	shared := testTxQUICTransaction(500, 0)
	oldPacket := testTxQUICPacket(t, config, sender, 1, shared)
	newPacket := testTxQUICPacket(t, config, sender, 2, shared, testTxQUICTransaction(501, 0))
	if _, err := store.StoreSync(context.Background(), oldPacket, testTxQUICAck(t, oldPacket, []int{0}, nil, nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StoreSync(context.Background(), newPacket, testTxQUICAck(t, newPacket, []int{0, 1}, nil, nil)); err != nil {
		t.Fatal(err)
	}
	if removed, err := store.CompactFinalized(oldPacket.BatchID, func(hash common.Hash) bool { return hash == shared.Hash() }, time.Now()); err != nil || removed != 1 {
		t.Fatalf("old duplicate compaction removed %d err %v", removed, err)
	}
	location, err := store.db.Get(txQUICIngressTxKey(shared.Hash()))
	if err != nil || !bytes.Equal(location, txQUICIngressTxLocation(newPacket.BatchID, 0)) {
		t.Fatalf("new duplicate index was lost: %x err %v", location, err)
	}
	if resolved, err := store.ResolveTransaction(shared.Hash()); err != nil || resolved == nil || resolved.Hash() != shared.Hash() {
		t.Fatalf("new duplicate did not resolve: %v err %v", resolved, err)
	}
	if removed, err := store.CompactFinalized(newPacket.BatchID, func(hash common.Hash) bool { return hash == shared.Hash() }, time.Now()); err != nil || removed != 1 {
		t.Fatalf("current duplicate compaction removed %d err %v", removed, err)
	}
	if resolved, err := store.ResolveTransaction(shared.Hash()); err != nil || resolved != nil {
		t.Fatalf("current duplicate index survived compaction: %v err %v", resolved, err)
	}
}

func TestTxQUICIngressMaintenanceCompactsFinalizedAndNonceConsumedOldHash(t *testing.T) {
	config := testTxQUICConfig()
	chainID := new(big.Int).SetUint64(config.ChainID)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	txSender := crypto.PubkeyToAddress(key.PublicKey)
	stateDB, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	stateDB.SetBalance(txSender, new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether)))
	const stateNonce = uint64(61)
	stateDB.SetNonce(txSender, stateNonce)

	chainConfig := *params.TestChainConfig
	chainConfig.ChainID = new(big.Int).Set(chainID)
	head := types.NewBlockWithHeader(&types.Header{
		Number:   big.NewInt(0),
		GasLimit: 30_000_000,
		BaseFee:  big.NewInt(1),
		Time:     uint64(time.Now().Unix()),
	})
	poolConfig := core.DefaultTxPoolConfig
	poolConfig.NoLocals = true
	poolConfig.Journal = ""
	pool := core.NewTxPool(poolConfig, &chainConfig, &testTxQUICPoolChain{block: head, state: stateDB})
	t.Cleanup(pool.Stop)
	signedTx := func(nonce uint64) *types.Transaction {
		t.Helper()
		unsigned := types.NewTransaction(
			nonce,
			common.HexToAddress("0x1000000000000000000000000000000000000001"),
			big.NewInt(1),
			21_000,
			big.NewInt(params.GWei),
			nil,
		)
		tx, err := types.SignTx(unsigned, types.NewEIP155Signer(chainID), key)
		if err != nil {
			t.Fatal(err)
		}
		return tx
	}

	store := NewTxQUICIngressStore(memorydb.New(), config)
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	sender := common.HexToAddress("0x6050000000000000000000000000000000000006")
	exactFinalized := signedTx(70)
	replacedOrCancelled := signedTx(60)
	stillExecutable := signedTx(61)
	packet := testTxQUICPacket(t, config, sender, 1, exactFinalized, replacedOrCancelled, stillExecutable)
	if _, err := store.StoreSync(context.Background(), packet, testTxQUICAck(t, packet, []int{0, 1, 2}, nil, nil)); err != nil {
		t.Fatal(err)
	}

	finalizedHashes := map[common.Hash]bool{exactFinalized.Hash(): true}
	ingress := NewTxQUICIngress(config, pool)
	ingress.SetDurableIngress(store)
	ingress.SetFinalizedTxLookup(func(hash common.Hash) bool { return finalizedHashes[hash] })
	lookupCalls, sawOldHash := 0, false
	ingress.SetObsoleteTxLookup(func(candidates types.Transactions) []bool {
		lookupCalls++
		resolved := make([]bool, len(candidates))
		for index, tx := range candidates {
			if tx != nil && tx.Hash() == replacedOrCancelled.Hash() {
				sawOldHash = true
			}
			resolved[index] = tx != nil && stateNonce > tx.Nonce()
		}
		return resolved
	})
	t.Cleanup(ingress.Stop)

	removed, err := ingress.maintainDurableIngressPage()
	if err != nil || removed != 2 {
		t.Fatalf("exact plus obsolete maintenance compaction removed %d, err=%v", removed, err)
	}
	if lookupCalls != 1 || !sawOldHash {
		t.Fatalf("obsolete batch lookup calls=%d saw old hash=%t", lookupCalls, sawOldHash)
	}
	if finalizedHashes[replacedOrCancelled.Hash()] {
		t.Fatal("test setup incorrectly marked the replaced/cancelled old hash as finalized")
	}
	pending, err := store.PendingItems(packet.BatchID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Tx.Hash() != stillExecutable.Hash() {
		t.Fatalf("pending items after obsolete nonce compaction = %#v, want only %s", pending, stillExecutable.Hash())
	}
	if pool.Has(exactFinalized.Hash()) || pool.Has(replacedOrCancelled.Hash()) || !pool.Has(stillExecutable.Hash()) {
		t.Fatalf("maintenance restored wrong WAL items: exact=%t obsolete=%t executable=%t", pool.Has(exactFinalized.Hash()), pool.Has(replacedOrCancelled.Hash()), pool.Has(stillExecutable.Hash()))
	}
}

func TestTxQUICIngressRetryTombstonesExpireAfterDurableItemsFinalize(t *testing.T) {
	config := testTxQUICConfig()
	store := NewTxQUICIngressStore(memorydb.New(), config)
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer store.Stop()
	sender := common.HexToAddress("0x6100000000000000000000000000000000000006")
	tx0, tx1 := testTxQUICTransaction(53, 0), testTxQUICTransaction(54, 0)
	packet := testTxQUICPacket(t, config, sender, 1, tx0, tx1)
	if _, err := store.StoreSync(context.Background(), packet, testTxQUICAck(t, packet, []int{0}, []int{1}, nil)); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if removed, err := store.CompactFinalized(packet.BatchID, func(hash common.Hash) bool { return hash == tx0.Hash() }, now); err != nil || removed != 1 {
		t.Fatalf("partial tombstone finalization removed %d, err=%v", removed, err)
	}
	if _, err := store.CompactFinalized(packet.BatchID, nil, now.Add(2*config.IngressAckRetention)); err != nil {
		t.Fatal(err)
	}
	if has, err := store.db.Has(txQUICIngressManifestKey(packet.BatchID)); err != nil || has {
		t.Fatalf("partial ACK tombstone remains after retention: has=%t err=%v", has, err)
	}

	retryOnly := testTxQUICPacket(t, config, sender, 2, testTxQUICTransaction(55, 0))
	if _, err := store.StoreSync(context.Background(), retryOnly, testTxQUICAck(t, retryOnly, nil, []int{0}, nil)); err != nil {
		t.Fatal(err)
	}
	manifest, _, err := store.readManifest(retryOnly.BatchID)
	if err != nil || manifest == nil || manifest.CompletedAt == 0 {
		t.Fatalf("retry-only tombstone completion = %#v err=%v", manifest, err)
	}
	expires := time.Unix(0, int64(manifest.CompletedAt)).Add(2 * config.IngressAckRetention)
	if _, err := store.CompactFinalized(retryOnly.BatchID, nil, expires); err != nil {
		t.Fatal(err)
	}
	if has, err := store.db.Has(txQUICIngressManifestKey(retryOnly.BatchID)); err != nil || has {
		t.Fatalf("retry-only tombstone remains after retention: has=%t err=%v", has, err)
	}
}

func testTxQUICBatchPayload(t *testing.T, config TxQUICConfig, txs ...*types.Transaction) []byte {
	t.Helper()
	payload, err := rlp.EncodeToBytes(testTxQUICBatch(t, config, txs...))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func testTxOutboxCommitRequest(t *testing.T, batchID common.Hash, payload []byte) *txOutboxCommitRequest {
	t.Helper()
	record := &TxOutboxRecord{
		BatchID: batchID, Payload: append([]byte(nil), payload...), CreatedAt: uint64(time.Now().UnixNano()),
	}
	encoded, err := rlp.EncodeToBytes(record)
	if err != nil {
		t.Fatal(err)
	}
	return &txOutboxCommitRequest{
		batchID: batchID,
		payload: record.Payload,
		encoded: encoded,
		bytes:   int64(len(txOutboxRecordKey(batchID)) + len(encoded)),
		result:  make(chan txOutboxCommitResult, 1),
	}
}

func TestTxOutboxGroupCommitUsesOneSynchronousBatch(t *testing.T) {
	config := testTxQUICConfig()
	db := &countingTxQUICDB{KeyValueStore: memorydb.New()}
	outbox := NewTxOutbox(db, config)
	outbox.commitInterval = 100 * time.Millisecond
	outbox.commitMaxRequests = 8
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	defer outbox.Stop()
	db.syncWrites.Store(0)
	db.maxSyncBytes.Store(0)

	payloads := make([][]byte, 8)
	for index := range payloads {
		payloads[index] = testTxQUICBatchPayload(t, config, testTxQUICTransaction(uint64(6100+index), 0))
	}
	start := make(chan struct{})
	errs := make(chan error, len(payloads))
	var group sync.WaitGroup
	for _, payload := range payloads {
		payload := payload
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := outbox.StoreSync(context.Background(), payload)
			errs <- err
		}()
	}
	close(start)
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("grouped outbox commit failed: %v", err)
		}
	}
	if writes := db.syncWrites.Load(); writes != 1 {
		t.Fatalf("sender group commit used %d synchronous batches, want 1", writes)
	}
	if records, _ := outbox.Pending(); records != len(payloads) {
		t.Fatalf("sender group commit persisted %d records, want %d", records, len(payloads))
	}
}

func TestTxOutboxGroupCommitNeverOvershootsByteLimit(t *testing.T) {
	config := testTxQUICConfig()
	payloads := [][]byte{
		testTxQUICBatchPayload(t, config, testTxQUICTransaction(6200, 512*1024)),
		testTxQUICBatchPayload(t, config, testTxQUICTransaction(6201, 512*1024)),
	}
	requests := []*txOutboxCommitRequest{
		testTxOutboxCommitRequest(t, txOutboxBatchID(payloads[0]), payloads[0]),
		testTxOutboxCommitRequest(t, txOutboxBatchID(payloads[1]), payloads[1]),
	}
	limit := requests[0].bytes
	if requests[1].bytes > limit {
		limit = requests[1].bytes
	}
	if requests[0].bytes+requests[1].bytes <= limit {
		t.Fatalf("test requests do not exceed the group byte bound")
	}

	db := &countingTxQUICDB{KeyValueStore: memorydb.New()}
	outbox := NewTxOutbox(db, config)
	outbox.commitInterval = 100 * time.Millisecond
	outbox.commitMaxRequests = 2
	outbox.commitMaxBytes = limit
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	defer outbox.Stop()
	db.syncWrites.Store(0)
	db.maxSyncBytes.Store(0)

	start := make(chan struct{})
	errs := make(chan error, len(payloads))
	var group sync.WaitGroup
	for _, payload := range payloads {
		payload := payload
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := outbox.StoreSync(context.Background(), payload)
			errs <- err
		}()
	}
	close(start)
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("byte-bounded outbox commit failed: %v", err)
		}
	}
	if writes := db.syncWrites.Load(); writes != 2 {
		t.Fatalf("byte-bounded outbox commit used %d synchronous batches, want 2", writes)
	}
	if written := db.maxSyncBytes.Load(); written > limit {
		t.Fatalf("outbox group commit wrote %d bytes, limit %d", written, limit)
	}
}

func TestTxOutboxGroupCommitDeduplicatesAndAlignsCollisionErrors(t *testing.T) {
	config := testTxQUICConfig()
	db := &countingTxQUICDB{KeyValueStore: memorydb.New()}
	outbox := NewTxOutbox(db, config)
	outbox.commitInterval = 100 * time.Millisecond
	outbox.commitMaxRequests = 4
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	defer outbox.Stop()
	db.syncWrites.Store(0)

	payloadA := testTxQUICBatchPayload(t, config, testTxQUICTransaction(6300, 0))
	payloadB := testTxQUICBatchPayload(t, config, testTxQUICTransaction(6301, 0))
	payloadC := testTxQUICBatchPayload(t, config, testTxQUICTransaction(6302, 0))
	idA := txOutboxBatchID(payloadA)
	idC := txOutboxBatchID(payloadC)
	requests := []*txOutboxCommitRequest{
		testTxOutboxCommitRequest(t, idA, payloadA),
		testTxOutboxCommitRequest(t, idA, payloadA),
		// A valid public StoreSync cannot forge this hash collision. Inject it at
		// the commit boundary to prove one conflicting waiter cannot be matched
		// to another request's success result.
		testTxOutboxCommitRequest(t, idA, payloadB),
		testTxOutboxCommitRequest(t, idC, payloadC),
	}
	for _, request := range requests {
		outbox.commitCh <- request
	}
	results := make([]txOutboxCommitResult, len(requests))
	for index, request := range requests {
		select {
		case results[index] = <-request.result:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for grouped outbox result")
		}
	}
	if results[0].err != nil || results[1].err != nil || results[3].err != nil {
		t.Fatalf("aligned grouped successes = [%v %v %v]", results[0].err, results[1].err, results[3].err)
	}
	if results[2].err == nil || !strings.Contains(results[2].err.Error(), "identity collision") {
		t.Fatalf("aligned collision result = %v", results[2].err)
	}
	if writes := db.syncWrites.Load(); writes != 1 {
		t.Fatalf("deduplicated outbox group used %d synchronous batches, want 1", writes)
	}
	if records, _ := outbox.Pending(); records != 2 {
		t.Fatalf("deduplicated outbox group persisted %d records, want 2", records)
	}
}

func TestTxOutboxGroupCommitContinuesAfterCallerCancellation(t *testing.T) {
	config := testTxQUICConfig()
	base := memorydb.New()
	db := &blockingSyncTxQUICDB{
		KeyValueStore: base, started: make(chan struct{}), release: make(chan struct{}),
	}
	outbox := NewTxOutbox(db, config)
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	db.block.Store(true)

	payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(6400, 0))
	batchID := txOutboxBatchID(payload)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := outbox.StoreSync(ctx, payload)
		result <- err
	}()
	select {
	case <-db.started:
	case <-time.After(time.Second):
		t.Fatal("outbox group fsync did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled StoreSync error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled StoreSync did not return")
	}
	stopped := make(chan struct{})
	go func() {
		outbox.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		close(db.release)
		t.Fatal("Stop returned before the node-owned projection fsync completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(db.release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop did not finish after the node-owned projection fsync completed")
	}
	deadline := time.Now().Add(time.Second)
	for {
		has, err := base.Has(txOutboxRecordKey(batchID))
		if err != nil {
			t.Fatal(err)
		}
		if has {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("caller cancellation discarded the already-enqueued durable commit")
		}
		time.Sleep(time.Millisecond)
	}
	stripeReleased := make(chan struct{})
	go func() {
		unlock := outbox.lockLifecycle(batchID)
		unlock()
		close(stripeReleased)
	}()
	select {
	case <-stripeReleased:
	case <-time.After(time.Second):
		t.Fatal("Stop returned with a canceled caller's lifecycle stripe still held")
	}
}

func TestTxOutboxGroupCommitStopFailsQueuedWaiters(t *testing.T) {
	config := testTxQUICConfig()
	db := &countingTxQUICDB{KeyValueStore: memorydb.New()}
	outbox := NewTxOutbox(db, config)
	outbox.commitInterval = time.Hour
	outbox.commitMaxRequests = 8
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	db.syncWrites.Store(0)

	payloadA := testTxQUICBatchPayload(t, config, testTxQUICTransaction(6500, 0))
	payloadB := testTxQUICBatchPayload(t, config, testTxQUICTransaction(6501, 0))
	requests := []*txOutboxCommitRequest{
		testTxOutboxCommitRequest(t, txOutboxBatchID(payloadA), payloadA),
		testTxOutboxCommitRequest(t, txOutboxBatchID(payloadB), payloadB),
	}
	outbox.mu.Lock()
	for _, request := range requests {
		capacityBytes, err := txOutboxRecordCapacityBytes(request.payload)
		if err != nil {
			outbox.mu.Unlock()
			t.Fatal(err)
		}
		request.reservedBytes = capacityBytes
		outbox.reservations[request.batchID] = capacityBytes
		outbox.reservedRecords++
		outbox.reservedBytes += capacityBytes
	}
	outbox.mu.Unlock()
	outbox.commitCh <- requests[0]
	deadline := time.Now().Add(time.Second)
	for len(outbox.commitCh) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("commit loop did not collect the first request")
		}
		time.Sleep(time.Millisecond)
	}
	outbox.commitCh <- requests[1]
	stopped := make(chan struct{})
	go func() {
		outbox.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("outbox Stop deadlocked with queued commit waiters")
	}
	for _, request := range requests {
		select {
		case result := <-request.result:
			if result.err == nil {
				t.Fatal("stopped outbox reported a queued commit as durable")
			}
		case <-time.After(time.Second):
			t.Fatal("stopped outbox did not fail a queued commit waiter")
		}
	}
	if writes := db.syncWrites.Load(); writes != 0 {
		t.Fatalf("stopped outbox performed %d unexpected sync writes", writes)
	}
	outbox.mu.Lock()
	reservedRecords, reservedBytes, reservations := outbox.reservedRecords, outbox.reservedBytes, len(outbox.reservations)
	outbox.mu.Unlock()
	if reservedRecords != 0 || reservedBytes != 0 || reservations != 0 {
		t.Fatalf("stopped queued commits leaked reservations = %d/%d/%d", reservedRecords, reservedBytes, reservations)
	}
}

func TestTxOutboxParentCancellationCannotEnqueueAfterCommitDrain(t *testing.T) {
	config := testTxQUICConfig()
	config.OutboxMaxRecords = 64
	config.OutboxMaxBytes = 64 << 20
	parent, cancelParent := context.WithCancel(context.Background())
	outbox := NewTxOutbox(memorydb.New(), config)
	// This path models local outcomes which already own their bytes in the
	// unified WAL. The callback is the deterministic boundary immediately before
	// projection-commit admission.
	outbox.wal = &txIngressWAL{}
	if err := outbox.Start(parent, func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}

	const stores = 64
	payloads := make([][]byte, 0, stores)
	stripes := make(map[int]struct{}, stores)
	for nonce := uint64(7100); len(payloads) < stores; nonce++ {
		payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(nonce, 0))
		stripe := txOutboxLifecycleStripe(txOutboxBatchID(payload))
		if _, duplicate := stripes[stripe]; duplicate {
			continue
		}
		stripes[stripe] = struct{}{}
		payloads = append(payloads, payload)
	}

	callbackEntered := make(chan struct{}, stores)
	releaseCallbacks := make(chan struct{})
	results := make(chan error, stores)
	for _, payload := range payloads {
		payload := payload
		go func() {
			_, err := outbox.storeLocalOutcomeVerifiedSync(context.Background(), payload, func(context.Context) error {
				callbackEntered <- struct{}{}
				<-releaseCallbacks
				return nil
			})
			results <- err
		}()
	}
	for range payloads {
		select {
		case <-callbackEntered:
		case <-time.After(2 * time.Second):
			cancelParent()
			close(releaseCallbacks)
			outbox.Stop()
			t.Fatal("stores did not reach the pre-enqueue shutdown boundary")
		}
	}
	cancelParent()
	// All node-owned consumers have completed their final drain while producers
	// remain paused just before enqueue.
	outbox.wg.Wait()
	close(releaseCallbacks)
	for range payloads {
		select {
		case err := <-results:
			if err == nil {
				t.Fatal("store succeeded after parent cancellation")
			}
		case <-time.After(2 * time.Second):
			outbox.Stop()
			t.Fatal("store did not terminate after parent cancellation")
		}
	}

	outbox.mu.Lock()
	queued := len(outbox.commitCh)
	reservedRecords, reservedBytes := outbox.reservedRecords, outbox.reservedBytes
	outbox.mu.Unlock()
	// Clean up a buggy implementation before reporting the assertion so leaked
	// lifecycle waiters do not contaminate later tests.
	for {
		select {
		case request := <-outbox.commitCh:
			if request != nil {
				_ = outbox.releaseRecordReservation(request.batchID, request.reservedBytes)
				request.result <- txOutboxCommitResult{err: errors.New("test cleanup after late enqueue")}
			}
		default:
			outbox.Stop()
			if queued != 0 || reservedRecords != 0 || reservedBytes != 0 {
				t.Fatalf("post-drain enqueue leaked queue/reservations = %d/%d/%d", queued, reservedRecords, reservedBytes)
			}
			return
		}
	}
}

func TestTxOutboxConcurrentStopsWaitForSameCompletion(t *testing.T) {
	config := testTxQUICConfig()
	deliveryStarted := make(chan struct{})
	deliveryCanceled := make(chan struct{})
	releaseDelivery := make(chan struct{})
	var startedOnce, canceledOnce sync.Once
	outbox := NewTxOutbox(memorydb.New(), config)
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		startedOnce.Do(func() { close(deliveryStarted) })
		<-ctx.Done()
		canceledOnce.Do(func() { close(deliveryCanceled) })
		<-releaseDelivery
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.StoreSync(context.Background(), testTxQUICBatchPayload(t, config, testTxQUICTransaction(7199, 0))); err != nil {
		t.Fatal(err)
	}
	select {
	case <-deliveryStarted:
	case <-time.After(time.Second):
		t.Fatal("outbox delivery did not start")
	}
	firstStopped := make(chan struct{})
	go func() {
		outbox.Stop()
		close(firstStopped)
	}()
	select {
	case <-deliveryCanceled:
	case <-time.After(time.Second):
		t.Fatal("first Stop did not cancel delivery")
	}
	secondStopped := make(chan struct{})
	go func() {
		outbox.Stop()
		close(secondStopped)
	}()
	select {
	case <-secondStopped:
		close(releaseDelivery)
		<-firstStopped
		t.Fatal("concurrent Stop returned before the shared shutdown completed")
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseDelivery)
	for index, stopped := range []<-chan struct{}{firstStopped, secondStopped} {
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Fatalf("Stop caller %d did not observe shared completion", index)
		}
	}
}

func TestTxOutboxCapacityWaitDoesNotHoldLifecycleStripe(t *testing.T) {
	config := testTxQUICConfig()
	payloadA := testTxQUICBatchPayload(t, config, testTxQUICTransaction(7200, 0))
	payloadB := testTxQUICBatchPayload(t, config, testTxQUICTransaction(7201, 0))
	idB := txOutboxBatchID(payloadB)
	idA := idB
	idA[len(idA)-1] ^= 0x01 // distinct identity on the exact same lifecycle stripe
	recordA := TxOutboxRecord{BatchID: idA, Payload: payloadA, CreatedAt: uint64(time.Now().UnixNano())}
	encodedA, err := rlp.EncodeToBytes(&recordA)
	if err != nil {
		t.Fatal(err)
	}
	capacityA, err := txOutboxRecordCapacityBytes(payloadA)
	if err != nil {
		t.Fatal(err)
	}
	capacityB, err := txOutboxRecordCapacityBytes(payloadB)
	if err != nil {
		t.Fatal(err)
	}
	config.OutboxMaxRecords = 1
	config.OutboxMaxBytes = capacityA
	if capacityB > config.OutboxMaxBytes {
		config.OutboxMaxBytes = capacityB
	}
	base := memorydb.New()
	db := &blockingHasTxQUICDB{
		KeyValueStore: base, target: txOutboxRecordKey(idB), entered: make(chan struct{}), release: make(chan struct{}),
	}
	outbox := NewTxOutbox(db, config)
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := base.Put(txOutboxRecordKey(idA), encodedA); err != nil {
		outbox.Stop()
		t.Fatal(err)
	}
	outbox.mu.Lock()
	outbox.records = 1
	outbox.bytes = capacityA
	outbox.mu.Unlock()

	stored := make(chan error, 1)
	go func() {
		_, err := outbox.StoreSync(context.Background(), payloadB)
		stored <- err
	}()
	select {
	case <-db.entered:
	case <-time.After(time.Second):
		outbox.Stop()
		t.Fatal("capacity waiter did not reach its authoritative record lookup")
	}
	deleted := make(chan error, 1)
	go func() { deleted <- outbox.deleteRecord(&recordA) }()
	close(db.release)
	select {
	case err := <-deleted:
		if err != nil {
			outbox.Stop()
			t.Fatalf("same-stripe delete failed to free capacity: %v", err)
		}
	case <-time.After(time.Second):
		outbox.Stop()
		t.Fatal("capacity waiter held the lifecycle stripe needed by its capacity-releasing delete")
	}
	select {
	case err := <-stored:
		if err != nil {
			t.Fatalf("store did not resume after same-stripe capacity release: %v", err)
		}
	case <-time.After(time.Second):
		outbox.Stop()
		t.Fatal("store did not resume after capacity was freed")
	}
	outbox.Stop()
}

func TestTxOutboxWALOwnedProjectionFailureRetainsCapacityUntilRestart(t *testing.T) {
	config := testTxQUICConfig()
	payloadA := testTxQUICBatchPayload(t, config, testTxQUICTransaction(7300, 0))
	payloadB := testTxQUICBatchPayload(t, config, testTxQUICTransaction(7301, 0))
	capacityA, err := txOutboxRecordCapacityBytes(payloadA)
	if err != nil {
		t.Fatal(err)
	}
	capacityB, err := txOutboxRecordCapacityBytes(payloadB)
	if err != nil {
		t.Fatal(err)
	}
	config.OutboxMaxRecords = 1
	config.OutboxMaxBytes = capacityA
	if capacityB > config.OutboxMaxBytes {
		config.OutboxMaxBytes = capacityB
	}

	walDB := memorydb.New()
	wal := newTxIngressWAL(walDB, config)
	wal.maxRecords = 64
	wal.maxBytes = config.OutboxMaxBytes * 64
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	base := memorydb.New()
	projectionDB := &failingPutTxQUICDB{KeyValueStore: base}
	outbox := NewTxOutbox(projectionDB, config)
	outbox.wal = wal
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		wal.Stop()
		t.Fatal(err)
	}
	projectionDB.failRecordPut.Store(true)
	if _, err := outbox.StoreSync(context.Background(), payloadA); err == nil || !strings.Contains(err.Error(), "projection") {
		outbox.Stop()
		wal.Stop()
		t.Fatalf("WAL-owned projection failure = %v", err)
	}
	outbox.mu.Lock()
	poison := outbox.poison
	reservedRecords, reservedBytes := outbox.reservedRecords, outbox.reservedBytes
	outbox.mu.Unlock()
	if poison == nil || reservedRecords != 1 || reservedBytes != capacityA {
		outbox.Stop()
		wal.Stop()
		t.Fatalf("post-WAL projection failure poison/reservation = %v/%d/%d, want poison/1/%d",
			poison, reservedRecords, reservedBytes, capacityA)
	}
	projectionDB.failRecordPut.Store(false)
	if _, err := outbox.StoreSync(context.Background(), payloadB); err == nil || !strings.Contains(err.Error(), "poisoned until restart") {
		outbox.Stop()
		wal.Stop()
		t.Fatalf("post-failure ownership was not failed closed: %v", err)
	}
	outbox.Stop()
	wal.Stop()

	restartedWAL := newTxIngressWAL(walDB, config)
	restartedWAL.maxRecords = 64
	restartedWAL.maxBytes = config.OutboxMaxBytes * 64
	if err := restartedWAL.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer restartedWAL.Stop()
	restartedOutbox := NewTxOutbox(base, config)
	if err := ensureTxQUICDatabaseIdentity(base, txOutboxIdentityKey, txQUICDatabaseIdentity{ChainID: config.ChainID, GenesisHash: config.GenesisHash}); err != nil {
		t.Fatal(err)
	}
	q := &TxQUICIngress{config: config, ctx: context.Background(), wal: restartedWAL, outbox: restartedOutbox}
	if err := q.replayWALOutboxProjection(); err != nil {
		t.Fatal(err)
	}
	if err := restartedOutbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatalf("capacity-bounded restart after projection failure: %v", err)
	}
	defer restartedOutbox.Stop()
	if records, _ := restartedOutbox.Pending(); records != 1 {
		t.Fatalf("restart materialized %d WAL-owned records, want 1", records)
	}
}

func TestTxOutboxBusyPredecessorDoesNotConsumeReenqueueSchedule(t *testing.T) {
	config := testTxQUICConfig()
	config.OutboxWorkers = 2
	outbox := NewTxOutbox(memorydb.New(), config)
	batchID := common.HexToHash("0x7311")
	due := uint64(time.Now().UnixNano())
	outbox.mu.Lock()
	outbox.inFlight[batchID] = struct{}{}
	outbox.scheduleRecordLocked(batchID, due)
	outbox.mu.Unlock()
	if claimed, ok := outbox.popDue(due); ok || claimed != (common.Hash{}) {
		t.Fatalf("busy predecessor was claimed again: %s", claimed)
	}
	outbox.mu.Lock()
	_, scheduled := outbox.scheduled[batchID]
	heapEntries := outbox.schedule.Len()
	delete(outbox.inFlight, batchID)
	outbox.mu.Unlock()
	if !scheduled || heapEntries != 1 {
		t.Fatalf("busy predecessor consumed re-enqueue schedule: scheduled=%t heap=%d", scheduled, heapEntries)
	}
	if claimed, ok := outbox.popDue(due); !ok || claimed != batchID {
		t.Fatalf("released predecessor claim = %s/%t, want %s/true", claimed, ok, batchID)
	}
}

func TestTxOutboxGroupCommitAmbiguousSyncFailsEveryWaiter(t *testing.T) {
	config := testTxQUICConfig()
	base := memorydb.New()
	db := &ambiguousSyncTxQUICDB{KeyValueStore: base}
	outbox := NewTxOutbox(db, config)
	outbox.commitInterval = 100 * time.Millisecond
	outbox.commitMaxRequests = 3
	deliveries := atomic.Int32{}
	if err := outbox.Start(context.Background(), func(context.Context, []byte) error {
		deliveries.Add(1)
		return nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	defer outbox.Stop()
	db.failAfterApply.Store(true)

	payloads := make([][]byte, 3)
	start := make(chan struct{})
	errs := make(chan error, len(payloads))
	var group sync.WaitGroup
	for index := range payloads {
		payloads[index] = testTxQUICBatchPayload(t, config, testTxQUICTransaction(uint64(6600+index), 0))
		payload := payloads[index]
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := outbox.StoreSync(context.Background(), payload)
			errs <- err
		}()
	}
	close(start)
	group.Wait()
	close(errs)
	for err := range errs {
		if err == nil || !strings.Contains(err.Error(), "ambiguous") {
			t.Fatalf("ambiguous grouped outbox result = %v", err)
		}
	}
	if _, err := outbox.StoreSync(context.Background(), testTxQUICBatchPayload(t, config, testTxQUICTransaction(6699, 0))); err == nil || !strings.Contains(err.Error(), "poisoned until restart") {
		t.Fatalf("post-fsync-failure outbox result = %v", err)
	}
	for _, payload := range payloads {
		has, err := base.Has(txOutboxRecordKey(txOutboxBatchID(payload)))
		if err != nil || !has {
			t.Fatalf("ambiguously applied group record = has %t err %v", has, err)
		}
	}
	time.Sleep(3 * config.OutboxRetryMin)
	if got := deliveries.Load(); got != 0 {
		t.Fatalf("poisoned grouped outbox delivered %d batches", got)
	}
}

func TestTxOutboxNonceReservationPersistsAcrossRestart(t *testing.T) {
	config := testTxQUICConfig()
	config.NonceReservation = 4
	db := memorydb.New()
	sender := common.HexToAddress("0x7000000000000000000000000000000000000007")
	epoch := txQUICSenderEpoch(config.ChainID, config.GenesisHash, sender)

	first := NewTxOutbox(db, config)
	if err := first.Start(context.Background(), func(context.Context, []byte) error { return errors.New("offline") }, nil); err != nil {
		t.Fatal(err)
	}
	nonce1, err := first.NextNonce(sender, epoch)
	if err != nil {
		t.Fatal(err)
	}
	nonce2, err := first.NextNonce(sender, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if nonce1 != 1 || nonce2 != 2 {
		t.Fatalf("initial nonces = %d, %d, want 1, 2", nonce1, nonce2)
	}
	first.Stop()

	second := NewTxOutbox(db, config)
	if err := second.Start(context.Background(), func(context.Context, []byte) error { return errors.New("offline") }, nil); err != nil {
		t.Fatal(err)
	}
	defer second.Stop()
	nonceAfterRestart, err := second.NextNonce(sender, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if nonceAfterRestart != 5 {
		t.Fatalf("nonce after restart = %d, want first nonce after the persisted reservation (5)", nonceAfterRestart)
	}
}

func TestTxOutboxRestoreFailsClosedAtPersistedCapacityBoundary(t *testing.T) {
	config := testTxQUICConfig()
	db := memorydb.New()
	payloads := [][]byte{
		testTxQUICBatchPayload(t, config, testTxQUICTransaction(5800, 256)),
		testTxQUICBatchPayload(t, config, testTxQUICTransaction(5801, 256)),
	}
	first := NewTxOutbox(db, config)
	if err := first.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	for _, payload := range payloads {
		if _, err := first.StoreSync(context.Background(), payload); err != nil {
			t.Fatal(err)
		}
	}
	records, storedBytes := first.Pending()
	first.Stop()
	if records != len(payloads) || storedBytes <= 1 {
		t.Fatalf("test outbox accounting = %d records/%d bytes", records, storedBytes)
	}

	restore := func(maxRecords int, maxBytes int64) (int, error) {
		bounded := config
		bounded.OutboxMaxRecords = maxRecords
		bounded.OutboxMaxBytes = maxBytes
		callbacks := 0
		outbox := NewTxOutbox(db, bounded)
		err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
			<-ctx.Done()
			return ctx.Err()
		}, func([]byte) error {
			callbacks++
			return nil
		})
		outbox.Stop()
		return callbacks, err
	}

	callbacks, err := restore(records, storedBytes)
	if err != nil || callbacks != len(payloads) {
		t.Fatalf("exact outbox capacity restore = callbacks %d err %v", callbacks, err)
	}
	callbacks, err = restore(records, storedBytes-1)
	if err == nil || !strings.Contains(err.Error(), "capacity") || callbacks != 0 {
		t.Fatalf("one-byte outbox overflow = callbacks %d err %v", callbacks, err)
	}
	callbacks, err = restore(records-1, storedBytes)
	if err == nil || !strings.Contains(err.Error(), "capacity") || callbacks != 0 {
		t.Fatalf("one-record outbox overflow = callbacks %d err %v", callbacks, err)
	}
}

func TestTxOutboxAmbiguousSyncStopsDeliveryUntilValidatedRestart(t *testing.T) {
	config := testTxQUICConfig()
	base := memorydb.New()
	db := &ambiguousSyncTxQUICDB{KeyValueStore: base}
	deliveries := atomic.Int32{}
	outbox := NewTxOutbox(db, config)
	if err := outbox.Start(context.Background(), func(context.Context, []byte) error {
		deliveries.Add(1)
		return nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	db.failAfterApply.Store(true)
	payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(56, 0))
	if _, err := outbox.StoreSync(context.Background(), payload); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous outbox fsync error = %v", err)
	}
	time.Sleep(3 * config.OutboxRetryMin)
	if got := deliveries.Load(); got != 0 {
		t.Fatalf("poisoned outbox delivered %d batches before restart", got)
	}
	outbox.Stop()

	restored := 0
	restarted := NewTxOutbox(base, config)
	if err := restarted.Start(context.Background(), func(context.Context, []byte) error { return errors.New("offline") }, func([]byte) error {
		restored++
		return nil
	}); err != nil {
		t.Fatalf("restart could not validate applied outbox record: %v", err)
	}
	defer restarted.Stop()
	if restored != 1 {
		t.Fatalf("restart restored %d outbox batches, want one", restored)
	}
}

func TestTxOutboxValidatesAllSchemaBeforeRestoreCallbacks(t *testing.T) {
	config := testTxQUICConfig()
	db := memorydb.New()
	first := NewTxOutbox(db, config)
	if err := first.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := first.StoreSync(context.Background(), testTxQUICBatchPayload(t, config, testTxQUICTransaction(57, 0))); err != nil {
		t.Fatal(err)
	}
	first.Stop()
	orphanID := common.HexToHash("0x9876")
	orphanRetry, err := rlp.EncodeToBytes(&txOutboxRetryState{Attempts: 1, NextRetry: uint64(time.Now().UnixNano()), LastError: "orphan"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Put(txOutboxRetryKey(orphanID), orphanRetry); err != nil {
		t.Fatal(err)
	}

	callbacks := 0
	second := NewTxOutbox(db, config)
	if err := second.Start(context.Background(), func(context.Context, []byte) error { return nil }, func([]byte) error {
		callbacks++
		return nil
	}); err == nil || !strings.Contains(err.Error(), "orphan") {
		second.Stop()
		t.Fatalf("orphan retry startup error = %v", err)
	}
	if callbacks != 0 {
		t.Fatalf("corrupt outbox invoked %d restore callbacks", callbacks)
	}
}

func TestTxQUICRuntimeLimitsRejectExtremeAllocationConfig(t *testing.T) {
	config := testTxQUICConfig()
	config.FairHotstuff = true
	config.ReplayWindow = ^uint64(0)
	q := NewTxQUICIngress(config, nil)
	q.config.HTTP3Enabled = true
	if err := q.validateSecurityConfig(); err == nil || !strings.Contains(err.Error(), "replay window") {
		t.Fatalf("extreme replay window validation error = %v", err)
	}
	store := NewTxQUICIngressStore(memorydb.New(), config)
	if err := store.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "replay window") {
		t.Fatalf("extreme replay window store error = %v", err)
	}
}

func TestTxQUICRuntimeLimitsKeepAckThroughPacketAge(t *testing.T) {
	config := testTxQUICConfig()
	applyTxQUICDefaults(&config)
	config.IngressAckRetention = config.MaxPacketAge - time.Nanosecond
	if err := validateTxQUICRuntimeLimits(config); err == nil || !strings.Contains(err.Error(), "replay or retention") {
		t.Fatalf("short ACK retention validation error = %v", err)
	}
}

func TestTxQUICRuntimeLimitsBoundBridgeQueueBytes(t *testing.T) {
	config := testTxQUICConfig()
	applyTxQUICDefaults(&config)
	config.BridgeQueueMaxBytes = txQUICMaxBridgeQueueBytes + 1
	if err := validateTxQUICRuntimeLimits(config); err == nil || !strings.Contains(err.Error(), "bridge concurrency") {
		t.Fatalf("oversized bridge byte limit validation error = %v", err)
	}
	if DefaultConfig.TxQUIC.BridgeQueueMaxBytes >= int64(DefaultConfig.TxQUIC.BridgeQueueSize)*(128<<10) {
		t.Fatalf("default bridge byte limit %d permits the count bound to retain 128 KiB per item", DefaultConfig.TxQUIC.BridgeQueueMaxBytes)
	}
	if defaultTxQUICBridgeQueueMaxBytes < 256<<20 || defaultTxQUICBridgeQueueMaxBytes > txQUICMaxBridgeQueueBytes {
		t.Fatalf("default bridge burst envelope %d is outside [256 MiB, %d]", defaultTxQUICBridgeQueueMaxBytes, txQUICMaxBridgeQueueBytes)
	}
}

func TestTxQUICRuntimeLimitsBoundDurableStorage(t *testing.T) {
	config := testTxQUICConfig()
	applyTxQUICDefaults(&config)
	config.OutboxMaxBytes = txQUICMaxOutboxBytes + 1
	if err := validateTxQUICRuntimeLimits(config); err == nil || !strings.Contains(err.Error(), "durable storage") {
		t.Fatalf("oversized durable byte limit validation error = %v", err)
	}

	config = testTxQUICConfig()
	applyTxQUICDefaults(&config)
	config.OutboxMaxRecords = txQUICMaxOutboxRecords + 1
	if err := validateTxQUICRuntimeLimits(config); err == nil || !strings.Contains(err.Error(), "durable storage") {
		t.Fatalf("oversized durable record limit validation error = %v", err)
	}
	if DefaultConfig.TxQUIC.OutboxMaxBytes != txQUICMaxOutboxBytes || DefaultConfig.TxQUIC.OutboxMaxRecords != txQUICMaxOutboxRecords {
		t.Fatalf("default durable bounds = %d bytes/%d records, want %d/%d",
			DefaultConfig.TxQUIC.OutboxMaxBytes, DefaultConfig.TxQUIC.OutboxMaxRecords,
			txQUICMaxOutboxBytes, txQUICMaxOutboxRecords)
	}
}

func TestTxOutboxCompactsAcknowledgedItemsIntoResidualBatch(t *testing.T) {
	config := testTxQUICConfig()
	db := memorydb.New()
	outbox := NewTxOutbox(db, config)
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	defer outbox.Stop()

	txs := []*types.Transaction{
		testTxQUICTransaction(60, 0),
		testTxQUICTransaction(61, 0),
		testTxQUICTransaction(62, 0),
	}
	batch := testTxQUICBatch(t, config, txs...)
	payload, err := rlp.EncodeToBytes(batch)
	if err != nil {
		t.Fatal(err)
	}
	batchID, err := outbox.StoreSync(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := db.Get(txOutboxRecordKey(batchID))
	if err != nil {
		t.Fatal(err)
	}
	var record TxOutboxRecord
	if err := rlp.DecodeBytes(encoded, &record); err != nil {
		t.Fatal(err)
	}

	sender := common.HexToAddress("0x8000000000000000000000000000000000000008")
	packet := testTxQUICPacketFromBatch(config, batch, sender, 1, uint64(time.Now().Unix()))
	expectation, err := newTxQUICAckExpectation(packet)
	if err != nil {
		t.Fatal(err)
	}
	ack := testTxQUICAck(t, packet, []int{0}, []int{1}, []txQUICPermanentError{{
		Index: 2, ItemID: expectation.itemIDs[2], Code: txQUICPermanentInvalidTransaction, Reason: "invalid",
	}})
	if err := validateTxQUICAckOutcome(&ack, expectation); err != nil {
		t.Fatal(err)
	}
	residual, oldDeleted, err := outbox.compactAcknowledgedRecord(&record, &ack)
	if err != nil {
		t.Fatal(err)
	}
	if !oldDeleted || residual == nil || residual.BatchID == batchID {
		t.Fatalf("residual compaction = residual %#v oldDeleted %t", residual, oldDeleted)
	}
	if has, err := db.Has(txOutboxRecordKey(batchID)); err != nil || has {
		t.Fatalf("superseded batch remains: has=%t err=%v", has, err)
	}
	if has, err := db.Has(txOutboxRecordKey(residual.BatchID)); err != nil || !has {
		t.Fatalf("residual batch missing: has=%t err=%v", has, err)
	}
	residualBatch, _, err := decodeTxQUICBatch(residual.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(residualBatch.Items) != 1 || residualBatch.Items[0].Tx.Hash() != txs[1].Hash() {
		t.Fatalf("residual batch items = %#v, want only retryable transaction %s", residualBatch.Items, txs[1].Hash())
	}
	if residualBatch.Items[0].AdmissionIndex != 1 {
		t.Fatalf("residual admission index = %d, want original index 1", residualBatch.Items[0].AdmissionIndex)
	}
	if residualBatch.Certificate == nil || residualBatch.Certificate.AdmissionID != batch.Certificate.AdmissionID {
		t.Fatalf("residual admission certificate changed: have %#v want %s", residualBatch.Certificate, batch.Certificate.AdmissionID)
	}
	originalCertificate, err := rlp.EncodeToBytes(batch.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	residualCertificate, err := rlp.EncodeToBytes(residualBatch.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalCertificate, residualCertificate) {
		t.Fatal("partial ACK rewrote the shared admission certificate")
	}
	if records, _ := outbox.Pending(); records != 1 {
		t.Fatalf("outbox pending records after compaction = %d, want 1", records)
	}
}

func testTxOutboxStoredRecord(t *testing.T, db ethdb.KeyValueReader, batchID common.Hash) TxOutboxRecord {
	t.Helper()
	encoded, err := db.Get(txOutboxRecordKey(batchID))
	if err != nil {
		t.Fatal(err)
	}
	var record TxOutboxRecord
	if err := rlp.DecodeBytes(encoded, &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func testTxOutboxPartialAck(t *testing.T, config TxQUICConfig, batch *txQUICBatch, durable, retryable []int) *txQUICAck {
	t.Helper()
	packet := testTxQUICPacketFromBatch(
		config, batch, common.HexToAddress("0x8100000000000000000000000000000000000008"), 1, uint64(time.Now().Unix()),
	)
	ack := testTxQUICAck(t, packet, durable, retryable, nil)
	return &ack
}

func testTxOutboxResidual(t *testing.T, batch *txQUICBatch, indexes ...int) (*txQUICBatch, []byte) {
	t.Helper()
	items := make([]*txQUICItem, len(indexes))
	for index, original := range indexes {
		items[index] = batch.Items[original]
	}
	residual, _, err := newTxQUICBatch(batch.ChainID, batch.GenesisHash, batch.Certificate, items)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := rlp.EncodeToBytes(residual)
	if err != nil {
		t.Fatal(err)
	}
	return residual, payload
}

func TestTxOutboxResidualReplacementUsesNetCapacityAtFullLimit(t *testing.T) {
	config := testTxQUICConfig()
	txs := []*types.Transaction{testTxQUICTransaction(6700, 0), testTxQUICTransaction(6701, 0)}
	batch := testTxQUICBatch(t, config, txs...)
	payload, err := rlp.EncodeToBytes(batch)
	if err != nil {
		t.Fatal(err)
	}
	config.OutboxMaxRecords = 1
	config.OutboxMaxBytes = int64(len(payload)) + txOutboxPlacementReserveBytes
	db := &recordingSyncTxQUICDB{KeyValueStore: memorydb.New()}
	outbox := NewTxOutbox(db, config)
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	batchID, err := outbox.StoreSync(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	record := testTxOutboxStoredRecord(t, db, batchID)
	db.resetWrites()
	ack := testTxOutboxPartialAck(t, config, batch, []int{0}, []int{1})
	residual, oldDeleted, err := outbox.compactAcknowledgedRecord(&record, ack)
	if err != nil {
		t.Fatal(err)
	}
	if residual == nil || !oldDeleted || residual.BatchID == batchID {
		t.Fatalf("full-capacity replacement = residual %#v oldDeleted %t", residual, oldDeleted)
	}
	if records, storedBytes := outbox.Pending(); records != 1 || storedBytes != int64(len(residual.Payload))+txOutboxPlacementReserveBytes {
		t.Fatalf("full-capacity replacement accounting = %d records/%d bytes, want 1/%d", records, storedBytes, int64(len(residual.Payload))+txOutboxPlacementReserveBytes)
	}
	if has, err := db.Has(txOutboxRecordKey(batchID)); err != nil || has {
		t.Fatalf("full-capacity superseded record = has %t err %v", has, err)
	}
	if has, err := db.Has(txOutboxRecordKey(residual.BatchID)); err != nil || !has {
		t.Fatalf("full-capacity residual record = has %t err %v", has, err)
	}
	writes := db.recordedWrites()
	if len(writes) != 1 || len(writes[0]) != 3 {
		t.Fatalf("atomic residual replacement writes = %#v, want one batch with three operations", writes)
	}
	wantOperations := []recordedTxQUICBatchOperation{
		{kind: "put", key: txOutboxRecordKey(residual.BatchID)},
		{kind: "delete", key: txOutboxRecordKey(batchID)},
		{kind: "delete", key: txOutboxRetryKey(batchID)},
	}
	for index, operation := range writes[0] {
		if operation.kind != wantOperations[index].kind || !bytes.Equal(operation.key, wantOperations[index].key) {
			t.Fatalf("atomic residual replacement operation %d = %s %x, want %s %x",
				index, operation.kind, operation.key, wantOperations[index].kind, wantOperations[index].key)
		}
	}
	outbox.Stop()

	restored := 0
	restarted := NewTxOutbox(db, config)
	if err := restarted.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, func(restoredPayload []byte) error {
		restored++
		if txOutboxBatchID(restoredPayload) != residual.BatchID {
			return fmt.Errorf("restored the wrong residual batch")
		}
		return nil
	}); err != nil {
		t.Fatalf("restart at exact capacity failed: %v", err)
	}
	defer restarted.Stop()
	if restored != 1 {
		t.Fatalf("restart restored %d records, want one residual", restored)
	}
}

func TestTxOutboxResidualReplacementAmbiguousApplyRestartsWithoutCapacityOverflow(t *testing.T) {
	config := testTxQUICConfig()
	batch := testTxQUICBatch(t, config, testTxQUICTransaction(6800, 0), testTxQUICTransaction(6801, 0))
	payload, err := rlp.EncodeToBytes(batch)
	if err != nil {
		t.Fatal(err)
	}
	config.OutboxMaxRecords = 1
	config.OutboxMaxBytes = int64(len(payload)) + txOutboxPlacementReserveBytes
	base := memorydb.New()
	db := &ambiguousSyncTxQUICDB{KeyValueStore: base}
	outbox := NewTxOutbox(db, config)
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	batchID, err := outbox.StoreSync(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	record := testTxOutboxStoredRecord(t, base, batchID)
	expectedResidual, _ := testTxOutboxResidual(t, batch, 1)
	db.failAfterApply.Store(true)
	residual, oldDeleted, err := outbox.compactAcknowledgedRecord(&record, testTxOutboxPartialAck(t, config, batch, []int{0}, []int{1}))
	if err == nil || !strings.Contains(err.Error(), "ambiguous") || residual != nil || oldDeleted {
		t.Fatalf("ambiguous atomic replacement = residual %#v deleted %t err %v", residual, oldDeleted, err)
	}
	if records, storedBytes := outbox.Pending(); records != 1 || storedBytes != int64(len(payload))+txOutboxPlacementReserveBytes {
		t.Fatalf("ambiguous replacement changed counters = %d records/%d bytes", records, storedBytes)
	}
	if has, err := base.Has(txOutboxRecordKey(batchID)); err != nil || has {
		t.Fatalf("atomically applied old record = has %t err %v", has, err)
	}
	if has, err := base.Has(txOutboxRecordKey(expectedResidual.BatchID)); err != nil || !has {
		t.Fatalf("atomically applied residual record = has %t err %v", has, err)
	}
	outbox.Stop()

	restored := 0
	restarted := NewTxOutbox(base, config)
	if err := restarted.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, func(restoredPayload []byte) error {
		restored++
		if txOutboxBatchID(restoredPayload) != expectedResidual.BatchID {
			return fmt.Errorf("restored unexpected batch")
		}
		return nil
	}); err != nil {
		t.Fatalf("restart after ambiguously applied replacement failed: %v", err)
	}
	defer restarted.Stop()
	if restored != 1 {
		t.Fatalf("restart after ambiguous replacement restored %d records", restored)
	}
}

func TestTxOutboxResidualReplacementDeterministicWriteFailureHasNoDrift(t *testing.T) {
	config := testTxQUICConfig()
	base := memorydb.New()
	db := &failingDeleteTxQUICDB{KeyValueStore: base}
	outbox := NewTxOutbox(db, config)
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	defer outbox.Stop()
	batch := testTxQUICBatch(t, config, testTxQUICTransaction(6900, 0), testTxQUICTransaction(6901, 0))
	payload, err := rlp.EncodeToBytes(batch)
	if err != nil {
		t.Fatal(err)
	}
	batchID, err := outbox.StoreSync(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	record := testTxOutboxStoredRecord(t, base, batchID)
	expectedResidual, _ := testTxOutboxResidual(t, batch, 1)
	db.failDelete.Store(true)
	residual, oldDeleted, err := outbox.compactAcknowledgedRecord(&record, testTxOutboxPartialAck(t, config, batch, []int{0}, []int{1}))
	if err == nil || !strings.Contains(err.Error(), "deterministic") || residual != nil || oldDeleted {
		t.Fatalf("deterministic replacement failure = residual %#v deleted %t err %v", residual, oldDeleted, err)
	}
	if records, storedBytes := outbox.Pending(); records != 1 || storedBytes != int64(len(payload))+txOutboxPlacementReserveBytes {
		t.Fatalf("deterministic failure changed counters = %d records/%d bytes", records, storedBytes)
	}
	if has, err := base.Has(txOutboxRecordKey(batchID)); err != nil || !has {
		t.Fatalf("deterministic failure lost old record: has %t err %v", has, err)
	}
	if has, err := base.Has(txOutboxRecordKey(expectedResidual.BatchID)); err != nil || has {
		t.Fatalf("deterministic failure stored residual: has %t err %v", has, err)
	}
	outbox.mu.Lock()
	poison := outbox.poison
	outbox.mu.Unlock()
	if poison != nil {
		t.Fatalf("deterministic pre-write failure poisoned outbox: %v", poison)
	}
}

func TestTxOutboxResidualReplacementReusesExistingRecordAtomically(t *testing.T) {
	config := testTxQUICConfig()
	db := &recordingSyncTxQUICDB{KeyValueStore: memorydb.New()}
	deliveryStarted := make(chan struct{})
	var deliveryOnce sync.Once
	outbox := NewTxOutbox(db, config)
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		deliveryOnce.Do(func() { close(deliveryStarted) })
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	defer outbox.Stop()

	batch := testTxQUICBatch(t, config, testTxQUICTransaction(7000, 0), testTxQUICTransaction(7001, 0))
	payload, err := rlp.EncodeToBytes(batch)
	if err != nil {
		t.Fatal(err)
	}
	oldID, err := outbox.StoreSync(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-deliveryStarted:
	case <-time.After(time.Second):
		t.Fatal("old outbox record did not enter delivery")
	}
	residualBatch, residualPayload := testTxOutboxResidual(t, batch, 1)
	if _, err := outbox.StoreSync(context.Background(), residualPayload); err != nil {
		t.Fatal(err)
	}
	oldRetry, err := outbox.updateRetry(oldID, errors.New("old delivery retry"))
	if err != nil {
		t.Fatal(err)
	}
	residualRetry, err := outbox.updateRetry(residualBatch.BatchID, errors.New("residual delivery retry"))
	if err != nil {
		t.Fatal(err)
	}
	if oldRetry.Attempts != 1 || residualRetry.Attempts != 1 {
		t.Fatalf("test retry setup failed: old %#v residual %#v", oldRetry, residualRetry)
	}
	oldRecord := testTxOutboxStoredRecord(t, db, oldID)
	outbox.mu.Lock()
	residualDue, residualScheduled := outbox.scheduled[residualBatch.BatchID]
	_, residualInFlight := outbox.inFlight[residualBatch.BatchID]
	outbox.mu.Unlock()
	if !residualScheduled || residualInFlight {
		t.Fatalf("test residual scheduling state = scheduled %t inFlight %t", residualScheduled, residualInFlight)
	}
	db.resetWrites()

	residual, oldDeleted, err := outbox.compactAcknowledgedRecord(&oldRecord, testTxOutboxPartialAck(t, config, batch, []int{0}, []int{1}))
	if err != nil {
		t.Fatal(err)
	}
	if residual == nil || residual.BatchID != residualBatch.BatchID || !oldDeleted {
		t.Fatalf("existing residual replacement = residual %#v deleted %t", residual, oldDeleted)
	}
	writes := db.recordedWrites()
	if len(writes) != 1 || len(writes[0]) != 2 ||
		writes[0][0].kind != "delete" || !bytes.Equal(writes[0][0].key, txOutboxRecordKey(oldID)) ||
		writes[0][1].kind != "delete" || !bytes.Equal(writes[0][1].key, txOutboxRetryKey(oldID)) {
		t.Fatalf("existing residual atomic delete operations = %#v", writes)
	}
	if records, storedBytes := outbox.Pending(); records != 1 || storedBytes != int64(len(residualPayload))+txOutboxPlacementReserveBytes {
		t.Fatalf("existing residual accounting = %d records/%d bytes, want 1/%d", records, storedBytes, int64(len(residualPayload))+txOutboxPlacementReserveBytes)
	}
	if has, err := db.Has(txOutboxRecordKey(oldID)); err != nil || has {
		t.Fatalf("existing residual replacement retained old record: has %t err %v", has, err)
	}
	if has, err := db.Has(txOutboxRetryKey(oldID)); err != nil || has {
		t.Fatalf("existing residual replacement retained old retry: has %t err %v", has, err)
	}
	persistedResidualRetry, err := outbox.readRetry(residualBatch.BatchID)
	if err != nil || persistedResidualRetry.Attempts != residualRetry.Attempts || persistedResidualRetry.LastError != residualRetry.LastError {
		t.Fatalf("existing residual retry changed = %#v err %v", persistedResidualRetry, err)
	}
	outbox.mu.Lock()
	afterDue, afterScheduled := outbox.scheduled[residualBatch.BatchID]
	_, afterInFlight := outbox.inFlight[residualBatch.BatchID]
	outbox.mu.Unlock()
	if !afterScheduled || afterDue != residualDue || afterInFlight {
		t.Fatalf("existing residual scheduling changed = scheduled %t due %d/%d inFlight %t", afterScheduled, afterDue, residualDue, afterInFlight)
	}
}

func startTxQUICDurableBatchHarness(t *testing.T, config TxQUICConfig) *TxQUICIngress {
	t.Helper()
	config.BridgeEnabled = true
	q := NewTxQUICIngress(config, nil)
	outbox := NewTxOutbox(memorydb.New(), config)
	q.SetDurableOutbox(outbox, nil)
	if err := outbox.Start(q.ctx, func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	q.startBridgeWorkers()
	t.Cleanup(q.Stop)
	return q
}

func newTxQUICManualBridgeHarness(t *testing.T, config TxQUICConfig) *TxQUICIngress {
	t.Helper()
	config.BridgeEnabled = true
	q := NewTxQUICIngress(config, nil)
	q.SetDurableOutbox(NewTxOutbox(memorydb.New(), config), nil)
	q.bridgeAcceptMu.Lock()
	q.bridgeAccepting = true
	q.bridgeAcceptMu.Unlock()
	t.Cleanup(q.Stop)
	return q
}

func submitTxQUICBridgeItems(t *testing.T, q *TxQUICIngress, txs ...*types.Transaction) {
	t.Helper()
	for start := 0; start < len(txs); start += txQUICMicroBatchMaxTxs {
		end := start + txQUICMicroBatchMaxTxs
		if end > len(txs) {
			end = len(txs)
		}
		chunk := txs[start:end]
		certificate := testTxQUICCertificate(t, q.config, chunk...)
		items := make([]txQUICBridgeItem, len(chunk))
		for index, tx := range chunk {
			items[index] = txQUICBridgeItem{tx: tx, admissionIndex: uint16(index)}
		}
		request, err := newTxQUICBridgeRequest(certificate, items, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := q.acquireDurableBridgeCapacity(context.Background(), len(request.items), request.rawBytes); err != nil {
			t.Fatal(err)
		}
		select {
		case q.durableQueue <- request:
		case <-time.After(time.Second):
			t.Fatal("timed out submitting durable bridge request")
		}
		select {
		case <-request.done:
			if err := request.err(); err != nil {
				t.Fatalf("durable bridge persistence failed: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for durable bridge persistence")
		}
	}
}

func txQUICOutboxBatchSizes(t *testing.T, outbox *TxOutbox) []int {
	t.Helper()
	iterator := outbox.db.NewIterator(txOutboxRecordPrefix, nil)
	defer iterator.Release()
	var sizes []int
	for iterator.Next() {
		var record TxOutboxRecord
		if err := rlp.DecodeBytes(iterator.Value(), &record); err != nil {
			t.Fatal(err)
		}
		batch, _, err := decodeTxQUICBatch(record.Payload)
		if err != nil {
			t.Fatal(err)
		}
		sizes = append(sizes, len(batch.Items))
	}
	if err := iterator.Error(); err != nil {
		t.Fatal(err)
	}
	return sizes
}

func TestTxQUICVerifiedLocalAdmissionAvoidsRedundantRecoveryButDiskRestoreFailsClosed(t *testing.T) {
	config := testTxQUICConfig()
	tx := testTxQUICTransaction(990, 0)
	admission := testTxQUICCertificate(t, config, tx)
	admission.Signature = make([]byte, crypto.SignatureLength)
	result := core.CommonRPCAdmissionResult{Batch: admission, Item: 0}
	if err := types.VerifyCommonTxAdmissionSignature(admission); err == nil {
		t.Fatal("test admission unexpectedly has a valid signature")
	}

	q := startTxQUICDurableBatchHarness(t, config)
	q.bridgeAcceptMu.Lock()
	q.bridgeAccepting = true
	q.bridgeAcceptMu.Unlock()
	if err := q.EnqueueLocalTxsWithAdmissions(context.Background(), []*types.Transaction{tx}, []core.CommonRPCAdmissionResult{result}, nil); err == nil {
		t.Fatal("untrusted local enqueue accepted an invalid admission signature")
	}
	// The invalid signature is an observable sentinel for this test only. The
	// production caller can enter this path solely with admissions returned by
	// core.SignAndRecordCommonRPCAdmissions, which already verified the signer.
	if err := q.enqueueVerifiedLocalTxsWithAdmissions(context.Background(), []*types.Transaction{tx}, []core.CommonRPCAdmissionResult{result}, nil); err != nil {
		t.Fatalf("verified local enqueue redundantly recovered admission signature: %v", err)
	}
	if records, _ := q.outbox.Pending(); records != 1 {
		t.Fatalf("verified local enqueue persisted %d outbox records, want 1", records)
	}

	wrongChain := *admission
	wrongChain.ChainID = new(big.Int).Add(admission.ChainID, big.NewInt(1))
	if err := q.enqueueVerifiedLocalTxsWithAdmissions(context.Background(), []*types.Transaction{tx}, []core.CommonRPCAdmissionResult{{Batch: &wrongChain, Item: 0}}, nil); err == nil {
		t.Fatal("verified local enqueue bypassed structural chain validation")
	}

	db := q.outbox.db
	q.Stop()
	restarted := NewTxOutbox(db, config)
	if err := restarted.Start(context.Background(), func(context.Context, []byte) error { return nil }, q.restoreOutboxPayload); err == nil {
		restarted.Stop()
		t.Fatal("disk restore accepted the deliberately invalid admission signature")
	}
}

func TestTxQUICBridgeSharedCertificateUsesOneSnapshot(t *testing.T) {
	config := testTxQUICConfig()
	txs := make([]*types.Transaction, txQUICMicroBatchMaxTxs)
	for index := range txs {
		txs[index] = testTxQUICTransaction(uint64(10_000+index), 0)
	}
	results := testTxQUICAdmissionResults(t, config, txs...)
	original := results[0].Batch
	originalFingerprint, err := txQUICCertificateHash(original)
	if err != nil {
		t.Fatal(err)
	}
	q := newTxQUICManualBridgeHarness(t, config)

	completed := make(chan error, 1)
	go func() {
		completed <- q.enqueueVerifiedLocalTxsWithAdmissions(context.Background(), txs, results, nil)
	}()
	var request *txQUICBridgeRequest
	select {
	case request = <-q.durableQueue:
	case err := <-completed:
		t.Fatalf("shared-certificate enqueue returned before persistence: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for shared-certificate bridge request")
	}
	if request == nil {
		t.Fatal("shared-certificate enqueue produced a nil bridge request")
	}
	if len(request.items) != len(txs) {
		t.Fatalf("shared-certificate request has %d items, want %d", len(request.items), len(txs))
	}
	if request.certificate == original {
		t.Fatal("shared-certificate request retained the caller-owned certificate pointer")
	}
	requestFingerprint, err := txQUICCertificateHash(request.certificate)
	if err != nil {
		t.Fatal(err)
	}
	if requestFingerprint != originalFingerprint {
		t.Fatalf("shared-certificate snapshot fingerprint = %s, want %s", requestFingerprint, originalFingerprint)
	}

	// Once the bounded request is queued, caller-owned memory can change without
	// changing the certificate that will be committed to the durable outbox.
	original.TxHashes[0] = common.HexToHash("0xdeadbeef")
	original.Signature[0] ^= 0xff
	requestFingerprint, err = txQUICCertificateHash(request.certificate)
	if err != nil {
		t.Fatal(err)
	}
	if requestFingerprint != originalFingerprint {
		t.Fatalf("caller mutation changed queued certificate fingerprint to %s", requestFingerprint)
	}

	q.finishDurableBridgeItems(request.items, nil)
	select {
	case err := <-completed:
		if err != nil {
			t.Fatalf("shared-certificate enqueue failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shared-certificate enqueue did not observe persistence completion")
	}
	if bytes := q.pendingDurableBridgeBytes(); bytes != 0 {
		t.Fatalf("shared-certificate completion retained %d durable bytes", bytes)
	}
	if slots := len(q.durableSlots); slots != 0 {
		t.Fatalf("shared-certificate completion retained %d durable item slots", slots)
	}
}

func TestTxQUICBridgeCoalescesIdenticalDistinctCertificatePointers(t *testing.T) {
	config := testTxQUICConfig()
	txs := []*types.Transaction{
		testTxQUICTransaction(11_000, 0),
		testTxQUICTransaction(11_001, 0),
	}
	original := testTxQUICCertificate(t, config, txs...)
	clone := copyCommonTxAdmissionBatchForQUIC(original)
	if clone == original {
		t.Fatal("test certificate clone retained the original pointer")
	}
	results := []core.CommonRPCAdmissionResult{
		{Batch: original, Item: 0},
		{Batch: clone, Item: 1},
	}
	q := newTxQUICManualBridgeHarness(t, config)

	completed := make(chan error, 1)
	go func() {
		completed <- q.enqueueVerifiedLocalTxsWithAdmissions(context.Background(), txs, results, nil)
	}()
	var request *txQUICBridgeRequest
	select {
	case request = <-q.durableQueue:
	case err := <-completed:
		t.Fatalf("identical distinct certificates returned before persistence: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for coalesced bridge request")
	}
	if request == nil {
		t.Fatal("identical certificate bodies produced a nil bridge request")
	}
	if len(request.items) != len(txs) {
		t.Fatalf("coalesced bridge request has %d items, want %d", len(request.items), len(txs))
	}
	if queued := len(q.durableQueue); queued != 0 {
		t.Fatalf("identical certificate bodies produced %d extra bridge requests", queued)
	}
	q.finishDurableBridgeItems(request.items, nil)
	select {
	case err := <-completed:
		if err != nil {
			t.Fatalf("identical distinct certificates failed to coalesce: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("coalesced bridge request did not complete")
	}
}

func TestTxQUICBridgeRejectsConflictingDistinctCertificatePointers(t *testing.T) {
	config := testTxQUICConfig()
	txs := []*types.Transaction{
		testTxQUICTransaction(12_000, 0),
		testTxQUICTransaction(12_001, 0),
	}
	original := testTxQUICCertificate(t, config, txs...)
	conflict := copyCommonTxAdmissionBatchForQUIC(original)
	conflict.Signature[0] ^= 0xff
	if conflict.AdmissionID != original.AdmissionID {
		t.Fatal("test conflict changed the admission identity")
	}
	results := []core.CommonRPCAdmissionResult{
		{Batch: original, Item: 0},
		{Batch: conflict, Item: 1},
	}
	q := newTxQUICManualBridgeHarness(t, config)

	err := q.enqueueVerifiedLocalTxsWithAdmissions(context.Background(), txs, results, nil)
	if err == nil || !strings.Contains(err.Error(), "conflicting TxQUIC certificates share admission id") {
		t.Fatalf("conflicting distinct certificate error = %v", err)
	}
	if queued := len(q.durableQueue); queued != 0 {
		t.Fatalf("conflicting certificate queued %d bridge requests", queued)
	}
	if bytes := q.pendingDurableBridgeBytes(); bytes != 0 {
		t.Fatalf("conflicting certificate retained %d durable bytes", bytes)
	}
	if slots := len(q.durableSlots); slots != 0 {
		t.Fatalf("conflicting certificate retained %d durable item slots", slots)
	}
}

func TestDurableTxQUICBridgeSplitsAtFixedMicroBatchCount(t *testing.T) {
	config := testTxQUICConfig()
	config.BridgeQueueSize = 1024
	q := startTxQUICDurableBatchHarness(t, config)

	txs := make([]*types.Transaction, 600)
	for index := range txs {
		txs[index] = testTxQUICTransaction(uint64(1000+index), 0)
	}
	submitTxQUICBridgeItems(t, q, txs...)
	sizes := txQUICOutboxBatchSizes(t, q.outbox)
	if len(sizes) != 2 {
		t.Fatalf("durable bridge batches = %v, want two batches", sizes)
	}
	total := 0
	for _, size := range sizes {
		if size > txQUICMicroBatchMaxTxs {
			t.Fatalf("durable bridge emitted oversized batch of %d items", size)
		}
		total += size
	}
	if total != len(txs) {
		t.Fatalf("durable bridge persisted %d items, want %d", total, len(txs))
	}
}

func TestDurableTxQUICBridgeSplitsAtFixedMicroBatchBytes(t *testing.T) {
	config := testTxQUICConfig()
	itemDataBytes := int(txQUICMicroBatchMaxStoredBytes/2) + 1024
	txs := []*types.Transaction{
		testTxQUICTransaction(2000, itemDataBytes),
		testTxQUICTransaction(2001, itemDataBytes),
	}
	oneSize := len(testTxQUICBatchPayload(t, config, txs[0]))
	otherSize := len(testTxQUICBatchPayload(t, config, txs[1]))
	combinedSize := len(testTxQUICBatchPayload(t, config, txs...))
	if otherSize > oneSize {
		oneSize = otherSize
	}
	if combinedSize <= oneSize {
		t.Fatalf("test payload sizes cannot exercise splitting: one=%d combined=%d", oneSize, combinedSize)
	}
	if int64(oneSize) > txQUICMicroBatchMaxStoredBytes || int64(combinedSize) <= txQUICMicroBatchMaxStoredBytes {
		t.Fatalf("test payload sizes do not straddle fixed stored micro-batch bound: one=%d combined=%d limit=%d", oneSize, combinedSize, txQUICMicroBatchMaxStoredBytes)
	}
	q := startTxQUICDurableBatchHarness(t, config)
	submitTxQUICBridgeItems(t, q, txs...)

	sizes := txQUICOutboxBatchSizes(t, q.outbox)
	if len(sizes) != 2 || sizes[0] != 1 || sizes[1] != 1 {
		t.Fatalf("payload-limited durable batches = %v, want [1 1] in any order", sizes)
	}
}

func TestTxQUICBridgeItemRawSizeMatchesCanonicalEncoding(t *testing.T) {
	legacy := testTxQUICTransaction(2050, 128)
	to := common.HexToAddress("0x2000000000000000000000000000000000000002")
	typed := types.NewTx(&types.DynamicFeeTx{
		ChainID: big.NewInt(1337), Nonce: 2051, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2),
		Gas: 100_000, To: &to, Value: big.NewInt(1), Data: make([]byte, 128),
	})
	for _, test := range []struct {
		name  string
		tx    *types.Transaction
		index uint16
	}{
		{name: "legacy", tx: legacy},
		{name: "typed", tx: typed},
		{name: "one-byte index", tx: legacy, index: 128},
		{name: "large index", tx: legacy, index: 511},
	} {
		t.Run(test.name, func(t *testing.T) {
			want, err := rlp.EncodeToBytes(&txQUICItem{AdmissionIndex: test.index, Tx: test.tx})
			if err != nil {
				t.Fatal(err)
			}
			got, err := txQUICBridgeItemRawSize(test.tx, test.index)
			if err != nil {
				t.Fatal(err)
			}
			if got != int64(len(want)) {
				t.Fatalf("raw item size = %d, want canonical RLP size %d", got, len(want))
			}
		})
	}
}

func TestTxQUICPayloadFramingDeclaresBoundedLength(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, 4096)
	var framed bytes.Buffer
	if err := writeFullTxQUIC(&framed, payload); err != nil {
		t.Fatal(err)
	}
	size, err := readTxQUICPayloadSize(&framed, txQUICMicroBatchMaxWireBytes)
	if err != nil || size != int64(len(payload)) {
		t.Fatalf("framed payload size = %d err=%v", size, err)
	}
	decoded := make([]byte, size)
	if _, err := io.ReadFull(&framed, decoded); err != nil || !bytes.Equal(decoded, payload) {
		t.Fatalf("framed payload body mismatch: err=%v", err)
	}
	for _, declared := range []uint32{0, uint32(txQUICMicroBatchMaxWireBytes + 1)} {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], declared)
		if _, err := readTxQUICPayloadSize(bytes.NewReader(header[:]), txQUICMicroBatchMaxWireBytes); err == nil {
			t.Fatalf("invalid declared payload size %d was accepted", declared)
		}
	}
}

func TestTxQUICBridgeRawByteBackpressureReleasesCompletedRequests(t *testing.T) {
	config := testTxQUICConfig()
	config.BridgeEnabled = true
	tx0 := testTxQUICTransaction(2100, 4096)
	tx1 := testTxQUICTransaction(2101, 4096)
	results0 := testTxQUICAdmissionResults(t, config, tx0)
	results1 := testTxQUICAdmissionResults(t, config, tx1)
	requestBytes := func(tx *types.Transaction, result core.CommonRPCAdmissionResult) int64 {
		request, err := newTxQUICBridgeRequest(result.Batch, []txQUICBridgeItem{{tx: tx, admissionIndex: result.Item}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return request.rawBytes
	}
	bytes0, bytes1 := requestBytes(tx0, results0[0]), requestBytes(tx1, results1[0])
	config.BridgeQueueMaxBytes = bytes0
	if bytes1 > config.BridgeQueueMaxBytes {
		config.BridgeQueueMaxBytes = bytes1
	}

	q := NewTxQUICIngress(config, nil)
	q.SetDurableOutbox(NewTxOutbox(memorydb.New(), config), nil)
	q.bridgeAcceptMu.Lock()
	q.bridgeAccepting = true
	q.bridgeAcceptMu.Unlock()
	t.Cleanup(q.Stop)

	firstResult := make(chan error, 1)
	go func() {
		firstResult <- q.EnqueueLocalTxsWithAdmissions(context.Background(), []*types.Transaction{tx0}, results0, nil)
	}()
	request0 := <-q.durableQueue
	if got := q.pendingDurableBridgeBytes(); got != bytes0 {
		t.Fatalf("queued raw bytes = %d, want %d", got, bytes0)
	}

	blockedCtx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err := q.EnqueueLocalTxsWithAdmissions(blockedCtx, []*types.Transaction{tx1}, results1, nil)
	cancel()
	if err == nil || !strings.Contains(err.Error(), "byte capacity wait") {
		t.Fatalf("second bridge request capacity error = %v", err)
	}
	if got := q.pendingDurableBridgeBytes(); got != bytes0 {
		t.Fatalf("failed enqueue changed queued raw bytes to %d, want %d", got, bytes0)
	}

	q.finishDurableBridgeItems(request0.items, nil)
	if err := <-firstResult; err != nil {
		t.Fatalf("first bridge request failed: %v", err)
	}
	if got := q.pendingDurableBridgeBytes(); got != 0 {
		t.Fatalf("completed bridge request retained %d raw bytes", got)
	}

	secondResult := make(chan error, 1)
	go func() {
		secondResult <- q.EnqueueLocalTxsWithAdmissions(context.Background(), []*types.Transaction{tx1}, results1, nil)
	}()
	request1 := <-q.durableQueue
	if got := q.pendingDurableBridgeBytes(); got != bytes1 {
		t.Fatalf("reused raw-byte capacity = %d, want %d", got, bytes1)
	}
	q.finishDurableBridgeItems(request1.items, nil)
	if err := <-secondResult; err != nil {
		t.Fatalf("second bridge request failed after release: %v", err)
	}
}

func TestTxQUICBridgeRawByteReservationRollsBackOnQueueFailure(t *testing.T) {
	config := testTxQUICConfig()
	config.BridgeEnabled = true
	config.BridgeQueueSize = 1
	config.BridgeQueueMaxBytes = 1 << 20
	q := NewTxQUICIngress(config, nil)
	q.bridgeAcceptMu.Lock()
	q.bridgeAccepting = true
	q.bridgeAcceptMu.Unlock()
	defer q.Stop()

	// Fill only the request channel. Capacity acquisition for the real request
	// succeeds, then its canceled enqueue must roll back both dimensions.
	q.durableQueue <- &txQUICBridgeRequest{}
	tx := testTxQUICTransaction(2200, 1024)
	certificate := testTxQUICCertificate(t, config, tx)
	items := []txQUICBridgeItem{{tx: tx, admissionIndex: 0}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err := q.enqueueDurableBridgeRequest(ctx, certificate, items, nil)
	cancel()
	if err == nil || !strings.Contains(err.Error(), "bridge enqueue") {
		t.Fatalf("queue-capacity error = %v", err)
	}
	if got := q.pendingDurableBridgeBytes(); got != 0 {
		t.Fatalf("failed count reservation retained %d raw bytes", got)
	}
	if got := len(q.durableSlots); got != 0 {
		t.Fatalf("failed count reservation retained %d item slots", got)
	}
}

func TestTxQUICBridgeShutdownReleasesQueuedRawBytes(t *testing.T) {
	config := testTxQUICConfig()
	config.BridgeEnabled = true
	q := NewTxQUICIngress(config, nil)
	q.SetDurableOutbox(NewTxOutbox(memorydb.New(), config), nil)
	q.bridgeAcceptMu.Lock()
	q.bridgeAccepting = true
	q.bridgeAcceptMu.Unlock()

	result := make(chan error, 1)
	tx := testTxQUICTransaction(2300, 4096)
	admissions := testTxQUICAdmissionResults(t, config, tx)
	go func() {
		result <- q.EnqueueLocalTxsWithAdmissions(context.Background(), []*types.Transaction{
			tx,
		}, admissions, nil)
	}()
	select {
	case <-time.After(time.Second):
		t.Fatal("bridge request was not queued")
	case request := <-q.durableQueue:
		q.durableQueue <- request
	}
	if got := q.pendingDurableBridgeBytes(); got == 0 {
		t.Fatal("queued bridge request did not reserve raw bytes")
	}
	q.Stop()
	if err := <-result; err == nil || !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("shutdown bridge request error = %v", err)
	}
	if got := q.pendingDurableBridgeBytes(); got != 0 {
		t.Fatalf("shutdown retained %d queued raw bytes", got)
	}
	if got := len(q.durableSlots); got != 0 {
		t.Fatalf("shutdown retained %d item slots", got)
	}
}

func TestTxOutboxRestartRestoresByteCapacityAndAckReleasesIt(t *testing.T) {
	config := testTxQUICConfig()
	payload0 := testTxQUICBatchPayload(t, config, testTxQUICTransaction(2400, 4096))
	payload1 := testTxQUICBatchPayload(t, config, testTxQUICTransaction(2401, 4096))
	config.OutboxMaxBytes = int64(len(payload0)) + txOutboxPlacementReserveBytes
	if len(payload1) > len(payload0) {
		config.OutboxMaxBytes = int64(len(payload1)) + txOutboxPlacementReserveBytes
	}
	db := memorydb.New()

	first := NewTxOutbox(db, config)
	if err := first.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	batchID0, err := first.StoreSync(context.Background(), payload0)
	if err != nil {
		t.Fatal(err)
	}
	first.Stop()

	deliveryStarted := make(chan struct{})
	acknowledge := make(chan struct{})
	var startOnce sync.Once
	second := NewTxOutbox(db, config)
	if err := second.Start(context.Background(), func(ctx context.Context, payload []byte) error {
		if txOutboxBatchID(payload) == batchID0 {
			startOnce.Do(func() { close(deliveryStarted) })
			select {
			case <-acknowledge:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	defer second.Stop()
	if records, bytes := second.Pending(); records != 1 || bytes != int64(len(payload0))+txOutboxPlacementReserveBytes {
		t.Fatalf("restored outbox accounting = %d records/%d bytes, want 1/%d", records, bytes, int64(len(payload0))+txOutboxPlacementReserveBytes)
	}
	select {
	case <-deliveryStarted:
	case <-time.After(time.Second):
		t.Fatal("restored outbox batch was not dispatched")
	}

	stored := make(chan error, 1)
	go func() {
		_, err := second.StoreSync(context.Background(), payload1)
		stored <- err
	}()
	select {
	case err := <-stored:
		t.Fatalf("new outbox batch bypassed restored byte capacity: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(acknowledge)
	select {
	case err := <-stored:
		if err != nil {
			t.Fatalf("store after ACK release failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ACK did not release restored outbox byte capacity")
	}
	deadline := time.Now().Add(time.Second)
	for {
		records, bytes := second.Pending()
		if records == 1 && bytes == int64(len(payload1))+txOutboxPlacementReserveBytes {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("outbox accounting after ACK = %d records/%d bytes, want 1/%d", records, bytes, int64(len(payload1))+txOutboxPlacementReserveBytes)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTxQUICEndpointFromCommitteeAddressSupportsIPv6(t *testing.T) {
	endpoint, ok := txQUICEndpointFromCommitteeAddress("[2001:db8::10]:7102", 2000)
	if !ok || endpoint != "[2001:db8::10]:9102" {
		t.Fatalf("IPv6 committee endpoint = %q, accepted=%t", endpoint, ok)
	}
}

func testTxQUICFHSCommittee() params.GenesisCommittee {
	return params.GenesisCommittee{
		0: {Address: "127.0.0.1:7102", Public: "01"},
		1: {Address: "127.0.0.1:7104", Public: "02"},
		2: {Address: "127.0.0.1:7106", Public: "03"},
		3: {Address: "127.0.0.1:7108", Public: "04"},
	}
}

func TestApplyFixedCommitteeAutoRoleUsesDynamicFHSRouting(t *testing.T) {
	committee := testTxQUICFHSCommittee()
	commonNode := &params.ChainConfig{
		GenCommittee: committee, RnetPort: "7999", FixedCommittee: true, FairHotstuff: true,
	}
	commonConfig := TxQUICConfig{AutoRole: true, PortOffset: 2000}
	commonConfig.ApplyFixedCommitteeAutoRole(commonNode)
	if commonConfig.Enabled || !commonConfig.BridgeEnabled || commonConfig.HTTP3Enabled {
		t.Fatalf("common-node FHS role ingress/bridge/http3 = %t/%t/%t", commonConfig.Enabled, commonConfig.BridgeEnabled, commonConfig.HTTP3Enabled)
	}

	validator := &params.ChainConfig{
		GenCommittee: committee, RnetPort: "7104", FixedCommittee: true, FairHotstuff: true,
	}
	validatorConfig := TxQUICConfig{AutoRole: true, PortOffset: 2000}
	validatorConfig.ApplyFixedCommitteeAutoRole(validator)
	if !validatorConfig.Enabled || validatorConfig.BridgeEnabled || validatorConfig.HTTP3Enabled || validatorConfig.Port != 9104 {
		t.Fatalf("validator FHS role ingress/bridge/http3 = %t/%t/%t, port = %d", validatorConfig.Enabled, validatorConfig.BridgeEnabled, validatorConfig.HTTP3Enabled, validatorConfig.Port)
	}
}

func TestTxQUICFHSForwardEndpointsUseCanonicalCurrentCommittee(t *testing.T) {
	committeeHash := common.HexToHash("0x4567")
	committeePublicKeys := make([]string, 4)
	for index := range committeePublicKeys {
		secret := new(bls.SecretKey)
		secret.SetByCSPRNG()
		committeePublicKeys[index] = secret.GetPublicKey().SerializeToHexStr()
	}
	q := &TxQUICIngress{
		config: TxQUICConfig{
			PortOffset: 2000,
		},
		routeProvider: func() (TxQUICFHSRoute, error) {
			return TxQUICFHSRoute{
				ProposalView: 10, KeyNumber: 3, CommitteeHash: committeeHash,
				LeaderIndex: 1, LeaderAddress: "127.0.0.1:7104",
				CommitteeAddresses:  []string{"127.0.0.1:7102", "127.0.0.1:7104", "127.0.0.1:7106", "127.0.0.1:7108"},
				CommitteePublicKeys: committeePublicKeys,
			}, nil
		},
	}

	got, err := q.refreshFHSRouteCache()
	if err != nil {
		t.Fatal(err)
	}
	if got.ProposalView != 10 || got.KeyNumber != 3 || got.CommitteeHash != committeeHash || got.LeaderIndex != 1 || got.Endpoint != "127.0.0.1:9104" {
		t.Fatalf("cached canonical FHS route = %#v", got)
	}
	wantCommittee := []string{"127.0.0.1:9102", "127.0.0.1:9104", "127.0.0.1:9106", "127.0.0.1:9108"}
	if len(got.CommitteeEndpoints) != len(wantCommittee) || len(got.CommitteePublicKeys) != len(committeePublicKeys) {
		t.Fatalf("cached FHS committee endpoints/keys = %v/%d", got.CommitteeEndpoints, len(got.CommitteePublicKeys))
	}
	for index := range wantCommittee {
		if got.CommitteeEndpoints[index] != wantCommittee[index] {
			t.Fatalf("cached FHS committee endpoints = %v, want %v", got.CommitteeEndpoints, wantCommittee)
		}
		if !bytes.Equal(got.CommitteePublicKeys[index], common.FromHex(committeePublicKeys[index])) {
			t.Fatalf("cached FHS committee key %d does not match provider", index)
		}
	}
}

func TestTxQUICFHSRouteRefreshRemovesLateClientOutsideCurrentCommittee(t *testing.T) {
	committeePublicKeys := make([]string, 4)
	for index := range committeePublicKeys {
		secret := new(bls.SecretKey)
		secret.SetByCSPRNG()
		committeePublicKeys[index] = secret.GetPublicKey().SerializeToHexStr()
	}
	currentRoute := TxQUICFHSRoute{
		ProposalView:        10,
		KeyNumber:           3,
		CommitteeHash:       common.HexToHash("0x4567"),
		LeaderIndex:         0,
		LeaderAddress:       "127.0.0.1:7102",
		CommitteeAddresses:  []string{"127.0.0.1:7102", "127.0.0.1:7104", "127.0.0.1:7106", "127.0.0.1:7108"},
		CommitteePublicKeys: committeePublicKeys,
	}
	config := testTxQUICConfig()
	config.PortOffset = 2000
	q := &TxQUICIngress{
		config:        config,
		routeProvider: func() (TxQUICFHSRoute, error) { return currentRoute, nil },
	}
	if _, err := q.refreshFHSRouteCache(); err != nil {
		t.Fatal(err)
	}
	oldEndpoint := "127.0.0.1:9102"

	currentRoute.ProposalView++
	currentRoute.KeyNumber++
	currentRoute.CommitteeHash = common.HexToHash("0x89ab")
	currentRoute.LeaderAddress = "127.0.0.1:7202"
	currentRoute.CommitteeAddresses = []string{"127.0.0.1:7202", "127.0.0.1:7204", "127.0.0.1:7206", "127.0.0.1:7208"}
	if _, err := q.refreshFHSRouteCache(); err != nil {
		t.Fatal(err)
	}

	// Simulate a dial that won LoadOrStore immediately after the generation-change
	// cleanup completed. A same-generation refresh must close this late stale client.
	stale := &txQUICForwardClient{endpoint: oldEndpoint, receiptIdentity: txQUICReceiptIdentity(common.FromHex(committeePublicKeys[0]))}
	currentEndpoint := "127.0.0.1:9202"
	_, currentGeneration, err := txQUICTLSIdentityPayload(q.config, currentRoute.KeyNumber, currentRoute.CommitteeHash, currentEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	current := &txQUICForwardClient{endpoint: currentEndpoint, receiptIdentity: txQUICReceiptIdentity(common.FromHex(committeePublicKeys[0])), tlsGeneration: currentGeneration}
	q.forwardClients.Store(oldEndpoint, stale)
	q.forwardClients.Store(currentEndpoint, current)
	t.Cleanup(func() { q.closeForwardClientsOutside(txQUICFHSRouteCache{}) })

	if _, err := q.refreshFHSRouteCache(); err != nil {
		t.Fatal(err)
	}
	if _, exists := q.forwardClients.Load(oldEndpoint); exists || !stale.closed.Load() {
		t.Fatalf("late stale forward client survived same-generation refresh: exists=%t closed=%t", exists, stale.closed.Load())
	}
	if got, exists := q.forwardClients.Load(currentEndpoint); !exists || got != current || current.closed.Load() {
		t.Fatalf("current committee client was removed: exists=%t got=%p want=%p closed=%t", exists, got, current, current.closed.Load())
	}

	// Reusing an endpoint for a different consensus identity must also force a
	// new TLS connection. Otherwise the retired member can keep serving the
	// address while every receipt fails the new generation's BLS pin.
	replacementSecret := new(bls.SecretKey)
	replacementSecret.SetByCSPRNG()
	currentRoute.ProposalView++
	currentRoute.KeyNumber++
	currentRoute.CommitteeHash = common.HexToHash("0xcdef")
	currentRoute.CommitteePublicKeys = append([]string(nil), currentRoute.CommitteePublicKeys...)
	currentRoute.CommitteePublicKeys[0] = replacementSecret.GetPublicKey().SerializeToHexStr()
	if _, err := q.refreshFHSRouteCache(); err != nil {
		t.Fatal(err)
	}
	if _, exists := q.forwardClients.Load(currentEndpoint); exists || !current.closed.Load() {
		t.Fatalf("old consensus identity retained endpoint client: exists=%t closed=%t", exists, current.closed.Load())
	}
}

func TestTxQUICForwardClientKeysAreCanonical(t *testing.T) {
	secret := new(bls.SecretKey)
	secret.SetByCSPRNG()
	publicKey := secret.GetPublicKey().Serialize()
	identity := txQUICReceiptIdentity(publicKey)
	route := txQUICFHSRouteCache{
		KeyNumber:           1,
		CommitteeHash:       common.HexToHash("0x1234"),
		CommitteeEndpoints:  []string{"node.example:9102"},
		CommitteePublicKeys: [][]byte{publicKey},
	}

	config := testTxQUICConfig()
	_, generation, err := txQUICTLSIdentityPayload(config, route.KeyNumber, route.CommitteeHash, route.CommitteeEndpoints[0])
	if err != nil {
		t.Fatal(err)
	}
	q := &TxQUICIngress{config: config}
	nonCanonical := &txQUICForwardClient{endpoint: "NODE.EXAMPLE:9102", receiptIdentity: identity, tlsGeneration: generation}
	q.forwardClients.Store("NODE.EXAMPLE:9102", nonCanonical)
	q.closeForwardClientsOutside(route)
	if _, exists := q.forwardClients.Load("NODE.EXAMPLE:9102"); exists || !nonCanonical.closed.Load() {
		t.Fatalf("non-canonical endpoint key survived route sweep: exists=%t closed=%t", exists, nonCanonical.closed.Load())
	}

	canonical := &txQUICForwardClient{endpoint: "node.example:9102", receiptIdentity: identity, tlsGeneration: generation}
	q.forwardClients.Store("node.example:9102", canonical)
	q.closeForwardClientsOutside(route)
	if got, exists := q.forwardClients.Load("node.example:9102"); !exists || got != canonical || canonical.closed.Load() {
		t.Fatalf("canonical endpoint client was removed: exists=%t got=%p want=%p closed=%t", exists, got, canonical, canonical.closed.Load())
	}
	t.Cleanup(func() { q.closeForwardClientsOutside(txQUICFHSRouteCache{}) })
}

func TestTxQUICFHSRouteLagFailsClosedWithoutStaticFallback(t *testing.T) {
	q := &TxQUICIngress{
		routeProvider: func() (TxQUICFHSRoute, error) {
			return TxQUICFHSRoute{}, errors.New("canonical route is behind")
		},
	}

	got, routeErr := q.refreshFHSRouteCache()
	if routeErr == nil || !strings.Contains(routeErr.Error(), "canonical route is behind") {
		t.Fatalf("route error = %v", routeErr)
	}
	if got.Endpoint != "" || len(got.CommitteeEndpoints) != 0 || len(got.CommitteePublicKeys) != 0 {
		t.Fatalf("route lag populated a non-canonical fallback cache: %#v", got)
	}
	if cached := q.cachedFHSRoute(); cached.Endpoint != "" || len(cached.CommitteeEndpoints) != 0 || len(cached.CommitteePublicKeys) != 0 {
		t.Fatalf("route lag persisted a non-canonical fallback cache: %#v", cached)
	}
}
