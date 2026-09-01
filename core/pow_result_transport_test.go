package core

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/rlp"
)

func testPoWResultTLSIdentity(t *testing.T) (*powResultTLSIdentityProvider, []byte) {
	t.Helper()
	secret := new(bls.SecretKey)
	secret.SetByCSPRNG()
	public := secret.GetPublicKey()
	if public == nil {
		t.Fatal("failed to derive test PoW result BLS public key")
	}
	publicBytes := public.Serialize()
	identity := &powResultTLSIdentityProvider{
		publicKey: func() ([]byte, error) {
			return append([]byte(nil), publicBytes...), nil
		},
		generation: func() (common.Hash, error) {
			return common.HexToHash("0x01020304"), nil
		},
		signDigest: func(generation common.Hash, digest []byte) ([]byte, error) {
			if generation == (common.Hash{}) {
				return nil, errors.New("missing test PoW result TLS generation")
			}
			signature := secret.SignHash(digest)
			if signature == nil {
				return nil, errors.New("failed to sign test PoW result TLS digest")
			}
			return signature.Serialize(), nil
		},
	}
	return identity, append([]byte(nil), publicBytes...)
}

func testPoWResultPayload(t *testing.T, nonce uint64) ([]byte, *types.PoWResult) {
	t.Helper()
	result := &types.PoWResult{
		ParentHash: common.HexToHash("0x01020304"),
		Number:     12,
		TNumber:    34,
		Time:       1_800_000_000,
		IP:         []byte{127, 0, 0, 1},
		Port:       8998,
		PubKey:     "test-common-miner-public-key",
		Coinbase:   "0x1000000000000000000000000000000000000001",
		Nonce:      types.EncodeNonce(nonce),
		MixDigest:  common.HexToHash(fmt.Sprintf("0x%x", nonce+1)),
	}
	payload, err := rlp.EncodeToBytes(result)
	if err != nil {
		t.Fatal(err)
	}
	return payload, result
}

func testPoWResultValidator(t *testing.T, address string) *common.Cnode {
	t.Helper()
	secret := new(bls.SecretKey)
	secret.SetByCSPRNG()
	public := secret.GetPublicKey()
	if public == nil {
		t.Fatal("failed to derive test validator BLS public key")
	}
	return &common.Cnode{Address: address, Public: public.SerializeToHexStr()}
}

func testPoWResultContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func testStartPoWResultTransportServer(
	t *testing.T,
	identity *powResultTLSIdentityProvider,
	admit func(*types.PoWResult) error,
) *powResultTransportServer {
	t.Helper()
	server, err := startPoWResultTransportServer("127.0.0.1:0", identity, admit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.stop)
	return server
}

func testStopPoWResultTransportServer(t *testing.T, server *powResultTransportServer) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		server.stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PoW result transport server did not stop")
	}
}

func TestPoWResultTransportQUICAcknowledgesOnlyAfterAdmission(t *testing.T) {
	identity, publicKey := testPoWResultTLSIdentity(t)
	entered := make(chan *types.PoWResult, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAdmission := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseAdmission)
	server := testStartPoWResultTransportServer(t, identity, func(result *types.PoWResult) error {
		entered <- result
		<-release
		return nil
	})
	payload, expected := testPoWResultPayload(t, 1)
	ctx := testPoWResultContext(t)

	resultCh := make(chan error, 1)
	go func() {
		resultCh <- sendPoWResultQUIC(ctx, server.address(), publicKey, payload)
	}()

	select {
	case admitted := <-entered:
		if admitted.Number != expected.Number || admitted.Nonce != expected.Nonce {
			t.Fatalf("admitted PoW result = number %d nonce %d, want number %d nonce %d",
				admitted.Number, admitted.Nonce.Uint64(), expected.Number, expected.Nonce.Uint64())
		}
	case err := <-resultCh:
		t.Fatalf("QUIC delivery returned before admission began: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("QUIC delivery did not reach admission callback")
	}

	select {
	case err := <-resultCh:
		t.Fatalf("QUIC delivery returned before admission completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	releaseAdmission()
	select {
	case err := <-resultCh:
		if err != nil {
			t.Fatalf("accepted QUIC PoW result was not acknowledged: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("QUIC delivery did not receive its semantic ACK")
	}
}

func TestPoWResultTransportFallsBackToRealTLSTCP(t *testing.T) {
	identity, publicKey := testPoWResultTLSIdentity(t)
	var admitted atomic.Int32
	server := testStartPoWResultTransportServer(t, identity, func(*types.PoWResult) error {
		admitted.Add(1)
		return nil
	})
	payload, _ := testPoWResultPayload(t, 2)
	var quicAttempts atomic.Int32
	client := powResultTransportClient{
		quicSend: func(context.Context, string, []byte, []byte) error {
			quicAttempts.Add(1)
			return errors.New("forced QUIC outage")
		},
		tcpSend: sendPoWResultTCP,
	}

	transport, err := client.send(testPoWResultContext(t), server.address(), publicKey, payload)
	if err != nil {
		t.Fatalf("TLS/TCP fallback failed: %v", err)
	}
	if transport != "tcp" {
		t.Fatalf("delivery transport = %q, want tcp", transport)
	}
	if quicAttempts.Load() != 1 || admitted.Load() != 1 {
		t.Fatalf("delivery attempts/admissions = quic %d admitted %d, want 1/1", quicAttempts.Load(), admitted.Load())
	}
}

func TestPoWResultTransportSemanticNACKDoesNotFallback(t *testing.T) {
	identity, publicKey := testPoWResultTLSIdentity(t)
	wantReject := errors.New("test validator rejected candidate")
	server := testStartPoWResultTransportServer(t, identity, func(*types.PoWResult) error {
		return wantReject
	})
	payload, _ := testPoWResultPayload(t, 3)
	var tcpAttempts atomic.Int32
	client := powResultTransportClient{
		quicSend: sendPoWResultQUIC,
		tcpSend: func(context.Context, string, []byte, []byte) error {
			tcpAttempts.Add(1)
			return nil
		},
	}

	transport, err := client.send(testPoWResultContext(t), server.address(), publicKey, payload)
	if transport != "quic" {
		t.Fatalf("rejected delivery transport = %q, want quic", transport)
	}
	var remote *powResultRemoteError
	if !errors.As(err, &remote) {
		t.Fatalf("semantic NACK error = %T %v, want *powResultRemoteError", err, err)
	}
	if remote.Code != 1 || !strings.Contains(remote.Reason, wantReject.Error()) {
		t.Fatalf("semantic NACK = code %d reason %q", remote.Code, remote.Reason)
	}
	if tcpAttempts.Load() != 0 {
		t.Fatalf("semantic NACK triggered %d TCP fallback attempts", tcpAttempts.Load())
	}
}

func TestPoWResultTransportEncodesReceiverBehindNACK(t *testing.T) {
	identity, publicKey := testPoWResultTLSIdentity(t)
	server := testStartPoWResultTransportServer(t, identity, func(*types.PoWResult) error {
		return &powResultRetryableAdmissionError{err: types.ErrUnknownAncestor}
	})
	payload, _ := testPoWResultPayload(t, 15)
	err := sendPoWResultQUIC(testPoWResultContext(t), server.address(), publicKey, payload)
	var remote *powResultRemoteError
	if !errors.As(err, &remote) || !remote.retryable() {
		t.Fatalf("receiver-behind ACK error = %T %v, want retryable remote rejection", err, err)
	}
}

func TestPoWResultTransportMissingACKIsFailure(t *testing.T) {
	identity, publicKey := testPoWResultTLSIdentity(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	requestRead := make(chan error, 1)
	go func() {
		raw, acceptErr := listener.Accept()
		if acceptErr != nil {
			requestRead <- acceptErr
			return
		}
		defer raw.Close()
		conn := tls.Server(raw, identity.serverTLSConfig())
		if handshakeErr := conn.Handshake(); handshakeErr != nil {
			requestRead <- handshakeErr
			return
		}
		_, readErr := readPoWResultFrame(conn, powResultRequestMagic, powResultTransportMaxPacketSize)
		requestRead <- readErr
		// Close without an ACK. A completed TLS write must not count as delivery.
	}()
	payload, _ := testPoWResultPayload(t, 4)
	client := powResultTransportClient{
		quicSend: func(context.Context, string, []byte, []byte) error {
			return errors.New("forced QUIC outage")
		},
		tcpSend: sendPoWResultTCP,
	}

	transport, sendErr := client.send(testPoWResultContext(t), listener.Addr().String(), publicKey, payload)
	if sendErr == nil {
		t.Fatal("delivery without a semantic ACK reported success")
	}
	if transport != "" {
		t.Fatalf("delivery without an ACK reported transport %q", transport)
	}
	select {
	case readErr := <-requestRead:
		if readErr != nil {
			t.Fatalf("no-ACK server did not receive the complete request: %v", readErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no-ACK server did not receive the request")
	}
}

func TestPoWResultTransportDuplicateACKIsSuccess(t *testing.T) {
	identity, publicKey := testPoWResultTLSIdentity(t)
	var admitted atomic.Int32
	server := testStartPoWResultTransportServer(t, identity, func(*types.PoWResult) error {
		admitted.Add(1)
		return ErrCandidateExisted
	})
	payload, _ := testPoWResultPayload(t, 5)

	if err := sendPoWResultQUIC(testPoWResultContext(t), server.address(), publicKey, payload); err != nil {
		t.Fatalf("duplicate PoW result ACK was not treated as success: %v", err)
	}
	if admitted.Load() != 1 {
		t.Fatalf("duplicate PoW result admission calls = %d, want 1", admitted.Load())
	}
}

func TestPoWResultTransportStopAllowsSamePortRebind(t *testing.T) {
	identity, publicKey := testPoWResultTLSIdentity(t)
	server := testStartPoWResultTransportServer(t, identity, func(*types.PoWResult) error { return nil })
	address := server.address()
	payload, _ := testPoWResultPayload(t, 6)
	if err := sendPoWResultQUIC(testPoWResultContext(t), address, publicKey, payload); err != nil {
		t.Fatalf("initial QUIC delivery failed: %v", err)
	}

	testStopPoWResultTransportServer(t, server)
	testStopPoWResultTransportServer(t, server)

	restarted, err := startPoWResultTransportServer(address, identity, func(*types.PoWResult) error { return nil })
	if err != nil {
		t.Fatalf("same-port PoW result transport restart failed: %v", err)
	}
	t.Cleanup(restarted.stop)
	if err := sendPoWResultTCP(testPoWResultContext(t), restarted.address(), publicKey, payload); err != nil {
		t.Fatalf("TLS/TCP delivery after same-port restart failed: %v", err)
	}
}

func TestPoWResultTransportRejectsBLSCertificateMismatch(t *testing.T) {
	identity, _ := testPoWResultTLSIdentity(t)
	_, wrongPublicKey := testPoWResultTLSIdentity(t)
	var admitted atomic.Int32
	server := testStartPoWResultTransportServer(t, identity, func(*types.PoWResult) error {
		admitted.Add(1)
		return nil
	})
	payload, _ := testPoWResultPayload(t, 7)

	tests := []struct {
		name string
		send powResultSendFunc
	}{
		{name: "quic", send: sendPoWResultQUIC},
		{name: "tls-tcp", send: sendPoWResultTCP},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.send(testPoWResultContext(t), server.address(), wrongPublicKey, payload); err == nil {
				t.Fatal("PoW result transport accepted a mismatched validator BLS certificate")
			}
		})
	}
	if admitted.Load() != 0 {
		t.Fatalf("BLS certificate mismatch reached admission %d times", admitted.Load())
	}
}

func TestPoWResultTransportPinsKeyBlockGeneration(t *testing.T) {
	identity, publicKey := testPoWResultTLSIdentity(t)
	firstGeneration := common.HexToHash("0x01020304")
	secondGeneration := common.HexToHash("0x05060708")
	var generationMu sync.RWMutex
	generation := firstGeneration
	identity.generation = func() (common.Hash, error) {
		generationMu.RLock()
		defer generationMu.RUnlock()
		return generation, nil
	}
	originalSigner := identity.signDigest
	identity.signDigest = func(keyHash common.Hash, digest []byte) ([]byte, error) {
		generationMu.RLock()
		current := generation
		generationMu.RUnlock()
		if keyHash != current {
			return nil, errors.New("test PoW result generation changed while signing")
		}
		return originalSigner(keyHash, digest)
	}
	var admissions atomic.Int32
	server := testStartPoWResultTransportServer(t, identity, func(*types.PoWResult) error {
		admissions.Add(1)
		return nil
	})
	firstPayload, _ := testPoWResultPayload(t, 16)
	if err := sendPoWResultQUIC(testPoWResultContext(t), server.address(), publicKey, firstPayload); err != nil {
		t.Fatalf("first-generation delivery failed: %v", err)
	}

	generationMu.Lock()
	generation = secondGeneration
	generationMu.Unlock()
	if err := sendPoWResultQUIC(testPoWResultContext(t), server.address(), publicKey, firstPayload); err == nil {
		t.Fatal("stale keyblock generation reused the cached TLS certificate")
	}
	_, secondResult := testPoWResultPayload(t, 17)
	secondResult.ParentHash = secondGeneration
	secondPayload, err := rlp.EncodeToBytes(secondResult)
	if err != nil {
		t.Fatal(err)
	}
	if err := sendPoWResultQUIC(testPoWResultContext(t), server.address(), publicKey, secondPayload); err != nil {
		t.Fatalf("second-generation delivery failed: %v", err)
	}
	if admissions.Load() != 2 {
		t.Fatalf("generation-pinned admissions = %d, want 2", admissions.Load())
	}
}

func TestPoWResultTransportConcurrentQUICAndTCP(t *testing.T) {
	identity, publicKey := testPoWResultTLSIdentity(t)
	const deliveries = 8 // Four TCP streams stay within the per-source bound.
	seen := make(map[uint64]int, deliveries)
	var seenMu sync.Mutex
	server := testStartPoWResultTransportServer(t, identity, func(result *types.PoWResult) error {
		seenMu.Lock()
		seen[result.Nonce.Uint64()]++
		seenMu.Unlock()
		return nil
	})

	ctx := testPoWResultContext(t)
	errs := make(chan error, deliveries)
	for index := 0; index < deliveries; index++ {
		index := index
		go func() {
			payload, err := rlp.EncodeToBytes(&types.PoWResult{
				ParentHash: common.HexToHash("0x01020304"),
				Number:     12,
				TNumber:    34,
				Time:       1_800_000_000,
				Nonce:      types.EncodeNonce(uint64(index + 1)),
			})
			if err != nil {
				errs <- err
				return
			}
			if index%2 == 0 {
				errs <- sendPoWResultQUIC(ctx, server.address(), publicKey, payload)
				return
			}
			errs <- sendPoWResultTCP(ctx, server.address(), publicKey, payload)
		}()
	}
	for index := 0; index < deliveries; index++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent PoW result delivery failed: %v", err)
		}
	}

	seenMu.Lock()
	defer seenMu.Unlock()
	if len(seen) != deliveries {
		t.Fatalf("concurrent admission received %d unique results, want %d", len(seen), deliveries)
	}
	for nonce := uint64(1); nonce <= deliveries; nonce++ {
		if seen[nonce] != 1 {
			t.Fatalf("concurrent admission count for nonce %d = %d, want 1", nonce, seen[nonce])
		}
	}
}

func TestPoWResultTransportSlowTCPDoesNotExhaustQUIC(t *testing.T) {
	identity, publicKey := testPoWResultTLSIdentity(t)
	entered := make(chan struct{}, powResultMaxTCPConnectionsPerIP)
	release := make(chan struct{})
	var releaseOnce sync.Once
	var slowAdmissions atomic.Int32
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	server := testStartPoWResultTransportServer(t, identity, func(result *types.PoWResult) error {
		if result.Nonce.Uint64() < 100 {
			slowAdmissions.Add(1)
			entered <- struct{}{}
			<-release
		}
		return nil
	})

	tcpResults := make(chan error, powResultMaxTCPConnectionsPerIP)
	for index := 0; index < powResultMaxTCPConnectionsPerIP; index++ {
		payload, _ := testPoWResultPayload(t, uint64(20+index))
		go func(payload []byte) {
			tcpResults <- sendPoWResultTCP(testPoWResultContext(t), server.address(), publicKey, payload)
		}(payload)
	}
	for index := 0; index < powResultMaxTCPConnectionsPerIP; index++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("slow TCP connection did not occupy its bounded source slot")
		}
	}

	overflowPayload, _ := testPoWResultPayload(t, 30)
	if err := sendPoWResultTCP(testPoWResultContext(t), server.address(), publicKey, overflowPayload); err == nil {
		t.Fatal("per-source TCP overflow connection was accepted")
	}
	if slowAdmissions.Load() != powResultMaxTCPConnectionsPerIP {
		t.Fatalf("slow TCP admissions = %d, want %d", slowAdmissions.Load(), powResultMaxTCPConnectionsPerIP)
	}
	quicPayload, _ := testPoWResultPayload(t, 100)
	if err := sendPoWResultQUIC(testPoWResultContext(t), server.address(), publicKey, quicPayload); err != nil {
		t.Fatalf("bounded slow TCP clients exhausted QUIC admission: %v", err)
	}

	releaseOnce.Do(func() { close(release) })
	for index := 0; index < powResultMaxTCPConnectionsPerIP; index++ {
		if err := <-tcpResults; err != nil {
			t.Fatalf("admitted TCP delivery failed after release: %v", err)
		}
	}
}

func TestPoWResultTransportBroadcastRequiresEveryValidatorACK(t *testing.T) {
	validators := []*common.Cnode{
		testPoWResultValidator(t, "192.0.2.10:7102"),
		testPoWResultValidator(t, "192.0.2.11:7202"),
	}
	_, result := testPoWResultPayload(t, 8)
	wantFailure := errors.New("test validator unavailable")
	var quicAttempts atomic.Int32
	var tcpAttempts atomic.Int32
	client := powResultTransportClient{
		quicSend: func(_ context.Context, endpoint string, _ []byte, _ []byte) error {
			quicAttempts.Add(1)
			if endpoint == "192.0.2.10:7103" {
				return nil
			}
			return wantFailure
		},
		tcpSend: func(context.Context, string, []byte, []byte) error {
			tcpAttempts.Add(1)
			return wantFailure
		},
	}

	err := broadcastPoWResultWithClient(context.Background(), client, "7000", validators, result)
	var delivery *PoWResultDeliveryError
	if !errors.As(err, &delivery) {
		t.Fatalf("partial committee delivery error = %T %v, want *PoWResultDeliveryError", err, err)
	}
	if delivery.Acknowledged != 1 || delivery.Total != 2 {
		t.Fatalf("partial committee delivery = %d/%d, want 1/2", delivery.Acknowledged, delivery.Total)
	}
	if quicAttempts.Load() != 2 || tcpAttempts.Load() != 1 {
		t.Fatalf("partial committee attempts = QUIC %d TCP %d, want 2/1", quicAttempts.Load(), tcpAttempts.Load())
	}
}

func TestPoWResultTransportBroadcastRejectsEmptyCommittee(t *testing.T) {
	_, result := testPoWResultPayload(t, 9)
	err := broadcastPoWResultWithClient(context.Background(), powResultTransportClient{}, "7000", nil, result)
	if err == nil || !strings.Contains(err.Error(), "no fixed-mode PoW result validators") {
		t.Fatalf("empty committee delivery error = %v", err)
	}
}

func TestPoWResultTransportBroadcastDeduplicatesWithoutImplicitLocalhost(t *testing.T) {
	first := testPoWResultValidator(t, "192.0.2.20:7102")
	second := testPoWResultValidator(t, "192.0.2.21:7202")
	validators := []*common.Cnode{
		first,
		{Address: first.Address, Public: first.Public},
		second,
	}
	_, result := testPoWResultPayload(t, 10)
	seen := make(map[string]int)
	var seenMu sync.Mutex
	client := powResultTransportClient{
		quicSend: func(_ context.Context, endpoint string, _ []byte, _ []byte) error {
			seenMu.Lock()
			seen[endpoint]++
			seenMu.Unlock()
			return nil
		},
		tcpSend: func(context.Context, string, []byte, []byte) error {
			return errors.New("unexpected TCP fallback")
		},
	}

	if err := broadcastPoWResultWithClient(context.Background(), client, "7000", validators, result); err != nil {
		t.Fatalf("deduplicated committee delivery failed: %v", err)
	}
	seenMu.Lock()
	defer seenMu.Unlock()
	want := map[string]int{"192.0.2.20:7103": 1, "192.0.2.21:7203": 1}
	if len(seen) != len(want) {
		t.Fatalf("broadcast endpoints = %v, want %v", seen, want)
	}
	for endpoint, count := range want {
		if seen[endpoint] != count {
			t.Fatalf("broadcast endpoint %s attempts = %d, want %d", endpoint, seen[endpoint], count)
		}
	}
	for endpoint := range seen {
		host, _, err := net.SplitHostPort(endpoint)
		if err != nil {
			t.Fatalf("invalid broadcast endpoint %q: %v", endpoint, err)
		}
		if net.ParseIP(host).IsLoopback() {
			t.Fatalf("broadcast added implicit localhost endpoint %q", endpoint)
		}
	}
}

func TestPoWResultTransportRetryTargetsOnlyUnacknowledgedValidators(t *testing.T) {
	validators := []*common.Cnode{
		testPoWResultValidator(t, "192.0.2.30:7102"),
		testPoWResultValidator(t, "192.0.2.31:7202"),
	}
	_, result := testPoWResultPayload(t, 11)
	var mu sync.Mutex
	quicAttempts := make(map[string]int)
	tcpAttempts := make(map[string]int)
	client := powResultTransportClient{
		quicSend: func(_ context.Context, endpoint string, _ []byte, _ []byte) error {
			mu.Lock()
			defer mu.Unlock()
			quicAttempts[endpoint]++
			if endpoint == "192.0.2.31:7203" && quicAttempts[endpoint] == 1 {
				return errors.New("transient QUIC failure")
			}
			return nil
		},
		tcpSend: func(_ context.Context, endpoint string, _ []byte, _ []byte) error {
			mu.Lock()
			defer mu.Unlock()
			tcpAttempts[endpoint]++
			return errors.New("transient TLS/TCP failure")
		},
	}

	if err := broadcastPoWResultWithRetryClient(client, "7000", validators, result); err != nil {
		t.Fatalf("retry delivery failed: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if quicAttempts["192.0.2.30:7103"] != 1 {
		t.Fatalf("already-ACKed validator QUIC attempts = %d, want 1", quicAttempts["192.0.2.30:7103"])
	}
	if quicAttempts["192.0.2.31:7203"] != 2 || tcpAttempts["192.0.2.31:7203"] != 1 {
		t.Fatalf("unacknowledged validator attempts = QUIC %d TCP %d, want 2/1",
			quicAttempts["192.0.2.31:7203"], tcpAttempts["192.0.2.31:7203"])
	}
}

func TestPoWResultTransportRetryStopsOnSemanticNACK(t *testing.T) {
	validators := []*common.Cnode{testPoWResultValidator(t, "192.0.2.40:7102")}
	_, result := testPoWResultPayload(t, 12)
	var quicAttempts atomic.Int32
	var tcpAttempts atomic.Int32
	client := powResultTransportClient{
		quicSend: func(context.Context, string, []byte, []byte) error {
			quicAttempts.Add(1)
			return &powResultRemoteError{Code: 1, Reason: "invalid candidate"}
		},
		tcpSend: func(context.Context, string, []byte, []byte) error {
			tcpAttempts.Add(1)
			return nil
		},
	}

	err := broadcastPoWResultWithRetryClient(client, "7000", validators, result)
	var delivery *PoWResultDeliveryError
	if !errors.As(err, &delivery) {
		t.Fatalf("semantic rejection error = %T %v, want *PoWResultDeliveryError", err, err)
	}
	if quicAttempts.Load() != 1 || tcpAttempts.Load() != 0 {
		t.Fatalf("semantic rejection attempts = QUIC %d TCP %d, want 1/0", quicAttempts.Load(), tcpAttempts.Load())
	}
}

func TestPoWResultTransportRetryContinuesOnReceiverBehindNACK(t *testing.T) {
	validators := []*common.Cnode{testPoWResultValidator(t, "192.0.2.45:7102")}
	_, result := testPoWResultPayload(t, 14)
	var quicAttempts atomic.Int32
	var tcpAttempts atomic.Int32
	client := powResultTransportClient{
		quicSend: func(context.Context, string, []byte, []byte) error {
			if quicAttempts.Add(1) == 1 {
				return &powResultRemoteError{Code: powResultAckCodeReceiverBehind, Reason: "receiver is syncing"}
			}
			return nil
		},
		tcpSend: func(context.Context, string, []byte, []byte) error {
			tcpAttempts.Add(1)
			return nil
		},
	}

	if err := broadcastPoWResultWithRetryClient(client, "7000", validators, result); err != nil {
		t.Fatalf("receiver-behind retry failed: %v", err)
	}
	if quicAttempts.Load() != 2 || tcpAttempts.Load() != 0 {
		t.Fatalf("receiver-behind attempts = QUIC %d TCP %d, want 2/0", quicAttempts.Load(), tcpAttempts.Load())
	}
}

func TestPoWResultTransportPendingRetryStopsOnContextCancellation(t *testing.T) {
	validators := []*common.Cnode{testPoWResultValidator(t, "192.0.2.50:7102")}
	_, result := testPoWResultPayload(t, 13)
	firstRound := make(chan struct{})
	var once sync.Once
	client := powResultTransportClient{
		quicSend: func(context.Context, string, []byte, []byte) error {
			return errors.New("transient QUIC failure")
		},
		tcpSend: func(context.Context, string, []byte, []byte) error {
			once.Do(func() { close(firstRound) })
			return errors.New("transient TLS/TCP failure")
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	resultCh := make(chan error, 1)
	go func() {
		resultCh <- broadcastPoWResultUntilAcknowledged(ctx, client, "7000", validators, result, 0)
	}()
	select {
	case <-firstRound:
	case <-time.After(2 * time.Second):
		t.Fatal("pending delivery did not complete its first transport round")
	}
	cancel()
	select {
	case err := <-resultCh:
		if err == nil {
			t.Fatal("cancelled pending delivery reported success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending delivery did not stop after context cancellation")
	}
}
