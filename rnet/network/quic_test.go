package network

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/cypherium/cypher/crypto/bls"
	quic "github.com/quic-go/quic-go"
)

type quicClassifiedTestMessage struct {
	Class uint32
	Value uint32
}

type authenticatedQUICStub struct {
	peerAddress string
	peerKey     []byte
	closed      bool
	sendErr     error
	sendBytes   uint64
	sendCount   int
}

func (stub *authenticatedQUICStub) Send(Message) (uint64, error) {
	stub.sendCount++
	return stub.sendBytes, stub.sendErr
}
func (stub *authenticatedQUICStub) Receive() (*Envelope, error) { return nil, errors.New("unused") }
func (stub *authenticatedQUICStub) Close() error                { stub.closed = true; return nil }
func (stub *authenticatedQUICStub) IsClosed() bool              { return stub.closed }
func (stub *authenticatedQUICStub) Type() ConnType              { return PlainQUIC }
func (stub *authenticatedQUICStub) Remote() Address             { return NewQUICAddress(stub.peerAddress) }
func (stub *authenticatedQUICStub) Local() Address              { return NewQUICAddress("127.0.0.1:7101") }
func (stub *authenticatedQUICStub) Tx() uint64                  { return 0 }
func (stub *authenticatedQUICStub) Rx() uint64                  { return 0 }
func (stub *authenticatedQUICStub) AuthenticatedPeer() (string, []byte, bool) {
	return stub.peerAddress, append([]byte(nil), stub.peerKey...), true
}

func (m *quicClassifiedTestMessage) NetworkClass() uint8 {
	return uint8(m.Class)
}

func TestQUICControlBypassesStalledStream(t *testing.T) {
	RegisterMessage(&quicClassifiedTestMessage{})

	listener, err := NewQUICListener(NewQUICAddress("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Stop()
	const chainID = uint64(10101919)
	_, listenerPort, err := net.SplitHostPort(listener.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	serverAddress := net.JoinHostPort("127.0.0.1", listenerPort)
	serverSecret, serverPublic := newQUICAuthTestKey(t)
	clientSecret, clientPublic := newQUICAuthTestKey(t)
	clientAddress := "127.0.0.1:7103"
	peers := map[string][]byte{serverAddress: serverPublic.Serialize(), clientAddress: clientPublic.Serialize()}
	if err := listener.ConfigurePeerAuthentication(chainID, serverAddress, serverSecret.SerializeToHexStr(), serverPublic.SerializeToHexStr(), peers); err != nil {
		t.Fatal(err)
	}

	accepted := make(chan Conn, 1)
	go func() {
		_ = listener.Listen(func(conn Conn) {
			accepted <- conn
		})
	}()

	clientAuth := newQUICPeerAuthenticator()
	if err := clientAuth.configure(chainID, clientAddress, clientSecret.SerializeToHexStr(), clientPublic.SerializeToHexStr(), peers); err != nil {
		t.Fatal(err)
	}
	serverIdentity := NewServerIdentityWithTransport(serverAddress, PlainQUIC)
	serverIdentity.PublicKey = serverPublic.Serialize()
	client, err := newAuthenticatedQUICConn(serverIdentity, clientAuth)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server Conn
	select {
	case server = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for QUIC connection")
	}
	defer server.Close()

	identity := NewServerIdentityWithTransport(clientAddress, PlainQUIC)
	identity.PublicKey = clientPublic.Serialize()
	if _, err := client.Send(identity); err != nil {
		t.Fatal(err)
	}
	if env, err := receiveQUICForTest(server, 2*time.Second); err != nil {
		t.Fatal(err)
	} else if env.MsgType != ServerIdentityType {
		t.Fatalf("first message type = %v, want ServerIdentity", env.MsgType)
	}

	stalled, err := client.conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.CancelWrite(0)
	if _, err := stalled.Write(encodePacketHeader(1024)); err != nil {
		t.Fatal(err)
	}

	control := &quicClassifiedTestMessage{
		Class: uint32(NetClassHotstuffControl),
		Value: 42,
	}
	if _, err := client.Send(control); err != nil {
		t.Fatal(err)
	}

	env, err := receiveQUICForTest(server, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	msg, ok := env.Msg.(*quicClassifiedTestMessage)
	if !ok {
		t.Fatalf("message type = %T, want *quicClassifiedTestMessage", env.Msg)
	}
	if msg.Value != control.Value {
		t.Fatalf("message value = %d, want %d", msg.Value, control.Value)
	}

	// The connector sends ServerIdentity but does not receive one back. Its first
	// inbound stream is therefore an ordinary message, not another handshake.
	reverse := &quicClassifiedTestMessage{Class: uint32(NetClassHotstuffControl), Value: 84}
	if _, err := server.Send(reverse); err != nil {
		t.Fatal(err)
	}
	reverseEnvelope, err := receiveQUICForTest(client, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	reverseMessage, ok := reverseEnvelope.Msg.(*quicClassifiedTestMessage)
	if !ok || reverseMessage.Value != reverse.Value {
		t.Fatalf("reverse message = %#v, want value %d", reverseEnvelope.Msg, reverse.Value)
	}
}

func TestQUICHandshakeGateBoundsGlobalAndPerSourceWork(t *testing.T) {
	gate := newQUICHandshakeGate(2, 1)
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	if _, err := gate.acquire(ctxA, &quic.ClientInfo{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1001}}); err != nil {
		t.Fatal(err)
	}
	ctxSame, cancelSame := context.WithCancel(context.Background())
	defer cancelSame()
	if _, err := gate.acquire(ctxSame, &quic.ClientInfo{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1002}}); err == nil {
		t.Fatal("same source exceeded pending-handshake quota")
	}
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	if _, err := gate.acquire(ctxB, &quic.ClientInfo{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1003}}); err != nil {
		t.Fatal(err)
	}
	ctxC, cancelC := context.WithCancel(context.Background())
	defer cancelC()
	if _, err := gate.acquire(ctxC, &quic.ClientInfo{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.3"), Port: 1004}}); err == nil {
		t.Fatal("global pending-handshake quota was exceeded")
	}

	cancelA()
	deadline := time.Now().Add(time.Second)
	for {
		gate.mu.Lock()
		total := gate.total
		_, sourceHeld := gate.bySource["192.0.2.1"]
		gate.mu.Unlock()
		if total == 1 && !sourceHeld {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("canceled handshake did not release its gate slot")
		}
		time.Sleep(time.Millisecond)
	}
	ctxRetry, cancelRetry := context.WithCancel(context.Background())
	defer cancelRetry()
	if _, err := gate.acquire(ctxRetry, &quic.ClientInfo{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1005}}); err != nil {
		t.Fatalf("released source slot was not reusable: %v", err)
	}
}

func TestQUICTransportUsesShortHandshakeTimeout(t *testing.T) {
	config := quicTransportConfig()
	if config.HandshakeIdleTimeout != quicHandshakeIdleTimeout || config.HandshakeIdleTimeout > 5*time.Second {
		t.Fatalf("handshake idle timeout = %v", config.HandshakeIdleTimeout)
	}
}

func TestQUICHandshakeGateReleasesImmediatelyAfterAccept(t *testing.T) {
	gate := newQUICHandshakeGate(1, 1)
	base, cancel := context.WithCancel(context.Background())
	leased, err := gate.acquire(base, &quic.ClientInfo{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: 1001}})
	if err != nil {
		t.Fatal(err)
	}
	lease, ok := leased.Value(quicHandshakeLeaseContextKey{}).(*quicHandshakeLease)
	if !ok {
		t.Fatal("handshake lease was not stored in the connection context")
	}
	releaseQUICHandshakeLease(leased)
	select {
	case <-lease.done:
	default:
		t.Fatal("accepted handshake did not stop its watchdog")
	}
	gate.mu.Lock()
	if gate.total != 0 || len(gate.bySource) != 0 {
		t.Fatalf("accepted handshake retained gate slot: total=%d sources=%d", gate.total, len(gate.bySource))
	}
	gate.mu.Unlock()

	// A later connection close races with neither accounting nor underflow.
	cancel()
	time.Sleep(time.Millisecond)
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.total != 0 || len(gate.bySource) != 0 {
		t.Fatalf("double release corrupted handshake accounting: total=%d sources=%d", gate.total, len(gate.bySource))
	}
}

func newQUICAuthTestKey(t *testing.T) (*bls.SecretKey, *bls.PublicKey) {
	t.Helper()
	secret := new(bls.SecretKey)
	secret.SetByCSPRNG()
	public := secret.GetPublicKey()
	if public == nil {
		t.Fatal("failed to derive BLS public key")
	}
	return secret, public
}

func TestQUICPeerAttestationPinsChainAddressAndBLSKey(t *testing.T) {
	const chainID = uint64(10101919)
	secret, public := newQUICAuthTestKey(t)
	certificate, err := generateAttestedQUICCertificate(chainID, "127.0.0.1:7102", secret, public.Serialize())
	if err != nil {
		t.Fatal(err)
	}
	raw := certificate.Certificate
	if _, err := parseAndVerifyQUICPeerCertificate(raw, chainID, "127.0.0.1:7102", public.Serialize()); err != nil {
		t.Fatalf("valid attestation rejected: %v", err)
	}
	if _, err := parseAndVerifyQUICPeerCertificate(raw, chainID+1, "127.0.0.1:7102", public.Serialize()); err == nil {
		t.Fatal("cross-chain QUIC attestation accepted")
	}
	if _, err := parseAndVerifyQUICPeerCertificate(raw, chainID, "127.0.0.1:9999", public.Serialize()); err == nil {
		t.Fatal("wrong-address QUIC attestation accepted")
	}
	_, otherPublic := newQUICAuthTestKey(t)
	if _, err := parseAndVerifyQUICPeerCertificate(raw, chainID, "127.0.0.1:7102", otherPublic.Serialize()); err == nil {
		t.Fatal("wrong-key QUIC attestation accepted")
	}
}

func TestBLSTLSCertificatePinsApplicationIdentityAndKey(t *testing.T) {
	secret, public := newQUICAuthTestKey(t)
	identity := []byte("chain/genesis/committee/endpoint")
	certificate, err := GenerateBLSTLSCertificate("txquic", identity, public.Serialize(), func(digest []byte) ([]byte, error) {
		return secret.SignHash(digest).Serialize(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBLSTLSCertificate(certificate.Certificate, "txquic", identity, public.Serialize()); err != nil {
		t.Fatalf("valid BLS TLS certificate rejected: %v", err)
	}
	if err := VerifyBLSTLSCertificate(certificate.Certificate, "other", identity, public.Serialize()); err == nil {
		t.Fatal("cross-application BLS TLS certificate accepted")
	}
	if err := VerifyBLSTLSCertificate(certificate.Certificate, "txquic", []byte("other identity"), public.Serialize()); err == nil {
		t.Fatal("wrong BLS TLS identity accepted")
	}
	_, otherPublic := newQUICAuthTestKey(t)
	if err := VerifyBLSTLSCertificate(certificate.Certificate, "txquic", identity, otherPublic.Serialize()); err == nil {
		t.Fatal("wrong BLS TLS public key accepted")
	}
}

func TestBLSTLSCertificateRejectsInvalidSigner(t *testing.T) {
	_, public := newQUICAuthTestKey(t)
	otherSecret, _ := newQUICAuthTestKey(t)
	if _, err := GenerateBLSTLSCertificate("txquic", []byte("identity"), public.Serialize(), func(digest []byte) ([]byte, error) {
		return otherSecret.SignHash(digest).Serialize(), nil
	}); err == nil {
		t.Fatal("BLS TLS certificate accepted a signer outside the declared identity")
	}
	for _, signature := range [][]byte{nil, {1}} {
		if _, err := GenerateBLSTLSCertificate("txquic", []byte("identity"), public.Serialize(), func([]byte) ([]byte, error) {
			return signature, nil
		}); err == nil {
			t.Fatalf("BLS TLS certificate accepted invalid signature length %d", len(signature))
		}
	}
}

func TestBLSTLSCertificateRejectsEmptyAndTruncatedProofWithoutPanic(t *testing.T) {
	secret, public := newQUICAuthTestKey(t)
	identity := []byte("committee generation")
	certificate, err := GenerateBLSTLSCertificate("txquic", identity, public.Serialize(), func(digest []byte) ([]byte, error) {
		return secret.SignHash(digest).Serialize(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf := certificate.Leaf
	privateKey := certificate.PrivateKey.(ed25519.PrivateKey)
	var proof blsTLSAttestation
	for _, extension := range leaf.Extensions {
		if extension.Id.Equal(blsTLSAuthOID) {
			if rest, err := asn1.Unmarshal(extension.Value, &proof); err != nil || len(rest) != 0 {
				t.Fatal("decode generated BLS TLS proof")
			}
		}
	}
	if proof.Application == "" {
		t.Fatal("generated certificate has no BLS TLS proof")
	}
	for _, signature := range [][]byte{nil, {1}} {
		mutated := proof
		mutated.Signature = signature
		encoded, err := asn1.Marshal(mutated)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber:    new(big.Int).Set(leaf.SerialNumber),
			NotBefore:       leaf.NotBefore,
			NotAfter:        leaf.NotAfter,
			KeyUsage:        x509.KeyUsageDigitalSignature,
			ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			ExtraExtensions: []pkix.Extension{{Id: blsTLSAuthOID, Critical: true, Value: encoded}},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyBLSTLSCertificate([][]byte{der}, "txquic", identity, public.Serialize()); err == nil {
			t.Fatalf("BLS TLS verifier accepted invalid proof length %d", len(signature))
		}
	}
}

func TestBLSTLSCertificateRejectsCopiedProofWithAlteredValidity(t *testing.T) {
	secret, public := newQUICAuthTestKey(t)
	identity := []byte("committee generation")
	certificate, err := GenerateBLSTLSCertificate("txquic", identity, public.Serialize(), func(digest []byte) ([]byte, error) {
		return secret.SignHash(digest).Serialize(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf := certificate.Leaf
	if leaf == nil {
		t.Fatal("generated certificate has no parsed leaf")
	}
	var attestation pkix.Extension
	for _, extension := range leaf.Extensions {
		if extension.Id.Equal(blsTLSAuthOID) {
			attestation = extension
			break
		}
	}
	if len(attestation.Value) == 0 {
		t.Fatal("generated certificate has no BLS proof")
	}
	privateKey, ok := certificate.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("TLS private key type = %T", certificate.PrivateKey)
	}
	altered := &x509.Certificate{
		SerialNumber:    new(big.Int).Set(leaf.SerialNumber),
		NotBefore:       leaf.NotBefore,
		NotAfter:        leaf.NotAfter.Add(30 * time.Minute),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{attestation},
	}
	der, err := x509.CreateCertificate(rand.Reader, altered, altered, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBLSTLSCertificate([][]byte{der}, "txquic", identity, public.Serialize()); err == nil {
		t.Fatal("copied BLS proof authorized an altered certificate lifetime")
	}
}

func TestQUICPeerCertificateRejectsEmptyAndTruncatedProofWithoutPanic(t *testing.T) {
	const chainID = uint64(10101919)
	const address = "127.0.0.1:7102"
	secret, public := newQUICAuthTestKey(t)
	certificate, err := generateAttestedQUICCertificate(chainID, address, secret, public.Serialize())
	if err != nil {
		t.Fatal(err)
	}
	leaf := certificate.Leaf
	privateKey := certificate.PrivateKey.(ed25519.PrivateKey)
	var proof quicPeerAttestation
	for _, extension := range leaf.Extensions {
		if extension.Id.Equal(quicPeerAuthOID) {
			if rest, err := asn1.Unmarshal(extension.Value, &proof); err != nil || len(rest) != 0 {
				t.Fatal("decode generated QUIC peer proof")
			}
		}
	}
	if proof.Address == "" {
		t.Fatal("generated certificate has no QUIC peer proof")
	}
	for _, signature := range [][]byte{nil, {1}} {
		mutated := proof
		mutated.Signature = signature
		encoded, err := asn1.Marshal(mutated)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber:    new(big.Int).Set(leaf.SerialNumber),
			NotBefore:       leaf.NotBefore,
			NotAfter:        leaf.NotAfter,
			KeyUsage:        x509.KeyUsageDigitalSignature,
			ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			ExtraExtensions: []pkix.Extension{{Id: quicPeerAuthOID, Critical: true, Value: encoded}},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseAndVerifyQUICPeerCertificate([][]byte{der}, chainID, address, public.Serialize()); err == nil {
			t.Fatalf("QUIC peer verifier accepted invalid proof length %d", len(signature))
		}
	}
}

func TestQUICPeerAuthorizationRejectsUnknownAndRotatedKeys(t *testing.T) {
	const chainID = uint64(10101919)
	localSecret, localPublic := newQUICAuthTestKey(t)
	_, peerPublic := newQUICAuthTestKey(t)
	attackerSecret, attackerPublic := newQUICAuthTestKey(t)
	const localAddress = "127.0.0.1:7101"
	const peerAddress = "127.0.0.1:7102"

	auth := newQUICPeerAuthenticator()
	peers := map[string][]byte{
		localAddress: localPublic.Serialize(),
		peerAddress:  peerPublic.Serialize(),
	}
	if err := auth.configure(chainID, localAddress, localSecret.SerializeToHexStr(), localPublic.SerializeToHexStr(), peers); err != nil {
		t.Fatal(err)
	}
	if err := auth.verifyAuthorizedPeer(&quicPeerIdentity{chainID: chainID, address: peerAddress, publicKey: peerPublic.Serialize()}); err != nil {
		t.Fatalf("authorized peer rejected: %v", err)
	}
	if err := auth.verifyAuthorizedPeer(&quicPeerIdentity{chainID: chainID, address: peerAddress, publicKey: attackerPublic.Serialize()}); err == nil {
		t.Fatal("attacker key accepted for an authorized peer address")
	}
	forgedCertificate, err := generateAttestedQUICCertificate(chainID, peerAddress, attackerSecret, attackerPublic.Serialize())
	if err != nil {
		t.Fatal(err)
	}
	serverTLS := quicServerTLSConfig(auth)
	if !serverTLS.SessionTicketsDisabled || serverTLS.VerifyConnection == nil {
		t.Fatal("inbound TLS did not install its mandatory per-connection verifier")
	}
	if err := serverTLS.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{forgedCertificate.Leaf}}); err == nil {
		t.Fatal("inbound TLS accepted an attacker key for an authorized peer address")
	}
	if err := auth.verifyAuthorizedPeer(&quicPeerIdentity{chainID: chainID, address: "127.0.0.1:7999", publicKey: attackerPublic.Serialize()}); err == nil {
		t.Fatal("unknown peer address accepted")
	}

	rotated := map[string][]byte{
		localAddress: localPublic.Serialize(),
		peerAddress:  attackerPublic.Serialize(),
	}
	if err := auth.updateAuthorizedPeers(rotated); err != nil {
		t.Fatal(err)
	}
	if err := auth.verifyAuthorizedPeer(&quicPeerIdentity{chainID: chainID, address: peerAddress, publicKey: peerPublic.Serialize()}); err == nil {
		t.Fatal("rotated-out peer key remained authorized")
	}
	if err := auth.verifyAuthorizedPeer(&quicPeerIdentity{chainID: chainID, address: peerAddress, publicKey: attackerPublic.Serialize()}); err != nil {
		t.Fatalf("rotated peer key rejected: %v", err)
	}
}

func TestQUICAuthorizationUpdateRevokesLocalAndFormerCommittee(t *testing.T) {
	const chainID = uint64(10101919)
	localSecret, localPublic := newQUICAuthTestKey(t)
	_, formerPublic := newQUICAuthTestKey(t)
	_, nextPublic := newQUICAuthTestKey(t)
	const localAddress = "127.0.0.1:7101"
	const formerAddress = "127.0.0.1:7102"
	const nextAddress = "127.0.0.1:7103"

	auth := newQUICPeerAuthenticator()
	if err := auth.configure(chainID, localAddress, localSecret.SerializeToHexStr(), localPublic.SerializeToHexStr(), map[string][]byte{
		localAddress: localPublic.Serialize(), formerAddress: formerPublic.Serialize(),
	}); err != nil {
		t.Fatal(err)
	}
	// The local validator is rotated out together with the former peer. Updating
	// the allowlist must still succeed so both credentials are immediately
	// rejected for new inbound connections.
	if err := auth.updateAuthorizedPeers(map[string][]byte{nextAddress: nextPublic.Serialize()}); err != nil {
		t.Fatalf("rotated-out local node could not install next committee: %v", err)
	}
	if err := auth.verifyAuthorizedPeer(&quicPeerIdentity{chainID: chainID, address: formerAddress, publicKey: formerPublic.Serialize()}); err == nil {
		t.Fatal("former committee peer remained authorized")
	}
	if err := auth.verifyAuthorizedPeer(&quicPeerIdentity{chainID: chainID, address: localAddress, publicKey: localPublic.Serialize()}); err == nil {
		t.Fatal("rotated-out local credential remained inbound-authorized")
	}
	if err := auth.verifyAuthorizedPeer(&quicPeerIdentity{chainID: chainID, address: nextAddress, publicKey: nextPublic.Serialize()}); err != nil {
		t.Fatalf("next committee peer rejected: %v", err)
	}
}

func TestQUICPeerCertificateRenewsBeforeExpiry(t *testing.T) {
	const chainID = uint64(10101919)
	secret, public := newQUICAuthTestKey(t)
	const address = "127.0.0.1:7101"
	auth := newQUICPeerAuthenticator()
	if err := auth.configure(chainID, address, secret.SerializeToHexStr(), public.SerializeToHexStr(), map[string][]byte{address: public.Serialize()}); err != nil {
		t.Fatal(err)
	}
	_, _, _, original, err := auth.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	auth.mu.Lock()
	auth.certificate.Leaf.NotAfter = time.Now().Add(30 * time.Minute)
	auth.mu.Unlock()
	_, _, _, renewed, err := auth.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(original.Certificate[0], renewed.Certificate[0]) {
		t.Fatal("certificate was not renewed before expiry")
	}
	if time.Until(renewed.Leaf.NotAfter) < 23*time.Hour {
		t.Fatalf("renewed certificate lifetime is too short: %v", time.Until(renewed.Leaf.NotAfter))
	}
	if _, err := parseAndVerifyQUICPeerCertificate(renewed.Certificate, chainID, address, public.Serialize()); err != nil {
		t.Fatalf("renewed certificate is invalid: %v", err)
	}
}

func TestQUICReceiveBudgetsSeparateControlFromLargeData(t *testing.T) {
	limiter := new(quicReceiveLimiter)
	if !limiter.reserve("byzantine", NetClassBulkGossip, def_MaxPacketSize, 0) {
		t.Fatal("first maximum bulk payload was rejected")
	}
	if limiter.reserve("byzantine", NetClassBulkGossip, 1, 0) {
		t.Fatal("one peer reserved a second large-data stream")
	}
	if !limiter.reserve("honest", NetClassHotstuffControl, quicControlMaxPacketSize, 0) {
		t.Fatal("large proposal body starved the separate control-message budget")
	}
	limiter.release("honest", NetClassHotstuffControl, quicControlMaxPacketSize)

	honestGranted := make(chan bool, 1)
	go func() {
		honestGranted <- limiter.reserve("honest", NetClassProposalBodyBulk, 1, time.Second)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		limiter.mu.Lock()
		queued := len(limiter.largeQueue) == 1
		limiter.mu.Unlock()
		if queued {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("honest large-data request was not queued")
		}
		time.Sleep(time.Millisecond)
	}
	limiter.release("byzantine", NetClassBulkGossip, def_MaxPacketSize)
	select {
	case granted := <-honestGranted:
		if !granted {
			t.Fatal("honest queued request was not granted after Byzantine release")
		}
	case <-time.After(time.Second):
		t.Fatal("honest queued request starved")
	}
	if limiter.reserve("byzantine", NetClassBulkGossip, def_MaxPacketSize, 0) {
		t.Fatal("new Byzantine request bypassed the already-granted honest request")
	}
	limiter.release("honest", NetClassProposalBodyBulk, 1)
}

func TestQUICReceiveLimiterAllowsBoundedProposalParallelism(t *testing.T) {
	limiter := new(quicReceiveLimiter)
	for stream := 0; stream < quicProposalPeerStreams; stream++ {
		if !limiter.reserve("leader", NetClassProposalBodyBulk, quicProposalBodyMaxPacketSize, 0) {
			t.Fatalf("proposal stream %d was rejected before the peer cap", stream)
		}
	}
	if limiter.reserve("leader", NetClassProposalBodyBulk, 1, 0) {
		t.Fatal("proposal leader exceeded its bounded stream cap")
	}
	if !limiter.reserve("other", NetClassProposalBodyBulk, 1, 0) {
		t.Fatal("one leader consumed the global proposal receive budget")
	}
	limiter.release("other", NetClassProposalBodyBulk, 1)
	for stream := 0; stream < quicProposalPeerStreams; stream++ {
		limiter.release("leader", NetClassProposalBodyBulk, quicProposalBodyMaxPacketSize)
	}
}

func TestQUICReceiveControlBudgetIsPeerFair(t *testing.T) {
	limiter := new(quicReceiveLimiter)
	for index := 0; index < 2; index++ {
		if !limiter.reserve("byzantine", NetClassHotstuffControl, quicControlMaxPacketSize, 0) {
			t.Fatalf("Byzantine peer reservation %d unexpectedly rejected", index)
		}
	}
	if limiter.reserve("byzantine", NetClassHotstuffControl, 1, 0) {
		t.Fatal("one peer exceeded its HotStuff control quota")
	}
	if !limiter.reserve("honest", NetClassHotstuffControl, quicControlMaxPacketSize, 0) {
		t.Fatal("one peer exhausted the honest peer's HotStuff control quota")
	}
	if !limiter.reserve("metadata-attacker", NetClassProposalBodyControl, quicMetadataPeerBudget, 0) {
		t.Fatal("valid maximum per-peer metadata reservation was rejected")
	}
	if !limiter.reserve("honest-2", NetClassHotstuffControl, quicControlMaxPacketSize, 0) {
		t.Fatal("metadata traffic starved the isolated HotStuff control budget")
	}
	limiter.release("byzantine", NetClassHotstuffControl, quicControlMaxPacketSize)
	limiter.release("byzantine", NetClassHotstuffControl, quicControlMaxPacketSize)
	limiter.release("honest", NetClassHotstuffControl, quicControlMaxPacketSize)
	limiter.release("metadata-attacker", NetClassProposalBodyControl, quicMetadataPeerBudget)
	limiter.release("honest-2", NetClassHotstuffControl, quicControlMaxPacketSize)
}

func TestQUICReceiveLimiterTimeoutGrantsNextFittingWaiter(t *testing.T) {
	limiter := new(quicReceiveLimiter)
	if !limiter.reserve("active", NetClassBulkGossip, def_MaxPacketSize-1, 0) {
		t.Fatal("active large reservation rejected")
	}
	head := make(chan bool, 1)
	go func() {
		head <- limiter.reserve("head", NetClassProposalBodyBulk, 2, 50*time.Millisecond)
	}()
	waitForQueue := func(want int) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for {
			limiter.mu.Lock()
			got := len(limiter.largeQueue)
			limiter.mu.Unlock()
			if got == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("large queue length = %d, want %d", got, want)
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitForQueue(1)
	tail := make(chan bool, 1)
	go func() {
		tail <- limiter.reserve("tail", NetClassProposalBodyBulk, 1, time.Second)
	}()
	waitForQueue(2)
	if granted := <-head; granted {
		t.Fatal("oversized head waiter was granted")
	}
	select {
	case granted := <-tail:
		if !granted {
			t.Fatal("next fitting waiter was not granted")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed-out head waiter left the fitting tail asleep")
	}
	limiter.release("tail", NetClassProposalBodyBulk, 1)
	limiter.release("active", NetClassBulkGossip, def_MaxPacketSize-1)
}

func TestQUICReceiveLimiterConnectionCancelClearsPeer(t *testing.T) {
	limiter := new(quicReceiveLimiter)
	if !limiter.reserve("active", NetClassBulkGossip, def_MaxPacketSize, 0) {
		t.Fatal("active large reservation rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan bool, 1)
	go func() {
		result <- limiter.reserveContext(ctx, "reconnecting-peer", NetClassProposalBodyBulk, 1, time.Second)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		limiter.mu.Lock()
		queued := len(limiter.largeQueue) == 1
		limiter.mu.Unlock()
		if queued {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cancel test waiter was not queued")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if granted := <-result; granted {
		t.Fatal("canceled connection retained a large reservation")
	}
	limiter.release("active", NetClassBulkGossip, def_MaxPacketSize)
	if !limiter.reserve("reconnecting-peer", NetClassProposalBodyBulk, 1, 0) {
		t.Fatal("canceled peer remained blocked after reconnect")
	}
	limiter.release("reconnecting-peer", NetClassProposalBodyBulk, 1)
}

func TestQUICReceiveLimiterRejectsPreCanceledReservation(t *testing.T) {
	limiter := new(quicReceiveLimiter)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if limiter.reserveContext(ctx, "closed-peer", NetClassProposalBodyBulk, 1, time.Second) {
		t.Fatal("pre-canceled connection acquired a large reservation")
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if limiter.largeUsed != 0 || len(limiter.largePeers) != 0 || len(limiter.largeQueue) != 0 {
		t.Fatalf("pre-canceled reservation leaked limiter state: used=%d peers=%d queue=%d", limiter.largeUsed, len(limiter.largePeers), len(limiter.largeQueue))
	}
}

func TestQUICListenerInboundLeaseIsPeerBounded(t *testing.T) {
	listener := &QUICListener{}
	if !listener.acquirePeerLease("peer-a") || !listener.acquirePeerLease("peer-a") {
		t.Fatal("two permitted inbound connections were rejected")
	}
	if listener.acquirePeerLease("peer-a") {
		t.Fatal("third inbound connection from one peer was accepted")
	}
	if !listener.acquirePeerLease("peer-b") {
		t.Fatal("one peer exhausted another peer's inbound connection allowance")
	}
	listener.releasePeerLease("peer-a")
	if !listener.acquirePeerLease("peer-a") {
		t.Fatal("closed connection did not return its peer lease")
	}
}

func TestQUICLargeFrameTimeoutScalesForWAN(t *testing.T) {
	if got := quicFrameReadTimeout(NetClassProposalBodyBulk, def_MaxPacketSize); got <= 5*time.Second || got > 30*time.Second {
		t.Fatalf("large-frame I/O timeout = %v, want (5s,30s]", got)
	}
}

func TestQUICClassPacketLimits(t *testing.T) {
	tests := []struct {
		class uint8
		limit uint32
	}{
		{NetClassHandshake, quicHandshakeMaxPacketSize},
		{NetClassHotstuffControl, quicControlMaxPacketSize},
		{NetClassProposalBodyControl, quicMetadataMaxPacketSize},
		{NetClassProposalBodyBulk, quicProposalBodyMaxPacketSize},
		{NetClassBulkGossip, def_MaxPacketSize},
	}
	for _, test := range tests {
		limit, ok := quicClassPacketLimit(test.class)
		if !ok || limit != test.limit {
			t.Fatalf("class %d limit = (%d,%v), want (%d,true)", test.class, limit, ok, test.limit)
		}
	}
	if _, ok := quicClassPacketLimit(0xff); ok {
		t.Fatal("unknown QUIC frame class accepted")
	}
}

func TestQUICSendLimiterBoundsProposalSlotsAndBytes(t *testing.T) {
	limiter := newQUICSendLimiter()
	reservations := make([]*quicSendReservation, 0, quicProposalPeerStreams)
	for slot := 0; slot < quicProposalPeerStreams; slot++ {
		reservation, err := limiter.acquireSlot(context.Background(), NetClassProposalBodyBulk)
		if err != nil {
			t.Fatalf("proposal slot %d rejected: %v", slot, err)
		}
		if err := reservation.reserveBytes(context.Background(), uint64(quicProposalBodyMaxPacketSize)); err != nil {
			t.Fatalf("proposal bytes %d rejected: %v", slot, err)
		}
		reservations = append(reservations, reservation)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if reservation, err := limiter.acquireSlot(canceled, NetClassProposalBodyBulk); err == nil {
		reservation.release()
		t.Fatal("proposal sender exceeded its bounded slot cap")
	}
	reservations[0].release()
	replacement, err := limiter.acquireSlot(context.Background(), NetClassProposalBodyBulk)
	if err != nil {
		t.Fatalf("released proposal slot was not reusable: %v", err)
	}
	if err := replacement.reserveBytes(context.Background(), uint64(quicProposalBodyMaxPacketSize)); err != nil {
		t.Fatalf("released proposal bytes were not reusable: %v", err)
	}
	replacement.release()
	for _, reservation := range reservations[1:] {
		reservation.release()
	}
}

func TestRouterRegistrationRechecksAuthorizationAndCapsPeerConnections(t *testing.T) {
	_, peerPublic := newQUICAuthTestKey(t)
	_, attackerPublic := newQUICAuthTestKey(t)
	const peerAddress = "127.0.0.1:7102"
	remote := NewServerIdentityWithTransport(peerAddress, PlainQUIC)
	remote.PublicKey = peerPublic.Serialize()
	router := &Router{
		connections:        make(map[ServerIdentityID][]Conn),
		peerAuthConfigured: true,
		authorizedPeers:    map[string][]byte{peerAddress: peerPublic.Serialize()},
	}

	attacker := &authenticatedQUICStub{peerAddress: peerAddress, peerKey: attackerPublic.Serialize()}
	if err := router.registerConnection(remote, attacker); err == nil {
		t.Fatal("connection authenticated with a non-authorized BLS key was registered")
	}
	registered := make([]*authenticatedQUICStub, 0, maxAuthenticatedConnectionsPerPeer)
	for index := 0; index < maxAuthenticatedConnectionsPerPeer; index++ {
		conn := &authenticatedQUICStub{peerAddress: peerAddress, peerKey: peerPublic.Serialize()}
		if err := router.registerConnection(remote, conn); err != nil {
			t.Fatalf("authorized connection %d rejected: %v", index, err)
		}
		registered = append(registered, conn)
	}
	extra := &authenticatedQUICStub{peerAddress: peerAddress, peerKey: peerPublic.Serialize()}
	if err := router.registerConnection(remote, extra); err == nil {
		t.Fatal("per-peer authenticated connection cap was not enforced")
	}
	if err := registered[0].Close(); err != nil {
		t.Fatal(err)
	}
	if err := router.registerConnection(remote, extra); err != nil {
		t.Fatalf("closed connection awaiting handler cleanup consumed peer cap: %v", err)
	}
	overflow := &authenticatedQUICStub{peerAddress: peerAddress, peerKey: peerPublic.Serialize()}
	if err := router.registerConnection(remote, overflow); err == nil {
		t.Fatal("replacement allowed more than the live per-peer connection cap")
	}

	spoofed := *remote
	spoofed.ID = NewServerIdentityWithTransport("127.0.0.1:7999", PlainQUIC).ID
	if err := router.registerConnection(&spoofed, overflow); err == nil {
		t.Fatal("ServerIdentity ID/address mismatch was registered")
	}
}

func TestRouterSendRetriesExistingConnectionBeforeDial(t *testing.T) {
	_, peerPublic := newQUICAuthTestKey(t)
	const peerAddress = "127.0.0.1:7102"
	remote := NewServerIdentityWithTransport(peerAddress, PlainQUIC)
	remote.PublicKey = peerPublic.Serialize()
	failed := &authenticatedQUICStub{
		peerAddress: peerAddress,
		peerKey:     peerPublic.Serialize(),
		sendErr:     ErrUnknown,
	}
	alternate := &authenticatedQUICStub{
		peerAddress: peerAddress,
		peerKey:     peerPublic.Serialize(),
		sendBytes:   17,
	}
	router := &Router{
		ServerIdentity: NewServerIdentityWithTransport("127.0.0.1:7101", PlainQUIC),
		connections: map[ServerIdentityID][]Conn{
			remote.ID: {failed, alternate},
		},
		sendsMap:           make(map[ServerIdentityID]int),
		peerAuthConfigured: true,
		authorizedPeers:    map[string][]byte{peerAddress: peerPublic.Serialize()},
	}

	sent, err := router.Send(remote, &quicClassifiedTestMessage{Class: uint32(NetClassHotstuffControl)}, false)
	if err != nil {
		t.Fatalf("send did not recover through the second registered connection: %v", err)
	}
	if sent != alternate.sendBytes {
		t.Fatalf("sent bytes = %d, want %d", sent, alternate.sendBytes)
	}
	if !failed.closed || failed.sendCount != 1 {
		t.Fatalf("failed connection was not retired exactly once: closed=%v sends=%d", failed.closed, failed.sendCount)
	}
	if alternate.sendCount != 1 || alternate.closed {
		t.Fatalf("alternate connection was not used exactly once: closed=%v sends=%d", alternate.closed, alternate.sendCount)
	}
}

func TestRouterKeepsConnectionOnStreamLocalSendFailure(t *testing.T) {
	_, peerPublic := newQUICAuthTestKey(t)
	const peerAddress = "127.0.0.1:7102"
	remote := NewServerIdentityWithTransport(peerAddress, PlainQUIC)
	remote.PublicKey = peerPublic.Serialize()
	streamFailed := &authenticatedQUICStub{
		peerAddress: peerAddress,
		peerKey:     peerPublic.Serialize(),
		sendErr:     &quicStreamLocalSendError{err: ErrTimeout},
	}
	router := &Router{
		ServerIdentity: NewServerIdentityWithTransport("127.0.0.1:7101", PlainQUIC),
		connections: map[ServerIdentityID][]Conn{
			remote.ID: {streamFailed},
		},
		sendsMap:           make(map[ServerIdentityID]int),
		peerAuthConfigured: true,
		authorizedPeers:    map[string][]byte{peerAddress: peerPublic.Serialize()},
	}
	if _, err := router.Send(remote, &quicClassifiedTestMessage{Class: uint32(NetClassHotstuffControl)}, false); !isQUICStreamLocalSendError(err) {
		t.Fatalf("router lost stream-local failure: %v", err)
	}
	if streamFailed.closed || streamFailed.sendCount != 1 {
		t.Fatalf("stream-local failure retired shared connection: closed=%v sends=%d", streamFailed.closed, streamFailed.sendCount)
	}
}

func TestRouterDoesNotRetryPermanentMessageFailure(t *testing.T) {
	_, peerPublic := newQUICAuthTestKey(t)
	const peerAddress = "127.0.0.1:7102"
	remote := NewServerIdentityWithTransport(peerAddress, PlainQUIC)
	remote.PublicKey = peerPublic.Serialize()
	failed := &authenticatedQUICStub{
		peerAddress: peerAddress,
		peerKey:     peerPublic.Serialize(),
		sendErr:     NewPermanentSendError(SendErrorMarshal, errors.New("invalid wire message")),
	}
	router := &Router{
		ServerIdentity: NewServerIdentityWithTransport("127.0.0.1:7101", PlainQUIC),
		connections: map[ServerIdentityID][]Conn{
			remote.ID: {failed},
		},
		sendsMap:           make(map[ServerIdentityID]int),
		peerAuthConfigured: true,
		authorizedPeers:    map[string][]byte{peerAddress: peerPublic.Serialize()},
	}
	if _, err := router.Send(remote, &quicClassifiedTestMessage{Class: uint32(NetClassHotstuffControl)}, false); !IsPermanentSendError(err) {
		t.Fatalf("router lost permanent message failure: %v", err)
	}
	if failed.closed || failed.sendCount != 1 {
		t.Fatalf("router retried or retired a healthy connection: closed=%v sends=%d", failed.closed, failed.sendCount)
	}
}

func receiveQUICForTest(conn Conn, timeout time.Duration) (*Envelope, error) {
	type result struct {
		env *Envelope
		err error
	}
	ch := make(chan result, 1)
	go func() {
		env, err := conn.Receive()
		ch <- result{env: env, err: err}
	}()

	select {
	case got := <-ch:
		return got.env, got.err
	case <-time.After(timeout):
		return nil, ErrTimeout
	}
}
