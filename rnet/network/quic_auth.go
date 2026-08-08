package network

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/cypherium/cypher/crypto/bls"
)

const (
	quicPeerAuthVersion = 1
	quicPeerAuthDomain  = "cypher-rnet-quic-peer-v1"
)

var quicPeerAuthOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}

type quicPeerAttestation struct {
	Version   int
	ChainID   []byte
	Address   string
	PublicKey []byte
	Signature []byte
}

type quicPeerIdentity struct {
	chainID   uint64
	address   string
	publicKey []byte
}

type quicPeerAuthenticator struct {
	mu          sync.RWMutex
	configured  bool
	chainID     uint64
	address     string
	publicKey   []byte
	secret      *bls.SecretKey
	authorized  map[string][]byte
	certificate tls.Certificate
	limiter     *quicReceiveLimiter
}

func newQUICPeerAuthenticator() *quicPeerAuthenticator {
	return &quicPeerAuthenticator{limiter: new(quicReceiveLimiter)}
}

func (auth *quicPeerAuthenticator) receiveLimiter() *quicReceiveLimiter {
	if auth == nil {
		return nil
	}
	auth.mu.Lock()
	defer auth.mu.Unlock()
	if auth.limiter == nil {
		auth.limiter = new(quicReceiveLimiter)
	}
	return auth.limiter
}

func writeQUICAuthPart(hash interface{ Write([]byte) (int, error) }, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write(value)
}

func quicPeerAuthDigest(chainID uint64, address string, publicKey, subjectPublicKeyInfo []byte) []byte {
	hash := sha256.New()
	writeQUICAuthPart(hash, []byte(quicPeerAuthDomain))
	var encodedChainID [8]byte
	binary.BigEndian.PutUint64(encodedChainID[:], chainID)
	writeQUICAuthPart(hash, encodedChainID[:])
	writeQUICAuthPart(hash, []byte(address))
	writeQUICAuthPart(hash, publicKey)
	writeQUICAuthPart(hash, subjectPublicKeyInfo)
	return hash.Sum(nil)
}

func validateQUICAuthorizedPeers(peers map[string][]byte) (map[string][]byte, error) {
	if len(peers) == 0 {
		return nil, fmt.Errorf("QUIC peer authorization set is empty")
	}
	validated := make(map[string][]byte, len(peers))
	for address, encoded := range peers {
		if address == "" || len(encoded) == 0 {
			return nil, fmt.Errorf("invalid QUIC authorized peer identity")
		}
		public := bls.GetPublicKey(encoded)
		if public == nil || !bytes.Equal(public.Serialize(), encoded) {
			return nil, fmt.Errorf("invalid QUIC authorized BLS key for %q", address)
		}
		validated[address] = append([]byte(nil), encoded...)
	}
	return validated, nil
}

func (auth *quicPeerAuthenticator) configure(chainID uint64, address, privateKeyHex, publicKeyHex string, authorizedPeers map[string][]byte) error {
	if auth == nil || chainID == 0 || address == "" || privateKeyHex == "" || publicKeyHex == "" {
		return fmt.Errorf("incomplete QUIC peer authentication identity")
	}
	secret := new(bls.SecretKey)
	if err := secret.DeserializeHexStr(privateKeyHex); err != nil {
		return fmt.Errorf("invalid QUIC BLS private key: %w", err)
	}
	public := new(bls.PublicKey)
	if err := public.DeserializeHexStr(publicKeyHex); err != nil {
		return fmt.Errorf("invalid QUIC BLS public key: %w", err)
	}
	derived := secret.GetPublicKey()
	if derived == nil || !derived.IsEqual(public) {
		return fmt.Errorf("QUIC BLS private/public key mismatch")
	}
	publicBytes := public.Serialize()
	validatedPeers, err := validateQUICAuthorizedPeers(authorizedPeers)
	if err != nil {
		return err
	}
	if expected, ok := validatedPeers[address]; !ok || !bytes.Equal(expected, publicBytes) {
		return fmt.Errorf("local QUIC identity is not authorized by the active committee")
	}
	certificate, err := generateAttestedQUICCertificate(chainID, address, secret, publicBytes)
	if err != nil {
		return err
	}
	auth.mu.Lock()
	auth.configured = true
	auth.chainID = chainID
	auth.address = address
	auth.publicKey = append(auth.publicKey[:0], publicBytes...)
	auth.secret = secret
	auth.authorized = validatedPeers
	auth.certificate = certificate
	auth.mu.Unlock()
	return nil
}

func (auth *quicPeerAuthenticator) snapshot() (uint64, string, []byte, tls.Certificate, error) {
	if auth == nil {
		return 0, "", nil, tls.Certificate{}, fmt.Errorf("QUIC peer authentication is unavailable")
	}
	auth.mu.Lock()
	defer auth.mu.Unlock()
	if !auth.configured || auth.chainID == 0 || auth.address == "" || len(auth.publicKey) == 0 || auth.secret == nil || len(auth.certificate.Certificate) == 0 {
		return 0, "", nil, tls.Certificate{}, fmt.Errorf("QUIC peer authentication is not configured")
	}
	if auth.certificate.Leaf == nil || time.Until(auth.certificate.Leaf.NotAfter) < time.Hour {
		certificate, err := generateAttestedQUICCertificate(auth.chainID, auth.address, auth.secret, auth.publicKey)
		if err != nil {
			return 0, "", nil, tls.Certificate{}, fmt.Errorf("renew QUIC peer certificate: %w", err)
		}
		auth.certificate = certificate
	}
	return auth.chainID, auth.address, append([]byte(nil), auth.publicKey...), auth.certificate, nil
}

func (auth *quicPeerAuthenticator) updateAuthorizedPeers(peers map[string][]byte) error {
	validated, err := validateQUICAuthorizedPeers(peers)
	if err != nil {
		return err
	}
	auth.mu.Lock()
	defer auth.mu.Unlock()
	if !auth.configured {
		return fmt.Errorf("QUIC peer authentication is not configured")
	}
	// Credential ownership and inbound peer authorization are separate. A node
	// removed by reconfiguration must still be able to install the new allowlist
	// so old peers are revoked, even though its retained certificate will no
	// longer be accepted by the new committee.
	auth.authorized = validated
	return nil
}

func (auth *quicPeerAuthenticator) verifyAuthorizedPeer(identity *quicPeerIdentity) error {
	if auth == nil || identity == nil {
		return fmt.Errorf("missing authenticated QUIC peer identity")
	}
	auth.mu.RLock()
	defer auth.mu.RUnlock()
	if !auth.configured || identity.chainID != auth.chainID {
		return fmt.Errorf("QUIC peer belongs to an unauthorized chain")
	}
	expected, ok := auth.authorized[identity.address]
	if !ok || !bytes.Equal(expected, identity.publicKey) {
		return fmt.Errorf("QUIC peer is not authorized by the active committee")
	}
	return nil
}

func (auth *quicPeerAuthenticator) localPublicKey() []byte {
	_, _, publicKey, _, err := auth.snapshot()
	if err != nil {
		return nil
	}
	return publicKey
}

func generateAttestedQUICCertificate(chainID uint64, address string, secret *bls.SecretKey, publicKey []byte) (tls.Certificate, error) {
	_, tlsPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	spki, err := x509.MarshalPKIXPublicKey(tlsPrivate.Public())
	if err != nil {
		return tls.Certificate{}, err
	}
	digest := quicPeerAuthDigest(chainID, address, publicKey, spki)
	signature := secret.SignHash(digest)
	if signature == nil {
		return tls.Certificate{}, fmt.Errorf("failed to sign QUIC certificate attestation")
	}
	var encodedChainID [8]byte
	binary.BigEndian.PutUint64(encodedChainID[:], chainID)
	attestation, err := asn1.Marshal(quicPeerAttestation{
		Version:   quicPeerAuthVersion,
		ChainID:   encodedChainID[:],
		Address:   address,
		PublicKey: append([]byte(nil), publicKey...),
		Signature: signature.Serialize(),
	})
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(now.UnixNano()),
		NotBefore:       now.Add(-5 * time.Minute),
		NotAfter:        now.Add(24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{{Id: quicPeerAuthOID, Critical: true, Value: attestation}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, tlsPrivate.Public(), tlsPrivate)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: tlsPrivate, Leaf: leaf}, nil
}

func parseAndVerifyQUICPeerCertificate(rawCerts [][]byte, expectedChainID uint64, expectedAddress string, expectedPublicKey []byte) (*quicPeerIdentity, error) {
	if len(rawCerts) != 1 {
		return nil, fmt.Errorf("QUIC peer must present exactly one attested certificate")
	}
	certificate, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil, fmt.Errorf("parse QUIC peer certificate: %w", err)
	}
	if err := certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature); err != nil {
		return nil, fmt.Errorf("invalid self-signed QUIC peer certificate: %w", err)
	}
	now := time.Now()
	if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
		return nil, fmt.Errorf("expired or not-yet-valid QUIC peer certificate")
	}
	if certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, fmt.Errorf("QUIC peer certificate lacks digital-signature usage")
	}
	var encodedAttestation []byte
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(quicPeerAuthOID) {
			if encodedAttestation != nil {
				return nil, fmt.Errorf("duplicate QUIC peer attestation extension")
			}
			if !extension.Critical {
				return nil, fmt.Errorf("QUIC peer attestation extension is not critical")
			}
			encodedAttestation = extension.Value
		}
	}
	if len(encodedAttestation) == 0 {
		return nil, fmt.Errorf("QUIC peer certificate has no BLS attestation")
	}
	var attestation quicPeerAttestation
	rest, err := asn1.Unmarshal(encodedAttestation, &attestation)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("invalid QUIC peer attestation encoding")
	}
	if attestation.Version != quicPeerAuthVersion || len(attestation.ChainID) != 8 || binary.BigEndian.Uint64(attestation.ChainID) != expectedChainID || expectedChainID == 0 || attestation.Address == "" {
		return nil, fmt.Errorf("QUIC peer attestation version, chain or address mismatch")
	}
	if expectedAddress != "" && attestation.Address != expectedAddress {
		return nil, fmt.Errorf("QUIC peer address %q does not match expected %q", attestation.Address, expectedAddress)
	}
	if len(expectedPublicKey) > 0 && !bytes.Equal(attestation.PublicKey, expectedPublicKey) {
		return nil, fmt.Errorf("QUIC peer BLS key does not match the committee identity")
	}
	public := bls.GetPublicKey(attestation.PublicKey)
	if public == nil || !bytes.Equal(public.Serialize(), attestation.PublicKey) {
		return nil, fmt.Errorf("invalid or non-canonical QUIC peer BLS key")
	}
	var signature bls.Sign
	if err := signature.Deserialize(attestation.Signature); err != nil {
		return nil, fmt.Errorf("invalid QUIC peer BLS attestation signature")
	}
	chainID := binary.BigEndian.Uint64(attestation.ChainID)
	digest := quicPeerAuthDigest(chainID, attestation.Address, attestation.PublicKey, certificate.RawSubjectPublicKeyInfo)
	if !signature.VerifyHash(public, digest) {
		return nil, fmt.Errorf("QUIC peer BLS attestation verification failed")
	}
	return &quicPeerIdentity{chainID: chainID, address: attestation.Address, publicKey: append([]byte(nil), attestation.PublicKey...)}, nil
}

func extractQUICPeerChainID(certificate *x509.Certificate) uint64 {
	if certificate == nil {
		return 0
	}
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(quicPeerAuthOID) {
			continue
		}
		var attestation quicPeerAttestation
		rest, err := asn1.Unmarshal(extension.Value, &attestation)
		if err != nil || len(rest) != 0 || len(attestation.ChainID) != 8 {
			return 0
		}
		return binary.BigEndian.Uint64(attestation.ChainID)
	}
	return 0
}

func quicServerTLSConfig(auth *quicPeerAuthenticator) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{quicNextProto},
		ClientAuth: tls.RequireAnyClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			_, _, _, certificate, err := auth.snapshot()
			if err != nil {
				return nil, err
			}
			return &certificate, nil
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			chainID, _, _, _, err := auth.snapshot()
			if err != nil {
				return err
			}
			identity, err := parseAndVerifyQUICPeerCertificate(rawCerts, chainID, "", nil)
			if err != nil {
				return err
			}
			return auth.verifyAuthorizedPeer(identity)
		},
	}
}

func quicClientTLSConfig(auth *quicPeerAuthenticator, expected *ServerIdentity) (*tls.Config, error) {
	chainID, _, _, _, err := auth.snapshot()
	if err != nil {
		return nil, err
	}
	if expected == nil || expected.Address.String() == "" || len(expected.PublicKey) == 0 {
		return nil, fmt.Errorf("missing expected QUIC peer address or BLS key")
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{quicNextProto},
		InsecureSkipVerify: true, // Replaced by the mandatory BLS-attestation verifier below.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			_, _, _, certificate, err := auth.snapshot()
			if err != nil {
				return nil, err
			}
			return &certificate, nil
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			_, err := parseAndVerifyQUICPeerCertificate(rawCerts, chainID, expected.Address.String(), expected.PublicKey)
			return err
		},
	}, nil
}
