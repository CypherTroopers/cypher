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
	blsTLSAuthDomain    = "cypher-bls-tls-attestation"
	maxBLSIdentityBytes = 512
)

var quicPeerAuthOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
var blsTLSAuthOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2}

type blsTLSAttestation struct {
	Application string
	Identity    []byte
	PublicKey   []byte
	Serial      []byte
	NotBefore   int64
	NotAfter    int64
	Signature   []byte
}

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

func blsTLSAuthDigest(application string, identity, publicKey, subjectPublicKeyInfo, serial []byte, notBefore, notAfter int64) []byte {
	hash := sha256.New()
	writeQUICAuthPart(hash, []byte(blsTLSAuthDomain))
	writeQUICAuthPart(hash, []byte(application))
	writeQUICAuthPart(hash, identity)
	writeQUICAuthPart(hash, publicKey)
	writeQUICAuthPart(hash, subjectPublicKeyInfo)
	writeQUICAuthPart(hash, serial)
	var encodedTime [8]byte
	binary.BigEndian.PutUint64(encodedTime[:], uint64(notBefore))
	writeQUICAuthPart(hash, encodedTime[:])
	binary.BigEndian.PutUint64(encodedTime[:], uint64(notAfter))
	writeQUICAuthPart(hash, encodedTime[:])
	return hash.Sum(nil)
}

// GenerateBLSTLSCertificate creates a short-lived, self-signed TLS certificate
// whose ephemeral public key is authenticated by a canonical BLS identity. The
// caller controls the application domain and opaque identity commitment, so a
// credential cannot be replayed across protocols or consensus generations.
func GenerateBLSTLSCertificate(application string, identity, publicKey []byte, sign func([]byte) ([]byte, error)) (tls.Certificate, error) {
	if application == "" || len(application) > 128 || len(identity) == 0 || len(identity) > 4096 ||
		len(publicKey) == 0 || len(publicKey) > maxBLSIdentityBytes || sign == nil {
		return tls.Certificate{}, fmt.Errorf("invalid BLS TLS certificate identity")
	}
	public := bls.GetPublicKey(publicKey)
	if public == nil || !bytes.Equal(public.Serialize(), publicKey) {
		return tls.Certificate{}, fmt.Errorf("invalid BLS TLS public key")
	}
	_, tlsPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	spki, err := x509.MarshalPKIXPublicKey(tlsPrivate.Public())
	if err != nil {
		return tls.Certificate{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	now := time.Now().UTC().Truncate(time.Second)
	notBefore := now.Add(-5 * time.Minute)
	notAfter := now.Add(24 * time.Hour)
	digest := blsTLSAuthDigest(application, identity, publicKey, spki, serial.Bytes(), notBefore.Unix(), notAfter.Unix())
	signature, err := sign(digest)
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(signature) == 0 || len(signature) > maxBLSIdentityBytes {
		return tls.Certificate{}, fmt.Errorf("BLS TLS signer returned an invalid signature length")
	}
	var proof bls.Sign
	if err := proof.Deserialize(signature); err != nil || !bytes.Equal(proof.Serialize(), signature) || !proof.VerifyHash(public, digest) {
		return tls.Certificate{}, fmt.Errorf("BLS TLS signer returned an invalid signature")
	}
	attestation, err := asn1.Marshal(blsTLSAttestation{
		Application: application,
		Identity:    append([]byte(nil), identity...),
		PublicKey:   append([]byte(nil), publicKey...),
		Serial:      append([]byte(nil), serial.Bytes()...),
		NotBefore:   notBefore.Unix(),
		NotAfter:    notAfter.Unix(),
		Signature:   append([]byte(nil), signature...),
	})
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber:    serial,
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{{Id: blsTLSAuthOID, Critical: true, Value: attestation}},
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

// VerifyBLSTLSCertificate replaces WebPKI verification with a mandatory BLS
// attestation check against the exact application identity and committee key.
func VerifyBLSTLSCertificate(rawCerts [][]byte, application string, identity, expectedPublicKey []byte) error {
	if application == "" || len(identity) == 0 || len(expectedPublicKey) == 0 || len(expectedPublicKey) > maxBLSIdentityBytes {
		return fmt.Errorf("missing expected BLS TLS identity")
	}
	if len(rawCerts) != 1 {
		return fmt.Errorf("BLS TLS peer must present exactly one certificate")
	}
	certificate, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse BLS TLS certificate: %w", err)
	}
	if err := certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature); err != nil {
		return fmt.Errorf("invalid self-signed BLS TLS certificate: %w", err)
	}
	now := time.Now()
	if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
		return fmt.Errorf("expired or not-yet-valid BLS TLS certificate")
	}
	if certificate.NotAfter.Sub(certificate.NotBefore) <= 0 || certificate.NotAfter.Sub(certificate.NotBefore) > 25*time.Hour {
		return fmt.Errorf("BLS TLS certificate lifetime exceeds its bound")
	}
	if certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("BLS TLS certificate lacks digital-signature usage")
	}
	serverAuth := false
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			serverAuth = true
			break
		}
	}
	if !serverAuth {
		return fmt.Errorf("BLS TLS certificate cannot authenticate a server")
	}
	var encodedAttestation []byte
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(blsTLSAuthOID) {
			continue
		}
		if encodedAttestation != nil {
			return fmt.Errorf("duplicate BLS TLS attestation extension")
		}
		if !extension.Critical {
			return fmt.Errorf("BLS TLS attestation extension is not critical")
		}
		encodedAttestation = extension.Value
	}
	if len(encodedAttestation) == 0 {
		return fmt.Errorf("BLS TLS certificate has no attestation")
	}
	var attestation blsTLSAttestation
	rest, err := asn1.Unmarshal(encodedAttestation, &attestation)
	if err != nil || len(rest) != 0 {
		return fmt.Errorf("invalid BLS TLS attestation encoding")
	}
	if attestation.Application != application || !bytes.Equal(attestation.Identity, identity) || !bytes.Equal(attestation.PublicKey, expectedPublicKey) {
		return fmt.Errorf("BLS TLS application, identity or public key mismatch")
	}
	if len(attestation.PublicKey) == 0 || len(attestation.PublicKey) > maxBLSIdentityBytes ||
		len(attestation.Signature) == 0 || len(attestation.Signature) > maxBLSIdentityBytes {
		return fmt.Errorf("invalid BLS TLS attestation key or signature length")
	}
	if len(attestation.Serial) == 0 || new(big.Int).SetBytes(attestation.Serial).Cmp(certificate.SerialNumber) != 0 ||
		attestation.NotBefore != certificate.NotBefore.Unix() || attestation.NotAfter != certificate.NotAfter.Unix() {
		return fmt.Errorf("BLS TLS certificate metadata is not attested")
	}
	public := bls.GetPublicKey(attestation.PublicKey)
	if public == nil || !bytes.Equal(public.Serialize(), attestation.PublicKey) {
		return fmt.Errorf("invalid or non-canonical BLS TLS public key")
	}
	var signature bls.Sign
	if err := signature.Deserialize(attestation.Signature); err != nil || !bytes.Equal(signature.Serialize(), attestation.Signature) {
		return fmt.Errorf("invalid BLS TLS attestation signature")
	}
	digest := blsTLSAuthDigest(attestation.Application, attestation.Identity, attestation.PublicKey, certificate.RawSubjectPublicKeyInfo,
		attestation.Serial, attestation.NotBefore, attestation.NotAfter)
	if !signature.VerifyHash(public, digest) {
		return fmt.Errorf("BLS TLS attestation verification failed")
	}
	return nil
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
	if len(attestation.PublicKey) == 0 || len(attestation.PublicKey) > maxBLSIdentityBytes ||
		len(attestation.Signature) == 0 || len(attestation.Signature) > maxBLSIdentityBytes {
		return nil, fmt.Errorf("invalid QUIC peer BLS key or signature length")
	}
	public := bls.GetPublicKey(attestation.PublicKey)
	if public == nil || !bytes.Equal(public.Serialize(), attestation.PublicKey) {
		return nil, fmt.Errorf("invalid or non-canonical QUIC peer BLS key")
	}
	var signature bls.Sign
	if err := signature.Deserialize(attestation.Signature); err != nil || !bytes.Equal(signature.Serialize(), attestation.Signature) {
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

func rawQUICPeerCertificates(certificates []*x509.Certificate) [][]byte {
	raw := make([][]byte, 0, len(certificates))
	for _, certificate := range certificates {
		if certificate != nil {
			raw = append(raw, certificate.Raw)
		}
	}
	return raw
}

func quicServerTLSConfig(auth *quicPeerAuthenticator) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		NextProtos:             []string{quicNextProto},
		ClientAuth:             tls.RequireAnyClientCert,
		SessionTicketsDisabled: true,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			_, _, _, certificate, err := auth.snapshot()
			if err != nil {
				return nil, err
			}
			return &certificate, nil
		},
		VerifyConnection: func(state tls.ConnectionState) error {
			chainID, _, _, _, err := auth.snapshot()
			if err != nil {
				return err
			}
			identity, err := parseAndVerifyQUICPeerCertificate(rawQUICPeerCertificates(state.PeerCertificates), chainID, "", nil)
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
		MinVersion:             tls.VersionTLS13,
		NextProtos:             []string{quicNextProto},
		InsecureSkipVerify:     true, // Replaced by the mandatory BLS-attestation verifier below.
		SessionTicketsDisabled: true,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			_, _, _, certificate, err := auth.snapshot()
			if err != nil {
				return nil, err
			}
			return &certificate, nil
		},
		VerifyConnection: func(state tls.ConnectionState) error {
			_, err := parseAndVerifyQUICPeerCertificate(rawQUICPeerCertificates(state.PeerCertificates), chainID, expected.Address.String(), expected.PublicKey)
			return err
		},
	}, nil
}
