package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/cypherium/cypher/dex/protocol"
)

type Peer struct {
	ID, Address, BLSPublic string
	RewardRecipient        [20]byte
	CertSHA256             protocol.Hash
}
type Config struct {
	Domain        protocol.Domain
	RegistryHash  protocol.Hash
	Index         uint8
	Peers         []Peer
	Certificate   tls.Certificate
	DataDir       string
	QueueLimit    int
	Timeout       time.Duration
	Retry         time.Duration
	RatePerSecond int
}

func RegistryCommitment(domain protocol.Domain, peers []Peer) (protocol.Hash, error) {
	if !domain.Valid() || len(peers) != 7 {
		return protocol.Hash{}, errors.New("seven registered TLS peers required")
	}
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, domain)
	ids, pins, keys, addrs := map[string]bool{}, map[protocol.Hash]bool{}, map[string]bool{}, map[string]bool{}
	for i, p := range peers {
		key, err := hex.DecodeString(p.BLSPublic)
		if err != nil || len(key) != 64 || bytes.Equal(key, make([]byte, 64)) || len(p.ID) == 0 || len(p.ID) > 128 || p.RewardRecipient == ([20]byte{}) || p.CertSHA256 == (protocol.Hash{}) || len(p.Address) > 128 {
			return protocol.Hash{}, errors.New("invalid TLS peer registration")
		}
		if err := ValidateLoopback(p.Address, false); err != nil {
			return protocol.Hash{}, err
		}
		if ids[p.ID] || pins[p.CertSHA256] || keys[string(key)] || addrs[p.Address] {
			return protocol.Hash{}, errors.New("duplicate registered TLS identity")
		}
		ids[p.ID], pins[p.CertSHA256], keys[string(key)], addrs[p.Address] = true, true, true, true
		b.WriteByte(byte(i))
		_ = binary.Write(&b, binary.BigEndian, uint16(len(p.ID)))
		b.WriteString(p.ID)
		_ = binary.Write(&b, binary.BigEndian, uint16(len(p.Address)))
		b.WriteString(p.Address)
		b.Write(key)
		b.Write(p.RewardRecipient[:])
		b.Write(p.CertSHA256[:])
	}
	return protocol.Digest("common-dex/socket-registry/v1", b.Bytes()), nil
}
func ValidateLoopback(addr string, allowZero bool) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("DEX endpoint must be numeric loopback host:port")
	}
	ip := net.ParseIP(host)
	n, e := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || e != nil || n < 0 || n > 65535 || n == 0 && !allowZero {
		return errors.New("DEX fixture endpoint must be loopback with valid port")
	}
	return nil
}
func (c Config) validate() error {
	hash, err := RegistryCommitment(c.Domain, c.Peers)
	if err != nil {
		return err
	}
	if hash != c.RegistryHash || c.Index >= 7 || c.QueueLimit < 1 || c.QueueLimit > 256 || c.Timeout < time.Millisecond*100 || c.Timeout > 30*time.Second || c.Retry < time.Millisecond*10 || c.Retry > 5*time.Second || c.RatePerSecond < 1 || c.RatePerSecond > 4096 {
		return errors.New("invalid bounded transport config")
	}
	if len(c.Certificate.Certificate) != 1 {
		return errors.New("one pinned TLS leaf required")
	}
	leaf, err := x509.ParseCertificate(c.Certificate.Certificate[0])
	if err != nil {
		return err
	}
	if _, ok := leaf.PublicKey.(ed25519.PublicKey); !ok {
		return errors.New("TLS fixture requires Ed25519")
	}
	if protocol.Hash(sha256.Sum256(leaf.Raw)) != c.Peers[c.Index].CertSHA256 {
		return errors.New("local TLS key not registered")
	}
	key, ok := c.Certificate.PrivateKey.(ed25519.PrivateKey)
	if !ok || !bytes.Equal(key.Public().(ed25519.PublicKey), leaf.PublicKey.(ed25519.PublicKey)) {
		return errors.New("TLS certificate/private key mismatch")
	}
	return nil
}
func (c Config) tlsConfig(expected int) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{c.Certificate}, ClientAuth: tls.RequireAnyClientCert, InsecureSkipVerify: true, // exact registration pin below replaces CA/DNS trust
		VerifyConnection: func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) != 1 {
				return errors.New("one registered peer certificate required")
			}
			leaf := s.PeerCertificates[0]
			if _, ok := leaf.PublicKey.(ed25519.PublicKey); !ok {
				return errors.New("wrong TLS key type")
			}
			if time.Now().Before(leaf.NotBefore) || time.Now().After(leaf.NotAfter) {
				return errors.New("expired TLS registration")
			}
			pin := protocol.Hash(sha256.Sum256(leaf.Raw))
			for i, p := range c.Peers {
				if p.CertSHA256 == pin && (expected < 0 || expected == i) {
					return nil
				}
			}
			return errors.New("unregistered TLS peer certificate")
		}}
}
