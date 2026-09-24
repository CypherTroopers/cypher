package testnet

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
	"github.com/cypherium/cypher/dex/transport"
)

const ownerMarker = "COMMON_DEX_FINANCIAL_PROCESS_TEST_V1\n"

type diskIdentity struct {
	Index                           int
	Public                          Identity
	Secret, Certificate, TLSPrivate []byte
}
type actionDisk struct {
	Config       protocol.Hash
	Actions      map[uint64][]byte
	Certificates map[string][]byte
}
type diskEnvelope struct {
	Payload json.RawMessage
	Hash    protocol.Hash
}

func strict(raw []byte, v interface{}) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(interface{})) != io.EOF {
		return errors.New("trailing control JSON")
	}
	return nil
}
func readRegular(path string, limit int) ([]byte, error) {
	f, err := noFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > int64(limit) {
		return nil, errors.New("helper file bound/type")
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if len(b) > limit {
		return nil, errors.New("helper file bound")
	}
	return b, err
}
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func saveFile(dir, name string, v interface{}) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(raw) > MaxControlBytes {
		return errors.New("helper state byte bound")
	}
	e := diskEnvelope{raw, protocol.Digest("common-dex/process-state/v1", raw)}
	raw, err = json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".state-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, werr := f.Write(raw)
	serr := f.Sync()
	cerr := f.Close()
	if err = errors.Join(werr, serr, cerr); err != nil {
		return err
	}
	if err = os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	return syncDirectory(dir)
}
func loadFile(dir, name string, v interface{}) error {
	raw, err := readRegular(filepath.Join(dir, name), MaxControlBytes+1024)
	if err != nil {
		return err
	}
	var e diskEnvelope
	if err = strict(raw, &e); err != nil {
		return err
	}
	if len(e.Payload) > MaxControlBytes || e.Hash != protocol.Digest("common-dex/process-state/v1", e.Payload) {
		return errors.New("helper state checksum")
	}
	return strict(e.Payload, v)
}
func openIdentity(dir string, index int) (diskIdentity, *os.File, error) {
	var d diskIdentity
	if index < 0 || index >= 7 || !filepath.IsAbs(dir) {
		return d, nil, errors.New("helper index/path")
	}
	if err := platform(); err != nil {
		return d, nil, err
	}
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		if err = os.Mkdir(dir, 0700); err != nil {
			return d, nil, err
		}
		f, e := noFollow(filepath.Join(dir, "OWNER"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return d, nil, e
		}
		_, we := f.WriteString(ownerMarker)
		se := f.Sync()
		ce := f.Close()
		if e = errors.Join(we, se, ce, syncDirectory(dir), syncDirectory(filepath.Dir(dir))); e != nil {
			return d, nil, e
		}
	} else if err != nil {
		return d, nil, err
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return d, nil, errors.New("helper directory type")
	}
	marker, err := readRegular(filepath.Join(dir, "OWNER"), len(ownerMarker))
	if err != nil || string(marker) != ownerMarker {
		return d, nil, errors.New("refuse unowned helper directory")
	}
	lock, err := noFollow(filepath.Join(dir, "LOCK"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return d, nil, err
	}
	info, err = lock.Stat()
	if err != nil || !info.Mode().IsRegular() {
		lock.Close()
		return d, nil, errors.New("helper lock type")
	}
	if err = lockFile(lock); err != nil {
		lock.Close()
		return d, nil, err
	}
	ok := false
	defer func() {
		if !ok {
			lock.Close()
		}
	}()
	if err = loadFile(dir, "identity.json", &d); os.IsNotExist(err) {
		d.Index = index
		var key bls.SecretKey
		key.SetByCSPRNG()
		d.Secret = key.Serialize()
		public, private, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return d, nil, e
		}
		d.TLSPrivate = private
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(index + 1)), Subject: pkix.Name{CommonName: fmt.Sprintf("devnet-process-%d", index)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
		d.Certificate, e = x509.CreateCertificate(rand.Reader, template, template, public, private)
		if e != nil {
			return d, nil, e
		}
		// Separate loopback interfaces allow the enclosing network namespace to
		// partition real peer sockets without a production fault-control API.
		listen := fmt.Sprintf("127.0.0.%d:0", index+2)
		listener, e := net.Listen("tcp", listen)
		if e != nil {
			return d, nil, e
		}
		addr := listener.Addr().String()
		listener.Close()
		var recipient [20]byte
		if _, e = rand.Read(recipient[:]); e != nil {
			return d, nil, e
		}
		peer := transport.Peer{ID: addr, Address: addr, BLSPublic: key.GetPublicKey().SerializeToHexStr(), RewardRecipient: recipient, CertSHA256: protocol.Hash(sha256.Sum256(d.Certificate))}
		apiListener, e := net.Listen("tcp", listen)
		if e != nil {
			return d, nil, e
		}
		api := apiListener.Addr().String()
		apiListener.Close()
		d.Public = Identity{Peer: peer, Member: &common.Cnode{Address: peer.ID, Public: peer.BLSPublic, CoinBase: common.Address(recipient).Hex()}, API: api}
		if err = saveFile(dir, "identity.json", d); err != nil {
			return d, nil, err
		}
	} else if err != nil {
		return d, nil, err
	}
	var secret bls.SecretKey
	secretInfo, err := os.Lstat(filepath.Join(dir, "identity.json"))
	if err != nil || secretInfo.Mode().Perm()&0077 != 0 {
		return d, nil, errors.New("unsafe helper secret permissions")
	}
	if err = transport.ValidateLoopback(d.Public.API, false); err != nil {
		return d, nil, err
	}
	if d.Index != index || d.Public.Member == nil || secret.Deserialize(d.Secret) != nil || d.Public.Peer.BLSPublic != secret.GetPublicKey().SerializeToHexStr() || len(d.TLSPrivate) != ed25519.PrivateKeySize || d.Public.Peer.CertSHA256 != protocol.Hash(sha256.Sum256(d.Certificate)) {
		return d, nil, errors.New("helper persisted identity mismatch")
	}
	leaf, err := x509.ParseCertificate(d.Certificate)
	if err != nil {
		return d, nil, err
	}
	pub, good := leaf.PublicKey.(ed25519.PublicKey)
	if !good || !bytes.Equal(pub, ed25519.PrivateKey(d.TLSPrivate).Public().(ed25519.PublicKey)) {
		return d, nil, errors.New("helper TLS secret mismatch")
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(d.TLSPrivate))
	if err != nil {
		return d, nil, err
	}
	paths := []string{filepath.Join(dir, "vote.key"), filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")}
	payloads := [][]byte{[]byte(secret.SerializeToHexStr() + "\n"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d.Certificate}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})}
	for i, path := range paths {
		if err = ownedKeyFile(path, payloads[i]); err != nil {
			return d, nil, err
		}
	}
	if d.Public.VoteKeyFile != paths[0] || d.Public.TLSCertFile != paths[1] || d.Public.TLSKeyFile != paths[2] {
		d.Public.VoteKeyFile, d.Public.TLSCertFile, d.Public.TLSKeyFile = paths[0], paths[1], paths[2]
		if err = saveFile(dir, "identity.json", d); err != nil {
			return d, nil, err
		}
	}
	ok = true
	return d, lock, nil
}
func ownedKeyFile(path string, raw []byte) error {
	f, err := noFollow(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if os.IsExist(err) {
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("unsafe existing helper key export")
		}
		existing, e := readRegular(path, 8192)
		if e != nil {
			return e
		}
		if !bytes.Equal(existing, raw) {
			return errors.New("refuse replacing existing helper key export")
		}
		return nil
	}
	if err != nil {
		return err
	}
	_, w := f.Write(raw)
	s := f.Sync()
	c := f.Close()
	return errors.Join(w, s, c, syncDirectory(filepath.Dir(path)))
}
func (d diskIdentity) tls() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{bytes.Clone(d.Certificate)}, PrivateKey: ed25519.PrivateKey(bytes.Clone(d.TLSPrivate))}
}
func loadActions(dir string, hash protocol.Hash, registry *rewards.Registry) (actionDisk, error) {
	var d actionDisk
	err := loadFile(dir, "actions.json", &d)
	if os.IsNotExist(err) {
		d = actionDisk{hash, map[uint64][]byte{}, map[string][]byte{}}
		err = saveFile(dir, "actions.json", d)
	}
	if err != nil {
		return d, err
	}
	if d.Config != hash || d.Actions == nil || d.Certificates == nil || len(d.Actions) > 128 || len(d.Certificates) > 128*7 {
		return d, errors.New("helper queue identity/count")
	}
	total := 0
	for h, b := range d.Actions {
		if h == 0 || h > 128 || len(b) == 0 || len(b) > 64*1024 {
			return d, errors.New("helper persisted action bound")
		}
		total += len(b)
	}
	if total > 1024*1024 {
		return d, errors.New("helper persisted queue bytes")
	}
	for id, b := range d.Certificates {
		c, e := rewards.DecodeCertificate(b)
		if e != nil {
			return d, e
		}
		if e = registry.VerifyCertificate(c); e != nil {
			return d, e
		}
		h, _ := c.Duty.Hash()
		if id != fmt.Sprintf("%x", h) {
			return d, errors.New("helper certificate key")
		}
	}
	return d, nil
}
