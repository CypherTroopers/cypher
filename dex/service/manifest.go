package service

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/transport"
)

// Manifest is explicitly devnet-only. It contains public registration and paths,
// never private key material. Funding/deposit snapshots are not trusted from JSON.
type Manifest struct {
	Version                              uint16
	Devnet                               bool
	Mode                                 string
	Domain                               protocol.Domain
	Index                                uint8
	Members                              []*common.Cnode
	Peers                                []transport.Peer
	DataDir                              string
	VoteKeyFile, TLSCertFile, TLSKeyFile string
	APIListen                            string
	BootstrapSnapshotFile                string `json:",omitempty"`
	CLXHeight                            uint64
	CLXHash                              protocol.Hash
	MaxHeight                            uint64
	StorageGenerations                   bool   `json:",omitempty"`
	ArchiveBudgetBytes                   uint64 `json:",omitempty"`
	TimeoutMillis                        uint64
	Finance                              *NativeConfig `json:",omitempty"`
	// LeaderSubmission selects a local durable worker inside this DEX sidecar.
	// It changes neither CLX validity nor DEX voting membership.
	LeaderSubmission string `json:",omitempty"`
}

type NativeConfig struct {
	Market         engine.Config
	CLX            clxevidence.Config
	ReceiptHeights []uint64
}

func LoadManifest(path string) (Manifest, error) {
	var m Manifest
	b, err := regularRead(path, 64*1024, false)
	if err != nil {
		return m, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&m); err != nil {
		return Manifest{}, err
	}
	if err = d.Decode(new(interface{})); err != io.EOF {
		return Manifest{}, errors.New("trailing DEX manifest")
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func (m Manifest) Validate() error {
	if (m.Version != 1 && m.Version != 2) || !m.Devnet || (m.Mode != "counter" && m.Mode != "native-finance") || !m.Domain.Valid() || m.Index >= 7 || len(m.Members) != 7 || m.DataDir == "" || !filepath.IsAbs(m.DataDir) || m.CLXHash == (protocol.Hash{}) || m.MaxHeight < 2 || m.MaxHeight > consensus.MaxOperatingHeight || m.TimeoutMillis < 100 || m.TimeoutMillis > 30000 {
		return errors.New("invalid isolated DEX manifest")
	}
	if m.Version == 1 && (m.StorageGenerations || m.ArchiveBudgetBytes != 0 || m.MaxHeight > consensus.MaxRecords) {
		return errors.New("legacy manifest cannot select continuous storage")
	}
	if m.Version == 2 && (!m.StorageGenerations || m.ArchiveBudgetBytes == 0 || m.Mode != "native-finance" || m.Finance == nil || m.Finance.CLX.ChainConfig == nil || !m.Finance.CLX.ChainConfig.DEXDevnet.ContinuousStorage()) {
		return errors.New("continuous manifest requires authenticated config4 and finite archive budget")
	}
	if m.Finance != nil && m.Finance.CLX.ChainConfig != nil && m.Finance.CLX.ChainConfig.DEXDevnet.ContinuousStorage() != (m.Version == 2) {
		return errors.New("manifest version differs from financial genesis")
	}
	if (m.Mode == "counter") != (m.Finance == nil) {
		return errors.New("manifest financial mode/config mismatch")
	}
	if m.LeaderSubmission != "" && (m.Mode != "native-finance" || m.Version != 2 || !filepath.IsAbs(m.LeaderSubmission) || filepath.Clean(m.LeaderSubmission) != m.LeaderSubmission || m.Finance == nil || m.Finance.CLX.ChainConfig == nil || !m.Finance.CLX.ChainConfig.DEXDevnet.AncestryProofs()) {
		return errors.New("leader submission requires an absolute local config and authenticated financial config5")
	}
	if m.BootstrapSnapshotFile != "" && !filepath.IsAbs(m.BootstrapSnapshotFile) {
		return errors.New("absolute bootstrap snapshot path required")
	}
	if m.Finance != nil {
		f := m.Finance
		if m.Version == 2 && len(f.ReceiptHeights) != 0 {
			return errors.New("continuous financial generation uses every-height duties, not a receipt-height fixture")
		}
		if f.Market.Domain != m.Domain || !f.Market.NativeInbox || f.Market.CLXHeight != m.CLXHeight || f.Market.CLXHash != m.CLXHash || len(f.ReceiptHeights) > 128 || f.CLX.ChainConfig == nil || f.CLX.Genesis == nil {
			return errors.New("invalid native financial manifest")
		}
		for i, h := range f.ReceiptHeights {
			if h == 0 || h > m.MaxHeight || (i > 0 && h <= f.ReceiptHeights[i-1]) {
				return errors.New("invalid financial receipt fixture")
			}
		}
	}
	if _, err := transport.RegistryCommitment(m.Domain, m.Peers); err != nil {
		return err
	}
	for i, n := range m.Members {
		if n == nil || n.Address != m.Peers[i].ID || n.Public != m.Peers[i].BLSPublic {
			return errors.New("manifest registration differs between transport/FHS")
		}
	}
	for _, p := range []string{m.VoteKeyFile, m.TLSCertFile, m.TLSKeyFile} {
		if !filepath.IsAbs(p) {
			return errors.New("absolute dedicated DEX key paths required")
		}
	}
	if m.APIListen != "" {
		if err := transport.ValidateLoopback(m.APIListen, false); err != nil {
			return err
		}
	}
	return nil
}
func regularRead(path string, max int, secret bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > int64(max) || secret && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("unsafe DEX config/key file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return nil, errors.New("DEX file changed while opening")
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if len(b) > max {
		return nil, errors.New("DEX file byte bound")
	}
	return b, err
}
func prepareRoot(path string) error {
	const marker = "COMMON_DEX_SIDECAR_DEVNET_V1\n"
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err = os.Mkdir(path, 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(filepath.Join(path, "DEX_SIDECAR"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, w := f.WriteString(marker)
		s := f.Sync()
		cl := f.Close()
		if err = errors.Join(w, s, cl); err != nil {
			return err
		}
		for _, p := range []string{path, filepath.Dir(path)} {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			e := f.Sync()
			f.Close()
			if e != nil {
				return e
			}
		}
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe DEX sidecar directory")
	}
	b, err := regularRead(filepath.Join(path, "DEX_SIDECAR"), len(marker), false)
	if err != nil || string(b) != marker {
		return errors.New("refuse existing unowned sidecar directory")
	}
	return nil
}
func OpenManifest(m Manifest) (*Service, error) {
	if m.Mode != "counter" {
		return nil, errors.New("native mode requires authenticated financial factory")
	}
	c, err := ManifestConfig(m)
	if err != nil {
		return nil, err
	}
	return Open(c)
}

// ManifestConfig is called only in a sidecar constructor. The Common supervisor
// uses LoadManifest and never opens DEX secrets or stores.
func ManifestConfig(m Manifest) (Config, error) {
	if err := m.Validate(); err != nil {
		return Config{}, err
	}
	// Key reads are confined to this child-only constructor. The Common supervisor
	// reads only registration and compares its own CLX chain/genesis identity.
	secret, err := regularRead(m.VoteKeyFile, 256, true)
	if err != nil {
		return Config{}, err
	}
	key := new(bls.SecretKey)
	if err = key.DeserializeHexStr(strings.TrimSpace(string(secret))); err != nil {
		return Config{}, errors.New("invalid DEX vote key")
	}
	pem, err := regularRead(m.TLSCertFile, 8192, false)
	if err != nil {
		return Config{}, err
	}
	keyPEM, err := regularRead(m.TLSKeyFile, 8192, true)
	if err != nil {
		return Config{}, err
	}
	certificate, err := tls.X509KeyPair(pem, keyPEM)
	if err != nil {
		return Config{}, errors.New("invalid DEX TLS key pair")
	}
	if err = prepareRoot(m.DataDir); err != nil {
		return Config{}, err
	}
	registry, err := transport.RegistryCommitment(m.Domain, m.Peers)
	if err != nil {
		return Config{}, err
	}
	return Config{Consensus: consensus.Config{Domain: m.Domain, Members: m.Members, Index: int(m.Index), Secret: key, DataDir: filepath.Join(m.DataDir, "fhs"), CLXHeight: m.CLXHeight, CLXHash: m.CLXHash, MaxHeight: m.MaxHeight, StorageGenerations: m.StorageGenerations, ArchiveBudgetBytes: m.ArchiveBudgetBytes}, Transport: transport.Config{Domain: m.Domain, RegistryHash: registry, Index: m.Index, Peers: m.Peers, Certificate: certificate, DataDir: filepath.Join(m.DataDir, "outbox")}, APIListen: m.APIListen, BootstrapSnapshotFile: m.BootstrapSnapshotFile, Timeout: time.Duration(m.TimeoutMillis) * time.Millisecond}, nil
}
