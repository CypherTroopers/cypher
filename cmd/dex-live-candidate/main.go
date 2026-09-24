// dex-live-candidate prepares a private, non-deployed generation proposal.
// It never contacts RPC/PM2, opens a live DB, initializes a datadir, or sends TXs.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/service"
	"github.com/cypherium/cypher/dex/service/finance"
	"github.com/cypherium/cypher/dex/transport"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
)

const oldChainID = 10101919
const candidateConfigVersion = 5
const workspace = "/root/work/cypher-FHS-D-ExchangeCore"

type keyInfo struct{ Purpose, Address, KeyFile string }
type participant struct {
	Name, CLXDataDir, DEXDataDir, Manifest, API, TLS string
	SubmissionConfig                                 string
	P2PPort, RnetPort                                int
	VotePublic, RewardRecipient                      string
	CommonWallet, CommonKeyFile                      string
}

// This mirrors the submission worker configuration used inside each DEX Common.
// The same bounded wire format remains available to standalone historical tests.
type relayPayer struct {
	Lane, Purpose string
	Address       common.Address
	KeyFile       string
	GasLimit      uint64
}
type relayManifest struct {
	Version                      uint16
	Devnet                       bool
	DataDir                      string
	Domain                       protocol.Domain
	Custody                      common.Address
	CLX                          clxevidence.Config
	SourceURL, SubmitURL, DEXURL string
	MaxHeight                    uint64
	AutoInbox                    bool
	DeferredRecipients           []common.Address
	PollMillis                   uint64
	GasPrice, MaxGasCost         string
	Payers                       []relayPayer
}
type inventory struct {
	Status                                                                                              string
	ResetAuthorized, Deployed, StorageGenerationReady                                                   bool
	ChainID                                                                                             uint64
	OldGenesis, Genesis, StateRoot, KeyGenesis, DEXID, DEXCommittee, TransportRegistry, BootstrapAnchor string
	ConfigurationVersion                                                                                uint16
	MaxHeight, MaxCheckpoints                                                                           uint64
	GenesisFile                                                                                         string
	GenesisSHA256                                                                                       string
	AllocPreserved, CLXCommitteePreserved                                                               bool
	ChainIDPreserved, OrdinaryCLXReplaySeparated                                                        bool
	CommonIdentitiesReused                                                                              bool
	ReusedCommonIdentitySource                                                                          string
	AllocEntries                                                                                        int
	Participants                                                                                        []participant
	Keys                                                                                                []keyInfo
	RelayConfigs                                                                                        []string `json:",omitempty"`
	LeaderSubmissionConfigs                                                                             []string `json:",omitempty"`
	Gates, Validation, FinancialAssumptions                                                             []string
	Funding                                                                                             []funding
}
type funding struct{ From, Recipient, Purpose, AmountAtoms string }

func main() {
	genesis := flag.String("genesis", filepath.Join(workspace, "genesis.json"), "read-only existing CLX genesis")
	out := flag.String("out", "", "new private candidate directory under workspace/build/stage")
	reuse := flag.String("reuse-common-identities-from", "", "private archived candidate; reuse only six Common wallet identities, never DEX or relay keys/state")
	prepare := flag.String("prepare-leader-submission-for", "", "prepare-only patch for an existing v5 candidate; preserve genesis, identities and all runtime data")
	deployment := flag.String("deployment", filepath.Join(workspace, "build/stage/live-deployment.json"), "existing active deployment selection for prepare-only mode")
	flag.Parse()
	if flag.NArg() != 0 || *out == "" || !filepath.IsAbs(*out) || !strings.HasPrefix(filepath.Clean(*out), filepath.Join(workspace, "build/stage")+string(os.PathSeparator)) {
		fmt.Fprintln(os.Stderr, "candidate output must be a new absolute directory under workspace/build/stage")
		os.Exit(2)
	}
	if *reuse != "" && (!filepath.IsAbs(*reuse) || !strings.HasPrefix(filepath.Clean(*reuse), filepath.Join(workspace, "build/stage")+string(os.PathSeparator))) {
		fmt.Fprintln(os.Stderr, "Common identity source must be an absolute archived candidate under workspace/build/stage")
		os.Exit(2)
	}
	if *prepare != "" {
		if *reuse != "" {
			fmt.Fprintln(os.Stderr, "identity reuse cannot be combined with in-place patch preparation")
			os.Exit(2)
		}
		plan, err := prepareLeaderSubmissionPatch(*prepare, *genesis, *deployment, *out)
		if err != nil {
			fmt.Fprintln(os.Stderr, "leader submission patch preparation failed:", err)
			os.Exit(1)
		}
		b, _ := json.MarshalIndent(plan, "", "  ")
		fmt.Println(string(b))
		return
	}
	i, err := generateWithCommonIdentities(*genesis, *out, *reuse)
	if err != nil {
		fmt.Fprintln(os.Stderr, "candidate preparation failed:", err)
		os.Exit(1)
	}
	// Only public information reaches stdout. Secrets are exclusively 0600 files.
	b, _ := json.MarshalIndent(i, "", "  ")
	fmt.Println(string(b))
}

func privateRoot(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("absolute clean output path required")
	}
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		s, e := os.Lstat(p)
		if e != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 {
			return errors.New("output ancestor is not a real directory")
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return os.Mkdir(path, 0700) // Existing outputs are never replaced or merged.
}
func put(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, w := f.Write(b)
	s := f.Sync()
	c := f.Close()
	return errors.Join(w, s, c)
}
func putJSON(path string, v interface{}) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return put(path, append(b, '\n'))
}
func digest(b []byte) string   { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func h(x protocol.Hash) string { return common.Hash(x).Hex() }

func newAccount(root, purpose string) (keyInfo, error) {
	k, e := crypto.GenerateKey()
	if e != nil {
		return keyInfo{}, e
	}
	i := keyInfo{Purpose: purpose, Address: crypto.PubkeyToAddress(k.PublicKey).Hex(), KeyFile: filepath.Join(root, "keys", purpose+".key")}
	if e = put(i.KeyFile, []byte(hex.EncodeToString(crypto.FromECDSA(k))+"\n")); e != nil {
		return keyInfo{}, e
	}
	return i, nil
}
func newTLS(root string, index int) (string, string, protocol.Hash, error) {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return "", "", protocol.Hash{}, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return "", "", protocol.Hash{}, e
	}
	now := time.Now().UTC()
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: fmt.Sprintf("private-common-dex-%d", index)}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, t, t, pub, key)
	if e != nil {
		return "", "", protocol.Hash{}, e
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return "", "", protocol.Hash{}, e
	}
	certPath := filepath.Join(root, "keys", fmt.Sprintf("dex-%d.crt", index))
	keyPath := filepath.Join(root, "keys", fmt.Sprintf("dex-%d.tls.key", index))
	if e = put(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); e != nil {
		return "", "", protocol.Hash{}, e
	}
	if e = put(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})); e != nil {
		return "", "", protocol.Hash{}, e
	}
	return certPath, keyPath, protocol.Hash(sha256.Sum256(der)), nil
}

func readGenesis(path string) (*core.Genesis, map[string]json.RawMessage, error) {
	s, e := os.Lstat(path)
	if e != nil {
		return nil, nil, e
	}
	if !s.Mode().IsRegular() || s.Size() > 1024*1024 {
		return nil, nil, errors.New("genesis file type/size")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, nil, e
	}
	var g core.Genesis
	var fields map[string]json.RawMessage
	if e = json.Unmarshal(b, &g); e != nil {
		return nil, nil, e
	}
	if e = json.Unmarshal(b, &fields); e != nil {
		return nil, nil, e
	}
	if g.Config == nil || g.Config.ChainID == nil || g.Config.ChainID.Cmp(big.NewInt(oldChainID)) != 0 || len(g.Config.GenCommittee) != 7 || !g.Config.FixedCommittee || !g.Config.FairHotstuff || g.Config.FixedLeader {
		return nil, nil, errors.New("expected preserved-chain fixed-seven generation")
	}
	if g.Config.DEXDevnet != nil {
		// The supported upgrade source is the current authenticated v4
		// deployment. Do not reinterpret an arbitrary future or legacy schema.
		if g.Config.DEXDevnet.Version != 4 {
			return nil, nil, errors.New("candidate upgrade requires source DEX configuration v4")
		}
		if e = g.Config.ValidateDEXDevnet(); e != nil {
			return nil, nil, e
		}
		commitment, err := params.FairHotstuffGenesisCommitment(g.Config)
		if err != nil || g.Mixhash != commitment {
			return nil, nil, errors.New("source DEX genesis configuration commitment mismatch")
		}
	}
	for i := 0; i < 7; i++ {
		if _, ok := g.Config.GenCommittee[i]; !ok {
			return nil, nil, errors.New("CLX committee indexes must be 0..6")
		}
	}
	return &g, fields, nil
}

func generate(genesisPath, out string) (*inventory, error) {
	return generateWithCommonIdentities(genesisPath, out, "")
}

type reusableCommonIdentity struct {
	address string
	encoded []byte
}

func privateOwnedDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("absolute clean identity directory required")
	}
	for p := path; ; p = filepath.Dir(p) {
		s, e := os.Lstat(p)
		if e != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 {
			return errors.New("identity directory ancestor is not a real directory")
		}
		if p == path {
			x, ok := s.Sys().(*syscall.Stat_t)
			if !ok || x.Uid != uint32(os.Getuid()) || s.Mode().Perm() != 0700 {
				return errors.New("identity directory must be private and owned")
			}
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return nil
}

func privateIdentityRead(path string, max int64) ([]byte, error) {
	s, e := os.Lstat(path)
	if e != nil {
		return nil, errors.New("identity file unavailable")
	}
	x, ok := s.Sys().(*syscall.Stat_t)
	if !ok || x.Uid != uint32(os.Getuid()) || x.Nlink != 1 || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || s.Size() > max {
		return nil, errors.New("identity file type, owner, permissions or size")
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, errors.New("identity no-follow open failed")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(s, actual) {
		return nil, errors.New("identity file changed during open")
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) != s.Size() {
		return nil, errors.New("identity file changed during read")
	}
	return b, nil
}

func reusableCommonIdentities(root string) (map[string]reusableCommonIdentity, error) {
	if err := privateOwnedDirectory(root); err != nil {
		return nil, err
	}
	for _, sub := range []string{"keys", "public"} {
		if err := privateOwnedDirectory(filepath.Join(root, sub)); err != nil {
			return nil, err
		}
	}
	raw, err := privateIdentityRead(filepath.Join(root, "public", "inventory.json"), 1024*1024)
	if err != nil {
		return nil, err
	}
	var old inventory
	if err = json.Unmarshal(raw, &old); err != nil {
		return nil, errors.New("identity inventory invalid")
	}
	original := filepath.Dir(old.GenesisFile)
	if !filepath.IsAbs(original) || filepath.Clean(original) != original || len(old.Participants) != 7 {
		return nil, errors.New("identity source inventory layout")
	}
	participants := map[string]participant{}
	for _, p := range old.Participants {
		if _, exists := participants[p.Name]; exists {
			return nil, errors.New("duplicate Common identity")
		}
		participants[p.Name] = p
	}
	if p, ok := participants["cyphermine"]; !ok || p.CommonWallet != "0xeb8c07def4c5a2541de730b027376e1068aa861a" || p.CommonKeyFile != "" {
		return nil, errors.New("original Common identity changed")
	}
	keys := map[string]keyInfo{}
	for _, k := range old.Keys {
		if _, exists := keys[k.Purpose]; exists {
			return nil, errors.New("duplicate identity purpose")
		}
		keys[k.Purpose] = k
	}
	out := map[string]reusableCommonIdentity{}
	addresses := map[common.Address]bool{}
	for n := 1; n <= 6; n++ {
		name := fmt.Sprintf("cypherdex%d", n)
		purpose := name + "-common-wallet"
		p, found := participants[name]
		k, haveKey := keys[purpose]
		// Inventory paths still refer to the original root after whole-directory
		// archival. Accept only this exact relative key, then read the new archive.
		want := filepath.Join(original, "keys", purpose+".key")
		if !found || !haveKey || p.CommonKeyFile != want || k.KeyFile != want || !common.IsHexAddress(p.CommonWallet) || p.CommonWallet != k.Address {
			return nil, errors.New("Common identity inventory binding")
		}
		encoded, e := privateIdentityRead(filepath.Join(root, "keys", purpose+".key"), 256)
		if e != nil {
			return nil, e
		}
		key, e := crypto.HexToECDSA(strings.TrimSpace(string(encoded)))
		if e != nil {
			return nil, errors.New("Common private identity encoding")
		}
		address := crypto.PubkeyToAddress(key.PublicKey)
		if address != common.HexToAddress(p.CommonWallet) || addresses[address] {
			return nil, errors.New("Common key/address mismatch or duplicate")
		}
		addresses[address] = true
		out[purpose] = reusableCommonIdentity{address: address.Hex(), encoded: encoded}
	}
	return out, nil
}

func generateWithCommonIdentities(genesisPath, out, identityRoot string) (*inventory, error) {
	g, fields, e := readGenesis(genesisPath)
	if e != nil {
		return nil, e
	}
	oldBlock := g.ToBlock(nil)
	oldAlloc, _ := json.Marshal(g.Alloc)
	oldCommittee, _ := json.Marshal(g.Config.GenCommittee)
	var commonIdentities map[string]reusableCommonIdentity
	if identityRoot != "" {
		oldRoot, newRoot := filepath.Clean(identityRoot), filepath.Clean(out)
		if oldRoot == newRoot || strings.HasPrefix(newRoot, oldRoot+string(os.PathSeparator)) || strings.HasPrefix(oldRoot, newRoot+string(os.PathSeparator)) {
			return nil, errors.New("archive and new output must be disjoint")
		}
		commonIdentities, e = reusableCommonIdentities(identityRoot)
		if e != nil {
			return nil, e
		}
	}
	if e = privateRoot(out); e != nil {
		return nil, e
	}
	for _, d := range []string{"keys", "manifests", "submissions", "public"} {
		if e = os.Mkdir(filepath.Join(out, d), 0700); e != nil {
			return nil, e
		}
	}
	if e = put(filepath.Join(out, "CANDIDATE_ONLY"), []byte("NOT_DEPLOYED; USER_PERFORMS_INIT; CHAIN_ID_PRESERVED; ORDINARY_CLX_REPLAY_NOT_SEPARATED\n")); e != nil {
		return nil, e
	}
	i := &inventory{Status: "BLOCKED", ChainID: g.Config.ChainID.Uint64(), ChainIDPreserved: true, OrdinaryCLXReplaySeparated: false, OldGenesis: oldBlock.Hash().Hex(), ConfigurationVersion: candidateConfigVersion, MaxHeight: 4096, MaxCheckpoints: 4096, AllocEntries: len(g.Alloc), Gates: []string{"USER_PERFORMS_INIT; generator never initializes or restarts the network", "Same CLX chain ID retained: ordinary CLX signature replay is not separated by genesis or DEX ID", "Bounded-history finality v5 implementation/review and LIVE verification remain separate from candidate validation", "Integrated leader submission CLI validation NOT_RUN; local shape and trust checked only", "Live port availability/PM2/resource budget NOT_RUN", "No live data/init/PM2/signing/network operations executed"}, FinancialAssumptions: []string{"BTC/CLX only; synthetic oracle; fixed DEX epoch 1, seven equal voters and quorum five", "No pre-credited deposits/support/insurance; every new key has zero genesis allocation", "Existing CLX chain ID, alloc and committee retained; old ordinary EIP-155 and unprotected TX signatures may remain valid when nonce and balances recur. Fresh DEX domain does not prevent ordinary CLX TX replay", "Never import old raw TX, nonce or ingress/relay queues; do not claim this operational restriction is cryptographic replay protection", "Existing market fee/funding/reward fixture economics preserved; not production settings"}}
	i.CommonIdentitiesReused, i.ReusedCommonIdentitySource = identityRoot != "", identityRoot
	accounts := map[string]keyInfo{}
	for _, purpose := range []string{"trader-a", "trader-b", "synthetic-oracle", "insurance-owner", "support-owner"} {
		a, err := newAccount(out, purpose)
		if err != nil {
			return nil, err
		}
		accounts[purpose] = a
		i.Keys = append(i.Keys, a)
	}
	var dexID protocol.Hash
	if _, e = rand.Read(dexID[:]); e != nil {
		return nil, e
	}
	if dexID == (protocol.Hash{}) {
		return nil, errors.New("zero random DEX domain")
	}
	seed, e := protocol.NativeMarketSeed([20]byte(common.HexToAddress(accounts["synthetic-oracle"].Address)))
	if e != nil {
		return nil, e
	}
	members := make([]*common.Cnode, 7)
	peers := make([]transport.Peer, 7)
	manifests := make([]service.Manifest, 7)
	for n := 0; n < 7; n++ {
		var k bls.SecretKey
		k.SetByCSPRNG()
		vote := filepath.Join(out, "keys", fmt.Sprintf("dex-%d.vote.key", n))
		if e = put(vote, []byte(k.SerializeToHexStr()+"\n")); e != nil {
			return nil, e
		}
		cert, secret, pin, err := newTLS(out, n)
		if err != nil {
			return nil, err
		}
		reward, err := newAccount(out, fmt.Sprintf("dex-%d-reward", n))
		if err != nil {
			return nil, err
		}
		i.Keys = append(i.Keys, reward)
		addr := fmt.Sprintf("127.0.0.1:%d", 18000+n)
		api := fmt.Sprintf("127.0.0.1:%d", 19000+n)
		peers[n] = transport.Peer{ID: addr, Address: addr, BLSPublic: k.GetPublicKey().SerializeToHexStr(), RewardRecipient: [20]byte(common.HexToAddress(reward.Address)), CertSHA256: pin}
		members[n] = &common.Cnode{Address: addr, Public: peers[n].BLSPublic, CoinBase: reward.Address}
		name := fmt.Sprintf("cypherdex%d", n)
		clxdir := filepath.Join(workspace, "build/stage/live-commons", fmt.Sprintf("chaindbdex%d", n))
		p2p, rnet := 6200+n, 7200+2*n
		commonWallet, commonKey := "0xeb8c07def4c5a2541de730b027376e1068aa861a", ""
		if n == 0 {
			name = "cyphermine"
			clxdir = filepath.Join(workspace, "chaindbmine")
			p2p, rnet = 6099, 7155
		} else {
			purpose := name + "-common-wallet"
			var wallet keyInfo
			var err error
			if reused, ok := commonIdentities[purpose]; ok {
				wallet = keyInfo{Purpose: purpose, Address: reused.address, KeyFile: filepath.Join(out, "keys", purpose+".key")}
				err = put(wallet.KeyFile, reused.encoded)
			} else {
				wallet, err = newAccount(out, purpose)
			}
			if err != nil {
				return nil, err
			}
			i.Keys = append(i.Keys, wallet)
			commonWallet, commonKey = wallet.Address, wallet.KeyFile
		}
		manifest := filepath.Join(out, "manifests", name+".json")
		data := filepath.Join(out, "runtime", name, "dex")
		i.Participants = append(i.Participants, participant{Name: name, CLXDataDir: clxdir, DEXDataDir: data, Manifest: manifest, API: api, TLS: addr, P2PPort: p2p, RnetPort: rnet, VotePublic: peers[n].BLSPublic, RewardRecipient: reward.Address, CommonWallet: commonWallet, CommonKeyFile: commonKey})
		manifests[n] = service.Manifest{Version: 2, StorageGenerations: true, ArchiveBudgetBytes: 256 * 1024 * 1024, Devnet: true, Mode: "native-finance", Index: uint8(n), Members: members, Peers: peers, DataDir: data, VoteKeyFile: vote, TLSCertFile: cert, TLSKeyFile: secret, APIListen: api, MaxHeight: 4096, TimeoutMillis: 4000}
	}
	// Preserve the user's CLX chain ID exactly. Genesis/DEX deployment changes
	// bind DEX authentication but do not isolate ordinary CLX transaction signatures.
	registered := make([]common.Cnode, 7)
	for n, m := range members {
		registered[n] = *m
	}
	g.Config.DEXDevnet = &params.DEXDevnetConfig{Version: candidateConfigVersion, ActivationBlock: 1, DEXID: common.Hash(dexID), GenesisSeed: common.Hash(seed), Custody: params.DEXSettlementAddress, Committee: registered, MaxCheckpoints: 4096}
	g.Mixhash, e = params.FairHotstuffGenesisCommitment(g.Config)
	if e != nil {
		return nil, e
	}
	// Keep every existing JSON configuration value. Marshaling the whole Go
	// struct would add defaults or normalize unrelated legacy fields.
	var configFields map[string]json.RawMessage
	if e = json.Unmarshal(fields["config"], &configFields); e != nil {
		return nil, e
	}
	configFields["dexDevnet"], e = json.Marshal(g.Config.DEXDevnet)
	if e != nil {
		return nil, e
	}
	fields["config"], e = json.Marshal(configFields)
	if e != nil {
		return nil, e
	}
	fields["mixHash"], _ = json.Marshal(g.Mixhash)
	// Preserve every original top-level field/alloc, including GenesisKey fields.
	genesisRaw, e := json.MarshalIndent(fields, "", "  ")
	if e != nil {
		return nil, e
	}
	genesisRaw = append(genesisRaw, '\n')
	i.GenesisFile = filepath.Join(out, "genesis.json")
	if e = put(i.GenesisFile, genesisRaw); e != nil {
		return nil, e
	}
	i.GenesisSHA256 = digest(genesisRaw)
	var actual core.Genesis
	var keyGenesis core.GenesisKey
	if e = json.Unmarshal(genesisRaw, &actual); e != nil {
		return nil, e
	}
	if e = json.Unmarshal(genesisRaw, &keyGenesis); e != nil {
		return nil, e
	}
	db := rawdb.NewMemoryDatabase()
	defer db.Close()
	bftview.SetCommitteeConfig(db, nil, nil)
	_, keyHash, e := core.SetupGenesisKeyBlock(db, &keyGenesis)
	if e != nil {
		return nil, e
	}
	_, blockHash, e := core.SetupGenesisBlock(db, &actual)
	if e != nil {
		return nil, e
	}
	block := actual.ToBlock(nil)
	if block.Hash() != blockHash {
		return nil, errors.New("formal genesis derivation mismatch")
	}
	alloc, _ := json.Marshal(actual.Alloc)
	committee, _ := json.Marshal(actual.Config.GenCommittee)
	i.AllocPreserved = string(alloc) == string(oldAlloc)
	i.CLXCommitteePreserved = string(committee) == string(oldCommittee)
	if !i.AllocPreserved || !i.CLXCommitteePreserved {
		return nil, errors.New("candidate modified original allocations/CLX identities")
	}
	clxMembers := make([]*common.Cnode, 7)
	for n := range clxMembers {
		m := actual.Config.GenCommittee[n]
		clxMembers[n] = &m
	}
	if actual.Config.ChainID.Cmp(g.Config.ChainID) != 0 || actual.Config.ChainID.Uint64() != i.ChainID {
		return nil, errors.New("candidate changed the preserved CLX chain ID")
	}
	domain := protocol.Domain{Version: 1, ChainID: i.ChainID, Genesis: protocol.Hash(blockHash), DEXID: dexID, Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: members}).RlpHash())}
	trust := clxevidence.Config{ChainID: i.ChainID, Genesis: block.Header(), ChainConfig: actual.Config, Seed: actual.Config.FairHotstuffSeed, DEXID: dexID, Custody: params.DEXSettlementAddress, Epochs: []clxevidence.CommitteeEpoch{{First: 1, End: math.MaxUint64, KeyHash: keyHash, Members: clxMembers}}}
	verifier, e := clxevidence.New(trust)
	if e != nil {
		return nil, e
	}
	anchor, e := verifier.BootstrapAnchor()
	if e != nil {
		return nil, e
	}
	anchorID, e := anchor.ID()
	if e != nil {
		return nil, e
	}
	registry, e := transport.RegistryCommitment(domain, peers)
	if e != nil {
		return nil, e
	}
	if _, e = checkpoint.NewEpoch(domain, 1, 4097, members); e != nil {
		return nil, e
	}
	i.Genesis = blockHash.Hex()
	i.StateRoot = block.Root().Hex()
	i.KeyGenesis = keyHash.Hex()
	i.DEXID = h(dexID)
	i.DEXCommittee = h(domain.Committee)
	i.TransportRegistry = h(registry)
	i.BootstrapAnchor = h(anchorID)
	for n := 0; n < len(manifests); n++ {
		m := relayManifest{Version: 2, Devnet: true, DataDir: filepath.Join(i.Participants[n].DEXDataDir, "submission"), Domain: domain, Custody: params.DEXSettlementAddress, CLX: trust, SourceURL: "http://127.0.0.1:8999", SubmitURL: "http://127.0.0.1:8999", DEXURL: "http://" + i.Participants[n].API, MaxHeight: 4096, AutoInbox: true, PollMillis: 500, GasPrice: "1000000000", MaxGasCost: "100000000000000000"}
		for _, lane := range []string{"anchor", "checkpoint", "claim"} {
			a, err := newAccount(out, fmt.Sprintf("submission-%d-%s-gas", n, lane))
			if err != nil {
				return nil, err
			}
			i.Keys = append(i.Keys, a)
			m.Payers = append(m.Payers, relayPayer{Lane: lane, Purpose: "leader-submission-gas", Address: common.HexToAddress(a.Address), KeyFile: a.KeyFile, GasLimit: 20000000})
			budget := "1000000000000000000"
			if lane == "checkpoint" {
				budget = "6000000000000000000"
			}
			i.Funding = append(i.Funding, funding{From: actual.Config.GenCommittee[0].CoinBase, Recipient: a.Address, Purpose: a.Purpose, AmountAtoms: budget})
		}
		path := filepath.Join(out, "submissions", i.Participants[n].Name+".json")
		if e = putJSON(path, m); e != nil {
			return nil, e
		}
		i.LeaderSubmissionConfigs = append(i.LeaderSubmissionConfigs, path)
		i.Participants[n].SubmissionConfig = path
		manifests[n].LeaderSubmission = path
	}
	for n := range manifests {
		m := &manifests[n]
		m.Domain = domain
		m.CLXHash = domain.Genesis
		m.Finance = &service.NativeConfig{Market: engine.Config{Domain: domain, Oracle: [20]byte(common.HexToAddress(accounts["synthetic-oracle"].Address)), Custody: [20]byte(params.DEXSettlementAddress), Support: "0", Insurance: "0", CLXHash: domain.Genesis, NativeInbox: true}, CLX: trust, ReceiptHeights: nil}
		if e = validateManifest(*m, seed); e != nil {
			return nil, e
		}
		if e = putJSON(i.Participants[n].Manifest, m); e != nil {
			return nil, e
		}
		loaded, err := service.LoadManifest(i.Participants[n].Manifest)
		if err != nil {
			return nil, err
		}
		encoded, _ := json.Marshal(loaded)
		original, _ := json.Marshal(m)
		if string(encoded) != string(original) {
			return nil, errors.New("manifest JSON roundtrip drift")
		}
	}
	for purpose, amount := range map[string]string{"trader-a": "105000000000000000000", "trader-b": "105000000000000000000", "support-owner": "21000000000000000000", "insurance-owner": "6000000000000000000", "synthetic-oracle": "1000000000000000000"} {
		a := accounts[purpose]
		i.Funding = append(i.Funding, funding{From: actual.Config.GenCommittee[0].CoinBase, Recipient: a.Address, Purpose: purpose + "; subsequent ordinary signed deposit, no direct StateDB mutation", AmountAtoms: amount})
	}
	i.Validation = []string{"core.SetupGenesisKeyBlock(memory DB) before core.SetupGenesisBlock(memory DB), same ordinary CLI init order", "genesis ToBlock matches formal committed hash; original CLX chain ID, allocations and seven committee identities unchanged", "clxevidence.New and BootstrapAnchor authenticate actual header/config/first historical key hash", "checkpoint.NewEpoch and transport.RegistryCommitment check seven distinct DEX identities", "all seven service.LoadManifest JSON roundtrips and finance.ValidateRegistration pass", "all seven TLS private/certificate matches and canonical BLS vote keys match registered public identities", "candidate-only: no live datadir open, no network, no PM2, no consensus votes/CLX transactions"}
	if e = putJSON(filepath.Join(out, "public", "inventory.json"), i); e != nil {
		return nil, e
	}
	for _, d := range []string{"keys", "manifests", "submissions", "public", ""} {
		f, err := os.Open(filepath.Join(out, d))
		if err != nil {
			return nil, err
		}
		err = errors.Join(f.Sync(), f.Close())
		if err != nil {
			return nil, err
		}
	}
	return i, nil
}

func validateManifest(m service.Manifest, seed protocol.Hash) error {
	if e := m.Validate(); e != nil {
		return e
	}
	if e := finance.ValidateRegistration(m, seed); e != nil {
		return e
	}
	v, e := clxevidence.New(m.Finance.CLX)
	if e != nil {
		return e
	}
	if _, e = v.BootstrapAnchor(); e != nil {
		return e
	}
	b, e := os.ReadFile(m.VoteKeyFile)
	if e != nil {
		return e
	}
	var key bls.SecretKey
	if key.DeserializeHexStr(strings.TrimSpace(string(b))) != nil || key.GetPublicKey().SerializeToHexStr() != m.Peers[m.Index].BLSPublic {
		return errors.New("candidate vote key does not match registry")
	}
	cert, e := tls.LoadX509KeyPair(m.TLSCertFile, m.TLSKeyFile)
	if e != nil {
		return errors.New("candidate TLS key pair invalid")
	}
	if len(cert.Certificate) != 1 || protocol.Hash(sha256.Sum256(cert.Certificate[0])) != m.Peers[m.Index].CertSHA256 {
		return errors.New("candidate TLS certificate pin mismatch")
	}
	for _, path := range []string{m.VoteKeyFile, m.TLSKeyFile} {
		s, e := os.Lstat(path)
		if e != nil || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 {
			return errors.New("candidate secret permissions")
		}
	}
	return nil
}
