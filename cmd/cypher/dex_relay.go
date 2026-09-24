package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/relay"
	"github.com/cypherium/cypher/params"
	cli "gopkg.in/urfave/cli.v1"
)

var dexRelayCommand = cli.Command{Name: "dex-relay", Usage: "Run an explicitly configured isolated native settlement relay", Flags: []cli.Flag{cli.StringFlag{Name: "relay.config", Usage: "Absolute isolated relay JSON configuration"}, cli.BoolFlag{Name: "relay.once", Usage: "Run one discovery and durable-step iteration"}, cli.DurationFlag{Name: "relay.duration", Usage: "Stop this relay after an explicit duration (maximum24h)"}}, Action: runDEXRelay}

type relayCLIPayer struct {
	Lane, Purpose string
	Address       common.Address
	KeyFile       string
	GasLimit      uint64
}
type relayCLIManifest struct {
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
	Payers                       []relayCLIPayer
}

func relayLane(name string) (relay.Lane, error) {
	switch name {
	case "anchor":
		return relay.Anchor, nil
	case "checkpoint":
		return relay.Checkpoint, nil
	case "claim":
		return relay.Claim, nil
	default:
		return 0, errors.New("relay payer lane must be anchor/checkpoint/claim")
	}
}

func relayURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("invalid relay endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 || ip == nil || !ip.IsLoopback() || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("relay endpoints require numeric loopback HTTP with explicit port")
	}
	return nil
}
func relayRegularRead(path string, max int, secret bool) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("absolute relay file path required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > int64(max) || (secret && (info.Mode().Perm() != 0600 || !relayOwned(info))) {
		return nil, errors.New("unsafe relay configuration/gas-key file")
	}
	f, err := relayNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return nil, errors.New("relay file changed while opening")
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if len(b) > max {
		return nil, errors.New("relay file size bound")
	}
	return b, err
}
func relayNoDuplicateJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return errors.New("relay JSON nesting bound")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				name = strings.ToLower(name)
				if !ok || seen[name] {
					return errors.New("duplicate relay JSON field")
				}
				seen[name] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("relay JSON object")
			}
		case '[':
			for d.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("relay JSON array")
			}
		default:
			return errors.New("relay JSON delimiter")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing relay JSON")
	}
	return nil
}
func loadRelayCLIManifest(path string) (relayCLIManifest, error) {
	var m relayCLIManifest
	raw, err := relayRegularRead(path, 128*1024, false)
	if err != nil {
		return m, err
	}
	if err = relayNoDuplicateJSON(raw); err != nil {
		return m, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&m); err != nil {
		return m, err
	}
	// Some nested upstream types implement custom JSON decoders. Verify they
	// did not silently discard an input field despite DisallowUnknownFields.
	canonical, err := json.Marshal(m)
	if err != nil {
		return m, err
	}
	var supplied, retained interface{}
	if err = json.Unmarshal(raw, &supplied); err != nil {
		return m, err
	}
	if err = json.Unmarshal(canonical, &retained); err != nil {
		return m, err
	}
	if err = relayRetainedJSONFields(supplied, retained); err != nil {
		return m, err
	}
	if _, err = m.config(); err != nil {
		return relayCLIManifest{}, err
	}
	return m, nil
}

func relayRetainedJSONFields(input, canonical interface{}) error {
	switch in := input.(type) {
	case map[string]interface{}:
		out, ok := canonical.(map[string]interface{})
		if !ok {
			return errors.New("relay custom JSON field was discarded")
		}
		for key, value := range in {
			found := false
			for canonicalKey, canonicalValue := range out {
				if strings.EqualFold(key, canonicalKey) {
					found = true
					if err := relayRetainedJSONFields(value, canonicalValue); err != nil {
						return err
					}
					break
				}
			}
			if !found {
				return errors.New("unsupported or discarded nested relay JSON field")
			}
		}
	case []interface{}:
		out, ok := canonical.([]interface{})
		if !ok || len(in) != len(out) {
			return errors.New("relay JSON collection changed during decode")
		}
		for i, value := range in {
			if err := relayRetainedJSONFields(value, out[i]); err != nil {
				return err
			}
		}
	}
	return nil
}
func relayDecimal(s string) (*big.Int, error) {
	if s == "" || len(s) > 39 || s[0] == '0' {
		return nil, errors.New("positive canonical u128 decimal gas amount required")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return nil, errors.New("invalid decimal gas amount")
		}
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.Sign() <= 0 || n.BitLen() > 128 {
		return nil, errors.New("gas amount u128 bound")
	}
	return n, nil
}
func (m relayCLIManifest) config() (relay.Config, error) {
	var c relay.Config
	if (m.Version != 1 && m.Version != 2) || !m.Devnet || !filepath.IsAbs(m.DataDir) || !m.Domain.Valid() || m.Custody != params.DEXSettlementAddress || m.PollMillis < 250 || m.PollMillis > 10000 || m.MaxHeight == 0 || m.MaxHeight > 4096 || (m.Version == 1 && m.MaxHeight > 128) || len(m.DeferredRecipients) > 16 || len(m.Payers) != 3 {
		return c, errors.New("invalid explicit isolated relay manifest")
	}
	for _, endpoint := range []string{m.SourceURL, m.SubmitURL, m.DEXURL} {
		if err := relayURL(endpoint); err != nil {
			return c, err
		}
	}
	v, err := clxevidence.New(m.CLX)
	if err != nil {
		return c, err
	}
	base, err := v.BootstrapAnchor()
	if err != nil {
		return c, err
	}
	chain := m.CLX.ChainConfig
	if chain == nil || chain.DEXDevnet == nil || !chain.DEXDevnet.RollingAnchors() || chain.DEXDevnet.ContinuousStorage() != (m.Version == 2) || chain.ValidateDEXDevnet() != nil || m.MaxHeight > chain.DEXDevnet.MaxCheckpoints || m.Domain.Epoch != 1 || m.Domain.ChainID != base.ChainID || m.Domain.Genesis != base.Genesis || m.Domain.DEXID != base.DEXID || [20]byte(m.Custody) != base.Custody {
		return c, errors.New("relay differs from authenticated supported genesis schema")
	}
	members := make([]*common.Cnode, len(chain.DEXDevnet.Committee))
	for i, n := range chain.DEXDevnet.Committee {
		x := n
		members[i] = &x
	}
	if _, err = checkpoint.NewEpoch(m.Domain, 1, chain.DEXDevnet.MaxCheckpoints+1, members); err != nil {
		return c, err
	}
	c = relay.Config{Devnet: true, Domain: m.Domain, Custody: m.Custody, Payers: map[relay.Lane]common.Address{}, GasLimits: map[relay.Lane]uint64{}}
	c.GasPrice, err = relayDecimal(m.GasPrice)
	if err != nil {
		return c, err
	}
	c.MaxGasCost, err = relayDecimal(m.MaxGasCost)
	if err != nil {
		return c, err
	}
	for _, p := range m.Payers {
		lane, err := relayLane(p.Lane)
		if err != nil {
			return c, err
		}
		if (p.Purpose != "relay-gas" && p.Purpose != "leader-submission-gas") || p.Address == (common.Address{}) || p.Address == m.Custody || !filepath.IsAbs(p.KeyFile) || p.GasLimit == 0 || p.GasLimit > 100000000 || c.Payers[lane] != (common.Address{}) || new(big.Int).Mul(new(big.Int).SetUint64(p.GasLimit), c.GasPrice).Cmp(c.MaxGasCost) > 0 {
			return c, errors.New("invalid explicit dedicated relay gas payer")
		}
		c.Payers[lane] = p.Address
		c.GasLimits[lane] = p.GasLimit
		for _, n := range chain.GenCommittee {
			if common.IsHexAddress(n.CoinBase) && common.HexToAddress(n.CoinBase) == p.Address {
				return c, errors.New("registered CLX reward recipient cannot be relay gas payer")
			}
		}
		for _, n := range chain.DEXDevnet.Committee {
			if common.IsHexAddress(n.CoinBase) && common.HexToAddress(n.CoinBase) == p.Address {
				return c, errors.New("registered DEX reward recipient cannot be relay gas payer")
			}
		}
		for _, recipient := range m.DeferredRecipients {
			if recipient == p.Address {
				return c, errors.New("claim recipient cannot be relay gas payer")
			}
		}
	}
	return c, nil
}

type relayLocalSigner struct {
	config relay.Config
	keys   map[common.Address]*ecdsa.PrivateKey
}

func loadRelayLocalSigner(m relayCLIManifest, c relay.Config) (*relayLocalSigner, error) {
	owned := c
	owned.Payers = map[relay.Lane]common.Address{}
	for l, a := range c.Payers {
		owned.Payers[l] = a
	}
	owned.GasLimits = map[relay.Lane]uint64{}
	for l, g := range c.GasLimits {
		owned.GasLimits[l] = g
	}
	owned.GasPrice = new(big.Int).Set(c.GasPrice)
	owned.MaxGasCost = new(big.Int).Set(c.MaxGasCost)
	s := &relayLocalSigner{config: owned, keys: map[common.Address]*ecdsa.PrivateKey{}}
	ok := false
	defer func() {
		if !ok {
			s.close()
		}
	}()
	for _, payer := range m.Payers {
		raw, err := relayRegularRead(payer.KeyFile, 66, true)
		if err != nil {
			return nil, errors.New("dedicated relay gas-key file unavailable or unsafe")
		}
		encoded := raw
		if len(encoded) == 65 && encoded[64] == '\n' {
			encoded = encoded[:64]
		}
		var key *ecdsa.PrivateKey
		if len(encoded) == 64 {
			key, err = crypto.HexToECDSA(string(encoded))
		} else {
			err = errors.New("gas key encoding")
		}
		for i := range raw {
			raw[i] = 0
		}
		if err != nil {
			return nil, errors.New("invalid dedicated relay gas key")
		}
		if crypto.PubkeyToAddress(key.PublicKey) != payer.Address {
			key.D.SetInt64(0)
			return nil, errors.New("relay gas key/address mismatch")
		}
		if old := s.keys[payer.Address]; old != nil {
			key.D.SetInt64(0)
		} else {
			s.keys[payer.Address] = key
		}
	}
	ok = true
	return s, nil
}
func (s *relayLocalSigner) close() {
	for _, k := range s.keys {
		k.D.SetInt64(0)
	}
	s.keys = nil
}
func (s *relayLocalSigner) Sign(ctx context.Context, from common.Address, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tx == nil || chainID == nil || chainID.Cmp(new(big.Int).SetUint64(s.config.Domain.ChainID)) != 0 || tx.To() == nil || *tx.To() != s.config.Custody || tx.Value().Sign() != 0 {
		return nil, errors.New("relay signer domain/destination/value mismatch")
	}
	call, err := protocol.DecodeNativeCall(tx.Data())
	if err != nil {
		return nil, errors.New("relay signer native call malformed")
	}
	lane := map[uint8]relay.Lane{protocol.NativeAnchorUpdate: relay.Anchor, protocol.NativeCheckpoint: relay.Checkpoint, protocol.NativeClaim: relay.Claim}[call.Operation]
	if lane == 0 || s.config.Payers[lane] != from || s.keys[from] == nil || tx.Gas() != s.config.EffectiveGasLimit(lane) || tx.GasPrice().Cmp(s.config.GasPrice) != 0 {
		return nil, errors.New("relay signer gas-payer/template mismatch")
	}
	if lane == relay.Claim {
		claim, _, _, _, err := protocol.DecodeNativeClaim(call.Body)
		if err != nil || claim.Domain != s.config.Domain {
			return nil, errors.New("relay signer claim domain")
		}
		if s.keys[common.Address(claim.Recipient)] != nil {
			return nil, errors.New("relay signer cannot use a claim recipient key")
		}
	}
	if lane == relay.Checkpoint {
		cp, _, _, _, err := protocol.DecodeNativeCheckpoint(call.Body)
		if err != nil || cp.Domain() != s.config.Domain {
			return nil, errors.New("relay signer checkpoint domain")
		}
	}
	return types.SignTx(tx, types.NewEIP155Signer(chainID), s.keys[from])
}

type relayCLIJobStatus struct {
	ID             protocol.Hash
	Lane           relay.Lane
	Phase          string
	Nonce          uint64
	Reserved       bool
	TXHash         common.Hash
	Sends          uint64
	RPCAckObserved bool   `json:"rpc_ack_observed"`
	LastError      string `json:",omitempty"`
}
type relayCLIStatus struct {
	Version                   uint16
	Devnet                    bool
	ObservedAt                int64
	Authenticated             relay.NetworkStatus
	Counts                    map[string]int
	TotalJobs                 int
	JobsTruncated             bool
	Jobs                      []relayCLIJobStatus
	DiscoveryError, StepError string
	LeaderIntegrated          bool                  `json:",omitempty"`
	Leader                    *consensus.Leadership `json:",omitempty"`
}

func relayShortError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}
func relayStatus(root string, n relay.NetworkStatus, records []relay.Record, discovery, step error) error {
	return relayStatusWithLeader(root, n, records, discovery, step, nil)
}
func relayStatusWithLeader(root string, n relay.NetworkStatus, records []relay.Record, discovery, step error, leader *consensus.Leadership) error {
	if len(records) > relay.MaxActive+relay.MaxHistory {
		return errors.New("relay status record bound")
	}
	s := relayCLIStatus{Version: 1, Devnet: true, ObservedAt: time.Now().Unix(), Authenticated: n, Counts: map[string]int{}, TotalJobs: len(records), JobsTruncated: len(records) > 256, DiscoveryError: relayShortError(discovery), StepError: relayShortError(step)}
	s.LeaderIntegrated, s.Leader = leader != nil, leader
	for _, r := range records {
		s.Counts[r.Phase]++
		if len(s.Jobs) >= 256 {
			continue
		}
		e := r.LastError
		if len(e) > 128 {
			e = e[:128]
		}
		s.Jobs = append(s.Jobs, relayCLIJobStatus{r.Job.ID, r.Job.Lane, r.Phase, r.Attempt.Nonce, r.Attempt.GasLimit != 0, r.Attempt.Hash, r.Attempt.Sends, r.Attempt.ACK != (common.Hash{}), e})
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if len(raw) > 1024*1024 {
		return errors.New("relay status byte bound")
	}
	path := filepath.Join(root, "status.json")
	if info, e := os.Lstat(path); e == nil && !info.Mode().IsRegular() {
		return errors.New("unsafe relay status target")
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	f, err := relayNoFollow(filepath.Join(root, "status.next"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, w := f.Write(raw)
	if err = errors.Join(w, f.Sync(), f.Close()); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return relaySyncDir(root)
}

type relayLoop interface {
	Discover(context.Context) error
	Step(context.Context) error
	WriteStatus(error, error) error
}
type realRelayLoop struct {
	network *relay.Network
	core    *relay.Relay
	root    string
}

func (l realRelayLoop) Discover(c context.Context) error { return l.network.Discover(c, l.core) }
func (l realRelayLoop) Step(c context.Context) error     { return l.core.Step(c) }
func (l realRelayLoop) WriteStatus(d, s error) error {
	return relayStatus(l.root, l.network.AuthenticatedStatus(), l.core.Status(), d, s)
}
func relayCLILoop(ctx context.Context, interval time.Duration, once bool, l relayLoop) error {
	for {
		if ctx.Err() != nil {
			return nil
		}
		discoveryContext, cancel := context.WithTimeout(ctx, 3*time.Second)
		discoveryErr := l.Discover(discoveryContext)
		cancel()
		stepContext, cancel := context.WithTimeout(ctx, 3*time.Second)
		stepErr := l.Step(stepContext)
		cancel()
		if err := l.WriteStatus(discoveryErr, stepErr); err != nil {
			return err
		}
		if errors.Is(stepErr, relay.ErrStore) {
			return stepErr
		}
		if once {
			return errors.Join(discoveryErr, stepErr)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
func runDEXRelay(ctx *cli.Context) error {
	if ctx.NArg() != 0 {
		return errors.New("dex-relay accepts only explicit relay flags")
	}
	duration := ctx.Duration("relay.duration")
	once := ctx.Bool("relay.once")
	if duration < 0 || duration > 24*time.Hour || (once && duration != 0) {
		return errors.New("invalid relay once/duration bounds")
	}
	m, err := loadRelayCLIManifest(ctx.String("relay.config"))
	if err != nil {
		return err
	}
	session, err := openRelaySession(m, nil)
	if err != nil {
		return err
	}
	defer session.Close()
	stop, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if duration > 0 {
		var end context.CancelFunc
		stop, end = context.WithTimeout(stop, duration)
		defer end()
	}
	return relayCLILoop(stop, time.Duration(m.PollMillis)*time.Millisecond, once, realRelayLoop{session.network, session.core, m.DataDir})
}

// Only an operational summary is restored here, never a financial trust root.
// Core/source independently restore and authenticate their canonical journals.
func cleanupRelayStatusTemporaries(root string) error {
	canonical := filepath.Join(root, "status.json")
	if _, err := os.Lstat(canonical); err == nil {
		raw, err := relayRegularRead(canonical, 1024*1024, true)
		if err != nil {
			return err
		}
		var status relayCLIStatus
		if err = json.Unmarshal(raw, &status); err != nil || status.Version != 1 || !status.Devnet || len(status.Jobs) > relay.MaxActive+relay.MaxHistory || len(status.Counts) > 16 {
			return errors.New("invalid canonical relay status")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	d, err := os.Open(root)
	if err != nil {
		return err
	}
	entries, readErr := d.ReadDir(65)
	closeErr := d.Close()
	if readErr != nil && readErr != io.EOF {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if len(entries) > 64 {
		return errors.New("relay parent entry budget")
	}
	var paths []string
	for _, e := range entries {
		n := e.Name()
		if n != "status.next" && !(strings.HasPrefix(n, "status-") && strings.HasSuffix(n, ".tmp")) {
			continue
		}
		if len(paths) == 32 {
			return errors.New("relay status orphan budget")
		}
		p := filepath.Join(root, n)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !relayTemporaryOwned(info) || info.Size() > 1024*1024 {
			return errors.New("unsafe relay status temporary")
		}
		paths = append(paths, p)
	}
	for _, p := range paths {
		if err = os.Remove(p); err != nil {
			return err
		}
	}
	if len(paths) > 0 {
		return relaySyncDir(root)
	}
	return nil
}
