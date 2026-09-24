package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/relay/source"
	"github.com/cypherium/cypher/dex/settlement"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

type NetworkConfig struct {
	Relay                  Config
	Source                 source.Config
	SubmitURL, DEXURL      string
	MaxHeight              uint64
	AutoInbox              bool
	CertifiedInboxPlanning bool
	DeferredRecipients     []common.Address
}

// Network is owned by the relay's serial event loop. It transports ordinary
// transactions and cryptographically verifies observations before the journal
// can use them. It has no StateDB mutation or financial execution capability.
type Network struct {
	cfg                 NetworkConfig
	Source              *source.Client
	verifier            *clxevidence.Verifier
	epoch               *checkpoint.Epoch
	genesisRoot         protocol.Hash
	checkpointSchema    uint16
	http                *http.Client
	bundles             []*checkpoint.VerifiedSettlementBundle
	bundleBytes         [][]byte
	archive             *bundleArchive
	claimSequence       uint64
	claimOffset         int
	clxSequence         uint64
	clxSequenceVerified bool
	certifiedPlanning   []certifiedPlanningRecord
}

// NetworkStatus contains only authenticated observations. Heights returned by
// discovery RPCs or transaction acknowledgements never populate these fields.
type NetworkStatus struct {
	SourceAnchor        clxevidence.Anchor
	DEXSequence         uint64
	CLXSequence         uint64
	CLXSequenceVerified bool
}

func (n *Network) AuthenticatedStatus() NetworkStatus {
	return NetworkStatus{n.Source.Current(), n.bundleCount(), n.clxSequence, n.clxSequenceVerified}
}

func loopbackURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	p, e := strconv.Atoi(u.Port())
	ip := net.ParseIP(u.Hostname())
	if e != nil || p < 1 || p > 65535 || ip == nil || !ip.IsLoopback() || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("explicit numeric loopback HTTP endpoint required")
	}
	u.Path = ""
	return u.String(), nil
}

func OpenNetwork(c NetworkConfig) (*Network, error) {
	if _, err := c.Relay.binding(); err != nil {
		return nil, err
	}
	continuous := c.Source.CLX.ChainConfig != nil && c.Source.CLX.ChainConfig.DEXDevnet.ContinuousStorage()
	if c.MaxHeight == 0 || c.MaxHeight > MaxBundleArchiveRecords || !continuous && c.MaxHeight > 128 || len(c.DeferredRecipients) > 16 {
		return nil, errors.New("relay discovery bounds")
	}
	payers, limits := make(map[Lane]common.Address), make(map[Lane]uint64)
	for l, p := range c.Relay.Payers {
		payers[l] = p
	}
	for l, g := range c.Relay.GasLimits {
		limits[l] = g
	}
	c.Relay.Payers, c.Relay.GasLimits = payers, limits
	c.Relay.GasPrice, c.Relay.MaxGasCost = new(big.Int).Set(c.Relay.GasPrice), new(big.Int).Set(c.Relay.MaxGasCost)
	c.DeferredRecipients = append([]common.Address(nil), c.DeferredRecipients...)
	var err error
	if c.SubmitURL, err = loopbackURL(c.SubmitURL); err != nil {
		return nil, err
	}
	if c.DEXURL, err = loopbackURL(c.DEXURL); err != nil {
		return nil, err
	}
	v, err := clxevidence.New(c.Source.CLX)
	if err != nil {
		return nil, err
	}
	g, err := v.BootstrapAnchor()
	if err != nil {
		return nil, err
	}
	cc := c.Source.CLX.ChainConfig
	if cc == nil || cc.DEXDevnet == nil || cc.ValidateDEXDevnet() != nil || !cc.DEXDevnet.RollingAnchors() || c.Relay.Domain.Epoch != 1 || c.Relay.Domain.ChainID != g.ChainID || c.Relay.Domain.Genesis != g.Genesis || c.Relay.Domain.DEXID != g.DEXID || [20]byte(c.Relay.Custody) != g.Custody || c.MaxHeight > cc.DEXDevnet.MaxCheckpoints {
		return nil, errors.New("relay registration differs from trusted genesis")
	}
	members := make([]*common.Cnode, len(cc.DEXDevnet.Committee))
	for i := range members {
		n := cc.DEXDevnet.Committee[i]
		members[i] = &n
	}
	e, err := checkpoint.NewEpoch(c.Relay.Domain, 1, cc.DEXDevnet.MaxCheckpoints+1, members)
	if err != nil {
		return nil, err
	}
	root, err := protocol.NativeGenesisRootV3(protocol.Hash(cc.DEXDevnet.GenesisSeed), c.Relay.Domain, [20]byte(c.Relay.Custody))
	if continuous {
		root, err = protocol.NativeGenesisRootV4(protocol.Hash(cc.DEXDevnet.GenesisSeed), c.Relay.Domain, [20]byte(c.Relay.Custody))
	}
	if err != nil {
		return nil, err
	}
	s, err := source.Open(c.Source)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, MaxConnsPerHost: 2, MaxIdleConns: 2, ResponseHeaderTimeout: 3 * time.Second, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}
	h := &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("relay redirect forbidden") }}
	n := &Network{cfg: c, Source: s, verifier: v, epoch: e, genesisRoot: root, checkpointSchema: cc.DEXDevnet.Version + 1, http: h}
	if continuous {
		n.archive, err = openBundleArchiveVersion(filepath.Join(filepath.Dir(c.Source.Dir), fmt.Sprintf("bundles-v%d", cc.DEXDevnet.Version)), e, c.Relay.Custody, root, c.MaxHeight, cc.DEXDevnet.Version)
		if err != nil {
			s.Close()
			transport.CloseIdleConnections()
			return nil, err
		}
	}
	return n, nil
}

// Production fixes this value only after authenticating the CLX genesis config.
// The fallback preserves the explicitly legacy in-memory fixture constructor.
func (n *Network) expectedCheckpointSchema() uint16 {
	if n.checkpointSchema != 0 {
		return n.checkpointSchema
	}
	if n.archive != nil {
		return n.archive.schema
	}
	return 4
}

func (n *Network) Close() error {
	n.http.CloseIdleConnections()
	return errors.Join(n.Source.Close(), n.archive.close())
}

func (n *Network) json(ctx context.Context, method, address string, body []byte, out interface{}, limit int) error {
	req, err := http.NewRequestWithContext(ctx, method, address, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	r, err := n.http.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil {
		return err
	}
	if len(raw) > limit {
		return errors.New("relay HTTP response bound")
	}
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		return fmt.Errorf("relay HTTP unavailable status=%d", r.StatusCode)
	}
	return json.Unmarshal(raw, out)
}
func (n *Network) SendRawTransaction(ctx context.Context, raw []byte) (common.Hash, error) {
	var result common.Hash
	if len(raw) > protocol.MaxNativeCallBytes+1024 {
		return result, ErrInvalidJob
	}
	request, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": []interface{}{hexutil.Encode(raw)}})
	var response struct {
		ID     int
		Result common.Hash
		Error  *struct {
			Code    int
			Message string
		}
	}
	if err := n.json(ctx, http.MethodPost, n.cfg.SubmitURL, request, &response, 65536); err != nil {
		return result, err
	}
	if response.ID != 1 {
		return result, errors.New("Common RPC submission unavailable/rejected")
	}
	if response.Error != nil {
		// Report only bounded known classes. Never reflect arbitrary server
		// messages, which can contain transaction contents or credentials.
		class := "rejected"
		switch response.Error.Message {
		case "transaction gas limit exceeds protocol maximum":
			class = "transaction_gas_cap"
		case "nonce too low":
			class = "nonce_too_low"
		case "replacement transaction underpriced":
			class = "replacement_underpriced"
		case "insufficient funds for gas * price + value":
			class = "insufficient_funds"
		}
		return result, fmt.Errorf("Common RPC submission code=%d class=%s", response.Error.Code, class)
	}
	return response.Result, nil
}
func (n *Network) SendDEX(ctx context.Context, raw []byte) (protocol.Hash, error) {
	var response struct{ ID string }
	var id protocol.Hash
	if len(raw) > protocol.MaxNativeCallBytes {
		return id, ErrInvalidJob
	}
	if err := n.json(ctx, http.MethodPost, n.cfg.DEXURL+"/v1/actions", raw, &response, 65536); err != nil {
		return id, err
	}
	b, err := hex.DecodeString(response.ID)
	if err != nil || len(b) != 32 {
		return id, errors.New("DEX admission identity")
	}
	copy(id[:], b)
	if id != protocol.Digest("common-dex/ingress-action/v1", raw) {
		return protocol.Hash{}, errors.New("DEX ACK payload mismatch")
	}
	return id, nil
}

func (n *Network) refreshDEX(ctx context.Context) error {
	var status struct{ Finalized uint64 }
	if err := n.json(ctx, http.MethodGet, n.cfg.DEXURL+"/v1/status", nil, &status, 65536); err != nil {
		return err
	}
	if status.Finalized > n.cfg.MaxHeight {
		return errors.New("DEX discovery height bound")
	}
	for added := 0; n.bundleCount() < status.Finalized && added < 8; added++ {
		h := n.bundleCount() + 1
		var response struct{ Bytes []byte }
		if err := n.json(ctx, http.MethodGet, n.cfg.DEXURL+"/v1/settlement?height="+strconv.FormatUint(h, 10), nil, &response, 256*1024); err != nil {
			return err
		}
		if n.archive != nil {
			if _, err := n.archive.accept(response.Bytes, true); err != nil {
				return err
			}
			continue
		}
		b, err := checkpoint.DecodeSettlementBundle(response.Bytes)
		if err != nil {
			return err
		}
		v, err := checkpoint.VerifySettlementBundle(n.epoch, b)
		if err != nil {
			return err
		}
		if v.Finance().Custody != [20]byte(n.cfg.Relay.Custody) {
			return errors.New("DEX bundle custody mismatch")
		}
		cp := v.Checkpoint()
		pre, prev := n.genesisRoot, protocol.Hash{}
		if h > 1 {
			old := n.bundles[h-2].Checkpoint()
			pre = old.PostRoot
			prev, _ = old.Hash()
		}
		if cp.Sequence != h || cp.DataSchema != n.expectedCheckpointSchema() || cp.PreRoot != pre || cp.Previous != prev {
			return errors.New("DEX discovered checkpoint chain mismatch")
		}
		n.bundles = append(n.bundles, v)
		n.bundleBytes = append(n.bundleBytes, bytes.Clone(response.Bytes))
	}
	return nil
}

type proofObservation struct {
	Anchor []byte
	Paths  [][]byte
	DEX    []byte
}

func (n *Network) slots(ctx context.Context, at clxevidence.Anchor, keys []common.Hash, proof *proofObservation) ([]common.Hash, error) {
	if len(keys) > 32 {
		return nil, errors.New("relay slot query bound")
	}
	typed := make([]protocol.Hash, len(keys))
	for i, k := range keys {
		typed[i] = protocol.Hash(k)
	}
	a, raw, err := n.Source.Account(ctx, at, [20]byte(n.cfg.Relay.Custody), typed)
	if err != nil {
		return nil, err
	}
	if !a.Exists || a.Nonce != 1 || a.CodeHash != protocol.Hash(crypto.Keccak256Hash(nil)) {
		return nil, errors.New("authenticated native custody account unavailable")
	}
	proof.Paths = append(proof.Paths, raw)
	out := make([]common.Hash, len(a.Values))
	for i, v := range a.Values {
		out[i] = common.Hash(v)
	}
	return out, nil
}
func wordUint(h common.Hash) (uint64, error) {
	if !bytes.Equal(h[:24], make([]byte, 24)) {
		return 0, errors.New("noncanonical uint64 storage")
	}
	return binary.BigEndian.Uint64(h[24:]), nil
}
func metaWord(h common.Hash) (settlement.RollingStatus, error) {
	s := settlement.RollingStatus{TipHeight: binary.BigEndian.Uint64(h[:8]), ConfirmedThrough: binary.BigEndian.Uint64(h[8:16]), Records: binary.BigEndian.Uint64(h[16:24])}
	if binary.BigEndian.Uint64(h[24:]) != 0 || s.ConfirmedThrough > s.TipHeight || s.Records > settlement.MaxNativeAnchors || (s.Records == 0) != (s.TipHeight == 0) || s.Records > s.TipHeight {
		return s, errors.New("invalid authenticated rolling metadata")
	}
	return s, nil
}
func (n *Network) storedAnchor(ctx context.Context, at clxevidence.Anchor, height uint64, proof *proofObservation) (clxevidence.Anchor, bool, error) {
	if height == 0 {
		a, e := n.verifier.BootstrapAnchor()
		return a, true, e
	}
	keys, err := settlement.RollingAnchorStorageKeysVersion(height, 2)
	if err != nil {
		return clxevidence.Anchor{}, false, err
	}
	words, err := n.slots(ctx, at, keys, proof)
	if err != nil {
		return clxevidence.Anchor{}, false, err
	}
	g, err := n.verifier.BootstrapAnchor()
	if err != nil {
		return clxevidence.Anchor{}, false, err
	}
	return decodeStoredAnchor(words, g, height)
}

// decodeStoredAnchor only interprets words already authenticated by slots against
// the verified source state root. It is not an RPC response authenticator.
func decodeStoredAnchor(words []common.Hash, g clxevidence.Anchor, height uint64) (clxevidence.Anchor, bool, error) {
	if len(words) != 11 || height == 0 {
		return clxevidence.Anchor{}, false, errors.New("anchor storage proof word count/height")
	}
	if words[9] == (common.Hash{}) {
		for _, word := range words {
			if word != (common.Hash{}) {
				return clxevidence.Anchor{}, false, errors.New("partial authenticated anchor storage")
			}
		}
		return clxevidence.Anchor{}, false, nil
	}
	if words[10] == (common.Hash{}) {
		return clxevidence.Anchor{}, false, errors.New("anchor evidence storage absent")
	}
	raw := make([]byte, 0, 288)
	for _, word := range words[:9] {
		raw = append(raw, word[:]...)
	}
	size := clxevidence.AnchorSize
	switch binary.BigEndian.Uint16(raw[:2]) {
	case 1:
	case 2:
		size = clxevidence.AnchorV2Size
	default:
		return clxevidence.Anchor{}, false, errors.New("anchor storage version")
	}
	if !bytes.Equal(raw[size:], make([]byte, len(raw)-size)) {
		return clxevidence.Anchor{}, false, errors.New("anchor storage padding")
	}
	a, err := clxevidence.DecodeAnchor(raw[:size])
	if err != nil {
		return a, false, err
	}
	id, err := a.ID()
	if err != nil {
		return a, false, err
	}
	if common.Hash(id) != words[9] || a.Height != height || a.ChainID != g.ChainID || a.Genesis != g.Genesis || a.DEXID != g.DEXID || a.Custody != g.Custody || a.SourceEpoch != g.SourceEpoch || (a.Version == 1 && (a.SourceKeyHash != g.SourceKeyHash || a.SourceCommittee != g.SourceCommittee)) {
		return a, false, errors.New("stored anchor binding")
	}
	return a, true, nil
}
func (n *Network) baseByID(ctx context.Context, at clxevidence.Anchor, id protocol.Hash, p *proofObservation) (clxevidence.Anchor, error) {
	g, _ := n.verifier.BootstrapAnchor()
	gid, _ := g.ID()
	if id == gid {
		return g, nil
	}
	v, err := n.slots(ctx, at, []common.Hash{settlement.RollingAnchorIDStorageKey(id)}, p)
	if err != nil {
		return g, err
	}
	h, err := wordUint(v[0])
	if err != nil || h == 0 {
		return g, errors.New("anchor base not retained")
	}
	a, found, err := n.storedAnchor(ctx, at, h, p)
	if err != nil || !found {
		return g, errors.New("anchor base data unavailable")
	}
	actual, _ := a.ID()
	if actual != id {
		return g, ErrInvalidJob
	}
	return a, nil
}

func (n *Network) Observe(ctx context.Context, j Job, attempt Attempt) (observation, error) {
	var o observation
	if err := validateJob(j); err != nil {
		return o, err
	}
	at := n.Source.Current()
	p := proofObservation{}
	p.Anchor, _ = at.Encode()
	if j.Lane == Inbox {
		return n.observeInbox(ctx, j, at, p)
	}
	payer := n.cfg.Relay.Payers[j.Lane]
	account, raw, err := n.Source.Account(ctx, at, [20]byte(payer), nil)
	if err != nil {
		return o, err
	}
	p.Paths = append(p.Paths, raw)
	o.nonce, o.balance, o.anchor = account.Nonce, account.Balance, at
	// Exact native execution gas plus intrinsic calldata under the genesis-
	// authenticated block-fork configuration. The Prague calldata floor is
	// included conservatively even before activation. No estimateGas/RPC flag
	// is treated as authorization, and no DEX engine is executed here.
	nonzeroCost := params.TxDataNonZeroGasFrontier
	if n.cfg.Source.CLX.ChainConfig.IsIstanbul(new(big.Int).SetUint64(at.Height)) {
		nonzeroCost = params.TxDataNonZeroGasEIP2028
	}
	intrinsic, floor := uint64(params.TxGas), uint64(params.TxGas)
	for _, b := range j.Payload {
		if b == 0 {
			intrinsic += params.TxDataZeroGas
			floor += params.TxCostFloorPerToken
		} else {
			intrinsic += nonzeroCost
			floor += params.TxTokenPerNonZeroByte * params.TxCostFloorPerToken
		}
	}
	o.requiredGas = intrinsic + settlement.RequiredNativeGas(j.Payload)
	if floor > o.requiredGas {
		o.requiredGas = floor
	}
	call, err := protocol.DecodeNativeCall(j.Payload)
	if err != nil {
		return o, errors.Join(ErrInvalidJob, err)
	}
	switch j.Lane {
	case Anchor:
		target, err := clxevidence.DecodeAnchor(j.Authorization)
		if err != nil {
			return o, errors.Join(ErrInvalidJob, err)
		}
		id, _ := target.ID()
		if j.ID != BusinessID(n.cfg.Relay.Domain, n.cfg.Relay.Custody, Anchor, id) {
			return o, ErrInvalidJob
		}
		e, continuation, err := settlement.DecodeAnchorUpdate(call.Body)
		if err != nil {
			return o, errors.Join(ErrInvalidJob, err)
		}
		base, err := n.baseByID(ctx, at, e.Base, &p)
		if err != nil {
			return o, err
		}
		verified, actual, err := n.verifier.VerifyRolling(base, 0, e)
		if err != nil || actual != target {
			return o, errors.Join(ErrInvalidJob, err)
		}
		if len(continuation) > 0 {
			end, endAnchor, _, e := n.verifier.VerifyHeaderContext(target, verified.KeyContext(), continuation)
			if e != nil || end == nil {
				return o, errors.Join(ErrInvalidJob, e)
			}
			desc, found, e := n.storedAnchor(ctx, at, end.Number.Uint64(), &p)
			if e != nil {
				return o, e
			}
			if !found || desc.BlockHash != protocol.Hash(end.Hash()) || desc.StateRoot != protocol.Hash(end.Root) || desc.Version != endAnchor.Version || desc.SourceKeyHash != endAnchor.SourceKeyHash || desc.SourceCommittee != endAnchor.SourceCommittee || desc.SourceEpoch != endAnchor.SourceEpoch || desc.ActivationEnd != endAnchor.ActivationEnd || desc.ActivationRoot != endAnchor.ActivationRoot {
				return o, ErrInvalidJob
			}
		}
		stored, found, err := n.storedAnchor(ctx, at, target.Height, &p)
		if err != nil {
			return o, err
		}
		if found {
			actual, _ := stored.ID()
			if actual != id {
				o.conflict = "anchor height occupied by different authenticated target"
			} else {
				o.completed = true
			}
			break
		}
		words, err := n.slots(ctx, at, []common.Hash{settlement.RollingMetadataStorageKey()}, &p)
		if err != nil {
			return o, err
		}
		meta, err := metaWord(words[0])
		if err != nil {
			return o, err
		}
		if len(continuation) == 0 {
			o.ready = base.Height == meta.TipHeight && target.Height > meta.TipHeight
		} else {
			end, endAnchor, _, err := n.verifier.VerifyHeaderContext(target, verified.KeyContext(), continuation)
			if err != nil || end == nil {
				return o, errors.Join(ErrInvalidJob, err)
			}
			desc, exists, err := n.storedAnchor(ctx, at, end.Number.Uint64(), &p)
			if err != nil {
				return o, err
			}
			o.ready = exists && desc.BlockHash == protocol.Hash(end.Hash()) && desc.StateRoot == protocol.Hash(end.Root) && desc.Version == endAnchor.Version && desc.SourceKeyHash == endAnchor.SourceKeyHash && desc.SourceCommittee == endAnchor.SourceCommittee && desc.SourceEpoch == endAnchor.SourceEpoch && desc.ActivationEnd == endAnchor.ActivationEnd && desc.ActivationRoot == endAnchor.ActivationRoot && target.Height < meta.TipHeight
		}
		if meta.Records >= settlement.MaxNativeAnchors {
			o.ready = false
		}
	case Checkpoint, Claim:
		b, err := checkpoint.DecodeSettlementBundle(j.Authorization)
		if err != nil {
			return o, errors.Join(ErrInvalidJob, err)
		}
		v, err := checkpoint.VerifySettlementBundle(n.epoch, b)
		if err != nil {
			return o, errors.Join(ErrInvalidJob, err)
		}
		cp := v.Checkpoint()
		if cp.DataSchema != n.expectedCheckpointSchema() || v.Finance().Custody != [20]byte(n.cfg.Relay.Custody) {
			return o, ErrInvalidJob
		}
		hash, _ := cp.Hash()
		history, _ := settlement.CheckpointHistoryStorageKey(cp.Sequence)
		if j.Lane == Checkpoint {
			want, err := protocol.EncodeNativeCheckpoint(cp, v.Finance(), v.Proof(), nil)
			if err != nil || !bytes.Equal(want, j.Payload) || j.ID != BusinessID(n.cfg.Relay.Domain, n.cfg.Relay.Custody, Checkpoint, hash) {
				return o, ErrInvalidJob
			}
			words, err := n.slots(ctx, at, []common.Hash{history, settlement.CheckpointSequenceStorageKey(), settlement.RollingMetadataStorageKey(), settlement.InboxCursorStorageKey()}, &p)
			if err != nil {
				return o, err
			}
			if words[0] != (common.Hash{}) {
				if words[0] == common.Hash(hash) {
					o.completed = true
				} else {
					o.conflict = "checkpoint sequence conflict"
				}
				break
			}
			seq, err := wordUint(words[1])
			if err != nil {
				return o, err
			}
			meta, err := metaWord(words[2])
			if err != nil {
				return o, err
			}
			cursor, err := wordUint(words[3])
			if err != nil {
				return o, err
			}
			a, found, err := n.storedAnchor(ctx, at, cp.CLXHeight, &p)
			if err != nil {
				return o, err
			}
			o.ready = seq+1 == cp.Sequence && cursor == cp.InboxStart && found && a.Height <= meta.ConfirmedThrough && a.BlockHash == cp.CLXHash && cp.InboxEnd <= a.InboxCount
		} else {
			claim, index, count, siblings, err := protocol.DecodeNativeClaim(call.Body)
			if err != nil {
				return o, errors.Join(ErrInvalidJob, err)
			}
			leaf, _ := claim.Hash()
			if j.ID != BusinessID(n.cfg.Relay.Domain, n.cfg.Relay.Custody, Claim, leaf) || j.Owner != common.Address(claim.Owner) {
				return o, ErrInvalidJob
			}
			matched := false
			for _, path := range append(v.Withdrawals(), v.Rewards()...) {
				want, e := protocol.EncodeNativeClaim(path.Claim, path.Index, path.Count, path.Siblings)
				if e == nil && bytes.Equal(want, j.Payload) {
					matched = true
					break
				}
			}
			_ = index
			_ = count
			_ = siblings
			if !matched {
				return o, ErrInvalidJob
			}
			nullifier, err := settlement.ClaimNullifierStorageKey(claim)
			if err != nil {
				return o, ErrInvalidJob
			}
			words, err := n.slots(ctx, at, []common.Hash{history, nullifier}, &p)
			if err != nil {
				return o, err
			}
			if words[1] != (common.Hash{}) {
				if words[1] == common.Hash(leaf) && words[0] == common.Hash(hash) {
					o.completed = true
				} else {
					o.conflict = "claim nullifier conflict"
				}
			} else {
				o.ready = words[0] == common.Hash(hash)
			}
		}
	default:
		return o, ErrInvalidJob
	}
	o.verified = true
	o.proof, err = rlp.EncodeToBytes(p)
	return o, err
}

func (n *Network) observeInbox(ctx context.Context, j Job, at clxevidence.Anchor, p proofObservation) (observation, error) {
	o := observation{balance: new(big.Int), anchor: at}
	e, err := clxevidence.DecodeRollingEvidence(j.Payload[4:])
	if err != nil {
		return o, errors.Join(ErrInvalidJob, err)
	}
	target, err := clxevidence.DecodeAnchor(j.Authorization)
	if err != nil {
		return o, ErrInvalidJob
	}
	// Reconstruct the target from the persisted source chain, never the job.
	authenticated, targetContext, err := n.Source.AnchorContextAt(ctx, target.Height, target.BlockHash)
	if err != nil {
		return o, err
	}
	if authenticated != target {
		return o, ErrInvalidJob
	}
	start := uint64(0)
	if len(e.Entries) > 0 {
		start = e.Entries[0].Entry.Index
	}
	entries := make([]protocol.InboxEntry, len(e.Entries))
	for i, v := range e.Entries {
		entries[i] = v.Entry
	}
	root, err := protocol.InboxEntriesRoot(entries)
	if err != nil {
		return o, ErrInvalidJob
	}
	key := inboxKey(start, start+uint64(len(entries)), root)
	if len(entries) == 0 {
		key, _ = target.ID()
	}
	if j.ID != BusinessID(n.cfg.Relay.Domain, n.cfg.Relay.Custody, Inbox, key) {
		return o, ErrInvalidJob
	}
	if err = n.verifier.VerifyRollingPayload(e); err != nil {
		return o, errors.Join(ErrInvalidJob, err)
	}
	id, _ := target.ID()
	same := clxevidence.RollingEvidence{Base: id, AccountProof: e.AccountProof, CountProof: e.CountProof, Entries: e.Entries}
	// Keep the submitted MPT paths: authenticating the target must not replace
	// a bad job proof with a fresh good one. Only its target key preimages come
	// from verified source history; e.KeyContext belongs to the range's base.
	same.SetKeyContext(targetContext)
	if _, _, err = n.verifier.VerifyRolling(target, start, same); err != nil {
		return o, errors.Join(ErrInvalidJob, err)
	}
	if err = n.refreshDEX(ctx); err != nil {
		return o, err
	}
	o.completed, o.conflict, err = n.inboxCompletion(ctx, target, entries, &p)
	if err != nil {
		return o, err
	}
	if !o.completed && o.conflict == "" {
		if err = n.refreshCertifiedPlanning(ctx); err != nil {
			return o, err
		}
		base, cursor, err := n.inboxPlanningBase(ctx)
		if err != nil {
			return o, err
		}
		id, _ := base.ID()
		if id == e.Base {
			_, result, err := n.verifier.VerifyRolling(base, cursor, e)
			if err != nil || result != target {
				return o, errors.Join(ErrInvalidJob, err)
			}
			o.ready = true
		}
	}
	o.verified = true
	o.proof, err = rlp.EncodeToBytes(p)
	return o, err
}

// inboxCompletion compares authenticated economic effects, not proof encodings
// or caller-reported cursors. The caller has already authenticated target and
// every entry against its source MPT and checked the semantic job identity.
func (n *Network) inboxCompletion(ctx context.Context, target clxevidence.Anchor, entries []protocol.InboxEntry, p *proofObservation) (bool, string, error) {
	var bundles [][]byte
	finish := func() (bool, string, error) {
		var err error
		p.DEX, err = rlp.EncodeToBytes(struct {
			Version uint16
			Bundles [][]byte
		}{1, bundles})
		return err == nil, "", err
	}
	if len(entries) == 0 {
		for h := n.bundleCount(); h > 0; h-- {
			cp, _ := n.bundleCP(h)
			if cp.CLXHeight < target.Height {
				continue
			}
			if cp.CLXHeight == target.Height {
				if cp.CLXHash != target.BlockHash {
					return false, "DEX source anchor conflicts with authenticated empty inbox target", nil
				}
			} else if _, err := n.Source.AnchorAt(ctx, cp.CLXHeight, cp.CLXHash); err != nil {
				return false, "", err
			}
			_, raw, err := n.bundleAt(h)
			if err != nil {
				return false, "", err
			}
			bundles = append(bundles, raw)
			return finish()
		}
		return false, "", nil
	}
	start, end := entries[0].Index, entries[0].Index+uint64(len(entries))
	covered := start
	proofBytes := 0
	for h := uint64(1); h <= n.bundleCount(); h++ {
		cp, _ := n.bundleCP(h)
		if cp.InboxEnd <= covered || cp.InboxEnd == cp.InboxStart {
			continue
		}
		if cp.InboxStart > covered {
			break // A gap is not completion, even if a later cursor exceeds end.
		}
		var imported []protocol.InboxEntry
		if cp.InboxStart >= start && cp.InboxEnd <= end {
			imported = entries[cp.InboxStart-start : cp.InboxEnd-start]
		} else {
			if cp.InboxEnd < cp.InboxStart || cp.InboxEnd-cp.InboxStart > protocol.MaxDepositsPerCheckpoint {
				return false, "", ErrInvalidJob
			}
			anchor, err := n.Source.AnchorAt(ctx, cp.CLXHeight, cp.CLXHash)
			if err != nil {
				return false, "", err
			}
			imported, err = n.Source.Entries(ctx, anchor, cp.InboxStart, cp.InboxEnd-cp.InboxStart)
			if err != nil {
				return false, "", err
			}
			e, _, err := n.Source.BuildRange(ctx, anchor, anchor.Height, cp.InboxStart, imported)
			if err != nil {
				return false, "", err
			}
			raw, err := clxevidence.EncodeRollingEvidence(e)
			if err != nil {
				return false, "", err
			}
			proofBytes += len(raw)
			if proofBytes > clxevidence.MaxEvidenceBytes/2 {
				return false, "", ErrCapacity
			}
			p.Paths = append(p.Paths, raw)
		}
		root, err := protocol.InboxEntriesRoot(imported)
		if err != nil {
			return false, "", err
		}
		if root != cp.InboxRoot {
			return false, "DEX inbox commitment conflicts with authenticated source entries", nil
		}
		for _, entry := range imported {
			if entry.Index >= start && entry.Index < end && entry != entries[entry.Index-start] {
				return false, "DEX inbox overlap conflicts with authenticated pending entries", nil
			}
		}
		_, raw, err := n.bundleAt(h)
		if err != nil {
			return false, "", err
		}
		proofBytes += len(raw)
		if proofBytes > clxevidence.MaxEvidenceBytes/2 {
			return false, "", ErrCapacity
		}
		bundles = append(bundles, raw)
		covered = cp.InboxEnd
		if covered >= end {
			return finish()
		}
	}
	return false, "", nil
}
