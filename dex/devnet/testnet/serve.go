package testnet

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"time"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
	"github.com/cypherium/cypher/dex/service"
	"github.com/cypherium/cypher/dex/transport"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

type node struct {
	dir           string
	identity      diskIdentity
	config        Init
	disk          actionDisk
	registry      *rewards.Registry
	collector     *rewards.Collector
	execution     *devnet.Execution
	service       *service.Service
	app           *consensus.Application // assigned/accessed only on the serialized actor
	allowed       [7]bool
	receipts      map[string]map[uint8]rewards.Receipt
	receiptErrors uint64
	failure       error
}

// Serve runs only inside a process-test child in a loopback-only network namespace.
// The parent pipe is the explicit trusted genesis/configuration boundary.
func Serve(in io.Reader, out io.Writer, dir string, index int) error {
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Flags&net.FlagLoopback == 0 {
		return errors.New("financial helper requires loopback-only namespace")
	}
	identity, lock, err := openIdentity(dir, index)
	if err != nil {
		return err
	}
	defer lock.Close()
	n := &node{dir: dir, identity: identity, receipts: map[string]map[uint8]rewards.Receipt{}}
	for i := range n.allowed {
		n.allowed[i] = true
	}
	defer func() {
		if n.service != nil {
			n.service.Close()
		}
		if n.collector != nil {
			n.collector.Shutdown()
		}
	}()
	write := func(r Response) error {
		b, e := json.Marshal(r)
		if e != nil {
			return e
		}
		if len(b) > MaxControlBytes {
			return errors.New("control response bound")
		}
		_, e = fmt.Fprintf(out, "%s%s\n", OutputPrefix, b)
		return e
	}
	if err = write(Response{Identity: &identity.Public}); err != nil {
		return err
	}
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), MaxControlBytes)
	for scanner.Scan() {
		var request Request
		var response Response
		if err = strict(scanner.Bytes(), &request); err == nil {
			response, err = n.handle(request)
		}
		if err != nil {
			response.Error = err.Error()
		}
		if err = write(response); err != nil {
			return err
		}
		if request.Op == "shutdown" {
			return nil
		}
	}
	return scanner.Err()
}
func (n *node) initialize(c Init) error {
	if n.service != nil {
		return errors.New("helper already initialized")
	}
	i := n.identity.Index
	if len(c.Peers) != 7 || len(c.Members) != 7 || c.Peers[i] != n.identity.Public.Peer || c.Members[i] == nil || *c.Members[i] != *n.identity.Public.Member || c.Domain != c.Market.Domain || !c.Market.NativeInbox || c.ParticipationHeight == 0 || c.ParticipationHeight > c.MaxHeight || c.MaxHeight < 2 || c.MaxHeight > 128 || c.TimeoutMillis < 100 || c.TimeoutMillis > 30000 {
		return errors.New("helper init identity/bounds")
	}
	recipients := make([][20]byte, 7)
	for j, p := range c.Peers {
		recipients[j] = p.RewardRecipient
	}
	registry, err := rewards.NewRegistry(c.Domain, c.Members, recipients)
	if err != nil {
		return err
	}
	verifier, err := clxevidence.New(c.CLX)
	if err != nil {
		return err
	}
	if c.CLX.ChainID != c.Domain.ChainID || protocol.Hash(c.CLX.Genesis.Hash()) != c.Domain.Genesis || c.CLX.DEXID != c.Domain.DEXID || [20]byte(c.CLX.Custody) != c.Market.Custody {
		return errors.New("helper trusted CLX/DEX mismatch")
	}
	market, err := engine.New(c.Market)
	if err != nil {
		return err
	}
	seed, err := protocol.NativeMarketSeed(c.Market.Oracle)
	if err != nil {
		return err
	}
	if err = validateNativeRegistration(c, seed); err != nil {
		return err
	}
	var secret bls.SecretKey
	if err = secret.Deserialize(n.identity.Secret); err != nil {
		return err
	}
	collector, err := rewards.OpenCollector(filepath.Join(n.dir, "participation"), registry, uint8(i), &secret)
	if err != nil {
		return err
	}
	good := false
	defer func() {
		if !good {
			collector.Shutdown()
		}
	}()
	execution := &devnet.Execution{Market: market, Registry: registry, Collector: collector, Native: &devnet.NativeContext{Seed: seed, Verifier: verifier, Rolling: c.CLX.ChainConfig.DEXDevnet.Version == 3}}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	hash := protocol.Digest("common-dex/process-init/v1", raw)
	disk, err := loadActions(n.dir, hash, registry)
	if err != nil {
		return err
	}
	for _, action := range disk.Actions {
		if err = execution.AuthenticateAction(action); err != nil {
			return err
		}
	}
	for _, b := range disk.Certificates {
		cert, _ := rewards.DecodeCertificate(b)
		if err = collector.RememberCertificate(cert); err != nil {
			return err
		}
	}
	registryHash, err := transport.RegistryCommitment(c.Domain, c.Peers)
	if err != nil {
		return err
	}
	n.config, n.disk, n.registry, n.collector, n.execution = c, disk, registry, collector, execution
	cfg := service.Config{
		Consensus: consensus.Config{Domain: c.Domain, Members: c.Members, Index: i, Secret: &secret, DataDir: filepath.Join(n.dir, "fhs"), CLXHeight: c.Market.CLXHeight, CLXHash: c.Market.CLXHash, MaxHeight: c.MaxHeight, Execution: execution, Actions: func(height uint64) ([]byte, error) {
			if n.failure != nil {
				return nil, n.failure
			}
			b := n.disk.Actions[height]
			if len(b) == 0 {
				return nil, consensus.ErrUnavailable
			}
			return bytes.Clone(b), nil
		},
			BeforeVote: func(v *hotstuff.PersistedVote) error {
				if n.failure != nil {
					return n.failure
				}
				return collector.BeforeVote(v)
			}, RestoreVote: collector.CheckFHSWatermark, OnFinalizedExecution: execution.Finalized, ObserveVote: n.observe},
		Transport: transport.Config{Domain: c.Domain, RegistryHash: registryHash, Index: uint8(i), Peers: c.Peers, Certificate: n.identity.tls(), DataDir: filepath.Join(n.dir, "outbox"), QueueLimit: 256, Timeout: 3 * time.Second, Retry: 40 * time.Millisecond},
		OnAction:  n.admitEnvelope, OnExtension: n.receive, APIListen: n.identity.Public.API,
		DeliveryFilter: func(peer, kind uint8, payload []byte) error {
			if peer >= 7 || !n.allowed[peer] {
				return transport.ErrBusy
			}
			return nil
		},
		Timeout: time.Duration(c.TimeoutMillis) * time.Millisecond,
	}
	s, err := service.Open(cfg)
	if err != nil {
		return err
	}
	n.service = s
	if err = s.Start(); err != nil {
		s.Close()
		n.service = nil
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = s.Do(ctx, func(a *consensus.Application) error { n.app = a; return nil }); err != nil {
		s.Close()
		n.service = nil
		return err
	}
	good = true
	return nil
}

func validateNativeRegistration(c Init, seed protocol.Hash) error {
	if c.CLX.ChainConfig == nil || c.CLX.ChainConfig.DEXDevnet == nil {
		return errors.New("native DEX is absent from trusted CLX genesis")
	}
	d := c.CLX.ChainConfig.DEXDevnet
	if (d.Version != 2 && d.Version != 3) || d.ActivationBlock == 0 || protocol.Hash(d.GenesisSeed) != seed || protocol.Hash(d.DEXID) != c.Domain.DEXID || [20]byte(d.Custody) != c.Market.Custody || c.Domain.Epoch != 1 || c.MaxHeight > d.MaxCheckpoints || len(d.Committee) != 7 || len(c.Members) != 7 || c.Market.CLXHeight != 0 || c.Market.CLXHash != c.Domain.Genesis {
		return errors.New("native DEX differs from genesis-committed seed/domain/custody/bounds")
	}
	for i, m := range c.Members {
		if m == nil || *m != d.Committee[i] {
			return errors.New("native DEX committee differs from trusted CLX genesis")
		}
	}
	return nil
}
func (n *node) handle(r Request) (Response, error) {
	if r.Op == "init" {
		if r.Init == nil {
			return Response{}, errors.New("missing init")
		}
		return Response{}, n.initialize(*r.Init)
	}
	if r.Op == "shutdown" {
		return Response{}, nil
	}
	if n.service == nil {
		return Response{}, errors.New("helper not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var response Response
	switch r.Op {
	case "status":
		status, err := n.service.Status(ctx)
		if err != nil {
			return response, err
		}
		response.Status = &status
		err = n.service.Do(ctx, func(*consensus.Application) error {
			var keys []string
			for k := range n.disk.Certificates {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				cert, err := rewards.DecodeCertificate(n.disk.Certificates[k])
				if err != nil {
					return err
				}
				response.Certificates = append(response.Certificates, cert)
			}
			response.ReceiptErrors = n.receiptErrors
			return nil
		})
		return response, err
	case "action":
		var prefix [8]byte
		binary.BigEndian.PutUint64(prefix[:], r.Height)
		body := append(prefix[:], r.Raw...)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+n.identity.Public.API+"/v1/actions", bytes.NewReader(body))
		if err != nil {
			return response, err
		}
		result, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			return response, err
		}
		defer result.Body.Close()
		reply, err := io.ReadAll(io.LimitReader(result.Body, 4096))
		if err != nil {
			return response, err
		}
		if result.StatusCode != http.StatusAccepted {
			return response, fmt.Errorf("HTTP ingress %d: %s", result.StatusCode, reply)
		}
		return response, nil
	case "checkpoint":
		err := n.service.Do(ctx, func(a *consensus.Application) error {
			c, p, err := a.FinalizedCheckpoint(r.Height)
			if err != nil {
				return err
			}
			state, err := a.FinalizedState(r.Height)
			if err != nil {
				return err
			}
			response.Checkpoint = &c
			response.Proof = p
			response.State = state
			return nil
		})
		return response, err
	case "partition":
		if len(r.Allowed) != 7 {
			return response, errors.New("partition must enumerate all seven peers")
		}
		return response, n.service.Do(ctx, func(*consensus.Application) error { copy(n.allowed[:], r.Allowed); return nil })
	case "repair":
		return response, n.service.Do(ctx, func(a *consensus.Application) error { return n.broadcast(requestData(a.CertifiedHeight())) })
	default:
		return response, errors.New("unknown control operation")
	}
}
func (n *node) commit(d actionDisk) error {
	if n.failure != nil {
		return n.failure
	}
	if err := saveFile(n.dir, "actions.json", d); err != nil {
		n.failure = fmt.Errorf("helper persistence uncertainty: %w", err)
		return n.failure
	}
	n.disk = d
	return nil
}
func (n *node) copyDisk() actionDisk {
	d := actionDisk{n.disk.Config, map[uint64][]byte{}, map[string][]byte{}}
	for h, b := range n.disk.Actions {
		d.Actions[h] = bytes.Clone(b)
	}
	for id, b := range n.disk.Certificates {
		d.Certificates[id] = bytes.Clone(b)
	}
	return d
}
func (n *node) admit(height uint64, raw []byte) error {
	if n.failure != nil {
		return n.failure
	}
	if height == 0 || height > n.config.MaxHeight || len(raw) == 0 || len(raw) > consensus.MaxActionBytes {
		return errors.New("helper action height/size")
	}
	if old, ok := n.disk.Actions[height]; ok {
		if !bytes.Equal(old, raw) {
			return errors.New("helper action height conflict")
		}
		return nil
	}
	if err := n.execution.AuthenticateAction(raw); err != nil {
		return err
	}
	total := len(raw)
	for _, b := range n.disk.Actions {
		total += len(b)
	}
	if total > 1024*1024 || len(n.disk.Actions) >= 128 {
		return errors.New("helper action queue capacity")
	}
	d := n.copyDisk()
	d.Actions[height] = bytes.Clone(raw)
	return n.commit(d)
}
func (n *node) admitEnvelope(raw []byte) error {
	if len(raw) < 9 {
		return errors.New("helper action envelope")
	}
	height := binary.BigEndian.Uint64(raw[:8])
	_, known := n.disk.Actions[height]
	if err := n.admit(height, raw[8:]); err != nil {
		return err
	}
	if known {
		return nil
	}
	if n.app != nil {
		if err := n.app.NotifyIngress(); err != nil && !errors.Is(err, hotstuff.ErrProposalValidationPending) {
			return err
		}
	}
	for i, p := range n.config.Peers {
		if i != n.identity.Index {
			if err := n.service.Relay(p.ID, transport.KindAction, raw); err != nil {
				return err
			}
		}
	}
	return nil
}
func (n *node) broadcast(raw []byte) error {
	var errs []error
	for i, p := range n.config.Peers {
		if i != n.identity.Index {
			if err := n.service.Relay(p.ID, transport.KindExtension, raw); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
func (n *node) observe(ref []byte, vote *hotstuff.HotstuffMessage) error {
	decoded, err := types.DecodeHotstuffProposalRef(ref)
	if err != nil {
		return err
	}
	if decoded.Number != n.config.ParticipationHeight {
		return nil
	}
	raw, err := rlp.EncodeToBytes(vote)
	if err != nil {
		return err
	}
	payload, err := encodeVote(ref, raw)
	if err != nil {
		return err
	}
	// Missing/late receipt affects reward eligibility, never ordinary FHS delivery.
	if err = n.receive(uint8(n.identity.Index), payload); err != nil {
		n.receiptErrors++
	}
	if err = n.broadcast(payload); err != nil {
		n.receiptErrors++
	}
	return nil
}
func (n *node) receive(peer uint8, raw []byte) error {
	if peer >= 7 {
		return errors.New("unregistered helper TLS peer")
	}
	kind, body, err := decodeExtension(raw)
	if err != nil {
		return err
	}
	switch kind {
	case extensionVote:
		ref, encoded, err := decodeVote(body)
		if err != nil {
			return err
		}
		var vote hotstuff.HotstuffMessage
		if err = rlp.DecodeBytes(encoded, &vote); err != nil {
			return err
		}
		key, e := hex.DecodeString(n.config.Peers[peer].BLSPublic)
		if e != nil || vote.Code != hotstuff.MsgVotePrepare || vote.Id != n.config.Peers[peer].ID || !bytes.Equal(key, vote.PubKey) {
			return errors.New("participation vote differs from TLS peer")
		}
		receipt, err := n.collector.Issue(ref, &vote)
		if errors.Is(err, rewards.ErrUnvalidatedTarget) {
			return transport.ErrBusy
		}
		if err != nil {
			n.receiptErrors++
			return err
		}
		b, err := receipt.Encode()
		if err != nil {
			return err
		}
		payload, err := extension(extensionReceipt, b)
		if err != nil {
			return err
		}
		if err = n.addReceipt(receipt); err != nil {
			return err
		}
		return n.broadcast(payload)
	case extensionReceipt:
		receipt, err := rewards.DecodeReceipt(body)
		if err != nil {
			return err
		}
		return n.addReceipt(receipt)
	case extensionCertificate:
		cert, err := rewards.DecodeCertificate(body)
		if err != nil {
			return err
		}
		return n.remember(cert)
	case extensionRequest:
		if len(body) != 8 {
			return errors.New("data request length")
		}
		// receive executes inside service.Do, so this closure must not re-enter Do.
		return n.dataRequest(peer, binary.BigEndian.Uint64(body))
	case extensionRecord:
		return n.importRecord(peer, body)
	default:
		return errors.New("unknown helper extension")
	}
}
func (n *node) addReceipt(receipt rewards.Receipt) error {
	if err := n.registry.VerifyReceipt(receipt); err != nil {
		return err
	}
	h, _ := receipt.Duty.Hash()
	key := fmt.Sprintf("%x", h)
	if _, ok := n.disk.Certificates[key]; ok {
		return nil
	}
	set := n.receipts[key]
	if set == nil {
		if len(n.receipts) >= 128*7 {
			return errors.New("receipt accumulator bound")
		}
		set = map[uint8]rewards.Receipt{}
		n.receipts[key] = set
	}
	set[receipt.Collector] = receipt
	if len(set) < 5 {
		return nil
	}
	var items []rewards.Receipt
	for _, r := range set {
		items = append(items, r)
	}
	cert, err := n.registry.Certificate(items)
	if err != nil {
		return err
	}
	if err = n.remember(cert); err != nil {
		return err
	}
	b, err := cert.Encode()
	if err != nil {
		return err
	}
	payload, err := extension(extensionCertificate, b)
	if err != nil {
		return err
	}
	return n.broadcast(payload)
}
func (n *node) remember(cert rewards.Certificate) error {
	if err := n.registry.VerifyCertificate(cert); err != nil {
		return err
	}
	h, _ := cert.Duty.Hash()
	key := fmt.Sprintf("%x", h)
	if _, ok := n.disk.Certificates[key]; ok {
		return nil
	}
	if len(n.disk.Certificates) >= 128*7 {
		return errors.New("certificate retention bound")
	}
	if err := n.collector.RememberCertificate(cert); err != nil {
		return err
	}
	b, err := cert.Encode()
	if err != nil {
		return err
	}
	d := n.copyDisk()
	d.Certificates[key] = b
	return n.commit(d)
}
func (n *node) dataRequest(peer uint8, after uint64) error {
	if n.app == nil {
		return transport.ErrBusy
	}
	records, err := n.app.CertifiedData(after, 1)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return nil
	}
	raw, err := extension(extensionRecord, records[0])
	if err != nil {
		return consensus.ErrUnavailable
	}
	return n.service.Relay(n.config.Peers[peer].ID, transport.KindExtension, raw)
}
func (n *node) importRecord(peer uint8, raw []byte) error {
	if n.app == nil {
		return transport.ErrBusy
	}
	if err := n.app.ImportProposalData(raw); err != nil {
		if errors.Is(err, consensus.ErrUnavailable) {
			return transport.ErrBusy
		}
		return err
	}
	return n.service.Relay(n.config.Peers[peer].ID, transport.KindExtension, requestData(n.app.CertifiedHeight()))
}
