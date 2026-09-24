package relay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/rlp"
)

// Only this package's tests construct fake authenticated observations. Production
// uses network.go finality/MPT verification; these tests exercise durable order.
type testBackend struct {
	obs     observation
	observe func(Job, Attempt) (observation, error)
	seen    []protocol.Hash
	sent    [][]byte
	dexSent int
	dir     string
	onSend  func() error
}

func (b *testBackend) Observe(_ context.Context, j Job, a Attempt) (observation, error) {
	b.seen = append(b.seen, j.ID)
	if b.observe != nil {
		return b.observe(j, a)
	}
	return b.obs, nil
}
func (b *testBackend) SendRawTransaction(_ context.Context, raw []byte) (common.Hash, error) {
	disk, err := readBounded(filepath.Join(b.dir, "state.bin"), MaxStoreBytes)
	if err != nil {
		return common.Hash{}, err
	}
	state, err := decodeState(disk)
	if err != nil {
		return common.Hash{}, err
	}
	found := false
	for _, r := range state.Records {
		if bytes.Equal(r.Attempt.Raw, raw) && r.Attempt.Sends > 0 {
			found = true
		}
	}
	if !found {
		return common.Hash{}, errors.New("broadcast before raw fsync")
	}
	b.sent = append(b.sent, append([]byte(nil), raw...))
	var tx types.Transaction
	if err := rlp.DecodeBytes(raw, &tx); err != nil {
		return common.Hash{}, err
	}
	if b.onSend != nil {
		if err := b.onSend(); err != nil {
			return common.Hash{}, err
		}
	}
	return tx.Hash(), nil
}
func (b *testBackend) SendDEX(_ context.Context, raw []byte) (protocol.Hash, error) {
	b.dexSent++
	return protocol.Digest("unit/action", raw), nil
}

type testSigner struct {
	keys   map[common.Address]*ecdsa.PrivateKey
	dir    string
	calls  int
	mutate bool
}

func (s *testSigner) Sign(_ context.Context, from common.Address, tx *types.Transaction, id *big.Int) (*types.Transaction, error) {
	s.calls++
	raw, err := readBounded(filepath.Join(s.dir, "state.bin"), MaxStoreBytes)
	if err != nil {
		return nil, err
	}
	disk, err := decodeState(raw)
	if err != nil {
		return nil, err
	}
	found := false
	for _, r := range disk.Records {
		if r.Phase == "prepared" && r.Attempt.Nonce == tx.Nonce() && bytes.Equal(r.Job.Payload, tx.Data()) {
			found = true
		}
	}
	if !found {
		return nil, errors.New("sign before template fsync")
	}
	if s.mutate {
		tx = types.NewTransaction(tx.Nonce(), *tx.To(), big.NewInt(1), tx.Gas(), tx.GasPrice(), tx.Data())
	}
	return types.SignTx(tx, types.NewEIP155Signer(id), s.keys[from])
}
func fixtureConfig(t *testing.T) (Config, *testBackend, *testSigner) {
	t.Helper()
	c := Config{Devnet: true, Domain: protocol.Domain{Version: 1, ChainID: 10101919, Genesis: protocol.Hash{1}, DEXID: protocol.Hash{2}, Epoch: 1, Committee: protocol.Hash{3}}, Custody: common.Address{9}, Payers: map[Lane]common.Address{}, GasLimits: map[Lane]uint64{}, GasPrice: big.NewInt(1000000000), MaxGasCost: clxUnit(1)}
	s := &testSigner{keys: map[common.Address]*ecdsa.PrivateKey{}}
	for _, lane := range []Lane{Anchor, Checkpoint, Claim} {
		key, err := crypto.HexToECDSA(fmt.Sprintf("%064x", uint64(lane+77)))
		if err != nil {
			t.Fatal(err)
		}
		payer := crypto.PubkeyToAddress(key.PublicKey)
		s.keys[payer] = key
		c.Payers[lane] = payer
		c.GasLimits[lane] = 15000000
	}
	b := &testBackend{obs: observation{verified: true, ready: true, balance: clxUnit(10), proof: []byte("unit authenticated evidence"), anchor: clxevidence.Anchor{Version: 1, ChainID: c.Domain.ChainID, Genesis: c.Domain.Genesis, DEXID: c.Domain.DEXID, Custody: [20]byte(c.Custody), Height: 1, BlockHash: protocol.Hash{4}, StateRoot: protocol.Hash{5}, SourceKeyHash: protocol.Hash{6}, SourceCommittee: protocol.Hash{7}, SourceEpoch: 1}}}
	return c, b, s
}
func clxUnit(n int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(n), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
}
func fixtureJob(lane Lane, id uint64) Job {
	var identity protocol.Hash
	binary.BigEndian.PutUint64(identity[24:], id)
	var payload []byte
	if lane == Inbox {
		payload = []byte("CDXAunit")
	} else {
		op := map[Lane]uint8{Anchor: 6, Checkpoint: 4, Claim: 5}[lane]
		payload, _ = (protocol.NativeCall{Operation: op, Body: []byte{byte(id)}}).Encode()
	}
	return Job{Version: 1, Lane: lane, ID: identity, Payload: payload, Authorization: []byte("unit bundle"), Owner: common.Address{19: byte(id)}}
}
func openFixture(t *testing.T, c Config, b *testBackend, s *testSigner, dir string) *Relay {
	t.Helper()
	b.dir = dir
	s.dir = dir
	r, err := Open(dir, c, b, s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func stepNow(r *Relay) error {
	r.mu.Lock()
	r.nextTry = map[protocol.Hash]time.Time{}
	r.mu.Unlock()
	return r.Step(context.Background())
}

func TestRelayCrashBoundaryRecoveryAndProofRevalidation(t *testing.T) {
	for _, stage := range []string{"after_intent", "after_prepared", "after_signed", "before_send", "after_send", "after_proof", "after_completion"} {
		t.Run(stage, func(t *testing.T) {
			c, b, s := fixtureConfig(t)
			dir := filepath.Join(t.TempDir(), "relay")
			armed := stage != "after_completion"
			c.Hook = func(at string) error {
				if armed && at == stage {
					return errors.New("injected crash")
				}
				return nil
			}
			r := openFixture(t, c, b, s, dir)
			job := fixtureJob(Checkpoint, 1)
			err := r.Enqueue(job)
			if stage != "after_intent" {
				if err != nil {
					t.Fatal(err)
				}
				err = stepNow(r)
			}
			if stage == "after_completion" {
				if err != nil {
					t.Fatal(err)
				}
				b.obs.completed = true
				b.obs.nonce = 1
				armed = true
				err = stepNow(r)
			}
			if err == nil {
				t.Fatal("fault hook did not interrupt")
			}
			first := r.Status()
			if e := r.Close(); e != nil {
				t.Fatal(e)
			}
			c.Hook = nil
			r = openFixture(t, c, b, s, dir)
			defer r.Close()
			if first[0].Phase == "complete" && r.Status()[0].Phase != "revalidation_wait" {
				t.Fatal("stored completion trusted")
			}
			if err = stepNow(r); err != nil {
				t.Fatal("recovery", err)
			}
			if stage != "after_completion" {
				b.obs.completed = true
				b.obs.nonce = 1
				if err = stepNow(r); err != nil {
					t.Fatal(err)
				}
			}
			if got := r.Status()[0]; got.Phase != "complete" || len(got.Proof) == 0 {
				t.Fatal("completion", got.Phase)
			}
			for _, raw := range b.sent {
				if !bytes.Equal(raw, b.sent[0]) {
					t.Fatal("ambiguous ACK changed signed TX")
				}
			}
			if stage == "after_send" && len(b.sent) != 2 {
				t.Fatal("signed retry absent", len(b.sent))
			}
		})
	}
}

func TestRelayAuthenticationNonceAndIndependentPayers(t *testing.T) {
	c, b, s := fixtureConfig(t)
	dir := filepath.Join(t.TempDir(), "relay")
	r := openFixture(t, c, b, s, dir)
	defer r.Close()
	j := fixtureJob(Checkpoint, 1)
	if err := r.Enqueue(j); err != nil {
		t.Fatal(err)
	}
	b.obs.verified = false
	if err := stepNow(r); err == nil || s.calls != 0 || len(b.sent) != 0 {
		t.Fatal("unverified observation authorized send")
	}
	b.obs.verified = true
	b.obs.ready = false
	if err := stepNow(r); err != nil || s.calls != 0 {
		t.Fatal("not ready allocated nonce", err)
	}
	b.obs.ready = true
	b.obs.balance = new(big.Int)
	if err := stepNow(r); err != nil || s.calls != 0 || r.Status()[0].LastError != "gas_wait" {
		t.Fatal("gas wait", err)
	}
	b.obs.balance = clxUnit(10)
	if err := stepNow(r); err != nil {
		t.Fatal(err)
	}
	// Native ACK is not a completion; external semantic completion also must
	// retain our signed nonce until its consumption is independently proven.
	if r.Status()[0].Phase == "complete" {
		t.Fatal("ACK completed")
	}
	b.obs.completed = true
	if err := stepNow(r); err != nil || r.Status()[0].Phase != "completed_pending_nonce" {
		t.Fatal("external completion released nonce", err)
	}
	j2 := fixtureJob(Checkpoint, 2)
	if err := r.Enqueue(j2); err != nil {
		t.Fatal(err)
	}
	b.observe = func(job Job, _ Attempt) (observation, error) { o := b.obs; o.completed = job.ID == j.ID; return o, nil }
	if err := stepNow(r); err != nil {
		t.Fatal(err)
	}
	if s.calls != 1 {
		t.Fatal("same payer nonce reused")
	}
	claim := fixtureJob(Claim, 3)
	if err := r.Enqueue(claim); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err := stepNow(r); err != nil {
			t.Fatal(err)
		}
	}
	if s.calls < 2 {
		t.Fatal("independent payer blocked")
	}
	b.observe = func(job Job, _ Attempt) (observation, error) {
		o := b.obs
		o.nonce = 1
		o.completed = job.ID == j.ID
		return o, nil
	}
	for i := 0; i < 6; i++ {
		_ = stepNow(r)
	}
	var conflict bool
	for _, record := range r.Status() {
		if record.Job.ID == claim.ID && record.Phase == "nonce_conflict" {
			conflict = true
		}
	}
	if !conflict {
		t.Fatal("consumed nonce without effect did not conflict")
	}
}

func TestRelayMalformedSignerReplanAndOwnership(t *testing.T) {
	c, b, s := fixtureConfig(t)
	dir := filepath.Join(t.TempDir(), "relay")
	r := openFixture(t, c, b, s, dir)
	j := fixtureJob(Anchor, 1)
	if err := r.Enqueue(j); err != nil {
		t.Fatal(err)
	}
	changed := cloneJob(j)
	changed.Payload[len(changed.Payload)-1] ^= 1
	if !errors.Is(r.Enqueue(changed), ErrConflict) {
		t.Fatal("conflicting Enqueue")
	}
	if err := r.ReplaceUnsent(changed); err != nil {
		t.Fatal(err)
	}
	s.mutate = true
	if err := stepNow(r); err == nil || len(b.sent) != 0 {
		t.Fatal("malicious signer sent")
	}
	if !errors.Is(r.ReplaceUnsent(j), ErrConflict) {
		t.Fatal("prepared template changed")
	}
	if _, err := Open(dir, c, b, s); err == nil {
		t.Fatal("double open")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	other := c
	other.Domain.ChainID++
	if _, err := Open(dir, other, b, s); err == nil {
		t.Fatal("binding mismatch")
	}
	data, err := os.ReadFile(filepath.Join(dir, "state.bin"))
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err = os.WriteFile(filepath.Join(dir, "state.bin"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(dir, c, b, s); err == nil {
		t.Fatal("corrupt state accepted")
	}
	unowned := t.TempDir()
	if _, err = Open(unowned, c, b, s); err == nil {
		t.Fatal("unowned datadir adopted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err = os.Symlink(unowned, link); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(link, c, b, s); err == nil {
		t.Fatal("symlink datadir adopted")
	}
}

func TestRelayCapacityFairnessHistoryAndRestartCursor(t *testing.T) {
	c, b, s := fixtureConfig(t)
	dir := filepath.Join(t.TempDir(), "relay")
	r := openFixture(t, c, b, s, dir)
	for i, lane := range []Lane{Anchor, Inbox, Checkpoint, Claim} {
		if err := r.Enqueue(fixtureJob(lane, uint64(i+1))); err != nil {
			t.Fatal(err)
		}
	}
	b.observe = func(j Job, _ Attempt) (observation, error) {
		if j.Lane == Anchor {
			return observation{}, ErrInvalidJob
		}
		o := b.obs
		o.ready = false
		return o, nil
	}
	_ = stepNow(r)
	if r.Status()[0].Phase != "quarantined" {
		t.Fatal("invalid head not quarantined")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r = openFixture(t, c, b, s, dir)
	for i := 0; i < 3; i++ {
		if err := stepNow(r); err != nil {
			t.Fatal(err)
		}
	}
	if len(b.seen) != 4 {
		t.Fatal("lane attempts", len(b.seen))
	}
	seen := map[protocol.Hash]bool{}
	for _, id := range b.seen {
		seen[id] = true
	}
	if len(seen) != 4 {
		t.Fatal("restarted failed head starved lanes")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	// Count admission preserves per-lane headroom rather than allowing one lane
	// to consume all256 active slots.
	dir = filepath.Join(t.TempDir(), "relay")
	r = openFixture(t, c, b, s, dir)
	d := cloneState(r.state)
	for i := 0; i < 208; i++ {
		j := fixtureJob(Claim, uint64(i+1))
		d.Records = append(d.Records, Record{LocalID: uint64(i + 1), Job: j, Phase: "queued"})
	}
	d.Next = 209
	if err := r.persist(d); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(r.Enqueue(fixtureJob(Claim, 209)), ErrCapacity) {
		t.Fatal("lane headroom exceeded")
	}
	if err := r.Enqueue(fixtureJob(Anchor, 210)); err != nil {
		t.Fatal("other lane headroom", err)
	}
	r.Close()
	// Full completed history is atomically pruned only after revalidation, and
	// an old completion referenced by another record is retained.
	dir = filepath.Join(t.TempDir(), "relay")
	r = openFixture(t, c, b, s, dir)
	defer r.Close()
	d = cloneState(r.state)
	for i := uint64(1); i <= 1024; i++ {
		j := fixtureJob(Claim, i)
		d.Records = append(d.Records, Record{LocalID: i, Job: j, Phase: "complete", Proof: []byte{1}})
		r.validated[j.ID] = true
	}
	d.Next = 1025
	if err := r.persist(d); err != nil {
		t.Fatal(err)
	}
	last := fixtureJob(Inbox, 1025)
	last.Dependencies = []protocol.Hash{fixtureJob(Claim, 1).ID}
	if err := r.Enqueue(last); err != nil {
		t.Fatal(err)
	}
	b.observe = nil
	b.obs.completed = true
	if err := stepNow(r); err != nil {
		t.Fatal(err)
	}
	if len(r.state.Records) != 1024 || r.find(fixtureJob(Claim, 1).ID) < 0 || r.find(fixtureJob(Claim, 2).ID) >= 0 {
		t.Fatal("history pruning/retention", len(r.state.Records))
	}
	if len(r.validated) > 1024 || len(r.nextTry) > 1024 {
		t.Fatal("pruned in-memory indexes leaked")
	}
}

func TestRelayDiskFailureStopsBeforeSigning(t *testing.T) {
	c, b, s := fixtureConfig(t)
	dir := filepath.Join(t.TempDir(), "relay")
	r := openFixture(t, c, b, s, dir)
	defer r.Close()
	if err := r.Enqueue(fixtureJob(Checkpoint, 1)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "state.bin"), filepath.Join(dir, "preserved-state.bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "state.bin"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := stepNow(r); !errors.Is(err, ErrStore) || s.calls != 0 || len(b.sent) != 0 {
		t.Fatal("persistence failure escaped", err)
	}
	if err := r.Enqueue(fixtureJob(Claim, 2)); !errors.Is(err, ErrStore) {
		t.Fatal("faulted store accepted new work", err)
	}
}

func TestRelayIndependentCanonicalGolden(t *testing.T) {
	raw, err := os.ReadFile("../testdata/relay.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Domain, Custody, Binding, Job, State, Disk string
		Payers                                     []string
		GasLimits                                  []uint64 `json:"gas_limits"`
		GasPrice                                   string   `json:"gas_price"`
		MaxGasCost                                 string   `json:"max_gas_cost"`
		BindingHash                                string   `json:"binding_hash"`
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var domain protocol.Domain
	if err = binary.Read(bytes.NewReader(decode(v.Domain)), binary.BigEndian, &domain); err != nil {
		t.Fatal(err)
	}
	c := Config{Devnet: true, Domain: domain, Custody: common.BytesToAddress(decode(v.Custody)), Payers: map[Lane]common.Address{}, GasLimits: map[Lane]uint64{}}
	c.GasPrice, _ = new(big.Int).SetString(v.GasPrice, 10)
	c.MaxGasCost, _ = new(big.Int).SetString(v.MaxGasCost, 10)
	for i, p := range v.Payers {
		c.Payers[Lane(i+1)] = common.BytesToAddress(decode(p))
		c.GasLimits[Lane(i+1)] = v.GasLimits[i]
	}
	b, err := c.binding()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := rlp.EncodeToBytes(b)
	if err != nil || !bytes.Equal(encoded, decode(v.Binding)) {
		t.Fatal("binding vector", err)
	}
	hash, _ := c.hash()
	if hex.EncodeToString(hash[:]) != v.BindingHash {
		t.Fatal("binding hash")
	}
	d, err := decodeState(decode(v.Disk))
	if err != nil {
		t.Fatal(err)
	}
	stateBytes, _ := rlp.EncodeToBytes(d)
	if !bytes.Equal(stateBytes, decode(v.State)) {
		t.Fatal("state vector")
	}
	again, _ := encodeState(d)
	if !bytes.Equal(again, decode(v.Disk)) {
		t.Fatal("disk vector")
	}
	jobBytes, _ := rlp.EncodeToBytes(d.Records[0].Job)
	if !bytes.Equal(jobBytes, decode(v.Job)) {
		t.Fatal("job vector")
	}
	if err := validateState(d, c, hash); err != nil {
		t.Fatal(err)
	}
	var round Job
	if err = rlp.DecodeBytes(jobBytes, &round); err != nil || !reflect.DeepEqual(round, d.Records[0].Job) {
		t.Fatal("job codec roundtrip", err)
	}
	for _, bad := range [][]byte{nil, append(decode(v.Disk), 0), decode(v.Disk)[:20]} {
		if _, err := decodeState(bad); err == nil {
			t.Fatal("malformed disk accepted")
		}
	}
}

func TestRelayOwnedOrphanCleanupBeforeNewWrites(t *testing.T) {
	c, b, s := fixtureConfig(t)
	dir := filepath.Join(t.TempDir(), "relay")
	r := openFixture(t, c, b, s, dir)
	r.Close()
	canonical, _ := os.ReadFile(filepath.Join(dir, "state.bin"))
	for _, name := range []string{"state.next", "relay-state-legacy.tmp", "unrelated.tmp"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("partial"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r = openFixture(t, c, b, s, dir)
	r.Close()
	for _, name := range []string{"state.next", "relay-state-legacy.tmp"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatal("owned orphan retained", name, err)
		}
	}
	if raw, _ := os.ReadFile(filepath.Join(dir, "unrelated.tmp")); string(raw) != "partial" {
		t.Fatal("unrelated file changed")
	}
	victim := filepath.Join(t.TempDir(), "external")
	os.WriteFile(victim, []byte("protected"), 0600)
	if err := os.Symlink(victim, filepath.Join(dir, "state.next")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, c, b, s); err == nil {
		t.Fatal("symlink temp accepted")
	}
	if raw, _ := os.ReadFile(victim); string(raw) != "protected" {
		t.Fatal("external target modified")
	}
	os.Remove(filepath.Join(dir, "state.next"))
	os.WriteFile(filepath.Join(dir, "state.next"), []byte("partial"), 0600)
	corrupt := append([]byte(nil), canonical...)
	corrupt[len(corrupt)-1] ^= 1
	os.WriteFile(filepath.Join(dir, "state.bin"), corrupt, 0600)
	if _, err := Open(dir, c, b, s); err == nil {
		t.Fatal("corrupt canonical accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "state.next")); err != nil {
		t.Fatal("cleanup before canonical validation")
	}
	os.WriteFile(filepath.Join(dir, "state.bin"), canonical, 0600)
	os.Remove(filepath.Join(dir, "state.next"))
	for i := 0; i < 33; i++ {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("relay-state-%d.tmp", i)), []byte("partial"), 0600)
	}
	if _, err := Open(dir, c, b, s); err == nil {
		t.Fatal("legacy orphan count unbounded")
	}
	for i := 0; i < 33; i++ {
		if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("relay-state-%d.tmp", i))); err != nil {
			t.Fatal("partial deletion before count validation")
		}
	}
}
