package clxevidence_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
	"github.com/cypherium/cypher/dex/service"
	"github.com/cypherium/cypher/dex/service/finance"
	"github.com/cypherium/cypher/dex/transport"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func snapshotBenign(err error) bool {
	if err == nil {
		return true
	}
	for _, e := range []error{hotstuff.ErrInsufficientQC, hotstuff.ErrProposalValidationPending, hotstuff.ErrProposalDataUnavailable, hotstuff.ErrUnhandledMsg, hotstuff.ErrOldState, hotstuff.ErrMissingView, hotstuff.ErrViewOldPhase, hotstuff.ErrFutureState} {
		if errors.Is(err, e) {
			return true
		}
	}
	return strings.Contains(err.Error(), "fixture")
}

func TestFinancialSnapshotDistinctRegisteredLateVoter(t *testing.T) {
	f, chain := rollingFinancialFixture(t, 1)
	x := f.execution
	genesis, _, err := x.Genesis()
	if err != nil {
		t.Fatal(err)
	}
	initial, _, err := x.Decode(genesis)
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := devnet.EncodeRollingInboxAction(chain.Evidence(t, *initial.RollingAnchor, 1, 0, true))
	if err != nil {
		t.Fatal(err)
	}
	oracle, err := engine.Sign(engine.Action{Version: 1, Epoch: f.config.Domain.EpochKey(), Owner: f.config.Oracle, Nonce: 1, Kind: engine.Oracle, Price: engine.Amount("1000000000000000000"), FeedSequence: 1, ValidUntil: 100}, f.oracle)
	if err != nil {
		t.Fatal(err)
	}
	duty := rewards.Duty{Version: 1, Domain: f.config.Domain, Period: 1, Height: 1, View: 1, ProposalID: protocol.Hash{12}, Participant: 0, Recipient: f.recipients[0]}
	var receipts []rewards.Receipt
	var keys [7]bls.SecretKey
	for i := range keys {
		if err = keys[i].SetDecString(fmt.Sprint(1200 + i)); err != nil {
			t.Fatal(err)
		}
		if i < 5 {
			raw, _ := duty.Encode()
			raw = append(raw, byte(i))
			raw = append(raw, keys[i].GetPublicKey().Serialize()...)
			h := protocol.Digest("common-dex/participation-receipt/v1", raw)
			r := rewards.Receipt{Duty: duty, Collector: uint8(i)}
			copy(r.Signature[:], keys[i].SignHash(h[:]).Serialize())
			receipts = append(receipts, r)
		}
	}
	cert, err := x.Registry.Certificate(receipts)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := devnet.EncodeParticipationAction(engine.Action{Version: 1, Epoch: f.config.Domain.EpochKey(), Owner: f.config.Oracle, Nonce: 2}, f.oracle, []rewards.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	noop, err := engine.Sign(engine.Action{Version: 1, Epoch: f.config.Domain.EpochKey(), Owner: f.config.Oracle, Nonce: 3, Kind: engine.Noop}, f.oracle)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[uint64][]byte{1: inbox, 2: oracle, 3: commit, 4: noop}
	root := t.TempDir()
	configs := make([]consensus.Config, 7)
	apps := make([]*consensus.Application, 6) // index6 has never opened or voted.
	type delivery struct {
		to  string
		msg *hotstuff.HotstuffMessage
	}
	var queue []delivery
	for i := 0; i < 7; i++ {
		configs[i] = consensus.Config{Domain: f.config.Domain, Members: f.members, Index: i, Secret: &keys[i], DataDir: filepath.Join(root, fmt.Sprint("fhs", i)), CLXHash: f.config.Domain.Genesis, MaxHeight: 4, Execution: x, Actions: func(h uint64) ([]byte, error) {
			if b := actions[h]; b != nil {
				return bytes.Clone(b), nil
			}
			return nil, consensus.ErrUnavailable
		}, OnFinalizedExecution: x.Finalized}
		if i == 6 {
			continue
		}
		a, err := consensus.Open(configs[i])
		if err != nil {
			t.Fatal(err)
		}
		apps[i] = a
		t.Cleanup(func() { a.Close() })
		a.SetTransport(func(to string, msg *hotstuff.HotstuffMessage) error {
			queue = append(queue, delivery{to, msg})
			return nil
		})
	}
	for _, a := range apps {
		if err = a.Start(); !snapshotBenign(err) {
			t.Fatal(err)
		}
	}
	for step := 0; step < 20000; step++ {
		progress := false
		for _, a := range apps {
			did, e := a.Advance()
			if !snapshotBenign(e) {
				t.Fatal(e)
			}
			progress = progress || did
		}
		if len(queue) > 0 {
			d := queue[0]
			queue = queue[1:]
			progress = true
			for _, a := range apps {
				if a.Self() == d.to {
					if e := a.Handle(d.msg); !snapshotBenign(e) {
						t.Fatal(e)
					}
					break
				}
			}
		}
		if !progress {
			break
		}
		if step == 19999 {
			t.Fatal("bounded FHS pump exhausted")
		}
	}
	for i, a := range apps {
		if a.FinalizedHeight() != 3 {
			t.Fatal("six registered participants finality", i, a.FinalizedHeight())
		}
	}
	cp, proof, err := apps[0].FinalizedCheckpoint(3)
	if err != nil {
		t.Fatal(err)
	}
	state, err := apps[0].FinalizedState(3)
	if err != nil {
		t.Fatal(err)
	}
	financial, market, err := x.Decode(state)
	if err != nil || financial.Version != 5 || len(financial.Participation.Entries) != 1 || market.Total != "6" {
		t.Fatal("state5 committed financial state", err)
	}
	epoch, err := checkpoint.NewEpoch(f.config.Domain, 1, math.MaxUint64, f.members)
	if err != nil {
		t.Fatal(err)
	}
	bundleBytes, err := finance.FinalizedSettlement(apps[0], x, epoch, 3)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := checkpoint.DecodeSettlementBundle(bundleBytes)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := checkpoint.VerifySettlementBundle(epoch, bundle)
	if err != nil || verified.Checkpoint() != cp || !bytes.Equal(verified.Proof(), proof) {
		t.Fatal("read-only finalized settlement", err)
	}
	if _, err = finance.FinalizedSettlement(apps[0], x, epoch, 4); err == nil {
		t.Fatal("uncertified tip exported as settlement")
	}
	snapshot, err := apps[0].ExportSnapshotAt(3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = apps[0].ExportSnapshotAt(2); err == nil {
		t.Fatal("historical tip invented")
	}
	if _, err = apps[0].ExportSnapshotAt(4); err == nil {
		t.Fatal("certified only snapshot")
	}
	// A pre-existing participant cannot use a peer snapshot to replace own votes.
	ownPath := filepath.Join(configs[0].DataDir, "state.json")
	ownBefore, err := os.ReadFile(ownPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = apps[0].BootstrapSnapshot(snapshot); err == nil {
		t.Fatal("existing voter accepted bootstrap")
	}
	ownAfter, _ := os.ReadFile(ownPath)
	if !bytes.Equal(ownBefore, ownAfter) {
		t.Fatal("bootstrap rejection changed own WAL")
	}
	// Only the previously unopened, differently registered key6 imports data.
	votes := 0
	configs[6].BeforeVote = func(*hotstuff.PersistedVote) error { votes++; return nil }
	late, err := consensus.Open(configs[6])
	if err != nil {
		t.Fatal(err)
	}
	defer late.Close()
	if err = late.BootstrapSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	got, err := late.FinalizedState(3)
	if err != nil || !bytes.Equal(got, state) || votes != 0 {
		t.Fatal("late financial replay before signing", err, votes)
	}
	latePath := filepath.Join(configs[6].DataDir, "state.json")
	before, _ := os.ReadFile(latePath)
	if err = late.BootstrapSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(latePath)
	if !bytes.Equal(before, after) {
		t.Fatal("idempotent bootstrap wrote WAL")
	}
	late.SetTransport(func(string, *hotstuff.HotstuffMessage) error { return nil })
	if err = late.Timeout(); !snapshotBenign(err) {
		t.Fatal(err)
	}
	before, _ = os.ReadFile(latePath)
	var persisted struct {
		Payload struct{ Safety *hotstuff.FHSSafetyState }
	}
	if err = json.Unmarshal(before, &persisted); err != nil || persisted.Payload.Safety == nil || persisted.Payload.Safety.LastTimeoutVote == nil || persisted.Payload.Safety.LastVote != nil {
		t.Fatal("bootstrap unexpectedly imported votes or failed to persist its own timeout", err)
	}
	late.Close()
	late, err = consensus.Open(configs[6])
	if err != nil {
		t.Fatal(err)
	}
	defer late.Close()
	before, _ = os.ReadFile(latePath)
	if err = late.BootstrapSnapshot(snapshot); err != nil {
		t.Fatal("restart bootstrap", err)
	}
	after, _ = os.ReadFile(latePath)
	if !bytes.Equal(before, after) {
		t.Fatal("restart erased local timeout safety")
	}
	if err = late.BootstrapSnapshot(append(bytes.Clone(snapshot), ' ')); err == nil {
		t.Fatal("different origin allowed")
	}
	if err = late.ImportSnapshot(snapshot); err == nil {
		t.Fatal("strict ImportSnapshot changed behavior")
	}
	for _, name := range []string{"domain", "genesis-root", "state-root", "omitted-state-root", "missing-data", "trailing"} {
		t.Run(name, func(t *testing.T) {
			// Mirror the public snapshot data fields to preserve its canonical
			// struct encoding while altering the authenticated contents.
			var s struct {
				Version   uint16
				Domain    protocol.Domain
				Records   map[string]*consensus.Record
				Finalized []struct {
					Key, Hash string
					Proof     []byte
				}
				ExecutionID     string
				ExecutionSchema uint16
				GenesisState    []byte
				GenesisRoot     protocol.Hash
			}
			if err := json.Unmarshal(snapshot, &s); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "domain":
				s.Domain.DEXID[0]++
			case "genesis-root":
				s.GenesisRoot[0]++
			case "state-root":
				changed := false
				for _, r := range s.Records {
					if len(r.State) == 0 {
						continue
					}
					r.State[0] ^= 1
					changed = true
					break
				}
				if !changed {
					t.Fatal("snapshot has no retained state to corrupt")
				}
			case "omitted-state-root":
				changed := false
				for _, r := range s.Records {
					if r.State == nil {
						r.Checkpoint.PostRoot[0] ^= 1
						changed = true
						break
					}
				}
				if !changed {
					t.Fatal("compact snapshot has no omitted state to reexecute")
				}
			case "missing-data":
				for k, r := range s.Records {
					if r.Checkpoint.Sequence == 1 {
						delete(s.Records, k)
						break
					}
				}
			}
			bad, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			if name == "trailing" {
				bad = append(bad, ' ')
			}
			cfg := configs[6]
			cfg.DataDir = filepath.Join(t.TempDir(), "fresh")
			a, err := consensus.Open(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			path := filepath.Join(cfg.DataDir, "state.json")
			before, _ := os.ReadFile(path)
			if err = a.BootstrapSnapshot(bad); err == nil {
				t.Fatal("unverified snapshot accepted")
			}
			after, _ := os.ReadFile(path)
			if a.FinalizedHeight() != 0 || !bytes.Equal(before, after) || votes != 0 {
				t.Fatal("failed bootstrap progressed/signing/WAL")
			}
		})
	}
	t.Run("service-startup-boundary", func(t *testing.T) {
		cfg := configs[6]
		cfg.DataDir = filepath.Join(t.TempDir(), "service-fhs")
		peers := make([]transport.Peer, 7)
		var certificates [7]tls.Certificate
		for i := range peers {
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
			der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
			if err != nil {
				t.Fatal(err)
			}
			certificates[i] = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
			peers[i] = transport.Peer{ID: f.members[i].Address, Address: f.members[i].Address, BLSPublic: f.members[i].Public, RewardRecipient: f.recipients[i], CertSHA256: protocol.Hash(sha256.Sum256(der))}
		}
		registry, err := transport.RegistryCommitment(f.config.Domain, peers)
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(t.TempDir(), "snapshot.json")
		if err = os.WriteFile(file, snapshot, 0600); err != nil {
			t.Fatal(err)
		}
		initialized := false
		c := service.Config{Consensus: cfg, Transport: transport.Config{Domain: f.config.Domain, RegistryHash: registry, Index: 6, Peers: peers, Certificate: certificates[6], DataDir: filepath.Join(t.TempDir(), "outbox")}, BootstrapSnapshotFile: file, ActorInit: func(*consensus.Application) error { initialized = true; return nil }}
		manifest := service.Manifest{Version: 1, Devnet: true, Mode: "counter", Domain: f.config.Domain, Index: 6, Members: f.members, Peers: peers, DataDir: filepath.Join(t.TempDir(), "sidecar"), VoteKeyFile: "/unused/vote", TLSCertFile: "/unused/cert", TLSKeyFile: "/unused/tls", CLXHash: f.config.Domain.Genesis, MaxHeight: 4, TimeoutMillis: 1000, BootstrapSnapshotFile: file}
		if err := manifest.Validate(); err != nil {
			t.Fatal(err)
		}
		manifest.BootstrapSnapshotFile = "relative-snapshot.json"
		if err := manifest.Validate(); err == nil {
			t.Fatal("relative bootstrap manifest path")
		}
		wrongKey := c
		wrongKey.Consensus.Secret = &keys[0]
		if badService, err := service.Open(wrongKey); err == nil {
			badService.Close()
			t.Fatal("snapshot replaced registered vote identity")
		}
		s, err := service.Open(c)
		if err != nil {
			t.Fatal(err)
		}
		if initialized || votes != 0 {
			t.Fatal("actor/vote started during Open")
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		a, err := consensus.Open(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if a.FinalizedHeight() != 3 {
			t.Fatal("service did not restore")
		}
		a.Close()
		s, err = service.Open(c)
		if err != nil {
			t.Fatal("idempotent service restart", err)
		}
		s.Close()
		bad := append(bytes.Clone(snapshot), ' ')
		if err = os.WriteFile(file, bad, 0600); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(filepath.Join(cfg.DataDir, "state.json"))
		if s, err = service.Open(c); err == nil {
			s.Close()
			t.Fatal("service accepted different bootstrap")
		}
		after, _ := os.ReadFile(filepath.Join(cfg.DataDir, "state.json"))
		if initialized || votes != 0 || !bytes.Equal(before, after) {
			t.Fatal("failed service bootstrap changed signer state")
		}
		fresh := c
		fresh.Consensus.DataDir = filepath.Join(t.TempDir(), "fresh-fhs")
		fresh.Transport.DataDir = filepath.Join(t.TempDir(), "never-opened-outbox")
		if s, err = service.Open(fresh); err == nil {
			s.Close()
			t.Fatal("fresh service accepted malformed snapshot")
		}
		if _, err = os.Stat(fresh.Transport.DataDir); !os.IsNotExist(err) || initialized || votes != 0 {
			t.Fatal("transport/actor/signing opened before bootstrap authentication")
		}
	})
	t.Logf("FINANCIAL_SNAPSHOT schema=4 state=5 finalized=3 distinctLateMember=6 participation=1 nativeTotal=6 bytes=%d", len(snapshot))
}
