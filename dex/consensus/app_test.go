package consensus

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

type delivery struct {
	to      string
	message *hotstuff.HotstuffMessage
}
type network struct {
	nodes    []*Application
	configs  []Config
	queue    []delivery
	dropped  map[string]bool
	capacity int
}

func newNetwork(t *testing.T, height uint64) *network {
	return newConfiguredNetwork(t, height, nil)
}
func newConfiguredNetwork(t *testing.T, height uint64, configure func(*Config)) *network {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("isolated DEX WAL fixture is Linux-only")
	}
	members := make([]*common.Cnode, 7)
	secrets := make([]bls.SecretKey, 7)
	for i := range secrets {
		if err := secrets[i].SetDecString(fmt.Sprint(700 + i)); err != nil {
			t.Fatal(err)
		}
		members[i] = &common.Cnode{Address: fmt.Sprintf("127.0.0.1:%d", 27000+i), CoinBase: fmt.Sprintf("fixture-reward-%d", i), Public: secrets[i].GetPublicKey().SerializeToHexStr()}
	}
	d := protocol.Domain{Version: 1, ChainID: 991, Genesis: protocol.Digest("fixture", []byte("clx-genesis")), DEXID: protocol.Digest("fixture", []byte("dex")), Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: members}).RlpHash())}
	n := &network{dropped: make(map[string]bool), capacity: 4096}
	root := t.TempDir()
	for i := range members {
		c := Config{Domain: d, Members: members, Index: i, Secret: &secrets[i], DataDir: filepath.Join(root, fmt.Sprint(i)), CLXHash: protocol.Digest("fixture", []byte("finalized-clx")), CLXHeight: 1, MaxHeight: height}
		if configure != nil {
			configure(&c)
		}
		a, err := Open(c)
		if err != nil {
			t.Fatal(err)
		}
		n.configs = append(n.configs, c)
		n.nodes = append(n.nodes, a)
		a.SetTransport(n.send)
	}
	t.Cleanup(func() {
		for _, a := range n.nodes {
			a.Close()
		}
	})
	return n
}
func (n *network) send(to string, msg *hotstuff.HotstuffMessage) error {
	if n.dropped[to] {
		return errors.New("partitioned DEX peer")
	}
	if len(n.queue) >= n.capacity {
		return errors.New("DEX queue saturated")
	}
	n.queue = append(n.queue, delivery{to, msg})
	return nil
}
func benign(err error) bool {
	if err == nil {
		return true
	}
	for _, target := range []error{hotstuff.ErrInsufficientQC, hotstuff.ErrProposalValidationPending, hotstuff.ErrUnhandledMsg, hotstuff.ErrOldState, hotstuff.ErrMissingView, hotstuff.ErrViewOldPhase, hotstuff.ErrFutureState} {
		if errors.Is(err, target) {
			return true
		}
	}
	return strings.Contains(err.Error(), "counter fixture height limit") || strings.Contains(err.Error(), "partitioned DEX peer")
}
func (n *network) pump(t *testing.T) {
	t.Helper()
	for step := 0; step < 20000; step++ {
		progress := false
		for _, a := range n.nodes {
			if n.dropped[a.Self()] || a.closed {
				continue
			}
			did, err := a.Advance()
			if !benign(err) {
				t.Fatalf("advance %s: %v", a.Self(), err)
			}
			progress = progress || did
		}
		if len(n.queue) > 0 {
			d := n.queue[0]
			n.queue = n.queue[1:]
			progress = true
			for _, a := range n.nodes {
				if a.Self() == d.to && !a.closed && !n.dropped[d.to] {
					if err := a.Handle(d.message); !benign(err) {
						t.Fatalf("handle %s code %d view %d: %v", d.to, d.message.Code, d.message.Number, err)
					}
					break
				}
			}
		}
		if !progress {
			return
		}
	}
	t.Fatal("bounded network did not quiesce")
}
func (n *network) start(t *testing.T) {
	t.Helper()
	for _, a := range n.nodes {
		if err := a.Start(); !benign(err) {
			t.Fatal(err)
		}
	}
	n.pump(t)
}

func TestSevenFHSInstancesExecuteFinalizeAndRestart(t *testing.T) {
	n := newNetwork(t, 5)
	n.start(t)
	for i, a := range n.nodes {
		if a.CertifiedHeight() != 5 || a.FinalizedHeight() != 4 {
			t.Fatalf("node %d certified=%d finalized=%d", i, a.CertifiedHeight(), a.FinalizedHeight())
		}
		for h := uint64(1); h <= 4; h++ {
			cp, proof, err := a.FinalizedCheckpoint(h)
			if err != nil {
				t.Fatal(err)
			}
			if cp.PostRoot != counterRoot(h) {
				t.Fatal("counter execution mismatch")
			}
			if _, err = a.epoch.Verify(cp, proof); err != nil {
				t.Fatal(err)
			}
		}
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		restarted, err := Open(n.configs[i])
		if err != nil {
			t.Fatalf("restart %d: %v", i, err)
		}
		n.nodes[i] = restarted
		restarted.SetTransport(n.send)
		if restarted.FinalizedHeight() != 4 || restarted.CertifiedHeight() != 5 {
			t.Fatal("restart lost certified/finalized state")
		}
	}
}

func TestWALExclusiveForeignAndCorruptFailClosed(t *testing.T) {
	n := newNetwork(t, 3)
	if other, err := Open(n.configs[0]); err == nil {
		other.Close()
		t.Fatal("same WAL opened twice")
	}
	n.start(t)
	if err := n.nodes[0].Close(); err != nil {
		t.Fatal(err)
	}
	foreign := n.configs[0]
	foreign.Domain.DEXID[0] ^= 1
	if other, err := Open(foreign); err == nil {
		other.Close()
		t.Fatal("foreign domain WAL accepted")
	}
	otherSigner := n.configs[1]
	otherSigner.DataDir = n.configs[0].DataDir
	if other, err := Open(otherSigner); err == nil {
		other.Close()
		t.Fatal("another vote key adopted this participant WAL")
	}
	p := filepath.Join(n.configs[0].DataDir, "state.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 1
	if err = os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(n.configs[0]); err == nil {
		other.Close()
		t.Fatal("corrupt WAL accepted")
	}
}

func TestRestartVoteConflictMissingDataAndQueueBound(t *testing.T) {
	n := newNetwork(t, 3)
	n.start(t)
	a := n.nodes[0]
	v := hotstuff.ClonePersistedVote(a.disk.Safety.LastVote)
	if v == nil {
		t.Fatal("no durable vote")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	a, err = Open(n.configs[0])
	if err != nil {
		t.Fatal(err)
	}
	n.nodes[0] = a
	bad := hotstuff.ClonePersistedVote(v)
	ref, err := types.DecodeHotstuffProposalRef(bad.ProposalRef)
	if err != nil {
		t.Fatal(err)
	}
	ref.StateRoot[0] ^= 1
	bad.ProposalRef = ref.EncodeToBytes()
	bad.ProposalRefHash = hotstuff.StateDigest(bad.ProposalRef)
	bad.ProposalID = ref.ProposalID()
	if err = a.PersistFHSVote(bad); err == nil {
		t.Fatal("restart allowed conflicting vote")
	}
	q := a.HighestCertified()
	r := a.recordForQC(q)
	ref, _ = types.DecodeHotstuffProposalRef(q.State)
	delete(a.disk.Records, ref.ProposalID().Hex())
	if err = a.AdoptFHSHighQC(q); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing data must be explicit: %v", err)
	}
	a.disk.Records[ref.ProposalID().Hex()] = r
	a.SetTransport(n.send)
	n.queue = nil
	n.capacity = 1
	msg := &hotstuff.HotstuffMessage{Code: hotstuff.MsgNewView}
	if err = a.Write(a.Self(), msg); err != nil {
		t.Fatal(err)
	}
	if err = a.Write(a.Self(), msg); err == nil {
		t.Fatal("queue overflow accepted")
	}
}

func TestCounterSnapshotThirdPartyReplayAndSafetyPreservation(t *testing.T) {
	n := newNetwork(t, 4)
	n.start(t)
	snapshot, err := n.nodes[2].ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	c := n.configs[0]
	c.DataDir = filepath.Join(t.TempDir(), "rejoin")
	fresh, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err = fresh.ImportSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	if fresh.FinalizedHeight() != 3 || fresh.CertifiedHeight() != 4 {
		t.Fatal("third party replay lost finality")
	}
	if fresh.disk.Safety.LastVote != nil || fresh.disk.Safety.LastTimeoutVote != nil || fresh.disk.Outbox != nil {
		t.Fatal("snapshot imported another participant's local safety")
	}
	if _, err = fresh.ProposalData("missing"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("data missing was not explicit")
	}
	before := hotstuff.ClonePersistedVote(n.nodes[1].disk.Safety.LastVote)
	if err = n.nodes[1].ImportSnapshot(snapshot); err == nil {
		t.Fatal("peer snapshot replaced voter state")
	}
	if !bytes.Equal(before.ProposalRef, n.nodes[1].disk.Safety.LastVote.ProposalRef) {
		t.Fatal("rejected snapshot changed local vote")
	}
	var broken replaySnapshot
	if err = json.Unmarshal(snapshot, &broken); err != nil {
		t.Fatal(err)
	}
	for _, r := range broken.Records {
		r.Action = 2
		break
	}
	bad, err := json.Marshal(broken)
	if err != nil {
		t.Fatal(err)
	}
	c.DataDir = filepath.Join(t.TempDir(), "bad-rejoin")
	empty, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	if err = empty.ImportSnapshot(bad); err == nil {
		t.Fatal("snapshot was accepted without reexecution")
	}
	if len(empty.disk.Records) != 0 || empty.FinalizedHeight() != 0 {
		t.Fatal("failed snapshot changed syncing state")
	}
}

func TestWALRefusesExistingUnmarkedDirectory(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	original := []byte("operational data fixture")
	if err := os.WriteFile(p, original, 0600); err != nil {
		t.Fatal(err)
	}
	if w, err := openWAL(dir); err == nil {
		w.close()
		t.Fatal("unmarked directory adopted")
	}
	after, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("unmarked data changed")
	}
	if _, err = os.Stat(filepath.Join(dir, "LOCK")); !os.IsNotExist(err) {
		t.Fatal("unmarked directory was written")
	}
}

func TestTwoOfflineValidatorsTimeoutThenFiveMakeProgress(t *testing.T) {
	n := newNetwork(t, 3)
	n.dropped[n.nodes[0].Self()] = true
	n.dropped[n.nodes[6].Self()] = true
	n.start(t)
	for _, a := range n.nodes {
		if a.FinalizedHeight() != 0 {
			t.Fatal("offline initial leader still finalized")
		}
	}
	for i, a := range n.nodes {
		if i == 0 || i == 6 {
			continue
		}
		if err := a.Timeout(); !benign(err) {
			t.Fatalf("timeout: %v", err)
		}
	}
	n.pump(t)
	for i, a := range n.nodes {
		if i == 0 || i == 6 {
			continue
		}
		if a.CertifiedHeight() != 3 || a.FinalizedHeight() != 2 {
			t.Fatalf("node %d after timeout: certified %d finalized %d", i, a.CertifiedHeight(), a.FinalizedHeight())
		}
	}
}

func TestCounterExecutionRejectsBadActionRootAndParent(t *testing.T) {
	n := newNetwork(t, 3)
	a := n.nodes[0]
	context := hotstuff.FHSViewContext{Version: 3, ChainID: a.ChainID(), TargetView: 1, KeyNumber: a.config.Domain.Epoch, KeyHash: common.Hash(a.config.Domain.EpochKey()), CommitteeHash: common.Hash(a.config.Domain.Committee), LeaderID: a.Self(), EntryKind: hotstuff.FHSViewFromQC}
	record, err := a.build(&hotstuff.FHSProposalBuildRequest{Key: hotstuff.FHSProposalBuildKey{ViewNumber: 1, ViewID: context.ID(), LeaderID: a.Self()}})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Record){
		func(r *Record) { r.Action = 2 }, func(r *Record) { r.Checkpoint.PreRoot[0] ^= 1 }, func(r *Record) { r.Checkpoint.PostRoot[0] ^= 1 }, func(r *Record) { r.Checkpoint.Previous[0] ^= 1 }, func(r *Record) { r.Checkpoint.ChainID++ },
	} {
		bad := *record
		mutate(&bad)
		extra, err := encodeExtra(&bad)
		if err != nil {
			t.Fatal(err)
		}
		if err = a.OnPropose(bad.Ref, extra, 1, nil); err == nil {
			t.Fatal("bad execution accepted")
		}
		if len(a.disk.Records) != 0 || a.disk.Safety.LastVote != nil {
			t.Fatal("bad execution mutated state")
		}
	}
	extra, err := encodeExtra(record)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.OnPropose(record.Ref, extra, 1, nil); err != nil {
		t.Fatal(err)
	}
	if len(a.disk.Records) != 1 {
		t.Fatal("valid deterministic execution not retained")
	}
}

func TestPersistenceFailureDisablesVotingUntilRestart(t *testing.T) {
	n := newNetwork(t, 3)
	a := n.nodes[0]
	ctx := hotstuff.FHSViewContext{Version: 3, ChainID: a.ChainID(), TargetView: 1, KeyNumber: a.config.Domain.Epoch, KeyHash: common.Hash(a.config.Domain.EpochKey()), CommitteeHash: common.Hash(a.config.Domain.Committee), LeaderID: a.Self(), EntryKind: hotstuff.FHSViewFromQC}
	r, err := a.build(&hotstuff.FHSProposalBuildRequest{Key: hotstuff.FHSProposalBuildKey{ViewNumber: 1, ViewID: ctx.ID(), LeaderID: a.Self()}})
	if err != nil {
		t.Fatal(err)
	}
	extra, _ := encodeExtra(r)
	if err = a.OnPropose(r.Ref, extra, 1, nil); err != nil {
		t.Fatal(err)
	}
	ref, _ := types.DecodeHotstuffProposalRef(r.Ref)
	v := &hotstuff.PersistedVote{ViewNumber: 1, ViewID: ctx.ID(), LeaderID: a.Self(), ProposalID: ref.ProposalID(), ProposalRef: r.Ref, ProposalRefHash: hotstuff.StateDigest(r.Ref)}
	original := a.wal.dir
	a.wal.dir = filepath.Join(original, "absent-directory")
	if err = a.PersistFHSVote(v); err == nil {
		t.Fatal("vote survived failed durable write")
	}
	a.wal.dir = original
	if err = a.PersistFHSVote(v); err == nil {
		t.Fatal("failed WAL continued signing in memory")
	}
	if err = a.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(n.configs[0])
	if err != nil {
		t.Fatal(err)
	}
	n.nodes[0] = restarted
	if restarted.disk.Safety.LastVote != nil {
		t.Fatal("failed vote appeared in durable WAL")
	}
	if err = restarted.PersistFHSVote(v); err != nil {
		t.Fatal(err)
	}
}

func TestCounterIndependentGoldenRoots(t *testing.T) {
	var vectors struct {
		Action     string
		ActionRoot string `json:"action_root"`
		Roots      []struct{ Value, Root string }
	}
	b, err := os.ReadFile("../testdata/counter.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors.Roots {
		n, err := strconv.ParseUint(v.Value, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		root := counterRoot(n)
		if hex.EncodeToString(root[:]) != v.Root {
			t.Fatalf("counter %d golden mismatch", n)
		}
	}
	action, err := hex.DecodeString(vectors.Action)
	if err != nil {
		t.Fatal(err)
	}
	root := protocol.Digest("common-dex/counter-action/v1", action)
	if hex.EncodeToString(root[:]) != vectors.ActionRoot {
		t.Fatal("action golden mismatch")
	}
}

func TestDEXIngressRejectsEmptySignatureAndInternalControl(t *testing.T) {
	n := newNetwork(t, 3)
	a := n.nodes[0]
	for _, code := range []uint32{hotstuff.MsgNewView, hotstuff.MsgTimeout, hotstuff.MsgTimeoutQC, hotstuff.MsgQCBroadcast, hotstuff.MsgPrepare, hotstuff.MsgDecide, hotstuff.MsgLocalTimeout, hotstuff.MsgStartNewView} {
		m := &hotstuff.HotstuffMessage{Code: code, Number: 1, Id: a.Self(), PubKey: a.keys[0].Serialize(), AuthSig: []byte{1}, DataC: []byte{0x1f}}
		if err := a.Handle(m); err == nil {
			t.Fatalf("empty signature/internal control accepted: %d", code)
		}
	}
	for _, bad := range []*hotstuff.HotstuffMessage{
		{Code: hotstuff.MsgVotePrepare, Id: a.Self(), PubKey: a.keys[0].Serialize(), AuthSig: []byte{1}},
		{Code: hotstuff.MsgVotePrepare, Id: a.Self(), PubKey: a.keys[0].Serialize(), AuthSig: []byte{1}, DataB: []byte{1}, DataC: []byte{1}},
		{Code: hotstuff.MsgVotePrepare, Id: a.Self(), PubKey: a.keys[0].Serialize(), AuthSig: []byte{1}, DataC: make([]byte, 129)},
	} {
		if err := a.Handle(bad); err == nil {
			t.Fatal("malformed prepare vote accepted")
		}
	}
	if a.CertifiedHeight() != 0 || a.FinalizedHeight() != 0 || a.disk.Safety.LastVote != nil {
		t.Fatal("malformed ingress changed DEX safety")
	}
}

func TestEmptyTimeoutSignatureRejectedByDirectAdmissionAndRecovery(t *testing.T) {
	n := newNetwork(t, 3)
	a := n.nodes[0]
	tc := &hotstuff.TimeoutCertificate{Statement: hotstuff.TimeoutStatement{Version: 3, ChainID: a.ChainID(), TimedOutView: 1, KeyNumber: a.config.Domain.Epoch, KeyHash: common.Hash(a.config.Domain.EpochKey()), CommitteeHash: common.Hash(a.config.Domain.Committee)}, Mask: []byte{0x1f}}
	if err := a.AcceptFHSTimeoutCertificate(tc); err == nil {
		t.Fatal("empty direct TC accepted")
	}
	a.disk.Safety.HighestTC = tc
	a.disk.Safety.LastTimeoutView = 1
	if err := a.persist(); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(n.configs[0]); err == nil {
		opened.Close()
		t.Fatal("empty TC accepted from checksummed WAL")
	}
}

func FuzzDEXWireBounds(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{byte(hotstuff.MsgVotePrepare), 0xff, 0xff})
	ctx := hotstuff.FHSViewContext{Version: 3, ChainID: 991, TargetView: 1, KeyNumber: 1, KeyHash: common.HexToHash("0x1"), CommitteeHash: common.HexToHash("0x2"), LeaderID: "fixture", EntryKind: hotstuff.FHSViewFromQC}
	report, _ := hotstuff.EncodeNewViewReport(&hotstuff.NewViewReport{Context: ctx})
	m := &hotstuff.HotstuffMessage{Code: hotstuff.MsgNewView, Number: 1, Id: "fixture", PubKey: make([]byte, 64), AuthSig: []byte{1}, DataA: report, DataB: []byte{1}}
	seed, _ := rlp.EncodeToBytes(m)
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxWireBytes {
			return
		}
		var m hotstuff.HotstuffMessage
		if err := rlp.DecodeBytes(b, &m); err != nil {
			return
		}
		_ = validateDEXWire(&m)
	})
}
