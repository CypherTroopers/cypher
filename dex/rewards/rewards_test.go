package rewards

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func TestIndependentParticipationGolden(t *testing.T) {
	data, err := os.ReadFile("../testdata/participation.json")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	raw := func(key string) []byte {
		b, err := hex.DecodeString(v[key])
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	duty, err := DecodeDuty(raw("duty"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := duty.Encode()
	if !bytes.Equal(encoded, raw("duty")) {
		t.Fatal("duty codec")
	}
	h, _ := duty.Hash()
	if hex.EncodeToString(h[:]) != v["duty_hash"] {
		t.Fatal("duty hash")
	}
	receipt, err := DecodeReceipt(raw("receipt"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = receipt.Encode()
	if !bytes.Equal(encoded, raw("receipt")) {
		t.Fatal("receipt codec")
	}
	h, err = receiptDigest(duty, receipt.Collector, raw("collector_public_structural_fixture"))
	if err != nil || hex.EncodeToString(h[:]) != v["receipt_signing_hash"] {
		t.Fatal("receipt hash", err)
	}
	cert, err := DecodeCertificate(raw("certificate"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = cert.Encode()
	if !bytes.Equal(encoded, raw("certificate")) {
		t.Fatal("certificate codec")
	}
	var points Points
	if err := binary.Read(bytes.NewReader(raw("points")), binary.BigEndian, &points); err != nil {
		t.Fatal(err)
	}
	encoded, err = points.Encode()
	if err != nil || !bytes.Equal(encoded, raw("points")) {
		t.Fatal("points codec", err)
	}
	h, err = points.Root()
	if err != nil || hex.EncodeToString(h[:]) != v["points_root"] {
		t.Fatal("points root", err)
	}
	p, err := DecodeClosePackage(raw("close_package"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = p.Encode()
	if err != nil || !bytes.Equal(encoded, raw("close_package")) {
		t.Fatal("close package codec", err)
	}

	var registration struct {
		Domain     protocol.Domain
		Epoch      protocol.Hash
		Recipients [7][20]byte
	}
	if err := binary.Read(bytes.NewReader(raw("registry_commitment_preimage")), binary.BigEndian, &registration); err != nil {
		t.Fatal(err)
	}
	h = registryCommitment(registration.Domain, registration.Epoch, registration.Recipients)
	if hex.EncodeToString(h[:]) != v["registry_commitment"] {
		t.Fatal("registry commitment golden")
	}
	if p.Period != 2 || len(p.Blocks) != 11 || p.Blocks[10].Checkpoint.LastBlock != 24 {
		t.Fatal("close golden boundary")
	}
}

type rewardFixture struct {
	registry *Registry
	keys     [7]bls.SecretKey
	members  []*common.Cnode
	cp       protocol.Checkpoint
	blocks   []FinalizedBlock
	refs     map[uint64]*types.HotstuffProposalRef
}

func newRewardFixture(t *testing.T) *rewardFixture {
	t.Helper()
	f := &rewardFixture{refs: make(map[uint64]*types.HotstuffProposalRef)}
	recipients := make([][20]byte, 7)
	for i := 0; i < 7; i++ {
		if err := f.keys[i].SetDecString(fmt.Sprint(11 + i)); err != nil {
			t.Fatal(err)
		}
		recipients[i][19] = byte(i + 1)
		f.members = append(f.members, &common.Cnode{Address: fmt.Sprintf("reward-devnet-%d", i), Public: f.keys[i].GetPublicKey().SerializeToHexStr(), CoinBase: fmt.Sprintf("nonpayment-voter-%d", i)})
	}
	f.cp = protocol.Checkpoint{Version: 1, ProofMode: 1, ChainID: 9127001, Genesis: protocol.Hash{1}, DEXID: protocol.Hash{2}, Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: f.members}).RlpHash()), Sequence: 1, PreRoot: protocol.Hash{3}, PostRoot: protocol.Hash{4}, FirstBlock: 1, LastBlock: 1, CLXHeight: 10, CLXHash: protocol.Hash{5}, DataRoot: protocol.Hash{6}, DataSchema: 2}
	var err error
	f.registry, err = NewRegistry(f.cp.Domain(), f.members, recipients)
	if err != nil {
		t.Fatal(err)
	}
	for height := uint64(1); height <= 14; height++ {
		if height > 1 {
			old := f.cp
			f.cp.Previous, _ = old.Hash()
			f.cp.PreRoot = old.PostRoot
			f.cp.PostRoot = protocol.Hash{byte(height), 4}
			f.cp.Sequence = height
			f.cp.FirstBlock = height
			f.cp.LastBlock = height
		}
		block, ref := f.proof(t, f.cp, height)
		f.refs[height] = ref
		if height <= 10 || height == 14 {
			f.blocks = append(f.blocks, block)
		}
	}
	return f
}
func (f *rewardFixture) signed(t *testing.T, ref *types.HotstuffProposalRef) *hotstuff.SignedState {
	t.Helper()
	var sig *bls.Sign
	for i := 0; i < 5; i++ {
		s, err := hotstuff.SignFHSSignatureWithContext(&f.keys[i], f.keys[i].GetPublicKey(), ref.EncodeToBytes(), ref.ChainID, hotstuff.MsgVotePrepare, ref.ViewID, ref.LeaderID)
		if err != nil {
			t.Fatal(err)
		}
		if sig == nil {
			sig = s
		} else {
			sig.Add(s)
		}
	}
	return &hotstuff.SignedState{State: ref.EncodeToBytes(), Sign: sig.Serialize(), Mask: []byte{31}, ViewID: ref.ViewID, LeaderID: ref.LeaderID, Number: ref.ViewNumber}
}
func (f *rewardFixture) proof(t *testing.T, cp protocol.Checkpoint, view uint64) (FinalizedBlock, *types.HotstuffProposalRef) {
	t.Helper()
	hash, err := cp.Hash()
	if err != nil {
		t.Fatal(err)
	}
	ref := &types.HotstuffProposalRef{Version: types.HotstuffProposalRefVersion, ChainID: cp.ChainID, Number: cp.LastBlock, ViewNumber: view, ViewID: common.Hash{byte(view), 42}, LeaderID: f.members[(view-1)%7].Address, BlockHash: common.Hash(hash), ParentHash: common.Hash{99}, StateRoot: common.Hash(cp.PostRoot), BodyHash: common.Hash(cp.DataRoot), BodySize: 8, ExtraHash: types.HotstuffProposalExtraHash(nil), KeyHash: common.Hash(cp.Domain().EpochKey()), Time: cp.LastBlock}
	target := f.signed(t, ref)
	child := *ref
	child.Number++
	child.Time++
	child.ViewNumber++
	child.ViewID = common.Hash{byte(child.ViewNumber), 42}
	child.LeaderID = f.members[(child.ViewNumber-1)%7].Address
	child.ParentHash = ref.BlockHash
	child.BlockHash = common.Hash{51, byte(cp.LastBlock)}
	id, err := hotstuff.SignedStateID(target)
	if err != nil {
		t.Fatal(err)
	}
	child.ParentQCID = id.Hash()
	proof, err := checkpoint.EncodeProof(checkpoint.Proof{Target: target, Descendants: []*hotstuff.SignedState{f.signed(t, &child)}})
	if err != nil {
		t.Fatal(err)
	}
	return FinalizedBlock{cp, proof}, ref
}
func persisted(ref *types.HotstuffProposalRef) *hotstuff.PersistedVote {
	data := ref.EncodeToBytes()
	return &hotstuff.PersistedVote{ViewNumber: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID, ProposalRef: data, ProposalID: ref.ProposalID(), ProposalRefHash: hotstuff.StateDigest(data)}
}
func (f *rewardFixture) vote(t *testing.T, height uint64, participant int) *hotstuff.HotstuffMessage {
	t.Helper()
	ref := f.refs[height]
	sig, err := hotstuff.SignFHSSignatureWithContext(&f.keys[participant], f.keys[participant].GetPublicKey(), ref.EncodeToBytes(), ref.ChainID, hotstuff.MsgVotePrepare, ref.ViewID, ref.LeaderID)
	if err != nil {
		t.Fatal(err)
	}
	return &hotstuff.HotstuffMessage{Code: hotstuff.MsgVotePrepare, Number: ref.ViewNumber, ViewId: ref.ViewID, Id: f.members[participant].Address, PubKey: f.keys[participant].GetPublicKey().Serialize(), DataC: sig.Serialize()}
}
func (f *rewardFixture) collector(t *testing.T, index int, dir string) *Collector {
	t.Helper()
	c, err := OpenCollector(dir, f.registry, uint8(index), &f.keys[index])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Shutdown() })
	return c
}
func (f *rewardFixture) certificate(t *testing.T, collectors []*Collector, height uint64, participant int) Certificate {
	t.Helper()
	var receipts []Receipt
	for _, c := range collectors {
		if err := c.BeforeVote(persisted(f.refs[height])); err != nil {
			t.Fatal(err)
		}
		receipt, err := c.Issue(f.refs[height].EncodeToBytes(), f.vote(t, height, participant))
		if err != nil {
			t.Fatal(err)
		}
		receipts = append(receipts, receipt)
	}
	cert, err := f.registry.Certificate(receipts)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
func (f *rewardFixture) five(t *testing.T) []*Collector {
	t.Helper()
	var cs []*Collector
	root := t.TempDir()
	for i := 0; i < 5; i++ {
		cs = append(cs, f.collector(t, i, filepath.Join(root, fmt.Sprint(i))))
	}
	return cs
}

func TestReceiptDeadlineRestartAndIndependentRewardAddress(t *testing.T) {
	f := newRewardFixture(t)
	dir := filepath.Join(t.TempDir(), "collector")
	c := f.collector(t, 0, dir)
	ref := f.refs[1]
	vote := f.vote(t, 1, 6)
	if _, err := c.Issue(ref.EncodeToBytes(), vote); !errors.Is(err, ErrUnvalidatedTarget) {
		t.Fatal("unvalidated target", err)
	}
	if err := c.BeforeVote(persisted(ref)); err != nil {
		t.Fatal(err)
	}
	receipt, err := c.Issue(ref.EncodeToBytes(), vote)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Duty.Recipient != f.registry.recipients[6] || receipt.Duty.Participant != 6 {
		t.Fatal("recipient registry")
	}
	if err := f.registry.VerifyReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	if err := c.BeforeVote(persisted(f.refs[2])); err != nil {
		t.Fatal(err)
	}
	if c.ClosedThrough() != 1 {
		t.Fatal("cutoff")
	}
	if _, err := c.Issue(ref.EncodeToBytes(), f.vote(t, 1, 5)); !errors.Is(err, ErrDeadline) {
		t.Fatal("late signature allowed", err)
	}
	if got, err := c.Issue(ref.EncodeToBytes(), vote); err != nil || got != receipt {
		t.Fatal("persisted retry", err)
	}
	if err := c.Shutdown(); err != nil {
		t.Fatal(err)
	}
	c = f.collector(t, 0, dir)
	if c.ClosedThrough() != 1 {
		t.Fatal("lost restart cutoff")
	}
	if _, err := c.Issue(ref.EncodeToBytes(), f.vote(t, 1, 5)); !errors.Is(err, ErrDeadline) {
		t.Fatal("restart late signature", err)
	}
	if got, err := c.Issue(ref.EncodeToBytes(), vote); err != nil || got != receipt {
		t.Fatal("restart receipt replay", err)
	}
	bad := persisted(f.refs[2])
	bad.ProposalRef[0] ^= 1
	if err := c.BeforeVote(bad); err == nil {
		t.Fatal("altered vote metadata")
	}
}

func TestCollectorAuthenticationAndQuorum(t *testing.T) {
	f := newRewardFixture(t)
	cs := f.five(t)
	cert := f.certificate(t, cs, 1, 6)
	if err := f.registry.VerifyCertificate(cert); err != nil {
		t.Fatal(err)
	}
	bad := cert
	bad.Signatures = append([]CollectorSignature(nil), cert.Signatures[:4]...)
	if err := f.registry.VerifyCertificate(bad); err == nil {
		t.Fatal("four collectors accepted")
	}
	bad = cert
	bad.Signatures = append([]CollectorSignature(nil), cert.Signatures...)
	bad.Signatures[1] = bad.Signatures[0]
	if err := f.registry.VerifyCertificate(bad); err == nil {
		t.Fatal("duplicate collector")
	}
	mutations := []func(*Receipt){func(r *Receipt) { r.Duty.Domain.DEXID[0]++ }, func(r *Receipt) { r.Duty.Domain.Epoch++ }, func(r *Receipt) { r.Duty.Domain.Genesis[0]++ }, func(r *Receipt) { r.Duty.Recipient[0]++ }, func(r *Receipt) { r.Duty.Participant = 0 }, func(r *Receipt) { r.Duty.ProposalID[0]++ }, func(r *Receipt) { r.Collector = 1 }, func(r *Receipt) { r.Signature[0] ^= 1 }}
	for i, mutate := range mutations {
		r := Receipt{cert.Duty, cert.Signatures[0].Collector, cert.Signatures[0].Signature}
		mutate(&r)
		if err := f.registry.VerifyReceipt(r); err == nil {
			t.Fatalf("receipt mutation %d accepted", i)
		}
	}
	for name, mutate := range map[string]func(*hotstuff.HotstuffMessage){"signature": func(v *hotstuff.HotstuffMessage) { v.DataC[0] ^= 1 }, "public": func(v *hotstuff.HotstuffMessage) { v.PubKey[0] ^= 1 }, "view": func(v *hotstuff.HotstuffMessage) { v.ViewId[0]++ }, "member": func(v *hotstuff.HotstuffMessage) { v.Id = "foreign" }, "message": func(v *hotstuff.HotstuffMessage) { v.Code = hotstuff.MsgNewView }, "oversized": func(v *hotstuff.HotstuffMessage) { v.DataA = make([]byte, 16384) }} {
		t.Run(name, func(t *testing.T) {
			v := f.vote(t, 1, 5)
			mutate(v)
			if _, err := cs[0].Issue(f.refs[1].EncodeToBytes(), v); err == nil {
				t.Fatal("malformed vote allowed")
			}
		})
	}
}

func TestPeriodPointsNotFirstQCAndCloseOmissionFreeze(t *testing.T) {
	f := newRewardFixture(t)
	cs := f.five(t)
	cert := f.certificate(t, cs, 1, 6)
	proof, err := checkpoint.DecodeProof(f.blocks[0].Proof)
	if err != nil || proof.Target.Mask[0]&(1<<6) != 0 {
		t.Fatal("fixture voter unexpectedly in first QC", err)
	}
	points, err := f.registry.ComputePoints(1, f.blocks, []Certificate{cert, cert})
	if err != nil {
		t.Fatal(err)
	}
	if points.Entries[6].Points != 1 {
		t.Fatal("duplicate adds points or omitted-QC voter excluded")
	}
	for i := 0; i < 6; i++ {
		if points.Entries[i].Points != 0 {
			t.Fatal("QC-only rewards")
		}
	}
	for _, c := range cs {
		if err := c.RememberCertificate(cert); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Close(1, f.blocks, nil); !errors.Is(err, ErrOmittedCertificate) {
			t.Fatal("known certificate omission", err)
		}
	}
	if _, err := cs[0].CheckClose(1, f.blocks, []Certificate{cert}); err != nil {
		t.Fatal(err)
	}
	if len(cs[0].disk.Closed) != 0 {
		t.Fatal("nonmutating close mutated WAL")
	}
	p, err := cs[0].Close(1, f.blocks, []Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	if p != points {
		t.Fatal("points mismatch")
	}
	if _, err := cs[0].Close(1, f.blocks, []Certificate{cert}); err != nil {
		t.Fatal("close replay", err)
	}
	if _, err := cs[0].Close(1, f.blocks, nil); !errors.Is(err, ErrPeriodClosed) {
		t.Fatal("closed root changed", err)
	}
	dir := cs[0].wal.dir
	cs[0].Shutdown()
	restored := f.collector(t, 0, dir)
	if _, err := restored.Close(1, f.blocks, []Certificate{cert}); err != nil {
		t.Fatal("closed WAL restart", err)
	}
	if _, err := restored.Close(1, f.blocks, nil); !errors.Is(err, ErrPeriodClosed) {
		t.Fatal("restart closed root changed", err)
	}
	fresh := f.five(t)
	newCert := f.certificate(t, fresh, 2, 6)
	if err := restored.RememberCertificate(newCert); !errors.Is(err, ErrPeriodClosed) {
		t.Fatal("late certificate amended closed period", err)
	}
}

func TestCloseFinalityBoundaryAndMalformedInputs(t *testing.T) {
	f := newRewardFixture(t)
	cert := f.certificate(t, f.five(t), 1, 6)
	p := ClosePackage{1, f.blocks, []Certificate{cert}}
	encoded, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeClosePackage(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.registry.ComputePoints(decoded.Period, decoded.Blocks, decoded.Certificates); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual close package bytes=%d, proof bytes=%d", len(encoded), len(f.blocks[0].Proof))
	for name, mutate := range map[string]func([]FinalizedBlock){"grace_missing": func(b []FinalizedBlock) { b[10] = b[9] }, "checkpoint_root": func(b []FinalizedBlock) { b[2].Checkpoint.PostRoot[0] ^= 1 }, "disconnected": func(b []FinalizedBlock) { b[1].Checkpoint.Previous[0] ^= 1 }, "single_qc": func(b []FinalizedBlock) {
		proof, _ := checkpoint.DecodeProof(b[0].Proof)
		proof.Descendants = nil
		b[0].Proof, _ = checkpoint.EncodeProof(proof)
	}, "signature": func(b []FinalizedBlock) { b[0].Proof = bytes.Clone(b[0].Proof); b[0].Proof[len(b[0].Proof)-1] ^= 1 }} {
		t.Run(name, func(t *testing.T) {
			bs := append([]FinalizedBlock(nil), f.blocks...)
			mutate(bs)
			if _, err := f.registry.ComputePoints(1, bs, []Certificate{cert}); err == nil {
				t.Fatal("bad finality accepted")
			}
		})
	}
	if _, err := f.registry.ComputePoints(1, f.blocks[:10], nil); err == nil {
		t.Fatal("missing grace")
	}
	if _, err := f.registry.ComputePoints(2, f.blocks, []Certificate{cert}); err == nil {
		t.Fatal("foreign period")
	}
	other := cert
	other.Duty.View++
	if _, err := f.registry.ComputePoints(1, f.blocks, []Certificate{other}); err == nil {
		t.Fatal("wrong duty view")
	}
	for name, b := range map[string][]byte{"trailing": append(bytes.Clone(encoded), 0), "truncated": encoded[:len(encoded)-1], "huge": make([]byte, MaxClosePackageBytes+1), "marker": append([]byte("NOTVALID"), encoded[8:]...), "count": append(append(bytes.Clone(encoded[:16]), 255), encoded[17:]...)} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeClosePackage(b); err == nil {
				t.Fatal("bad envelope")
			}
		})
	}
	p.Certificates = []Certificate{cert, cert}
	if _, err := p.Encode(); err == nil {
		t.Fatal("duplicate slot canonical envelope")
	}
	p.Certificates = nil
	p.Blocks = append([]FinalizedBlock(nil), f.blocks...)
	for i := range p.Blocks {
		p.Blocks[i].Proof = make([]byte, checkpoint.MaxProofBytes)
	}
	if _, err := p.Encode(); err == nil {
		t.Fatal("aggregate size bound")
	}
}

func TestCollectorPersistenceUncertaintyAndOwnership(t *testing.T) {
	f := newRewardFixture(t)
	root := t.TempDir()
	dir := filepath.Join(root, "wal")
	c := f.collector(t, 0, dir)
	if _, err := OpenCollector(dir, f.registry, 0, &f.keys[0]); err == nil {
		t.Fatal("WAL concurrent owner")
	}
	occupied := filepath.Join(root, "operational")
	if err := os.Mkdir(occupied, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(occupied, "sentinel")
	os.WriteFile(sentinel, []byte("untouched"), 0600)
	if _, err := OpenCollector(occupied, f.registry, 0, &f.keys[0]); err == nil {
		t.Fatal("accepted unowned WAL")
	}
	data, _ := os.ReadFile(sentinel)
	if string(data) != "untouched" {
		t.Fatal("unowned data changed")
	}
	if err := c.BeforeVote(persisted(f.refs[1])); err != nil {
		t.Fatal(err)
	}
	c.persist = func(collectorDisk) error { return errors.New("injected fsync uncertainty") }
	if r, err := c.Issue(f.refs[1].EncodeToBytes(), f.vote(t, 1, 6)); !errors.Is(err, ErrPersistence) || r != (Receipt{}) {
		t.Fatal("signature escaped uncertain durable write", err)
	}
	if err := c.BeforeVote(persisted(f.refs[2])); !errors.Is(err, ErrPersistence) {
		t.Fatal("failed collector signed later vote", err)
	}
	c.Shutdown()
	c = f.collector(t, 0, dir)
	if c.ClosedThrough() != 0 || len(c.disk.Issued) != 0 {
		t.Fatal("failed nonpersisted mutation published")
	}
	c.persist = func(collectorDisk) error { return errors.New("injected WAL failure") }
	if err := c.BeforeVote(persisted(f.refs[2])); !errors.Is(err, ErrPersistence) {
		t.Fatal("pre-vote failure", err)
	}
	if c.ClosedThrough() != 0 {
		t.Fatal("failed cutoff published")
	}
	c.Shutdown()
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, f.keys[0].Serialize()) {
		t.Fatal("secret serialized")
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), bytes.Replace(data, []byte("Payload"), []byte("Unknown"), 1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCollector(dir, f.registry, 0, &f.keys[0]); err == nil {
		t.Fatal("corrupt WAL accepted")
	}
}

func TestCodecBoundsAndCanonicality(t *testing.T) {
	data, err := os.ReadFile("../testdata/participation.json")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	json.Unmarshal(data, &v)
	raw, _ := hex.DecodeString(v["certificate"])
	for _, length := range []int{0, 1, DutySize, MaxCertificateSize + 1} {
		if _, err := DecodeCertificate(make([]byte, length)); err == nil {
			t.Fatal("bad certificate length", length)
		}
	}
	if _, err := DecodeCertificate(append(bytes.Clone(raw), 0)); err == nil {
		t.Fatal("certificate trailing")
	}
	raw[DutySize] = 255
	if _, err := DecodeCertificate(raw); err == nil {
		t.Fatal("certificate huge count")
	}
	dutyRaw, _ := hex.DecodeString(v["duty"])
	duty, _ := DecodeDuty(dutyRaw)
	for name, mutate := range map[string]func(*Duty){"period": func(d *Duty) { d.Period++ }, "height": func(d *Duty) { d.Height = 0 }, "version": func(d *Duty) { d.Version = 2 }, "index": func(d *Duty) { d.Participant = 7 }, "recipient": func(d *Duty) { d.Recipient = [20]byte{} }, "view": func(d *Duty) { d.View = 0 }} {
		t.Run(name, func(t *testing.T) {
			d := duty
			mutate(&d)
			if _, err := d.Encode(); err == nil {
				t.Fatal("invalid duty accepted")
			}
		})
	}
	if _, err := DecodeDuty(append(dutyRaw, 0)); err == nil {
		t.Fatal("duty trailing")
	}
	receiptRaw, _ := hex.DecodeString(v["receipt"])
	receiptRaw[DutySize] = 7
	if _, err := DecodeReceipt(receiptRaw); err == nil {
		t.Fatal("collector overflow")
	}
	if strings.Contains(string(data), "private_key") {
		t.Fatal("golden secret fixture")
	}
}

func TestRestoredFHSWatermarkRequiresMatchingCollectorWAL(t *testing.T) {
	f := newRewardFixture(t)
	c := f.collector(t, 0, filepath.Join(t.TempDir(), "collector"))
	if err := c.CheckFHSWatermark(nil); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckFHSWatermark(persisted(f.refs[1])); err == nil {
		t.Fatal("fresh collector attached to old signer")
	}
	if err := c.BeforeVote(persisted(f.refs[1])); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckFHSWatermark(nil); err != nil {
		t.Fatal("safe collector ahead", err)
	}
	if err := c.CheckFHSWatermark(persisted(f.refs[1])); err != nil {
		t.Fatal(err)
	}
	if err := c.BeforeVote(persisted(f.refs[2])); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckFHSWatermark(persisted(f.refs[1])); err != nil {
		t.Fatal("collector ahead of FHS", err)
	}
	if err := c.CheckFHSWatermark(persisted(f.refs[3])); err == nil {
		t.Fatal("FHS ahead of collector")
	}
	v := persisted(f.refs[2])
	v.ProposalID[0]++
	if err := c.CheckFHSWatermark(v); err == nil {
		t.Fatal("invalid restored identity")
	}
}

func FuzzParticipationCodecs(f *testing.F) {
	data, err := os.ReadFile("../testdata/participation.json")
	if err != nil {
		f.Fatal(err)
	}
	var v map[string]string
	if err := json.Unmarshal(data, &v); err != nil {
		f.Fatal(err)
	}
	for _, key := range []string{"duty", "receipt", "certificate", "close_package"} {
		b, err := hex.DecodeString(v[key])
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add(make([]byte, MaxClosePackageBytes+1))
	f.Fuzz(func(t *testing.T, b []byte) {
		if d, err := DecodeDuty(b); err == nil {
			encoded, e := d.Encode()
			if e != nil || !bytes.Equal(encoded, b) {
				t.Fatal("duty noncanonical")
			}
		}
		if r, err := DecodeReceipt(b); err == nil {
			encoded, e := r.Encode()
			if e != nil || !bytes.Equal(encoded, b) {
				t.Fatal("receipt noncanonical")
			}
		}
		if c, err := DecodeCertificate(b); err == nil {
			encoded, e := c.Encode()
			if e != nil || !bytes.Equal(encoded, b) {
				t.Fatal("certificate noncanonical")
			}
		}
		if p, err := DecodeClosePackage(b); err == nil {
			encoded, e := p.Encode()
			if e != nil || !bytes.Equal(encoded, b) {
				t.Fatal("package noncanonical")
			}
		}
	})
}

func TestCollectorRegistryImmutableEvenBeforeAnyReceipt(t *testing.T) {
	f := newRewardFixture(t)
	dir := filepath.Join(t.TempDir(), "collector")
	c := f.collector(t, 0, dir)
	before, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal("registry not durable at open", err)
	}
	c.Shutdown()
	recipients := append([][20]byte(nil), f.registry.recipients[:]...)
	recipients[6][0]++
	changed, err := NewRegistry(f.cp.Domain(), f.members, recipients)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Commitment() == f.registry.Commitment() {
		t.Fatal("unbound recipient change")
	}
	if unexpected, err := OpenCollector(dir, changed, 0, &f.keys[0]); err == nil {
		unexpected.Shutdown()
		t.Fatal("changed unused reward registry attached")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("rejected registration mutated WAL")
	}
	members := make([]*common.Cnode, 7)
	for i, m := range f.members {
		clone := *m
		members[i] = &clone
	}
	members[3].Address = "different-endpoint"
	changed, err = NewRegistry(f.cp.Domain(), members, f.registry.recipients[:])
	if err == nil {
		if changed.Commitment() == f.registry.Commitment() {
			t.Fatal("unbound endpoint change")
		}
		if unexpected, err := OpenCollector(dir, changed, 0, &f.keys[0]); err == nil {
			unexpected.Shutdown()
			t.Fatal("changed endpoint registry attached")
		}
	}
	restored := f.collector(t, 0, dir)
	if err := restored.CheckFHSWatermark(nil); err != nil {
		t.Fatal(err)
	}
}
