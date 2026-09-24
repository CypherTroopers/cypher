package consensus

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// Construct two independently executable proposals for a pending view, with
// complete internally consistent metadata. Neither has a QC. Raising this
// test's workload ceiling lets it retain height7 after its six-height network
// has quiesced; domain, threshold and safety rules remain unchanged.
func compactPendingRecords(t *testing.T, n *network, index int) (*Record, *Record) {
	t.Helper()
	a := n.nodes[index]
	if a.CurrentN() != 7 || a.CertifiedHeight() != 6 || a.FinalizedHeight() != 5 {
		t.Fatal("expected a pending view7 after six certified records")
	}
	a.config.MaxHeight = 8
	n.configs[index].MaxHeight = 8
	parent := a.HighestCertified()
	id, err := hotstuff.SignedStateID(parent)
	if err != nil {
		t.Fatal(err)
	}
	context := hotstuff.FHSViewContext{Version: 3, ChainID: a.ChainID(), TargetView: 7,
		KeyNumber: a.config.Domain.Epoch, KeyHash: common.Hash(a.config.Domain.EpochKey()),
		CommitteeHash: common.Hash(a.config.Domain.Committee), LeaderID: a.committee.List[6].Address,
		EntryKind: hotstuff.FHSViewFromQC}
	if err := context.Validate(); err != nil {
		t.Fatal(err)
	}
	request := &hotstuff.FHSProposalBuildRequest{Key: hotstuff.FHSProposalBuildKey{
		ViewNumber: 7, ViewID: context.ID(), LeaderID: context.LeaderID, ParentQCID: id.Hash()}, ParentQC: parent}
	records := make([]*Record, 2)
	for i, action := range []byte{7, 8} {
		record, err := a.buildAction(request, []byte{action})
		if err != nil {
			t.Fatal(err)
		}
		extra, err := encodeExtra(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.OnPropose(record.Ref, extra, 7, parent); err != nil {
			t.Fatal("valid alternate pending record was not executed/stored", err)
		}
		records[i] = record
	}
	if bytes.Equal(records[0].Ref, records[1].Ref) || records[0].QC != nil || records[1].QC != nil || a.CurrentN() != 7 {
		t.Fatal("pending alternatives must have distinct refs and no certification")
	}
	return records[0], records[1]
}

func reopenCompactSafetyNode(t *testing.T, n *network, index int) *Application {
	t.Helper()
	if err := n.nodes[index].Close(); err != nil {
		t.Fatal(err)
	}
	a, err := Open(n.configs[index])
	if err != nil {
		t.Fatal(err)
	}
	n.nodes[index] = a
	return a
}

func TestCompactSafetyPendingSameViewVoteSurvivesRestart(t *testing.T) {
	n := compactNetwork(t)
	n.start(t)
	a := n.nodes[0]
	first, second := compactPendingRecords(t, n, 0)
	firstVote, err := decodeRecordVote(first)
	if err != nil {
		t.Fatal(err)
	}
	secondVote, err := decodeRecordVote(second)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.PersistFHSVote(firstVote); err != nil {
		t.Fatal(err)
	}
	expected := hotstuff.CloneFHSSafetyState(a.disk.Safety)
	path := filepath.Join(n.configs[0].DataDir, "state.json")
	disk := readCompact(t, path)
	if disk.Version != 2 || disk.Safety.HighestQC.Number != 6 || disk.Safety.LastVote.ViewNumber != 7 || disk.Records[disk.Finalized[0].Key].State != nil {
		t.Fatal("fixture did not persist a pending vote in genuinely compact WAL")
	}
	for _, vote := range []*hotstuff.PersistedVote{firstVote, secondVote} {
		if r := disk.Records[vote.ProposalID.Hex()]; r == nil || r.State == nil || r.QC != nil {
			t.Fatal("pending branch state was omitted or certified")
		}
	}
	a = reopenCompactSafetyNode(t, n, 0)
	if a.CurrentN() != firstVote.ViewNumber || !reflect.DeepEqual(expected, a.disk.Safety) {
		t.Fatal("restart changed own safety or made this a stale-view test")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.PersistFHSVote(firstVote); err != nil {
		t.Fatal("identical pending vote must remain idempotent", err)
	}
	err = a.PersistFHSVote(secondVote)
	if err == nil || !strings.Contains(err.Error(), "conflicting durable DEX vote") {
		t.Fatalf("consistent alternate vote must reach durable same-view guard, got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || !reflect.DeepEqual(expected, a.disk.Safety) {
		t.Fatal("rejected alternate vote changed in-memory or durable safety", err)
	}
	a = reopenCompactSafetyNode(t, n, 0)
	if !reflect.DeepEqual(expected, a.disk.Safety) {
		t.Fatal("second restart lost the original pending vote")
	}
}

func TestCompactSafetyPendingTimeoutAndOutboxSurviveRestart(t *testing.T) {
	n := compactNetwork(t)
	n.start(t)
	// The registered leader for certified view6 has a real durable QC outbox.
	const index = 5
	a := n.nodes[index]
	first, _ := compactPendingRecords(t, n, index)
	vote, err := decodeRecordVote(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Timeout(); !benign(err) {
		t.Fatal(err)
	}
	expected := hotstuff.CloneFHSSafetyState(a.disk.Safety)
	outbox := hotstuff.CloneSignedState(a.disk.Outbox)
	if expected.LastTimeoutVote == nil || expected.LastTimeoutVote.TimedOutView != 7 || expected.HighestTC != nil || outbox == nil || outbox.Number != 6 || outbox.LeaderID != a.Self() {
		t.Fatal("fixture did not create a real pending timeout and leader outbox")
	}
	a = reopenCompactSafetyNode(t, n, index)
	if !reflect.DeepEqual(expected, a.disk.Safety) || !reflect.DeepEqual(outbox, a.disk.Outbox) || a.CurrentN() != 7 {
		t.Fatal("compact recovery lost timeout/outbox bytes or advanced unproven view")
	}
	pending, err := a.PendingFHSTimeoutVote()
	if err != nil || !reflect.DeepEqual(pending, expected.LastTimeoutVote) {
		t.Fatal("pending timeout was not restored through the application API", err)
	}
	err = a.PersistFHSVote(vote)
	if err == nil || !strings.Contains(err.Error(), "below safety watermark") {
		t.Fatalf("consistent vote in timed-out view must be rejected, got %v", err)
	}
	if err := a.PersistFHSTimeoutVote(pending); err != nil {
		t.Fatal("identical restored timeout must remain idempotent", err)
	}
	stale := *pending
	stale.TimedOutView--
	if err := a.PersistFHSTimeoutVote(&stale); err == nil {
		t.Fatal("restart accepted stale timeout")
	}
	if !reflect.DeepEqual(expected, a.disk.Safety) {
		t.Fatal("rejected vote/timeout changed safety")
	}
	// Start reconstructs the actual authenticated network envelope, preserving
	// the aggregate QC bytes; merely retaining an Outbox field is insufficient.
	broadcasts := 0
	a.SetTransport(func(_ string, message *hotstuff.HotstuffMessage) error {
		if message.Code == hotstuff.MsgQCBroadcast {
			broadcasts++
			if message.Number != outbox.Number || !bytes.Equal(message.DataB, outbox.Sign) || !bytes.Equal(message.DataC, outbox.Mask) || !bytes.Equal(message.DataD, outbox.State) || len(message.AuthSig) == 0 {
				t.Fatal("restart outbox broadcast changed QC or omitted authentication")
			}
		}
		return nil
	})
	if err := a.Start(); !benign(err) {
		t.Fatal(err)
	}
	if broadcasts != 7 || !reflect.DeepEqual(expected, a.disk.Safety) {
		t.Fatalf("expected exactly seven authenticated outbox sends without safety change, got %d", broadcasts)
	}
}

func TestCompactSafetyCertifiedTimeoutWatermarkSurvivesRestart(t *testing.T) {
	n := compactNetwork(t)
	n.start(t)
	const index = 5
	first, _ := compactPendingRecords(t, n, index)
	vote, err := decodeRecordVote(first)
	if err != nil {
		t.Fatal(err)
	}
	// Let the normal FHS managers sign and aggregate the timeout; never install
	// a hand-authored certificate or mutate a serialized safety watermark.
	for _, a := range n.nodes {
		if err := a.Timeout(); !benign(err) {
			t.Fatal(err)
		}
	}
	a := n.nodes[index]
	// Deliver the real signed votes to this replica until it durably creates
	// its certificate. Delay the remaining network traffic at this crash point
	// rather than driving old-view messages through a later view's scheduler.
	delivered := make(map[string]bool)
	for _, delivery := range append([]delivery(nil), n.queue...) {
		message := delivery.message
		if delivery.to != a.Self() || message.Code != hotstuff.MsgTimeout || delivered[string(message.PubKey)] {
			continue
		}
		if err := a.Handle(message); !benign(err) {
			t.Fatal("authenticated timeout delivery", err)
		}
		delivered[string(message.PubKey)] = true
		if a.disk.Safety.HighestTC != nil {
			break
		}
	}
	if len(delivered) != 5 {
		t.Fatalf("expected real five-of-seven timeout aggregation, got %d", len(delivered))
	}
	expected := hotstuff.CloneFHSSafetyState(a.disk.Safety)
	outbox := hotstuff.CloneSignedState(a.disk.Outbox)
	if expected.HighestTC == nil || expected.HighestTC.Statement.TimedOutView != 7 || expected.LastTimeoutView != 7 || expected.LastTimeoutVote != nil || a.CurrentN() != 8 || a.CertifiedHeight() != 6 {
		t.Fatal("fixture must stop after a real view7 timeout certificate")
	}
	if err := hotstuff.VerifyTimeoutCertificate(expected.HighestTC, a.keys, 5); err != nil {
		t.Fatal(err)
	}
	a = reopenCompactSafetyNode(t, n, index)
	if !reflect.DeepEqual(expected, a.disk.Safety) || !reflect.DeepEqual(outbox, a.disk.Outbox) || a.CurrentN() != 8 {
		t.Fatal("certified timeout/outbox or next-view watermark changed on restart")
	}
	if err := a.PersistFHSVote(vote); err == nil || !strings.Contains(err.Error(), "below safety watermark") {
		t.Fatalf("consistent pending view7 vote must remain expired after TC7, got %v", err)
	}
	if err := a.PersistFHSTimeoutVote(&expected.HighestTC.Statement); err == nil {
		t.Fatal("stale timeout vote accepted after certified timeout restart")
	}
	if !reflect.DeepEqual(expected, a.disk.Safety) {
		t.Fatal("expired requests changed restored TC watermark")
	}
}
