package clxevidence_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/relay"
	"github.com/cypherium/cypher/dex/relay/source"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

type planningCertificateFixture struct {
	Checkpoint protocol.Checkpoint
	QC         *hotstuff.SignedState
	Ref        []byte
}

func planningCertificates(t *testing.T, f *clxevidence.RollingFinancialFixture, ranges []plannerRange) ([]planningCertificateFixture, [][]byte) {
	t.Helper()
	legacy := plannerBundles(t, f, ranges)
	records := make([]planningCertificateFixture, len(legacy))
	decoded := make([]checkpoint.SettlementBundle, len(legacy))
	for i, raw := range legacy {
		var err error
		decoded[i], err = checkpoint.DecodeSettlementBundle(raw)
		if err != nil {
			t.Fatal(err)
		}
		p, err := checkpoint.DecodeProof(decoded[i].Proof)
		if err != nil {
			t.Fatal(err)
		}
		cp, err := protocol.DecodeCheckpoint(decoded[i].Checkpoint)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := types.DecodeHotstuffProposalRef(p.Target.State)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			id := "BTC-CLX-native-finance-v5"
			key := plannerDomain(f).EpochKey()
			buf := append([]byte(nil), key[:]...)
			var length [2]byte
			binary.BigEndian.PutUint16(length[:], uint16(len(id)))
			buf = append(buf, length[:]...)
			buf = append(buf, id...)
			buf = append(buf, cp.PreRoot[:]...)
			ref.ParentHash = common.Hash(protocol.Digest("common-dex/execution-genesis/v1", buf))
		} else {
			id, err := hotstuff.SignedStateID(records[i-1].QC)
			if err != nil {
				t.Fatal(err)
			}
			hash, _ := records[i-1].Checkpoint.Hash()
			ref.ParentHash, ref.ParentQCID = common.Hash(hash), id.Hash()
		}
		records[i] = planningCertificateFixture{cp, plannerQC(t, ref), ref.EncodeToBytes()}
	}
	var finalized [][]byte
	for i := 0; i+1 < len(records); i++ {
		proof, err := checkpoint.EncodeProof(checkpoint.Proof{Target: records[i].QC, Descendants: []*hotstuff.SignedState{records[i+1].QC}})
		if err != nil {
			t.Fatal(err)
		}
		decoded[i].Proof = proof
		raw, err := checkpoint.EncodeSettlementBundle(decoded[i])
		if err != nil {
			t.Fatal(err)
		}
		finalized = append(finalized, raw)
	}
	return records, finalized
}

func TestRelayCertifiedParentPipelinesInboxWithoutClaimingFinality(t *testing.T) {
	requireSourceNetwork(t)
	f := clxevidence.RollingPlannerFixtureForTest(t, 100, func(_ uint64, db *state.StateDB, f *clxevidence.RollingFinancialFixture) {
		db.SetNonce(f.Config.Custody, 1)
	})
	sourceHTTP := &sourceFixtureHTTP{f: f, head: 100}
	sourceHTTP.server = httptest.NewServer(http.HandlerFunc(sourceHTTP.serve))
	defer sourceHTTP.server.Close()
	certificates, bundles := planningCertificates(t, sourceHTTP.f, []plannerRange{{16, 0, 0, false}, {48, 0, 3, false}, {48, 3, 3, false}})
	certified, finalized := 1, 0
	var actions [][]byte
	var mu sync.Mutex
	certificateReads := 0
	var requested []int
	cancelHeight := 0
	var cancelRequest context.CancelFunc
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch req.URL.Path {
		case "/v1/status":
			json.NewEncoder(w).Encode(map[string]interface{}{"Certified": certified, "Finalized": finalized})
		case "/v1/certified":
			if req.URL.Query().Get("selected") != "true" {
				http.Error(w, "must request one selected QC ancestry", http.StatusBadRequest)
				return
			}
			certificateReads++
			h, _ := strconv.Atoi(req.URL.Query().Get("height"))
			requested = append(requested, h)
			if h == cancelHeight && cancelRequest != nil {
				cancelRequest()
				http.Error(w, "injected request cancellation", 503)
				return
			}
			if h < 1 || h > certified {
				http.Error(w, "unavailable", 404)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"Record": certificates[h-1]})
		case "/v1/settlement":
			h, _ := strconv.Atoi(req.URL.Query().Get("height"))
			if h < 1 || h > finalized {
				http.Error(w, "unavailable", 404)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"Bytes": bundles[h-1]})
		case "/v1/actions":
			raw, err := io.ReadAll(io.LimitReader(req.Body, protocol.MaxNativeCallBytes+1))
			if err != nil || len(raw) > protocol.MaxNativeCallBytes {
				http.Error(w, "bound", 400)
				return
			}
			actions = append(actions, raw)
			id := protocol.Digest("common-dex/ingress-action/v1", raw)
			json.NewEncoder(w).Encode(map[string]interface{}{"ID": common.Bytes2Hex(id[:])})
		default:
			http.Error(w, "unsupported", 400)
		}
	}))
	defer server.Close()
	var none [][]byte
	old, cfg, networkConfig := plannerNetwork(t, sourceHTTP, &none)
	old.Close()
	networkConfig.DEXURL, networkConfig.SubmitURL, networkConfig.CertifiedInboxPlanning = server.URL, server.URL, true
	n, err := relay.OpenNetwork(networkConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	dir := filepath.Join(t.TempDir(), "relay")
	r, err := relay.Open(dir, cfg, n, plannerNoSigner{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	first := plannerInboxJob(t, n, cfg, sourceHTTP.f, 0, 16, 0, 0)
	if err = r.Enqueue(first); err != nil {
		t.Fatal(err)
	}
	// Retain sixteen independently authenticated old source ranges. A single
	// ready successor must be submitted promptly even though none is finalized.
	const oldIntents = 16
	for height := uint64(1); height < oldIntents; height++ {
		if err := r.Enqueue(plannerInboxJob(t, n, cfg, sourceHTTP.f, 0, height, 0, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if err = n.Discover(context.Background(), r); err != nil && err.Error() != source.ErrUnavailable.Error() {
		t.Fatal("certified parent could not plan next source segment", err)
	}
	records := r.Status()
	if len(records) != oldIntents+1 || n.AuthenticatedStatus().DEXSequence != 0 {
		t.Fatal("certification became finality or did not pipeline", len(records), n.AuthenticatedStatus())
	}
	second := records[oldIntents].Job
	evidence, err := clxevidence.DecodeRollingEvidence(second.Payload[4:])
	if err != nil {
		t.Fatal(err)
	}
	base, err := n.Source.AnchorAt(context.Background(), 16, protocol.Hash(sourceHTTP.f.Blocks[15].Hash()))
	if err != nil {
		t.Fatal(err)
	}
	baseID, _ := base.ID()
	if evidence.Base != baseID || len(evidence.Entries) != 3 {
		t.Fatal("next segment did not use authenticated certified parent")
	}
	if err = r.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	prompt := len(actions) == 1 && bytes.Equal(actions[0], second.Payload)
	mu.Unlock()
	if !prompt {
		t.Fatal("authenticated frontier waited behind sixteen certified pending intents")
	}
	if err = r.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	validActions := len(actions) == 1 && bytes.Equal(actions[0], second.Payload)
	mu.Unlock()
	if !validActions || r.Status()[0].Phase == "complete" || r.Status()[oldIntents].Phase == "complete" {
		t.Fatal("old anchor replayed, or single QC completed business")
	}
	// Cold recovery reconstructs the planning chain from verified QCs. It does
	// not persist a certified cursor as a finalized accounting authority.
	r.Close()
	n.Close()
	n, err = relay.OpenNetwork(networkConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	r, err = relay.Open(dir, cfg, n, plannerNoSigner{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err = n.Discover(context.Background(), r); err != nil && err.Error() != source.ErrUnavailable.Error() || len(r.Status()) != oldIntents+1 || n.AuthenticatedStatus().DEXSequence != 0 {
		t.Fatal("cold certified planning changed finality", err)
	}
	mu.Lock()
	certificates[0].QC.Sign[0] ^= 1
	mu.Unlock()
	if err = n.Discover(context.Background(), r); err == nil || err.Error() == source.ErrUnavailable.Error() || len(r.Status()) != oldIntents+1 || n.AuthenticatedStatus().DEXSequence != 0 {
		t.Fatal("bad certified metadata changed planning state")
	}
	mu.Lock()
	certificates[0].QC.Sign[0] ^= 1
	certified, finalized = 3, 2
	mu.Unlock()
	if err = n.Discover(context.Background(), r); err != nil && err.Error() != source.ErrUnavailable.Error() {
		t.Fatal("real descendant proof did not recover", err)
	}
	for i := 0; i < 4*len(r.Status())+8; i++ {
		if err := r.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	for _, record := range r.Status() {
		if (record.Job.ID == first.ID || record.Job.ID == second.ID) && record.Phase != "complete" {
			t.Fatal("finalized descendant did not complete prior inbox", record.Phase)
		}
	}
	t.Log("certified-only source16 -> nextboundedsource48 planned/sent; no finalizedcredit/payment claim; badQC rejected; cold reconstruction; finality proofs completed oldintents")

	// An RPC height cannot force an unbounded catch-up. Seventeen real QCs
	// require bounded discovery ticks, and intermediate prefixes are not
	// used to submit an action against the wrong current certified parent.
	r.Close()
	n.Close()
	ranges := make([]plannerRange, 17)
	for i := range ranges {
		ranges[i] = plannerRange{16, 0, 0, false}
	}
	longRecords, longBundles := planningCertificates(t, sourceHTTP.f, ranges)
	mu.Lock()
	certificates, bundles = longRecords, longBundles
	certified, finalized = 17, 0
	mu.Unlock()
	networkConfig.Source.Dir = filepath.Join(t.TempDir(), "source")
	n, err = relay.OpenNetwork(networkConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	for n.Source.Current().Height < 100 {
		if _, err := n.Source.Advance(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	r, err = relay.Open(filepath.Join(t.TempDir(), "relay"), cfg, n, plannerNoSigner{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for tick := 0; tick < 4; tick++ {
		ctx, cancel := context.WithCancel(context.Background())
		mu.Lock()
		certificateReads = 0
		requested = nil
		cancelHeight, cancelRequest = 0, nil
		if tick == 1 {
			cancelHeight, cancelRequest = 10, cancel
		}
		mu.Unlock()
		err = n.Discover(ctx, r)
		cancel()
		mu.Lock()
		reads := certificateReads
		firstRead := 0
		if len(requested) > 0 {
			firstRead = requested[0]
		}
		mu.Unlock()
		if reads > 8 || reads == 0 || n.AuthenticatedStatus().DEXSequence != 0 {
			t.Fatal("certified catch-up bound or finality distinction lost", reads)
		}
		if tick == 1 {
			if err == nil || !errors.Is(err, context.Canceled) || len(r.Status()) != 0 {
				t.Fatal("cancellation did not stop incomplete planning", err)
			}
		} else if tick < 3 {
			if err == nil || !strings.Contains(err.Error(), "bounded catch-up pending") || len(r.Status()) != 0 {
				t.Fatal("intermediate certified prefix used for submission", tick, err)
			}
		} else if len(r.Status()) != 1 {
			t.Fatal("bounded certified cache did not progress across ticks", err)
		}
		if tick == 2 && firstRead != 9 {
			t.Fatal("request cancellation discarded fully verified prefix", firstRead)
		}
	}
	mu.Lock()
	certified = 129
	certificateReads = 0
	mu.Unlock()
	if err := n.Discover(context.Background(), r); err == nil || !strings.Contains(err.Error(), "discovery bound") {
		t.Fatal("oversized claimed certified height accepted", err)
	}
	mu.Lock()
	reads := certificateReads
	mu.Unlock()
	if reads != 0 || len(r.Status()) != 1 {
		t.Fatal("height bound was not enforced before data/cryptography")
	}
	t.Log("certified catchup17 QCs:<=8reads/tick; cancellation afterverified9 retainedprefix; no intermediate submissions; hostile height rejected before reads")
}
