package clxevidence_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/relay"
)

func TestRelayInboxRenewalReadyACKThenColdCompletion(t *testing.T) {
	f := clxevidence.RollingPermutationFixtureForTest(t, 5, []uint64{3})
	s := renewalHTTP(t, f)
	s.mu.Lock()
	s.head = 5
	s.mu.Unlock()
	for _, tc := range []struct {
		name      string
		base, end uint64
	}{
		{"cross-renewal-entries", 0, 3},
		{"cross-renewal-empty", 0, 0},
		{"pending-base-entries", 3, 3},
		{"pending-base-empty", 3, 0},
		{"same-anchor-entries", 5, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ranges []plannerRange
			if tc.base != 0 {
				ranges = append(ranges, plannerRange{tc.base, 0, 0, false})
			}
			bundles := plannerBundles(t, s.f, ranges)
			n, cfg, nc := plannerNetwork(t, s, &bundles)
			job := plannerInboxJob(t, n, cfg, s.f, tc.base, 5, 0, tc.end)
			if err := n.Close(); err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var received [][]byte
			dex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				switch r.URL.Path {
				case "/v1/status":
					json.NewEncoder(w).Encode(map[string]interface{}{"Finalized": len(bundles)})
				case "/v1/settlement":
					h, err := strconv.Atoi(r.URL.Query().Get("height"))
					if err != nil || h < 1 || h > len(bundles) {
						http.Error(w, "unavailable", 404)
						return
					}
					json.NewEncoder(w).Encode(map[string]interface{}{"Bytes": bundles[h-1]})
				case "/v1/actions":
					raw, err := io.ReadAll(io.LimitReader(r.Body, protocol.MaxNativeCallBytes+1))
					if err != nil || len(raw) > protocol.MaxNativeCallBytes {
						http.Error(w, "invalid", 400)
						return
					}
					received = append(received, raw)
					id := protocol.Digest("common-dex/ingress-action/v1", raw)
					json.NewEncoder(w).Encode(map[string]string{"ID": hex.EncodeToString(id[:])})
				default:
					http.Error(w, "unexpected", 400)
				}
			}))
			defer dex.Close()
			nc.DEXURL = dex.URL
			n, err := relay.OpenNetwork(nc)
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(t.TempDir(), "relay")
			r, err := relay.Open(dir, cfg, n, plannerNoSigner{})
			if err != nil {
				t.Fatal(err)
			}
			if err = r.Enqueue(job); err != nil {
				t.Fatal(err)
			}
			if err = r.Step(context.Background()); err != nil || r.Status()[0].Phase != "submitted" || r.Status()[0].Attempt.Sends != 1 {
				t.Fatal("valid renewal was not ready or ACK became completion", err, r.Status()[0].Phase)
			}
			mu.Lock()
			got := len(received) == 1 && bytes.Equal(received[0], job.Payload)
			mu.Unlock()
			if !got {
				t.Fatal("submitted job bytes changed")
			}
			if err = r.Close(); err != nil {
				t.Fatal(err)
			}
			if err = n.Close(); err != nil {
				t.Fatal(err)
			}
			// The fixture publishes a registered DEX quorum proof only now. The
			// earlier HTTP ACK contained no finality and caused no credit assertion.
			ranges = append(ranges, plannerRange{5, 0, tc.end, false})
			complete := plannerBundles(t, s.f, ranges)
			mu.Lock()
			bundles = complete
			mu.Unlock()
			n, err = relay.OpenNetwork(nc)
			if err != nil {
				t.Fatal(err)
			}
			defer n.Close()
			r, err = relay.Open(dir, cfg, n, plannerNoSigner{})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if err = r.Step(context.Background()); err != nil || r.Status()[0].Phase != "complete" || r.Status()[0].Attempt.Sends != 1 {
				t.Fatal("authenticated cold completion", err, r.Status()[0].Phase)
			}
			mu.Lock()
			count := len(received)
			mu.Unlock()
			if count != 1 {
				t.Fatal("cold completion unnecessarily resubmitted job")
			}
		})
	}
}

func TestRelayInboxRenewalTargetContext(t *testing.T) {
	f := clxevidence.RollingPermutationFixtureForTest(t, 5, []uint64{3})
	s := renewalHTTP(t, f)
	s.mu.Lock()
	s.head = 5
	s.mu.Unlock()
	for _, tc := range []struct {
		name              string
		base, target, end uint64
	}{
		{"cross-renewal-entries", 0, 5, 3},
		{"cross-renewal-empty", 0, 5, 0},
		{"pending-target-entries", 0, 3, 3},
		{"pending-target-empty", 0, 3, 0},
		{"same-anchor-entries", 5, 5, 3},
		{"same-anchor-empty", 5, 5, 0},
		{"pending-same-anchor-entries", 3, 3, 3},
		{"pending-same-anchor-empty", 3, 3, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundles := plannerBundles(t, s.f, []plannerRange{{tc.target, 0, tc.end, false}})
			n, cfg, networkConfig := plannerNetwork(t, s, &bundles)
			job := plannerInboxJob(t, n, cfg, s.f, tc.base, tc.target, 0, tc.end)
			target, err := clxevidence.DecodeAnchor(job.Authorization)
			if err != nil {
				t.Fatal(err)
			}
			e, err := clxevidence.DecodeRollingEvidence(job.Payload[4:])
			if err != nil {
				t.Fatal(err)
			}
			at, targetContext, err := n.Source.AnchorContextAt(context.Background(), target.Height, target.BlockHash)
			if err != nil || at != target || at.Version != 2 {
				t.Fatal("target authentication", err)
			}
			if tc.base == 0 && bytes.Equal(e.KeyHeader, targetContext.KeyHeader) {
				t.Fatal("cross-renewal fixture did not distinguish input/target context")
			}
			id, _ := target.ID()
			same := clxevidence.RollingEvidence{Base: id, AccountProof: e.AccountProof, CountProof: e.CountProof, Entries: e.Entries}
			same.SetKeyContext(targetContext)
			verified, derived, err := f.Verifier.VerifyRolling(target, 0, same)
			if err != nil || derived != target || len(verified.Entries()) != int(tc.end) {
				t.Fatal("same-target original paths", err)
			}
			for _, mutation := range []string{"absent", "wrong-current-header", "wrong-current-order", "wrong-previous-header", "wrong-previous-order", "wrong-boundary"} {
				if target.ActivationEnd == 0 && (mutation == "wrong-previous-header" || mutation == "wrong-previous-order") {
					continue
				}
				t.Run(mutation, func(t *testing.T) {
					k := targetContext.Clone()
					switch mutation {
					case "absent":
						k = clxevidence.KeyContext{}
					case "wrong-current-header":
						k.KeyHeader[len(k.KeyHeader)-1] ^= 1
					case "wrong-current-order":
						k.Order[0], k.Order[1] = k.Order[1], k.Order[0]
					case "wrong-previous-header":
						k.PreviousKeyHeader[len(k.PreviousKeyHeader)-1] ^= 1
					case "wrong-previous-order":
						k.PreviousOrder[0], k.PreviousOrder[1] = k.PreviousOrder[1], k.PreviousOrder[0]
					case "wrong-boundary":
						if len(k.Boundary) == 0 {
							k.Boundary = []protocol.Hash{{1}}
						} else {
							k.Boundary[0][0] ^= 1
						}
					}
					bad := same
					bad.SetKeyContext(k)
					if _, _, err := f.Verifier.VerifyRolling(target, 0, bad); err == nil {
						t.Fatal("unauthenticated target context accepted")
					}
				})
			}
			// Returned context bytes must not alias the retained authenticated source.
			targetContext.KeyHeader[0] ^= 1
			_, owned, err := n.Source.AnchorContextAt(context.Background(), target.Height, target.BlockHash)
			if err != nil || bytes.Equal(owned.KeyHeader, targetContext.KeyHeader) {
				t.Fatal("context ownership", err)
			}
			dir := filepath.Join(t.TempDir(), "relay")
			r, err := relay.Open(dir, cfg, n, plannerNoSigner{})
			if err != nil {
				t.Fatal(err)
			}
			if err = r.Enqueue(job); err != nil {
				t.Fatal(err)
			}
			// Cold restore both the source proof journal and the queued relay job.
			for restart := 0; restart < 2; restart++ {
				if err = r.Close(); err != nil {
					t.Fatal(err)
				}
				if err = n.Close(); err != nil {
					t.Fatal(err)
				}
				n, err = relay.OpenNetwork(networkConfig)
				if err != nil {
					t.Fatal("source cold recovery", err)
				}
				r, err = relay.Open(dir, cfg, n, plannerNoSigner{})
				if err != nil {
					t.Fatal("relay cold recovery", err)
				}
				if restart == 1 && r.Status()[0].Phase != "revalidation_wait" {
					t.Fatal("cached completion trusted after cold restart")
				}
				if err = r.Step(context.Background()); err != nil || r.Status()[0].Phase != "complete" {
					t.Fatal("post-renewal observation", err, r.Status()[0].Phase)
				}
				if !bytes.Equal(r.Status()[0].Job.Payload, job.Payload) || r.Status()[0].Attempt.Sends != 0 {
					t.Fatal("observation replaced submitted proofs or resent completed effect")
				}
			}
			r.Close()
			n.Close()
		})
	}
}

func TestRelayInboxRenewalDoesNotReplaceInvalidJobProofs(t *testing.T) {
	f := clxevidence.RollingPermutationFixtureForTest(t, 5, []uint64{3})
	s := renewalHTTP(t, f)
	s.mu.Lock()
	s.head = 5
	s.mu.Unlock()
	for _, mutation := range []string{"account", "count", "entry", "target-current-key", "target-inbox-count", "target-epoch", "target-activation"} {
		t.Run(mutation, func(t *testing.T) {
			bundles := plannerBundles(t, s.f, []plannerRange{{5, 0, 3, false}})
			n, cfg, _ := plannerNetwork(t, s, &bundles)
			job := plannerInboxJob(t, n, cfg, s.f, 0, 5, 0, 3)
			e, err := clxevidence.DecodeRollingEvidence(job.Payload[4:])
			if err != nil {
				t.Fatal(err)
			}
			target, err := clxevidence.DecodeAnchor(job.Authorization)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "account":
				e.AccountProof[0][len(e.AccountProof[0])-1] ^= 1
			case "count":
				e.CountProof[0][len(e.CountProof[0])-1] ^= 1
			case "entry":
				e.Entries[0].Proof[0][len(e.Entries[0].Proof[0])-1] ^= 1
			case "target-current-key":
				target.SourceKeyHash[0] ^= 1
			case "target-inbox-count":
				target.InboxCount++
			case "target-epoch":
				// Encode rejects unsupported epochs; mutate the canonical field to
				// exercise the receiving decoder rather than an authorized encoder.
				job.Authorization[237]++
			case "target-activation":
				target.ActivationEnd = target.Height + 1
				target.ActivationRoot = protocol.Hash{9}
			}
			encoded, err := clxevidence.EncodeRollingEvidence(e)
			if err != nil {
				t.Fatal(err)
			}
			job.Payload = append([]byte("CDXA"), encoded...)
			if mutation != "target-epoch" {
				job.Authorization, err = target.Encode()
				if err != nil {
					t.Fatal(err)
				}
			}
			r, err := relay.Open(filepath.Join(t.TempDir(), "relay"), cfg, n, plannerNoSigner{})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if err = r.Enqueue(job); err != nil {
				t.Fatal(err)
			}
			if err = r.Step(context.Background()); !errors.Is(err, relay.ErrInvalidJob) || r.Status()[0].Phase != "quarantined" || r.Status()[0].Attempt.Sends != 0 {
				t.Fatal("invalid original proof/target repaired by observation", err, r.Status()[0].Phase)
			}
		})
	}
}
