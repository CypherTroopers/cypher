package settlement

import (
	"bytes"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
)

// This is a bounded component measurement, not a CLX throughput benchmark or
// a proof that every possible max-descendant/committee layout costs the same.
func TestNativeRollingFullCalldataCostAndLateProofFailure(t *testing.T) {
	r := newRollingNativeFixture(t)
	base, _ := r.verifier.BootstrapAnchor()
	var maximal clxevidence.RollingEvidence
	var raw []byte
	for end := uint64(1); end <= clxevidence.MaxAncestryBlocks; end++ {
		e := r.evidence(t, base, end)
		encoded, err := EncodeNativeAnchorUpdate(e, nil)
		if err != nil {
			break
		}
		maximal, raw = e, encoded
	}
	if len(raw) == 0 {
		t.Fatal("no bounded update")
	}
	// Unused proof nodes are allowed by the current MPT codec. Exercise the full
	// actual calldata cap with such nodes, while retaining every required path.
	for len(maximal.CountProof) < clxevidence.MaxProofNodes && len(raw) < protocol.MaxNativeCallBytes {
		lo, hi := 1, clxevidence.MaxProofNodeBytes
		best := 0
		var bestRaw []byte
		for lo <= hi {
			size := (lo + hi) / 2
			candidate := maximal
			candidate.CountProof = append(append([][]byte(nil), maximal.CountProof...), bytes.Repeat([]byte{0x55}, size))
			encoded, err := EncodeNativeAnchorUpdate(candidate, nil)
			if err == nil {
				best, bestRaw = size, encoded
				lo = size + 1
			} else {
				hi = size - 1
			}
		}
		if best == 0 {
			break
		}
		maximal.CountProof = append(maximal.CountProof, bytes.Repeat([]byte{0x55}, best))
		raw = bestRaw
	}
	if len(raw) != protocol.MaxNativeCallBytes {
		t.Fatalf("full-cap fixture size=%d", len(raw))
	}
	r.ctx.BlockNumber = uint64(len(maximal.Headers)) + 1
	nodes, proofBytes := len(maximal.AccountProof)+len(maximal.CountProof), 0
	for _, list := range [][][]byte{maximal.AccountProof, maximal.CountProof} {
		for _, b := range list {
			proofBytes += len(b)
		}
	}
	bad := maximal
	bad.CountProof = append([][]byte(nil), maximal.CountProof...)
	bad.CountProof[0] = bytes.Clone(bad.CountProof[0])
	bad.CountProof[0][len(bad.CountProof[0])-1] ^= 1
	malformed, err := EncodeNativeAnchorUpdate(bad, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		data  []byte
		valid bool
	}{{"full-calldata", raw, true}, {"late-count-MPT-failure", malformed, false}} {
		t.Run(tc.name, func(t *testing.T) {
			for repeat := 0; repeat < 3; repeat++ {
				state := &countingNativeState{StateDB: r.state.Copy()}
				root := state.IntermediateRoot(false)
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				start := time.Now()
				_, err := RunNative(state, r.config, r.ctx, tc.data)
				duration := time.Since(start)
				runtime.ReadMemStats(&after)
				if (err == nil) != tc.valid {
					t.Fatalf("valid=%v err=%v", tc.valid, err)
				}
				if state.writes > 16 {
					t.Fatal("write budget")
				}
				if !tc.valid && (state.writes != 0 || state.IntermediateRoot(false) != root) {
					t.Fatal("late failure changed state")
				}
				if tc.valid && state.writes != 12 {
					t.Fatal("missing accepted record")
				}
				rss := []string{}
				if proc, e := os.ReadFile("/proc/self/status"); e == nil {
					for _, line := range strings.Split(string(proc), "\n") {
						if strings.HasPrefix(line, "VmRSS:") || strings.HasPrefix(line, "VmHWM:") {
							rss = append(rss, strings.TrimSpace(line))
						}
					}
				}
				t.Logf("BOUNDED_NATIVE_COST repeat=%d accepted=%v calldata=%d headers=%d fixtureQCRecords=%d mptNodes=%d mptBytes=%d nativeExecutionGas=%d writes=%d wallNs=%d goAllocatedBytes=%d processMemory=%q CHeap=NOT_SEPARATELY_MEASURED", repeat, tc.valid, len(tc.data), len(maximal.Headers), 2*len(maximal.Headers), nodes, proofBytes, RequiredNativeGas(tc.data), state.writes, duration.Nanoseconds(), after.TotalAlloc-before.TotalAlloc, rss)
			}
		})
	}
}
