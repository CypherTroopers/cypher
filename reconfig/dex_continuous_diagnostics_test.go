package reconfig_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/devnet/testnet"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// Reads the public replay snapshot for diagnostics and scheduling only. A
// certified record is explicitly NOT treated as finality or native settlement.
func (f *continuousFixture) certifiedRecord(t *testing.T, height uint64) *consensus.Record {
	t.Helper()
	deadline := time.Now().Add(75 * time.Second)
	for attempt := 0; attempt < 5; attempt++ {
		status := continuousCLIStatus(t, f.children[0], deadline)
		if status.Finalized == 0 {
			return nil
		}
		response, err := f.children[0].cli.client.Get(fmt.Sprintf("http://%s/v1/snapshot?height=%d", f.children[0].cli.api, status.Finalized))
		if err != nil {
			t.Fatal(err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, 3*1024*1024+1))
		response.Body.Close()
		if readErr != nil || len(raw) > 3*1024*1024 {
			t.Fatal("snapshot diagnostic response bound", readErr)
		}
		if response.StatusCode != http.StatusOK {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		var envelope struct {
			Height uint64
			Bytes  []byte
		}
		if err = json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		var snapshot struct{ Records map[string]*consensus.Record }
		if err = json.Unmarshal(envelope.Bytes, &snapshot); err != nil {
			t.Fatal(err)
		}
		var best *consensus.Record
		var bestView uint64
		for _, r := range snapshot.Records {
			if r == nil || r.QC == nil || r.Checkpoint.Sequence != height {
				continue
			}
			ref, err := types.DecodeHotstuffProposalRef(r.Ref)
			if err != nil {
				t.Fatal(err)
			}
			if best == nil || ref.ViewNumber > bestView {
				best, bestView = r, ref.ViewNumber
			}
		}
		if best == nil {
			t.Fatal("public replay snapshot lacks certified record", height)
		}
		ref, err := types.DecodeHotstuffProposalRef(best.Ref)
		if err != nil {
			t.Fatal(err)
		}
		q := best.QC
		h, err := best.Checkpoint.Hash()
		if err != nil || ref.Number != height || ref.ViewNumber == 0 || best.Checkpoint.Domain() != f.init.Domain || ref.ChainID != f.init.Domain.ChainID || ref.KeyHash != common.Hash(f.init.Domain.EpochKey()) || ref.LeaderID != f.init.Members[(ref.ViewNumber-1)%7].Address || !bytes.Equal(q.State, best.Ref) || q.Number != ref.ViewNumber || q.LeaderID != ref.LeaderID || q.ViewID != ref.ViewID || ref.BlockHash != common.Hash(h) || ref.StateRoot != common.Hash(best.Checkpoint.PostRoot) || ref.BodyHash != common.Hash(best.Checkpoint.DataRoot) {
			t.Fatal("certified record/QC context mismatch", err)
		}
		keys := make([]*bls.PublicKey, len(f.init.Members))
		for i, m := range f.init.Members {
			keys[i] = new(bls.PublicKey)
			if err := keys[i].DeserializeHexStr(m.Public); err != nil {
				t.Fatal(err)
			}
		}
		if !hotstuff.VerifyFHSSignatureWithContext(q.Sign, q.Mask, q.State, keys, 5, f.init.Domain.ChainID, hotstuff.MsgVotePrepare, q.ViewID, q.LeaderID) {
			t.Fatal("certified record QC signature")
		}
		// Compact v2 snapshots omit only older finalized state copies. The
		// existing finalized checkpoint endpoint returns their reconstructed state;
		// verify its full finality and CP identity before using this optional copy.
		if len(best.State) == 0 {
			var finalized testnet.Response
			if err := f.children[0].cli.http("GET", fmt.Sprintf("/v1/checkpoint?height=%d", height), nil, &finalized); err != nil {
				t.Fatal(err)
			}
			epoch, err := checkpoint.NewEpoch(f.init.Domain, 1, ^uint64(0), f.init.Members)
			if err != nil || finalized.Checkpoint == nil || *finalized.Checkpoint != best.Checkpoint {
				t.Fatal("compact snapshot checkpoint identity", err)
			}
			if _, err = epoch.Verify(*finalized.Checkpoint, finalized.Proof); err != nil {
				t.Fatal("compact snapshot state finality", err)
			}
			best.State = bytes.Clone(finalized.State)
		}
		var financial devnet.FinancialState
		if err := json.Unmarshal(best.State, &financial); err != nil {
			t.Fatal(err)
		}
		stateRoot, err := financial.Root()
		if err != nil || stateRoot != best.Checkpoint.PostRoot {
			t.Fatal("certified financial state commitment", err)
		}
		root, err := consensus.ComputeExecutionDataRoot(best.Actions)
		if err != nil || root != best.Checkpoint.DataRoot {
			t.Fatal("certified action data commitment mismatch", err)
		}
		t.Logf("CONTINUOUS_CERTIFIED_RECORD height=%d view=%d finalizedTip=%d anchor=%d inbox=%d..%d actionBytes=%d dataRoot=%x isCDXA=%v NOT_FINALITY=true", height, bestView, envelope.Height, best.Checkpoint.CLXHeight, best.Checkpoint.InboxStart, best.Checkpoint.InboxEnd, len(best.Actions), root, bytes.HasPrefix(best.Actions, []byte("CDXA")))
		return best
	}
	t.Fatal("snapshot tip changed throughout bounded retry")
	return nil
}

// Only public signed journals/configuration are preserved after a failed test.
// Private key files, normal chaindata and keystores are deliberately excluded.
func (f *continuousFixture) preserveFailure(t *testing.T) {
	t.Helper()
	if !t.Failed() {
		return
	}
	dir, err := os.MkdirTemp("", "continuous-public-failure-")
	if err != nil {
		t.Log("public failure archive unavailable", err)
		return
	}
	patterns := []string{"common-*/dex.json", "common-*/dex/fhs/state.json", "common-*/dex/participation/state.json", "common-*/dex/mempool/pool.json", "relay-config-*/relay.json", "relay-*/status.json", "relay-*/core/state.bin", "relay-*/source/source-wal.json"}
	for _, pattern := range patterns {
		paths, _ := filepath.Glob(filepath.Join(f.root, pattern))
		for _, path := range paths {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Log(err)
				continue
			}
			relative, _ := filepath.Rel(f.root, path)
			target := filepath.Join(dir, relative)
			if err = os.MkdirAll(filepath.Dir(target), 0700); err == nil {
				err = os.WriteFile(target, raw, 0600)
			}
			if err != nil {
				t.Log(err)
			}
		}
	}
	t.Logf("CONTINUOUS_PUBLIC_FAILURE_ARCHIVE path=%s privateKeysExcluded=true noOperationalData=true", dir)
}
