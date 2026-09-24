package rewards

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/dex/protocol"
)

func retirementBlock(t *testing.T, f *rewardFixture, period uint64) FinalizedBlock {
	t.Helper()
	cp := f.cp
	cp.Sequence, cp.FirstBlock, cp.LastBlock = period*10+5, period*10+5, period*10+5
	cp.RewardPeriod = period
	cp.PostRoot = protocol.Digest("retirement-unit", []byte{byte(period)})
	b, _ := f.proof(t, cp, period*10+5)
	return b
}

func TestCollectorFinalizedRetirementRetainsEvidenceAndVoteSafety(t *testing.T) {
	f := newRewardFixture(t)
	cs := f.five(t)
	cert := f.certificate(t, cs, 1, 6)
	c := cs[0]
	if err := c.RememberCertificate(cert); err != nil {
		t.Fatal(err)
	}
	// This locally known certificate has not been used by local Close. It must
	// survive as archival evidence even if the committed close omitted it.
	vote := persisted(f.refs[14])
	if err := c.BeforeVote(vote); err != nil {
		t.Fatal(err)
	}
	closedThrough := c.ClosedThrough()
	one := retirementBlock(t, f, 1)
	if err := c.RetireFinalized(one); err != nil {
		t.Fatal(err)
	}
	if len(c.disk.Issued) != 0 || len(c.disk.Certificates) != 0 || len(c.disk.Targets) != 2 || c.ClosedThrough() != closedThrough || c.CheckFHSWatermark(vote) != nil {
		t.Fatal("retirement lost vote safety or failed to bound hot evidence")
	}
	p, _, _, err := readRetired(c.wal.dir, 1)
	if err != nil || len(p.Certificates) != 1 || len(p.Issued) != 1 || len(p.Targets) != 1 {
		t.Fatal("locally known omitted evidence not retained", err)
	}
	if err := c.RememberCertificate(cert); !errors.Is(err, ErrPeriodClosed) {
		t.Fatal("old evidence reintroduced", err)
	}
	if _, err := c.Issue(f.refs[1].EncodeToBytes(), f.vote(t, 1, 6)); !errors.Is(err, ErrPeriodClosed) {
		t.Fatal("old duty signed again", err)
	}
	if err := c.RetireFinalized(one); err != nil {
		t.Fatal("exact retirement retry", err)
	}
	two := retirementBlock(t, f, 2)
	if err := c.RetireFinalized(two); err != nil {
		t.Fatal("second retirement", err)
	}
	// The latest own vote is older than this authenticated finalized cut.
	// Its exact target remains pinned even though its period was retired.
	if c.CheckFHSWatermark(vote) != nil || len(c.disk.Targets) != 2 {
		t.Fatal("late-voter safety pin lost")
	}
	dir := c.wal.dir
	if err := c.Shutdown(); err != nil {
		t.Fatal(err)
	}
	restored, err := OpenCollector(dir, f.registry, 0, &f.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Shutdown()
	if restored.Retirement().Period != 2 || restored.CheckFHSWatermark(vote) != nil {
		t.Fatal("cold recovery lost frontier or own vote")
	}
	if err := restored.RetireFinalized(one); err != nil {
		t.Fatal("old finalized callback retry", err)
	}
	bad := one
	bad.Checkpoint.PostRoot[0] ^= 1
	if err := restored.RetireFinalized(bad); err == nil {
		t.Fatal("same period changed state with old proof accepted")
	}
}

func TestCollectorRetirementCrashBeforeAndAfterFrontier(t *testing.T) {
	for _, beforePublish := range []bool{true, false} {
		t.Run(map[bool]string{true: "archive_durable_frontier_not_published", false: "frontier_published_completion_not_saved"}[beforePublish], func(t *testing.T) {
			f := newRewardFixture(t)
			dir := filepath.Join(t.TempDir(), "collector")
			c := f.collector(t, 0, dir)
			if err := c.BeforeVote(persisted(f.refs[1])); err != nil {
				t.Fatal(err)
			}
			one := retirementBlock(t, f, 1)
			if beforePublish {
				c.persist = func(collectorDisk) error { return errors.New("injected before active frontier publication") }
			}
			err := c.RetireFinalized(one)
			if beforePublish && !errors.Is(err, ErrPersistence) || !beforePublish && err != nil {
				t.Fatal("wrong crash outcome", err)
			}
			c.Shutdown()
			restored, err := OpenCollector(dir, f.registry, 0, &f.keys[0])
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Shutdown()
			if err := restored.RetireFinalized(one); err != nil {
				t.Fatal("durable archive replay did not resume", err)
			}
			if restored.Retirement().Period != 1 || restored.CheckFHSWatermark(persisted(f.refs[1])) != nil {
				t.Fatal("wrong recovered safety/frontier")
			}
		})
	}
}

func TestCollectorRetirementCorruptionAndFinalityBounds(t *testing.T) {
	f := newRewardFixture(t)
	dir := filepath.Join(t.TempDir(), "collector")
	c := f.collector(t, 0, dir)
	one := retirementBlock(t, f, 1)
	before, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	for _, bad := range []FinalizedBlock{retirementBlock(t, f, 2), {Checkpoint: one.Checkpoint}, {Checkpoint: one.Checkpoint, Proof: append(bytes.Clone(one.Proof), 0)}} {
		if err := c.RetireFinalized(bad); err == nil {
			t.Fatal("unauthenticated or skipped retirement accepted")
		}
	}
	after, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("invalid retirement changed active WAL")
	}
	if err := c.RetireFinalized(one); err != nil {
		t.Fatal(err)
	}
	c.Shutdown()
	path := retirementPath(dir, 1)
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, raw[:len(raw)/2], 0600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenCollector(dir, f.registry, 0, &f.keys[0]); err == nil {
		reopened.Shutdown()
		t.Fatal("lost authoritative archive silently reopened from older state")
	}
}

func TestCollectorRetiredPinSurvivesCollectorAheadOfFHS(t *testing.T) {
	f := newRewardFixture(t)
	dir := filepath.Join(t.TempDir(), "collector")
	c := f.collector(t, 0, dir)
	old := persisted(f.refs[1])
	if err := c.BeforeVote(old); err != nil {
		t.Fatal(err)
	}
	if err := c.RetireFinalized(retirementBlock(t, f, 1)); err != nil {
		t.Fatal(err)
	}
	// Collector fsync succeeds, then the FHS WAL save crashes. The restored
	// actual signer still has the previous exact vote (not the collector tip).
	if err := c.BeforeVote(persisted(f.refs[14])); err != nil {
		t.Fatal(err)
	}
	c.Shutdown()
	restored, err := OpenCollector(dir, f.registry, 0, &f.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Shutdown()
	if err := restored.CheckFHSWatermark(old); err != nil {
		t.Fatal("retired previous vote lost across two-WAL crash", err)
	}
	conflict := *old
	conflict.ProposalRef = bytes.Clone(old.ProposalRef)
	conflict.ProposalRef[len(conflict.ProposalRef)-1] ^= 1
	if restored.CheckFHSWatermark(&conflict) == nil {
		t.Fatal("recovery pin authorized different vote")
	}
}

func TestCollectorRetirementPartialStagingRecoveryDoesNotRemoveArchive(t *testing.T) {
	f := newRewardFixture(t)
	dir := filepath.Join(t.TempDir(), "collector")
	c := f.collector(t, 0, dir)
	if err := c.RetireFinalized(retirementBlock(t, f, 1)); err != nil {
		t.Fatal(err)
	}
	c.Shutdown()
	archiveBefore, err := os.ReadFile(retirementPath(dir, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, retirementTemporary), []byte("partial uncommitted staging inode"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenCollector(dir, f.registry, 0, &f.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	r.Shutdown()
	if _, err := os.Lstat(filepath.Join(dir, retirementTemporary)); !os.IsNotExist(err) {
		t.Fatal("stale staging not reclaimed", err)
	}
	archiveAfter, err := os.ReadFile(retirementPath(dir, 1))
	if err != nil || !bytes.Equal(archiveBefore, archiveAfter) {
		t.Fatal("canonical archive changed", err)
	}
	if err := os.Symlink(retirementPath(dir, 1), filepath.Join(dir, retirementTemporary)); err != nil {
		t.Fatal(err)
	}
	if r, err := OpenCollector(dir, f.registry, 0, &f.keys[0]); err == nil {
		r.Shutdown()
		t.Fatal("symlink staging accepted")
	}
}

// The second startup must pin the actual FHS WAL watermark, not the newer
// collector-only attempt. Two consecutive pre-FHS-fsync crashes must remain
// recoverable without deleting safety history or weakening conflict checks.
func TestCollectorRetiredPinSurvivesRepeatedCollectorAheadCrashes(t *testing.T) {
	f := newRewardFixture(t)
	dir := filepath.Join(t.TempDir(), "collector")
	c := f.collector(t, 0, dir)
	durable := persisted(f.refs[1])
	if err := c.BeforeVote(durable); err != nil {
		t.Fatal(err)
	}
	if err := c.RetireFinalized(retirementBlock(t, f, 1)); err != nil {
		t.Fatal(err)
	}
	for _, height := range []uint64{12, 13, 14} {
		if err := c.CheckFHSWatermark(durable); err != nil {
			t.Fatal("actual durable FHS vote lost before retry", err)
		}
		if err := c.BeforeVote(persisted(f.refs[height])); err != nil {
			t.Fatal(err)
		}
		if err := c.Shutdown(); err != nil {
			t.Fatal(err)
		}
		var err error
		c, err = OpenCollector(dir, f.registry, 0, &f.keys[0])
		if err != nil {
			t.Fatal(err)
		}
	}
	defer c.Shutdown()
	if err := c.CheckFHSWatermark(durable); err != nil {
		t.Fatal("actual durable FHS vote lost after repeated crashes", err)
	}
}

func TestCollectorExactRetryAdvancesRecoveredFHSPin(t *testing.T) {
	f := newRewardFixture(t)
	dir := filepath.Join(t.TempDir(), "collector")
	c := f.collector(t, 0, dir)
	a, b, next := persisted(f.refs[1]), persisted(f.refs[2]), persisted(f.refs[14])
	if err := c.BeforeVote(a); err != nil {
		t.Fatal(err)
	}
	if err := c.RetireFinalized(retirementBlock(t, f, 1)); err != nil {
		t.Fatal(err)
	}
	if err := c.BeforeVote(b); err != nil {
		t.Fatal(err)
	}
	c.Shutdown()
	var err error
	c, err = OpenCollector(dir, f.registry, 0, &f.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if err = c.CheckFHSWatermark(a); err != nil {
		t.Fatal(err)
	}
	// Exact collector retry B succeeds, and the real FHS WAL now persists B.
	if err = c.BeforeVote(b); err != nil {
		t.Fatal(err)
	}
	// Next collector C persists but FHS C does not; restart must retain B.
	if err = c.BeforeVote(next); err != nil {
		t.Fatal(err)
	}
	c.Shutdown()
	c, err = OpenCollector(dir, f.registry, 0, &f.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Shutdown()
	if err = c.CheckFHSWatermark(b); err != nil {
		t.Fatal("exact retry left stale recovered pin", err)
	}
}

func TestCollectorOrphanRetirementCompletesBeforeLateCertificateAdmission(t *testing.T) {
	f := newRewardFixture(t)
	peers := f.five(t)
	early := f.certificate(t, peers, 1, 6)
	late := f.certificate(t, peers, 2, 6)
	dir := filepath.Join(t.TempDir(), "collector")
	c := f.collector(t, 0, dir)
	if err := c.RememberCertificate(early); err != nil {
		t.Fatal(err)
	}
	one := retirementBlock(t, f, 1)
	c.persist = func(collectorDisk) error { return errors.New("injected frontier publication failure") }
	if err := c.RetireFinalized(one); !errors.Is(err, ErrPersistence) {
		t.Fatal(err)
	}
	c.Shutdown()
	c, err := OpenCollector(dir, f.registry, 0, &f.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Shutdown()
	// Network can deliver this before the first actor Tick. Startup must have
	// completed the exact proved tail, making the finalized period closed.
	if err := c.RememberCertificate(late); !errors.Is(err, ErrPeriodClosed) {
		t.Fatal("orphan tail exposed open period to delayed certificate", err)
	}
	if err := c.RetireFinalized(one); err != nil {
		t.Fatal("tail retry", err)
	}
	archived, _, _, err := readRetired(dir, 1)
	if err != nil || len(archived.Certificates) != 1 || c.Retirement().Period != 1 {
		t.Fatal("already acknowledged evidence lost", err)
	}
}

func TestCollectorOrphanArchiveCannotReplaceLostCanonicalWAL(t *testing.T) {
	f := newRewardFixture(t)
	dir := filepath.Join(t.TempDir(), "collector")
	c := f.collector(t, 0, dir)
	c.persist = func(collectorDisk) error { return errors.New("injected frontier failure") }
	if err := c.RetireFinalized(retirementBlock(t, f, 1)); !errors.Is(err, ErrPersistence) {
		t.Fatal(err)
	}
	c.Shutdown()
	if err := os.Remove(filepath.Join(dir, "state.json")); err != nil {
		t.Fatal(err)
	}
	if r, err := OpenCollector(dir, f.registry, 0, &f.keys[0]); err == nil {
		r.Shutdown()
		t.Fatal("orphan became fresh trust root after lost canonical WAL")
	}
}

func TestCollectorOrphanFilenamePeriodMustMatchProof(t *testing.T) {
	f := newRewardFixture(t)
	dir := filepath.Join(t.TempDir(), "collector")
	c := f.collector(t, 0, dir)
	if err := c.RetireFinalized(retirementBlock(t, f, 1)); err != nil {
		t.Fatal(err)
	}
	c.Shutdown()
	raw, err := os.ReadFile(retirementPath(dir, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(retirementPath(dir, 2), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenCollector(dir, f.registry, 0, &f.keys[0]); err == nil {
		reopened.Shutdown()
		t.Fatal("valid old proof accepted as next archive filename")
	}
}
