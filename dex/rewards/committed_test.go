package rewards

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/dex/protocol"
)

func TestIndependentParticipationCommitGolden(t *testing.T) {
	raw, err := os.ReadFile("../testdata/participation_commit.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Payload string `json:"payload"`
		Hash    string `json:"payload_hash"`
		Target  string `json:"action_target"`
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	payload, err := hex.DecodeString(v.Payload)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := DecodeCommitBatch(payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := batch.Encode()
	if err != nil || !bytes.Equal(encoded, payload) {
		t.Fatal("commit codec", err)
	}
	h := protocol.Digest("common-dex/participation-commit/v2", payload)
	if hex.EncodeToString(h[:]) != v.Hash || hex.EncodeToString(h[:20]) != v.Target {
		t.Fatal("commit hash domain")
	}
	for name, bad := range map[string][]byte{"trailing": append(bytes.Clone(payload), 0), "truncated": payload[:len(payload)-1], "huge": make([]byte, MaxCommitBytes+1), "version": append(append(bytes.Clone(payload[:9]), 3), payload[10:]...), "count": append(append(bytes.Clone(payload[:10]), 0, 71), payload[12:]...)} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeCommitBatch(bad); err == nil {
				t.Fatal("malformed accepted")
			}
		})
	}
	batch.Certificates[0], batch.Certificates[1] = batch.Certificates[1], batch.Certificates[0]
	if _, err := batch.Encode(); err == nil {
		t.Fatal("unordered batch")
	}
}

func TestCommittedParticipationExactSetDeadlineAndOrphan(t *testing.T) {
	f := newRewardFixture(t)
	collectors := f.five(t)
	one := f.certificate(t, collectors, 1, 0)
	two := f.certificate(t, collectors, 1, 6)
	batch, err := SortedCommitBatch([]Certificate{one, two})
	if err != nil {
		t.Fatal(err)
	}
	committed, err := f.registry.Commit(nil, 0, 2, batch)
	if err != nil {
		t.Fatal(err)
	}
	prior, _ := json.Marshal(committed)
	repeated, err := f.registry.Commit(committed, 0, 14, batch)
	if err != nil || !reflect.DeepEqual(repeated, committed) {
		t.Fatal("duplicate commit changed evidence or timestamp", err)
	}
	for _, height := range []uint64{1, 15} {
		if _, err := f.registry.Commit(nil, 0, height, batch); err == nil {
			t.Fatal("commit deadline accepted", height)
		}
	}
	if _, err := f.registry.Commit(nil, 1, 2, batch); err == nil {
		t.Fatal("closed period reopened")
	}
	bad := batch
	bad.Certificates = append([]Certificate(nil), batch.Certificates...)
	bad.Certificates[0].Signatures = append([]CollectorSignature(nil), bad.Certificates[0].Signatures...)
	bad.Certificates[0].Signatures[0].Signature[0] ^= 1
	if _, err := f.registry.Commit(committed, 0, 3, bad); err == nil {
		t.Fatal("invalid receipt committed")
	}
	pkg := ClosePackage{1, f.blocks, []Certificate{one, two}}
	if _, _, err := f.registry.CheckCommittedClose(nil, 0, 15, pkg); !errors.Is(err, ErrUncommittedPeriod) {
		t.Fatal("uncommitted close", err)
	}
	partial := pkg
	partial.Certificates = partial.Certificates[:1]
	if _, _, err := f.registry.CheckCommittedClose(committed, 0, 15, partial); !errors.Is(err, ErrCommittedOmission) {
		t.Fatal("committed omission", err)
	}
	points, next, err := f.registry.CheckCommittedClose(committed, 0, 15, pkg)
	if err != nil || points.Entries[0].Points != 1 || points.Entries[6].Points != 1 || len(next.Entries) != 0 {
		t.Fatal("exact committed close", err)
	}
	// A different duty signed by five registered receipt keys is authenticated
	// evidence but not canonical work. Finality witnesses, never local delivery,
	// decide eligibility; such a record cannot poison the canonical close.
	orphan := one
	orphan.Duty.ProposalID[0] ^= 1
	orphan.Signatures = append([]CollectorSignature(nil), one.Signatures...)
	for i := range orphan.Signatures {
		index := orphan.Signatures[i].Collector
		h, err := receiptDigest(orphan.Duty, index, f.registry.keys[index].Serialize())
		if err != nil {
			t.Fatal(err)
		}
		copy(orphan.Signatures[i].Signature[:], f.keys[index].SignHash(h[:]).Serialize())
	}
	orphanBatch, err := SortedCommitBatch([]Certificate{orphan})
	if err != nil {
		t.Fatal(err)
	}
	withOrphan, err := f.registry.Commit(committed, 0, 3, orphanBatch)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := f.registry.CheckCommittedClose(withOrphan, 0, 15, pkg)
	if err != nil || got != points {
		t.Fatal("orphan poisoned committed period", err)
	}
	orphanClose := pkg
	orphanClose.Certificates = []Certificate{orphan, two}
	if _, _, err := f.registry.CheckCommittedClose(withOrphan, 0, 15, orphanClose); err == nil {
		t.Fatal("orphan earned points")
	}
	after, _ := json.Marshal(committed)
	if !bytes.Equal(prior, after) {
		t.Fatal("validation/failed commit mutated parent")
	}
}

func FuzzParticipationCommitCodec(f *testing.F) {
	f.Add([]byte(CommitMarker))
	f.Add(make([]byte, MaxCommitBytes+1))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if b, err := DecodeCommitBatch(raw); err == nil {
			encoded, err := b.Encode()
			if err != nil || !bytes.Equal(raw, encoded) {
				t.Fatal("noncanonical roundtrip")
			}
		}
	})
}
