package eth

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/params"
)

func completeCheckpoint(section uint64) *params.TrustedCheckpoint {
	return &params.TrustedCheckpoint{
		SectionIndex: section,
		SectionHead:  common.HexToHash("0x01"),
		CHTRoot:      common.HexToHash("0x02"),
		BloomRoot:    common.HexToHash("0x03"),
	}
}

func TestResolveTrustedCheckpointRejectsIncompleteCheckpoint(t *testing.T) {
	checkpoint := completeCheckpoint(182)
	checkpoint.BloomRoot = common.Hash{}

	if _, _, err := resolveTrustedCheckpoint(checkpoint, 0, nil); err == nil {
		t.Fatal("incomplete checkpoint was accepted")
	}
}

func TestResolveTrustedCheckpointRejectsOverflow(t *testing.T) {
	checkpoint := completeCheckpoint(^uint64(0))
	if _, _, err := resolveTrustedCheckpoint(checkpoint, 0, nil); err == nil {
		t.Fatal("overflowing checkpoint was accepted")
	}
}

func TestResolveTrustedCheckpointChecksKnownCanonicalHeader(t *testing.T) {
	checkpoint := completeCheckpoint(0)
	target := uint64(params.CHTFrequency - 1)

	_, _, err := resolveTrustedCheckpoint(checkpoint, target, func(number uint64) common.Hash {
		if number != target {
			t.Fatalf("canonical lookup number = %d, want %d", number, target)
		}
		return common.HexToHash("0xff")
	})
	if err == nil {
		t.Fatal("checkpoint contradicting the canonical chain was accepted")
	}

	number, hash, err := resolveTrustedCheckpoint(checkpoint, target, func(uint64) common.Hash {
		return checkpoint.SectionHead
	})
	if err != nil {
		t.Fatalf("matching checkpoint was rejected: %v", err)
	}
	if number != target || hash != checkpoint.SectionHead {
		t.Fatalf("resolved checkpoint = (%d, %s), want (%d, %s)", number, hash, target, checkpoint.SectionHead)
	}
}

func TestPromotePeerHeadUsesOneBlockAheadAnnouncement(t *testing.T) {
	parentHash := common.HexToHash("0x10")
	blockHash := common.HexToHash("0x11")
	peer := &peer{head: parentHash, td: big.NewInt(100)}

	if !promotePeerHead(peer, blockHash, big.NewInt(105)) {
		t.Fatal("one-block-ahead announcement did not request a downloader wakeup")
	}
	head, td := peer.Head()
	if head != blockHash || td.Cmp(big.NewInt(105)) != 0 {
		t.Fatalf("peer head after announcement = (%s, %s), want (%s, 105)", head, td, blockHash)
	}

	if promotePeerHead(peer, parentHash, big.NewInt(100)) {
		t.Fatal("stale announcement requested a downloader wakeup")
	}
	head, td = peer.Head()
	if head != blockHash || td.Cmp(big.NewInt(105)) != 0 {
		t.Fatalf("stale announcement regressed peer head to (%s, %s)", head, td)
	}
}
