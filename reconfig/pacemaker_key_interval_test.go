package reconfig

import (
	"testing"
	"time"

	"github.com/cypherium/cypher/params"
)

func TestDeferFairHotstuffIdleKeyPace(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	waiting := uint64(now.Add(-9 * time.Minute).Unix())
	due := uint64(now.Add(-params.KeyBlockMinInterval).Unix())
	config := &params.ChainConfig{FairHotstuff: true}

	if !deferFairHotstuffIdleKeyPace(config, 0, waiting, now) {
		t.Fatal("idle Fair HotStuff chain did not keep its leader until the key interval")
	}
	if deferFairHotstuffIdleKeyPace(config, 0, due, now) {
		t.Fatal("a due key interval still deferred the pacemaker")
	}
	if deferFairHotstuffIdleKeyPace(config, 1, waiting, now) {
		t.Fatal("pending transactions deferred the pacemaker")
	}
	if deferFairHotstuffIdleKeyPace(&params.ChainConfig{}, 0, waiting, now) {
		t.Fatal("a chain without Fair HotStuff deferred the pacemaker")
	}
	if deferFairHotstuffIdleKeyPace(config, 0, 0, now) {
		t.Fatal("a zero key timestamp deferred the pacemaker")
	}
}
