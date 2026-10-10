package eth

import (
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
)

func TestMiningCannotRestartAfterNodeShutdown(t *testing.T) {
	service := new(Ethereum)
	service.miningClosed.Store(true)
	if err := service.StartMining(1, true, common.Address{}, nil); err == nil || !strings.Contains(err.Error(), "node shutdown") {
		t.Fatalf("direct mining start after shutdown = %v", err)
	}
	api := NewPrivateMinerAPI(service)
	threads := 1
	result, err := api.Start(&threads, common.Address{}, "")
	if result != "" || err == nil || !strings.Contains(err.Error(), "node shutdown") {
		t.Fatalf("RPC mining start after shutdown = (%q, %v)", result, err)
	}
}
