package params

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cypherium/cypher/crypto"
)

func TestCommonRPCRecipientActivationOptionRejected(t *testing.T) {
	for _, name := range []string{"commonRPCRewardRecipientBlock", "COMMONRPCREWARDRECIPIENTBLOCK"} {
		for _, value := range []string{"0", "100", "null"} {
			var config ChainConfig
			err := json.Unmarshal([]byte(`{"`+name+`":`+value+`}`), &config)
			if err == nil || !strings.Contains(err.Error(), "mandatory from genesis") {
				t.Fatalf("obsolete option %s=%s error = %v", name, value, err)
			}
		}
	}
	encoded, err := json.Marshal(testFairHotstuffConfig())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "commonRPCRewardRecipientBlock") {
		t.Fatal("obsolete activation option is still advertised")
	}
}

func TestCommonRPCRecipientNetworkHasDistinctGenesisDomain(t *testing.T) {
	config := testFairHotstuffConfig()
	config.RnetTransport = config.EffectiveRnetTransport()
	config.RnetFallbackTransport = config.EffectiveRnetFallbackTransport()
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	current, err := FairHotstuffGenesisCommitment(config)
	if err != nil {
		t.Fatal(err)
	}
	if want := crypto.Keccak256Hash([]byte("cypher-fhs-genesis-config-v3"), encoded); current != want {
		t.Fatalf("new network commitment = %s, want v3 %s", current, want)
	}
	if old := crypto.Keccak256Hash([]byte("cypher-fhs-genesis-config-v2"), encoded); current == old {
		t.Fatal("mandatory recipient network retained the old genesis commitment")
	}
}
