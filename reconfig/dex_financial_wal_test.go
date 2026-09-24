package reconfig_test

import (
	"encoding/json"
	"github.com/cypherium/cypher/dex/protocol"
	"testing"
)

func TestFinancialFaultWALChecksumVersions(t *testing.T) {
	for _, test := range []struct {
		name            string
		version, schema uint16
		domain          string
		valid           bool
	}{
		{"legacy1", 1, 1, "common-dex/wal/v1", true},
		{"legacy-financial", 1, 3, "common-dex/wal/v1", true},
		{"compact-rolling", 2, 4, "common-dex/wal/v2", true},
		{"compact-under-old-digest", 2, 4, "common-dex/wal/v1", false},
		{"legacy-under-new-digest", 1, 4, "common-dex/wal/v2", false},
		{"compact-wrong-schema", 2, 3, "common-dex/wal/v2", false},
		{"dictionary-rolling", 3, 4, "common-dex/wal/v3", true},
		{"dictionary-under-v1-digest", 3, 4, "common-dex/wal/v1", false},
		{"dictionary-under-v2-digest", 3, 4, "common-dex/wal/v2", false},
		{"dictionary-wrong-schema", 3, 3, "common-dex/wal/v3", false},
		{"compact-under-dictionary-digest", 2, 4, "common-dex/wal/v3", false},
		{"unknown-version", 4, 4, "common-dex/wal/v3", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload, err := json.Marshal(struct{ Version, ExecutionSchema uint16 }{test.version, test.schema})
			if err != nil {
				t.Fatal(err)
			}
			envelope := struct {
				Payload  json.RawMessage
				Checksum protocol.Hash
			}{payload, protocol.Digest(test.domain, payload)}
			raw, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if err = validateFinancialWALChecksum(raw); (err == nil) != test.valid {
				t.Fatal("versioned envelope result", err)
			}
			envelope.Checksum[0] ^= 1
			raw, _ = json.Marshal(envelope)
			if err = validateFinancialWALChecksum(raw); err == nil {
				t.Fatal("checksum corruption accepted")
			}
		})
	}
}
