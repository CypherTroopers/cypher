package service

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/cypherium/cypher/dex/consensus"
)

func TestSnapshotAndSettlementAPIResponseBounds(t *testing.T) {
	configs := serviceConfigs(t)
	c := configs[0]
	// Query remains an actor callback; this fixture isolates route and byte-limit
	// behavior. Financial authentication is tested by the real provider separately.
	c.Query = func(_ *consensus.Application, path string, q url.Values) (interface{}, error) {
		n := consensus.MaxSnapshotBytes
		if q.Get("oversized") == "1" {
			n = 3 * 1024 * 1024
		}
		if path == "/v1/settlement" {
			n = 128 * 1024
		}
		return struct{ Bytes []byte }{make([]byte, n)}, nil
	}
	s, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Start(); err != nil {
		t.Fatal(err)
	}
	api, err := startAPI(s, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer api.close()
	base := "http://" + api.listener.Addr().String()
	for _, tc := range []struct {
		path         string
		status, size int
	}{{"/v1/snapshot?height=3", 200, consensus.MaxSnapshotBytes}, {"/v1/settlement?height=3", 200, 128 * 1024}, {"/v1/snapshot?oversized=1", 503, 0}} {
		r, err := http.Get(base + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 3*1024*1024+1))
		r.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != tc.status || len(raw) > 3*1024*1024 {
			t.Fatal("API response bound", tc.path, r.StatusCode, len(raw))
		}
		if tc.status == 200 {
			var data struct{ Bytes []byte }
			if err = json.Unmarshal(raw, &data); err != nil || len(data.Bytes) != tc.size {
				t.Fatal("base64 data expansion", err, len(data.Bytes))
			}
		}
	}
	r, err := http.Post(base+"/v1/snapshot?height=3", "application/octet-stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusNotFound {
		t.Fatal("snapshot mutation endpoint available")
	}
}
