package node

import (
	"bytes"
	"encoding/json"
	"github.com/cypherium/cypher/common"
	"net/http/httptest"
	"testing"
)

func TestDEXEvidenceMethodsCrossPublicFilterWithoutAuthority(t *testing.T) {
	backend, apis, _, _, _ := newPublicBoundaryFixture(t)
	stack, err := New(&Config{DataDir: t.TempDir(), HTTPModules: []string{"eth"}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	stack.RegisterAPIs(apis)
	public, err := stack.PublicRPCHandler()
	if err != nil {
		t.Fatal(err)
	}
	// Populate the same public filter without opening a socket in this unit
	// test. The process gate separately exercises Node.Start and real HTTP.
	if err = RegisterApisFromWhitelist(apis, []string{"eth"}, public, false); err != nil {
		t.Fatal(err)
	}
	before := backend.state.IntermediateRoot(false)
	for _, tc := range []struct {
		method string
		params []interface{}
	}{
		{"eth_getCLXFinalityWitness", []interface{}{"0x1"}},
		{"eth_getDEXInboxEntries", []interface{}{common.Hash{1}.Hex(), "0x0", "0x1"}},
	} {
		t.Run(tc.method, func(t *testing.T) {
			if !allowPublicRPCMethod(tc.method, false) || allowPublicRPCMethod(tc.method, true) {
				t.Fatal("incorrect public evidence policy")
			}
			request, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": tc.method, "params": tc.params})
			req := httptest.NewRequest("POST", "http://127.0.0.1/", bytes.NewReader(request))
			req.Header.Set("Content-Type", "application/json")
			reply := httptest.NewRecorder()
			public.ServeHTTP(reply, req)
			var response struct {
				Error *struct {
					Code    int
					Message string
				}
				Result json.RawMessage
			}
			if err := json.Unmarshal(reply.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			// The normal implementation is reached, but an ordinary/non-devnet chain
			// remains disabled. A global RPC filter is not a settlement activation flag.
			if response.Error == nil || response.Error.Code == -32601 || len(response.Result) > 0 {
				t.Fatalf("public evidence authority: %s", reply.Body.String())
			}
			if backend.state.IntermediateRoot(false) != before || backend.publications.Load() != 0 {
				t.Fatal("read-only evidence mutated/published")
			}
		})
	}
	for _, method := range []string{"eth_setCLXFinalityWitness", "eth_setDEXInboxEntries", "eth_submitVerifiedRange", "eth_setRollingAnchor"} {
		if allowPublicRPCMethod(method, false) {
			t.Fatal("unexpected mutation API")
		}
	}
}
