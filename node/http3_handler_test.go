package node

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestHTTP3PureCompositionFailures(t *testing.T) {
	existing := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) })
	shared := func(h http.Handler) http.Handler { return h }
	for _, c := range []HTTP3HandlerComposer{
		func(http.Handler, func(http.Handler) http.Handler) (http.Handler, error) {
			return nil, errors.New("operator error")
		},
		func(http.Handler, func(http.Handler) http.Handler) (http.Handler, error) { return nil, nil },
		func(http.Handler, func(http.Handler) http.Handler) (http.Handler, error) { panic("operator panic") },
	} {
		if h, e := ComposeHTTP3Handler(existing, shared, c); e == nil || h != nil {
			t.Fatal("failed hook accepted")
		}
	}
	if _, e := ComposeHTTP3Handler(nil, shared, nil); e == nil {
		t.Fatal("nil RPC accepted")
	}
	if _, e := ComposeHTTP3Handler(existing, nil, nil); e == nil {
		t.Fatal("nil shared accepted")
	}
	if _, e := ComposeHTTP3Handler(existing, func(http.Handler) http.Handler { return nil }, nil); e == nil {
		t.Fatal("nil shared result accepted")
	}
	h, e := ComposeHTTP3Handler(existing, shared, nil)
	if e != nil || h == nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "https://example", nil))
	if w.Code != 202 {
		t.Fatal("default request changed", w.Code)
	}
}

func TestHTTP3TypedNilFailsStartup(t *testing.T) {
	var absent *http.ServeMux
	shared := func(h http.Handler) http.Handler { return h }
	if _, e := ComposeHTTP3Handler(absent, shared, nil); e == nil {
		t.Fatal("typed nil RPC accepted")
	}
	rpc := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if _, e := ComposeHTTP3Handler(rpc, shared, func(http.Handler, func(http.Handler) http.Handler) (http.Handler, error) {
		return http.HandlerFunc(nil), nil
	}); e == nil {
		t.Fatal("typed nil hook output accepted")
	}
}

// This compares the nil hook with the actual existing shared middleware. It
// deliberately uses recorders, never a server, node, DB or IPC connection.
func TestHTTP3NilComposerPreservesExistingStack(t *testing.T) {
	rpc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("X-RPC", r.Header.Get("X-Original"))
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write(body)
	})
	shared := func(h http.Handler) http.Handler {
		return NewHTTPHandlerStack(h, []string{"https://ui.example"}, []string{"allowed.example"})
	}
	composed, err := ComposeHTTP3Handler(rpc, shared, nil)
	if err != nil {
		t.Fatal(err)
	}
	baseline := shared(rpc)
	cases := []struct{ method, host, origin string }{
		{"POST", "allowed.example", "https://ui.example"},
		{"POST", "blocked.example", "https://ui.example"},
		{"POST", "allowed.example", "https://other.example"},
		{"OPTIONS", "allowed.example", "https://ui.example"},
		{"OPTIONS", "allowed.example", "https://other.example"},
	}
	for _, c := range cases {
		t.Run(c.method+"/"+c.host+"/"+c.origin, func(t *testing.T) {
			request := func() *http.Request {
				r := httptest.NewRequest(c.method, "https://"+c.host+"/rpc", strings.NewReader("rpc bytes"))
				r.Header.Set("Origin", c.origin)
				r.Header.Set("X-Original", "kept")
				if c.method == "OPTIONS" {
					r.Header.Set("Access-Control-Request-Method", "POST")
					r.Header.Set("Access-Control-Request-Headers", "X-Original")
				}
				return r
			}
			before, after := httptest.NewRecorder(), httptest.NewRecorder()
			baseline.ServeHTTP(before, request())
			composed.ServeHTTP(after, request())
			if before.Code != after.Code || before.Body.String() != after.Body.String() || !reflect.DeepEqual(before.Header(), after.Header()) {
				t.Fatalf("nil hook changed existing stack: before=%d %q %v after=%d %q %v", before.Code, before.Body.String(), before.Header(), after.Code, after.Body.String(), after.Header())
			}
		})
	}
	var cfg Config
	if cfg.HTTP3HandlerComposer != nil {
		t.Fatal("default config enables composer")
	}
	field, ok := reflect.TypeOf(cfg).FieldByName("HTTP3HandlerComposer")
	if !ok || field.Tag.Get("toml") != "-" {
		t.Fatal("composer is exposed as TOML setting")
	}
}
