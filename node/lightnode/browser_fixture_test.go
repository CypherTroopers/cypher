package lightnode

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestBrowserHTTPFixture is an opt-in, finite real HTTP handler fixture for
// cross-language browser tests. Only its owned source is synthetic; it must
// never be described as a real Common DB, peer, chain, or finality verification.
func TestBrowserHTTPFixture(t *testing.T) {
	if os.Getenv("COMMON_LIGHTNODE_BROWSER_FIXTURE") != "1" {
		t.Skip("explicit synthetic browser HTTP fixture opt-in required")
	}
	origin := os.Getenv("COMMON_LIGHTNODE_FIXTURE_PAGE_ORIGIN")
	if !literalOrigin(origin) {
		t.Fatal("explicit exact literal loopback fixture page origin required")
	}
	dir := os.Getenv("COMMON_LIGHTNODE_FIXTURE_DIR")
	if dir == "" {
		dir = ".preview"
	}
	// Parent owns the selected isolated output directory. No credential is written.
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(dir, "lightnode-browser-fixture-ready.json")
	stop := filepath.Join(dir, "lightnode-browser-fixture-stop")
	if _, err := os.Stat(ready); !os.IsNotExist(err) {
		t.Fatal("ready marker already exists; use a fresh owner-selected fixture directory")
	}
	if _, err := os.Stat(stop); !os.IsNotExist(err) {
		t.Fatal("stop marker already exists; use a fresh owner-selected fixture directory")
	}
	var height uint64 = 41
	factory := func(ctx context.Context) (View, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// The view snapshots one advancing synthetic head. Header bytes remain
		// deterministic at every height, enabling exact retained-byte checks.
		h := atomic.AddUint64(&height, 1)
		return &syntheticView{store: &syntheticStore{head: h, network: syntheticNetwork, headers: make(map[uint64][]byte)}}, nil
	}
	s, err := New(Config{Enabled: true, ListenAddr: "127.0.0.1:18083", AllowedPageOrigin: origin, ExpectedNetwork: syntheticNetwork, Factory: factory})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:18083")
	if err != nil {
		s.Close()
		t.Fatal("owned fixture loopback port unavailable:", err)
	}
	httpServer := &http.Server{Handler: s, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096}
	defer func() { s.Close(); httpServer.Close(); listener.Close(); os.Remove(ready) }()
	done := make(chan error, 1)
	go func() { done <- httpServer.Serve(listener) }()
	b, _ := json.Marshal(struct {
		Source  string  `json:"source"`
		Port    int     `json:"port"`
		Network Network `json:"network"`
	}{"synthetic", 18083, syntheticNetwork})
	if err := os.WriteFile(ready, b, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("SYNTHETIC source; actual lightnode HTTP handler active for at most 90 seconds; owner stops it after browser checks")
	deadline := time.NewTimer(90 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			return
		case <-tick.C:
			if _, err := os.Stat(stop); err == nil {
				return
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
		case err := <-done:
			if err != nil && err != http.ErrServerClosed {
				t.Fatal(err)
			}
			return
		}
	}
}
