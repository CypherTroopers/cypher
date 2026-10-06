// SPDX-License-Identifier: GPL-3.0-or-later
package browserstartup

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
)

func options() Options {
	return Options{Enabled: true, ConfigPath: "/public/gateway.json", StateRoot: "/dedicated/proof", Role: "common-rpc"}
}
func role() Role { return Role{HTTP3: true, Bridge: true, FairHotstuff: true} }

func TestBrowserStartupDefaultDisabledAndStrictOptions(t *testing.T) {
	c, err := New(Options{})
	if err != nil || c != nil {
		t.Fatal("default enabled", err)
	}
	bad := []Options{
		{ConfigPath: "/public/gateway.json"},
		{Enabled: true},
		{Enabled: true, ConfigPath: "relative", StateRoot: "/dedicated/proof", Role: "common-rpc"},
		{Enabled: true, ConfigPath: "/public/../gateway.json", StateRoot: "/dedicated/proof", Role: "common-rpc"},
	}
	for _, change := range []func(*Options){
		func(o *Options) { o.Role = "validator" }, func(o *Options) { o.CommandName = "console" },
		func(o *Options) { o.UnlockRequested = true }, func(o *Options) { o.MiningRequested = true },
	} {
		o := options()
		change(&o)
		bad = append(bad, o)
	}
	for _, o := range bad {
		if c, err := New(o); err == nil || c != nil {
			t.Fatal("unsafe option accepted", o)
		}
	}
	if c, err := New(options()); err != nil || c == nil {
		t.Fatal(err)
	}
}

func TestBrowserStartupFinalRoleRejectsBeforeFactory(t *testing.T) {
	for _, r := range []Role{{}, {HTTP3: true, Ingress: true, Bridge: true, FairHotstuff: true}, {HTTP3: true, FairHotstuff: true}, {HTTP3: true, Bridge: true}} {
		c, _ := New(options())
		calls := 0
		if err := c.Initialize(r, func() (Resource, error) { calls++; return Resource{}, nil }); err == nil || calls != 0 {
			t.Fatal("invalid role reached factory")
		}
		if c.Start() == nil {
			t.Fatal("failed role left controller active")
		}
	}
}

func TestBrowserStartupHandlerLifecycle(t *testing.T) {
	c, _ := New(options())
	closed := 0
	serve := func() int {
		w := httptest.NewRecorder()
		c.ServeHTTP(w, httptest.NewRequest("POST", "https://peer.example/api/node/v1/sessions", nil))
		return w.Code
	}
	if serve() != http.StatusServiceUnavailable || c.Start() == nil {
		t.Fatal("uninitialized handler exposed")
	}
	err := c.Initialize(role(), func() (Resource, error) {
		return Resource{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), Close: func() error { closed++; return nil }}, nil
	})
	if err != nil || c.Start() != nil || serve() != 204 {
		t.Fatal("initialized handler unavailable", err)
	}
	if err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil || closed != 1 || serve() != http.StatusServiceUnavailable {
		t.Fatal("owned handler leaked or closed twice")
	}
}

func TestBrowserStartupPartialFactoryAndTypedNilCleanup(t *testing.T) {
	for _, factoryError := range []error{errors.New("constructor failed"), nil} {
		c, _ := New(options())
		closed := 0
		var h *http.ServeMux
		err := c.Initialize(role(), func() (Resource, error) {
			return Resource{Handler: h, Close: func() error { closed++; return nil }}, factoryError
		})
		if err == nil || closed != 1 || c.Start() == nil {
			t.Fatal("partial constructor leaked")
		}
		_ = c.Close()
		if closed != 1 {
			t.Fatal("partial close repeated")
		}
	}
}

func TestBrowserStartupCloseBeforeFatalAndTransport(t *testing.T) {
	for _, stage := range []string{"node-construction", "eth-registration", "network-start"} {
		t.Run(stage, func(t *testing.T) {
			events := []string{}
			err := errors.New(stage)
			if got := CloseOnError(err, func() error { events = append(events, "controller-close"); return nil }, func() error { events = append(events, "stack-close"); return nil }); got != err {
				t.Fatal("error changed")
			}
			events = append(events, "fatal-exit")
			if !reflect.DeepEqual(events, []string{"controller-close", "stack-close", "fatal-exit"}) {
				t.Fatal(events)
			}
		})
	}
	called := false
	_ = CloseOnError(nil, func() error { called = true; return nil })
	if called {
		t.Fatal("success released live owner")
	}
}

func TestBrowserStartupCloseDuringInitialize(t *testing.T) {
	for _, mode := range []string{"late-success", "late-partial-failure", "late-typed-nil"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := New(options())
			entered, release := make(chan struct{}), make(chan struct{})
			done := make(chan error, 1)
			var closes atomic.Int32
			go func() {
				done <- c.Initialize(role(), func() (Resource, error) {
					close(entered)
					<-release
					var h http.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
					var err error
					if mode == "late-partial-failure" {
						err = errors.New("partial constructor failed")
					}
					if mode == "late-typed-nil" {
						var absent *http.ServeMux
						h = absent
					}
					return Resource{Handler: h, Close: func() error { closes.Add(1); return nil }}, err
				})
			}()
			<-entered
			var wg sync.WaitGroup
			for i := 0; i < 16; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); _ = c.Close() }()
			}
			wg.Wait()
			close(release)
			if err := <-done; err == nil || closes.Load() != 1 || c.Start() == nil {
				t.Fatal("late factory resource escaped", err, closes.Load())
			}
			w := httptest.NewRecorder()
			c.ServeHTTP(w, httptest.NewRequest("GET", "https://peer.example/api/node/v1/anchors", nil))
			if w.Code != http.StatusServiceUnavailable {
				t.Fatal("closed handler published late resource")
			}
		})
	}
}

func TestBrowserStartupCloseErrorStable(t *testing.T) {
	c, _ := New(options())
	want := errors.New("close failure")
	calls := 0
	if err := c.Initialize(role(), func() (Resource, error) {
		return Resource{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Close: func() error { calls++; return want }}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if c.Close() != want || c.Close() != want || calls != 1 {
		t.Fatal("close result changed")
	}
}

func TestBrowserStartupRegistersLastAndStopsFirst(t *testing.T) {
	for _, mode := range []string{"success", "factory-failure", "registration-failure"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := New(options())
			events := []string{}
			registrations := 0
			closes := 0
			// Model Node's documented reverse lifecycle order using owned mocks.
			stops := []func() error{
				func() error { events = append(events, "chain-stop"); return nil },
				func() error { events = append(events, "ingress-stop"); return nil },
			}
			err := c.InitializeAndRegister(role(), func() (Resource, error) {
				if mode == "factory-failure" {
					return Resource{}, errors.New("factory failed")
				}
				return Resource{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Close: func() error { closes++; events = append(events, "gateway-close"); return nil }}, nil
			}, func() error {
				registrations++
				if c.Start() != nil {
					t.Fatal("registered before ready")
				}
				if mode == "registration-failure" {
					return errors.New("registration failed")
				}
				stops = append(stops, c.Stop)
				return nil
			})
			if mode == "success" {
				if err != nil || registrations != 1 {
					t.Fatal(err)
				}
				for i := len(stops) - 1; i >= 0; i-- {
					_ = stops[i]()
				}
				if closes != 1 || !reflect.DeepEqual(events, []string{"gateway-close", "ingress-stop", "chain-stop"}) {
					t.Fatal(events)
				}
			} else {
				if err == nil || c.Start() == nil {
					t.Fatal("failed registration stayed ready")
				}
				if mode == "factory-failure" && registrations != 0 {
					t.Fatal("failed factory registered lifecycle")
				}
				if mode == "registration-failure" && (registrations != 1 || closes != 1) {
					t.Fatal("failed registration leaked")
				}
			}
		})
	}
}

func TestBrowserStartupStateSeparation(t *testing.T) {
	if err := SeparateStateRoot("/dedicated/proof", "/node/data", "/node/keys"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/node/data", "/node/data/proof", "/node", "/node/keys/proof"} {
		if SeparateStateRoot(path, "/node/data", "/node/keys") == nil {
			t.Fatal("overlapping state accepted", path)
		}
	}
}

func TestBrowserStartupCanonicalStateMetadata(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "proof")
	data := filepath.Join(root, "node")
	instance := filepath.Join(data, "instance")
	keys := filepath.Join(root, "keys")
	for _, p := range []string{state, data, instance, keys} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := ValidateStateRoot(state, data, instance, keys, filepath.EvalSymlinks); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(state, alias); err != nil {
		t.Fatal(err)
	}
	if ValidateStateRoot(alias, data, instance, keys, filepath.EvalSymlinks) == nil {
		t.Fatal("state symlink accepted")
	}
	mock := func(path string) (string, error) {
		if path == data {
			return state, nil
		}
		return path, nil
	}
	if ValidateStateRoot(state, data, instance, keys, mock) == nil {
		t.Fatal("protected alias accepted")
	}
	if ValidateStateRoot(state, "", instance, keys, filepath.EvalSymlinks) == nil {
		t.Fatal("unknown runtime directory accepted")
	}
	if got, err := ConfiguredKeyStore(data, ""); err != nil || got != filepath.Join(data, "keystore") {
		t.Fatal("default keystore path mismatch")
	}
}
