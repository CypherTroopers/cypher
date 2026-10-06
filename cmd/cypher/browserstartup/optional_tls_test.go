// SPDX-License-Identifier: GPL-3.0-or-later
package browserstartup

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// No real TLS adapter, socket, DB, node or backend is constructed here.
type fakeTLSOwner struct {
	mu                                sync.Mutex
	ctx                               context.Context
	events                            *[]string
	starts, closes, waits             atomic.Int32
	startError, closeError, waitError error
	startGate                         <-chan struct{}
	startEntered                      chan struct{}
}

func (o *fakeTLSOwner) event(s string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.events != nil {
		*o.events = append(*o.events, s)
	}
}
func (o *fakeTLSOwner) Start(ctx context.Context) error {
	o.starts.Add(1)
	o.mu.Lock()
	o.ctx = ctx
	o.mu.Unlock()
	o.event("tls-start")
	if o.startEntered != nil {
		close(o.startEntered)
	}
	if o.startGate != nil {
		<-o.startGate
	}
	return o.startError
}
func (o *fakeTLSOwner) Close() error { o.closes.Add(1); o.event("tls-close"); return o.closeError }
func (o *fakeTLSOwner) Wait(ctx context.Context) error {
	o.waits.Add(1)
	o.event("tls-wait")
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > tlsCloseWait || ctx.Err() != nil {
		return errors.New("finite active owner Wait context required")
	}
	return o.waitError
}

type fakeSharedProof struct{ calls, closes atomic.Int32 }

func (h *fakeSharedProof) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.calls.Add(1)
	w.WriteHeader(204)
}
func (h *fakeSharedProof) Close() error { h.closes.Add(1); return nil }
func tlsHelper(t *testing.T, f TLSFactory) *TLSLifecycle {
	t.Helper()
	g, err := NewTLS(true, f)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}
func wrapTLS(t *testing.T, g *TLSLifecycle, f Factory) Factory {
	t.Helper()
	out, err := g.WrapFactory(f)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func consumeTLS(t *testing.T, g *TLSLifecycle, h http.Handler, closeSource func() error) {
	t.Helper()
	f := wrapTLS(t, g, func() (Resource, error) { return Resource{Handler: h, Close: closeSource}, nil })
	if _, err := f(); err != nil {
		t.Fatal(err)
	}
}
func tlsAwait(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(2 * time.Second):
		t.Fatal("mock lifecycle did not join")
	}
}

func TestTLSDisabledPreservesFactoryAndZeroOwnerCalls(t *testing.T) {
	var calls atomic.Int32
	g, err := NewTLS(false, func(http.Handler) (TLSOwner, error) { calls.Add(1); return nil, errors.New("must not execute") })
	if g != nil || err != nil {
		t.Fatal("disabled creation")
	}
	if g.Start() != nil || g.Close() != nil {
		t.Fatal("disabled lifecycle")
	}
	if f, err := g.WrapFactory(nil); f != nil || err != nil {
		t.Fatal("disabled nil factory changed")
	}
	proof := &fakeSharedProof{}
	closed := 0
	original := func() (Resource, error) {
		return Resource{Handler: proof, Close: func() error { closed++; return nil }}, nil
	}
	f, err := g.WrapFactory(original)
	if err != nil {
		t.Fatal(err)
	}
	r, err := f()
	if err != nil || r.Handler != proof {
		t.Fatal("disabled original factory changed")
	}
	_ = r.Close()
	if calls.Load() != 0 || closed != 1 {
		t.Fatal("disabled owner invocation")
	}
}

func TestTLSFactoryRunsOnlyAfterFinalSourceBinding(t *testing.T) {
	owner := &fakeTLSOwner{}
	proof := &fakeSharedProof{}
	calls := 0
	closed := 0
	g := tlsHelper(t, func(h http.Handler) (TLSOwner, error) {
		calls++
		if h != proof {
			t.Fatal("borrowed wrong handler")
		}
		return owner, nil
	})
	if calls != 0 || owner.starts.Load() != 0 {
		t.Fatal("prepared owner ran")
	}
	if g.Start() == nil {
		t.Fatal("unbound Start accepted")
	}
	final := func() (Resource, error) {
		return Resource{Handler: proof, Close: func() error { closed++; return nil }}, nil
	}
	f := wrapTLS(t, g, final)
	if calls != 0 {
		t.Fatal("wrap invoked constructor")
	}
	r, err := f()
	if err != nil || r.Handler != proof || calls != 1 || owner.starts.Load() != 0 {
		t.Fatal("wrong initialization")
	}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	if g.Start() == nil {
		t.Fatal("repeated Start accepted")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if closed != 1 || owner.closes.Load() != 1 || owner.waits.Load() != 1 || proof.closes.Load() != 0 {
		t.Fatal("wrong owned closure")
	}
	if owner.ctx.Err() != context.Canceled {
		t.Fatal("lifetime not canceled")
	}
}

func TestTLSCloseOrderingRetainsEveryErrorAndAlwaysReleasesSource(t *testing.T) {
	closeFailure, waitFailure, sourceFailure := errors.New("TLS close"), errors.New("TLS wait"), errors.New("source close")
	events := []string{}
	owner := &fakeTLSOwner{events: &events, closeError: closeFailure, waitError: waitFailure}
	g := tlsHelper(t, func(http.Handler) (TLSOwner, error) { return owner, nil })
	proof := &fakeSharedProof{}
	var sourceCloses atomic.Int32
	consumeTLS(t, g, proof, func() error { events = append(events, "source-close"); sourceCloses.Add(1); return sourceFailure })
	err := g.Close()
	for _, failure := range []error{closeFailure, waitFailure, sourceFailure} {
		if !errors.Is(err, failure) {
			t.Fatalf("lost %v", failure)
		}
	}
	if len(events) != 3 || events[0] != "tls-close" || events[1] != "tls-wait" || events[2] != "source-close" {
		t.Fatalf("order=%v", events)
	}
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() { defer group.Done(); _ = g.Close() }()
	}
	group.Wait()
	if sourceCloses.Load() != 1 || owner.closes.Load() != 1 || owner.waits.Load() != 1 || proof.closes.Load() != 0 {
		t.Fatal("shared closure or repeated lease cleanup")
	}
}

func TestTLSConstructorAndSourceFailuresRollbackOnlyOwnedResources(t *testing.T) {
	boom := errors.New("mock failure")
	for _, name := range []string{"source-error", "source-error-resource", "missing-handler", "typed-nil-handler", "missing-close", "owner-error", "owner-error-resource", "nil-owner", "typed-nil-owner"} {
		t.Run(name, func(t *testing.T) {
			owner := &fakeTLSOwner{}
			proof := &fakeSharedProof{}
			sourceClose := 0
			created := 0
			g := tlsHelper(t, func(http.Handler) (TLSOwner, error) {
				created++
				switch name {
				case "owner-error":
					return nil, boom
				case "owner-error-resource":
					return owner, boom
				case "nil-owner":
					return nil, nil
				case "typed-nil-owner":
					return (*fakeTLSOwner)(nil), nil
				default:
					return owner, nil
				}
			})
			f := wrapTLS(t, g, func() (Resource, error) {
				r := Resource{Handler: proof, Close: func() error { sourceClose++; return nil }}
				switch name {
				case "source-error":
					return Resource{}, boom
				case "source-error-resource":
					return r, boom
				case "missing-handler":
					r.Handler = nil
				case "typed-nil-handler":
					r.Handler = (*fakeSharedProof)(nil)
				case "missing-close":
					r.Close = nil
				}
				return r, nil
			})
			if r, err := f(); err == nil || r.Handler != nil || r.Close != nil {
				t.Fatal("malformed resource published")
			}
			if g.Start() == nil {
				t.Fatal("failed resource restarted")
			}
			expectedSource := 1
			if name == "source-error" || name == "missing-close" {
				expectedSource = 0
			}
			expectedOwner := int32(0)
			if name == "owner-error-resource" {
				expectedOwner = 1
			}
			if sourceClose != expectedSource || owner.closes.Load() != expectedOwner || owner.starts.Load() != 0 || proof.closes.Load() != 0 {
				t.Fatal("wrong rollback")
			}
			if name[:6] == "source" && created != 0 {
				t.Fatal("owner constructed after source failure")
			}
		})
	}
}

func TestTLSBindFailureWithdrawsControllerWithoutStoppingSharedNode(t *testing.T) {
	boom := errors.New("mock TCP occupied")
	owner := &fakeTLSOwner{startError: boom}
	proof := &fakeSharedProof{}
	sourceCloses := 0
	g := tlsHelper(t, func(http.Handler) (TLSOwner, error) { return owner, nil })
	controller, err := New(options())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	f := wrapTLS(t, g, func() (Resource, error) {
		return Resource{Handler: proof, Close: func() error { sourceCloses++; return nil }}, nil
	})
	if err := controller.Initialize(role(), f); err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(); err != nil {
		t.Fatal(err)
	}
	if err := g.Start(); !errors.Is(err, boom) {
		t.Fatal("bind failure lost")
	}
	_ = controller.Close()
	rec := httptest.NewRecorder()
	controller.ServeHTTP(rec, httptest.NewRequest("GET", "/api/node/v1/status", nil))
	if rec.Code != 503 || proof.calls.Load() != 0 || sourceCloses != 1 || owner.closes.Load() != 1 || proof.closes.Load() != 0 {
		t.Fatal("publication or owned cleanup after bind failure")
	}
}

func TestTLSCloseDuringLateFactoryAndOwnerConstruction(t *testing.T) {
	for _, stage := range []string{"source", "owner"} {
		t.Run(stage, func(t *testing.T) {
			owner := &fakeTLSOwner{}
			proof := &fakeSharedProof{}
			var sourceCloses atomic.Int32
			entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			open := func() { once.Do(func() { close(release) }) }
			g := tlsHelper(t, func(http.Handler) (TLSOwner, error) {
				if stage == "owner" {
					close(entered)
					<-release
				}
				return owner, nil
			})
			f := wrapTLS(t, g, func() (Resource, error) {
				if stage == "source" {
					close(entered)
					<-release
				}
				return Resource{Handler: proof, Close: func() error { sourceCloses.Add(1); return nil }}, nil
			})
			result := make(chan error, 1)
			go func() { defer close(returned); _, err := f(); result <- err }()
			t.Cleanup(func() { _ = g.Close(); open(); tlsAwait(t, returned) })
			tlsAwait(t, entered)
			_ = g.Close()
			open()
			tlsAwait(t, returned)
			if err := <-result; err == nil {
				t.Fatal("closed factory published")
			}
			if sourceCloses.Load() != 1 || owner.closes.Load() != 1 || owner.starts.Load() != 0 || proof.closes.Load() != 0 {
				t.Fatal("late resources not released")
			}
		})
	}
}

func TestTLSCloseDuringStartCancelsAndJoinsOwnedLease(t *testing.T) {
	entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }
	owner := &fakeTLSOwner{startEntered: entered, startGate: release}
	proof := &fakeSharedProof{}
	var sourceCloses atomic.Int32
	g := tlsHelper(t, func(http.Handler) (TLSOwner, error) { return owner, nil })
	consumeTLS(t, g, proof, func() error { sourceCloses.Add(1); return nil })
	result := make(chan error, 1)
	go func() { defer close(returned); result <- g.Start() }()
	t.Cleanup(func() { _ = g.Close(); open(); tlsAwait(t, returned) })
	tlsAwait(t, entered)
	_ = g.Close()
	open()
	tlsAwait(t, returned)
	if err := <-result; err == nil {
		t.Fatal("closed Start succeeded")
	}
	if sourceCloses.Load() != 1 || owner.closes.Load() != 1 || owner.waits.Load() != 1 || owner.ctx.Err() != context.Canceled {
		t.Fatal("wrong canceled Start")
	}
}

func TestTLSInvalidOptionsAndRoleHaveZeroFactoryCalls(t *testing.T) {
	if _, err := NewTLS(true, nil); err == nil {
		t.Fatal("nil TLS factory accepted")
	}
	g := tlsHelper(t, func(http.Handler) (TLSOwner, error) { t.Fatal("unreachable owner"); return nil, nil })
	if _, err := g.WrapFactory(nil); err == nil {
		t.Fatal("nil source factory accepted")
	}
	c, err := New(options())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	calls := 0
	f := wrapTLS(t, g, func() (Resource, error) { calls++; return Resource{}, nil })
	if err := c.Initialize(Role{HTTP3: true, Ingress: true, Bridge: true, FairHotstuff: true}, f); err == nil || calls != 0 {
		t.Fatal("invalid native role constructed source")
	}
	o := options()
	o.Enabled = false
	o.ConfigPath = ""
	o.StateRoot = ""
	o.Role = ""
	o.TLS = true
	if err := o.Validate(); err == nil {
		t.Fatal("TLS flag without gateway accepted")
	}
}
