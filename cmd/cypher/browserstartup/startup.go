// SPDX-License-Identifier: GPL-3.0-or-later
// Package browserstartup owns only the optional application boundary. It does
// not construct a node, gateway, listener, database or RPC client.
package browserstartup

import (
	"errors"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
)

type Options struct {
	Enabled                                  bool
	TLS                                      bool
	ConfigPath, StateRoot, Role, CommandName string
	UnlockRequested, MiningRequested         bool
}

func (o Options) Validate() error {
	if !o.Enabled {
		if o.TLS || o.ConfigPath != "" || o.StateRoot != "" || o.Role != "" {
			return errors.New("browser gateway options require explicit enable")
		}
		return nil
	}
	if o.Role != "common-rpc" {
		return errors.New("browser gateway requires explicit common-rpc role")
	}
	if o.CommandName != "" || o.UnlockRequested || o.MiningRequested {
		return errors.New("browser gateway is limited to the normal non-mining command without account unlock")
	}
	for _, path := range []string{o.ConfigPath, o.StateRoot} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || strings.ContainsRune(path, 0) {
			return errors.New("explicit clean absolute public config and dedicated state paths required")
		}
	}
	return nil
}

// Role is copied from the final existing TxQUIC configuration after eth.New's
// unchanged auto-role selection. An operator label never overrides these facts.
type Role struct{ HTTP3, Ingress, Bridge, FairHotstuff bool }

func (r Role) Validate() error {
	if !r.HTTP3 || r.Ingress || !r.Bridge || !r.FairHotstuff {
		return errors.New("browser gateway requires the final existing Common RPC HTTP/3 bridge role")
	}
	return nil
}

// SeparateStateRoot compares configured names only. The gateway separately
// validates its own precreated nonsymlink directory; node data is never opened.
func SeparateStateRoot(stateRoot, nodeData, keyStore string) error {
	if nodeData == "" {
		return errors.New("explicit native data directory required for state separation")
	}
	for _, protected := range []string{nodeData, keyStore} {
		if protected == "" {
			continue
		}
		absolute, err := filepath.Abs(protected)
		if err != nil {
			return err
		}
		for _, pair := range [][2]string{{absolute, stateRoot}, {stateRoot, absolute}} {
			rel, err := filepath.Rel(pair[0], pair[1])
			if err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
				return errors.New("proof state must be separate from configured node data and keystore directories")
			}
		}
	}
	return nil
}

func ConfiguredKeyStore(nodeData, keyStore string) (string, error) {
	if keyStore != "" {
		return filepath.Abs(keyStore)
	}
	if nodeData == "" {
		return "", errors.New("ephemeral keystore is unsupported by the optional gateway")
	}
	return filepath.Join(nodeData, "keystore"), nil
}

// ValidateStateRoot receives a metadata-only resolver so tests can use isolated
// directories or a mock. It opens no directory contents, DB, WAL or key file.
func ValidateStateRoot(stateRoot, nodeData, instanceDir, keyStore string, resolve func(string) (string, error)) error {
	if nodeData == "" || instanceDir == "" || resolve == nil {
		return errors.New("configured persistent node directories and metadata resolver required")
	}
	if err := SeparateStateRoot(stateRoot, nodeData, keyStore); err != nil {
		return err
	}
	if err := SeparateStateRoot(stateRoot, instanceDir, ""); err != nil {
		return err
	}
	state, err := resolve(stateRoot)
	if err != nil || state != stateRoot {
		return errors.New("proof state must be an existing canonical nonsymlink directory")
	}
	for _, path := range []string{nodeData, instanceDir, keyStore} {
		if path == "" {
			continue
		}
		resolved, err := resolve(path)
		if err != nil {
			return errors.New("protected directory metadata could not be resolved")
		}
		if err := SeparateStateRoot(state, resolved, ""); err != nil {
			return err
		}
	}
	return nil
}

type Resource struct {
	Handler http.Handler
	Close   func() error
}
type Factory func() (Resource, error)

// Controller is prepared before node.New, but gains an owned resource only
// during explicit Initialize. It denies requests until that succeeds.
type Controller struct {
	mu                          sync.Mutex
	handler                     http.Handler
	closeResource               func() error
	initializing, ready, closed bool
	closeDone                   chan struct{}
	closeError                  error
}

func New(o Options) (*Controller, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	if !o.Enabled {
		return nil, nil
	}
	return &Controller{}, nil
}

func absent(h http.Handler) bool {
	if h == nil {
		return true
	}
	v := reflect.ValueOf(h)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func (c *Controller) Initialize(role Role, factory Factory) error {
	if c == nil {
		return errors.New("browser gateway controller required")
	}
	if err := role.Validate(); err != nil {
		_ = c.Close()
		return err
	}
	if factory == nil {
		_ = c.Close()
		return errors.New("browser gateway factory required")
	}
	c.mu.Lock()
	if c.closed || c.ready || c.initializing {
		c.mu.Unlock()
		return errors.New("browser gateway initialization unavailable")
	}
	c.initializing = true
	c.mu.Unlock()
	resource, err := factory()
	if err != nil || absent(resource.Handler) || resource.Close == nil {
		if resource.Close != nil {
			_ = resource.Close()
		}
		_ = c.Close()
		if err != nil {
			return err
		}
		return errors.New("browser gateway factory returned an incomplete owned handler")
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = resource.Close()
		return errors.New("browser gateway closed during initialization")
	}
	c.handler, c.closeResource = resource.Handler, resource.Close
	c.initializing, c.ready = false, true
	c.mu.Unlock()
	return nil
}

func (c *Controller) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if c == nil {
		http.Error(w, "browser gateway unavailable", http.StatusServiceUnavailable)
		return
	}
	c.mu.Lock()
	handler, ready := c.handler, c.ready && !c.closed
	c.mu.Unlock()
	if !ready {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "browser gateway unavailable", http.StatusServiceUnavailable)
		return
	}
	handler.ServeHTTP(w, r)
}

// InitializeAndRegister publishes a lifecycle only after the owned resource is
// ready. The caller registers this last so its Stop runs before older services.
func (c *Controller) InitializeAndRegister(role Role, factory Factory, register func() error) error {
	if register == nil {
		return CloseOnError(errors.New("browser lifecycle registration required"), c.Close)
	}
	if err := c.Initialize(role, factory); err != nil {
		return err
	}
	return CloseOnError(register(), c.Close)
}

func (c *Controller) Start() error {
	if c == nil {
		return errors.New("browser gateway controller required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.ready || c.closed {
		return errors.New("browser gateway is not initialized")
	}
	return nil
}
func (c *Controller) Stop() error { return c.Close() }

// Close is required even if the node has not started: Node.Close does not stop
// unstarted lifecycles. Closing also hides the handler before canceling work.
func (c *Controller) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		done := c.closeDone
		c.mu.Unlock()
		<-done
		c.mu.Lock()
		err := c.closeError
		c.mu.Unlock()
		return err
	}
	c.closed, c.ready = true, false
	c.handler = nil
	c.closeDone = make(chan struct{})
	closeResource := c.closeResource
	c.closeResource = nil
	c.mu.Unlock()
	var err error
	if closeResource != nil {
		err = closeResource()
	}
	c.mu.Lock()
	c.closeError = err
	close(c.closeDone)
	c.mu.Unlock()
	return err
}

// CloseOnError is invoked before a caller's fatal exit, never through a defer.
// The controller must be closed before a transport-owning stack is closed.
func CloseOnError(err error, cleanup ...func() error) error {
	if err == nil {
		return nil
	}
	for _, closeResource := range cleanup {
		if closeResource != nil {
			_ = closeResource()
		}
	}
	return err
}
