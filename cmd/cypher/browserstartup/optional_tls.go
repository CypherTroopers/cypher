// SPDX-License-Identifier: GPL-3.0-or-later
package browserstartup

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"time"
)

// TLSOwner is an exclusively owned frontdoor, never a shared native UDP/node
// service. Constructor and source factory must not synchronously reenter Close.
type TLSOwner interface {
	Start(context.Context) error
	Close() error
	Wait(context.Context) error
}
type TLSFactory func(http.Handler) (TLSOwner, error)

const tlsCloseWait = 5 * time.Second

// TLSLifecycle attaches an optional owned TCP frontdoor without changing the
// Resource ABI. New and WrapFactory are pure; the final source factory runs in
// Initialize, and TCP/TLS execution remains deferred until explicit Start.
type TLSLifecycle struct {
	mu                                   sync.Mutex
	newOwner                             TLSFactory
	ctx                                  context.Context
	cancel                               context.CancelFunc
	preparing, starting, started, closed bool
	lease                                *tlsLease
	lateCloseError                       error
}

func NewTLS(enabled bool, factory TLSFactory) (*TLSLifecycle, error) {
	if !enabled {
		return nil, nil
	}
	if factory == nil {
		return nil, errors.New("explicit TLS owner factory required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &TLSLifecycle{newOwner: factory, ctx: ctx, cancel: cancel}, nil
}

// WrapFactory must wrap the final factory after a synced backend has been
// bound. It preserves the original source Handler and transfers only its Close.
func (t *TLSLifecycle) WrapFactory(factory Factory) (Factory, error) {
	if t == nil {
		return factory, nil
	}
	if t.newOwner == nil {
		return nil, errors.New("prepared TLS lifecycle required")
	}
	if factory == nil {
		return nil, errors.New("final owned source factory required")
	}
	return func() (Resource, error) { return t.initialize(factory) }, nil
}

func (t *TLSLifecycle) initialize(factory Factory) (Resource, error) {
	t.mu.Lock()
	if t.closed || t.preparing || t.lease != nil {
		t.mu.Unlock()
		return Resource{}, errors.New("TLS source initialization unavailable")
	}
	t.preparing = true
	t.mu.Unlock()
	resource, err := factory()
	lease := &tlsLease{sourceClose: resource.Close}
	if err != nil || absent(resource.Handler) || resource.Close == nil {
		if err == nil {
			err = errors.New("complete owned source resource required for TLS")
		}
		return Resource{}, t.reject(err, lease)
	}
	owner, err := t.newOwner(resource.Handler)
	// Constructor results are exclusively owned even when returned with error.
	if !absentTLSOwner(owner) {
		lease.owner = owner
	}
	if err != nil || lease.owner == nil {
		if err == nil {
			err = errors.New("complete owned TLS frontdoor required")
		}
		return Resource{}, t.reject(err, lease)
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return Resource{}, t.reject(errors.New("TLS closed during source preparation"), lease)
	}
	t.lease = lease
	t.preparing = false
	t.mu.Unlock()
	return Resource{Handler: resource.Handler, Close: t.Close}, nil
}

func (t *TLSLifecycle) reject(err error, lease *tlsLease) error {
	_ = t.Close()
	closed := lease.close()
	t.mu.Lock()
	t.preparing = false
	t.lateCloseError = errors.Join(t.lateCloseError, closed)
	t.mu.Unlock()
	return errors.Join(err, closed)
}

// Start is called only after Controller.Start accepts the published resource.
// Any bind/TLS/Serve-commit failure cancels and releases the owned source. The
// CLI must then close its Controller to withdraw the native proof publication.
func (t *TLSLifecycle) Start() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	if t.closed || t.preparing || t.lease == nil || t.starting || t.started {
		t.mu.Unlock()
		return errors.New("TLS lifecycle is not ready for single-use Start")
	}
	t.starting = true
	lease, ctx := t.lease, t.ctx
	t.mu.Unlock()
	err := lease.owner.Start(ctx)
	t.mu.Lock()
	t.starting = false
	closed := t.closed
	if err == nil && !closed {
		t.started = true
	}
	t.mu.Unlock()
	if err != nil {
		return errors.Join(err, t.Close())
	}
	if closed {
		return errors.Join(errors.New("TLS closed during Start"), t.Close())
	}
	return nil
}

// Close hides no shared resource and stops no node: publication withdrawal is
// the existing Controller's job. Late source/owner results are locally closed
// by initialize before it returns; no abandoned constructor task is spawned.
func (t *TLSLifecycle) Close() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	t.closed = true
	lease, late := t.lease, t.lateCloseError
	cancel := t.cancel
	t.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if lease == nil {
		return late
	}
	return errors.Join(late, lease.close())
}

type tlsLease struct {
	owner       TLSOwner
	sourceClose func() error
	once        sync.Once
	err         error
}

func (l *tlsLease) close() error {
	l.once.Do(func() {
		var ownerClose, ownerWait, sourceClose error
		if l.owner != nil {
			ownerClose = l.owner.Close()
			ctx, cancel := context.WithTimeout(context.Background(), tlsCloseWait)
			ownerWait = l.owner.Wait(ctx)
			cancel()
		}
		// Source lease release is mandatory even when TCP Close/Wait fails.
		if l.sourceClose != nil {
			sourceClose = l.sourceClose()
		}
		l.err = errors.Join(ownerClose, ownerWait, sourceClose)
	})
	return l.err
}

func absentTLSOwner(owner TLSOwner) bool {
	if owner == nil {
		return true
	}
	v := reflect.ValueOf(owner)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
