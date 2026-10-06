// SPDX-License-Identifier: LGPL-3.0-or-later
package node

import (
	"fmt"
	"net/http"
	"reflect"
)

// HTTP3HandlerComposer is an application-owned, pure startup hook. It must not
// start listeners, read TLS keys, invoke RPC or acquire node/source resources.
type HTTP3HandlerComposer func(existing http.Handler, shared func(http.Handler) http.Handler) (http.Handler, error)

// ComposeHTTP3Handler validates an opt-in mount before Ethereum opens a DB.
// Errors, nil results and panics fail startup before Ethereum owns resources.
func ComposeHTTP3Handler(existing http.Handler, shared func(http.Handler) http.Handler, compose HTTP3HandlerComposer) (handler http.Handler, err error) {
	if nilHTTPHandler(existing) || shared == nil {
		return nil, fmt.Errorf("HTTP3 restricted RPC and shared stack required")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			handler = nil
			err = fmt.Errorf("HTTP3 composer panicked")
		}
	}()
	if compose == nil {
		handler = shared(existing)
	} else {
		handler, err = compose(existing, shared)
	}
	if err != nil {
		return nil, err
	}
	if nilHTTPHandler(handler) {
		return nil, fmt.Errorf("HTTP3 composer returned nil handler")
	}
	return handler, nil
}

func nilHTTPHandler(h http.Handler) bool {
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
