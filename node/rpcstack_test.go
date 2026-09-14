// Copyright 2020 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package node

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/internal/testlog"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/rpc"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
)

type deadlineResponseWriter struct {
	header   http.Header
	deadline time.Time
}

func (w *deadlineResponseWriter) Header() http.Header         { return w.header }
func (w *deadlineResponseWriter) WriteHeader(int)             {}
func (w *deadlineResponseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *deadlineResponseWriter) SetWriteDeadline(t time.Time) error {
	w.deadline = t
	return nil
}

func TestGzipResponseWriterExposesWriteDeadline(t *testing.T) {
	underlying := &deadlineResponseWriter{header: make(http.Header)}
	wrapped := &gzipResponseWriter{Writer: io.Discard, ResponseWriter: underlying}
	want := time.Now().Add(time.Second)

	if err := http.NewResponseController(wrapped).SetWriteDeadline(want); err != nil {
		t.Fatal(err)
	}
	if !underlying.deadline.Equal(want) {
		t.Fatalf("underlying deadline = %v, want %v", underlying.deadline, want)
	}
}

type delayedGzipRPCService struct {
	entered chan struct{}
	release chan struct{}
}

func (s *delayedGzipRPCService) Wait() string {
	close(s.entered)
	<-s.release
	return "ok"
}

func TestGzipRPCResponseRefreshesExpiredServerWriteDeadline(t *testing.T) {
	service := &delayedGzipRPCService{entered: make(chan struct{}), release: make(chan struct{})}
	rpcServer := rpc.NewServer()
	if err := rpcServer.RegisterName("delay", service); err != nil {
		t.Fatal(err)
	}

	const writeTimeout = 50 * time.Millisecond
	httpServer := httptest.NewUnstartedServer(NewHTTPHandlerStack(rpcServer, nil, []string{"*"}))
	httpServer.Config.WriteTimeout = writeTimeout
	httpServer.Start()
	defer httpServer.Close()
	released := false
	defer func() {
		if !released {
			close(service.release)
		}
	}()

	type response struct {
		body []byte
		err  error
	}
	result := make(chan response, 1)
	go func() {
		request, err := http.NewRequest(http.MethodPost, httpServer.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"delay_wait"}`))
		if err != nil {
			result <- response{err: err}
			return
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept-Encoding", "gzip")
		client := httpServer.Client()
		client.Timeout = 2 * time.Second
		resp, err := client.Do(request)
		if err != nil {
			result <- response{err: err}
			return
		}
		defer resp.Body.Close()
		if encoding := resp.Header.Get("Content-Encoding"); encoding != "gzip" {
			result <- response{err: fmt.Errorf("content encoding = %q, want gzip", encoding)}
			return
		}
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			result <- response{err: err}
			return
		}
		defer reader.Close()
		body, err := io.ReadAll(reader)
		result <- response{body: body, err: err}
	}()

	select {
	case <-service.entered:
	case <-time.After(time.Second):
		t.Fatal("RPC method did not start")
	}
	time.Sleep(2 * writeTimeout)
	close(service.release)
	released = true

	select {
	case response := <-result:
		if response.err != nil {
			t.Fatalf("delayed gzip RPC response failed after handler timeout: %v", response.err)
		}
		if !strings.Contains(string(response.body), `"result":"ok"`) {
			t.Fatalf("delayed gzip RPC response body = %s", response.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for delayed gzip RPC response")
	}
}

// TestCorsHandler makes sure CORS are properly handled on the http server.
func TestCorsHandler(t *testing.T) {
	srv := createAndStartServer(t, httpConfig{CorsAllowedOrigins: []string{"test", "test.com"}}, false, wsConfig{})
	defer srv.stop()

	resp := testRequest(t, "origin", "test.com", "", srv)
	assert.Equal(t, "test.com", resp.Header.Get("Access-Control-Allow-Origin"))

	resp2 := testRequest(t, "origin", "bad", "", srv)
	assert.Equal(t, "", resp2.Header.Get("Access-Control-Allow-Origin"))
}

// TestVhosts makes sure vhosts are properly handled on the http server.
func TestVhosts(t *testing.T) {
	srv := createAndStartServer(t, httpConfig{Vhosts: []string{"test"}}, false, wsConfig{})
	defer srv.stop()

	resp := testRequest(t, "", "", "test", srv)
	assert.Equal(t, resp.StatusCode, http.StatusOK)

	resp2 := testRequest(t, "", "", "bad", srv)
	assert.Equal(t, resp2.StatusCode, http.StatusForbidden)
}

// TestWebsocketOrigins makes sure the websocket origins are properly handled on the websocket server.
func TestWebsocketOrigins(t *testing.T) {
	srv := createAndStartServer(t, httpConfig{}, true, wsConfig{Origins: []string{"test"}})
	defer srv.stop()

	dialer := websocket.DefaultDialer
	_, _, err := dialer.Dial("ws://"+srv.listenAddr(), http.Header{
		"Content-type":          []string{"application/json"},
		"Sec-WebSocket-Version": []string{"13"},
		"Origin":                []string{"test"},
	})
	assert.NoError(t, err)

	_, _, err = dialer.Dial("ws://"+srv.listenAddr(), http.Header{
		"Content-type":          []string{"application/json"},
		"Sec-WebSocket-Version": []string{"13"},
		"Origin":                []string{"bad"},
	})
	assert.Error(t, err)
}

func TestHTTPServerListenAddrSupportsIPv6(t *testing.T) {
	srv := newHTTPServer(testlog.Logger(t, log.LvlDebug), rpc.DefaultHTTPTimeouts)
	assert.NoError(t, srv.setListenAddr("::1", 8545))
	assert.Equal(t, "[::1]:8545", srv.listenAddr())
	assert.NoError(t, srv.setListenAddr("[::1]", 8546))
	assert.Equal(t, "[::1]:8546", srv.listenAddr())
}

func createAndStartServer(t *testing.T, conf httpConfig, ws bool, wsConf wsConfig) *httpServer {
	t.Helper()

	srv := newHTTPServer(testlog.Logger(t, log.LvlDebug), rpc.DefaultHTTPTimeouts)

	assert.NoError(t, srv.enableRPC(nil, conf))
	if ws {
		assert.NoError(t, srv.enableWS(nil, wsConf))
	}
	assert.NoError(t, srv.setListenAddr("localhost", 0))
	assert.NoError(t, srv.start())

	return srv
}

func testRequest(t *testing.T, key, value, host string, srv *httpServer) *http.Response {
	t.Helper()

	body := bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,method":"rpc_modules"}`))
	req, _ := http.NewRequest("POST", "http://"+srv.listenAddr(), body)
	req.Header.Set("content-type", "application/json")
	if key != "" && value != "" {
		req.Header.Set(key, value)
	}
	if host != "" {
		req.Host = host
	}

	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
