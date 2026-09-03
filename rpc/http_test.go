// Copyright 2017 The go-ethereum Authors
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

package rpc

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type delayedHTTPTestService struct {
	entered chan struct{}
	release chan struct{}
}

func (s *delayedHTTPTestService) Wait() string {
	close(s.entered)
	<-s.release
	return "ok"
}

type immediateHTTPTestService struct{}

func (immediateHTTPTestService) Ping() string { return "ok" }

type concurrentRawTxBatchTestService struct {
	entered chan struct{}
	release chan struct{}

	mu        sync.Mutex
	active    int
	maxActive int
}

func (s *concurrentRawTxBatchTestService) SendRawTransaction(_ context.Context, raw string) string {
	return s.wait(raw)
}

func (s *concurrentRawTxBatchTestService) SendTransaction(_ context.Context, raw string) string {
	return s.wait(raw)
}

func (s *concurrentRawTxBatchTestService) wait(raw string) string {
	s.mu.Lock()
	s.active++
	if s.active > s.maxActive {
		s.maxActive = s.active
	}
	s.mu.Unlock()
	s.entered <- struct{}{}
	<-s.release
	s.mu.Lock()
	s.active--
	s.mu.Unlock()
	return raw
}

func (s *concurrentRawTxBatchTestService) maximumActive() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxActive
}

type recordingDeadlineResponseWriter struct {
	header    http.Header
	deadlines []time.Time
}

func (w *recordingDeadlineResponseWriter) Header() http.Header         { return w.header }
func (w *recordingDeadlineResponseWriter) WriteHeader(int)             {}
func (w *recordingDeadlineResponseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *recordingDeadlineResponseWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

func confirmStatusCode(t *testing.T, got, want int) {
	t.Helper()
	if got == want {
		return
	}
	if gotName := http.StatusText(got); len(gotName) > 0 {
		if wantName := http.StatusText(want); len(wantName) > 0 {
			t.Fatalf("response status code: got %d (%s), want %d (%s)", got, gotName, want, wantName)
		}
	}
	t.Fatalf("response status code: got %d, want %d", got, want)
}

func confirmRequestValidationCode(t *testing.T, method, contentType, body string, expectedStatusCode int) {
	t.Helper()
	request := httptest.NewRequest(method, "http://url.com", strings.NewReader(body))
	if len(contentType) > 0 {
		request.Header.Set("Content-Type", contentType)
	}
	code, err := validateRequest(request)
	if code == 0 {
		if err != nil {
			t.Errorf("validation: got error %v, expected nil", err)
		}
	} else if err == nil {
		t.Errorf("validation: code %d: got nil, expected error", code)
	}
	confirmStatusCode(t, code, expectedStatusCode)
}

func TestHTTPErrorResponseWithDelete(t *testing.T) {
	confirmRequestValidationCode(t, http.MethodDelete, contentType, "", http.StatusMethodNotAllowed)
}

func TestHTTPErrorResponseWithPut(t *testing.T) {
	confirmRequestValidationCode(t, http.MethodPut, contentType, "", http.StatusMethodNotAllowed)
}

func TestHTTPErrorResponseWithMaxContentLength(t *testing.T) {
	body := make([]rune, maxRequestContentLength+1)
	confirmRequestValidationCode(t,
		http.MethodPost, contentType, string(body), http.StatusRequestEntityTooLarge)
}

func TestHTTPErrorResponseWithEmptyContentType(t *testing.T) {
	confirmRequestValidationCode(t, http.MethodPost, "", "", http.StatusUnsupportedMediaType)
}

func TestHTTPErrorResponseWithValidRequest(t *testing.T) {
	confirmRequestValidationCode(t, http.MethodPost, contentType, "", 0)
}

func confirmHTTPRequestYieldsStatusCode(t *testing.T, method, contentType, body string, expectedStatusCode int) {
	t.Helper()
	s := Server{}
	ts := httptest.NewServer(&s)
	defer ts.Close()

	request, err := http.NewRequest(method, ts.URL, strings.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create a valid HTTP request: %v", err)
	}
	if len(contentType) > 0 {
		request.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	confirmStatusCode(t, resp.StatusCode, expectedStatusCode)
}

func TestHTTPResponseWithEmptyGet(t *testing.T) {
	confirmHTTPRequestYieldsStatusCode(t, http.MethodGet, "", "", http.StatusOK)
}

func TestRawTransactionBatchUsesBoundedParallelFastPath(t *testing.T) {
	const calls = 32
	service := &concurrentRawTxBatchTestService{
		entered: make(chan struct{}, calls),
		release: make(chan struct{}),
	}
	server := NewServer()
	if err := server.RegisterName("eth", service); err != nil {
		t.Fatal(err)
	}
	client := DialInProc(server)
	defer client.Close()

	results := make([]string, calls)
	batch := make([]BatchElem, calls)
	for index := range batch {
		batch[index] = BatchElem{
			Method: "eth_sendRawTransaction",
			Args:   []interface{}{"raw-" + strconv.Itoa(index+1)},
			Result: &results[index],
		}
	}
	result := make(chan error, 1)
	go func() {
		result <- client.BatchCallContext(context.Background(), batch)
	}()

	released := false
	defer func() {
		if !released {
			close(service.release)
		}
	}()
	for index := 0; index < calls; index++ {
		select {
		case <-service.entered:
		case <-time.After(time.Second):
			t.Fatalf("raw transaction batch started only %d/%d calls concurrently", index, calls)
		}
	}
	if got := service.maximumActive(); got != calls {
		t.Fatalf("maximum active raw transaction calls = %d, want %d", got, calls)
	}
	close(service.release)
	released = true

	if err := <-result; err != nil {
		t.Fatal(err)
	}
	for index := range batch {
		if batch[index].Error != nil {
			t.Fatalf("batch response %d error: %v", index, batch[index].Error)
		}
		if results[index] != "raw-"+strconv.Itoa(index+1) {
			t.Fatalf("batch response %d result %q", index, results[index])
		}
	}
}

func TestRawTransactionBatchParallelFastPathIsNodeBounded(t *testing.T) {
	const calls = rawTransactionBatchParallelism + 16
	service := &concurrentRawTxBatchTestService{
		entered: make(chan struct{}, calls),
		release: make(chan struct{}),
	}
	server := NewServer()
	if err := server.RegisterName("eth", service); err != nil {
		t.Fatal(err)
	}
	client := DialInProc(server)
	defer client.Close()

	results := make([]string, calls)
	batch := make([]BatchElem, calls)
	for index := range batch {
		batch[index] = BatchElem{Method: "eth_sendRawTransaction", Args: []interface{}{"raw"}, Result: &results[index]}
	}
	result := make(chan error, 1)
	go func() { result <- client.BatchCallContext(context.Background(), batch) }()
	released := false
	defer func() {
		if !released {
			close(service.release)
		}
	}()
	for index := 0; index < rawTransactionBatchParallelism; index++ {
		select {
		case <-service.entered:
		case <-time.After(time.Second):
			t.Fatalf("raw transaction slot %d/%d was not activated", index, rawTransactionBatchParallelism)
		}
	}
	select {
	case <-service.entered:
		t.Fatalf("raw transaction batch exceeded node limit %d", rawTransactionBatchParallelism)
	case <-time.After(50 * time.Millisecond):
	}
	if got := service.maximumActive(); got != rawTransactionBatchParallelism {
		t.Fatalf("maximum active raw transaction calls = %d, want %d", got, rawTransactionBatchParallelism)
	}
	close(service.release)
	released = true
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestRawTransactionParallelLimitIncludesSingleRequestShapes(t *testing.T) {
	const batchCalls = rawTransactionBatchParallelism - 1
	service := &concurrentRawTxBatchTestService{
		entered: make(chan struct{}, rawTransactionBatchParallelism+1),
		release: make(chan struct{}),
	}
	server := NewServer()
	if err := server.RegisterName("eth", service); err != nil {
		t.Fatal(err)
	}
	batchClient := DialInProc(server)
	singleClient := DialInProc(server)
	oneElementBatchClient := DialInProc(server)
	defer batchClient.Close()
	defer singleClient.Close()
	defer oneElementBatchClient.Close()

	batch := make([]BatchElem, batchCalls)
	for index := range batch {
		var result string
		batch[index] = BatchElem{Method: "eth_sendRawTransaction", Args: []interface{}{"batch"}, Result: &result}
	}
	batchDone := make(chan error, 1)
	go func() { batchDone <- batchClient.BatchCallContext(context.Background(), batch) }()
	for index := 0; index < batchCalls; index++ {
		select {
		case <-service.entered:
		case <-time.After(time.Second):
			t.Fatalf("raw transaction batch started only %d/%d calls", index, batchCalls)
		}
	}

	singleDone := make(chan error, 1)
	go func() {
		var result string
		singleDone <- singleClient.CallContext(context.Background(), &result, "eth_sendRawTransaction", "single")
	}()
	select {
	case <-service.entered:
	case <-time.After(time.Second):
		t.Fatal("single raw transaction did not consume the final node-global slot")
	}

	oneElementDone := make(chan error, 1)
	go func() {
		var result string
		oneElementDone <- oneElementBatchClient.BatchCallContext(context.Background(), []BatchElem{{
			Method: "eth_sendRawTransaction", Args: []interface{}{"one-element"}, Result: &result,
		}})
	}()
	select {
	case <-service.entered:
		t.Fatalf("one-element batch exceeded node-global limit %d", rawTransactionBatchParallelism)
	case <-time.After(50 * time.Millisecond):
	}
	if got := service.maximumActive(); got != rawTransactionBatchParallelism {
		t.Fatalf("maximum active raw transaction calls = %d, want %d", got, rawTransactionBatchParallelism)
	}

	close(service.release)
	if err := <-batchDone; err != nil {
		t.Fatal(err)
	}
	if err := <-singleDone; err != nil {
		t.Fatal(err)
	}
	if err := <-oneElementDone; err != nil {
		t.Fatal(err)
	}
}

func TestMixedBatchRetainsSerialExecution(t *testing.T) {
	service := &concurrentRawTxBatchTestService{
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	server := NewServer()
	if err := server.RegisterName("eth", service); err != nil {
		t.Fatal(err)
	}
	client := DialInProc(server)
	defer client.Close()

	var rawResult, transactionResult string
	batch := []BatchElem{
		{Method: "eth_sendRawTransaction", Args: []interface{}{"raw"}, Result: &rawResult},
		{Method: "eth_sendTransaction", Args: []interface{}{"managed"}, Result: &transactionResult},
	}
	result := make(chan error, 1)
	go func() { result <- client.BatchCallContext(context.Background(), batch) }()
	select {
	case <-service.entered:
	case <-time.After(time.Second):
		t.Fatal("first mixed batch call did not start")
	}
	select {
	case <-service.entered:
		t.Fatal("mixed JSON-RPC batch executed concurrently")
	case <-time.After(50 * time.Millisecond):
	}
	close(service.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if got := service.maximumActive(); got != 1 {
		t.Fatalf("maximum active mixed batch calls = %d, want 1", got)
	}
	if rawResult != "raw" || transactionResult != "managed" {
		t.Fatalf("mixed batch results = %q, %q", rawResult, transactionResult)
	}
}

func TestHTTPResponseWriteDeadlineStartsWhenRPCCompletesHTTP1(t *testing.T) {
	testHTTPResponseWriteDeadlineStartsWhenRPCCompletes(t, false)
}

func TestHTTPResponseWriteDeadlineStartsWhenRPCCompletesHTTP2(t *testing.T) {
	testHTTPResponseWriteDeadlineStartsWhenRPCCompletes(t, true)
}

func testHTTPResponseWriteDeadlineStartsWhenRPCCompletes(t *testing.T, http2 bool) {
	t.Helper()
	service := &delayedHTTPTestService{entered: make(chan struct{}), release: make(chan struct{})}
	server := NewServer()
	if err := server.RegisterName("delay", service); err != nil {
		t.Fatal(err)
	}

	const writeTimeout = 50 * time.Millisecond
	protocol := make(chan int, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case protocol <- r.ProtoMajor:
		default:
		}
		server.ServeHTTP(w, r)
	})
	httpServer := httptest.NewUnstartedServer(handler)
	httpServer.Config.WriteTimeout = writeTimeout
	httpServer.EnableHTTP2 = http2
	if http2 {
		httpServer.StartTLS()
	} else {
		httpServer.Start()
	}
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
		request.Header.Set("Content-Type", contentType)
		client := httpServer.Client()
		client.Timeout = 2 * time.Second
		resp, err := client.Do(request)
		if err != nil {
			result <- response{err: err}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		result <- response{body: body, err: err}
	}()

	select {
	case <-service.entered:
	case <-time.After(time.Second):
		t.Fatal("RPC method did not start")
	}
	wantProtocol := 1
	if http2 {
		wantProtocol = 2
	}
	select {
	case got := <-protocol:
		if got != wantProtocol {
			t.Fatalf("HTTP protocol major = %d, want %d", got, wantProtocol)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for HTTP protocol observation")
	}
	// The HTTP server's original write deadline is now expired. JSON-RPC must
	// establish a fresh bounded deadline when the completed result is encoded.
	time.Sleep(2 * writeTimeout)
	close(service.release)
	released = true

	select {
	case response := <-result:
		if response.err != nil {
			t.Fatalf("delayed RPC response failed after handler timeout: %v", response.err)
		}
		if !strings.Contains(string(response.body), `"result":"ok"`) {
			t.Fatalf("delayed RPC response body = %s", response.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for delayed RPC response")
	}
}

func TestHTTPResponseUsesConfiguredWriteTimeout(t *testing.T) {
	tests := []struct {
		name          string
		serverTimeout time.Duration
		wantTimeout   time.Duration
	}{
		{name: "shorter than codec fallback", serverTimeout: 2 * time.Second, wantTimeout: 2 * time.Second},
		{name: "longer than codec fallback", serverTimeout: 20 * time.Second, wantTimeout: 20 * time.Second},
		{name: "unbounded server uses codec fallback", wantTimeout: defaultWriteTimeout},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := NewServer()
			if err := server.RegisterName("immediate", immediateHTTPTestService{}); err != nil {
				t.Fatal(err)
			}
			writer := &recordingDeadlineResponseWriter{header: make(http.Header)}
			httpServer := &http.Server{WriteTimeout: test.serverTimeout}
			request := httptest.NewRequest(http.MethodPost, "http://example.invalid", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"immediate_ping"}`))
			request.Header.Set("Content-Type", contentType)
			request = request.WithContext(context.WithValue(request.Context(), http.ServerContextKey, httpServer))

			before := time.Now()
			server.ServeHTTP(writer, request)
			after := time.Now()

			if len(writer.deadlines) != 2 {
				t.Fatalf("write deadline calls = %d, want clear and response deadline", len(writer.deadlines))
			}
			if !writer.deadlines[0].IsZero() {
				t.Fatalf("initial write deadline = %v, want zero", writer.deadlines[0])
			}
			deadline := writer.deadlines[1]
			if deadline.Before(before.Add(test.wantTimeout)) || deadline.After(after.Add(test.wantTimeout)) {
				t.Fatalf("response write deadline = %v, want timeout %v after response start", deadline, test.wantTimeout)
			}
		})
	}
}

func TestHTTPResponsePrefersEarlierRequestDeadline(t *testing.T) {
	server := NewServer()
	if err := server.RegisterName("immediate", immediateHTTPTestService{}); err != nil {
		t.Fatal(err)
	}
	writer := &recordingDeadlineResponseWriter{header: make(http.Header)}
	httpServer := &http.Server{WriteTimeout: 20 * time.Second}
	request := httptest.NewRequest(http.MethodPost, "http://example.invalid", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"immediate_ping"}`))
	request.Header.Set("Content-Type", contentType)
	ctx := context.WithValue(request.Context(), http.ServerContextKey, httpServer)
	requestDeadline := time.Now().Add(2 * time.Second)
	ctx, cancel := context.WithDeadline(ctx, requestDeadline)
	defer cancel()
	request = request.WithContext(ctx)

	server.ServeHTTP(writer, request)

	if len(writer.deadlines) != 2 {
		t.Fatalf("write deadline calls = %d, want clear and response deadline", len(writer.deadlines))
	}
	if !writer.deadlines[0].IsZero() {
		t.Fatalf("initial write deadline = %v, want zero", writer.deadlines[0])
	}
	if !writer.deadlines[1].Equal(requestDeadline) {
		t.Fatalf("response write deadline = %v, want request deadline %v", writer.deadlines[1], requestDeadline)
	}
}
