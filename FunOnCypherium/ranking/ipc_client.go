package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync/atomic"
	"time"
)

type rpcCaller interface {
	CallContext(ctx context.Context, result interface{}, method string, args ...interface{}) error
	Close() error
}

type ipcRPCClient struct {
	path      string
	timeout   time.Duration
	requestID uint64
}

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      uint64        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func newIPCRPCClient(path string) (*ipcRPCClient, error) {
	if path == "" {
		return nil, errors.New("ipc path is empty")
	}
	client := &ipcRPCClient{
		path:    path,
		timeout: 30 * time.Second,
	}
	return client, nil
}

func (c *ipcRPCClient) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{}
	if runtime.GOOS == "windows" {
		return nil, errors.New("ipc transport is not supported on windows")
	}
	conn, err := d.DialContext(ctx, "unix", c.path)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *ipcRPCClient) CallContext(ctx context.Context, result interface{}, method string, args ...interface{}) error {
	if ctx == nil {
		ctx = context.Background()
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	timeout := c.timeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		timeout = remaining
	}
	if timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
	}

	id := atomic.AddUint64(&c.requestID, 1)
	req := rpcRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  args,
	}
	if err := json.NewEncoder(conn).Encode(&req); err != nil {
		return err
	}

	var resp rpcResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return err
	}
	if resp.Error != nil {
		return fmt.Errorf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	if result == nil || len(resp.Result) == 0 {
		return nil
	}
	return json.Unmarshal(resp.Result, result)
}

func (c *ipcRPCClient) Close() error {
	return nil
}
