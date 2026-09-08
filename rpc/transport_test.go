package rpc

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type transportTestService struct{}

func (*transportTestService) Identity(ctx context.Context) [2]bool {
	return [2]bool{IsIPC(ctx), IsLocal(ctx)}
}

func TestTransportIdentity(t *testing.T) {
	if IsIPC(context.Background()) || IsLocal(context.Background()) {
		t.Fatal("unclassified context was trusted")
	}
	srv := NewServer()
	defer srv.Stop()
	if err := srv.RegisterName("test", new(transportTestService)); err != nil {
		t.Fatal(err)
	}
	check := func(client *Client, want [2]bool) {
		t.Helper()
		defer client.Close()
		var got [2]bool
		if err := client.Call(&got, "test_identity"); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("transport identity = %v, want %v", got, want)
		}
	}
	t.Run("inproc", func(t *testing.T) { check(DialInProc(srv), [2]bool{false, true}) })
	t.Run("http_forged_headers", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Even a context inherited from another server must be reset by HTTP.
			r = r.WithContext(context.WithValue(r.Context(), transportContextKey{}, transportIPC))
			srv.ServeHTTP(w, r)
		}))
		defer server.Close()
		client, err := DialHTTP(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		client.SetHeader("Origin", "ipc://local")
		client.SetHeader("X-Forwarded-For", "127.0.0.1")
		check(client, [2]bool{})
	})
	t.Run("websocket", func(t *testing.T) {
		server := httptest.NewServer(srv.WebsocketHandler([]string{"*"}))
		defer server.Close()
		client, err := DialWebsocket(context.Background(), "ws"+server.URL[4:], "ipc://local")
		if err != nil {
			t.Fatal(err)
		}
		check(client, [2]bool{})
	})
	t.Run("tcp_listener_is_not_ipc", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go srv.ServeListener(listener)
		client, err := newClient(context.Background(), func(ctx context.Context) (ServerCodec, error) {
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				return nil, err
			}
			return NewCodec(conn), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		check(client, [2]bool{})
	})
	t.Run("ipc", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "ipc-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		endpoint := filepath.Join(dir, "rpc.ipc")
		if runtime.GOOS == "windows" {
			endpoint = `\\.\pipe\` + filepath.Base(dir)
		}
		listener, err := ipcListen(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go srv.ServeListener(listener)
		client, err := DialIPC(context.Background(), endpoint)
		if err != nil {
			t.Fatal(err)
		}
		check(client, [2]bool{true, true})
	})
}
