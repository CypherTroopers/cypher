//go:build windows

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/gorilla/websocket"
	"golang.org/x/sys/windows"
)

func publicRelayWindowsTestPipe(t *testing.T) string {
	t.Helper()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	return publicRelayPipePrefix + "cypher-test-" + hex.EncodeToString(id[:])
}

func publicRelayWindowsTestUser(t *testing.T) *windows.SID {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid
}

func TestPublicRelayWindowsPaths(t *testing.T) {
	for _, path := range []string{`\\host\pipe\relay`, `\\?\pipe\relay`, `\\.\PIPE\relay`, `\\.\pipe\`, `\\.\pipe\a\b`, `\\.\pipe\..`, `\\.\pipe\a b`, `\\.\pipe\a:b`, publicRelayPipePrefix + strings.Repeat("a", 129)} {
		if err := validatePublicRelaySocketPath(path); err == nil {
			t.Errorf("accepted invalid pipe path %q", path)
		}
	}
	for _, path := range []string{`\\.\pipe\relay`, `\\.\pipe\Cypher_123-abc`} {
		if err := validatePublicRelaySocketPath(path); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{`relative.json`, `C:relative.json`, `\\host\share\config.json`, `\\?\C:\config.json`, `C:\a\..\config.json`, `C:\a.\config.json`, `C:\config.json:stream`, `C:\NUL`, `C:/config.json`} {
		if err := validatePublicRelayFilePath(path); err == nil {
			t.Errorf("accepted invalid file path %q", path)
		}
	}
	a, err := resolvePublicRelaySocketPath(`C:\Users\alice\cypher\common.json`, "auto")
	if err != nil {
		t.Fatal(err)
	}
	b, err := resolvePublicRelaySocketPath(`c:\users\ALICE\cypher\common.json`, "auto")
	if err != nil || a != b {
		t.Fatal("automatic pipe name is not stable under path case changes", err)
	}
	c, err := resolvePublicRelaySocketPath(`C:\Users\alice\other\common.json`, "auto")
	if err != nil || a == c {
		t.Fatal("different config paths did not isolate pipe names", err)
	}
	if err := validatePublicRelaySocketPath(a); err != nil {
		t.Fatal(err)
	}
}

func TestPublicRelayWindowsACLPolicy(t *testing.T) {
	user := publicRelayWindowsTestUser(t)
	base := "O:" + user.String() + "D:P(A;;FA;;;" + user.String() + ")"
	for _, tc := range []struct {
		name, extra               string
		ancestor, secret, wantErr bool
	}{
		{name: "owner config"},
		{name: "owner key", secret: true},
		{name: "users read config", extra: "(A;;FR;;;BU)"},
		{name: "users read key", extra: "(A;;FR;;;BU)", secret: true, wantErr: true},
		{name: "users write config", extra: "(A;;FW;;;BU)", wantErr: true},
		{name: "admins and system key", extra: "(A;;FA;;;BA)(A;;FA;;;SY)", secret: true},
		{name: "inherit-only users write", extra: "(A;OICIIO;FA;;;BU)", ancestor: true},
		{name: "ancestor create siblings", extra: "(A;;0x6;;;AU)", ancestor: true},
		{name: "ancestor delete children", extra: "(A;;0x40;;;AU)", ancestor: true, wantErr: true},
		{name: "ancestor write ACL", extra: "(A;;WD;;;BU)", ancestor: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(base + tc.extra)
			if err != nil {
				t.Fatal(err)
			}
			err = validatePublicRelaySecurity(sd, user, tc.ancestor, tc.secret)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ACL accepted=%v, want error=%v: %v", err == nil, tc.wantErr, err)
			}
		})
	}
	for _, sddl := range []string{"O:WD" + "D:P(A;;FA;;;WD)", "O:" + user.String() + "D:NO_ACCESS_CONTROL"} {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		if err := validatePublicRelaySecurity(sd, user, false, false); err == nil {
			t.Fatal("accepted untrusted owner or null DACL")
		}
	}
}

func publicRelayWindowsSetACL(t *testing.T, path, extra string) {
	t.Helper()
	user := publicRelayWindowsTestUser(t)
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.String() + ")" + extra)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, user, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func publicRelayWindowsPrivateDir(t *testing.T) string {
	t.Helper()
	// Some CI machines put TEMP beneath a directory writable by all users.
	// Exercise successful reads under the same protected profile requirement as
	// production, without changing permissions on a shared ancestor.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(home, ".cypher-relay-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	publicRelayWindowsSetACL(t, dir, "")
	return dir
}

func TestPublicRelayWindowsBoundedFiles(t *testing.T) {
	dir := publicRelayWindowsPrivateDir(t)
	path := filepath.Join(dir, "relay.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	publicRelayWindowsSetACL(t, path, "(A;;FR;;;BU)")
	if raw, err := readPublicRelayFile(path, false); err != nil || string(raw) != "{}" {
		t.Fatal("owner-controlled config with public read failed", err)
	}
	if _, err := readPublicRelayFile(path, true); err == nil {
		t.Fatal("accepted publicly readable signing key")
	}
	publicRelayWindowsSetACL(t, path, "")
	if _, err := readPublicRelayFile(path, true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, 4097), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPublicRelayFile(path, false); err == nil {
		t.Fatal("accepted oversized file")
	}
	if _, err := readPublicRelayFile(dir, false); err == nil {
		t.Fatal("accepted directory")
	}
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	publicRelayWindowsSetACL(t, path, "(A;;FW;;;BU)")
	if _, err := readPublicRelayFile(path, false); err == nil {
		t.Fatal("accepted untrusted writable config")
	}
	publicRelayWindowsSetACL(t, path, "")
	publicRelayWindowsSetACL(t, dir, "(A;;0x40;;;BU)")
	if _, err := readPublicRelayFile(path, false); err == nil {
		t.Fatal("accepted replaceable ancestor")
	}
}

func TestPublicRelayWindowsRejectReparse(t *testing.T) {
	dir := publicRelayWindowsPrivateDir(t)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	publicRelayWindowsSetACL(t, path, "")
	if _, err := readPublicRelayFile(path, false); err != nil {
		t.Fatal("safe target must be readable before testing reparse rejection", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("Windows symlink privilege/developer mode unavailable: %v", err)
	}
	if _, err := readPublicRelayFile(link, false); err == nil {
		t.Fatal("accepted leaf reparse point")
	}
	dirLink := filepath.Join(dir, "linked-directory")
	if err := os.Symlink(dir, dirLink); err != nil {
		t.Fatal(err)
	}
	if _, err := readPublicRelayFile(filepath.Join(dirLink, "config.json"), false); err == nil {
		t.Fatal("accepted ancestor reparse point")
	}
}

func TestPublicRelayWindowsHTTPAndWebSocket(t *testing.T) {
	path := publicRelayWindowsTestPipe(t)
	listener, err := listenPublicRelaySocket(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if other, err := listenPublicRelaySocket(path); err == nil {
		other.Close()
		t.Fatal("replaced an active listener")
	}
	mux := http.NewServeMux()
	websocketDone := make(chan struct{})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ready") })
	mux.HandleFunc("/mesh", func(w http.ResponseWriter, r *http.Request) {
		defer close(websocketDone)
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetReadLimit(4096)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		kind, data, err := conn.ReadMessage()
		if err == nil {
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			conn.WriteMessage(kind, data)
		}
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	defer server.Close()
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) { return winio.DialPipeContext(ctx, path) }
	transport := &http.Transport{DialContext: dial}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	res, err := client.Get("http://relay/status")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || string(data) != "ready" {
		t.Fatal("HTTP named pipe round trip failed", err)
	}
	ws, _, err := (&websocket.Dialer{NetDialContext: dial, HandshakeTimeout: 5 * time.Second}).Dial("ws://relay/mesh", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := ws.WriteMessage(websocket.BinaryMessage, []byte("native mesh bytes")); err != nil {
		t.Fatal(err)
	}
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	kind, data, err := ws.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage || string(data) != "native mesh bytes" {
		t.Fatal("WebSocket named pipe round trip failed", err)
	}
	server.Close()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP listener did not stop")
	}
	transport.CloseIdleConnections()
	ws.Close()
	select {
	case <-websocketDone:
	case <-time.After(5 * time.Second):
		t.Fatal("WebSocket connection did not finish closing")
	}
	restarted, err := listenPublicRelaySocket(path)
	if err != nil {
		t.Fatal("could not restart closed pipe", err)
	}
	restarted.Close()
}

func TestPublicRelayWindowsPipeDeadlineAndShutdown(t *testing.T) {
	path := publicRelayWindowsTestPipe(t)
	listener, err := listenPublicRelaySocket(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
		} else {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := winio.DialPipeContext(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server net.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	fd, ok := server.(interface{ Fd() uintptr })
	if !ok {
		t.Fatal("pipe handle is unavailable for security inspection")
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(fd.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	user := publicRelayWindowsTestUser(t)
	if err := validatePublicRelaySecurity(sd, user, false, true); err != nil {
		t.Fatal("listener did not apply private owner security", err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl.AceCount != 1 {
		t.Fatal("pipe must grant access only to its owner", err)
	}
	server.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, err = server.Read(make([]byte, 1))
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatal("pipe read deadline failed", err)
	}
	server.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	_, err = server.Write(make([]byte, 1<<20))
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatal("pipe write deadline failed", err)
	}
	server.SetReadDeadline(time.Time{})
	read := make(chan error, 1)
	go func() { _, err := server.Read(make([]byte, 1)); read <- err }()
	server.Close()
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("closed read returned no error")
		}
	case <-ctx.Done():
		t.Fatal("pipe Close did not interrupt Read")
	}
	go func() { _, err := listener.Accept(); acceptErr <- err }()
	listener.Close()
	select {
	case err := <-acceptErr:
		if err == nil {
			t.Fatal("closed Accept returned no error")
		}
	case <-ctx.Done():
		t.Fatal("listener Close did not interrupt Accept")
	}
}
