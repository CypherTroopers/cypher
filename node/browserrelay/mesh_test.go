// SPDX-License-Identifier: LGPL-3.0-or-later
package browserrelay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/p2p/enode"
	"github.com/gorilla/websocket"
)

type meshTestNode struct {
	mesh    *Mesh
	node    *enode.Node
	key     *ecdsa.PrivateKey
	inbound chan net.Conn
	server  *httptest.Server
}

func newMeshTestNode(t *testing.T) *meshTestNode {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	n := enode.NewV4(&key.PublicKey, net.IPv4(127, 0, 0, 1), 30303, 30303)
	f := &meshTestNode{node: n, key: key, inbound: make(chan net.Conn, MeshMaxCircuits)}
	f.mesh, err = NewMesh(MeshConfig{Network: Network{ChainID: 10101919, GenesisHash: "0x" + strings.Repeat("1", 64)}, LocalNode: func() *enode.Node { return n }, SignDigest: func(d []byte) ([]byte, error) { return crypto.Sign(d, key) }, OnInbound: func(c net.Conn, _ *enode.Node) error { f.inbound <- c; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.mesh.Start(); err != nil {
		t.Fatal(err)
	}
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		_ = f.mesh.Attach(r.Context(), strings.TrimPrefix(r.URL.Path, "/"), ws)
	}))
	t.Cleanup(func() { f.mesh.Stop(); f.server.Close() })
	return f
}

type meshTestClient struct {
	ws    *websocket.Conn
	hello MeshFrame
	mu    sync.Mutex
}

func meshConnect(t *testing.T, n *meshTestNode, browser string) *meshTestClient {
	t.Helper()
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(n.server.URL, "http")+"/"+browser, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &meshTestClient{ws: ws}
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err = ws.ReadJSON(&c.hello); err != nil {
		ws.Close()
		t.Fatal(err)
	}
	_ = ws.SetReadDeadline(time.Time{})
	if c.hello.Type != "hello" || !meshRandomID.MatchString(c.hello.Session) || c.hello.Protocol != MeshProtocol || c.hello.Advertisement == nil {
		t.Fatal("invalid mesh hello")
	}
	t.Cleanup(func() { ws.Close() })
	return c
}
func (c *meshTestClient) send(f MeshFrame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	f.Session = c.hello.Session
	return c.ws.WriteJSON(f)
}

type meshTestBridge struct {
	a, b *meshTestClient
	done chan struct{}
	once sync.Once
	hook func(*meshTestClient, MeshFrame) bool
	mu   sync.Mutex
	drop func(*meshTestClient, MeshFrame) bool
}

func meshBridge(t *testing.T, a, b *meshTestNode, aID, bID string, hook func(*meshTestClient, MeshFrame) bool) *meshTestBridge {
	t.Helper()
	bridge := &meshTestBridge{a: meshConnect(t, a, aID), b: meshConnect(t, b, bID), done: make(chan struct{}), hook: hook}
	if err := bridge.a.send(MeshFrame{Type: "advertisement", Advertisement: bridge.b.hello.Advertisement, Route: []string{bID, aID}}); err != nil {
		t.Fatal(err)
	}
	if err := bridge.b.send(MeshFrame{Type: "advertisement", Advertisement: bridge.a.hello.Advertisement, Route: []string{aID, bID}}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	pump := func(from, to *meshTestClient) {
		defer wg.Done()
		defer bridge.close()
		for {
			var f MeshFrame
			if from.ws.ReadJSON(&f) != nil {
				return
			}
			if bridge.hook != nil && !bridge.hook(from, f) {
				return
			}
			bridge.mu.Lock()
			drop := bridge.drop
			bridge.mu.Unlock()
			if drop != nil && drop(from, f) {
				continue
			}
			if f.Type == "advertisement" {
				f.Route = []string{from.hello.BrowserID, to.hello.BrowserID}
			}
			if to.send(f) != nil {
				return
			}
		}
	}
	go pump(bridge.a, bridge.b)
	go pump(bridge.b, bridge.a)
	go func() { wg.Wait(); close(bridge.done) }()
	t.Cleanup(func() { bridge.close(); <-bridge.done })
	waitMesh(t, func() bool {
		a.mesh.mu.Lock()
		ar := a.mesh.routes[b.node.ID()][bridge.a.hello.Session]
		a.mesh.mu.Unlock()
		b.mesh.mu.Lock()
		br := b.mesh.routes[a.node.ID()][bridge.b.hello.Session]
		b.mesh.mu.Unlock()
		return ar != nil && br != nil
	})
	return bridge
}
func (b *meshTestBridge) close() { b.once.Do(func() { b.a.ws.Close(); b.b.ws.Close() }) }
func waitMesh(t *testing.T, ready func() bool) {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		if ready() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("mesh condition timed out")
}
func meshDialPair(t *testing.T, a, b *meshTestNode) (net.Conn, net.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := a.mesh.Dial(ctx, b.node)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case in := <-b.inbound:
		t.Cleanup(func() { out.Close(); in.Close() })
		return out, in
	case <-ctx.Done():
		out.Close()
		t.Fatal("missing native inbound")
		return nil, nil
	}
}

func TestMeshSignedAdvertisementAndStrictProtocol(t *testing.T) {
	a, b := newMeshTestNode(t), newMeshTestNode(t)
	ad := a.mesh.advertisement
	if node, _, err := meshVerifyAdvertisement(ad, a.mesh.config.Network, time.Now()); err != nil || node.ID() != a.node.ID() {
		t.Fatal("native advertisement verify failed", err)
	}
	wrong := a.mesh.config.Network
	wrong.ChainID++
	if _, _, err := meshVerifyAdvertisement(ad, wrong, time.Now()); err == nil {
		t.Fatal("cross-network advertisement admitted")
	}
	raw, _ := base64.StdEncoding.DecodeString(ad.PayloadBase64)
	raw = bytes.Replace(raw, []byte(a.node.URLv4()), []byte(b.node.URLv4()), 1)
	ad.PayloadBase64 = base64.StdEncoding.EncodeToString(raw)
	if _, _, err := meshVerifyAdvertisement(ad, a.mesh.config.Network, time.Now()); err == nil {
		t.Fatal("native identity replacement admitted")
	}
	raw, _ = base64.StdEncoding.DecodeString(a.mesh.advertisement.PayloadBase64)
	raw = bytes.Replace(raw, []byte("127.0.0.1"), []byte("untrusted.invalid"), 1)
	ad = a.mesh.advertisement
	ad.PayloadBase64 = base64.StdEncoding.EncodeToString(raw)
	if _, _, err := meshVerifyAdvertisement(ad, a.mesh.config.Network, time.Now()); err == nil {
		t.Fatal("advertisement accepted a DNS destination")
	}
	old, err := meshSignAdvertisement(a.mesh.config.Network, a.node, a.mesh.bootID, time.Now().Add(-MeshAdvertisementTTL-time.Second), a.mesh.config.SignDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := meshVerifyAdvertisement(old, a.mesh.config.Network, time.Now()); err == nil {
		t.Fatal("expired advertisement admitted")
	}
	for _, raw := range []string{`{"type":"opened","session":"` + strings.Repeat("1", 32) + `","circuitId":"` + strings.Repeat("2", 32) + `","type":"opened"}`, `{"type":"data","session":"` + strings.Repeat("1", 32) + `","circuitId":"` + strings.Repeat("2", 32) + `","seq":0,"data":"YQ=="}`} {
		if _, err := meshDecodeFrame([]byte(raw)); err == nil {
			t.Fatal("ambiguous or invalid frame admitted")
		}
	}
	if meshValidRoute([]string{"a", "b", "a"}, "a") || meshValidRoute([]string{"a", "b", "c", "d", "e"}, "e") {
		t.Fatal("loop or overlong route admitted")
	}
}

// Two WebSocket clients forward frames as the future browser bridge would.
// This proves native stream transport, not a browser or WebRTC implementation.
func TestMeshTwoNativeEndpointsBridgeStreamAndCredit(t *testing.T) {
	a, b := newMeshTestNode(t), newMeshTestNode(t)
	meshBridge(t, a, b, "browserA", "browserB", nil)
	out, in := meshDialPair(t, a, b)
	info, ok := MeshConnectionInfo(out)
	if !ok || info.RemoteID != b.node.ID() || strings.Join(info.RelayIDs, ",") != "browserA,browserB" {
		t.Fatal("native identity and browser route were conflated")
	}
	_ = out.SetDeadline(time.Now().Add(5 * time.Second))
	_ = in.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("actual-native-stream-"), 7000)
	sent := make(chan error, 1)
	go func() { _, err := out.Write(payload); sent <- err }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(in, got); err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil || !bytes.Equal(payload, got) {
		t.Fatal("stream bytes differ", err)
	}
	if _, err := in.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(out, reply); err != nil || string(reply) != "reply" {
		t.Fatal("duplex reply failed", err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	waitMesh(t, func() bool { return a.mesh.Status().Circuits == 0 && b.mesh.Status().Circuits == 0 })
}

func TestMeshSlowNativeReaderAppliesCreditAndDeadlines(t *testing.T) {
	a, b := newMeshTestNode(t), newMeshTestNode(t)
	meshBridge(t, a, b, "slowA", "slowB", nil)
	out, in := meshDialPair(t, a, b)
	payload := bytes.Repeat([]byte{0x67}, 9*MeshMaxChunkBytes)
	_ = out.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	n, err := out.Write(payload)
	if n != MeshReceiveChunks*MeshMaxChunkBytes || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("flow control did not bound sender: bytes=%d err=%v", n, err)
	}
	if a.mesh.Status().Circuits != 1 || b.mesh.Status().Circuits != 1 {
		t.Fatal("slow consumer disconnected healthy circuit")
	}
	_ = in.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, n)
	if _, err := io.ReadFull(in, got); err != nil {
		t.Fatal(err)
	}
	_ = out.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := out.Write(payload[n:]); err != nil {
		t.Fatal("credit did not resume stream", err)
	}
	got = make([]byte, len(payload)-n)
	if _, err := io.ReadFull(in, got); err != nil {
		t.Fatal(err)
	}
	_ = in.SetReadDeadline(time.Now().Add(time.Millisecond))
	if _, err := in.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("read deadline ignored", err)
	}
	_ = in.SetReadDeadline(time.Time{})
	if _, err := out.Write([]byte{7}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(in, got[:1]); err != nil || got[0] != 7 {
		t.Fatal("deadline reset did not recover", err)
	}
}

func TestMeshAbruptDisconnectRepeatedChurnAndStaleGeneration(t *testing.T) {
	a, b := newMeshTestNode(t), newMeshTestNode(t)
	seen := map[string]bool{}
	var oldSession, oldCircuit string
	for i := 0; i < 6; i++ {
		bridge := meshBridge(t, a, b, "churnA", "churnB", nil)
		if seen[bridge.a.hello.Session] {
			t.Fatal("session generation reused")
		}
		seen[bridge.a.hello.Session] = true
		out, in := meshDialPair(t, a, b)
		info, _ := MeshConnectionInfo(out)
		oldSession, oldCircuit = bridge.a.hello.Session, info.CircuitID
		waiting := make(chan error, 1)
		go func() { _, err := in.Read(make([]byte, 1)); waiting <- err }()
		bridge.close()
		<-bridge.done
		select {
		case err := <-waiting:
			if err == nil {
				t.Fatal("disconnect reported success")
			}
		case <-time.After(time.Second):
			t.Fatal("disconnect left blocked native read")
		}
		waitMesh(t, func() bool {
			sa, sb := a.mesh.Status(), b.mesh.Status()
			return sa.Sessions == 0 && sb.Sessions == 0 && sa.Circuits == 0 && sb.Circuits == 0 && sa.Candidates == 0 && sb.Candidates == 0
		})
	}
	client := meshConnect(t, a, "churnA")
	client.mu.Lock()
	err := client.ws.WriteJSON(MeshFrame{Type: "opened", Session: oldSession, CircuitID: oldCircuit})
	client.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	waitMesh(t, func() bool { return a.mesh.Status().Sessions == 0 })
	if a.mesh.Status().Circuits != 0 {
		t.Fatal("old frame revived closed circuit")
	}
	meshBridge(t, a, b, "churnA", "churnB", nil)
	out, in := meshDialPair(t, a, b)
	if _, err := out.Write([]byte("new-generation")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 14)
	_ = in.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(in, got); err != nil || string(got) != "new-generation" {
		t.Fatal("reconnect did not restore data", err)
	}
}

func TestMeshDialRetriesAnotherSessionAfterMidOpenDisconnect(t *testing.T) {
	a, b := newMeshTestNode(t), newMeshTestNode(t)
	var mu sync.Mutex
	dropSession := ""
	hook := func(from *meshTestClient, f MeshFrame) bool {
		mu.Lock()
		drop := f.Type == "open" && from.hello.Session == dropSession
		mu.Unlock()
		return !drop
	}
	one := meshBridge(t, a, b, "routeA1", "routeB1", hook)
	two := meshBridge(t, a, b, "routeA2", "routeB2", hook)
	mu.Lock()
	dropSession = one.a.hello.Session
	if two.a.hello.Session < dropSession {
		dropSession = two.a.hello.Session
	}
	mu.Unlock()
	out, in := meshDialPair(t, a, b)
	info, _ := MeshConnectionInfo(out)
	if info.SessionID == dropSession {
		t.Fatal("failed route remained selected")
	}
	if _, err := out.Write([]byte("alternate")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 9)
	_ = in.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(in, got); err != nil || string(got) != "alternate" {
		t.Fatal("alternate session did not carry stream", err)
	}
}

func TestMeshRejectsUnknownDestinationAndForgedCredit(t *testing.T) {
	a, b := newMeshTestNode(t), newMeshTestNode(t)
	bridge := meshBridge(t, a, b, "guardA", "guardB", nil)
	unknown, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if c, err := a.mesh.Dial(context.Background(), enode.NewV4(&unknown.PublicKey, net.IPv4(1, 1, 1, 1), 80, 80)); err == nil || c != nil {
		t.Fatal("unknown advertised destination dialed")
	}
	out, _ := meshDialPair(t, a, b)
	info, _ := MeshConnectionInfo(out)
	if err := bridge.a.send(MeshFrame{Type: "credit", CircuitID: info.CircuitID, Seq: 1, Bytes: 8192}); err != nil {
		t.Fatal(err)
	}
	waitMesh(t, func() bool { return a.mesh.Status().Circuits == 0 })
	if _, err := out.Write([]byte("denied")); err == nil {
		t.Fatal("forged credit allowed writes")
	}
	// An old circuit ID in a current session cannot allocate or revive a stream.
	if err := bridge.a.send(MeshFrame{Type: "data", CircuitID: info.CircuitID, Seq: 1, Data: base64.StdEncoding.EncodeToString([]byte{1})}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if a.mesh.Status().Circuits != 0 {
		t.Fatal("late data revived a stream")
	}
}

func TestMeshCircuitCapacityAndSessionDepartureReleaseReservations(t *testing.T) {
	for _, sessions := range []int{1, MeshMaxRoutesPerCandidate} {
		t.Run(fmt.Sprintf("sessions-%d", sessions), func(t *testing.T) {
			a, b := newMeshTestNode(t), newMeshTestNode(t)
			var bridges []*meshTestBridge
			for i := 0; i < sessions; i++ {
				bridges = append(bridges, meshBridge(t, a, b, fmt.Sprintf("capA%d", i), fmt.Sprintf("capB%d", i), nil))
			}
			for i := 0; i < MeshMaxCircuits; i++ {
				meshDialPair(t, a, b)
			}
			if a.mesh.Status().Circuits != MeshMaxCircuits || b.mesh.Status().Circuits != MeshMaxCircuits {
				t.Fatal("circuit reservations missing")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if c, err := a.mesh.Dial(ctx, b.node); err == nil || c != nil {
				t.Fatal("circuit capacity exceeded")
			}
			released := 0
			for _, route := range a.mesh.Status().Routes {
				if route.SessionID == bridges[0].a.hello.Session {
					released++
				}
			}
			if released == 0 || released > MeshMaxCircuitsPerSession {
				t.Fatal("invalid circuit distribution across sessions")
			}
			bridges[0].close()
			<-bridges[0].done
			waitMesh(t, func() bool {
				return a.mesh.Status().Circuits == MeshMaxCircuits-released && b.mesh.Status().Circuits == MeshMaxCircuits-released
			})
			meshBridge(t, a, b, "capReplacementA", "capReplacementB", nil)
			for i := 0; i < released; i++ {
				meshDialPair(t, a, b)
			}
			if a.mesh.Status().Circuits != MeshMaxCircuits || b.mesh.Status().Circuits != MeshMaxCircuits {
				t.Fatal("departed session leaked circuit capacity")
			}
		})
	}
}

func TestMeshStopUnblocksWriterAndJoinsInboundHandshake(t *testing.T) {
	a, b := newMeshTestNode(t), newMeshTestNode(t)
	entered, readClosed, released := make(chan struct{}), make(chan struct{}), make(chan struct{})
	b.mesh.config.OnInbound = func(c net.Conn, _ *enode.Node) error {
		close(entered)
		<-c.(*meshConn).done
		close(readClosed)
		<-released
		return nil
	}
	meshBridge(t, a, b, "joinA", "joinB", nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out, err := a.mesh.Dial(ctx, b.node)
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	writeResult := make(chan error, 1)
	go func() { _, err := out.Write(make([]byte, 9*MeshMaxChunkBytes)); writeResult <- err }()
	waitMesh(t, func() bool {
		c := out.(*meshConn)
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.pending) == MeshReceiveChunks
	})
	stopped := make(chan struct{})
	go func() { b.mesh.Stop(); close(stopped) }()
	<-readClosed
	select {
	case <-stopped:
		t.Fatal("Stop returned before inbound callback finished")
	default:
	}
	select {
	case err := <-writeResult:
		if err == nil {
			t.Fatal("disconnect completed an uncredited write")
		}
	case <-time.After(time.Second):
		t.Fatal("disconnect did not unblock credit wait")
	}
	close(released)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop did not join callback")
	}
	if s := b.mesh.Status(); s.Sessions != 0 || s.Circuits != 0 || s.Candidates != 0 {
		t.Fatal("Stop retained mesh state")
	}
}

func TestMeshNextDialRotatesAfterOpenedRouteBlackholesData(t *testing.T) {
	a, b := newMeshTestNode(t), newMeshTestNode(t)
	one := meshBridge(t, a, b, "badA", "badB", nil)
	two := meshBridge(t, a, b, "goodA", "goodB", nil)
	bad := one
	if two.a.hello.Session < one.a.hello.Session {
		bad = two
	}
	bad.mu.Lock()
	bad.drop = func(from *meshTestClient, f MeshFrame) bool { return from == bad.a && f.Type == "data" }
	bad.mu.Unlock()
	out, in := meshDialPair(t, a, b)
	info, _ := MeshConnectionInfo(out)
	if info.SessionID != bad.a.hello.Session {
		t.Fatal("fixture did not select bad route first")
	}
	if _, err := out.Write([]byte("rlpx-handshake-attempt")); err != nil {
		t.Fatal(err)
	}
	_ = in.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, err := in.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("fixture did not blackhole native data", err)
	}
	out.Close()
	in.Close()
	waitMesh(t, func() bool { return a.mesh.Status().Circuits == 0 && b.mesh.Status().Circuits == 0 })
	if a.mesh.Status().Sessions != 2 || b.mesh.Status().Sessions != 2 {
		t.Fatal("bad route should still advertise and keep WS alive")
	}
	out, in = meshDialPair(t, a, b)
	info, _ = MeshConnectionInfo(out)
	if info.SessionID == bad.a.hello.Session {
		t.Fatal("new dial repeated opened but broken route")
	}
	if _, err := out.Write([]byte("recovered")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 9)
	_ = in.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(in, buf); err != nil || string(buf) != "recovered" {
		t.Fatal("healthy alternative failed", err)
	}
}

func TestMeshWebSocketControlFramesCannotBypassBudgets(t *testing.T) {
	for _, kind := range []int{websocket.PingMessage, websocket.PongMessage} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			n := newMeshTestNode(t)
			client := meshConnect(t, n, "control")
			pong := make(chan string, 1)
			client.ws.SetPongHandler(func(payload string) error {
				select {
				case pong <- payload:
				default:
				}
				return nil
			})
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					if _, _, err := client.ws.ReadMessage(); err != nil {
						return
					}
				}
			}()
			t.Cleanup(func() { client.ws.Close(); <-done })
			if err := client.ws.WriteControl(websocket.PingMessage, []byte("probe"), time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			select {
			case payload := <-pong:
				if payload != "probe" {
					t.Fatal("incorrect pong")
				}
			case <-time.After(time.Second):
				t.Fatal("normal ping did not receive pong")
			}
			for i := 0; i < 20; i++ {
				if client.ws.WriteControl(kind, bytes.Repeat([]byte{1}, 125), time.Now().Add(time.Second)) != nil {
					break
				}
			}
			waitMesh(t, func() bool { return n.mesh.Status().Sessions == 0 })
		})
	}
	n := newMeshTestNode(t)
	var clients []*meshTestClient
	heartbeats := make(chan struct{}, MeshMaxSessions)
	probe := make(chan struct{}, 1)
	var readers sync.WaitGroup
	t.Cleanup(func() {
		for _, client := range clients {
			client.ws.Close()
		}
		readers.Wait()
	})
	for i := 0; i < MeshMaxSessions; i++ {
		client := meshConnect(t, n, fmt.Sprintf("global%d", i))
		clients = append(clients, client)
		if i == 0 {
			client.ws.SetPongHandler(func(payload string) error {
				if payload == "probe-after-heartbeat" {
					select {
					case probe <- struct{}{}:
					default:
					}
				}
				return nil
			})
		}
		ping := client.ws.PingHandler()
		client.ws.SetPingHandler(func(payload string) error {
			if err := ping(payload); err != nil {
				return err
			}
			select {
			case heartbeats <- struct{}{}:
			default:
			}
			return nil
		})
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				if _, _, err := client.ws.ReadMessage(); err != nil {
					return
				}
			}
		}()
	}
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(n.server.URL, "http")+"/over-capacity", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = ws.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := ws.ReadMessage(); err == nil {
		t.Fatal("session capacity exceeded")
	}
	ws.Close()
	// A complete heartbeat round at the session limit must not consume the
	// aggregate control budget and evict otherwise idle, healthy browsers.
	heartbeatDeadline := time.NewTimer(MeshHeartbeatInterval + 3*time.Second)
	defer heartbeatDeadline.Stop()
	for i := 0; i < MeshMaxSessions; i++ {
		select {
		case <-heartbeats:
		case <-heartbeatDeadline.C:
			t.Fatal("full session capacity did not survive a heartbeat round")
		}
	}
	if n.mesh.Status().Sessions != MeshMaxSessions {
		t.Fatal("healthy browser sessions were evicted at capacity")
	}
	if err := clients[0].ws.WriteControl(websocket.PingMessage, []byte("probe-after-heartbeat"), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-probe:
	case <-time.After(time.Second):
		t.Fatal("ordinary control traffic failed alongside full-capacity heartbeats")
	}
	for _, client := range clients {
		for i := 0; i < 5; i++ {
			_ = client.ws.WriteControl(websocket.PongMessage, []byte{1}, time.Now().Add(time.Second))
		}
	}
	waitMesh(t, func() bool { return n.mesh.Status().Sessions < MeshMaxSessions })
}

func TestMeshEndpointOriginAndSignature(t *testing.T) {
	for _, origin := range []string{"https://gateway.example.org", "https://gateway.example.org:8443", "https://8.8.8.8", "https://[2606:4700:4700::1111]"} {
		if err := ValidateMeshGatewayOrigin(origin); err != nil {
			t.Fatalf("valid origin %s: %v", origin, err)
		}
	}
	for _, origin := range []string{"http://gateway.example.org", "https://gateway.example.org/", "https://gateway.example.org:", "https://gateway.example.org:0", "https://gateway.example.org:443", "https://USER@gateway.example.org", "https://GATEWAY.example.org", "https://gateway.example.org?x=1", "https://127.0.0.1", "https://127.1", "https://0x7f.0.0.1", "https://10.1.1.1", "https://[::1]", "https://[::ffff:127.0.0.1]", "https://[2002:7f00:1::1]", "https://[2001::7f00:1]", "https://localhost", "https://a.local", "https://a.internal", "https://a.example.org."} {
		if ValidateMeshGatewayOrigin(origin) == nil {
			t.Fatalf("unsafe origin accepted: %s", origin)
		}
	}
	key, _ := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	n := enode.NewV4(&key.PublicKey, net.IPv4(127, 0, 0, 1), 30445, 0)
	network := Network{ChainID: 10101919, GenesisHash: "0x" + strings.Repeat("2", 64)}
	now := time.UnixMilli(1700000000000)
	sign := func(d []byte) ([]byte, error) { return crypto.Sign(d, key) }
	envelope, err := meshSignEndpoint(network, n, "common-a", "https://gateway.example.org", strings.Repeat("66", 16), 1, now, sign)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(envelope.PayloadBase64)
	var payload meshEndpointPayload
	if err = json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Sequence != 1 || payload.ExpiresAt != now.Add(MeshAdvertisementTTL).UnixMilli() {
		t.Fatalf("invalid endpoint payload %+v", payload)
	}
	if verified, _, err := meshVerifyEndpoint(envelope, network, now); err != nil || verified.ID() != n.ID() {
		t.Fatal("signature verification", err)
	}
	wrongNetwork := network
	wrongNetwork.ChainID++
	if _, _, err = meshVerifyEndpoint(envelope, wrongNetwork, now); err == nil {
		t.Fatal("other network accepted")
	}
	if _, _, err = meshVerifyEndpoint(envelope, network, now.Add(MeshAdvertisementTTL)); err == nil {
		t.Fatal("expired endpoint accepted")
	}
	modified := envelope
	modified.SignatureHex = strings.Repeat("00", 65)
	if _, _, err = meshVerifyEndpoint(modified, network, now); err == nil {
		t.Fatal("forged signature accepted")
	}
	modified = envelope
	modified.PayloadBase64 = base64.StdEncoding.EncodeToString(bytes.Replace(raw, []byte("gateway.example.org"), []byte("another.example.org"), 1))
	if _, _, err = meshVerifyEndpoint(modified, network, now); err == nil {
		t.Fatal("changed gateway accepted")
	}
	raw = bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"\u0076ersion":1`), 1)
	sig, _ := sign(crypto.Keccak256([]byte(MeshEndpointDomain), raw))
	modified = MeshAdvertisement{PayloadBase64: base64.StdEncoding.EncodeToString(raw), SignatureHex: hex.EncodeToString(sig)}
	if _, _, err = meshVerifyEndpoint(modified, network, now); err == nil {
		t.Fatal("signed duplicate key accepted")
	}
	// Fixed Go/WebCrypto-independent vector checked by the browser test as well.
	data, err := os.ReadFile("testdata/mesh-endpoint-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Envelope MeshAdvertisement `json:"envelope"`
		NodeID   string            `json:"nodeId"`
	}
	if json.Unmarshal(data, &vector) != nil || vector.Envelope != envelope || vector.NodeID != n.ID().String() {
		t.Fatal("fixed endpoint interoperability vector differs")
	}
}

func TestMeshEndpointLifecycle(t *testing.T) {
	key, _ := crypto.GenerateKey()
	n := enode.NewV4(&key.PublicKey, net.IPv4(127, 0, 0, 1), 30445, 0)
	config := MeshConfig{Network: Network{ChainID: 10101919, GenesisHash: "0x" + strings.Repeat("2", 64)}, LocalNode: func() *enode.Node { return n }, SignDigest: func(d []byte) ([]byte, error) { return crypto.Sign(d, key) }, OnInbound: func(c net.Conn, _ *enode.Node) error { return c.Close() }, SourceID: "common-a", PublicGatewayOrigin: "https://gateway.example.org"}
	m, err := NewMesh(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Endpoint(); !errors.Is(err, ErrMeshUnavailable) {
		t.Fatal("descriptor before start")
	}
	if err = m.Start(); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	first, err := m.Endpoint()
	if err != nil {
		t.Fatal(err)
	}
	repeat, err := m.Endpoint()
	if err != nil || repeat != first || m.endpointSequence != 1 {
		t.Fatal("GET must not resign/increment")
	}
	m.mu.Lock()
	initial := m.endpointAdvertisedAt
	err = m.refreshEndpointLocked(initial.Add(30 * time.Second))
	sequence := m.endpointSequence
	second := m.endpoint
	m.mu.Unlock()
	if err != nil || sequence != 2 || second == first {
		t.Fatal("endpoint refresh did not advance", err)
	}
	m.mu.Lock()
	if rollback := m.refreshEndpointLocked(initial.Add(-time.Second)); rollback == nil || m.endpointSequence != 2 {
		m.mu.Unlock()
		t.Fatal("wall clock rollback altered descriptor")
	}
	goodSigner := m.config.SignDigest
	m.config.SignDigest = func([]byte) ([]byte, error) { return nil, errors.New("fixture signing failure") }
	err = m.refreshEndpointLocked(initial.Add(60 * time.Second))
	unchanged := m.endpoint == second && m.endpointSequence == 2
	m.config.SignDigest = goodSigner
	m.endpointAdvertisedAt = time.Now().Add(-MeshAdvertisementTTL - time.Second)
	m.mu.Unlock()
	if err == nil || !unchanged {
		t.Fatal("failed refresh changed endpoint lease")
	}
	if _, err = m.Endpoint(); !errors.Is(err, ErrMeshUnavailable) {
		t.Fatal("expired descriptor remains available")
	}
	m.Stop()
	if _, err = m.Endpoint(); !errors.Is(err, ErrMeshUnavailable) {
		t.Fatal("descriptor after stop")
	}
	other, err := NewMesh(config)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Stop()
	if other.bootID == m.bootID {
		t.Fatal("restart reused boot")
	}
	config.PublicGatewayOrigin = ""
	disabled, err := NewMesh(config)
	if err != nil {
		t.Fatal(err)
	}
	defer disabled.Stop()
	if err = disabled.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err = disabled.Endpoint(); !errors.Is(err, ErrMeshEndpointDisabled) {
		t.Fatal("legacy mesh should not publish an endpoint")
	}
}

func TestMeshUplinkEndpointKeepsLocalLabelAndGlobalSequence(t *testing.T) {
	key, _ := crypto.GenerateKey()
	n := enode.NewV4(&key.PublicKey, net.IPv4(127, 0, 0, 1), 30445, 0)
	m, err := NewMesh(MeshConfig{Network: Network{ChainID: 10101919, GenesisHash: "0x" + strings.Repeat("2", 64)}, LocalNode: func() *enode.Node { return n }, SignDigest: func(d []byte) ([]byte, error) { return crypto.Sign(d, key) }, OnInbound: func(c net.Conn, _ *enode.Node) error { return c.Close() }, SourceID: "common-mine", PublicGatewayOrigin: "https://gateway.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.UplinkEndpoint(); !errors.Is(err, ErrMeshUnavailable) {
		t.Fatal("uplink before start")
	}
	if err = m.Start(); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	decode := func(e MeshAdvertisement) meshEndpointPayload {
		t.Helper()
		if _, _, err := meshVerifyEndpoint(e, m.config.Network, time.Now()); err != nil {
			t.Fatal(err)
		}
		var p meshEndpointPayload
		raw, _ := base64.StdEncoding.DecodeString(e.PayloadBase64)
		if json.Unmarshal(raw, &p) != nil {
			t.Fatal("endpoint decode")
		}
		return p
	}
	local, _ := m.Endpoint()
	lp := decode(local)
	uplink, err := m.UplinkEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	up := decode(uplink)
	if lp.SourceID != "common-mine" || up.SourceID != n.ID().String() || lp.BootID != up.BootID || up.Sequence <= lp.Sequence {
		t.Fatal("source labels or generations were not separated")
	}
	if again, _ := m.Endpoint(); again != local {
		t.Fatal("uplink changed local envelope")
	}
	if again, _ := m.UplinkEndpoint(); again != uplink {
		t.Fatal("read unexpectedly resigned")
	}
	m.mu.Lock()
	now := time.Now()
	err = m.refreshEndpointLocked(now)
	nextLocal := m.endpoint
	err2 := m.refreshUplinkEndpointLocked(now)
	nextUplink := m.uplinkEndpoint
	m.mu.Unlock()
	if err != nil || err2 != nil {
		t.Fatal(err, err2)
	}
	if decode(nextLocal).Sequence <= up.Sequence || decode(nextUplink).Sequence <= decode(nextLocal).Sequence {
		t.Fatal("independent counters allow rollback")
	}
	m.mu.Lock()
	previous := m.uplinkEndpoint
	sequence := m.endpointSequence
	m.config.SignDigest = func([]byte) ([]byte, error) { return nil, errors.New("signer unavailable") }
	err = m.refreshUplinkEndpointLocked(time.Now())
	unchanged := m.uplinkEndpoint == previous && m.endpointSequence == sequence
	m.uplinkAdvertisedAt = time.Now().Add(-MeshAdvertisementTTL - time.Second)
	m.mu.Unlock()
	if err == nil || !unchanged {
		t.Fatal("failed signer changed lease")
	}
	if _, err = m.UplinkEndpoint(); !errors.Is(err, ErrMeshUnavailable) {
		t.Fatal("expired uplink returned")
	}
	m.Stop()
	if _, err = m.UplinkEndpoint(); !errors.Is(err, ErrMeshUnavailable) {
		t.Fatal("uplink after stop")
	}
}
