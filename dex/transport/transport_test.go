package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/dex/protocol"
)

func TestSocketGolden(t *testing.T) {
	b, err := os.ReadFile("../testdata/transport.json")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if err = json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(v["frame"])
	if err != nil {
		t.Fatal(err)
	}
	f, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := f.Encode()
	if err != nil || !bytes.Equal(encoded, raw) {
		t.Fatal("canonical frame", err)
	}
	id := ID(raw)
	if hex.EncodeToString(id[:]) != v["id"] {
		t.Fatal("independent frame hash")
	}
	for _, b := range [][]byte{raw[:4], append(bytes.Clone(raw), 0), make([]byte, MaxFrame+5)} {
		if _, err := Decode(b); err == nil {
			t.Fatal("malformed frame")
		}
	}
	var huge [4]byte
	binary.BigEndian.PutUint32(huge[:], ^uint32(0))
	if _, _, err := Read(bytes.NewReader(huge[:])); err == nil {
		t.Fatal("huge length before allocation")
	}
}
func requireIsolated(t *testing.T) {
	t.Helper()
	if os.Getenv("CYPHER_DEX_SOCKET_DEVNET") != "1" {
		t.Skip("requires opted-in isolated loopback network namespace")
	}
	ifs, err := net.Interfaces()
	if err != nil || len(ifs) != 1 || ifs[0].Flags&net.FlagLoopback == 0 {
		t.Fatal("isolated loopback-only namespace required", ifs, err)
	}
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] != "lo" {
			t.Fatal("external route forbidden")
		}
	}
}
func cert(t *testing.T, n int) tls.Certificate {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := &x509.Certificate{SerialNumber: big.NewInt(int64(n + 1)), Subject: pkix.Name{CommonName: "isolated-dex"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, x, x, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
func configs(t *testing.T) []Config {
	t.Helper()
	requireIsolated(t)
	var peers []Peer
	certs := make([]tls.Certificate, 7)
	var reservations []net.Listener
	for i := 0; i < 7; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		reservations = append(reservations, l)
		certs[i] = cert(t, i)
		peers = append(peers, Peer{ID: fmtIndex(i), Address: l.Addr().String(), BLSPublic: strings.Repeat(hex.EncodeToString([]byte{byte(i + 1)}), 64), RewardRecipient: [20]byte{byte(i + 1)}, CertSHA256: protocol.Hash(sha256.Sum256(certs[i].Certificate[0]))})
	}
	for _, l := range reservations {
		l.Close()
	}
	domain := protocol.Domain{Version: 1, ChainID: 9127001, Genesis: protocol.Hash{1}, DEXID: protocol.Hash{2}, Epoch: 1, Committee: protocol.Hash{3}}
	hash, err := RegistryCommitment(domain, peers)
	if err != nil {
		t.Fatal(err)
	}
	var cs []Config
	root := t.TempDir()
	for i := 0; i < 7; i++ {
		cs = append(cs, Config{Domain: domain, RegistryHash: hash, Index: uint8(i), Peers: peers, Certificate: certs[i], DataDir: filepath.Join(root, fmtIndex(i)), QueueLimit: 16, Timeout: 500 * time.Millisecond, Retry: 20 * time.Millisecond, RatePerSecond: 128})
	}
	return cs
}
func fmtIndex(n int) string { return string(rune('a' + n)) }
func openTest(t *testing.T, c Config, h Handler) *Transport {
	t.Helper()
	n, err := Open(c, h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}
func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("socket condition timed out")
}
func TestTLSOutboxReconnectDuplicatesAndRestart(t *testing.T) {
	cs := configs(t)
	cs[0].QueueLimit = 2
	var received atomic.Int32
	n0 := openTest(t, cs[0], func(context.Context, uint8, uint8, []byte) error { return nil })
	if err := n0.Send(cs[1].Peers[1].ID, KindConsensus, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := n0.Send(cs[1].Peers[1].ID, KindConsensus, []byte{2}); err != nil {
		t.Fatal(err)
	}
	if err := n0.Send(cs[1].Peers[1].ID, KindConsensus, []byte{3}); !errors.Is(err, ErrCapacity) {
		t.Fatal("outbox limit", err)
	}
	n0.Close()
	n0 = openTest(t, cs[0], func(context.Context, uint8, uint8, []byte) error { return nil })
	if n0.Stats().Pending != 2 {
		t.Fatal("lost pending on restart")
	}
	if err := n0.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	if n0.Stats().Pending != 2 {
		t.Fatal("offline peer lost outbox")
	}
	n1 := openTest(t, cs[1], func(_ context.Context, p, k uint8, b []byte) error {
		if p != 0 || k != 1 {
			return errors.New("identity")
		}
		received.Add(1)
		return nil
	})
	if err := n1.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return n0.Stats().Pending == 0 && received.Load() == 2 })
	if err := n0.Send(cs[1].Peers[1].ID, KindConsensus, []byte{1}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return received.Load() == 3 && n0.Stats().Pending == 0 })
	n1.Close()
	if err := n0.Send(cs[1].Peers[1].ID, KindConsensus, []byte{4}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	n1 = openTest(t, cs[1], func(context.Context, uint8, uint8, []byte) error { received.Add(1); return nil })
	if err := n1.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return received.Load() == 4 && n0.Stats().Pending == 0 })
}
func exchange(t *testing.T, c Config, raw []byte) ([]byte, error) {
	t.Helper()
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := tls.DialWithDialer(&dialer, "tcp", c.Peers[1].Address, c.tlsConfig(1))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	if err := writeFull(conn, raw); err != nil {
		return nil, err
	}
	ack := make([]byte, 33)
	_, err = io.ReadFull(conn, ack)
	return ack, err
}
func TestTLSIdentityEpochPartialAndOutOfOrder(t *testing.T) {
	cs := configs(t)
	got := make(chan byte, 4)
	n1 := openTest(t, cs[1], func(_ context.Context, _ uint8, _ uint8, b []byte) error { got <- b[0]; return nil })
	if err := n1.Start(); err != nil {
		t.Fatal(err)
	}
	makeFrame := func(v byte) []byte {
		b, err := (Frame{cs[0].Domain.EpochKey(), cs[0].RegistryHash, 0, 1, 1, []byte{v}}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, v := range []byte{2, 1} {
		ack, err := exchange(t, cs[0], makeFrame(v))
		if err != nil || ack[0] != 1 {
			t.Fatal(err)
		}
	}
	if <-got != 2 || <-got != 1 {
		t.Fatal("application must handle actual delivery order")
	}
	for name, raw := range map[string][]byte{"partial": makeFrame(1)[:10], "old_epoch": func() []byte { b := makeFrame(1); b[12]++; return b }(), "wrong_source": func() []byte { b := makeFrame(1); b[76] = 2; return b }(), "huge_length": {255, 255, 255, 255}} {
		t.Run(name, func(t *testing.T) {
			if _, err := exchange(t, cs[0], raw); err == nil {
				t.Fatal("invalid frame acknowledged")
			}
		})
	}
	wrong := cs[0]
	wrong.Certificate = cert(t, 20)
	if _, err := exchange(t, wrong, makeFrame(9)); err == nil {
		t.Fatal("unregistered TLS certificate accepted")
	}
	select {
	case <-got:
		t.Fatal("unauthenticated message reached actor")
	default:
	}
}
func TestOutboxOwnershipAndRegistryRebind(t *testing.T) {
	cs := configs(t)
	n := openTest(t, cs[0], func(context.Context, uint8, uint8, []byte) error { return nil })
	if _, err := Open(cs[0], func(context.Context, uint8, uint8, []byte) error { return nil }); err == nil {
		t.Fatal("concurrent outbox owner")
	}
	n.Close()
	cs[0].Peers = append([]Peer(nil), cs[0].Peers...)
	cs[0].Peers[6].RewardRecipient[0]++
	cs[0].RegistryHash, _ = RegistryCommitment(cs[0].Domain, cs[0].Peers)
	if _, err := Open(cs[0], func(context.Context, uint8, uint8, []byte) error { return nil }); err == nil {
		t.Fatal("changed registration reopened old outbox")
	}
	cs[1].DataDir = t.TempDir()
	if _, err := Open(cs[1], func(context.Context, uint8, uint8, []byte) error { return nil }); err == nil {
		t.Fatal("unowned existing directory")
	}
}
