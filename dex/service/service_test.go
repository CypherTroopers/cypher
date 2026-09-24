package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/transport"
	"github.com/cypherium/cypher/reconfig/bftview"
)

func serviceConfigs(t *testing.T) []Config {
	t.Helper()
	if os.Getenv("CYPHER_DEX_SOCKET_DEVNET") != "1" {
		t.Skip("opt-in isolated socket namespace required")
	}
	ifs, err := net.Interfaces()
	if err != nil || len(ifs) != 1 || ifs[0].Flags&net.FlagLoopback == 0 {
		t.Fatal("loopback-only namespace required", err)
	}
	keys := make([]bls.SecretKey, 7)
	var members []*common.Cnode
	var peers []transport.Peer
	certs := make([]tls.Certificate, 7)
	var listeners []net.Listener
	for i := 0; i < 7; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, l)
		if err = keys[i].SetDecString(fmt.Sprint(i + 31)); err != nil {
			t.Fatal(err)
		}
		members = append(members, &common.Cnode{Address: l.Addr().String(), Public: keys[i].GetPublicKey().SerializeToHexStr(), CoinBase: fmt.Sprint("reward-", i)})
		pub, secret, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, template, template, pub, secret)
		if err != nil {
			t.Fatal(err)
		}
		certs[i] = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: secret}
		peers = append(peers, transport.Peer{ID: l.Addr().String(), Address: l.Addr().String(), BLSPublic: members[i].Public, RewardRecipient: [20]byte{byte(i + 1)}, CertSHA256: protocol.Hash(sha256.Sum256(der))})
	}
	for _, l := range listeners {
		l.Close()
	}
	domain := protocol.Domain{Version: 1, ChainID: 9127001, Genesis: protocol.Hash{1}, DEXID: protocol.Hash{2}, Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: members}).RlpHash())}
	registry, err := transport.RegistryCommitment(domain, peers)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	var configs []Config
	for i := 0; i < 7; i++ {
		configs = append(configs, Config{Consensus: consensus.Config{Domain: domain, Members: members, Index: i, Secret: &keys[i], DataDir: filepath.Join(root, fmt.Sprint("fhs", i)), CLXHash: domain.Genesis, MaxHeight: 5}, Transport: transport.Config{Domain: domain, RegistryHash: registry, Index: uint8(i), Peers: peers, Certificate: certs[i], DataDir: filepath.Join(root, fmt.Sprint("outbox", i)), Timeout: 2 * time.Second, Retry: 20 * time.Millisecond, QueueLimit: 256}, Timeout: 2 * time.Second})
	}
	return configs
}
func openServices(t *testing.T, configs []Config) []*Service {
	t.Helper()
	var ss []*Service
	for _, c := range configs {
		s, err := Open(c)
		if err != nil {
			t.Fatal(err)
		}
		ss = append(ss, s)
		t.Cleanup(func() { s.Close() })
	}
	for _, s := range ss {
		if err := s.Start(); err != nil {
			t.Fatal(err)
		}
	}
	return ss
}
func TestSevenFHSActorsOverPinnedTLSSockets(t *testing.T) {
	cs := serviceConfigs(t)
	ss := openServices(t, cs)
	deadline := time.Now().Add(30 * time.Second)
	done := false
	for time.Now().Before(deadline) {
		done = true
		for i, s := range ss {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			status, err := s.Status(ctx)
			cancel()
			if err != nil || status.Finalized < 4 {
				done = false
				if time.Until(deadline) < time.Second {
					t.Log(i, status, err)
				}
			}
		}
		if done {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !done {
		t.Fatal("real TLS FHS finality did not progress")
	}
	for i, s := range ss {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := s.Do(ctx, func(a *consensus.Application) error {
			cp, proof, err := a.FinalizedCheckpoint(4)
			if err != nil {
				return err
			}
			if cp.LastBlock != 4 || len(proof) == 0 {
				return errors.New("missing checkpoint")
			}
			return nil
		})
		cancel()
		if err != nil {
			t.Fatal(i, err)
		}
	}
	t.Log("seven actual FHS managers finalized4 using mutually pinned TLS sockets; no financial execution in this test")
}
func TestAuthenticatedActionAPIAndSerializedActor(t *testing.T) {
	cs := serviceConfigs(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cs[0].APIListen = l.Addr().String()
	l.Close()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	owner := crypto.PubkeyToAddress(key.PublicKey)
	file := filepath.Join(t.TempDir(), "admitted")
	var active, max, accepted atomic.Int32
	cs[0].OnAction = func(raw []byte) error {
		n := active.Add(1)
		defer active.Add(-1)
		if n > max.Load() {
			max.Store(n)
		}
		a, err := engine.Decode(raw)
		if err != nil || a.Epoch != cs[0].Consensus.Domain.EpochKey() {
			return errors.New("authentication")
		}
		f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, w := f.Write(raw)
		s := f.Sync()
		c := f.Close()
		if err = errors.Join(w, s, c); err != nil {
			return err
		}
		accepted.Add(1)
		time.Sleep(5 * time.Millisecond)
		return nil
	}
	ss := openServices(t, cs)
	raw, err := engine.Sign(engine.Action{Version: 1, Epoch: cs[0].Consensus.Domain.EpochKey(), Kind: engine.Noop, Owner: [20]byte(owner), Nonce: 1}, key)
	if err != nil {
		t.Fatal(err)
	}
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post("http://"+cs[0].APIListen+"/v1/actions", "application/octet-stream", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 202 || !bytes.Contains(body, []byte("ingress_admitted")) || !bytes.Contains(body, []byte("pending")) {
		t.Fatal(resp.StatusCode, string(body))
	}
	bad := bytes.Clone(raw)
	bad[len(bad)-1] ^= 1
	resp, err = client.Post("http://"+cs[0].APIListen+"/v1/actions", "application/octet-stream", bytes.NewReader(bad))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatal("invalid signature admitted", resp.StatusCode)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := ss[0].Submit(ctx, raw); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if max.Load() != 1 || accepted.Load() != 9 {
		t.Fatal("actor concurrency/ingress", max.Load(), accepted.Load())
	}
	b, err := os.ReadFile(file)
	if err != nil || len(b) != 9*len(raw) {
		t.Fatal("admission not durable", err)
	}
	// The fixture adapter deliberately records receipts only. It does not promise
	// nonce execution or finality for these action submissions.
}
func TestManifestDisabledAndUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	b, _ := json.Marshal(Manifest{Version: 1, Devnet: false})
	os.WriteFile(path, b, 0600)
	if _, err := LoadManifest(path); err == nil {
		t.Fatal("production manifest accepted")
	}
	os.WriteFile(path, []byte(`{"Version":1,"Unknown":true}`), 0600)
	if _, err := LoadManifest(path); err == nil {
		t.Fatal("unknown field accepted")
	}
}
