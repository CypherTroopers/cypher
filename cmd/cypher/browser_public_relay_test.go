//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/eth"
	"github.com/cypherium/cypher/node/lightnode"
	cli "gopkg.in/urfave/cli.v1"
)

func publicRelayTestDirectory(t *testing.T) string {
	t.Helper()
	// Native builds use a deeply nested TMPDIR. Unix socket addresses must stay
	// short, and macOS /tmp is a symlink rejected by the production path checks.
	base, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(base, "cpr-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func publicRelayTestConfig(t *testing.T) (string, browserPublicRelayConfiguration) {
	t.Helper()
	dir := publicRelayTestDirectory(t)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := browserPublicRelayConfiguration{Enabled: true, SocketPath: filepath.Join(dir, "headers.sock"),
		Network:  lightnode.Network{ChainID: 10101919, GenesisHash: "0x" + strings.Repeat("1", 64)},
		SourceID: "fixture-common", KeyID: "fixture-key", SigningKeyPath: filepath.Join(dir, "source-key.pem")}
	if err := os.WriteFile(cfg.SigningKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "relay.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path, cfg
}

func publicRelayCLI(enabled bool, path, command string, mine bool, unlock string) *cli.Context {
	flags := flag.NewFlagSet("public-header fixture", flag.ContinueOnError)
	flags.Bool("browser.public-relay", enabled, "")
	flags.String("browser.public-relay.config", path, "")
	flags.Bool("mine", mine, "")
	flags.String("unlock", unlock, "")
	ctx := cli.NewContext(cli.NewApp(), flags, nil)
	ctx.Command = cli.Command{Name: command}
	return ctx
}

func TestPublicRelayDisabledAndCommonRoleGuards(t *testing.T) {
	if g, err := prepareBrowserPublicRelay(publicRelayCLI(false, "", "", false, "")); err != nil || g != nil {
		t.Fatalf("disabled path acquired state: %v", err)
	}
	if g, err := prepareBrowserPublicRelay(publicRelayCLI(false, "/does-not-exist", "", false, "")); err == nil || g != nil || !strings.Contains(err.Error(), "requires explicit") {
		t.Fatal("disabled path attempted configuration I/O")
	}
	path, _ := publicRelayTestConfig(t)
	for _, test := range []struct {
		command string
		mine    bool
		unlock  string
		allowed bool
	}{
		{"", false, "", true}, {"console", false, "", true},
		{"init", false, "", false}, {"attach", false, "", false}, {"js", false, "", false},
		{"dumpconfig", false, "", false}, {"console", true, "", true}, {"console", false, "0", true},
	} {
		g, err := prepareBrowserPublicRelay(publicRelayCLI(true, path, test.command, test.mine, test.unlock))
		if test.allowed {
			if err != nil || g == nil || g.source != nil || g.listener != nil {
				t.Fatalf("allowed preparation acquired runtime resources or failed: %v", err)
			}
			if err := g.Close(); err != nil {
				t.Fatal(err)
			}
		} else if err == nil || g != nil {
			t.Fatalf("unsafe command admitted: %+v", test)
		}
	}
	cfg := &gethConfig{Eth: eth.DefaultConfig}
	if err := initializeBrowserPublicRelay(cfg, nil, nil); err != nil {
		t.Fatal("disabled initialization changed ordinary startup", err)
	}
	cfg.browserPublicRelay = &browserPublicRelayStartup{}
	for _, role := range []struct{ ingress, fhs bool }{{false, false}, {true, true}, {false, true}} {
		cfg.Eth.TxQUIC.Enabled, cfg.Eth.TxQUIC.FairHotstuff = role.ingress, role.fhs
		err := initializeBrowserPublicRelay(cfg, nil, nil)
		if err == nil || ((err.Error() == "Common backend is missing") != (!role.ingress && role.fhs)) {
			t.Fatalf("Common role guard failed for %+v: %v", role, err)
		}
	}
}

func TestPublicRelayConfigRejectsAmbiguityAndUnsafeFiles(t *testing.T) {
	for _, mutation := range []string{"duplicate", "network-duplicate", "unknown", "missing", "trailing", "null", "oversized", "config-link", "parent-link", "key-link", "key-mode", "config-mode", "socket-mode", "wrong-key"} {
		t.Run(mutation, func(t *testing.T) {
			path, cfg := publicRelayTestConfig(t)
			raw, _ := os.ReadFile(path)
			switch mutation {
			case "duplicate":
				raw = append([]byte(`{"enabled":true,`), raw[1:]...)
			case "network-duplicate":
				raw = []byte(strings.Replace(string(raw), `"network":{`, `"network":{"chainId":1,`, 1))
			case "unknown":
				raw = append([]byte(`{"privateRpc":"http://localhost",`), raw[1:]...)
			case "missing":
				raw = []byte(strings.Replace(string(raw), `"enabled":true,`, "", 1))
			case "trailing":
				raw = append(raw, []byte(` {}`)...)
			case "null":
				raw = []byte(strings.Replace(string(raw), `"enabled":true`, `"enabled":null`, 1))
			case "oversized":
				raw = []byte(strings.Repeat(" ", 4097))
			case "config-link":
				link := filepath.Join(filepath.Dir(path), "link.json")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "parent-link":
				link := filepath.Join(publicRelayTestDirectory(t), "linked")
				if err := os.Symlink(filepath.Dir(path), link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, filepath.Base(path))
			case "key-link":
				moved := cfg.SigningKeyPath + ".original"
				if err := os.Rename(cfg.SigningKeyPath, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(moved, cfg.SigningKeyPath); err != nil {
					t.Fatal(err)
				}
			case "key-mode":
				if err := os.Chmod(cfg.SigningKeyPath, 0640); err != nil {
					t.Fatal(err)
				}
			case "config-mode":
				if err := os.Chmod(path, 0660); err != nil {
					t.Fatal(err)
				}
			case "socket-mode":
				if err := os.Chmod(filepath.Dir(cfg.SocketPath), 0750); err != nil {
					t.Fatal(err)
				}
			case "wrong-key":
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				der, err := x509.MarshalPKCS8PrivateKey(key)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(cfg.SigningKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mutation == "duplicate" || mutation == "network-duplicate" || mutation == "unknown" || mutation == "missing" || mutation == "trailing" || mutation == "null" || mutation == "oversized" {
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := loadBrowserPublicRelayConfiguration(path); err == nil {
				t.Fatal("unsafe configuration was admitted")
			}
		})
	}
}

type publicRelayLifecycleFixture struct {
	starts, stops atomic.Int32
	start         func() error
	stop          func() error
}

func (f *publicRelayLifecycleFixture) Start() error {
	f.starts.Add(1)
	if f.start != nil {
		return f.start()
	}
	return nil
}
func (f *publicRelayLifecycleFixture) Stop() error {
	f.stops.Add(1)
	if f.stop != nil {
		return f.stop()
	}
	return nil
}

func publicRelayRuntimeFixture(t *testing.T, source *publicRelayLifecycleFixture) *browserPublicRelayStartup {
	t.Helper()
	dir := publicRelayTestDirectory(t)
	ctx, cancel := context.WithCancel(context.Background())
	g := &browserPublicRelayStartup{public: browserPublicRelayConfiguration{SocketPath: filepath.Join(dir, "headers.sock")},
		source: source, ctx: ctx, cancel: cancel, handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "fixture-ready") })}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

func TestPublicRelayUnixReadinessOwnershipAndJoin(t *testing.T) {
	t.Run("ready-and-stop", func(t *testing.T) {
		source := &publicRelayLifecycleFixture{}
		g := publicRelayRuntimeFixture(t, source)
		if err := g.Start(); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(g.public.SocketPath)
		if err != nil || info.Mode().Perm() != 0600 || info.Mode()&os.ModeSocket == 0 {
			t.Fatalf("socket mode: %v %v", info, err)
		}
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", g.public.SocketPath)
		}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: time.Second}
		response, err := client.Get("http://unix/relay/v1/head")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || string(body) != "fixture-ready" {
			t.Fatal("owned handler was not served")
		}
		if g.Start() == nil || source.starts.Load() != 1 {
			t.Fatal("duplicate Start reacquired source")
		}
		if err := g.Stop(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(g.public.SocketPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("owned socket remains", err)
		}
		select {
		case <-g.serveDone:
		default:
			t.Fatal("Serve was not joined")
		}
		if g.Start() == nil || g.Stop() != nil || source.stops.Load() != 1 {
			t.Fatal("stopped lifecycle restarted or closed source twice")
		}
	})
	t.Run("readiness-failure", func(t *testing.T) {
		source := &publicRelayLifecycleFixture{start: func() error { return errors.New("fixture source unavailable") }}
		g := publicRelayRuntimeFixture(t, source)
		if g.Start() == nil || source.stops.Load() != 1 || g.listener != nil {
			t.Fatal("failed readiness exposed a listener or leaked source")
		}
		if _, err := os.Lstat(g.public.SocketPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("failed readiness created socket")
		}
	})
	t.Run("existing-file", func(t *testing.T) {
		g := publicRelayRuntimeFixture(t, &publicRelayLifecycleFixture{})
		if err := os.WriteFile(g.public.SocketPath, []byte("preserve"), 0600); err != nil {
			t.Fatal(err)
		}
		if g.Start() == nil {
			t.Fatal("existing path was admitted")
		}
		raw, _ := os.ReadFile(g.public.SocketPath)
		if string(raw) != "preserve" {
			t.Fatal("existing path was changed")
		}
	})
	t.Run("existing-socket", func(t *testing.T) {
		g := publicRelayRuntimeFixture(t, &publicRelayLifecycleFixture{})
		other, err := net.ListenUnix("unix", &net.UnixAddr{Name: g.public.SocketPath, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		if g.Start() == nil {
			t.Fatal("occupied Unix socket was admitted")
		}
		conn, err := net.DialTimeout("unix", g.public.SocketPath, time.Second)
		if err != nil {
			t.Fatal("preexisting listener was removed or closed", err)
		}
		conn.Close()
	})
	t.Run("replacement-preserved", func(t *testing.T) {
		g := publicRelayRuntimeFixture(t, &publicRelayLifecycleFixture{})
		if err := g.Start(); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(g.public.SocketPath); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(g.public.SocketPath, []byte("replacement"), 0600); err != nil {
			t.Fatal(err)
		}
		if g.Stop() == nil {
			t.Fatal("replacement was not reported")
		}
		raw, _ := os.ReadFile(g.public.SocketPath)
		if string(raw) != "replacement" {
			t.Fatal("replacement was removed")
		}
	})
}

func TestPublicRelayStopDuringReadinessCannotCreateLateSocket(t *testing.T) {
	entered, cancelled, released := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	source := &publicRelayLifecycleFixture{
		start: func() error { close(entered); <-cancelled; <-released; return nil },
		stop:  func() error { once.Do(func() { close(cancelled) }); return nil },
	}
	g := publicRelayRuntimeFixture(t, source)
	started := make(chan error, 1)
	go func() { started <- g.Start() }()
	<-entered
	stopped := make(chan error, 1)
	go func() { stopped <- g.Stop() }()
	<-cancelled
	select {
	case <-stopped:
		t.Fatal("Stop returned before startup joined")
	default:
	}
	close(released)
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if err := <-started; err == nil {
		t.Fatal("cancelled startup succeeded")
	}
	if g.listener != nil || source.stops.Load() != 1 {
		t.Fatal("late listener or duplicate source stop")
	}
}

func TestPublicRelayAutomaticSocketConfiguration(t *testing.T) {
	path, cfg := publicRelayTestConfig(t)
	cfg.SocketPath = "auto"
	cfg.Mesh = &browserMeshConfiguration{AllowedOrigins: []string{"https://fixture.invalid"}}
	cfg.KeyID, cfg.SigningKeyPath = "", ""
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"relay.json", "another-common.json"} {
		configPath := filepath.Join(filepath.Dir(path), name)
		if err := os.WriteFile(configPath, raw, 0600); err != nil {
			t.Fatal(err)
		}
		loaded, key, err := loadBrowserPublicRelayConfiguration(configPath)
		want := strings.TrimSuffix(configPath, ".json") + ".sock"
		if err != nil || key != nil || loaded.SocketPath != want {
			t.Fatalf("auto endpoint for %s: got %q, want %q, err %v", name, loaded.SocketPath, want, err)
		}
		if _, err := os.Lstat(want); !os.IsNotExist(err) {
			t.Fatalf("configuration loading created a socket: %v", err)
		}
	}
	if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadBrowserPublicRelayConfiguration(path); err == nil {
		t.Fatal("auto must retain the owner-only socket directory requirement")
	}
}

func TestPublicRelayMeshConfigurationWithoutHeaderKey(t *testing.T) {
	path, cfg := publicRelayTestConfig(t)
	cfg.Mesh = &browserMeshConfiguration{AllowedOrigins: []string{"https://fixture.invalid"}}
	cfg.KeyID, cfg.SigningKeyPath = "", ""
	write := func(v any) {
		raw, _ := json.Marshal(v)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(cfg)
	loaded, key, err := loadBrowserPublicRelayConfiguration(path)
	if err != nil || key != nil || loaded.Mesh == nil {
		t.Fatalf("mesh-only requires no P-256 key: %v", err)
	}
	g, err := prepareBrowserPublicRelay(publicRelayCLI(true, path, "console", true, "0"))
	if err != nil {
		t.Fatal("Common miner preparation", err)
	}
	_ = g.Close()
	for _, origins := range [][]string{nil, {"http://fixture.invalid"}, {"https://fixture.invalid/"}, {"https://user@fixture.invalid"}, {"https://fixture.invalid", "https://fixture.invalid"}} {
		cfg.Mesh.AllowedOrigins = origins
		write(cfg)
		if _, _, err := loadBrowserPublicRelayConfiguration(path); err == nil {
			t.Fatalf("invalid mesh origins accepted: %v", origins)
		}
	}
	cfg.Mesh.AllowedOrigins = []string{"https://fixture.invalid"}
	for _, field := range []string{"unknown", "AllowedOrigins"} {
		raw, _ := json.Marshal(cfg)
		var obj map[string]any
		_ = json.Unmarshal(raw, &obj)
		obj["mesh"].(map[string]any)[field] = true
		write(obj)
		if _, _, err := loadBrowserPublicRelayConfiguration(path); err == nil {
			t.Fatal("ambiguous mesh configuration accepted")
		}
	}
}

func TestPublicRelayEndpointConfiguration(t *testing.T) {
	path, cfg := publicRelayTestConfig(t)
	cfg.Mesh = &browserMeshConfiguration{AllowedOrigins: []string{"https://gateway.example.org"}, PublicGatewayOrigin: "https://gateway.example.org"}
	cfg.KeyID, cfg.SigningKeyPath = "", ""
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, key, err := loadBrowserPublicRelayConfiguration(path)
	if err != nil || key != nil || loaded.Mesh.PublicGatewayOrigin != cfg.Mesh.PublicGatewayOrigin {
		t.Fatal("valid native-key endpoint configuration", err)
	}
	for _, replacement := range []string{`null`, `"https://127.0.0.1"`, `"https://gateway.example.org/path"`, `"https://gateway.example.org","publicGatewayOrigin":"https://another.example.org"`} {
		modified := strings.Replace(string(raw), `"publicGatewayOrigin":"https://gateway.example.org"`, `"publicGatewayOrigin":`+replacement, 1)
		if err := os.WriteFile(path, []byte(modified), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadBrowserPublicRelayConfiguration(path); err == nil {
			t.Fatalf("invalid endpoint configuration accepted: %s", replacement)
		}
	}
}

func TestPublicRelayGatewayUplinkConfiguration(t *testing.T) {
	path, cfg := publicRelayTestConfig(t)
	cfg.KeyID, cfg.SigningKeyPath = "", ""
	cfg.Mesh = &browserMeshConfiguration{AllowedOrigins: []string{"https://gateway.example.org"}, PublicGatewayOrigin: "https://gateway.example.org", GatewayUplink: true}
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := loadBrowserPublicRelayConfiguration(path)
	if err != nil || !loaded.Mesh.GatewayUplink {
		t.Fatal("uplink config", err)
	}
	for _, value := range []string{`null`, `"true"`, `1`, `true,"gatewayUplink":false`} {
		bad := strings.Replace(string(raw), `"gatewayUplink":true`, `"gatewayUplink":`+value, 1)
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadBrowserPublicRelayConfiguration(path); err == nil {
			t.Fatal("ambiguous uplink accepted", value)
		}
	}
	for _, origin := range []string{"", "https://other.example.org"} {
		cfg.Mesh.PublicGatewayOrigin = origin
		raw, _ = json.Marshal(cfg)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadBrowserPublicRelayConfiguration(path); err == nil {
			t.Fatal("unserved uplink origin accepted")
		}
	}
}
