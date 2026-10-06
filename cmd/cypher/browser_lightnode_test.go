package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cypherium/cypher/eth"
	"github.com/cypherium/cypher/node/lightnode"
	cli "gopkg.in/urfave/cli.v1"
)

func TestLightnodeOrdinaryCommonDefaultTransportNeedsNoTxQUICBridge(t *testing.T) {
	cfg := &gethConfig{Eth: eth.DefaultConfig}
	if cfg.Eth.TxQUIC.Enabled || cfg.Eth.TxQUIC.BridgeEnabled || cfg.Eth.TxQUIC.HTTP3Enabled {
		t.Fatal("ordinary Common transport defaults unexpectedly enabled")
	}
	if err := initializeBrowserLightnode(cfg, nil, nil); err != nil {
		t.Fatalf("disabled overlay changed ordinary startup: %v", err)
	}
	cfg.browserLightnode = &browserLightnodeStartup{}
	// eth.New establishes this flag from the existing chain configuration.
	// No bridge, ingress, HTTP/3, source or listener is enabled by this fixture.
	cfg.Eth.TxQUIC.FairHotstuff = true
	err := initializeBrowserLightnode(cfg, nil, nil)
	if err == nil || err.Error() != "Common backend is missing" {
		t.Fatalf("ordinary Common was stopped by a transport role assumption: %v", err)
	}
	if cfg.Eth.TxQUIC.Enabled || cfg.Eth.TxQUIC.BridgeEnabled || cfg.Eth.TxQUIC.HTTP3Enabled || !cfg.Eth.TxQUIC.FairHotstuff {
		t.Fatal("read-only overlay changed existing transport facts")
	}
	for _, role := range []struct{ ingress, fairHotstuff bool }{{true, true}, {false, false}} {
		cfg.Eth.TxQUIC.Enabled, cfg.Eth.TxQUIC.FairHotstuff = role.ingress, role.fairHotstuff
		err := initializeBrowserLightnode(cfg, nil, nil)
		if err == nil || err.Error() == "Common backend is missing" {
			t.Fatalf("unsafe role reached the backend boundary: %+v: %v", role, err)
		}
	}
	if g := cfg.browserLightnode; g.factory != nil || g.handler != nil || g.listener != nil {
		t.Fatal("role checks acquired source or listener resources")
	}
}

func TestLightnodeStartupOrdinaryConsoleKeepsPermissionGuards(t *testing.T) {
	path := filepath.Join(t.TempDir(), "public.json")
	data := `{"enabled":true,"listenAddr":"127.0.0.1:18083","allowedPageOrigin":"http://127.0.0.1:18081","network":{"chainId":10101919,"genesisHash":"0x` + strings.Repeat("1", 64) + `"}}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		command string
		mine    bool
		unlock  string
		allowed bool
	}{
		{"", false, "", true}, {"console", false, "", true},
		{"init", false, "", false}, {"attach", false, "", false},
		{"js", false, "", false}, {"dumpconfig", false, "", false},
		{"console", true, "", false}, {"console", false, "0", false},
	} {
		flags := flag.NewFlagSet("ordinary Common launcher", flag.ContinueOnError)
		flags.Bool("browser.lightnode", true, "")
		flags.String("browser.lightnode.config", path, "")
		flags.Bool("mine", test.mine, "")
		flags.String("unlock", test.unlock, "")
		ctx := cli.NewContext(cli.NewApp(), flags, nil)
		ctx.Command = cli.Command{Name: test.command}
		startup, err := prepareBrowserLightnode(ctx)
		if test.allowed {
			if err != nil || startup == nil || startup.factory != nil || startup.listener != nil {
				t.Fatalf("ordinary %q startup rejected or acquired resources: %v", test.command, err)
			}
			startup.Close()
		} else if err == nil || startup != nil {
			t.Fatalf("command %q mine=%v unlock=%q bypassed permission guard", test.command, test.mine, test.unlock)
		}
	}
}

type lightnodeLifecycleFixture struct {
	closes  *atomic.Int32
	network lightnode.Network
}

func (v *lightnodeLifecycleFixture) Network() lightnode.Network                   { return v.network }
func (v *lightnodeLifecycleFixture) LatestHeight(context.Context) (uint64, error) { return 42, nil }
func (v *lightnodeLifecycleFixture) HeaderRLP(context.Context, uint64, int) ([]byte, error) {
	return nil, errors.New("synthetic lifecycle fixture does not serve headers")
}
func (v *lightnodeLifecycleFixture) Close() error { v.closes.Add(1); return nil }

func syntheticLightnodeStartup(t *testing.T, address string, factory lightnode.Factory) *browserLightnodeStartup {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	network := lightnode.Network{ChainID: 10101919, GenesisHash: "0x" + strings.Repeat("1", 64)}
	handler, err := lightnode.New(lightnode.Config{Enabled: true, ListenAddr: address, AllowedPageOrigin: "http://127.0.0.1:18081", ExpectedNetwork: network, Factory: factory})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	g := &browserLightnodeStartup{public: lightnode.PublicConfiguration{Enabled: true, ListenAddr: address, AllowedPageOrigin: "http://127.0.0.1:18081", Network: network}, factory: factory, handler: handler, ctx: ctx, cancel: cancel}
	t.Cleanup(func() { g.Close() })
	return g
}

func TestLightnodeStartupBindFailureReleasesContextAndOwnView(t *testing.T) {
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	var closes atomic.Int32
	factory := func(context.Context) (lightnode.View, error) {
		return &lightnodeLifecycleFixture{&closes, lightnode.Network{ChainID: 10101919, GenesisHash: "0x" + strings.Repeat("1", 64)}}, nil
	}
	g := syntheticLightnodeStartup(t, hold.Addr().String(), factory)
	if g.Start() == nil {
		t.Fatal("occupied listener unexpectedly admitted")
	}
	if !g.closed || g.ctx.Err() != context.Canceled || closes.Load() != 1 || g.listener != nil {
		t.Fatal("bind failure did not release exactly the owned readiness view and context")
	}
}

func TestLightnodeStartupCancelPreventsLateListener(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var closes atomic.Int32
	factory := func(context.Context) (lightnode.View, error) {
		close(entered)
		<-release
		return &lightnodeLifecycleFixture{&closes, lightnode.Network{ChainID: 10101919, GenesisHash: "0x" + strings.Repeat("1", 64)}}, nil
	}
	g := syntheticLightnodeStartup(t, "127.0.0.1:18083", factory)
	done := make(chan error, 1)
	go func() { done <- g.Start() }()
	<-entered
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("late readiness result revived service")
	}
	if closes.Load() != 1 || g.listener != nil {
		t.Fatal("late snapshot or listener leaked")
	}
}

func TestLightnodeStartupDoubleStartAndStopOnlyOwnResources(t *testing.T) {
	port, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := port.Addr().String()
	port.Close()
	var opens, closes atomic.Int32
	factory := func(context.Context) (lightnode.View, error) {
		opens.Add(1)
		return &lightnodeLifecycleFixture{&closes, lightnode.Network{ChainID: 10101919, GenesisHash: "0x" + strings.Repeat("1", 64)}}, nil
	}
	g := syntheticLightnodeStartup(t, address, factory)
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	if g.Start() == nil || opens.Load() != 1 || closes.Load() != 1 {
		t.Fatal("duplicate startup did source work")
	}
	if err := g.Stop(); err != nil {
		t.Fatal(err)
	}
	if g.Start() == nil || opens.Load() != 1 {
		t.Fatal("closed lifecycle reopened source")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal("owned listener remained bound:", err)
	}
	listener.Close()
}
