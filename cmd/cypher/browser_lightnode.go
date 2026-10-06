package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cypherium/cypher/cmd/utils"
	"github.com/cypherium/cypher/eth"
	"github.com/cypherium/cypher/node"
	"github.com/cypherium/cypher/node/lightnode"
	cli "gopkg.in/urfave/cli.v1"
)

var browserLightnodeEnabledFlag = cli.BoolFlag{Name: "browser.lightnode", Usage: "Enable the bounded loopback Common recent-header communication overlay; no mining or chain import"}
var browserLightnodeConfigFlag = cli.StringFlag{Name: "browser.lightnode.config", Usage: "Absolute owner-approved public loopback communication configuration"}
var browserLightnodeOwners sync.Map

type browserLightnodeStartup struct {
	mu                sync.Mutex
	public            lightnode.PublicConfiguration
	factory           lightnode.Factory
	handler           *lightnode.Server
	http              *http.Server
	listener          net.Listener
	ctx               context.Context
	cancel            context.CancelFunc
	closed            bool
	starting, started bool
	owner             *node.Node
}

func bindBrowserLightnode(stack *node.Node, g *browserLightnodeStartup) {
	if g == nil {
		return
	}
	g.owner = stack
	browserLightnodeOwners.Store(stack, g)
}

func prepareBrowserLightnode(ctx *cli.Context) (*browserLightnodeStartup, error) {
	enabled := ctx.GlobalBool(browserLightnodeEnabledFlag.Name)
	path := ctx.GlobalString(browserLightnodeConfigFlag.Name)
	if !enabled {
		if path != "" {
			return nil, errors.New("browser.lightnode.config requires explicit browser.lightnode")
		}
		return nil, nil // Original startup does not read a config, snapshot or socket.
	}
	// The user's ordinary Common launcher runs its local console. Permit that
	// same node-owning startup, while attach, init and script commands stay out.
	if (ctx.Command.Name != "" && ctx.Command.Name != "console") || ctx.GlobalBool(utils.MiningEnabledFlag.Name) || strings.TrimSpace(ctx.GlobalString(utils.UnlockedAccountFlag.Name)) != "" {
		return nil, errors.New("browser light-node communication requires the ordinary locked non-mining Common command")
	}
	public, err := lightnode.LoadPublicConfiguration(path)
	if err != nil {
		return nil, err
	}
	stopCtx, cancel := context.WithCancel(context.Background())
	return &browserLightnodeStartup{public: public, ctx: stopCtx, cancel: cancel}, nil
}

func initializeBrowserLightnode(cfg *gethConfig, stack *node.Node, backend *eth.EthAPIBackend) error {
	g := cfg.browserLightnode
	if g == nil {
		return nil
	}
	q := cfg.Eth.TxQUIC
	if err := (lightnode.CommonRole{Ingress: q.Enabled, FairHotstuff: q.FairHotstuff}).Validate(); err != nil {
		return err
	}
	if backend == nil {
		return errors.New("Common backend is missing")
	}
	g.factory = lightnode.NativeFactory(backend.ChainDb()) // Borrow the shared DB; views own only their snapshots.
	handler, err := lightnode.New(lightnode.Config{Enabled: true, ListenAddr: g.public.ListenAddr,
		AllowedPageOrigin: g.public.AllowedPageOrigin, ExpectedNetwork: g.public.Network, Factory: g.factory})
	if err != nil {
		return err
	}
	g.handler = handler
	// Node stops lifecycles in reverse order: revoke browser leases before eth closes its DB.
	stack.RegisterLifecycle(g)
	return nil
}

func (g *browserLightnodeStartup) Start() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	if g.closed || g.starting || g.started {
		g.mu.Unlock()
		return errors.New("Common communication lifecycle cannot start twice or after close")
	}
	g.starting = true
	g.mu.Unlock()
	defer func() { g.mu.Lock(); g.starting = false; g.mu.Unlock() }()
	if g.factory == nil {
		return errors.Join(errors.New("Common communication source is unbound"), g.Close())
	}
	ctx, cancel := context.WithTimeout(g.ctx, 2*time.Second)
	view, err := g.factory(ctx)
	if err == nil && view == nil {
		err = errors.New("Common snapshot factory returned no view")
	}
	if view != nil {
		if err == nil && view.Network() != g.public.Network {
			err = errors.New("Common snapshot network does not match owner pins")
		}
		if err == nil {
			_, err = view.LatestHeight(ctx)
		}
		err = errors.Join(err, view.Close())
	}
	if err == nil {
		err = ctx.Err()
	}
	cancel()
	if err != nil {
		return errors.Join(err, g.Close())
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return errors.New("Common communication startup was cancelled")
	}
	listener, err := net.Listen("tcp", g.public.ListenAddr)
	if err != nil {
		g.mu.Unlock()
		return errors.Join(err, g.Close())
	}
	g.listener = &boundedLightnodeListener{Listener: listener, slots: make(chan struct{}, 8)}
	g.http = &http.Server{Handler: g.handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second,
		WriteTimeout: 3 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096,
		BaseContext: func(net.Listener) context.Context { return g.ctx }}
	g.started = true
	server, ownedListener := g.http, g.listener
	g.mu.Unlock()
	go func() { _ = server.Serve(ownedListener) }()
	return nil
}

func (g *browserLightnodeStartup) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	if g.owner != nil {
		browserLightnodeOwners.Delete(g.owner)
	}
	if g.cancel != nil {
		g.cancel()
	}
	handler, server, listener := g.handler, g.http, g.listener
	g.mu.Unlock()
	var result error
	if handler != nil {
		result = handler.Close()
	}
	if server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		result = errors.Join(result, server.Shutdown(ctx), server.Close())
		cancel()
	}
	// Serve may not yet have registered its listener when an immediate Stop
	// races startup. Always close the separately owned listener as well.
	if listener != nil {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, err)
		}
	}
	return result
}
func (g *browserLightnodeStartup) Stop() error { return g.Close() }

type boundedLightnodeListener struct {
	net.Listener
	slots chan struct{}
}

func (l *boundedLightnodeListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &boundedLightnodeConn{Conn: conn, slots: l.slots}, nil
		default:
			_ = conn.Close()
		}
	}
}

type boundedLightnodeConn struct {
	net.Conn
	slots chan struct{}
	once  sync.Once
}

func (c *boundedLightnodeConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.slots })
	return err
}
