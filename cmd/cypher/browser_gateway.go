// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"errors"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/cypherium/cypher/cmd/cypher/browserstartup"
	"github.com/cypherium/cypher/cmd/utils"
	"github.com/cypherium/cypher/eth"
	"github.com/cypherium/cypher/internal/debug"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/node"
	cli "gopkg.in/urfave/cli.v1"
)

var browserGatewayEnabledFlag = cli.BoolFlag{Name: "browser.gateway", Usage: "Explicitly attach the optional proof gateway to the existing Common RPC HTTP/3 service"}
var browserGatewayTLSFlag = cli.BoolFlag{Name: "browser.gateway.tls", Usage: "Explicitly add an owned proof-only TCP TLS first-contact entry; requires browser.gateway"}
var browserGatewayConfigFlag = cli.StringFlag{Name: "browser.gateway.config", Usage: "Public canonical proof gateway configuration"}
var browserGatewayStateFlag = cli.StringFlag{Name: "browser.gateway.state", Usage: "Dedicated precreated proof metadata directory outside node data"}
var browserGatewayRoleFlag = cli.StringFlag{Name: "browser.gateway.role", Usage: "Explicit application role, must be common-rpc"}

type browserGatewayStartup struct {
	controller  *browserstartup.Controller
	factory     browserstartup.Factory
	checkMount  func(*gethConfig) error
	owner       *node.Node
	stateRoot   string
	bindBackend func(*eth.EthAPIBackend) error
	tls         *browserstartup.TLSLifecycle
}

var browserGatewayOwners sync.Map

func prepareBrowserGateway(ctx *cli.Context, cfg *gethConfig) (*browserGatewayStartup, error) {
	o := browserstartup.Options{
		Enabled:         ctx.GlobalBool(browserGatewayEnabledFlag.Name),
		TLS:             ctx.GlobalBool(browserGatewayTLSFlag.Name),
		ConfigPath:      ctx.GlobalString(browserGatewayConfigFlag.Name),
		StateRoot:       ctx.GlobalString(browserGatewayStateFlag.Name),
		Role:            ctx.GlobalString(browserGatewayRoleFlag.Name),
		CommandName:     ctx.Command.Name,
		UnlockRequested: strings.TrimSpace(ctx.GlobalString(utils.UnlockedAccountFlag.Name)) != "",
		MiningRequested: ctx.GlobalBool(utils.MiningEnabledFlag.Name),
	}
	if err := o.Validate(); err != nil {
		return nil, err
	}
	if !o.Enabled {
		return nil, nil
	}
	// SetEthConfig applies CLI transport flags after node.New. Prepare only the
	// dormant mount here; Initialize checks the effective policy before Start.
	return newNativeBrowserGatewayStartup(o, cfg)
}

func (g *browserGatewayStartup) Close() error {
	if g == nil {
		return nil
	}
	if g.owner != nil {
		browserGatewayOwners.Delete(g.owner)
	}
	if g.tls == nil {
		return g.controller.Close()
	}
	// Controller first withdraws its publication, then its wrapped resource
	// cancels TCP and releases only the owned source. Also cancel pre-init TLS.
	return errors.Join(g.controller.Close(), g.tls.Close())
}
func (g *browserGatewayStartup) Start() error {
	if g.tls == nil {
		return g.controller.Start()
	}
	if err := g.controller.Start(); err != nil {
		return errors.Join(err, g.Close())
	}
	if err := g.tls.Start(); err != nil {
		return errors.Join(err, g.Close())
	}
	return nil
}
func (g *browserGatewayStartup) Stop() error { return g.Close() }

func bindBrowserGateway(stack *node.Node, g *browserGatewayStartup) {
	if g == nil {
		return
	}
	g.owner = stack
	browserGatewayOwners.Store(stack, g)
}

// bindBrowserGatewayBackend borrows the existing service backend only for an
// explicitly installed typed binding. The ordinary disabled and pinned IPC
// startup paths preserve their existing behavior and perform no native read.
func bindBrowserGatewayBackend(g *browserGatewayStartup, backend *eth.EthAPIBackend) error {
	if g == nil || g.bindBackend == nil {
		return nil
	}
	return g.bindBackend(backend)
}

func initializeBrowserGateway(cfg *gethConfig) error {
	g := cfg.browserGateway
	if g == nil {
		return nil
	}
	q := cfg.Eth.TxQUIC
	role := browserstartup.Role{HTTP3: q.HTTP3Enabled, Ingress: q.Enabled, Bridge: q.BridgeEnabled, FairHotstuff: q.FairHotstuff}
	if err := role.Validate(); err != nil {
		return browserstartup.CloseOnError(err, g.Close)
	}
	keyStore, err := browserstartup.ConfiguredKeyStore(g.owner.Config().DataDir, g.owner.Config().KeyStoreDir)
	if err != nil {
		return browserstartup.CloseOnError(err, g.Close)
	}
	if err := browserstartup.ValidateStateRoot(g.stateRoot, g.owner.Config().DataDir, g.owner.InstanceDir(), keyStore, resolveBrowserDirectory); err != nil {
		return browserstartup.CloseOnError(err, g.Close)
	}
	if g.checkMount != nil {
		if err := g.checkMount(cfg); err != nil {
			return browserstartup.CloseOnError(err, g.Close)
		}
	}
	// Node stops lifecycles in reverse registration order. Register only after
	// eth.New's existing services, so gateway cancellation precedes their Stop.
	// Synced binding can replace g.factory. Wrap only the final bound factory.
	factory := g.factory
	if g.tls != nil {
		var err error
		factory, err = g.tls.WrapFactory(factory)
		if err != nil {
			return browserstartup.CloseOnError(err, g.Close)
		}
	}
	return g.controller.InitializeAndRegister(role, factory, func() error {
		g.owner.RegisterLifecycle(g)
		return nil
	})
}

func closeBrowserGatewayOwned(stack *node.Node) {
	closeOwned := false
	if value, ok := browserPublicRelayOwners.Load(stack); ok {
		_ = value.(*browserPublicRelayStartup).Close()
		closeOwned = true
	}
	if value, ok := browserGatewayOwners.Load(stack); ok {
		_ = value.(*browserGatewayStartup).Close()
		closeOwned = true
	}
	if value, ok := browserLightnodeOwners.Load(stack); ok {
		_ = value.(*browserLightnodeStartup).Close()
		closeOwned = true
	}
	if closeOwned {
		_ = stack.Close()
	}
}

func startNodeWithBrowserGateway(stack *node.Node) {
	value, ok := browserGatewayOwners.Load(stack)
	lightValue, lightOK := browserLightnodeOwners.Load(stack)
	publicValue, publicOK := browserPublicRelayOwners.Load(stack)
	if !ok && !lightOK && !publicOK {
		utils.StartNode(stack)
		return
	}
	var g *browserGatewayStartup
	if ok {
		g = value.(*browserGatewayStartup)
	}
	var light *browserLightnodeStartup
	if lightOK {
		light = lightValue.(*browserLightnodeStartup)
	}
	var publicRelay *browserPublicRelayStartup
	if publicOK {
		publicRelay = publicValue.(*browserPublicRelayStartup)
	}
	if err := stack.Start(); err != nil {
		_ = browserstartup.CloseOnError(err, publicRelay.Close, light.Close, g.Close, stack.Close)
		utils.Fatalf("Error starting protocol stack: %v", err)
		return
	}
	// Preserve the existing successful-start signal behavior. The registered
	// lifecycle releases the proof controller when stack.Close stops services.
	go func() {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigc)
		<-sigc
		log.Info("Got interrupt, shutting down...")
		go stack.Close()
		for i := 10; i > 0; i-- {
			<-sigc
			if i > 1 {
				log.Warn("Already shutting down, interrupt more to panic.", "times", i-1)
			}
		}
		debug.Exit()
		debug.LoudPanic("boom")
	}()
}
