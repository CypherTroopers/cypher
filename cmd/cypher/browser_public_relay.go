package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cypherium/cypher/eth"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/node"
	"github.com/cypherium/cypher/node/browserrelay"
	"github.com/cypherium/cypher/node/lightnode"
	cli "gopkg.in/urfave/cli.v1"
)

var browserPublicRelayEnabledFlag = cli.BoolFlag{Name: "browser.public-relay", Usage: "Enable configured Common browser mesh and optional signed headers through an owner-only local endpoint"}
var browserPublicRelayConfigFlag = cli.StringFlag{Name: "browser.public-relay.config", Usage: "Absolute owner-controlled Common browser relay configuration"}
var browserPublicRelayOwners sync.Map

type browserPublicRelayConfiguration struct {
	Enabled        bool                      `json:"enabled"`
	SocketPath     string                    `json:"socketPath"`
	Network        lightnode.Network         `json:"network"`
	SourceID       string                    `json:"sourceId"`
	KeyID          string                    `json:"keyId,omitempty"`
	SigningKeyPath string                    `json:"signingKeyPath,omitempty"`
	Mesh           *browserMeshConfiguration `json:"mesh,omitempty"`
}

// The exporter borrows the existing Common database. Only its own snapshots,
// HTTP service and socket are owned here; the signing key is not a wallet key.
type browserPublicRelayStartup struct {
	mu                   sync.Mutex
	public               browserPublicRelayConfiguration
	key                  *ecdsa.PrivateKey
	source               node.Lifecycle
	handler              http.Handler
	http                 *http.Server
	listener             net.Listener
	ctx                  context.Context
	cancel               context.CancelFunc
	closed, started      bool
	startDone, serveDone chan struct{}
	closeDone            chan struct{}
	closeErr             error
	owner                *node.Node
}

func prepareBrowserPublicRelay(ctx *cli.Context) (*browserPublicRelayStartup, error) {
	enabled := ctx.GlobalBool(browserPublicRelayEnabledFlag.Name)
	path := ctx.GlobalString(browserPublicRelayConfigFlag.Name)
	if !enabled {
		if path != "" {
			return nil, errors.New("browser.public-relay.config requires explicit browser.public-relay")
		}
		return nil, nil // No configuration, key, database or socket access.
	}
	if ctx.Command.Name != "" && ctx.Command.Name != "console" {
		return nil, errors.New("browser relay requires an ordinary Common or console command")
	}
	public, key, err := loadBrowserPublicRelayConfiguration(path)
	if err != nil {
		return nil, err
	}
	stopCtx, cancel := context.WithCancel(context.Background())
	return &browserPublicRelayStartup{public: public, key: key, ctx: stopCtx, cancel: cancel}, nil
}

func bindBrowserPublicRelay(stack *node.Node, g *browserPublicRelayStartup) {
	if g != nil {
		g.owner = stack
		browserPublicRelayOwners.Store(stack, g)
	}
}

func initializeBrowserPublicRelay(cfg *gethConfig, stack *node.Node, backend *eth.EthAPIBackend) error {
	g := cfg.browserPublicRelay
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
	// AutoRole/ingress switches are not an identity boundary. A configured
	// committee key must never expose the browser endpoint, even with AutoRole off.
	if chain := backend.ChainConfig(); chain != nil && q.CommitteePublicKey != "" {
		for _, member := range chain.GenCommittee {
			if strings.EqualFold(strings.TrimPrefix(q.CommitteePublicKey, "0x"), strings.TrimPrefix(member.Public, "0x")) {
				return errors.New("committee identity cannot enable browser relay")
			}
		}
	}
	var exporter *browserrelay.Exporter
	if g.key != nil {
		var err error
		exporter, err = browserrelay.New(browserrelay.Config{
			Factory: lightnode.NativeFactory(backend.ChainDb()), Network: g.public.Network,
			SourceID: g.public.SourceID, KeyID: g.public.KeyID, SigningKey: g.key,
			PollInterval: 2 * time.Second, SourceTimeout: 2 * time.Second, ManifestTTL: 30 * time.Second,
		})
		if err != nil {
			return err
		}
	}
	if err := initializeBrowserMesh(g, stack, backend, exporter); err != nil {
		return err
	}
	// Reverse lifecycle shutdown joins export work before eth closes its DB.
	stack.RegisterLifecycle(g)
	return nil
}

func (g *browserPublicRelayStartup) Start() (result error) {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	if g.closed || g.startDone != nil || g.started {
		g.mu.Unlock()
		return errors.New("public-header exporter cannot start twice or after close")
	}
	g.startDone = make(chan struct{})
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		close(g.startDone)
		g.mu.Unlock()
		if result != nil {
			result = errors.Join(result, g.Close())
		}
	}()
	if g.source == nil || g.handler == nil {
		return errors.New("public-header exporter is unbound")
	}
	// Start performs the bounded initial network/header read synchronously.
	// Do not expose a listener until that readiness check has succeeded.
	if err := g.source.Start(); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return errors.New("public-header exporter startup was cancelled")
	}
	listener, err := listenPublicRelaySocket(g.public.SocketPath)
	if err != nil {
		return err
	}
	connections := 8
	if g.public.Mesh != nil {
		// Leave room for authentication and lease renewal beside the browser WSs.
		connections = browserrelay.MeshMaxSessions + 8
	}
	g.listener = &boundedLightnodeListener{Listener: listener, slots: make(chan struct{}, connections)}
	g.http = &http.Server{Handler: g.handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second,
		WriteTimeout: 3 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096,
		BaseContext: func(net.Listener) context.Context { return g.ctx }}
	g.started = true
	log.Info("Browser relay listening", "endpoint", g.public.SocketPath)
	g.serveDone = make(chan struct{})
	go func() {
		defer close(g.serveDone)
		_ = g.http.Serve(g.listener)
	}()
	return nil
}

func (g *browserPublicRelayStartup) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	if g.closed {
		done := g.closeDone
		g.mu.Unlock()
		<-done
		return g.closeErr
	}
	g.closed, g.closeDone = true, make(chan struct{})
	if g.owner != nil {
		browserPublicRelayOwners.Delete(g.owner)
	}
	if g.cancel != nil {
		g.cancel()
	}
	source, startDone := g.source, g.startDone
	g.mu.Unlock()
	var result error
	if source != nil {
		result = source.Stop()
	}
	if startDone != nil {
		<-startDone
	}
	if g.http != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		result = errors.Join(result, g.http.Shutdown(ctx), g.http.Close())
		cancel()
	}
	if g.listener != nil {
		if err := g.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, err)
		}
	}
	if g.serveDone != nil {
		<-g.serveDone
	}
	g.mu.Lock()
	g.key = nil
	g.closeErr = result
	close(g.closeDone)
	g.mu.Unlock()
	return result
}

func (g *browserPublicRelayStartup) Stop() error { return g.Close() }

// Exact objects reject aliases, duplicate keys, missing keys and trailing data.
func publicRelayObject(raw []byte, names ...string) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("public-header configuration must be an exact JSON object")
	}
	allowed := make(map[string]bool, len(names))
	required := make(map[string]bool, len(names))
	for _, name := range names {
		optional := len(name) > 0 && name[len(name)-1] == '?'
		if optional {
			name = name[:len(name)-1]
		} else {
			required[name] = true
		}
		allowed[name] = true
	}
	fields := make(map[string]json.RawMessage, len(names))
	for d.More() {
		token, err = d.Token()
		name, ok := token.(string)
		if err != nil || !ok || !allowed[name] || fields[name] != nil {
			return nil, errors.New("unknown or duplicate public-header configuration key")
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, errors.New("invalid public-header configuration value")
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errors.New("null configuration value")
		}
		fields[name] = value
	}
	if _, err := d.Token(); err != nil || d.Decode(new(any)) != io.EOF {
		return nil, errors.New("missing public-header configuration keys or trailing data")
	}
	for name := range required {
		if fields[name] == nil {
			return nil, errors.New("missing configuration key")
		}
	}
	return fields, nil
}

func loadBrowserPublicRelayConfiguration(path string) (browserPublicRelayConfiguration, *ecdsa.PrivateKey, error) {
	var cfg browserPublicRelayConfiguration
	raw, err := readPublicRelayFile(path, false)
	if err != nil {
		return cfg, nil, err
	}
	fields, err := publicRelayObject(raw, "enabled", "socketPath", "network", "sourceId", "keyId?", "signingKeyPath?", "mesh?")
	if err != nil {
		return cfg, nil, err
	}
	if _, err := publicRelayObject(fields["network"], "chainId", "genesisHash"); err != nil {
		return cfg, nil, err
	}
	if json.Unmarshal(raw, &cfg) != nil || !cfg.Enabled || cfg.SourceID == "" || len(cfg.SourceID) > 128 {
		return cfg, nil, errors.New("explicit enabled configuration and bounded source ID are required")
	}
	if err := browserrelay.ValidateNetwork(cfg.Network); err != nil {
		return cfg, nil, err
	}
	if meshRaw, ok := fields["mesh"]; ok {
		if _, err := publicRelayObject(meshRaw, "allowedOrigins", "publicGatewayOrigin?", "gatewayUplink?"); err != nil {
			return cfg, nil, err
		}
		if err := validateBrowserMeshConfiguration(cfg.Mesh); err != nil {
			return cfg, nil, err
		}
	}
	cfg.SocketPath, err = resolvePublicRelaySocketPath(path, cfg.SocketPath)
	if err != nil {
		return cfg, nil, err
	}
	if err := validatePublicRelaySocketPath(cfg.SocketPath); err != nil {
		return cfg, nil, err
	}
	if cfg.Mesh != nil && cfg.KeyID == "" && cfg.SigningKeyPath == "" {
		return cfg, nil, nil
	}
	if cfg.KeyID == "" || cfg.SigningKeyPath == "" {
		return cfg, nil, errors.New("header export requires both keyId and signingKeyPath")
	}
	rawKey, err := readPublicRelayFile(cfg.SigningKeyPath, true)
	if err != nil {
		return cfg, nil, err
	}
	defer clear(rawKey)
	block, rest := pem.Decode(rawKey)
	if !bytes.HasPrefix(bytes.TrimSpace(rawKey), []byte("-----BEGIN PRIVATE KEY-----")) || block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return cfg, nil, errors.New("public-header signing key must be one unencrypted PKCS8 PEM private key")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return cfg, nil, errors.New("public-header signing key must use ECDSA P-256")
	}
	return cfg, key, nil
}
