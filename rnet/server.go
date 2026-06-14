package rnet

import (
	"fmt"
	"sync"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/rnet/network"
	"rsc.io/goversion/version"
)

// Server connects the Router and the Services together. It sets
// up everything and returns once a working network has been set up.
type Server struct {
	*network.Router
	serviceManager *serviceManager
	//	statusReporterStruct *statusReporterStruct
	// protocols holds a map of all available protocols and how to create an
	// instance of it
	//protocols *protocolStorage
	// when this node has been started
	started time.Time
	// once everything's up and running
	closeitChannel chan bool
	IsStarted      bool
}

// NewServer returns a fresh Server tied to a given Router.
// If dbPath is "", the server will write its database to the default
// location. If dbPath is != "", it is considered a temp dir, and the
// DB is deleted on close.
func newServer(r *network.Router) *Server {
	c := &Server{
		//	statusReporterStruct: newStatusReporterStruct(),
		Router:         r,
		closeitChannel: make(chan bool),
	}
	c.serviceManager = newServiceManager(c)
	return c
}

func NewKcpServer(addr string) *Server {
	serverIdentity := network.NewServerIdentityWithTransport(addr, network.PlainKCP)
	return NewServerKCPWithListenAddr(serverIdentity, "")
}

func NewQuicServer(addr string) *Server {
	serverIdentity := network.NewServerIdentityWithTransport(addr, network.PlainQUIC)
	return NewServerQUICWithListenAddr(serverIdentity, "")
}

func NewTcpServer(addr string) *Server {
	serverIdentity := network.NewServerIdentityWithTransport(addr, network.PlainTCP)
	return NewServerTCPWithListenAddr(serverIdentity, "")
}

func NewFallbackServer(addr string) *Server {
	serverIdentity := network.NewServerIdentityWithTransport(addr, network.PlainQUIC)
	return NewServerFallbackWithListenAddr(serverIdentity, "")
}

func NewServerWithTransport(addr, transport, fallback string) *Server {
	switch transport {
	case "", "quic":
		if fallback == "" || fallback == "tcp" {
			return NewFallbackServer(addr)
		}
		return NewQuicServer(addr)
	case "tcp":
		return NewTcpServer(addr)
	case "kcp":
		return NewKcpServer(addr)
	default:
		return NewFallbackServer(addr)
	}
}

// NewServerKCPWithListenAddr returns a new Server out of a private-key and
// its related address within the ServerIdentity. The server will use a
// KcpRouter listening on the given address as Router.
func newServerFromRouter(r *network.Router, err error, transport string) *Server {
	if err != nil {
		panic(fmt.Sprintf("failed to create %s rnet server: %v", transport, err))
	}
	if r == nil {
		panic(fmt.Sprintf("failed to create %s rnet server: nil router", transport))
	}
	return newServer(r)
}

func NewServerKCPWithListenAddr(e *network.ServerIdentity, listenAddr string) *Server {
	r, err := network.NewKCPRouterWithListenAddr(e, listenAddr)
	return newServerFromRouter(r, err, "kcp")
}

func NewServerQUICWithListenAddr(e *network.ServerIdentity, listenAddr string) *Server {
	r, err := network.NewQUICRouterWithListenAddr(e, listenAddr)
	return newServerFromRouter(r, err, "quic")
}

func NewServerTCPWithListenAddr(e *network.ServerIdentity, listenAddr string) *Server {
	r, err := network.NewTCPRouterWithListenAddr(e, listenAddr)
	return newServerFromRouter(r, err, "tcp")
}

func NewServerFallbackWithListenAddr(e *network.ServerIdentity, listenAddr string) *Server {
	r, err := network.NewFallbackRouterWithListenAddr(e, listenAddr)
	return newServerFromRouter(r, err, "fallback")
}

var gover version.Version
var goverOnce sync.Once
var goverOk = false

// Close closes the  Router
func (c *Server) Close() error {
	c.Lock()
	if c.IsStarted {
		// c.closeitChannel <- true
		c.IsStarted = false
	}
	c.Unlock()
	err := c.Router.Stop()
	log.Warn("Close", "Host Close", c.ServerIdentity.Address, "listening?", c.Router.Listening())
	return err
}

// Address returns the address used by the Router.
func (c *Server) Address() network.Address {
	return c.ServerIdentity.Address
}

// Service returns the service with the given name.
func (c *Server) Service(name string) Service {
	return c.serviceManager.service(name)
}

// GetService is kept for backward-compatibility.
func (c *Server) GetService(name string) Service {
	log.Warn("This method is deprecated - use `Server.Service` instead")
	return c.Service(name)
}

// Start makes the router listen on their respective
// ports. It returns once all servers are started.
func (c *Server) Start() {
	c.started = time.Now()
	log.Info(fmt.Sprintf("Starting server at %s on address %s ", c.started.Format("2006-01-02 15:04:05"), c.ServerIdentity.Address))
	go c.Router.Start()
	for !c.Router.Listening() {
		time.Sleep(50 * time.Millisecond)
	}
	c.Lock()
	c.IsStarted = true
	c.Unlock()
	// Wait for closing of the channel
	//<-c.closeitChannel
}

// CloseConnect close remote connection
func (c *Server) AdjustConnect(list []*common.Cnode) {
}
