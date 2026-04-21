package node

import (
	colossusx "github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/p2p"
)

// RegisterColossusXProtocol registers the colossusX/1 devp2p subprotocol.
func (n *Node) RegisterColossusXProtocol(cfg colossusx.Config, handlers colossusx.Handlers) {
	cfg.Logger = n.log
	n.RegisterProtocols([]p2p.Protocol{colossusx.MakeProtocol(cfg, handlers)})
}
