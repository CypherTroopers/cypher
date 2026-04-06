package colossusx

import (
	"fmt"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/p2p"
)

const (
	ProtocolName    = "colossusX"
	ProtocolVersion = uint(1)
	ProtocolLength  = uint64(5)
)

const (
	HelloMsg uint64 = iota
	StatusMsg
	PingMsg
	PongMsg
	NewBlockMsg
)

type Config struct {
	NodeID  string
	Network string
	Version string
	Logger  log.Logger
}

type HelloPacket struct {
	NodeID  string
	Network string
	Version string
}

type StatusPacket struct {
	NodeID      string
	BestHash    common.Hash
	BestNumber  uint64
	TotalWeight *big.Int
}

type PingPacket struct {
	Timestamp int64
}

type PongPacket struct {
	Timestamp int64
}

type NewBlockPacket struct {
	Block *types.Block
}

type Handlers struct {
	OnPeerConnected    func(peer *p2p.Peer) error
	OnPeerDisconnected func(peer *p2p.Peer)
	OnHello            func(peer *p2p.Peer, msg *HelloPacket) error
	OnStatus           func(peer *p2p.Peer, msg *StatusPacket) error
	OnPing             func(peer *p2p.Peer, msg *PingPacket) error
	OnPong             func(peer *p2p.Peer, msg *PongPacket) error
	OnNewBlock         func(peer *p2p.Peer, msg *NewBlockPacket) error
	LocalStatus        func(peer *p2p.Peer) (*StatusPacket, error)
}

func MakeProtocol(cfg Config, handlers Handlers) p2p.Protocol {
	logger := cfg.Logger
	if logger == nil {
		logger = log.New()
	}
	if cfg.Version == "" {
		cfg.Version = "1"
	}
	return p2p.Protocol{
		Name:    ProtocolName,
		Version: ProtocolVersion,
		Length:  ProtocolLength,
		Run: func(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
			if handlers.OnPeerConnected != nil {
				if err := handlers.OnPeerConnected(peer); err != nil {
					return err
				}
			}
			defer func() {
				if handlers.OnPeerDisconnected != nil {
					handlers.OnPeerDisconnected(peer)
				}
			}()

			hello := &HelloPacket{NodeID: cfg.NodeID, Network: cfg.Network, Version: cfg.Version}
			if err := p2p.Send(rw, HelloMsg, hello); err != nil {
				return err
			}
			if handlers.LocalStatus != nil {
				status, err := handlers.LocalStatus(peer)
				if err != nil {
					return err
				}
				if status != nil {
					if err := p2p.Send(rw, StatusMsg, status); err != nil {
						return err
					}
				}
			}

			for {
				msg, err := rw.ReadMsg()
				if err != nil {
					return err
				}
				switch msg.Code {
				case HelloMsg:
					var packet HelloPacket
					if err := msg.Decode(&packet); err != nil {
						return err
					}
					if handlers.OnHello != nil {
						if err := handlers.OnHello(peer, &packet); err != nil {
							return err
						}
					}
				case StatusMsg:
					var packet StatusPacket
					if err := msg.Decode(&packet); err != nil {
						return err
					}
					if handlers.OnStatus != nil {
						if err := handlers.OnStatus(peer, &packet); err != nil {
							return err
						}
					}
				case PingMsg:
					var packet PingPacket
					if err := msg.Decode(&packet); err != nil {
						return err
					}
					if handlers.OnPing != nil {
						if err := handlers.OnPing(peer, &packet); err != nil {
							return err
						}
					}
					if err := p2p.Send(rw, PongMsg, &PongPacket{Timestamp: packet.Timestamp}); err != nil {
						return err
					}
				case PongMsg:
					var packet PongPacket
					if err := msg.Decode(&packet); err != nil {
						return err
					}
					if handlers.OnPong != nil {
						if err := handlers.OnPong(peer, &packet); err != nil {
							return err
						}
					}
				case NewBlockMsg:
					var packet NewBlockPacket
					if err := msg.Decode(&packet); err != nil {
						return err
					}
					if handlers.OnNewBlock != nil {
						if err := handlers.OnNewBlock(peer, &packet); err != nil {
							return err
						}
					}
				default:
					logger.Warn("Received unknown colossusX message", "code", msg.Code, "peer", peer.ID())
					if err := msg.Discard(); err != nil {
						return err
					}
					return fmt.Errorf("colossusX: unsupported message code %d", msg.Code)
				}
			}
		},
	}
}
