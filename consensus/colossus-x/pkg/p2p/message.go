package p2p

import "colossusx/pkg/types"

type Message struct {
	Type string `json:"type"`
	Body any    `json:"body,omitempty"`
}

const (
	MessageHello  = "hello"
	MessageStatus = "status"
	MessagePing   = "ping"
	MessagePong   = "pong"
	MessageNewBlk = "newblock"
)

type HelloMessage struct {
	NodeID  string `json:"node_id"`
	Network string `json:"network"`
	Version string `json:"version"`
	Listen  string `json:"listen"`
}

type StatusMessage struct {
	Status types.PeerStatus `json:"status"`
}

type PingMessage struct {
	Timestamp int64 `json:"timestamp"`
}

type PongMessage struct {
	Timestamp int64 `json:"timestamp"`
}

type NewBlockMessage struct {
	Block types.Block `json:"block"`
}
