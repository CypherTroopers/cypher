package node

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	cx "colossusx/colossusx"
	"colossusx/pkg/chain"
	"colossusx/pkg/consensus"
	"colossusx/pkg/p2p"
	"colossusx/pkg/types"
)

type Config struct {
	Chain              types.ChainConfig
	Genesis            types.GenesisConfig
	Mine               bool
	MaxNonces          uint64
	BlockTime          time.Duration
	Logf               func(string, ...any)
	NodeID             string
	ListenAddr         string
	Bootnodes          []string
	MinerBackend       string
	MinerDAGAlloc      string
	ResolvedDAGAlloc   string
	RuntimeInitStatus  string
	MinerExecutionPath string
}

type Node struct {
	cfg       Config
	store     chain.Store
	validator *consensus.Validator
	p2p       *p2p.Server
	mu        sync.RWMutex
}

func New(cfg Config, validator *consensus.Validator, store chain.Store) (*Node, error) {
	if store == nil {
		store = chain.NewMemoryStore()
	}
	if validator == nil {
		return nil, fmt.Errorf("validator is required")
	}
	if cfg.BlockTime <= 0 {
		cfg.BlockTime = time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.NodeID == "" {
		cfg.NodeID = fmt.Sprintf("node-%d", time.Now().UnixNano())
	}
	n := &Node{cfg: cfg, validator: validator, store: store}
	cfg.Logf("node mining configured backend=%s dag_alloc=%s resolved_alloc=%s runtime_init=%s execution=%s", cfg.MinerBackend, cfg.MinerDAGAlloc, cfg.ResolvedDAGAlloc, cfg.RuntimeInitStatus, cfg.MinerExecutionPath)
	n.p2p = p2p.NewServer(p2p.Config{
		NodeID:        cfg.NodeID,
		Network:       cfg.Chain.NetworkID,
		ListenAddr:    cfg.ListenAddr,
		AdvertiseAddr: cfg.ListenAddr,
		Bootnodes:     cfg.Bootnodes,
		Handlers: p2p.Handlers{
			OnPeerConnected:    n.onPeerConnected,
			OnPeerDisconnected: n.onPeerDisconnected,
			OnHello:            n.onHello,
			OnStatus:           n.onStatus,
			OnPing:             n.onPing,
			OnPong:             n.onPong,
			OnNewBlock:         n.onNewBlock,
		},
	})
	return n, nil
}

func (n *Node) Store() chain.Store { return n.store }

func (n *Node) InitGenesis() (types.Block, error) {
	if tip, _, err := n.store.CurrentTip(); err == nil {
		return tip, nil
	}
	genesis := types.NewGenesisBlock(n.cfg.Genesis)
	sealed, res, err := n.validator.SealBlock(genesis, n.cfg.MaxNonces)
	if err != nil {
		return types.Block{}, err
	}
	work := consensus.CalcBlockWork(sealed.Header.Target)
	if err := n.store.StoreBlock(sealed, work); err != nil {
		return types.Block{}, err
	}
	if err := n.store.SetCurrentTip(sealed.BlockHash()); err != nil {
		return types.Block{}, err
	}
	n.cfg.Logf("genesis initialized hash=%s nonce=%d hashes=%d", sealed.BlockHash().String(), sealed.Header.Nonce, res.Hashes)
	return sealed, nil
}

func (n *Node) Run(ctx context.Context) error {
	if _, err := n.InitGenesis(); err != nil {
		return err
	}
	if err := n.p2p.Start(ctx); err != nil {
		return err
	}
	if !n.cfg.Mine {
		<-ctx.Done()
		return ctx.Err()
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		block, res, err := n.mineNextBlock()
		if err != nil {
			return err
		}
		_, becameTip, err := n.validator.InsertBlock(n.store, block)
		if err != nil {
			return err
		}
		n.cfg.Logf("mined block height=%d hash=%s nonce=%d hashes=%d hashrate=%.2fH/s became_tip=%t", block.Header.Height, block.BlockHash().String(), block.Header.Nonce, res.Hashes, res.HashRate, becameTip)
		if becameTip {
			n.broadcastNewBlock(block)
			go n.broadcastStatus()
		}
		timer := time.NewTimer(n.cfg.BlockTime)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (n *Node) mineNextBlock() (types.Block, cx.MineResult, error) {
	tip, _, err := n.store.CurrentTip()
	if err != nil {
		return types.Block{}, cx.MineResult{}, err
	}
	nextHeight := tip.Header.Height + 1
	resolvedSpec := n.cfg.Chain.Spec.ResolvedForHeight(nextHeight)
	header := types.BlockHeader{
		Version:          1,
		AlgorithmVersion: resolvedSpec.AlgorithmVersion,
		Height:           nextHeight,
		ParentHash:       tip.BlockHash(),
		Timestamp:        max(time.Now().Unix(), tip.Header.Timestamp+1),
		Target:           n.cfg.Genesis.Bits,
		EpochSeed:        types.EpochSeedForHeight(resolvedSpec, nextHeight),
		DAGSizeBytes:     resolvedSpec.DAGSizeBytes,
		TxRoot:           sha256.Sum256([]byte(fmt.Sprintf("height:%d", nextHeight))),
		StateRoot:        sha256.Sum256([]byte(tip.BlockHash().String())),
	}
	block := types.Block{Header: header}
	sealed, res, err := n.validator.SealBlock(block, n.cfg.MaxNonces)
	if err != nil {
		return types.Block{}, cx.MineResult{}, err
	}
	return sealed, res, nil
}

func (n *Node) onPeerConnected(peer *p2p.Peer) {
	n.cfg.Logf("peer connected addr=%s inbound=%t", peer.Addr, peer.Inbound)
	go n.sendStatus(peer)
	go func() {
		_ = peer.Send(p2p.Message{Type: p2p.MessagePing, Body: p2p.PingMessage{Timestamp: time.Now().Unix()}})
	}()
}

func (n *Node) onPeerDisconnected(peer *p2p.Peer) {
	n.cfg.Logf("peer disconnected addr=%s id=%s", peer.Addr, peer.ID)
}

func (n *Node) onHello(peer *p2p.Peer, msg p2p.HelloMessage) {
	if msg.Network != n.cfg.Chain.NetworkID {
		n.cfg.Logf("peer network mismatch addr=%s peer_network=%s local_network=%s", peer.Addr, msg.Network, n.cfg.Chain.NetworkID)
		_ = peer.Conn.Close()
		return
	}
	n.cfg.Logf("hello received peer=%s addr=%s version=%s listen=%s", msg.NodeID, peer.Addr, msg.Version, msg.Listen)
	go n.sendStatus(peer)
}

func (n *Node) onStatus(peer *p2p.Peer, msg p2p.StatusMessage) {
	n.cfg.Logf("status received peer=%s height=%d hash=%s total_work=%s", msg.Status.PeerID, msg.Status.BestHeight, msg.Status.BestHash.String(), msg.Status.TotalWork)
}

func (n *Node) onPing(peer *p2p.Peer, msg p2p.PingMessage) {
	n.cfg.Logf("ping received peer=%s ts=%d", peer.ID, msg.Timestamp)
}

func (n *Node) onPong(peer *p2p.Peer, msg p2p.PongMessage) {
	n.cfg.Logf("pong received peer=%s ts=%d", peer.ID, msg.Timestamp)
}

func (n *Node) onNewBlock(peer *p2p.Peer, msg p2p.NewBlockMessage) {
	if msg.Block.BlockHash() == (types.Hash{}) {
		return
	}
	if n.store.HasBlock(msg.Block.BlockHash()) {
		return
	}
	_, becameTip, err := n.validator.InsertBlock(n.store, msg.Block)
	if err != nil {
		n.cfg.Logf("newblock rejected peer=%s err=%v", peer.ID, err)
		return
	}
	n.cfg.Logf("newblock accepted peer=%s height=%d hash=%s became_tip=%t", peer.ID, msg.Block.Header.Height, msg.Block.BlockHash().String(), becameTip)
	if becameTip {
		go n.broadcastStatus()
	}
}

func (n *Node) sendStatus(peer *p2p.Peer) {
	status, err := n.localStatus()
	if err != nil {
		n.cfg.Logf("status build failed: %v", err)
		return
	}
	if err := peer.Send(p2p.Message{Type: p2p.MessageStatus, Body: p2p.StatusMessage{Status: status}}); err != nil {
		n.cfg.Logf("status send failed peer=%s err=%v", peer.Addr, err)
	}
}

func (n *Node) broadcastStatus() {
	status, err := n.localStatus()
	if err != nil {
		n.cfg.Logf("status build failed: %v", err)
		return
	}
	n.p2p.Broadcast(p2p.Message{Type: p2p.MessageStatus, Body: p2p.StatusMessage{Status: status}})
}

func (n *Node) broadcastNewBlock(block types.Block) {
	n.p2p.Broadcast(p2p.Message{Type: p2p.MessageNewBlk, Body: p2p.NewBlockMessage{Block: block}})
}

func (n *Node) localStatus() (types.PeerStatus, error) {
	tip, work, err := n.store.CurrentTip()
	if err != nil {
		return types.PeerStatus{}, err
	}
	return types.PeerStatus{
		PeerID:      n.cfg.NodeID,
		BestHash:    tip.BlockHash(),
		BestHeight:  tip.Header.Height,
		TotalWork:   work.String(),
		ConnectedAt: time.Now().Unix(),
	}, nil
}

func ParseBootnodes(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func FormatWork(work *big.Int) string {
	if work == nil {
		return "0"
	}
	return work.String()
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
