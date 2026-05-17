package core

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
)

const powResultUDPMaxPacketSize = 4096

// PoWResultUDPPort derives the fixed-mode PoW result UDP port from the
// consensus UDP port. Keeping it separate avoids colliding with the rnet
// protocol already bound to RnetPort.
func PoWResultUDPPort(rnetPort string) (int, error) {
	port, err := strconv.Atoi(rnetPort)
	if err != nil {
		return 0, err
	}
	return port + 1, nil
}

// BroadcastPoWResultUDP broadcasts a mined PoW result to validators over UDP.
func BroadcastPoWResultUDP(rnetPort string, result *types.PoWResult) error {
	if result == nil {
		return errors.New("nil pow result")
	}
	port, err := PoWResultUDPPort(rnetPort)
	if err != nil {
		return err
	}
	payload, err := rlp.EncodeToBytes(result)
	if err != nil {
		return err
	}
	if len(payload) > powResultUDPMaxPacketSize {
		return errors.New("pow result UDP payload too large")
	}

	var firstErr error
	for _, ip := range []net.IP{net.IPv4bcast, net.IPv4(127, 0, 0, 1)} {
		addr := &net.UDPAddr{IP: ip, Port: port}
		conn, err := net.DialUDP("udp4", nil, addr)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		_, err = conn.Write(payload)
		conn.Close()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

type powResultUDPServer struct {
	conn net.PacketConn
	once sync.Once
}

func (s *powResultUDPServer) stop() {
	s.once.Do(func() {
		if s.conn != nil {
			s.conn.Close()
		}
	})
}

// StartPoWResultUDP starts the fixed-mode UDP listener that accepts compact PoW
// results from miners, reconstructs candidates, verifies them locally and adds
// the verified candidate to the pool for keyblock reward accounting.
func (cp *CandidatePool) StartPoWResultUDP(rnetPort string) error {
	port, err := PoWResultUDPPort(rnetPort)
	if err != nil {
		return err
	}
	addr := ":" + strconv.Itoa(port)
	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return err
	}
	cp.powResultUDP = &powResultUDPServer{conn: conn}
	go cp.powResultUDPLoop(conn)
	log.Info("Started fixed-mode PoW result UDP listener", "addr", addr)
	return nil
}

// StopPoWResultUDP stops the fixed-mode PoW result UDP listener, if present.
func (cp *CandidatePool) StopPoWResultUDP() {
	cp.mu.Lock()
	server := cp.powResultUDP
	cp.powResultUDP = nil
	cp.mu.Unlock()
	if server != nil {
		server.stop()
	}
}

func (cp *CandidatePool) powResultUDPLoop(conn net.PacketConn) {
	buf := make([]byte, powResultUDPMaxPacketSize)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		var result types.PoWResult
		if err := rlp.DecodeBytes(buf[:n], &result); err != nil {
			log.Warn("Failed to decode fixed-mode PoW result", "from", from, "err", err)
			continue
		}
		if err := cp.AddRemotePoWResult(&result); err != nil {
			log.Warn("Rejected fixed-mode PoW result", "from", from, "err", err)
		}
	}
}

// AddRemotePoWResult reconstructs and verifies a UDP PoW result without asking
// the miner to participate in CandidatePool or block/keyblock validation.
func (cp *CandidatePool) AddRemotePoWResult(result *types.PoWResult) error {
	candidate := result.ToCandidate()
	if candidate == nil || candidate.KeyCandidate == nil {
		return errors.New("nil pow result candidate")
	}
	if bftview.GetMemberIndex(candidate.PubKey) >= 0 {
		return ErrCandidateIsMember
	}

	keyBlock := cp.backend.KeyBlockChain().CurrentBlock()
	if keyBlock == nil {
		return types.ErrUnknownAncestor
	}
	if candidate.KeyCandidate.ParentHash != keyBlock.Hash() || candidate.KeyCandidate.Number.Uint64() != keyBlock.NumberU64()+1 {
		return ErrCandidateNumberLow
	}
	if candidate.KeyCandidate.T_Number < keyBlock.T_Number() || candidate.KeyCandidate.T_Number > cp.backend.BlockChain().CurrentBlockN() {
		return errors.New("pow result tx block number is outside the local work range")
	}
	if time.Since(time.Unix(int64(candidate.KeyCandidate.Time), 0)) > 2*time.Hour {
		return errors.New("pow result is stale")
	}

	committeeSize := len(cp.backend.KeyBlockChain().CurrentCommittee())
	if err := cp.backend.Engine().PrepareCandidate(cp.backend.KeyBlockChain(), candidate, committeeSize); err != nil {
		return err
	}
	if err := cp.verify(candidate); err != nil {
		return err
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()
	if exists := cp.candidates.Add(candidate); exists {
		return ErrCandidateExisted
	}
	log.Info("Accepted fixed-mode UDP PoW result", "candidate.number", candidate.KeyCandidate.Number.Uint64(), "pubkey", candidate.PubKey, "hash", candidate.Hash())
	go cp.feed.Send(candidate)
	return nil
}
