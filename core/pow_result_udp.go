package core

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
	kcp "github.com/xtaci/kcp-go"
)

const powResultUDPMaxPacketSize = 64 * 1024

var powResultKCPMagic = [4]byte{'C', 'P', 'W', 'R'}

// PoWResultUDPPort derives the fixed-mode PoW result KCP port from the
// consensus UDP/KCP port. Keeping it separate avoids colliding with the rnet
// protocol already bound to RnetPort. The public function name is kept for
// compatibility with the existing fixed-mode call sites.
func PoWResultUDPPort(rnetPort string) (int, error) {
	port, err := strconv.Atoi(rnetPort)
	if err != nil {
		return 0, err
	}
	return port + 1, nil
}

func appendPoWResultUDPAddr(addrs []net.UDPAddr, seen map[string]struct{}, addr net.UDPAddr) []net.UDPAddr {
	key := addr.String()
	if _, ok := seen[key]; ok {
		return addrs
	}
	seen[key] = struct{}{}
	return append(addrs, addr)
}

func powResultUDPAddrFromCommitteeNode(node *common.Cnode, fallbackPort int) (*net.UDPAddr, error) {
	if node == nil {
		return nil, errors.New("nil committee node")
	}
	address := strings.TrimSpace(node.Address)
	if address == "" {
		return nil, errors.New("empty committee node address")
	}

	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return net.ResolveUDPAddr("udp4", net.JoinHostPort(address, strconv.Itoa(fallbackPort)))
	}

	rnetPort, err := strconv.Atoi(portText)
	if err != nil {
		return nil, err
	}
	return net.ResolveUDPAddr("udp4", net.JoinHostPort(host, strconv.Itoa(rnetPort+1)))
}

func tunePoWResultKCPSession(session *kcp.UDPSession) {
	if session == nil {
		return
	}
	session.SetNoDelay(1, 10, 2, 1)
	session.SetWindowSize(128, 512)
	session.SetStreamMode(true)
	session.SetACKNoDelay(true)
}

func writePoWResultKCPFrame(conn net.Conn, payload []byte) error {
	if len(payload) == 0 {
		return errors.New("empty pow result payload")
	}
	if len(payload) > powResultUDPMaxPacketSize {
		return errors.New("pow result KCP payload too large")
	}
	header := make([]byte, 8)
	copy(header[:4], powResultKCPMagic[:])
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

func readPoWResultKCPFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, 8)
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if string(header[:4]) != string(powResultKCPMagic[:]) {
		return nil, errors.New("invalid pow result KCP frame magic")
	}
	size := binary.BigEndian.Uint32(header[4:])
	if size == 0 || size > powResultUDPMaxPacketSize {
		return nil, errors.New("invalid pow result KCP frame size")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func sendPoWResultUDP(payload []byte, addr net.UDPAddr) error {
	session, err := kcp.DialWithOptions(addr.String(), nil, 10, 3)
	if err != nil {
		return err
	}
	defer session.Close()
	tunePoWResultKCPSession(session)
	return writePoWResultKCPFrame(session, payload)
}

// BroadcastPoWResultUDP broadcasts a mined PoW result to validators over KCP.
// The legacy function name is kept because fixed-mode callers already use it.
func BroadcastPoWResultUDP(rnetPort string, validators []*common.Cnode, result *types.PoWResult) error {
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
		return errors.New("pow result KCP payload too large")
	}

	seen := make(map[string]struct{})
	addrs := make([]net.UDPAddr, 0, len(validators)+1)
	for _, validator := range validators {
		addr, err := powResultUDPAddrFromCommitteeNode(validator, port)
		if err != nil {
			address := ""
			if validator != nil {
				address = validator.Address
			}
			log.Warn("Failed to resolve fixed-mode PoW result validator KCP address", "address", address, "err", err)
			continue
		}
		addrs = appendPoWResultUDPAddr(addrs, seen, *addr)
	}

	// Keep localhost for same-host tests. Broadcast packets are intentionally not
	// used here because KCP is connection-oriented over UDP.
	addrs = appendPoWResultUDPAddr(addrs, seen, net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})

	var firstErr error
	sent := 0
	for _, addr := range addrs {
		if err := sendPoWResultUDP(payload, addr); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			log.Warn("Failed to send fixed-mode PoW result KCP", "addr", addr.String(), "err", err)
			continue
		}
		sent++
		log.Debug("Sent fixed-mode PoW result KCP", "addr", addr.String())
	}
	if sent > 0 {
		return nil
	}
	return firstErr
}

type powResultUDPServer struct {
	listener *kcp.Listener
	once     sync.Once
}

func (s *powResultUDPServer) stop() {
	s.once.Do(func() {
		if s.listener != nil {
			s.listener.Close()
		}
	})
}

// StartPoWResultUDP starts the fixed-mode KCP listener that accepts compact PoW
// results from miners, reconstructs candidates, verifies them locally and adds
// the verified candidate to the pool for keyblock reward accounting. The public
// function name is kept for compatibility with existing fixed-mode code.
func (cp *CandidatePool) StartPoWResultUDP(rnetPort string) error {
	port, err := PoWResultUDPPort(rnetPort)
	if err != nil {
		return err
	}
	addr := ":" + strconv.Itoa(port)
	listener, err := kcp.ListenWithOptions(addr, nil, 10, 3)
	if err != nil {
		return err
	}
	cp.powResultUDP = &powResultUDPServer{listener: listener}
	go cp.powResultUDPLoop(listener)
	log.Info("Started fixed-mode PoW result KCP listener", "addr", addr)
	return nil
}

// StopPoWResultUDP stops the fixed-mode PoW result KCP listener, if present.
func (cp *CandidatePool) StopPoWResultUDP() {
	cp.mu.Lock()
	server := cp.powResultUDP
	cp.powResultUDP = nil
	cp.mu.Unlock()
	if server != nil {
		server.stop()
	}
}

func (cp *CandidatePool) powResultUDPLoop(listener *kcp.Listener) {
	for {
		session, err := listener.AcceptKCP()
		if err != nil {
			return
		}
		tunePoWResultKCPSession(session)
		go cp.handlePoWResultKCPSession(session)
	}
}

func (cp *CandidatePool) handlePoWResultKCPSession(session *kcp.UDPSession) {
	defer session.Close()
	from := session.RemoteAddr()
	payload, err := readPoWResultKCPFrame(session)
	if err != nil {
		log.Warn("Failed to read fixed-mode PoW result KCP", "from", from, "err", err)
		return
	}
	var result types.PoWResult
	if err := rlp.DecodeBytes(payload, &result); err != nil {
		log.Warn("Failed to decode fixed-mode PoW result", "from", from, "err", err)
		return
	}
	if err := cp.AddRemotePoWResult(&result); err != nil {
		log.Warn("Rejected fixed-mode PoW result", "from", from, "err", err)
	}
}

// AddRemotePoWResult reconstructs and verifies a PoW result without asking
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
	log.Info("Accepted fixed-mode KCP PoW result", "candidate.number", candidate.KeyCandidate.Number.Uint64(), "pubkey", candidate.PubKey, "hash", candidate.Hash())
	go cp.feed.Send(candidate)
	return nil
}
