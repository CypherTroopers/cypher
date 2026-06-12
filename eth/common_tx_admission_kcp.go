package eth

import (
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/rlp"
	kcp "github.com/xtaci/kcp-go"
)

const (
	commonTxAdmissionKCPPortOffset = 1000
	commonTxAdmissionKCPMaxPayload = 2 * 1024 * 1024
)

var (
	commonTxAdmissionKCPMagic  = [4]byte{'C', 'T', 'A', 'D'}
	commonTxAdmissionKCPRelays sync.Map // map[*ProtocolManager]*commonTxAdmissionKCPRelay
)

type commonTxAdmissionKCPRelay struct {
	pm       *ProtocolManager
	listener *kcp.Listener
	targets  []string
	once     sync.Once
}

func commonTxAdmissionKCPPort(rnetPort string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(rnetPort))
	if err != nil {
		return 0, err
	}
	return port + commonTxAdmissionKCPPortOffset, nil
}

func commonTxAdmissionKCPAddrFromCommitteeAddress(address string) (string, bool) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", false
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return "", false
	}
	rnetPort, err := strconv.Atoi(portText)
	if err != nil {
		return "", false
	}
	return net.JoinHostPort(host, strconv.Itoa(rnetPort+commonTxAdmissionKCPPortOffset)), true
}

func (pm *ProtocolManager) commonTxAdmissionKCPTargets() []string {
	if pm == nil || pm.chainConfig == nil {
		return nil
	}
	targets := make([]string, 0, len(pm.chainConfig.GenCommittee))
	seen := make(map[string]struct{})
	add := func(address string) {
		target, ok := commonTxAdmissionKCPAddrFromCommitteeAddress(address)
		if !ok {
			return
		}
		key := strings.ToLower(target)
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
	}

	if leader, ok := pm.chainConfig.GenCommittee[0]; ok {
		add(leader.Address)
	}
	for i := 0; i < len(pm.chainConfig.GenCommittee); i++ {
		if i == 0 {
			continue
		}
		if member, ok := pm.chainConfig.GenCommittee[i]; ok {
			add(member.Address)
		}
	}
	for i, member := range pm.chainConfig.GenCommittee {
		if i >= 0 && i < len(pm.chainConfig.GenCommittee) {
			continue
		}
		add(member.Address)
	}
	return targets
}

func tuneCommonTxAdmissionKCPSession(session *kcp.UDPSession) {
	if session == nil {
		return
	}
	session.SetNoDelay(1, 10, 2, 1)
	session.SetWindowSize(128, 512)
	session.SetStreamMode(true)
	session.SetACKNoDelay(true)
}

func writeCommonTxAdmissionKCPFrame(conn net.Conn, payload []byte) error {
	if len(payload) == 0 {
		return errors.New("empty common tx admission payload")
	}
	if len(payload) > commonTxAdmissionKCPMaxPayload {
		return errors.New("common tx admission KCP payload too large")
	}
	header := make([]byte, 8)
	copy(header[:4], commonTxAdmissionKCPMagic[:])
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

func readCommonTxAdmissionKCPFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, 8)
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if string(header[:4]) != string(commonTxAdmissionKCPMagic[:]) {
		return nil, errors.New("invalid common tx admission KCP frame magic")
	}
	size := binary.BigEndian.Uint32(header[4:])
	if size == 0 || size > commonTxAdmissionKCPMaxPayload {
		return nil, errors.New("invalid common tx admission KCP frame size")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func newCommonTxAdmissionKCPRelay(pm *ProtocolManager) (*commonTxAdmissionKCPRelay, error) {
	if pm == nil || pm.chainConfig == nil {
		return nil, errors.New("nil protocol manager or chain config")
	}
	if !pm.commonTxAdmissionTargetedMode() {
		return nil, errors.New("common tx admission KCP relay is only enabled in fixed committee mode")
	}
	listenPort, err := commonTxAdmissionKCPPort(pm.chainConfig.RnetPort)
	if err != nil {
		return nil, err
	}
	targets := pm.commonTxAdmissionKCPTargets()
	if len(targets) == 0 {
		return nil, errors.New("no fixed committee KCP targets")
	}
	listenAddr := ":" + strconv.Itoa(listenPort)
	listener, err := kcp.ListenWithOptions(listenAddr, nil, 10, 3)
	if err != nil {
		return nil, err
	}
	relay := &commonTxAdmissionKCPRelay{pm: pm, listener: listener, targets: targets}
	go relay.acceptLoop()
	log.Info("Started common tx admission KCP relay", "listen", listenAddr, "targets", len(targets))
	return relay, nil
}

func (pm *ProtocolManager) commonTxAdmissionKCPRelay() *commonTxAdmissionKCPRelay {
	if pm == nil {
		return nil
	}
	if value, ok := commonTxAdmissionKCPRelays.Load(pm); ok {
		if relay, ok := value.(*commonTxAdmissionKCPRelay); ok {
			return relay
		}
	}
	relay, err := newCommonTxAdmissionKCPRelay(pm)
	if err != nil {
		log.Debug("Common tx admission KCP relay unavailable", "err", err)
		return nil
	}
	actual, loaded := commonTxAdmissionKCPRelays.LoadOrStore(pm, relay)
	if loaded {
		relay.stop()
		if existing, ok := actual.(*commonTxAdmissionKCPRelay); ok {
			return existing
		}
		return nil
	}
	return relay
}

func (pm *ProtocolManager) broadcastCommonTxAdmissionsKCPOnly(admissions []*types.CommonTxAdmission) bool {
	relay := pm.commonTxAdmissionKCPRelay()
	if relay == nil {
		return false
	}
	return relay.Broadcast(admissions)
}


func (pm *ProtocolManager) broadcastAcceptedCommonTxAdmissions(admissions []*types.CommonTxAdmission, exceptPeerID string) {
	pm.broadcastCommonTxAdmissionsDedicated(admissions)
	pm.broadcastCommonTxAdmissionsExcept(admissions, exceptPeerID)
}

func (r *commonTxAdmissionKCPRelay) stop() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		if r.listener != nil {
			r.listener.Close()
		}
	})
}

func (r *commonTxAdmissionKCPRelay) Broadcast(admissions []*types.CommonTxAdmission) bool {
	if r == nil || len(admissions) == 0 || len(r.targets) == 0 {
		return false
	}
	valid := make([]*types.CommonTxAdmission, 0, len(admissions))
	for _, admission := range admissions {
		if admission == nil {
			continue
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
			log.Warn("Skip KCP broadcasting invalid common tx admission", "err", err)
			continue
		}
		copy := *admission
		if admission.ChainID != nil {
			copy.ChainID = new(big.Int).Set(admission.ChainID)
		}
		if len(admission.Signature) > 0 {
			copy.Signature = append([]byte(nil), admission.Signature...)
		}
		valid = append(valid, &copy)
	}
	if len(valid) == 0 {
		return false
	}
	payload, err := rlp.EncodeToBytes(valid)
	if err != nil {
		log.Warn("Failed to encode common tx admissions for KCP", "err", err)
		return false
	}
	if len(payload) > commonTxAdmissionKCPMaxPayload {
		log.Warn("Common tx admission KCP payload too large", "size", len(payload))
		return false
	}
	for _, target := range r.targets {
		target := target
		go func() {
			if err := sendCommonTxAdmissionKCP(payload, target); err != nil {
				log.Debug("Failed to send common tx admission KCP", "target", target, "count", len(valid), "err", err)
			}
		}()
	}
	return true
}

func sendCommonTxAdmissionKCP(payload []byte, target string) error {
	session, err := kcp.DialWithOptions(target, nil, 10, 3)
	if err != nil {
		return err
	}
	defer session.Close()
	tuneCommonTxAdmissionKCPSession(session)
	return writeCommonTxAdmissionKCPFrame(session, payload)
}

func (r *commonTxAdmissionKCPRelay) acceptLoop() {
	for {
		session, err := r.listener.AcceptKCP()
		if err != nil {
			return
		}
		tuneCommonTxAdmissionKCPSession(session)
		go r.handleSession(session)
	}
}

func (r *commonTxAdmissionKCPRelay) handleSession(session *kcp.UDPSession) {
	defer session.Close()
	from := session.RemoteAddr()
	payload, err := readCommonTxAdmissionKCPFrame(session)
	if err != nil {
		log.Warn("Failed to read common tx admission KCP", "from", from, "err", err)
		return
	}
	var admissions []*types.CommonTxAdmission
	if err := rlp.DecodeBytes(payload, &admissions); err != nil {
		log.Warn("Failed to decode common tx admissions from KCP", "from", from, "err", err)
		return
	}
	r.handleAdmissions(admissions, from.String())
}

func (r *commonTxAdmissionKCPRelay) handleAdmissions(admissions []*types.CommonTxAdmission, from string) {
	if r == nil || r.pm == nil || len(admissions) == 0 {
		return
	}
	accepted := make([]*types.CommonTxAdmission, 0, len(admissions))
	for _, admission := range admissions {
		if admission == nil {
			continue
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
			log.Warn("Received invalid common tx admission from KCP", "from", from, "err", err)
			continue
		}
		if core.StoreCommonRPCAdmission(admission) {
			accepted = append(accepted, admission)
		}
	}
	if len(accepted) == 0 {
		return
	}
	log.Trace("Accepted common tx admissions from KCP", "from", from, "count", len(accepted))
	r.pm.broadcastAcceptedCommonTxAdmissions(accepted, "")
}
