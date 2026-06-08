package eth

import (
	"net"
	"strconv"
	"strings"

	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/p2p"
)

type commonTxAdmissionTarget struct {
	host string
	port int
}

func parseCommonTxAdmissionTarget(address string) (commonTxAdmissionTarget, bool) {
	address = strings.TrimSpace(address)
	if address == "" {
		return commonTxAdmissionTarget{}, false
	}

	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return commonTxAdmissionTarget{}, false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 {
		return commonTxAdmissionTarget{}, false
	}
	return commonTxAdmissionTarget{host: host, port: port}, host != ""
}

func commonTxAdmissionHostEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ipA := net.ParseIP(a)
	ipB := net.ParseIP(b)
	if ipA != nil && ipB != nil {
		return ipA.Equal(ipB)
	}
	return strings.EqualFold(a, b)
}

func commonTxAdmissionPeerAddrs(p *peer) (nodeHost string, nodeTCP int, remoteHost string, remotePort int) {
	if p == nil {
		return "", 0, "", 0
	}
	if n := p.Node(); n != nil {
		if ip := n.IP(); ip != nil {
			nodeHost = ip.String()
		}
		nodeTCP = n.TCP()
	}
	if addr := p.RemoteAddr(); addr != nil {
		if tcp, ok := addr.(*net.TCPAddr); ok {
			if tcp.IP != nil {
				remoteHost = tcp.IP.String()
			}
			remotePort = tcp.Port
		} else {
			host, portText, err := net.SplitHostPort(addr.String())
			if err == nil {
				remoteHost = host
				remotePort, _ = strconv.Atoi(portText)
			}
		}
	}
	return nodeHost, nodeTCP, remoteHost, remotePort
}

func commonTxAdmissionPeerMatchesTarget(p *peer, target commonTxAdmissionTarget) bool {
	nodeHost, nodeTCP, remoteHost, remotePort := commonTxAdmissionPeerAddrs(p)
	return (commonTxAdmissionHostEqual(nodeHost, target.host) && nodeTCP == target.port) ||
		(commonTxAdmissionHostEqual(remoteHost, target.host) && remotePort == target.port)
}

func commonTxAdmissionPeerMatchesAnyTarget(p *peer, targets []commonTxAdmissionTarget) bool {
	for _, target := range targets {
		if commonTxAdmissionPeerMatchesTarget(p, target) {
			return true
		}
	}
	return false
}

func (pm *ProtocolManager) commonTxAdmissionTargetedMode() bool {
	return pm != nil && pm.chainConfig != nil && (pm.chainConfig.FixedCommittee || pm.chainConfig.FixedLeader)
}

func (pm *ProtocolManager) commonTxAdmissionCommitteeTargets() []commonTxAdmissionTarget {
	if pm == nil || pm.chainConfig == nil {
		return nil
	}
	targets := make([]commonTxAdmissionTarget, 0, len(pm.chainConfig.GenCommittee))
	seen := make(map[string]struct{})
	add := func(address string) {
		target, ok := parseCommonTxAdmissionTarget(address)
		if !ok {
			return
		}
		key := target.host + ":" + strconv.Itoa(target.port)
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
	}

	// Fixed leader is committee index 0 in the current fixed-committee layout.
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

// BroadcastCommonTxAdmissions propagates signed common RPC tx admissions. In
// fixed committee mode this fallback eth/p2p relay is restricted to exact fixed
// leader/committee peers only. The preferred production path is the dedicated
// KCP committee channel installed by reconfig.
func (pm *ProtocolManager) BroadcastCommonTxAdmissions(admissions []*types.CommonTxAdmission) {
	pm.broadcastCommonTxAdmissionsExcept(admissions, "")
}

func (pm *ProtocolManager) broadcastCommonTxAdmissionsExcept(admissions []*types.CommonTxAdmission, exceptPeerID string) {
	if len(admissions) == 0 || pm == nil || pm.peers == nil {
		return
	}
	valid := make([]*types.CommonTxAdmission, 0, len(admissions))
	for _, admission := range admissions {
		if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
			log.Warn("Skip broadcasting invalid common tx admission", "err", err)
			continue
		}
		valid = append(valid, admission)
	}
	if len(valid) == 0 {
		return
	}

	pm.peers.lock.RLock()
	var allPeers []*peer
	for id, ethPeer := range pm.peers.peers {
		if id == exceptPeerID || ethPeer == nil {
			continue
		}
		allPeers = append(allPeers, ethPeer)
	}
	pm.peers.lock.RUnlock()

	sendPeers := allPeers
	if pm.commonTxAdmissionTargetedMode() {
		targets := pm.commonTxAdmissionCommitteeTargets()
		if len(targets) == 0 {
			log.Warn("No fixed committee common tx admission targets")
			return
		}
		exactPeers := make([]*peer, 0, len(allPeers))
		for _, ethPeer := range allPeers {
			if commonTxAdmissionPeerMatchesAnyTarget(ethPeer, targets) {
				exactPeers = append(exactPeers, ethPeer)
			}
		}
		if len(exactPeers) == 0 {
			log.Warn("No exact connected fixed committee peers for common tx admission relay", "targets", len(targets), "count", len(valid))
			return
		}
		sendPeers = exactPeers
	}

	for _, ethPeer := range sendPeers {
		batch := make([]*types.CommonTxAdmission, len(valid))
		for i, admission := range valid {
			copy := *admission
			if len(admission.Signature) > 0 {
				copy.Signature = append([]byte(nil), admission.Signature...)
			}
			batch[i] = &copy
		}
		go func(p *peer, out []*types.CommonTxAdmission) {
			if err := p2p.Send(p.rw, CommonTxAdmissionMsg, out); err != nil {
				log.Debug("Failed to broadcast common tx admissions", "peer", p.id, "count", len(out), "err", err)
			}
		}(ethPeer, batch)
	}
}

func (pm *ProtocolManager) handleCommonTxAdmissionMsg(p *peer, msg p2p.Msg) error {
	var admissions []*types.CommonTxAdmission
	if err := msg.Decode(&admissions); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	accepted := make([]*types.CommonTxAdmission, 0, len(admissions))
	for _, admission := range admissions {
		if admission == nil {
			continue
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
			log.Warn("Received invalid common tx admission", "peer", p.id, "err", err)
			continue
		}
		if core.StoreCommonRPCAdmission(admission) {
			accepted = append(accepted, admission)
		}
	}
	if len(accepted) > 0 {
		log.Trace("Accepted common tx admissions", "peer", p.id, "count", len(accepted))
		pm.broadcastCommonTxAdmissionsExcept(accepted, p.id)
	}
	return nil
}
