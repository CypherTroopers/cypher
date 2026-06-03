package reconfig

import (
	"sort"
	"sync"
	"time"

	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rnet/network"
)

type commonMinerHeartbeatMsg struct {
	KeyBlockNumber uint64
	BlockNumber    uint64
	CoinBase       string
	Public         string
	Address        string
	Timestamp      uint64
}

type CommonMinerStatus struct {
	CoinBase       string `json:"coinbase"`
	Public         string `json:"public"`
	Address        string `json:"address"`
	LastSeenUnix   uint64 `json:"lastSeenUnix"`
	LastSeenAgoSec uint64 `json:"lastSeenAgoSec"`
	LastKeyBlock   uint64 `json:"lastKeyBlock"`
	LastBlock      uint64 `json:"lastBlock"`
	HeartbeatCount uint64 `json:"heartbeatCount"`
	UptimeScore    uint64 `json:"uptimeScore"`
}

type commonMinerStatusEntry struct {
	coinbase       string
	public         string
	address        string
	lastSeen       time.Time
	lastSeenUnix   uint64
	lastKeyBlock   uint64
	lastBlock      uint64
	heartbeatCount uint64
}

var commonMinerStatusStore = struct {
	sync.RWMutex
	miners map[string]*commonMinerStatusEntry
}{
	miners: make(map[string]*commonMinerStatusEntry),
}

func (s *Service) commonMinerHeartbeatMsgAck(si *network.ServerIdentity, msg *commonMinerHeartbeatMsg) {
	if msg == nil {
		return
	}
	if msg.Address == "" && si != nil {
		msg.Address = si.Address.String()
	}
	recordCommonMinerHeartbeat(msg)
}

func recordCommonMinerHeartbeat(msg *commonMinerHeartbeatMsg) {
	if msg == nil || msg.Public == "" || msg.CoinBase == "" {
		return
	}
	key := msg.Public
	now := time.Now()
	commonMinerStatusStore.Lock()
	entry := commonMinerStatusStore.miners[key]
	if entry == nil {
		entry = &commonMinerStatusEntry{}
		commonMinerStatusStore.miners[key] = entry
	}
	entry.coinbase = msg.CoinBase
	entry.public = msg.Public
	entry.address = msg.Address
	entry.lastSeen = now
	entry.lastSeenUnix = uint64(now.Unix())
	entry.lastKeyBlock = msg.KeyBlockNumber
	entry.lastBlock = msg.BlockNumber
	entry.heartbeatCount++
	commonMinerStatusStore.Unlock()

	log.Debug("common miner heartbeat", "coinbase", msg.CoinBase, "address", msg.Address, "keyBlock", msg.KeyBlockNumber, "block", msg.BlockNumber)
}

func snapshotCommonMinerStatuses() []CommonMinerStatus {
	now := time.Now()
	commonMinerStatusStore.RLock()
	result := make([]CommonMinerStatus, 0, len(commonMinerStatusStore.miners))
	for _, entry := range commonMinerStatusStore.miners {
		if entry == nil {
			continue
		}
		ago := uint64(0)
		if !entry.lastSeen.IsZero() && now.After(entry.lastSeen) {
			ago = uint64(now.Sub(entry.lastSeen).Seconds())
		}
		result = append(result, CommonMinerStatus{
			CoinBase:       entry.coinbase,
			Public:         entry.public,
			Address:        entry.address,
			LastSeenUnix:   entry.lastSeenUnix,
			LastSeenAgoSec: ago,
			LastKeyBlock:   entry.lastKeyBlock,
			LastBlock:      entry.lastBlock,
			HeartbeatCount: entry.heartbeatCount,
			UptimeScore:    heartbeatUptimeScore(ago),
		})
	}
	commonMinerStatusStore.RUnlock()

	sort.Slice(result, func(i, j int) bool {
		if result[i].UptimeScore == result[j].UptimeScore {
			if result[i].HeartbeatCount == result[j].HeartbeatCount {
				return result[i].CoinBase < result[j].CoinBase
			}
			return result[i].HeartbeatCount > result[j].HeartbeatCount
		}
		return result[i].UptimeScore > result[j].UptimeScore
	})
	return result
}

func heartbeatUptimeScore(lastSeenAgoSec uint64) uint64 {
	// First-stage testnet scoring:
	// 100 = heartbeat seen within 30 seconds
	// 80  = within 60 seconds
	// 60  = within 120 seconds
	// 30  = within 300 seconds
	// 0   = stale or never seen recently
	switch {
	case lastSeenAgoSec <= 30:
		return 100
	case lastSeenAgoSec <= 60:
		return 80
	case lastSeenAgoSec <= 120:
		return 60
	case lastSeenAgoSec <= 300:
		return 30
	default:
		return 0
	}
}

func (s *netService) commonMinerHeartbeatLoop() {
	for !s.isStoping {
		if s.chainConfig == nil || !s.chainConfig.CommonApprovalEnabled {
			time.Sleep(2 * time.Second)
			continue
		}
		// Validator HotStuff members are the fixed finality layer, not common miners.
		// They must not pollute common miner uptime/candidate status.
		if bftview.IamMember() >= 0 && !s.isConfiguredCommonApprover() {
			time.Sleep(10 * time.Second)
			continue
		}
		public := bftview.GetServerInfo(bftview.PublicKey)
		coinbase := bftview.GetServerCoinBase().String()
		if public == "" || coinbase == "" {
			time.Sleep(2 * time.Second)
			continue
		}
		msg := &commonMinerHeartbeatMsg{
			KeyBlockNumber: s.kbc.CurrentBlockN(),
			BlockNumber:    s.bc.CurrentBlockN(),
			CoinBase:       coinbase,
			Public:         public,
			Address:        s.serverAddress,
			Timestamp:      uint64(time.Now().Unix()),
		}
		s.recordLocalCommonMinerHeartbeat(msg)
		s.sendCommonMinerHeartbeat(msg)
		time.Sleep(10 * time.Second)
	}
}

func (s *netService) isConfiguredCommonApprover() bool {
	if s == nil || s.chainConfig == nil {
		return false
	}
	public := bftview.GetServerInfo(bftview.PublicKey)
	address := bftview.GetServerAddress()
	for _, node := range s.chainConfig.CommonCommittee {
		if node.Public != "" && node.Public == public {
			return true
		}
		if node.Address != "" && node.Address == address {
			return true
		}
	}
	return false
}

func (s *netService) recordLocalCommonMinerHeartbeat(msg *commonMinerHeartbeatMsg) {
	recordCommonMinerHeartbeat(msg)
}

func (s *netService) sendCommonMinerHeartbeat(msg *commonMinerHeartbeatMsg) {
	seen := make(map[string]struct{})
	if mb := bftview.GetCurrentMember(); mb != nil {
		for _, node := range mb.List {
			if node == nil || node.Address == "" || IsSelf(node.Address) {
				continue
			}
			seen[node.Address] = struct{}{}
		}
	}
	for _, node := range s.chainConfig.CommonCommittee {
		if node.Address == "" || IsSelf(node.Address) {
			continue
		}
		seen[node.Address] = struct{}{}
	}
	for address := range seen {
		si := network.NewServerIdentity(address)
		go s.SendRaw(si, msg, false)
	}
}
