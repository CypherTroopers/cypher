package eth

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/rlp"
	quic "github.com/quic-go/quic-go"
)

const (
	commonTxAdmissionQUICProtocolName  = "cypher-admission-quic/1"
	commonTxAdmissionQUICPortOffset    = 3000
	commonTxAdmissionQUICMaxPayload    = 4 * 1024 * 1024
	commonTxAdmissionQUICQueueSize     = 200000
	commonTxAdmissionQUICMaxBatch      = 4096
	commonTxAdmissionQUICWorkers       = 2
	commonTxAdmissionQUICBatchInterval = 5 * time.Millisecond
	commonTxAdmissionQUICTimeout       = 2 * time.Second
)

var commonTxAdmissionQUICRelays sync.Map // map[*ProtocolManager]*commonTxAdmissionQUICRelay

type commonTxAdmissionQUICRelay struct {
	pm       *ProtocolManager
	listener *quic.Listener
	targets  []string

	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
	wg     sync.WaitGroup

	queue chan []*types.CommonTxAdmission
}

func commonTxAdmissionQUICPort(rnetPort string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(rnetPort))
	if err != nil {
		return 0, err
	}
	return port + commonTxAdmissionQUICPortOffset, nil
}

func commonTxAdmissionQUICAddrFromCommitteeAddress(address string) (string, bool) {
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
	return net.JoinHostPort(host, strconv.Itoa(rnetPort+commonTxAdmissionQUICPortOffset)), true
}

func (pm *ProtocolManager) commonTxAdmissionQUICTargets() []string {
	if pm == nil || pm.chainConfig == nil {
		return nil
	}
	targets := make([]string, 0, len(pm.chainConfig.GenCommittee))
	seen := make(map[string]struct{})
	add := func(address string) {
		target, ok := commonTxAdmissionQUICAddrFromCommitteeAddress(address)
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

func newCommonTxAdmissionQUICRelay(pm *ProtocolManager) (*commonTxAdmissionQUICRelay, error) {
	if pm == nil || pm.chainConfig == nil {
		return nil, errors.New("nil protocol manager or chain config")
	}
	if !pm.commonTxAdmissionTargetedMode() {
		return nil, errors.New("common tx admission QUIC relay is only enabled in fixed committee mode")
	}
	listenPort, err := commonTxAdmissionQUICPort(pm.chainConfig.RnetPort)
	if err != nil {
		return nil, err
	}
	targets := pm.commonTxAdmissionQUICTargets()
	if len(targets) == 0 {
		return nil, errors.New("no fixed committee QUIC targets")
	}
	cert, err := generateTxQUICSelfSignedCert()
	if err != nil {
		return nil, err
	}
	listenAddr := ":" + strconv.Itoa(listenPort)
	listener, err := quic.ListenAddr(listenAddr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{commonTxAdmissionQUICProtocolName},
		MinVersion:   tls.VersionTLS13,
	}, &quic.Config{
		MaxIncomingStreams: 4096,
		KeepAlivePeriod:    10 * time.Second,
		MaxIdleTimeout:     30 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	relay := &commonTxAdmissionQUICRelay{
		pm:       pm,
		listener: listener,
		targets:  targets,
		ctx:      ctx,
		cancel:   cancel,
		queue:    make(chan []*types.CommonTxAdmission, commonTxAdmissionQUICQueueSize),
	}
	relay.wg.Add(1)
	go relay.acceptLoop()
	for i := 0; i < commonTxAdmissionQUICWorkers; i++ {
		relay.wg.Add(1)
		go relay.worker(i)
	}
	log.Info("Started common tx admission QUIC relay", "listen", listenAddr, "targets", len(targets), "queue", commonTxAdmissionQUICQueueSize, "batch", commonTxAdmissionQUICMaxBatch, "interval", commonTxAdmissionQUICBatchInterval)
	return relay, nil
}

func (pm *ProtocolManager) commonTxAdmissionQUICRelay() *commonTxAdmissionQUICRelay {
	if pm == nil {
		return nil
	}
	if value, ok := commonTxAdmissionQUICRelays.Load(pm); ok {
		if relay, ok := value.(*commonTxAdmissionQUICRelay); ok {
			return relay
		}
	}
	relay, err := newCommonTxAdmissionQUICRelay(pm)
	if err != nil {
		log.Debug("Common tx admission QUIC relay unavailable", "err", err)
		return nil
	}
	actual, loaded := commonTxAdmissionQUICRelays.LoadOrStore(pm, relay)
	if loaded {
		relay.stop()
		if existing, ok := actual.(*commonTxAdmissionQUICRelay); ok {
			return existing
		}
		return nil
	}
	core.SetCommonRPCAdmissionDedicatedRelay(func(admissions []*types.CommonTxAdmission) {
		if !relay.Broadcast(admissions) {
			if !pm.broadcastCommonTxAdmissionsKCPOnly(admissions) {
				pm.broadcastCommonTxAdmissionsExcept(admissions, "")
			}
		}
	})
	return relay
}

func (r *commonTxAdmissionQUICRelay) stop() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		if r.cancel != nil {
			r.cancel()
		}
		if r.listener != nil {
			_ = r.listener.Close()
		}
		r.wg.Wait()
	})
}

func (r *commonTxAdmissionQUICRelay) Broadcast(admissions []*types.CommonTxAdmission) bool {
	if r == nil || len(admissions) == 0 || len(r.targets) == 0 || r.queue == nil {
		return false
	}
	valid := make([]*types.CommonTxAdmission, 0, len(admissions))
	for _, admission := range admissions {
		if admission == nil {
			continue
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
			log.Warn("Skip QUIC broadcasting invalid common tx admission", "err", err)
			continue
		}
		valid = append(valid, copyCommonTxAdmissionForRelay(admission))
	}
	if len(valid) == 0 {
		return false
	}
	select {
	case r.queue <- valid:
		return true
	default:
		log.Warn("Common tx admission QUIC queue full", "count", len(valid), "queue", commonTxAdmissionQUICQueueSize)
		return false
	}
}

func copyCommonTxAdmissionForRelay(admission *types.CommonTxAdmission) *types.CommonTxAdmission {
	if admission == nil {
		return nil
	}
	copy := *admission
	if admission.ChainID != nil {
		copy.ChainID = new(big.Int).Set(admission.ChainID)
	}
	if len(admission.Signature) > 0 {
		copy.Signature = append([]byte(nil), admission.Signature...)
	}
	return &copy
}

func (r *commonTxAdmissionQUICRelay) worker(id int) {
	defer r.wg.Done()
	ticker := time.NewTicker(commonTxAdmissionQUICBatchInterval)
	defer ticker.Stop()
	batch := make([]*types.CommonTxAdmission, 0, commonTxAdmissionQUICMaxBatch)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		out := append([]*types.CommonTxAdmission(nil), batch...)
		batch = batch[:0]
		r.forwardBatch(out)
	}
	for {
		select {
		case <-r.ctx.Done():
			flush()
			return
		case admissions := <-r.queue:
			for _, admission := range admissions {
				if admission == nil {
					continue
				}
				batch = append(batch, admission)
				if len(batch) >= commonTxAdmissionQUICMaxBatch {
					flush()
				}
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (r *commonTxAdmissionQUICRelay) forwardBatch(admissions []*types.CommonTxAdmission) {
	if len(admissions) == 0 {
		return
	}
	payload, err := rlp.EncodeToBytes(admissions)
	if err != nil {
		log.Warn("Failed to encode common tx admissions for QUIC", "err", err, "count", len(admissions))
		return
	}
	if len(payload) > commonTxAdmissionQUICMaxPayload && len(admissions) > 1 {
		mid := len(admissions) / 2
		r.forwardBatch(admissions[:mid])
		r.forwardBatch(admissions[mid:])
		return
	}
	if len(payload) > commonTxAdmissionQUICMaxPayload {
		log.Warn("Common tx admission QUIC payload too large", "size", len(payload), "count", len(admissions))
		return
	}
	for _, target := range r.targets {
		target := target
		go func() {
			if err := sendCommonTxAdmissionQUIC(r.ctx, payload, target); err != nil {
				log.Debug("Failed to send common tx admission QUIC", "target", target, "count", len(admissions), "err", err)
			}
		}()
	}
}

func sendCommonTxAdmissionQUIC(parent context.Context, payload []byte, target string) error {
	ctx, cancel := context.WithTimeout(parent, commonTxAdmissionQUICTimeout)
	defer cancel()
	conn, err := quic.DialAddr(ctx, target, &tls.Config{
		NextProtos:         []string{commonTxAdmissionQUICProtocolName},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}, &quic.Config{MaxIdleTimeout: commonTxAdmissionQUICTimeout})
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "done")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()
	_ = stream.SetWriteDeadline(time.Now().Add(commonTxAdmissionQUICTimeout))
	_, err = stream.Write(payload)
	return err
}

func (r *commonTxAdmissionQUICRelay) acceptLoop() {
	defer r.wg.Done()
	for {
		conn, err := r.listener.Accept(r.ctx)
		if err != nil {
			select {
			case <-r.ctx.Done():
				return
			default:
				log.Debug("Common tx admission QUIC accept failed", "err", err)
				continue
			}
		}
		r.wg.Add(1)
		go r.handleConn(conn)
	}
}

func (r *commonTxAdmissionQUICRelay) handleConn(conn *quic.Conn) {
	defer r.wg.Done()
	defer conn.CloseWithError(0, "closed")
	for {
		stream, err := conn.AcceptStream(r.ctx)
		if err != nil {
			select {
			case <-r.ctx.Done():
				return
			default:
				return
			}
		}
		r.wg.Add(1)
		go r.handleStream(conn.RemoteAddr().String(), stream)
	}
}

func (r *commonTxAdmissionQUICRelay) handleStream(from string, stream *quic.Stream) {
	defer r.wg.Done()
	defer stream.Close()
	_ = stream.SetReadDeadline(time.Now().Add(30 * time.Second))
	payload, err := io.ReadAll(io.LimitReader(stream, commonTxAdmissionQUICMaxPayload+1))
	if err != nil {
		log.Warn("Failed to read common tx admission QUIC", "from", from, "err", err)
		return
	}
	if len(payload) == 0 || len(payload) > commonTxAdmissionQUICMaxPayload {
		log.Warn("Invalid common tx admission QUIC payload", "from", from, "size", len(payload))
		return
	}
	var admissions []*types.CommonTxAdmission
	if err := rlp.DecodeBytes(payload, &admissions); err != nil {
		log.Warn("Failed to decode common tx admissions from QUIC", "from", from, "err", err)
		return
	}
	r.handleAdmissions(admissions, from)
}

func (r *commonTxAdmissionQUICRelay) handleAdmissions(admissions []*types.CommonTxAdmission, from string) {
	if r == nil || r.pm == nil || len(admissions) == 0 {
		return
	}
	accepted := make([]*types.CommonTxAdmission, 0, len(admissions))
	for _, admission := range admissions {
		if admission == nil {
			continue
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
			log.Warn("Received invalid common tx admission from QUIC", "from", from, "err", err)
			continue
		}
		if core.StoreCommonRPCAdmission(admission) {
			accepted = append(accepted, admission)
		}
	}
	if len(accepted) == 0 {
		return
	}
	log.Trace("Accepted common tx admissions from QUIC", "from", from, "count", len(accepted))
	r.pm.broadcastAcceptedCommonTxAdmissions(accepted, "")
}
