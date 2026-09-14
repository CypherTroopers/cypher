package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
	rnetnetwork "github.com/cypherium/cypher/rnet/network"
	quic "github.com/quic-go/quic-go"
)

const (
	powResultTransportMaxPacketSize     = 64 * 1024
	powResultAckMaxPacketSize           = 4 * 1024
	powResultAckReasonMaxLength         = 512
	powResultProtocolVersion            = uint64(1)
	powResultALPN                       = "cypher-pow-result-v1"
	powResultTLSApplication             = "cypher-pow-result-tls-v1"
	powResultHandshakeTimeout           = 3 * time.Second
	powResultReadTimeout                = 5 * time.Second
	powResultWriteTimeout               = 5 * time.Second
	powResultDeliveryTimeout            = 17 * time.Second
	powResultRetryDelay                 = 250 * time.Millisecond
	powResultRetryMaxDelay              = 4 * time.Second
	powResultDeliveryAttempts           = 2
	powResultMaxIncomingQUICConnections = 64
	powResultMaxIncomingTCPConnections  = 32
	powResultMaxTCPConnectionsPerIP     = 4
	powResultMaxParallelDeliveries      = 128
)

var (
	powResultRequestMagic = [4]byte{'C', 'P', 'W', 'R'}
	powResultAckMagic     = [4]byte{'C', 'P', 'W', 'A'}
)

const (
	powResultAckAccepted  = uint64(1)
	powResultAckDuplicate = uint64(2)
	powResultAckRejected  = uint64(3)

	powResultAckCodeOK             = uint64(0)
	powResultAckCodeRejected       = uint64(1)
	powResultAckCodeInvalidPayload = uint64(2)
	powResultAckCodeReceiverBehind = uint64(3)
)

// PoWResultTransportPort derives the fixed-mode PoW result port from the
// consensus port. QUIC and TLS/TCP use the same numeric port on UDP and TCP.
func PoWResultTransportPort(rnetPort string) (int, error) {
	port, err := strconv.Atoi(rnetPort)
	if err != nil {
		return 0, fmt.Errorf("invalid rnet port %q: %w", rnetPort, err)
	}
	if port < 1 || port >= 65535 {
		return 0, fmt.Errorf("rnet port %d cannot provide a PoW result port", port)
	}
	return port + 1, nil
}

// PoWResultUDPPort is retained for source compatibility. The returned port is
// now used by QUIC and by the authenticated TCP fallback, not KCP.
func PoWResultUDPPort(rnetPort string) (int, error) {
	return PoWResultTransportPort(rnetPort)
}

func powResultEndpointFromCommitteeNode(node *common.Cnode, fallbackPort int) (string, error) {
	if node == nil {
		return "", errors.New("nil committee node")
	}
	address := strings.TrimSpace(node.Address)
	if address == "" {
		return "", errors.New("empty committee node address")
	}

	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		// A host without a port (including an unbracketed IPv6 literal) uses the
		// caller's locally derived fixed-mode port.
		host = address
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		}
		return net.JoinHostPort(host, strconv.Itoa(fallbackPort)), nil
	}
	if strings.TrimSpace(host) == "" {
		return "", errors.New("empty committee node host")
	}
	rnetPort, err := strconv.Atoi(portText)
	if err != nil {
		return "", fmt.Errorf("invalid committee rnet port %q: %w", portText, err)
	}
	if rnetPort < 1 || rnetPort >= 65535 {
		return "", fmt.Errorf("committee rnet port %d cannot provide a PoW result port", rnetPort)
	}
	return net.JoinHostPort(host, strconv.Itoa(rnetPort+1)), nil
}

// powResultUDPAddrFromCommitteeNode remains for compatibility with existing
// address tests and callers. It resolves the new QUIC endpoint.
func powResultUDPAddrFromCommitteeNode(node *common.Cnode, fallbackPort int) (*net.UDPAddr, error) {
	endpoint, err := powResultEndpointFromCommitteeNode(node, fallbackPort)
	if err != nil {
		return nil, err
	}
	return net.ResolveUDPAddr("udp", endpoint)
}

func canonicalPoWResultPublicKey(encoded string) ([]byte, error) {
	publicKey := common.FromHex(strings.TrimSpace(encoded))
	public := bls.GetPublicKey(publicKey)
	if public == nil || !bytes.Equal(public.Serialize(), publicKey) {
		return nil, errors.New("invalid validator BLS public key")
	}
	return append([]byte(nil), publicKey...), nil
}

func powResultTLSIdentity(publicKey []byte, generation common.Hash) []byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(powResultTLSApplication))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(publicKey)
	_, _ = hash.Write(generation[:])
	return hash.Sum(nil)
}

func writeFullPoWResult(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := w.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrNoProgress
		}
		payload = payload[n:]
	}
	return nil
}

func powResultBoundedDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if ctx != nil {
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			return contextDeadline
		}
	}
	return deadline
}

func writePoWResultFrame(w io.Writer, magic [4]byte, payload []byte, maxSize int) error {
	if len(payload) == 0 || len(payload) > maxSize {
		return fmt.Errorf("invalid PoW result frame size %d", len(payload))
	}
	var header [8]byte
	copy(header[:4], magic[:])
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	if err := writeFullPoWResult(w, header[:]); err != nil {
		return err
	}
	return writeFullPoWResult(w, payload)
}

func readPoWResultFrame(r io.Reader, magic [4]byte, maxSize int) ([]byte, error) {
	var header [8]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if !bytes.Equal(header[:4], magic[:]) {
		return nil, errors.New("invalid PoW result frame magic")
	}
	size := binary.BigEndian.Uint32(header[4:])
	if size == 0 || uint64(size) > uint64(maxSize) {
		return nil, fmt.Errorf("invalid PoW result frame size %d", size)
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

type powResultAck struct {
	Version   uint64
	RequestID common.Hash
	Status    uint64
	Code      uint64
	Reason    string
}

type powResultRemoteError struct {
	Code   uint64
	Reason string
}

func (err *powResultRemoteError) retryable() bool {
	return err != nil && err.Code == powResultAckCodeReceiverBehind
}

type powResultRetryableAdmissionError struct {
	err error
}

func (err *powResultRetryableAdmissionError) Error() string {
	if err == nil || err.err == nil {
		return "PoW result receiver is not ready"
	}
	return err.err.Error()
}

func (err *powResultRetryableAdmissionError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.err
}

func (err *powResultRemoteError) Error() string {
	if err.Reason == "" {
		return fmt.Sprintf("validator rejected PoW result (code %d)", err.Code)
	}
	return fmt.Sprintf("validator rejected PoW result (code %d): %s", err.Code, err.Reason)
}

func powResultRequestID(payload []byte) common.Hash {
	digest := sha256.Sum256(payload)
	return common.BytesToHash(digest[:])
}

func encodePoWResultAck(ack powResultAck) ([]byte, error) {
	if len(ack.Reason) > powResultAckReasonMaxLength {
		ack.Reason = ack.Reason[:powResultAckReasonMaxLength]
	}
	return rlp.EncodeToBytes(&ack)
}

func readAndValidatePoWResultAck(r io.Reader, requestID common.Hash) error {
	payload, err := readPoWResultFrame(r, powResultAckMagic, powResultAckMaxPacketSize)
	if err != nil {
		return fmt.Errorf("read PoW result ACK: %w", err)
	}
	var ack powResultAck
	if err := rlp.DecodeBytes(payload, &ack); err != nil {
		return fmt.Errorf("decode PoW result ACK: %w", err)
	}
	if ack.Version != powResultProtocolVersion {
		return fmt.Errorf("unsupported PoW result ACK version %d", ack.Version)
	}
	if ack.RequestID != requestID {
		return errors.New("PoW result ACK request ID mismatch")
	}
	switch ack.Status {
	case powResultAckAccepted, powResultAckDuplicate:
		return nil
	case powResultAckRejected:
		return &powResultRemoteError{Code: ack.Code, Reason: ack.Reason}
	default:
		return fmt.Errorf("invalid PoW result ACK status %d", ack.Status)
	}
}

type powResultTLSIdentityProvider struct {
	publicKey  func() ([]byte, error)
	generation func() (common.Hash, error)
	signDigest func(common.Hash, []byte) ([]byte, error)

	mu          sync.Mutex
	public      []byte
	keyHash     common.Hash
	certificate tls.Certificate
}

func (provider *powResultTLSIdentityProvider) certificateForHandshake() (tls.Certificate, error) {
	if provider == nil || provider.publicKey == nil || provider.generation == nil || provider.signDigest == nil {
		return tls.Certificate{}, errors.New("PoW result TLS signer is unavailable")
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()

	publicKey, err := provider.publicKey()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("resolve PoW result TLS public key: %w", err)
	}
	public := bls.GetPublicKey(publicKey)
	if public == nil || !bytes.Equal(public.Serialize(), publicKey) {
		return tls.Certificate{}, errors.New("invalid PoW result TLS public key")
	}
	generation, err := provider.generation()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("resolve PoW result TLS generation: %w", err)
	}
	if generation == (common.Hash{}) {
		return tls.Certificate{}, errors.New("PoW result TLS generation is unavailable")
	}
	if bytes.Equal(provider.public, publicKey) && provider.keyHash == generation && provider.certificate.Leaf != nil && time.Until(provider.certificate.Leaf.NotAfter) >= time.Hour {
		return provider.certificate, nil
	}
	certificate, err := rnetnetwork.GenerateBLSTLSCertificate(
		powResultTLSApplication,
		powResultTLSIdentity(publicKey, generation),
		publicKey,
		func(digest []byte) ([]byte, error) { return provider.signDigest(generation, digest) },
	)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("attest PoW result TLS certificate: %w", err)
	}
	provider.public = append(provider.public[:0], publicKey...)
	provider.keyHash = generation
	provider.certificate = certificate
	return certificate, nil
}

func (provider *powResultTLSIdentityProvider) serverTLSConfig() *tls.Config {
	return &tls.Config{
		NextProtos:             []string{powResultALPN},
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			certificate, err := provider.certificateForHandshake()
			if err != nil {
				return nil, err
			}
			return &certificate, nil
		},
	}
}

func powResultClientTLSConfig(expectedPublicKey []byte, generation common.Hash) (*tls.Config, error) {
	public := bls.GetPublicKey(expectedPublicKey)
	if public == nil || !bytes.Equal(public.Serialize(), expectedPublicKey) {
		return nil, errors.New("invalid expected validator BLS public key")
	}
	if generation == (common.Hash{}) {
		return nil, errors.New("missing expected PoW result TLS generation")
	}
	publicKey := append([]byte(nil), expectedPublicKey...)
	identity := powResultTLSIdentity(publicKey, generation)
	return &tls.Config{
		NextProtos:             []string{powResultALPN},
		MinVersion:             tls.VersionTLS13,
		InsecureSkipVerify:     true, // Replaced by the mandatory BLS verifier below.
		SessionTicketsDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if state.NegotiatedProtocol != powResultALPN {
				return fmt.Errorf("unexpected PoW result ALPN %q", state.NegotiatedProtocol)
			}
			raw := make([][]byte, 0, len(state.PeerCertificates))
			for _, certificate := range state.PeerCertificates {
				if certificate != nil {
					raw = append(raw, certificate.Raw)
				}
			}
			return rnetnetwork.VerifyBLSTLSCertificate(raw, powResultTLSApplication, identity, publicKey)
		},
	}, nil
}

type powResultSendFunc func(context.Context, string, []byte, []byte) error

type powResultTransportClient struct {
	quicSend powResultSendFunc
	tcpSend  powResultSendFunc
}

func defaultPoWResultTransportClient() powResultTransportClient {
	return powResultTransportClient{quicSend: sendPoWResultQUIC, tcpSend: sendPoWResultTCP}
}

func (client powResultTransportClient) send(ctx context.Context, endpoint string, expectedPublicKey, payload []byte) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if client.quicSend == nil || client.tcpSend == nil {
		return "", errors.New("PoW result transport client is incomplete")
	}
	quicErr := client.quicSend(ctx, endpoint, expectedPublicKey, payload)
	if quicErr == nil {
		return "quic", nil
	}
	var rejected *powResultRemoteError
	if errors.As(quicErr, &rejected) {
		return "quic", quicErr
	}
	tcpErr := client.tcpSend(ctx, endpoint, expectedPublicKey, payload)
	if tcpErr == nil {
		return "tcp", nil
	}
	return "", fmt.Errorf("QUIC failed: %v; TLS/TCP fallback failed: %w", quicErr, tcpErr)
}

func powResultPayloadGeneration(payload []byte) (common.Hash, error) {
	var result types.PoWResult
	if err := rlp.DecodeBytes(payload, &result); err != nil {
		return common.Hash{}, fmt.Errorf("decode PoW result TLS generation: %w", err)
	}
	if result.ParentHash == (common.Hash{}) {
		return common.Hash{}, errors.New("PoW result TLS generation is empty")
	}
	return result.ParentHash, nil
}

func sendPoWResultQUIC(ctx context.Context, endpoint string, expectedPublicKey, payload []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	generation, err := powResultPayloadGeneration(payload)
	if err != nil {
		return err
	}
	tlsConfig, err := powResultClientTLSConfig(expectedPublicKey, generation)
	if err != nil {
		return err
	}
	dialCtx, cancel := context.WithTimeout(ctx, powResultHandshakeTimeout)
	defer cancel()
	conn, err := quic.DialAddr(dialCtx, endpoint, tlsConfig, &quic.Config{
		HandshakeIdleTimeout:  powResultHandshakeTimeout,
		MaxIdleTimeout:        powResultReadTimeout,
		MaxIncomingStreams:    1,
		MaxIncomingUniStreams: -1,
	})
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "PoW result delivered")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()
	stopStream := context.AfterFunc(ctx, func() {
		stream.CancelRead(1)
		stream.CancelWrite(1)
	})
	defer stopStream()
	_ = stream.SetWriteDeadline(powResultBoundedDeadline(ctx, powResultWriteTimeout))
	if err := writePoWResultFrame(stream, powResultRequestMagic, payload, powResultTransportMaxPacketSize); err != nil {
		return err
	}
	if err := stream.Close(); err != nil {
		return err
	}
	_ = stream.SetReadDeadline(powResultBoundedDeadline(ctx, powResultReadTimeout))
	return readAndValidatePoWResultAck(stream, powResultRequestID(payload))
}

func sendPoWResultTCP(ctx context.Context, endpoint string, expectedPublicKey, payload []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	generation, err := powResultPayloadGeneration(payload)
	if err != nil {
		return err
	}
	tlsConfig, err := powResultClientTLSConfig(expectedPublicKey, generation)
	if err != nil {
		return err
	}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: powResultHandshakeTimeout},
		Config:    tlsConfig,
	}
	conn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return err
	}
	defer conn.Close()
	stopConnection := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopConnection()
	_ = conn.SetWriteDeadline(powResultBoundedDeadline(ctx, powResultWriteTimeout))
	if err := writePoWResultFrame(conn, powResultRequestMagic, payload, powResultTransportMaxPacketSize); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(powResultBoundedDeadline(ctx, powResultReadTimeout))
	return readAndValidatePoWResultAck(conn, powResultRequestID(payload))
}

type powResultTarget struct {
	endpoint  string
	publicKey []byte
}

// PoWResultDeliveryError reports committee-wide delivery failure. Success is
// returned only after every unique configured validator acknowledges admission.
type PoWResultDeliveryError struct {
	Acknowledged int
	Total        int
	First        error
}

func (err *PoWResultDeliveryError) Error() string {
	if err.First == nil {
		return fmt.Sprintf("PoW result acknowledged by %d/%d validators", err.Acknowledged, err.Total)
	}
	return fmt.Sprintf("PoW result acknowledged by %d/%d validators: %v", err.Acknowledged, err.Total, err.First)
}

func (err *PoWResultDeliveryError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.First
}

func buildPoWResultTargets(rnetPort string, validators []*common.Cnode) ([]powResultTarget, []error, error) {
	port, err := PoWResultTransportPort(rnetPort)
	if err != nil {
		return nil, nil, err
	}
	targets := make([]powResultTarget, 0, len(validators))
	invalid := make([]error, 0)
	seen := make(map[string][]byte)
	for index, validator := range validators {
		endpoint, endpointErr := powResultEndpointFromCommitteeNode(validator, port)
		if endpointErr != nil {
			invalid = append(invalid, fmt.Errorf("validator %d endpoint: %w", index, endpointErr))
			continue
		}
		publicKey, publicErr := canonicalPoWResultPublicKey(validator.Public)
		if publicErr != nil {
			invalid = append(invalid, fmt.Errorf("validator %d (%s): %w", index, endpoint, publicErr))
			continue
		}
		if previous, exists := seen[endpoint]; exists {
			if !bytes.Equal(previous, publicKey) {
				invalid = append(invalid, fmt.Errorf("validator %d conflicts with another BLS key at %s", index, endpoint))
			}
			continue
		}
		seen[endpoint] = append([]byte(nil), publicKey...)
		targets = append(targets, powResultTarget{endpoint: endpoint, publicKey: publicKey})
	}
	return targets, invalid, nil
}

func preparePoWResultDelivery(rnetPort string, validators []*common.Cnode, result *types.PoWResult) ([]byte, []powResultTarget, []error, error) {
	if result == nil {
		return nil, nil, nil, errors.New("nil PoW result")
	}
	payload, err := rlp.EncodeToBytes(result)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(payload) == 0 || len(payload) > powResultTransportMaxPacketSize {
		return nil, nil, nil, fmt.Errorf("invalid PoW result payload size %d", len(payload))
	}
	targets, invalid, err := buildPoWResultTargets(rnetPort, validators)
	if err != nil {
		return nil, nil, nil, err
	}
	total := len(targets) + len(invalid)
	if total == 0 {
		return nil, nil, nil, errors.New("no fixed-mode PoW result validators configured")
	}
	return payload, targets, invalid, nil
}

type powResultDeliveryRound struct {
	acknowledged int
	failed       []powResultTarget
	firstErr     error
	permanent    bool
}

func deliverPoWResultTargets(ctx context.Context, client powResultTransportClient, targets []powResultTarget, payload []byte) powResultDeliveryRound {
	if ctx == nil {
		ctx = context.Background()
	}
	type deliveryResult struct {
		transport string
		target    powResultTarget
		err       error
	}
	results := make(chan deliveryResult, len(targets))
	semaphore := make(chan struct{}, powResultMaxParallelDeliveries)
	for _, target := range targets {
		target := target
		go func() {
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				results <- deliveryResult{target: target, err: ctx.Err()}
				return
			}
			transport, sendErr := client.send(ctx, target.endpoint, target.publicKey, payload)
			results <- deliveryResult{transport: transport, target: target, err: sendErr}
		}()
	}

	round := powResultDeliveryRound{failed: make([]powResultTarget, 0)}
	for range targets {
		result := <-results
		if result.err != nil {
			if round.firstErr == nil {
				round.firstErr = result.err
			}
			round.failed = append(round.failed, result.target)
			var rejected *powResultRemoteError
			if errors.As(result.err, &rejected) && !rejected.retryable() {
				round.permanent = true
			}
			log.Warn("Failed to deliver fixed-mode PoW result", "endpoint", result.target.endpoint, "err", result.err)
			continue
		}
		round.acknowledged++
		log.Debug("Fixed-mode PoW result acknowledged", "endpoint", result.target.endpoint, "transport", result.transport)
	}
	return round
}

func broadcastPoWResultWithClient(ctx context.Context, client powResultTransportClient, rnetPort string, validators []*common.Cnode, result *types.PoWResult) error {
	payload, targets, invalid, err := preparePoWResultDelivery(rnetPort, validators, result)
	if err != nil {
		return err
	}
	round := deliverPoWResultTargets(ctx, client, targets, payload)
	firstErr := round.firstErr
	if len(invalid) > 0 {
		firstErr = invalid[0]
		for _, invalidErr := range invalid {
			log.Warn("Invalid fixed-mode PoW result validator", "err", invalidErr)
		}
	}
	total := len(targets) + len(invalid)
	if round.acknowledged != total {
		return &PoWResultDeliveryError{Acknowledged: round.acknowledged, Total: total, First: firstErr}
	}
	return nil
}

func broadcastPoWResultUntilAcknowledged(ctx context.Context, client powResultTransportClient, rnetPort string, validators []*common.Cnode, result *types.PoWResult, maxAttempts int) error {
	if ctx == nil {
		ctx = context.Background()
	}
	payload, targets, invalid, err := preparePoWResultDelivery(rnetPort, validators, result)
	if err != nil {
		return err
	}
	total := len(targets) + len(invalid)
	acknowledged := 0
	remaining := targets
	var firstErr error
	if len(invalid) > 0 {
		firstErr = invalid[0]
		for _, invalidErr := range invalid {
			log.Warn("Invalid fixed-mode PoW result validator", "err", invalidErr)
		}
	}
	for attempt := 0; len(remaining) > 0; attempt++ {
		if contextErr := ctx.Err(); contextErr != nil {
			if firstErr == nil {
				firstErr = contextErr
			}
			break
		}
		roundCtx, cancel := context.WithTimeout(ctx, powResultDeliveryTimeout)
		round := deliverPoWResultTargets(roundCtx, client, remaining, payload)
		cancel()
		acknowledged += round.acknowledged
		if firstErr == nil {
			firstErr = round.firstErr
		}
		remaining = round.failed
		if len(remaining) == 0 || round.permanent || len(invalid) > 0 {
			break
		}
		if maxAttempts > 0 && attempt+1 >= maxAttempts {
			break
		}
		delay := powResultRetryDelay << min(attempt, 4)
		if delay > powResultRetryMaxDelay {
			delay = powResultRetryMaxDelay
		}
		log.Warn("Retrying unacknowledged fixed-mode PoW result delivery", "attempt", attempt+2, "remaining", len(remaining), "delay", delay)
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			if firstErr == nil {
				firstErr = ctx.Err()
			}
			remaining = nil
		}
	}
	if acknowledged != total {
		return &PoWResultDeliveryError{Acknowledged: acknowledged, Total: total, First: firstErr}
	}
	return nil
}

func broadcastPoWResultWithRetryClient(client powResultTransportClient, rnetPort string, validators []*common.Cnode, result *types.PoWResult) error {
	return broadcastPoWResultUntilAcknowledged(context.Background(), client, rnetPort, validators, result, powResultDeliveryAttempts)
}

// BroadcastPoWResult delivers a mined result to every fixed validator. QUIC is
// attempted first; authenticated TLS/TCP is used only for transport failures.
func BroadcastPoWResult(rnetPort string, validators []*common.Cnode, result *types.PoWResult) error {
	return broadcastPoWResultWithRetryClient(defaultPoWResultTransportClient(), rnetPort, validators, result)
}

// BroadcastPoWResultContext retries only validators that have not acknowledged
// admission. A zero-deadline context can keep the compact result pending until
// its parent keyblock changes; cancellation stops in-flight QUIC and TCP I/O.
func BroadcastPoWResultContext(ctx context.Context, rnetPort string, validators []*common.Cnode, result *types.PoWResult) error {
	return broadcastPoWResultUntilAcknowledged(ctx, defaultPoWResultTransportClient(), rnetPort, validators, result, 0)
}

// BroadcastPoWResultUDP is retained for source compatibility and now uses the
// acknowledged QUIC-with-TLS/TCP-fallback transport.
func BroadcastPoWResultUDP(rnetPort string, validators []*common.Cnode, result *types.PoWResult) error {
	return BroadcastPoWResult(rnetPort, validators, result)
}

type powResultTransportServer struct {
	ctx       context.Context
	cancel    context.CancelFunc
	identity  *powResultTLSIdentityProvider
	admit     func(*types.PoWResult) error
	tcp       net.Listener
	packet    net.PacketConn
	transport *quic.Transport
	quic      *quic.Listener
	quicSem   chan struct{}
	tcpSem    chan struct{}

	mu         sync.Mutex
	tcpConns   map[net.Conn]string
	tcpSources map[string]int
	quicConns  map[*quic.Conn]struct{}
	wg         sync.WaitGroup
	once       sync.Once
}

func startPoWResultTransportServer(address string, identity *powResultTLSIdentityProvider, admit func(*types.PoWResult) error) (*powResultTransportServer, error) {
	if identity == nil || identity.publicKey == nil || identity.generation == nil || identity.signDigest == nil {
		return nil, errors.New("PoW result TLS identity is not configured")
	}
	if admit == nil {
		return nil, errors.New("PoW result admission callback is unavailable")
	}
	host, requestedPort, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid PoW result listen address %q: %w", address, err)
	}
	tcpListener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen for PoW result TLS/TCP: %w", err)
	}
	_, actualPort, err := net.SplitHostPort(tcpListener.Addr().String())
	if err != nil {
		_ = tcpListener.Close()
		return nil, err
	}
	udpAddress := address
	if requestedPort == "0" {
		udpAddress = net.JoinHostPort(host, actualPort)
	}
	packetConn, err := net.ListenPacket("udp", udpAddress)
	if err != nil {
		_ = tcpListener.Close()
		return nil, fmt.Errorf("listen for PoW result QUIC: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := &powResultTransportServer{
		ctx:        ctx,
		cancel:     cancel,
		identity:   identity,
		admit:      admit,
		tcp:        tcpListener,
		packet:     packetConn,
		quicSem:    make(chan struct{}, powResultMaxIncomingQUICConnections),
		tcpSem:     make(chan struct{}, powResultMaxIncomingTCPConnections),
		tcpConns:   make(map[net.Conn]string),
		tcpSources: make(map[string]int),
		quicConns:  make(map[*quic.Conn]struct{}),
	}
	transport := &quic.Transport{
		Conn:                packetConn,
		VerifySourceAddress: func(net.Addr) bool { return true },
		ConnContext: func(connectionContext context.Context, info *quic.ClientInfo) (context.Context, error) {
			if info == nil || !info.AddrVerified {
				return nil, errors.New("PoW result QUIC source address was not verified")
			}
			select {
			case server.quicSem <- struct{}{}:
				context.AfterFunc(connectionContext, func() { <-server.quicSem })
				return connectionContext, nil
			default:
				return nil, errors.New("too many PoW result connections")
			}
		},
	}
	listener, err := transport.Listen(identity.serverTLSConfig(), &quic.Config{
		HandshakeIdleTimeout:  powResultHandshakeTimeout,
		MaxIdleTimeout:        powResultReadTimeout,
		MaxIncomingStreams:    1,
		MaxIncomingUniStreams: -1,
	})
	if err != nil {
		cancel()
		_ = transport.Close()
		_ = packetConn.Close()
		_ = tcpListener.Close()
		return nil, fmt.Errorf("start PoW result QUIC listener: %w", err)
	}
	server.transport = transport
	server.quic = listener
	server.wg.Add(2)
	go server.acceptQUIC()
	go server.acceptTCP()
	return server, nil
}

func (server *powResultTransportServer) address() string {
	if server == nil || server.tcp == nil {
		return ""
	}
	return server.tcp.Addr().String()
}

func (server *powResultTransportServer) acceptQUIC() {
	defer server.wg.Done()
	for {
		conn, err := server.quic.Accept(server.ctx)
		if err != nil {
			if server.ctx.Err() == nil {
				log.Debug("PoW result QUIC accept failed", "err", err)
			}
			return
		}
		server.mu.Lock()
		server.quicConns[conn] = struct{}{}
		server.mu.Unlock()
		server.wg.Add(1)
		go server.handleQUIC(conn)
	}
}

func (server *powResultTransportServer) handleQUIC(conn *quic.Conn) {
	defer server.wg.Done()
	defer func() {
		server.mu.Lock()
		delete(server.quicConns, conn)
		server.mu.Unlock()
	}()
	stream, err := conn.AcceptStream(server.ctx)
	if err != nil {
		return
	}
	_ = stream.SetReadDeadline(time.Now().Add(powResultReadTimeout))
	_ = stream.SetWriteDeadline(time.Now().Add(powResultWriteTimeout))
	if err := server.handleRequest(stream); err != nil {
		stream.CancelRead(1)
		stream.CancelWrite(1)
		_ = conn.CloseWithError(1, "invalid PoW result request")
		if server.ctx.Err() == nil {
			log.Warn("Failed to handle fixed-mode PoW result over QUIC", "from", conn.RemoteAddr(), "err", err)
		}
		return
	}
	// Closing a QUIC connection here can overtake the stream ACK and turn a
	// successful admission into an application error at the miner. Close only
	// the server's stream write side, then let the client close the connection
	// after it has read the ACK (or let the bounded idle timeout expire).
	if err := stream.Close(); err != nil {
		return
	}
	select {
	case <-conn.Context().Done():
	case <-server.ctx.Done():
		_ = conn.CloseWithError(1, "PoW result listener stopped")
	}
}

func (server *powResultTransportServer) acceptTCP() {
	defer server.wg.Done()
	for {
		raw, err := server.tcp.Accept()
		if err != nil {
			if server.ctx.Err() == nil {
				log.Debug("PoW result TLS/TCP accept failed", "err", err)
			}
			return
		}
		select {
		case server.tcpSem <- struct{}{}:
		case <-server.ctx.Done():
			_ = raw.Close()
			return
		default:
			_ = raw.Close()
			continue
		}
		source := raw.RemoteAddr().String()
		if host, _, splitErr := net.SplitHostPort(source); splitErr == nil {
			source = host
		}
		server.mu.Lock()
		if server.tcpSources[source] >= powResultMaxTCPConnectionsPerIP {
			server.mu.Unlock()
			<-server.tcpSem
			_ = raw.Close()
			continue
		}
		server.tcpSources[source]++
		server.tcpConns[raw] = source
		server.mu.Unlock()
		server.wg.Add(1)
		go server.handleTCP(raw)
	}
}

func (server *powResultTransportServer) handleTCP(raw net.Conn) {
	defer server.wg.Done()
	defer func() {
		server.mu.Lock()
		source := server.tcpConns[raw]
		delete(server.tcpConns, raw)
		if server.tcpSources[source] <= 1 {
			delete(server.tcpSources, source)
		} else {
			server.tcpSources[source]--
		}
		server.mu.Unlock()
		<-server.tcpSem
		_ = raw.Close()
	}()
	_ = raw.SetDeadline(time.Now().Add(powResultHandshakeTimeout))
	conn := tls.Server(raw, server.identity.serverTLSConfig())
	if err := conn.HandshakeContext(server.ctx); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(powResultReadTimeout))
	_ = conn.SetWriteDeadline(time.Now().Add(powResultWriteTimeout))
	if err := server.handleRequest(conn); err != nil && server.ctx.Err() == nil {
		log.Warn("Failed to handle fixed-mode PoW result over TLS/TCP", "from", raw.RemoteAddr(), "err", err)
	}
}

func (server *powResultTransportServer) handleRequest(rw io.ReadWriter) error {
	payload, err := readPoWResultFrame(rw, powResultRequestMagic, powResultTransportMaxPacketSize)
	if err != nil {
		return err
	}
	requestID := powResultRequestID(payload)
	ack := powResultAck{Version: powResultProtocolVersion, RequestID: requestID, Status: powResultAckRejected, Code: powResultAckCodeRejected}
	var result types.PoWResult
	if err := rlp.DecodeBytes(payload, &result); err != nil {
		ack.Code = powResultAckCodeInvalidPayload
		ack.Reason = "invalid PoW result encoding"
	} else {
		admitErr := server.admit(&result)
		switch {
		case admitErr == nil:
			ack.Status = powResultAckAccepted
			ack.Code = powResultAckCodeOK
		case errors.Is(admitErr, ErrCandidateExisted):
			ack.Status = powResultAckDuplicate
			ack.Code = powResultAckCodeOK
		default:
			var retryable *powResultRetryableAdmissionError
			if errors.As(admitErr, &retryable) {
				ack.Code = powResultAckCodeReceiverBehind
			}
			ack.Reason = admitErr.Error()
		}
	}
	encoded, err := encodePoWResultAck(ack)
	if err != nil {
		return err
	}
	return writePoWResultFrame(rw, powResultAckMagic, encoded, powResultAckMaxPacketSize)
}

func (server *powResultTransportServer) stop() {
	if server == nil {
		return
	}
	server.once.Do(func() {
		server.cancel()
		if server.quic != nil {
			_ = server.quic.Close()
		}
		if server.transport != nil {
			_ = server.transport.Close()
		}
		if server.packet != nil {
			_ = server.packet.Close()
		}
		if server.tcp != nil {
			_ = server.tcp.Close()
		}
		server.mu.Lock()
		for conn := range server.quicConns {
			_ = conn.CloseWithError(1, "PoW result listener stopped")
		}
		for conn := range server.tcpConns {
			_ = conn.Close()
		}
		server.mu.Unlock()
		server.wg.Wait()
	})
}

// ConfigurePoWResultTLS installs the validator BLS identity used to attest the
// PoW result server's ephemeral TLS certificate. It must be configured before
// StartPoWResultTransport.
func (cp *CandidatePool) ConfigurePoWResultTLS(publicKey func() ([]byte, error), generation func() (common.Hash, error), signDigest func(common.Hash, []byte) ([]byte, error)) error {
	if publicKey == nil || generation == nil || signDigest == nil {
		return errors.New("PoW result TLS callbacks are required")
	}
	cp.powResultLifecycle.Lock()
	defer cp.powResultLifecycle.Unlock()
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.powResultTransport != nil {
		return errors.New("PoW result transport is already running")
	}
	cp.powResultTLS = &powResultTLSIdentityProvider{publicKey: publicKey, generation: generation, signDigest: signDigest}
	return nil
}

// StartPoWResultTransport starts QUIC and authenticated TLS/TCP listeners for
// fixed-mode PoW results.
func (cp *CandidatePool) StartPoWResultTransport(rnetPort string) error {
	cp.powResultLifecycle.Lock()
	defer cp.powResultLifecycle.Unlock()
	port, err := PoWResultTransportPort(rnetPort)
	if err != nil {
		return err
	}
	cp.mu.Lock()
	if cp.powResultTransport != nil {
		cp.mu.Unlock()
		return nil
	}
	identity := cp.powResultTLS
	cp.mu.Unlock()
	server, err := startPoWResultTransportServer(":"+strconv.Itoa(port), identity, cp.AddRemotePoWResult)
	if err != nil {
		return err
	}
	cp.mu.Lock()
	cp.powResultTransport = server
	cp.mu.Unlock()
	log.Info("Started fixed-mode PoW result transport", "addr", server.address(), "primary", "quic", "fallback", "tls/tcp")
	return nil
}

// StopPoWResultTransport stops both fixed-mode transport listeners.
func (cp *CandidatePool) StopPoWResultTransport() {
	cp.powResultLifecycle.Lock()
	defer cp.powResultLifecycle.Unlock()
	cp.mu.Lock()
	server := cp.powResultTransport
	cp.powResultTransport = nil
	cp.mu.Unlock()
	if server != nil {
		server.stop()
	}
}

// StartPoWResultUDP is retained for source compatibility.
func (cp *CandidatePool) StartPoWResultUDP(rnetPort string) error {
	return cp.StartPoWResultTransport(rnetPort)
}

// StopPoWResultUDP is retained for source compatibility.
func (cp *CandidatePool) StopPoWResultUDP() {
	cp.StopPoWResultTransport()
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
		return &powResultRetryableAdmissionError{err: types.ErrUnknownAncestor}
	}
	expectedNumber := keyBlock.NumberU64() + 1
	candidateNumber := candidate.KeyCandidate.Number.Uint64()
	if candidate.KeyCandidate.ParentHash != keyBlock.Hash() || candidateNumber != expectedNumber {
		if candidateNumber > expectedNumber {
			return &powResultRetryableAdmissionError{err: fmt.Errorf("%w: receiver key head is %d, candidate is %d", ErrCandidateNumberLow, keyBlock.NumberU64(), candidateNumber)}
		}
		return ErrCandidateNumberLow
	}
	currentTxNumber := cp.backend.BlockChain().CurrentBlockN()
	if candidate.KeyCandidate.T_Number > currentTxNumber {
		return &powResultRetryableAdmissionError{err: fmt.Errorf("receiver tx head is %d, PoW result requires %d", currentTxNumber, candidate.KeyCandidate.T_Number)}
	}
	if candidate.KeyCandidate.T_Number < keyBlock.T_Number() {
		return errors.New("pow result tx block number is outside the local work range")
	}
	if time.Since(time.Unix(int64(candidate.KeyCandidate.Time), 0)) > 2*time.Hour {
		return errors.New("pow result is stale")
	}

	committeeSize := len(cp.backend.KeyBlockChain().CurrentCommittee())
	if err := cp.backend.Engine().PrepareCandidate(cp.backend.KeyBlockChain(), candidate, committeeSize); err != nil {
		if errors.Is(err, types.ErrUnknownAncestor) {
			return &powResultRetryableAdmissionError{err: err}
		}
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
	log.Info("Accepted fixed-mode PoW result", "candidate.number", candidate.KeyCandidate.Number.Uint64(), "pubkey", candidate.PubKey, "hash", candidate.Hash())
	go cp.feed.Send(candidate)
	return nil
}
