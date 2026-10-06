// SPDX-License-Identifier: LGPL-3.0-or-later
package browserrelay

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/p2p/enode"
)

const (
	MeshProtocol              = "cypher-browser-mesh/1"
	MeshAdvertisementDomain   = "cypher-browser-mesh-advertisement-v1\x00"
	MeshEndpointDomain        = "cypher-browser-mesh-endpoint-v1\x00"
	MeshMaxChunkBytes         = 8192
	MeshMaxFrameBytes         = 16384
	MeshMaxSessions           = 80
	MeshMaxCircuits           = 40
	MeshMaxCircuitsPerSession = 40
	MeshMaxCandidates         = 64
	MeshMaxRoutesPerCandidate = 4
	MeshMaxHops               = 4
	MeshQueueFrames           = 64
	MeshQueueBytes            = 512 << 10
	MeshReceiveChunks         = 8
	MeshSessionBytesPerSecond = 64 << 10
	MeshTotalBytesPerSecond   = 256 << 10
	MeshAdvertisementTTL      = 120 * time.Second
	MeshHeartbeatInterval     = 5 * time.Second
	MeshHeartbeatTimeout      = 15 * time.Second
	MeshCircuitTTL            = 30 * time.Minute
	MeshOpenTimeout           = 8 * time.Second
)

var meshLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
var meshRandomID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// MeshAdvertisement carries exact signed JSON bytes. Relay path labels are
// deliberately outside the signature: they are routing hints, not identities.
type MeshAdvertisement struct {
	PayloadBase64 string `json:"payloadBase64"`
	SignatureHex  string `json:"signatureHex"`
}

type meshAdvertisementPayload struct {
	Version   int     `json:"version"`
	Network   Network `json:"network"`
	Enode     string  `json:"enode"`
	BootID    string  `json:"bootId"`
	IssuedAt  int64   `json:"issuedAt"`
	ExpiresAt int64   `json:"expiresAt"`
}

// MeshFrame is the browser-facing circuit protocol. The browser replaces
// Session with the receiving endpoint's current hello session when forwarding;
// circuit IDs and ordered data sequence numbers remain unchanged end-to-end.
type MeshFrame struct {
	Type          string             `json:"type"`
	Session       string             `json:"session"`
	BrowserID     string             `json:"browserId,omitempty"`
	Protocol      string             `json:"protocol,omitempty"`
	Advertisement *MeshAdvertisement `json:"advertisement,omitempty"`
	Route         []string           `json:"route,omitempty"`
	Target        string             `json:"target,omitempty"`
	CircuitID     string             `json:"circuitId,omitempty"`
	Seq           uint64             `json:"seq,omitempty"`
	Bytes         int                `json:"bytes,omitempty"`
	Data          string             `json:"data,omitempty"`
	Reason        string             `json:"reason,omitempty"`
}

func meshSignAdvertisement(network Network, node *enode.Node, boot string, now time.Time, sign func([]byte) ([]byte, error)) (MeshAdvertisement, error) {
	if node == nil || node.Pubkey() == nil {
		return MeshAdvertisement{}, errors.New("mesh local identity unavailable")
	}
	p := meshAdvertisementPayload{Version: 1, Network: network, Enode: node.URLv4(), BootID: boot,
		IssuedAt: now.UnixMilli(), ExpiresAt: now.Add(MeshAdvertisementTTL).UnixMilli()}
	raw, err := json.Marshal(p)
	if err != nil {
		return MeshAdvertisement{}, err
	}
	sig, err := sign(crypto.Keccak256([]byte(MeshAdvertisementDomain), raw))
	if err != nil {
		return MeshAdvertisement{}, errors.New("mesh advertisement signing failed")
	}
	a := MeshAdvertisement{PayloadBase64: base64.StdEncoding.EncodeToString(raw), SignatureHex: hex.EncodeToString(sig)}
	verified, _, err := meshVerifyAdvertisement(a, network, now)
	if err != nil || verified.ID() != node.ID() {
		return MeshAdvertisement{}, errors.New("mesh signer does not match local node identity")
	}
	return a, nil
}

func meshVerifyAdvertisement(a MeshAdvertisement, network Network, now time.Time) (*enode.Node, time.Time, error) {
	fail := func() (*enode.Node, time.Time, error) {
		return nil, time.Time{}, errors.New("invalid mesh advertisement")
	}
	if len(a.PayloadBase64) > 4096 || len(a.SignatureHex) != 130 {
		return fail()
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(a.PayloadBase64)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != a.PayloadBase64 || len(raw) > 2048 || strictJSON(raw) != nil {
		return fail()
	}
	if _, err := exactObject(raw, "version", "network", "enode", "bootId", "issuedAt", "expiresAt"); err != nil {
		return fail()
	}
	var p meshAdvertisementPayload
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || p.Version != 1 || p.Network != network || ValidateNetwork(p.Network) != nil || !meshRandomID.MatchString(p.BootID) || len(p.Enode) > 512 {
		return fail()
	}
	if p.IssuedAt < 0 || p.IssuedAt > now.Add(10*time.Second).UnixMilli() || p.ExpiresAt <= now.UnixMilli() || p.ExpiresAt <= p.IssuedAt || p.ExpiresAt-p.IssuedAt > MeshAdvertisementTTL.Milliseconds() {
		return fail()
	}
	// enode.ParseV4 ordinarily permits DNS resolution. Advertisements are
	// untrusted routing metadata: reject hostnames before calling that parser.
	u, err := url.Parse(p.Enode)
	if err != nil || (u.User != nil && net.ParseIP(u.Hostname()) == nil) {
		return fail()
	}
	n, err := enode.ParseV4(p.Enode)
	if err != nil || n.Pubkey() == nil || n.URLv4() != p.Enode {
		return fail()
	}
	sig, err := hex.DecodeString(a.SignatureHex)
	if err != nil || hex.EncodeToString(sig) != a.SignatureHex || sig[64] > 1 {
		return fail()
	}
	hash := crypto.Keccak256([]byte(MeshAdvertisementDomain), raw)
	key, err := crypto.SigToPub(hash, sig)
	if err != nil || enode.PubkeyToIDV4(key) != n.ID() || !crypto.VerifySignature(crypto.FromECDSAPub(key), hash, sig[:64]) {
		return fail()
	}
	return n, time.UnixMilli(p.ExpiresAt), nil
}

func meshDecodeFrame(raw []byte) (MeshFrame, error) {
	var f MeshFrame
	if len(raw) > MeshMaxFrameBytes || strictJSON(raw) != nil {
		return f, errors.New("invalid mesh frame")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&f); err != nil || !meshRandomID.MatchString(f.Session) {
		return f, errors.New("invalid mesh frame")
	}
	fields := []string{"type", "session"}
	switch f.Type {
	case "advertisement":
		fields = append(fields, "advertisement", "route")
	case "open":
		fields = append(fields, "circuitId", "target", "advertisement", "route")
	case "opened":
		fields = append(fields, "circuitId")
	case "data":
		fields = append(fields, "circuitId", "seq", "data")
	case "credit":
		fields = append(fields, "circuitId", "seq", "bytes")
	case "close":
		fields = append(fields, "circuitId", "reason")
	default:
		return f, errors.New("unknown mesh frame type")
	}
	if _, err := exactObject(raw, fields...); err != nil {
		return f, err
	}
	if f.CircuitID != "" && !meshRandomID.MatchString(f.CircuitID) {
		return f, errors.New("invalid circuit ID")
	}
	if f.Type == "data" && (f.Seq == 0 || f.Seq > MaxSafeInteger || len(f.Data) == 0 || len(f.Data) > base64.StdEncoding.EncodedLen(MeshMaxChunkBytes)) {
		return f, errors.New("invalid circuit chunk")
	}
	if f.Type == "credit" && (f.Seq == 0 || f.Seq > MaxSafeInteger || f.Bytes < 1 || f.Bytes > MeshMaxChunkBytes) {
		return f, errors.New("invalid circuit credit")
	}
	if f.Type == "close" && (len(f.Reason) > 64 || !meshLabel.MatchString(f.Reason)) {
		return f, errors.New("invalid circuit close reason")
	}
	return f, nil
}

func meshValidRoute(route []string, localBrowser string) bool {
	if len(route) < 1 || len(route) > MeshMaxHops || route[len(route)-1] != localBrowser {
		return false
	}
	seen := make(map[string]bool, len(route))
	for _, id := range route {
		if !meshLabel.MatchString(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func meshReverseRoute(route []string) []string {
	out := make([]string, len(route))
	for i := range route {
		out[len(route)-1-i] = route[i]
	}
	return out
}

// meshEndpointPayload is independent of mesh/1 wire advertisements. The origin
// claim is signed by the existing Common key; no key leaves the native process.
type meshEndpointPayload struct {
	Version       int     `json:"version"`
	Network       Network `json:"network"`
	Enode         string  `json:"enode"`
	SourceID      string  `json:"sourceId"`
	GatewayOrigin string  `json:"gatewayOrigin"`
	BootID        string  `json:"bootId"`
	Sequence      uint64  `json:"sequence"`
	IssuedAt      int64   `json:"issuedAt"`
	ExpiresAt     int64   `json:"expiresAt"`
}

// ValidateMeshGatewayOrigin validates a public TLS transport claim. It does not
// resolve DNS or dial the address. Native role/admission and RLPx remain separate.
func ValidateMeshGatewayOrigin(origin string) error {
	fail := errors.New("mesh public gateway must be a canonical public HTTPS origin")
	if len(origin) > 255 || strings.ContainsAny(origin, "\\ \t\r\n") {
		return fail
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != origin || strings.ToLower(u.Host) != u.Host {
		return fail
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || n == 443 {
			return fail
		}
	}
	host := u.Hostname()
	canonicalHost := host
	if strings.Contains(host, ":") {
		canonicalHost = "[" + host + "]"
	}
	if u.Port() != "" {
		canonicalHost += ":" + u.Port()
	}
	if canonicalHost != u.Host {
		return fail
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.String() != host {
			return fail
		}
		if ip.Is4() {
			x := ip.As4()
			a, b, c := x[0], x[1], x[2]
			if a == 0 || a == 10 || a == 127 || a >= 224 || (a == 100 && b >= 64 && b <= 127) || (a == 169 && b == 254) || (a == 172 && b >= 16 && b <= 31) || (a == 192 && (b == 168 || b == 0 || b == 2 || b == 88 && c == 99)) || (a == 198 && (b == 18 || b == 19 || b == 51 && c == 100)) || (a == 203 && b == 0 && c == 113) {
				return fail
			}
		} else {
			if !netip.MustParsePrefix("2000::/3").Contains(ip) {
				return fail
			}
			for _, prefix := range []string{"2001::/23", "2001:db8::/32", "2002::/16", "3fff::/16"} {
				if netip.MustParsePrefix(prefix).Contains(ip) {
					return fail
				}
			}
		}
	} else {
		if !strings.Contains(host, ".") || strings.HasSuffix(host, ".") || strings.ContainsAny(host, "[]:") {
			return fail
		}
		parts := strings.Split(host, ".")
		for _, part := range parts {
			if len(part) > 63 || !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`).MatchString(part) {
				return fail
			}
		}
		switch parts[len(parts)-1] {
		case "localhost", "local", "internal", "lan", "home", "invalid", "test":
			return fail
		}
		// Numeric aliases such as 127.1 or 2130706433 must not become DNS hints.
		if regexp.MustCompile(`^[0-9.]+$`).MatchString(host) || !regexp.MustCompile(`[a-z]`).MatchString(parts[len(parts)-1]) {
			return fail
		}
	}
	return nil
}

func meshSignEndpoint(network Network, node *enode.Node, source, origin, boot string, sequence uint64, now time.Time, sign func([]byte) ([]byte, error)) (MeshAdvertisement, error) {
	if node == nil || node.Pubkey() == nil || !meshLabel.MatchString(source) || ValidateMeshGatewayOrigin(origin) != nil || sequence == 0 || sequence > MaxSafeInteger {
		return MeshAdvertisement{}, errors.New("invalid local mesh endpoint identity")
	}
	payload := meshEndpointPayload{Version: 1, Network: network, Enode: node.URLv4(), SourceID: source, GatewayOrigin: origin, BootID: boot, Sequence: sequence, IssuedAt: now.UnixMilli(), ExpiresAt: now.Add(MeshAdvertisementTTL).UnixMilli()}
	raw, err := json.Marshal(payload)
	if err != nil {
		return MeshAdvertisement{}, err
	}
	sig, err := sign(crypto.Keccak256([]byte(MeshEndpointDomain), raw))
	if err != nil {
		return MeshAdvertisement{}, errors.New("mesh endpoint signing failed")
	}
	envelope := MeshAdvertisement{PayloadBase64: base64.StdEncoding.EncodeToString(raw), SignatureHex: hex.EncodeToString(sig)}
	verified, _, err := meshVerifyEndpoint(envelope, network, now)
	if err != nil || verified.ID() != node.ID() {
		return MeshAdvertisement{}, errors.New("mesh endpoint signer differs from local native identity")
	}
	return envelope, nil
}

func meshVerifyEndpoint(a MeshAdvertisement, network Network, now time.Time) (*enode.Node, time.Time, error) {
	fail := func() (*enode.Node, time.Time, error) { return nil, time.Time{}, errors.New("invalid mesh endpoint") }
	if len(a.PayloadBase64) > 5464 || len(a.SignatureHex) != 130 {
		return fail()
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(a.PayloadBase64)
	if err != nil || len(raw) > 4096 || base64.StdEncoding.EncodeToString(raw) != a.PayloadBase64 || strictJSON(raw) != nil {
		return fail()
	}
	if _, err = exactObject(raw, "version", "network", "enode", "sourceId", "gatewayOrigin", "bootId", "sequence", "issuedAt", "expiresAt"); err != nil {
		return fail()
	}
	var p meshEndpointPayload
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || p.Version != 1 || p.Network != network || ValidateNetwork(p.Network) != nil || !meshLabel.MatchString(p.SourceID) || !meshRandomID.MatchString(p.BootID) || ValidateMeshGatewayOrigin(p.GatewayOrigin) != nil || p.Sequence == 0 || p.Sequence > MaxSafeInteger || len(p.Enode) > 512 {
		return fail()
	}
	if p.IssuedAt < 0 || p.IssuedAt > now.Add(10*time.Second).UnixMilli() || p.ExpiresAt <= now.UnixMilli() || p.ExpiresAt <= p.IssuedAt || p.ExpiresAt-p.IssuedAt > MeshAdvertisementTTL.Milliseconds() {
		return fail()
	}
	u, err := url.Parse(p.Enode)
	if err != nil || (u.User != nil && net.ParseIP(u.Hostname()) == nil) {
		return fail()
	}
	n, err := enode.ParseV4(p.Enode)
	if err != nil || n.Pubkey() == nil || n.URLv4() != p.Enode {
		return fail()
	}
	sig, err := hex.DecodeString(a.SignatureHex)
	if err != nil || len(sig) != 65 || hex.EncodeToString(sig) != a.SignatureHex || sig[64] > 1 {
		return fail()
	}
	digest := crypto.Keccak256([]byte(MeshEndpointDomain), raw)
	key, err := crypto.SigToPub(digest, sig)
	if err != nil || enode.PubkeyToIDV4(key) != n.ID() || !crypto.VerifySignature(crypto.FromECDSAPub(key), digest, sig[:64]) {
		return fail()
	}
	return n, time.UnixMilli(p.ExpiresAt), nil
}
