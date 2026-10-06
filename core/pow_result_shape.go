package core

import (
	"errors"
	"net"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

// ValidatePoWResultShape bounds the retained candidate representation before
// reconstruction or expensive PoW work. PubKey's cryptographic work binding is
// checked by the seal verifier, independently of the forwarding peer identity.
func ValidatePoWResultShape(r *types.PoWResult) error {
	if r == nil || r.ParentHash == (common.Hash{}) || r.Number == 0 || r.Port == 0 || r.Port > 65535 ||
		(len(r.IP) != net.IPv4len && len(r.IP) != net.IPv6len) || len(r.PubKey) == 0 || len(r.PubKey) > 256 ||
		len(r.Coinbase) != 42 || !common.IsHexAddress(r.Coinbase) || common.HexToAddress(r.Coinbase) == (common.Address{}) {
		return errors.New("invalid compact PoW result shape")
	}
	return nil
}
