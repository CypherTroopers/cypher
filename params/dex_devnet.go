package params

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
)

var DEXSettlementAddress = common.HexToAddress("0x0000000000000000000000000000000000de0001")

// DEXDevnetConfig is a genesis-committed isolated experiment, never a CLI role flag.
type DEXDevnetConfig struct {
	Version         uint16         `json:"version"`
	ActivationBlock uint64         `json:"activationBlock"`
	DEXID           common.Hash    `json:"dexId"`
	GenesisSeed     common.Hash    `json:"genesisSeed"`
	Custody         common.Address `json:"custody"`
	Committee       []common.Cnode `json:"committee"`
	MaxCheckpoints  uint64         `json:"maxCheckpoints"`
}

// RollingAnchors recognizes only explicitly supported authenticated schemas.
// Unknown future versions must not inherit acceptance rules by an inequality.
func (d *DEXDevnetConfig) RollingAnchors() bool {
	return d != nil && (d.Version == 3 || d.Version == 4 || d.Version == 5)
}

func (d *DEXDevnetConfig) ContinuousStorage() bool {
	return d != nil && (d.Version == 4 || d.Version == 5)
}

// AncestryProofs explicitly selects data schema 6 and finality proof v2. It does
// not change the financial state 6 arithmetic used by continuous storage.
func (d *DEXDevnetConfig) AncestryProofs() bool { return d != nil && d.Version == 5 }

func (c *ChainConfig) DEXDevnetActive(number *big.Int) bool {
	return c != nil && c.DEXDevnet != nil && number != nil && number.IsUint64() && number.Uint64() >= c.DEXDevnet.ActivationBlock
}

func (c *ChainConfig) ValidateDEXDevnet() error {
	if c == nil || c.DEXDevnet == nil {
		return nil
	}
	d := c.DEXDevnet
	if !c.FairHotstuff || !c.FixedCommittee || c.FixedLeader || len(c.GenCommittee) != 7 || c.ChainID == nil || !c.ChainID.IsUint64() || c.ChainID.Sign() <= 0 || (d.Version != 2 && !d.RollingAnchors()) || d.ActivationBlock == 0 || d.DEXID == (common.Hash{}) || d.GenesisSeed == (common.Hash{}) || d.Custody != DEXSettlementAddress || len(d.Committee) != 7 || d.MaxCheckpoints == 0 || d.MaxCheckpoints > 4096 {
		return errors.New("invalid genesis DEX devnet configuration")
	}
	keys := map[string]bool{}
	addresses := map[string]bool{}
	for _, n := range d.Committee {
		encoded, err := hex.DecodeString(n.Public)
		if err != nil || len(encoded) != 64 || bytes.Equal(encoded, make([]byte, 64)) {
			return errors.New("invalid genesis DEX key encoding")
		}
		key := bls.GetPublicKey(encoded)
		if key == nil || !bytes.Equal(key.Serialize(), encoded) {
			return errors.New("noncanonical genesis DEX key")
		}
		if n.Address == "" || len(n.Address) > 128 || keys[string(encoded)] || addresses[n.Address] {
			return errors.New("invalid genesis DEX committee")
		}
		keys[string(encoded)] = true
		addresses[n.Address] = true
	}
	return nil
}
