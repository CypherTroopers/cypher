// Copyright 2017 The cypherBFT Authors
// This file is part of the cypherBFT library.
//
// The cypherBFT library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The cypherBFT library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the cypherBFT library. If not, see <http://www.gnu.org/licenses/>.

package bftview

import (
	"bytes"
	"io"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/rlp"
	"golang.org/x/crypto/sha3"
)

type View struct {
	TxNumber      uint64
	TxHash        common.Hash
	KeyNumber     uint64
	KeyHash       common.Hash
	CommitteeHash common.Hash
	LeaderIndex   uint
	NoDone        bool
	Round         uint64
	ViewNumber    uint64
}

// Check for identity
func (v *View) EqualAll(other *View) bool {
	return v.TxNumber == other.TxNumber && v.TxHash == other.TxHash && v.KeyNumber == other.KeyNumber && v.KeyHash == other.KeyHash && v.CommitteeHash == other.CommitteeHash && v.LeaderIndex == other.LeaderIndex && v.NoDone == other.NoDone && v.Round == other.Round && v.ViewNumber == other.ViewNumber
}

// EqualConsensus compares only fields that identify a HotStuff view. NoDone and
// Round are local liveness/proposal-mode fields and may change while an
// otherwise identical view is still in flight.
func (v *View) EqualConsensus(other *View) bool {
	if v == nil || other == nil {
		return v == other
	}
	return v.TxNumber == other.TxNumber &&
		v.TxHash == other.TxHash &&
		v.KeyNumber == other.KeyNumber &&
		v.KeyHash == other.KeyHash &&
		v.CommitteeHash == other.CommitteeHash &&
		v.LeaderIndex == other.LeaderIndex &&
		v.ViewNumber == other.ViewNumber
}

// Check for identity except index
func (v *View) EqualNoIndex(other *View) bool {
	return v.TxNumber == other.TxNumber && v.TxHash == other.TxHash && v.KeyNumber == other.KeyNumber && v.KeyHash == other.KeyHash && v.ViewNumber == other.ViewNumber
}

func (v *View) Hash() (h common.Hash) {
	hw := sha3.NewLegacyKeccak256()
	if v.Round == 0 && v.ViewNumber == 0 {
		rlp.Encode(hw, []interface{}{v.TxNumber, v.TxHash, v.KeyNumber, v.KeyHash, v.CommitteeHash, v.LeaderIndex, v.NoDone})
	} else if v.ViewNumber == 0 {
		rlp.Encode(hw, []interface{}{v.TxNumber, v.TxHash, v.KeyNumber, v.KeyHash, v.CommitteeHash, v.LeaderIndex, v.NoDone, v.Round})
	} else {
		rlp.Encode(hw, []interface{}{v.TxNumber, v.TxHash, v.KeyNumber, v.KeyHash, v.CommitteeHash, v.LeaderIndex, v.NoDone, v.Round, v.ViewNumber})
	}
	hw.Sum(h[:0])
	return h
}

type ViewExt struct {
	TxNumber      uint64
	TxHash        common.Hash
	KeyNumber     uint64
	KeyHash       common.Hash
	CommitteeHash common.Hash
	LeaderIndex   uint
	NoDone        bool
	Tail          []uint64 `rlp:"tail"`
}

func (v *View) DecodeRLP(s *rlp.Stream) error {
	var eb ViewExt
	if err := s.Decode(&eb); err != nil {
		return err
	}
	v.KeyNumber, v.KeyHash, v.TxNumber, v.TxHash = eb.KeyNumber, eb.KeyHash, eb.TxNumber, eb.TxHash
	v.CommitteeHash, v.LeaderIndex, v.NoDone = eb.CommitteeHash, eb.LeaderIndex, eb.NoDone
	v.Round = 0
	v.ViewNumber = 0
	if len(eb.Tail) > 0 {
		v.Round = eb.Tail[0]
	}
	if len(eb.Tail) > 1 {
		v.ViewNumber = eb.Tail[1]
	}

	return nil
}

func (v *View) EncodeRLP(w io.Writer) error {
	var tail []uint64
	if v.ViewNumber != 0 {
		tail = []uint64{v.Round, v.ViewNumber}
	} else if v.Round != 0 {
		tail = []uint64{v.Round}
	}
	return rlp.Encode(w, ViewExt{
		TxNumber:      v.TxNumber,
		TxHash:        v.TxHash,
		KeyNumber:     v.KeyNumber,
		KeyHash:       v.KeyHash,
		CommitteeHash: v.CommitteeHash,
		LeaderIndex:   v.LeaderIndex,
		NoDone:        v.NoDone,
		Tail:          tail,
	})
}

func (v *View) EncodeToBytes() []byte {
	m := make([]byte, 0)
	buff := bytes.NewBuffer(m)
	err := v.EncodeRLP(buff)
	if err != nil {
		return nil
	}

	return buff.Bytes()
}

// ConsensusView returns the state signed by HotStuff. NoDone and Round are
// intentionally normalized because they control local proposal/recovery timing,
// not which chain state and committee the replicas are voting for.
func (v *View) ConsensusView() View {
	if v == nil {
		return View{}
	}
	consensus := *v
	consensus.NoDone = false
	consensus.Round = 0
	return consensus
}

func (v *View) ConsensusHash() common.Hash {
	consensus := v.ConsensusView()
	return consensus.Hash()
}

func (v *View) EncodeConsensusToBytes() []byte {
	consensus := v.ConsensusView()
	return consensus.EncodeToBytes()
}

func DecodeToView(data []byte) *View {
	v := &View{}
	buff := bytes.NewBuffer(data)
	c := rlp.NewStream(buff, 0)
	err := v.DecodeRLP(c)
	if err != nil {
		log.Error("DecodeToView", "error", err)
		return nil
	}
	return v
}
