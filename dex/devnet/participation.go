package devnet

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"

	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
)

func EncodeParticipationAction(command engine.Action, key *ecdsa.PrivateKey, certificates []rewards.Certificate) ([]byte, error) {
	batch, err := rewards.SortedCommitBatch(certificates)
	if err != nil {
		return nil, err
	}
	payload, err := batch.Encode()
	if err != nil {
		return nil, err
	}
	h := protocol.Digest("common-dex/participation-commit/v2", payload)
	command.Kind = engine.RewardClose
	copy(command.Target[:], h[:20])
	signed, err := engine.Sign(command, key)
	if err != nil {
		return nil, err
	}
	out := append([]byte("CDXP"), signed...)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(payload)))
	out = append(out, n[:]...)
	out = append(out, payload...)
	if len(out) > consensus.MaxActionBytes {
		return nil, errors.New("participation action byte bound")
	}
	return out, nil
}

func decodeCommitAction(raw []byte) ([]byte, *rewards.CommitBatch, error) {
	if len(raw) < 4+engine.SignedActionSize+4 || len(raw) > consensus.MaxActionBytes || !bytes.Equal(raw[:4], []byte("CDXP")) {
		return nil, nil, errors.New("participation action envelope")
	}
	signed := raw[4 : 4+engine.SignedActionSize]
	tail := raw[4+engine.SignedActionSize:]
	if uint64(binary.BigEndian.Uint32(tail[:4])) != uint64(len(tail)-4) {
		return nil, nil, errors.New("participation payload length")
	}
	command, err := engine.Decode(signed)
	if err != nil {
		return nil, nil, err
	}
	h := protocol.Digest("common-dex/participation-commit/v2", tail[4:])
	var target [20]byte
	copy(target[:], h[:20])
	if command.Kind != engine.RewardClose || command.Target != target {
		return nil, nil, errors.New("participation payload signature binding")
	}
	batch, err := rewards.DecodeCommitBatch(tail[4:])
	if err != nil {
		return nil, nil, err
	}
	return signed, &batch, nil
}
