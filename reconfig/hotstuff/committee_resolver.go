package hotstuff

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/reconfig/bftview"
)

// CommitteeResolverApplication owns an independent historical committee
// registry. Once provided, missing or invalid entries fail closed: the protocol
// must never consult the CLX global registry for this application.
//
// ResolveHotstuffCommittee must return a stable snapshot for the exact epoch
// number/hash. Callers must not mutate registry entries concurrently with this
// call. GetPublicKey must use the same immutable historical signer ordering.
type CommitteeResolverApplication interface {
	ResolveHotstuffCommittee(keyNumber uint64, keyHash common.Hash, needIP bool) (*bftview.Committee, error)
}

// Application-owned keys must not alias the manager's immutable view snapshot.
// Legacy CLX applications retain their existing snapshot behavior.
func (hsm *HotstuffProtocolManager) snapshotApplicationKeys(keys []*bls.PublicKey) ([]*bls.PublicKey, error) {
	snapshot, err := snapshotPublicKeys(keys)
	if err != nil {
		return nil, err
	}
	if _, isolated := hsm.app.(CommitteeResolverApplication); !isolated {
		return snapshot, nil
	}
	for i, key := range snapshot {
		copyKey := new(bls.PublicKey)
		if err := copyKey.Deserialize(key.Serialize()); err != nil {
			return nil, err
		}
		snapshot[i] = copyKey
	}
	return snapshot, nil
}

func (hsm *HotstuffProtocolManager) loadCommittee(keyNumber uint64, keyHash, expectedHash common.Hash, needIP bool) (*bftview.Committee, error) {
	resolver, isolated := hsm.app.(CommitteeResolverApplication)
	if !isolated {
		return bftview.LoadMember(keyNumber, keyHash, needIP), nil
	}
	committee, err := resolver.ResolveHotstuffCommittee(keyNumber, keyHash, needIP)
	if err != nil {
		return nil, fmt.Errorf("resolve application committee: %w", err)
	}
	if committee == nil || keyHash == (common.Hash{}) || expectedHash == (common.Hash{}) {
		return nil, fmt.Errorf("%w: missing application committee", ErrInvalidLeaderView)
	}
	if err := ValidateBFTCommitteeSize(len(committee.List)); err != nil {
		return nil, err
	}
	keys, err := hsm.app.GetPublicKey(keyHash)
	if err != nil {
		return nil, err
	}
	if len(keys) != len(committee.List) {
		return nil, fmt.Errorf("%w: application committee key count mismatch", ErrInvalidPublicKey)
	}
	copyCommittee := &bftview.Committee{List: make([]*common.Cnode, len(committee.List))}
	identities := make(map[string]struct{}, len(committee.List))
	publicKeys := make(map[string]struct{}, len(committee.List))
	for i, member := range committee.List {
		if member == nil || keys[i] == nil {
			return nil, fmt.Errorf("%w: missing application member/key %d", ErrInvalidPublicKey, i)
		}
		copyMember := *member
		id := bftview.GetNodeID(copyMember.Address, copyMember.Public)
		if _, exists := identities[id]; id == "" || exists {
			return nil, fmt.Errorf("%w: empty or duplicate application member identity", ErrInvalidReplica)
		}
		identities[id] = struct{}{}
		encoded, err := hex.DecodeString(copyMember.Public)
		if err != nil || len(encoded) == 0 || !bytes.Equal(encoded, keys[i].Serialize()) {
			return nil, fmt.Errorf("%w: application committee key/order mismatch at %d", ErrInvalidPublicKey, i)
		}
		if _, exists := publicKeys[string(encoded)]; exists {
			return nil, fmt.Errorf("%w: duplicate application committee key", ErrInvalidPublicKey)
		}
		publicKeys[string(encoded)] = struct{}{}
		copyCommittee.List[i] = &copyMember
	}
	if copyCommittee.RlpHash() != expectedHash {
		return nil, fmt.Errorf("%w: application committee commitment mismatch", ErrInvalidLeaderView)
	}
	return copyCommittee, nil
}
