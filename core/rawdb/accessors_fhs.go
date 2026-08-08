package rawdb

import (
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/ethdb"
)

var fhsSafetyStateKey = []byte("cypher-fhs-safety-v2")

var (
	fhsProposalPrefix    = []byte("cypher-fhs-proposal-v2/")
	fhsCertificatePrefix = []byte("cypher-fhs-cert-v2/")
)

func fhsHashKey(prefix []byte, hash common.Hash) []byte {
	key := make([]byte, len(prefix)+len(hash))
	copy(key, prefix)
	copy(key[len(prefix):], hash[:])
	return key
}

// ReadFHSSafetyState returns the opaque RLP safety record. Encoding belongs to
// reconfig/hotstuff so rawdb does not create a consensus import cycle.
func ReadFHSSafetyState(db ethdb.KeyValueReader) ([]byte, error) {
	has, err := db.Has(fhsSafetyStateKey)
	if err != nil || !has {
		return nil, err
	}
	data, err := db.Get(fhsSafetyStateKey)
	return common.CopyBytes(data), err
}

func WriteFHSSafetyState(db ethdb.KeyValueWriter, data []byte) error {
	return db.Put(fhsSafetyStateKey, common.CopyBytes(data))
}

func ReadFHSProposal(db ethdb.KeyValueReader, proposalID common.Hash) ([]byte, error) {
	key := fhsHashKey(fhsProposalPrefix, proposalID)
	has, err := db.Has(key)
	if err != nil || !has {
		return nil, err
	}
	data, err := db.Get(key)
	return common.CopyBytes(data), err
}

func WriteFHSProposal(db ethdb.KeyValueWriter, proposalID common.Hash, data []byte) error {
	return db.Put(fhsHashKey(fhsProposalPrefix, proposalID), common.CopyBytes(data))
}

func DeleteFHSProposal(db ethdb.KeyValueWriter, proposalID common.Hash) error {
	return db.Delete(fhsHashKey(fhsProposalPrefix, proposalID))
}

func ReadFHSCertificate(db ethdb.KeyValueReader, blockHash common.Hash) ([]byte, error) {
	key := fhsHashKey(fhsCertificatePrefix, blockHash)
	has, err := db.Has(key)
	if err != nil || !has {
		return nil, err
	}
	data, err := db.Get(key)
	return common.CopyBytes(data), err
}

func WriteFHSCertificate(db ethdb.KeyValueWriter, blockHash common.Hash, data []byte) error {
	return db.Put(fhsHashKey(fhsCertificatePrefix, blockHash), common.CopyBytes(data))
}

func DeleteFHSCertificate(db ethdb.KeyValueWriter, blockHash common.Hash) error {
	return db.Delete(fhsHashKey(fhsCertificatePrefix, blockHash))
}
