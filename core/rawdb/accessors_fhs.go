package rawdb

import (
	"fmt"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/ethdb"
)

var fhsSafetyStateKey = []byte("cypher-fhs-safety")

var (
	fhsProposalPrefix    = []byte("cypher-fhs-proposal/")
	fhsBodyPrefix        = []byte("cypher-fhs-body/")
	fhsCertificatePrefix = []byte("cypher-fhs-cert/")
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

// IterateFHSProposals visits every durable proposal proof. The value is owned
// by the iterator and is only valid for the duration of the callback.
func IterateFHSProposals(db ethdb.Iteratee, visit func(common.Hash, []byte) error) error {
	return iterateFHSHashRecords(db, fhsProposalPrefix, visit)
}

func ReadFHSBody(db ethdb.KeyValueReader, bodyHash common.Hash) ([]byte, error) {
	key := fhsHashKey(fhsBodyPrefix, bodyHash)
	has, err := db.Has(key)
	if err != nil || !has {
		return nil, err
	}
	data, err := db.Get(key)
	return common.CopyBytes(data), err
}

func WriteFHSBody(db ethdb.KeyValueWriter, bodyHash common.Hash, data []byte) error {
	return db.Put(fhsHashKey(fhsBodyPrefix, bodyHash), common.CopyBytes(data))
}

func DeleteFHSBody(db ethdb.KeyValueWriter, bodyHash common.Hash) error {
	return db.Delete(fhsHashKey(fhsBodyPrefix, bodyHash))
}

// IterateFHSBodies visits content-addressed body hashes without loading the
// potentially multi-megabyte values from disk.
func IterateFHSBodies(db ethdb.Iteratee, visit func(common.Hash) error) error {
	if db == nil || visit == nil {
		return fmt.Errorf("invalid FHS body iterator")
	}
	iterator := db.NewIterator(fhsBodyPrefix, nil)
	defer iterator.Release()
	for iterator.Next() {
		key := iterator.Key()
		if len(key) != len(fhsBodyPrefix)+common.HashLength {
			return fmt.Errorf("invalid FHS record key length %d for prefix %q", len(key), fhsBodyPrefix)
		}
		if err := visit(common.BytesToHash(key[len(fhsBodyPrefix):])); err != nil {
			return err
		}
	}
	return iterator.Error()
}

// Certificates are keyed by proposal identity, which includes the view. The
// same execution block may have independently valid certificates in many views.
func ReadFHSCertificate(db ethdb.KeyValueReader, proposalID common.Hash) ([]byte, error) {
	key := fhsHashKey(fhsCertificatePrefix, proposalID)
	has, err := db.Has(key)
	if err != nil || !has {
		return nil, err
	}
	data, err := db.Get(key)
	return common.CopyBytes(data), err
}

func WriteFHSCertificate(db ethdb.KeyValueWriter, proposalID common.Hash, data []byte) error {
	return db.Put(fhsHashKey(fhsCertificatePrefix, proposalID), common.CopyBytes(data))
}

func DeleteFHSCertificate(db ethdb.KeyValueWriter, proposalID common.Hash) error {
	return db.Delete(fhsHashKey(fhsCertificatePrefix, proposalID))
}

// IterateFHSCertificates visits every durable certificate. The value is owned
// by the iterator and is only valid for the duration of the callback.
func IterateFHSCertificates(db ethdb.Iteratee, visit func(common.Hash, []byte) error) error {
	return iterateFHSHashRecords(db, fhsCertificatePrefix, visit)
}

func iterateFHSHashRecords(db ethdb.Iteratee, prefix []byte, visit func(common.Hash, []byte) error) error {
	if db == nil || visit == nil {
		return fmt.Errorf("invalid FHS record iterator")
	}
	iterator := db.NewIterator(prefix, nil)
	defer iterator.Release()
	for iterator.Next() {
		key := iterator.Key()
		if len(key) != len(prefix)+common.HashLength {
			return fmt.Errorf("invalid FHS record key length %d for prefix %q", len(key), prefix)
		}
		if err := visit(common.BytesToHash(key[len(prefix):]), iterator.Value()); err != nil {
			return err
		}
	}
	return iterator.Error()
}
