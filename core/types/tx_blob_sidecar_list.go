package types

import (
	"runtime"
	"sync"
)

const maxParallelBlobVerificationWorkers = 64

func blobVerificationWorkerBudget() int {
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		return 1
	}
	if workers > maxParallelBlobVerificationWorkers {
		return maxParallelBlobVerificationWorkers
	}
	return workers
}

// All block and authenticated-ingress callers share one KZG CPU budget. A
// per-call worker limit alone would still let many QUIC streams multiply into
// an unbounded verifier population during a burst.
var blobVerificationSlots = make(chan struct{}, blobVerificationWorkerBudget())

func runBoundedBlobVerification(count int, verify func(int)) {
	if count <= 0 || verify == nil {
		return
	}
	workers := cap(blobVerificationSlots)
	if workers > count {
		workers = count
	}
	blobVerificationSlots <- struct{}{}
	acquired := 1
	for acquired < workers {
		select {
		case blobVerificationSlots <- struct{}{}:
			acquired++
		default:
			workers = acquired
			acquired = workers
		}
	}
	jobs := make(chan int, workers)
	var group sync.WaitGroup
	group.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer group.Done()
			defer func() { <-blobVerificationSlots }()
			for index := range jobs {
				verify(index)
			}
		}()
	}
	for index := 0; index < count; index++ {
		jobs <- index
	}
	close(jobs)
	group.Wait()
}

// VerifyBlobSidecars verifies every BlobTx sidecar attached to the transaction
// list. Non-blob transactions are ignored. BlobTxs must have an attached sidecar
// and a non-nil verifier.
func VerifyBlobSidecars(txs Transactions, verifier BlobVerifier) error {
	return verifyBlobSidecars(txs, nil, verifier)
}

// VerifyBlobSidecarsForVersion additionally binds every sidecar to the format
// required by the active fork (v0 through Prague, v1 from Osaka).
func VerifyBlobSidecarsForVersion(txs Transactions, version byte, verifier BlobVerifier) error {
	return verifyBlobSidecars(txs, &version, verifier)
}

func verifyBlobSidecars(txs Transactions, version *byte, verifier BlobVerifier) error {
	if verifier == nil {
		return ErrBlobVerifierMissing
	}
	blobTxs := make(Transactions, 0)
	for _, tx := range txs {
		if tx == nil || tx.Type() != BlobTxType {
			continue
		}
		blobTxs = append(blobTxs, tx)
	}
	if len(blobTxs) < 2 {
		for _, tx := range blobTxs {
			if err := verifyBlobTransactionSidecar(tx, version, verifier); err != nil {
				return err
			}
		}
		return nil
	}
	// BlobVerifier does not generally promise concurrency safety. The real KZG
	// verifier is stateless over a process-wide immutable trusted setup, so only
	// that implementation is fanned out here. Tests and custom verifiers retain
	// the historical serial call contract.
	switch verifier.(type) {
	case KZGBlobVerifier, *KZGBlobVerifier:
	default:
		for _, tx := range blobTxs {
			if err := verifyBlobTransactionSidecar(tx, version, verifier); err != nil {
				return err
			}
		}
		return nil
	}
	errs := make([]error, len(blobTxs))
	runBoundedBlobVerification(len(blobTxs), func(index int) {
		tx := blobTxs[index]
		errs[index] = verifyBlobTransactionSidecar(tx, version, verifier)
	})
	// Worker timing is never observable: report the first error in canonical
	// transaction order, matching the serial verifier exactly.
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func verifyBlobTransactionSidecar(tx *Transaction, version *byte, verifier BlobVerifier) error {
	if version != nil {
		return tx.VerifyBlobSidecarVersion(tx.BlobSidecar(), *version, verifier)
	}
	return tx.VerifyBlobSidecar(tx.BlobSidecar(), verifier)
}
