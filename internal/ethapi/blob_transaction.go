package ethapi

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"github.com/cypherium/cypher/core/types"
	kzg "github.com/cypherium/cypher/crypto/kzg4844"
	"github.com/cypherium/cypher/params"
)

const maxManagedBlobBuilders = 64

var managedBlobBuilderSlots = make(chan struct{}, managedBlobBuilderBudget())

func managedBlobBuilderBudget() int {
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		return 1
	}
	if workers > maxManagedBlobBuilders {
		return maxManagedBlobBuilders
	}
	return workers
}

func (args *SendTxArgs) hasBlobSidecarFields() bool {
	return args != nil && (args.Blobs != nil || args.Commitments != nil || args.Proofs != nil)
}

func acquireManagedBlobBuilder(ctx context.Context) (func(), error) {
	select {
	case managedBlobBuilderSlots <- struct{}{}:
		return func() { <-managedBlobBuilderSlots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// setBlobSidecarDefaults constructs and verifies the EIP-4844 pooled sidecar
// used by eth_sendTransaction, eth_signTransaction and eth_fillTransaction.
// Expensive KZG work is process-bounded so concurrent managed-account RPCs
// cannot multiply CPU usage without limit before transaction-pool admission.
func (args *SendTxArgs) setBlobSidecarDefaults(ctx context.Context, version byte) error {
	if args == nil {
		return errors.New("nil transaction arguments")
	}
	if version != types.BlobSidecarVersion0 && version != types.BlobSidecarVersion1 {
		return fmt.Errorf("unsupported blob sidecar version %d", version)
	}
	if len(args.Blobs) == 0 {
		return errors.New("blob transaction requires blobs for pooled propagation")
	}
	if len(args.Blobs) > params.BlobTxMaxBlobs {
		return fmt.Errorf("blob transaction has %d blobs, maximum is %d", len(args.Blobs), params.BlobTxMaxBlobs)
	}
	if args.Commitments != nil && len(args.Commitments) != len(args.Blobs) {
		return fmt.Errorf("blob sidecar commitment count %d does not match blob count %d", len(args.Commitments), len(args.Blobs))
	}
	wantProofs := len(args.Blobs)
	if version == types.BlobSidecarVersion1 {
		wantProofs *= kzg.CellProofsPerBlob
	}
	if args.Proofs != nil && len(args.Proofs) != wantProofs {
		return fmt.Errorf("blob sidecar proof count %d does not match required count %d for version %d", len(args.Proofs), wantProofs, version)
	}

	release, err := acquireManagedBlobBuilder(ctx)
	if err != nil {
		return err
	}
	defer release()

	if args.Commitments == nil {
		args.Commitments = make([]kzg.Commitment, len(args.Blobs))
		for i := range args.Blobs {
			commitment, err := kzg.BlobToCommitment(&args.Blobs[i])
			if err != nil {
				return fmt.Errorf("compute blob commitment %d: %w", i, err)
			}
			args.Commitments[i] = commitment
		}
	}
	if args.Proofs == nil {
		args.Proofs = make([]kzg.Proof, 0, wantProofs)
		for i := range args.Blobs {
			switch version {
			case types.BlobSidecarVersion0:
				proof, err := kzg.ComputeBlobProof(&args.Blobs[i], args.Commitments[i])
				if err != nil {
					return fmt.Errorf("compute blob proof %d: %w", i, err)
				}
				args.Proofs = append(args.Proofs, proof)
			case types.BlobSidecarVersion1:
				proofs, err := kzg.ComputeCellProofs(&args.Blobs[i])
				if err != nil {
					return fmt.Errorf("compute blob cell proofs %d: %w", i, err)
				}
				args.Proofs = append(args.Proofs, proofs...)
			}
		}
	}
	switch version {
	case types.BlobSidecarVersion0:
		for i := range args.Blobs {
			if err := kzg.VerifyBlobProof(&args.Blobs[i], args.Commitments[i], args.Proofs[i]); err != nil {
				return fmt.Errorf("verify blob proof %d: %w", i, err)
			}
		}
	case types.BlobSidecarVersion1:
		if err := kzg.VerifyCellProofs(args.Blobs, args.Commitments, args.Proofs); err != nil {
			return fmt.Errorf("verify blob cell proofs: %w", err)
		}
	}
	args.blobSidecarVersion = version

	sidecar := args.blobSidecar()
	if len(args.BlobVersionedHashes) == 0 {
		args.BlobVersionedHashes = sidecar.BlobHashes()
	}
	if err := sidecar.ValidateBlobHashes(args.BlobVersionedHashes); err != nil {
		return fmt.Errorf("blob sidecar: %w", err)
	}
	return nil
}

func (args *SendTxArgs) blobSidecar() *types.BlobTxSidecar {
	if args == nil || len(args.Blobs) == 0 {
		return nil
	}
	sidecar := &types.BlobTxSidecar{
		Version:     args.blobSidecarVersion,
		Blobs:       make([]types.Blob, len(args.Blobs)),
		Commitments: make([]types.KZGCommitment, len(args.Commitments)),
		Proofs:      make([]types.KZGProof, len(args.Proofs)),
	}
	for i := range args.Blobs {
		sidecar.Blobs[i] = append(types.Blob(nil), args.Blobs[i][:]...)
	}
	for i := range args.Commitments {
		sidecar.Commitments[i] = types.KZGCommitment(args.Commitments[i])
	}
	for i := range args.Proofs {
		sidecar.Proofs[i] = types.KZGProof(args.Proofs[i])
	}
	return sidecar
}

func blobSidecarVersionForBackend(b Backend) byte {
	if b == nil || b.ChainConfig() == nil {
		return types.BlobSidecarVersion0
	}
	head := b.CurrentHeader()
	if head == nil || head.Number == nil {
		return types.BlobSidecarVersion0
	}
	return types.BlobSidecarVersionForOsaka(b.ChainConfig().IsOsaka(head.Number, head.Time))
}

func marshalTransactionForRPC(tx *types.Transaction) ([]byte, error) {
	if tx != nil && tx.Type() == types.BlobTxType && tx.BlobSidecar() != nil {
		return tx.MarshalPooledBinary()
	}
	return tx.MarshalBinary()
}
