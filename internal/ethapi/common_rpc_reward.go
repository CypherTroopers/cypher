package ethapi

import (
	"context"
	"errors"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/accounts/keystore"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/commonrpcreward"
	"github.com/cypherium/cypher/rpc"
)

// The optional backend keeps light clients and unrelated API implementations
// independent of node-local storage. Full nodes provide the durable registry.
type commonRPCRewardBackend interface {
	CommonRPCRewardRegistry() *commonrpcreward.Registry
}

type ipcRewardMethodError struct{}

func (ipcRewardMethodError) Error() string {
	return "Common RPC reward registration is available only through IPC"
}
func (ipcRewardMethodError) ErrorCode() int { return -32601 }

func (s *PrivateAccountAPI) commonRPCRewardRegistry(ctx context.Context) (*commonrpcreward.Registry, error) {
	if !rpc.IsIPC(ctx) {
		return nil, ipcRewardMethodError{}
	}
	b, ok := s.b.(commonRPCRewardBackend)
	if !ok || b.CommonRPCRewardRegistry() == nil {
		return nil, errors.New("Common RPC reward registry unavailable on this backend")
	}
	return b.CommonRPCRewardRegistry(), nil
}

// SetCommonRPCRewardAddress changes only the future reward preference. Address
// decoding at the RPC boundary requires full-length hexadecimal addresses. B
// need not have a key, balance, code, or previous history on this node.
func (s *PrivateAccountAPI) SetCommonRPCRewardAddress(ctx context.Context, signer, recipient common.Address, password string) (commonrpcreward.Status, error) {
	registry, err := s.commonRPCRewardRegistry(ctx)
	if err != nil {
		return commonrpcreward.Status{}, err
	}
	if err := commonrpcreward.Validate(signer, recipient); err != nil {
		return commonrpcreward.Status{}, err
	}
	account := accounts.Account{Address: signer}
	var ks *keystore.KeyStore
	for _, backend := range s.am.Backends(keystore.KeyStoreType) {
		candidate := backend.(*keystore.KeyStore)
		if _, err := candidate.Find(account); err != nil {
			if errors.Is(err, keystore.ErrNoMatch) {
				continue
			}
			return commonrpcreward.Status{}, err
		}
		if ks != nil {
			return commonrpcreward.Status{}, errors.New("Common RPC signing account is ambiguous across local keystores")
		}
		ks = candidate
	}
	if ks == nil {
		return commonrpcreward.Status{}, errors.New("Common RPC reward registration requires a local keystore signing account")
	}
	if err := ks.VerifySigningPassword(account, password); err != nil {
		return commonrpcreward.Status{}, err
	}
	return registry.Set(signer, recipient)
}

// GetCommonRPCRewardAddress is IPC-only, including when the service is mounted
// on an internal handler. An unset value is returned explicitly as configured=false.
func (s *PrivateAccountAPI) GetCommonRPCRewardAddress(ctx context.Context, signer common.Address) (commonrpcreward.Status, error) {
	registry, err := s.commonRPCRewardRegistry(ctx)
	if err != nil {
		return commonrpcreward.Status{}, err
	}
	return registry.Get(signer)
}
