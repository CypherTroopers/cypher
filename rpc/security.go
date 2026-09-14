package rpc

import (
	"context"
)

type securityContextKey string
type securityContext context.Context

const (
	HttpAuthorizationHeader = "Authorization"
	// this key is exported for WS transport
	CtxCredentialsProvider   = securityContextKey("CREDENTIALS_PROVIDER")   // key to save reference to rpc.HttpCredentialsProviderFunc
	CtxPreauthenticatedToken = securityContextKey("PREAUTHENTICATED_TOKEN") // key to save the preauthenticated token once authenticated
)

type securityContextConfigurer interface {
	Configure(secCtx securityContext)
}

type securityContextResolver interface {
	Resolve() securityContext
}

// Provider function to return token being injected in Authorization http request header
type HttpCredentialsProviderFunc func(ctx context.Context) (string, error)
