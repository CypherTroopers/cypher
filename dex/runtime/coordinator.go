package runtime

import (
	"context"
	"errors"
)

type Role uint8

const (
	PoW Role = iota
	RPC
	DEX
)

// Lifecycle is a boundary for independently managed roles. Existing miner and
// RPC APIs are deliberately not adapted here until real integration is tested.
type Lifecycle interface {
	Start(context.Context) error
	Stop(context.Context) error
}

// Coordinator contains no shared callback lock, rollback, or cross-role stop.
// Every role remains responsible for serializing its own lifecycle transitions.
type Coordinator struct{ roles [3]Lifecycle }

func NewCoordinator(pow, rpc, dex Lifecycle) *Coordinator {
	return &Coordinator{roles: [3]Lifecycle{pow, rpc, dex}}
}

func (c *Coordinator) Start(ctx context.Context, role Role) error {
	if int(role) >= len(c.roles) || c.roles[role] == nil {
		return errors.New("role unavailable")
	}
	return c.roles[role].Start(ctx)
}

func (c *Coordinator) Stop(ctx context.Context, role Role) error {
	if int(role) >= len(c.roles) || c.roles[role] == nil {
		return errors.New("role unavailable")
	}
	return c.roles[role].Stop(ctx)
}
