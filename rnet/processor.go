package rnet

import (
	"errors"
	"net/http"

	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/rnet/network"
)

// ServiceProcessor embeds the service context and provides default request
// handlers. Services register committee message processors through Context.
type ServiceProcessor struct {
	*Context
}

// NewServiceProcessor initializes your ServiceProcessor.
func NewServiceProcessor(c *Context) *ServiceProcessor {
	return &ServiceProcessor{
		Context: c,
	}
}

// Process implements the Processor interface and dispatches ClientRequest messages.
func (p *ServiceProcessor) Process(env *network.Envelope) {
	panic("Cannot handle message.")
}

// ProcessClientRequest rejects client requests because this service has no
// websocket handler registry.
func (p *ServiceProcessor) ProcessClientRequest(req *http.Request, path string, buf []byte) ([]byte, error) {
	err := errors.New("The requested message hasn't been registered: " + path)
	log.Error("ProcessClientRequest", "error", err)
	return nil, err
}
