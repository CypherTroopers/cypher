# Cypher Makefile for Go modules

.PHONY: cypher bootnode all test clean tidy version LFG
.PHONY: cypher-linux-amd64 cypher-darwin-amd64 cypher-windows-amd64

GOBIN := ./build/bin
GO ?= go
GOMOD := -mod=mod

cypher:
	@mkdir -p $(GOBIN)
	$(GO) build $(GOMOD) -o $(GOBIN)/cypher ./cmd/cypher
	@echo "Done building."
	@echo "Run \"$(GOBIN)/cypher\" to launch cypher."

bootnode:
	@mkdir -p $(GOBIN)
	$(GO) build $(GOMOD) -o $(GOBIN)/bootnode ./cmd/bootnode
	@echo "Done building."
	@echo "Run \"$(GOBIN)/bootnode\" to launch bootnode."

all: cypher bootnode

tidy:
	$(GO) mod tidy

test:
	$(GO) test $(GOMOD) ./...

clean:
	$(GO) clean -cache
	rm -f $(GOBIN)/cypher $(GOBIN)/bootnode
	rm -f $(GOBIN)/cypher-linux-amd64
	rm -f $(GOBIN)/cypher-darwin-amd64
	rm -f $(GOBIN)/cypher.exe

version:
	$(GOBIN)/cypher version

cypher-linux-amd64:
	@mkdir -p $(GOBIN)
	GOOS=linux GOARCH=amd64 $(GO) build $(GOMOD) -o $(GOBIN)/cypher-linux-amd64 ./cmd/cypher

cypher-darwin-amd64:
	@mkdir -p $(GOBIN)
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOMOD) -o $(GOBIN)/cypher-darwin-amd64 ./cmd/cypher

cypher-windows-amd64:
	@mkdir -p $(GOBIN)
	GOOS=windows GOARCH=amd64 $(GO) build $(GOMOD) -o $(GOBIN)/cypher.exe ./cmd/cypher

.PHONY: LFG

LFG:
	@printf '%s\n' \
	'                    Cypherium is Back!!' \
	'' \
	'                          🌕' \
	'                           *' \
	'                              *' \
	'                                 *' \
	'                           🚀🚀🚀' \
	'                          /     \' \
	'                         /_______\' \
	'                         |  C Y  |' \
	'                         |  P H  |' \
	'                         |  E R  |' \
	'                         |  I U  |' \
	'                         |   M   |' \
	'                         |       |' \
	'                         /_______\' \
	'                        /_________\' \
	'                           |   |' \
	'                           |   |' \
	'                        ___/   \___' \
	'                      _/   /   \   \_' \
	'                    _/    /     \    \_' \
	'                  _/     /       \     \_' \
	'                _/      /         \      \_' \
	'              _/       /           \       \_' \
	'            _/        /             \        \_' \
	'                 BOOSTER IGNITION >>>>>' \
	'                 Cypherium is Back!!' \
	'        ────────────  LFT LAUNCH  ────────────' \
	'' \
	'                       _________' \
	'                  .-´           `-.' \
	'               .-´                 `-.' \
	'            .-´                     `-.' \
	'           /                           \' \
	'          /                             \' \
	'         |          🌍  EARTH           |' \
	'         |                               |' \
	'         |  [AI]--[AI]--[AI]--[AI]--[AI] |' \
	'         |    |  \/   |  \/   |  \/      |' \
	'         |  [AI]--[AI]--[AI]--[AI]--[AI] |' \
	'         |    |   |   |   |   |   |      |' \
	'         |  [AI]--[AI]--[AI]--[AI]--[AI] |' \
	'         |    |  /\   |  /\   |  /\      |' \
	'         |  [AI]--[AI]--[AI]--[AI]--[AI] |' \
	'         |    |   |   |   |   |   |      |' \
	'         |  [AI]--[AI]--[AI]--[AI]--[AI] |' \
	'         |                               |' \
	'          \                             /' \
	'           \                           /' \
	'            `-.                     .-´' \
	'               `-.               .-´' \
	'                  `-._       _.-´' \
	'                       `---´' \
	'' \
	'     AI NODES NETWORK ACTIVE (GLOBAL CONSENSUS)'
