# Cypher native build entry points.
#
# GitHub Actions provisions the operating-system packages. The build helper
# handles module mode, BLS archives, platform naming, runtime verification,
# and clean artifact staging.

.PHONY: cypher bootnode all deps test clean tidy version LFG
.PHONY: cypher-linux-amd64 cypher-darwin-arm64 cypher-windows-amd64

GO ?= go
BINDIR ?= ./build/bin
STAGE_ROOT ?= ./build/stage
BUILD_TMPDIR ?= $(STAGE_ROOT)/tmp
TARGET_OS ?=
TARGET_ARCH ?=
BUILD_HELPER := ./build/build-cypher.sh

cypher:
	@GO="$(GO)" \
		BINDIR="$(BINDIR)" \
		STAGE_ROOT="$(STAGE_ROOT)" \
		BUILD_TMPDIR="$(BUILD_TMPDIR)" \
		TARGET_OS="$(TARGET_OS)" \
		TARGET_ARCH="$(TARGET_ARCH)" \
		$(BUILD_HELPER)

cypher-linux-amd64:
	@$(MAKE) cypher TARGET_OS=linux TARGET_ARCH=amd64

cypher-darwin-arm64:
	@$(MAKE) cypher TARGET_OS=darwin TARGET_ARCH=arm64

cypher-windows-amd64:
	@$(MAKE) cypher TARGET_OS=windows TARGET_ARCH=amd64

deps:
	@GO111MODULE=on $(GO) mod download
	@GO111MODULE=on $(GO) mod verify

bootnode: deps
	@mkdir -p "$(BINDIR)"
	@GO111MODULE=on $(GO) build -mod=readonly -trimpath -o "$(BINDIR)/bootnode" ./cmd/bootnode
	@echo "Built $(BINDIR)/bootnode"

all: cypher bootnode

tidy:
	@GO111MODULE=on $(GO) mod tidy

test:
	@GO111MODULE=on $(GO) test -mod=readonly ./...

clean:
	@rm -f "$(BINDIR)/cypher" "$(BINDIR)/bootnode"
	@rm -f "$(BINDIR)/cypher-linux-amd64"
	@rm -f "$(BINDIR)/cypher-darwin-arm64"
	@rm -f "$(BINDIR)/cypher.exe"
	@rm -f "$(BINDIR)/libcrypto-3-x64.dll"
	@rm -f "$(BINDIR)/libgmp-10.dll"
	@rm -f "$(BINDIR)/libstdc++-6.dll"
	@rm -f "$(BINDIR)/libgcc_s_seh-1.dll"
	@rm -f "$(BINDIR)/libwinpthread-1.dll"
	@rm -rf ./build/stage

version:
	@if [ -x "$(BINDIR)/cypher" ]; then \
		"$(BINDIR)/cypher" version; \
	elif [ -f "$(BINDIR)/cypher.exe" ]; then \
		"$(BINDIR)/cypher.exe" version; \
	else \
		echo "No native cypher binary found in $(BINDIR)" >&2; \
		exit 1; \
	fi

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
