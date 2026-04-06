BINARY := bin/colossusx
CMD_DIR := ./cmd/colossusx
GO ?= go

.PHONY: help SKY colossusx run-help bench-small bench-cpu mine-easy clean

help:
	@echo "Available targets:"
	@echo "  make SKY         - Download Go module dependencies"
	@echo "  make colossusx   - Build $(BINARY)"
	@echo "  make run-help    - Show CLI help"
	@echo "  make bench-small - Run a small verified unified benchmark"
	@echo "  make bench-cpu   - Run a small verified CPU benchmark"
	@echo "  make mine-easy   - Run an easy-target mining check"
	@echo "  make clean       - Remove built artifacts"

SKY:
	$(GO) mod download

colossusx:
	mkdir -p bin
	$(GO) build -o $(BINARY) $(CMD_DIR)

run-help:
	$(GO) run $(CMD_DIR) -h

bench-small:
	$(GO) run $(CMD_DIR) -bench -backend unified -dag-mib 1 -max-nonces 1000 -workers 2

bench-cpu:
	$(GO) run $(CMD_DIR) -bench -backend cpu -dag-mib 1 -max-nonces 1000 -workers 2

mine-easy:
	$(GO) run $(CMD_DIR) -backend unified -dag-mib 1 -workers 2 -max-nonces 10 -target ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

clean:
	python -c "import os, shutil; shutil.rmtree('bin', ignore_errors=True)"
