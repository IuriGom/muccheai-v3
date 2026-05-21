# MuccheAI v3.0 — One-command install
# Just type: make install

.PHONY: install build test clean setup

INSTALL_DIR := $(HOME)/.cargo/bin
BINARY := $(INSTALL_DIR)/muccheai
CONFIG := $(HOME)/.muccheai/config.toml

install: build
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║  Installing MuccheAI...                                      ║"
	@echo "╚══════════════════════════════════════════════════════════════╝"
	@echo ""
	cargo install --path . --force
	@echo ""
	@if [ ! -f "$(CONFIG)" ]; then \
		echo "First run detected. Launching setup wizard..."; \
		echo ""; \
		$(BINARY) setup; \
	else \
		echo "✓ muccheai installed at $(BINARY)"; \
		echo ""; \
		echo "Run 'muccheai --help' to get started."; \
	fi
	@echo ""
	@echo "If 'muccheai' is not found, add $(INSTALL_DIR) to your PATH:"
	@echo '  export PATH="$$HOME/.cargo/bin:$$PATH"'

build:
	cargo build --release

test:
	cargo test --workspace

setup:
	$(BINARY) setup

reset:
	@echo "Resetting MuccheAI (deleting config, memories, vault)..."
	rm -rf $(HOME)/.muccheai
	cargo clean
	@echo "Reset complete. Run 'make install' to start fresh."

clean:
	cargo clean
