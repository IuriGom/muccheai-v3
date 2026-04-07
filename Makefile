# MuccheAI v3.0 — One-command install
# Just type: make install

.PHONY: install build test clean setup reset deep-clean run

INSTALL_DIR := $(HOME)/.cargo/bin
BINARY := $(INSTALL_DIR)/muccheai
CONFIG := $(HOME)/.muccheai/config.toml

install:
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

# Default `cargo run` builds debug (huge target/ dir). Use `make run` for release.
run:
	cargo run --release

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
	@echo ""
	@echo "Reset complete. Next steps:"
	@echo "  1. Run 'make install' to rebuild and auto-launch setup"
	@echo "  2. Or run 'cargo run -- setup' to run setup with the dev build"
	@echo ""
	@echo "⚠️  NOTE: 'cargo run' without --release creates a ~3-6 GB debug target."
	@echo "         Use 'make run' or 'cargo run --release' to avoid bloat."

dep-clean: clean
	@echo "Clearing global cargo registry cache..."
	rm -rf $(HOME)/.cargo/registry/cache
	@echo "Deep clean complete."

clean:
	cargo clean
