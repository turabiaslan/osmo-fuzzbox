# ============================================================================
# Makefile — Open Source Guard Baseband Fuzzing Pipeline
#
# Convenience targets for the Fedora RAN/Core node.
# All podman commands require root (rootful podman) for --net=host + USB.
#
# Usage:
#   sudo make build              # Build the container image
#   sudo make build IMSI=... KI=... ALGO=comp128v1   # With real SIM credentials
#   sudo make run                # Run the container (B210 must be attached)
#   sudo make export             # Export as air-gappable tarball
#   sudo make load               # Load exported tarball on target host
# ============================================================================

IMAGE_NAME  := localhost/baseband_fuzzer
IMAGE_TAG   := v1
FULL_IMAGE  := $(IMAGE_NAME):$(IMAGE_TAG)
TARBALL     := baseband_fuzzer_v1.tar

# ── Test SIM credentials (override with make build IMSI=... KI=... ALGO=...) ──
# Ki must be 32 hex characters (16 bytes, no spaces).
IMSI ?= 001010123456780
KI   ?= 42559F98E1958CFB15812CA3F953B076
ALGO ?= comp128v1

# ── BTS mode: virtual (default, no SDR) or trx (B210 hardware) ──────────────
BTS_MODE ?= virtual

# ── Fuzzer config (override with make run FUZZ_RATE=50 FUZZ_SEED=12345) ─────
FUZZ_RATE ?= 100
FUZZ_SEED ?=
FUZZ_SKIP ?= 10

# ── Podman run flags ──────────────────────────────────────────────────────────
# --net=host        : puts the container on the Fedora host network stack.
#                     Required for Abis/GSUP/A-interface loopback.
# --device /dev/bus/usb : USB passthrough for B210 (and HackRF).
PODMAN_RUN_FLAGS := \
    --rm -it \
    --net=host \
    --device=/dev/bus/usb \
    --name baseband_fuzzer

.PHONY: all build run debug-run inspect export load shell clean help

all: build

## build: Build the container image (pulls Osmocom sources at build time)
build:
	@echo "==> Building $(FULL_IMAGE)  [IMSI=$(IMSI) ALGO=$(ALGO)]"
	podman build \
	    --build-arg TEST_IMSI="$(IMSI)" \
	    --build-arg TEST_KI="$(KI)"     \
	    --build-arg TEST_ALGO="$(ALGO)" \
	    -t "$(FULL_IMAGE)" \
	    .
	@echo "==> Build complete: $(FULL_IMAGE)"

## run: Run the container
##      Default: BTS_MODE=virtual (no SDR).  Use BTS_MODE=trx for B210.
run:
	@echo "==> Starting $(FULL_IMAGE)  [BTS_MODE=$(BTS_MODE)]"
	@echo "    In-process fuzzer: rate=$(FUZZ_RATE)%"
	podman run $(PODMAN_RUN_FLAGS) \
	    -e BTS_MODE=$(BTS_MODE) \
	    -e FUZZ_RATE=$(FUZZ_RATE) \
	    -e FUZZ_SKIP=$(FUZZ_SKIP) \
	    $(if $(FUZZ_SEED),-e FUZZ_SEED=$(FUZZ_SEED)) \
	    "$(FULL_IMAGE)"

## debug-run: Like run, but keeps the container after exit so you can inspect it
##            After a crash: podman logs baseband_fuzzer  OR  podman start -ai baseband_fuzzer
debug-run:
	@echo "==> Starting $(FULL_IMAGE) in DEBUG mode [BTS_MODE=$(BTS_MODE)]"
	podman run \
	    -it \
	    --net=host \
	    --device=/dev/bus/usb \
	    --name baseband_fuzzer \
	    -e BTS_MODE=$(BTS_MODE) \
	    -e FUZZ_RATE=$(FUZZ_RATE) \
	    -e FUZZ_SKIP=$(FUZZ_SKIP) \
	    $(if $(FUZZ_SEED),-e FUZZ_SEED=$(FUZZ_SEED)) \
	    "$(FULL_IMAGE)" || true
	@echo ""
	@echo "==> Container stopped. Inspect with:"
	@echo "      podman logs baseband_fuzzer"
	@echo "      podman start -ai baseband_fuzzer"
	@echo "      podman rm baseband_fuzzer   (when done)"

## inspect: Dump all daemon logs from a stopped container (after debug-run crash)
inspect:
	@echo "==> Fetching logs from stopped container 'baseband_fuzzer'"
	@for d in osmo-stp osmo-hlr osmo-mgw osmo-msc osmo-bsc osmo-bts osmo-trx; do \
	    echo ""; \
	    echo "===== $${d}.log ====="; \
	    podman cp baseband_fuzzer:/var/log/osmocom/$${d}.log - 2>/dev/null \
	        | tar -xO 2>/dev/null || echo "(no log)"; \
	done

## export: Export the image to a portable tarball for air-gapped deployment
##         Always regenerates — safe to re-run after any rebuild.
export:
	@echo "==> Exporting $(FULL_IMAGE) → $(CURDIR)/$(TARBALL)"
	podman save -o "$(TARBALL)" "$(FULL_IMAGE)"
	@ls -lh "$(CURDIR)/$(TARBALL)"
	@echo "==> Full path: $(CURDIR)/$(TARBALL)"
	@echo "==> Copy this file + Makefile to your USB key."

## load: Load a previously exported tarball  (run on the air-gapped host)
load:
	@echo "==> Loading $(TARBALL)"
	podman load -i "$(TARBALL)"
	@echo "==> Loaded.  Run: sudo make run"

## shell: Drop into a shell inside the container (debugging)
shell:
	podman run --rm -it $(PODMAN_RUN_FLAGS) \
	    --entrypoint /bin/bash \
	    "$(FULL_IMAGE)"

## provision: Re-provision HLR inside a running container (update Ki after SIM reflash)
provision:
	@echo "==> Re-provisioning HLR (IMSI=$(IMSI) ALGO=$(ALGO))"
	podman exec baseband_fuzzer \
	    /usr/local/bin/provision_hlr.sh "$(IMSI)" "$(KI)" "$(ALGO)"

## logs: Follow daemon logs from a running container
logs:
	podman exec baseband_fuzzer \
	    tail -f /var/log/osmocom/osmo-msc.log \
	           /var/log/osmocom/osmo-bsc.log \
	           /var/log/osmocom/osmo-bts.log \
	           /var/log/osmocom/osmo-trx.log

## clean: Remove the local image
clean:
	podman rmi "$(FULL_IMAGE)" 2>/dev/null || true

## help: Show this help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
