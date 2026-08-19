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
IMSI ?= 001010000000001
KI   ?= 00000000000000000000000000000000
ALGO ?= comp128v1

# ── Podman run flags ──────────────────────────────────────────────────────────
# --net=host        : puts the container on the Fedora host network stack.
#                     Required for Abis/GSUP/A-interface loopback AND makes the
#                     fuzzer hook port (27017) directly reachable from Windows.
# --device /dev/bus/usb : USB passthrough for B210 (and HackRF).
#                     If udev permissions bite, fall back to --privileged.
# -v /tmp:/tmp      : Only needed if the optional L1 FIFO path is used.
#                     The primary L3 TCP path does not require this.
PODMAN_RUN_FLAGS := \
    --rm -it \
    --net=host \
    --device=/dev/bus/usb \
    -v /tmp:/tmp \
    --name baseband_fuzzer

.PHONY: all build run export load shell clean help

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

## run: Run the container (B210 must be attached via USB)
run:
	@echo "==> Starting $(FULL_IMAGE)"
	@echo "    Fuzzer hook will listen on TCP port 27017 once the first MM TX occurs."
	podman run $(PODMAN_RUN_FLAGS) "$(FULL_IMAGE)"

## export: Export the image to a portable tarball for air-gapped deployment
export: $(TARBALL)

$(TARBALL):
	@echo "==> Exporting $(FULL_IMAGE) → $(TARBALL)"
	podman save -o "$(TARBALL)" "$(FULL_IMAGE)"
	@ls -lh "$(TARBALL)"
	@echo "==> Transfer $(TARBALL) to the air-gapped host and run: sudo make load"

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
