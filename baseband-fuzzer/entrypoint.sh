#!/bin/bash
# ============================================================================
# entrypoint.sh — Start the Osmocom GSM stack inside the container
#
# Start order (dependency-driven):
#   1. osmo-stp   — SCCP/M3UA router; must be ready before BSC/MSC connect
#   2. osmo-hlr   — Subscriber DB; must be ready before MSC sends GSUP
#   3. osmo-mgw   — Media gateway; BSC+MSC connect at startup
#   4. osmo-msc   — MSC with L3/MM fuzzer hook (waits for Boofuzz on :27017)
#   5. osmo-bsc   — BSC; connects to STP+MGW, waits for BTS OML
#   6. osmo-trx   — TRX; drives the USRP B210 (blocks until B210 is found)
#   7. osmo-bts   — BTS; connects to TRX (UDP) and BSC (IPA/OML)
#
# Each step waits up to WAIT_SECS seconds for the expected port/process to
# appear before proceeding.  On any failure the entrypoint prints which
# daemon failed and exits non-zero (Podman will report the container as
# unhealthy).
#
# Logs:  /var/log/osmocom/<daemon>.log
# ============================================================================
set -euo pipefail

LOG_DIR=/var/log/osmocom
mkdir -p "$LOG_DIR"

WAIT_SECS=30    # timeout per daemon health-check

# ─── Helper: wait for a TCP port to be listening ─────────────────────────────
# Uses 'ss' (iproute2 — always present) instead of nc/netcat.
wait_port() {
    local port="$1"
    local desc="$2"
    local logfile="${3:-}"
    local elapsed=0

    echo "[entrypoint] Waiting for ${desc} on port ${port} …"
    while ! ss -tnlp 2>/dev/null | grep -qE ":${port}([^0-9]|$)"; do
        sleep 1
        elapsed=$((elapsed + 1))
        if [[ $elapsed -ge $WAIT_SECS ]]; then
            echo "[entrypoint] ERROR: ${desc} did not open port ${port} within ${WAIT_SECS}s" >&2
            if [[ -n "$logfile" && -f "$logfile" ]]; then
                echo "--- first 30 lines of ${logfile} ---" >&2
                head -30 "$logfile" >&2
                echo "--- last 20 lines of ${logfile} ---" >&2
                tail -20 "$logfile" >&2
            fi
            return 1
        fi
    done
    echo "[entrypoint] ✓ ${desc} ready (port ${port})"
}

# ─── Helper: wait for process by name ────────────────────────────────────────
wait_proc() {
    local proc="$1"
    local elapsed=0

    while ! pgrep -x "$proc" >/dev/null; do
        sleep 1
        elapsed=$((elapsed + 1))
        if [[ $elapsed -ge $WAIT_SECS ]]; then
            echo "[entrypoint] ERROR: ${proc} did not start within ${WAIT_SECS}s" >&2
            return 1
        fi
    done
}

# ─── 1. osmo-stp (SCCP/M3UA router) ─────────────────────────────────────────
echo "[entrypoint] Starting osmo-stp …"
osmo-stp -c /etc/osmocom/osmo-stp.cfg \
    >"${LOG_DIR}/osmo-stp.log" 2>&1 &
STP_PID=$!

# M3UA listener on port 2905 (SCTP); VTY TCP port at 4239
wait_port 4239 "osmo-stp VTY" "${LOG_DIR}/osmo-stp.log"

# ─── 2. osmo-hlr (subscriber database) ──────────────────────────────────────
echo "[entrypoint] Starting osmo-hlr …"
osmo-hlr -c /etc/osmocom/osmo-hlr.cfg \
         --database /var/lib/osmocom/hlr.db \
    >"${LOG_DIR}/osmo-hlr.log" 2>&1 &
HLR_PID=$!

# GSUP listens on port 4222
wait_port 4222 "osmo-hlr GSUP" "${LOG_DIR}/osmo-hlr.log"

# ─── 3. osmo-mgw (media gateway) ─────────────────────────────────────────────
echo "[entrypoint] Starting osmo-mgw …"
osmo-mgw -c /etc/osmocom/osmo-mgw.cfg \
    >"${LOG_DIR}/osmo-mgw.log" 2>&1 &
MGW_PID=$!

# MGCP listens on port 2427 (UDP; nc -z -u)
echo "[entrypoint] Waiting for osmo-mgw VTY …"
wait_port 4243 "osmo-mgw VTY" "${LOG_DIR}/osmo-mgw.log"

# ─── 4. osmo-msc (MSC — contains the L3/MM fuzzer hook) ─────────────────────
echo "[entrypoint] Starting osmo-msc (fuzzer hook on TCP:27017) …"
osmo-msc -c /etc/osmocom/osmo-msc.cfg \
    >"${LOG_DIR}/osmo-msc.log" 2>&1 &
MSC_PID=$!

# VTY port 4254; the fuzzer hook port (27017) is opened lazily on first MM TX
wait_port 4254 "osmo-msc VTY" "${LOG_DIR}/osmo-msc.log"

# ─── 5. osmo-bsc (base station controller) ───────────────────────────────────
echo "[entrypoint] Starting osmo-bsc …"
osmo-bsc -c /etc/osmocom/osmo-bsc.cfg \
    >"${LOG_DIR}/osmo-bsc.log" 2>&1 &
BSC_PID=$!

# IPA OML listener on port 3002 (BTS connects here)
wait_port 3002 "osmo-bsc OML" "${LOG_DIR}/osmo-bsc.log"

# ─── 6. osmo-trx (TRX — drives the USRP B210) ───────────────────────────────
echo "[entrypoint] Starting osmo-trx (USRP B210) …"
osmo-trx-uhd -C /etc/osmocom/osmo-trx.cfg \
    >"${LOG_DIR}/osmo-trx.log" 2>&1 &
TRX_PID=$!

# osmo-trx VTY on port 4236 — non-fatal (requires physical B210 USB hardware)
wait_port 4236 "osmo-trx VTY" "${LOG_DIR}/osmo-trx.log" || \
    echo "[entrypoint] NOTE: osmo-trx not ready (no B210 hardware?) — radio stack offline, fuzzer core OK"

# ─── 7. osmo-bts (BTS — links TRX and BSC) ───────────────────────────────────
echo "[entrypoint] Starting osmo-bts-trx …"
osmo-bts-trx -c /etc/osmocom/osmo-bts.cfg \
    >"${LOG_DIR}/osmo-bts.log" 2>&1 &
BTS_PID=$!

# BTS doesn't have a fixed standalone port to poll; just give it 5s to start
sleep 5

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  Osmocom GSM stack started.                                      ║"
echo "║                                                                  ║"
echo "║  Fuzzer hook: TCP port 27017 (opens on first MM TX)             ║"
echo "║  → Connect Boofuzz on Windows to <FedoraIP>:27017               ║"
echo "║                                                                  ║"
echo "║  Logs: /var/log/osmocom/<daemon>.log                             ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# ─── Monitor: restart any daemon that exits unexpectedly ─────────────────────
# Simple crash-watch: if any background PID exits non-zero, log and exit.
monitor() {
    local pid="$1"
    local name="$2"
    wait "$pid"
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "[entrypoint] ERROR: ${name} (PID ${pid}) exited with code ${rc}" >&2
        echo "[entrypoint] Last 20 lines of ${LOG_DIR}/${name}.log:" >&2
        tail -20 "${LOG_DIR}/${name}.log" >&2
        exit "$rc"
    fi
}

# Wait on any child; if one dies, log and exit (let Podman restart the container)
wait -n 2>/dev/null || {
    # -n not available on older bash; fall back to waiting on the BTS (leaf node)
    wait "$BTS_PID"
}
