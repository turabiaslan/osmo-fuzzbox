#!/bin/bash
# ============================================================================
# entrypoint.sh — Start the Osmocom GSM stack inside the container
#
# Start order (dependency-driven):
#   1. osmo-stp   — SCCP/M3UA router; must be ready before BSC/MSC connect
#   2. osmo-hlr   — Subscriber DB; must be ready before MSC sends GSUP
#   3. osmo-mgw   — Media gateway; BSC+MSC connect at startup
#   4. osmo-msc   — MSC with in-process L3/MM fuzzer (mutates outgoing MM msgs)
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

# Ensure /tmp allows unix socket creation (PCU socket for osmo-bts).
# The host bind-mount (-v /tmp:/tmp) may have restrictive permissions.
chmod 1777 /tmp 2>/dev/null || true

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
echo "[entrypoint] Starting osmo-msc (in-process fuzzer) …"
osmo-msc -c /etc/osmocom/osmo-msc.cfg \
    >"${LOG_DIR}/osmo-msc.log" 2>&1 &
MSC_PID=$!

wait_port 4254 "osmo-msc VTY" "${LOG_DIR}/osmo-msc.log"

# ─── 5. osmo-bsc (base station controller) ───────────────────────────────────
echo "[entrypoint] Starting osmo-bsc …"
osmo-bsc -c /etc/osmocom/osmo-bsc.cfg \
    >"${LOG_DIR}/osmo-bsc.log" 2>&1 &
BSC_PID=$!

# IPA OML listener on port 3002 (BTS connects here)
wait_port 3002 "osmo-bsc OML" "${LOG_DIR}/osmo-bsc.log"

# ─── 6+7. BTS mode: virtual (default) or trx (B210 hardware) ─────────────────
# Set BTS_MODE=trx (env or build-arg) when real B210 hardware is attached.
# Default: virtual — no SDR needed, full L3/MM stack still exercises the hook.
BTS_MODE="${BTS_MODE:-virtual}"

if [[ "$BTS_MODE" == "trx" ]]; then
    # ── 6a. osmo-trx (TRX — drives the USRP B210) ───────────────────────────
    echo "[entrypoint] Starting osmo-trx (USRP B210) …"
    osmo-trx-uhd -C /etc/osmocom/osmo-trx.cfg \
        >"${LOG_DIR}/osmo-trx.log" 2>&1 &
    TRX_PID=$!

    # Wait for VTY (TCP 4236) — proves the process started
    wait_port 4236 "osmo-trx VTY" "${LOG_DIR}/osmo-trx.log"
    # If TRX VTY didn't come up, the B210 likely wasn't found.  FATAL.
    if ! kill -0 "$TRX_PID" 2>/dev/null; then
        echo "[entrypoint] FATAL: osmo-trx-uhd died (no B210 hardware?)" >&2
        tail -30 "${LOG_DIR}/osmo-trx.log" >&2
        exit 1
    fi

    # Wait for the TRXC UDP socket (port 5701) to be listening.
    # VTY ready ≠ TRXC ready.  The B210 needs time for USB enumeration,
    # clock synchronisation, and frequency tuning BEFORE it can accept POWERON.
    echo "[entrypoint] Waiting for TRXC UDP socket (port 5701) …"
    TRXC_WAIT=0
    while ! ss -ulnp 2>/dev/null | grep -qE ':5701([^0-9]|$)'; do
        sleep 1
        TRXC_WAIT=$((TRXC_WAIT + 1))
        if [[ $TRXC_WAIT -ge 45 ]]; then
            echo "[entrypoint] FATAL: osmo-trx TRXC (UDP 5701) not listening after 45s" >&2
            tail -30 "${LOG_DIR}/osmo-trx.log" >&2
            exit 1
        fi
    done
    echo "[entrypoint] ✓ TRXC UDP socket ready (port 5701)"

    # Extra settle time for B210 clock reference lock
    echo "[entrypoint] Waiting 5s for B210 clock settle …"
    sleep 5

    # ── 7a. osmo-bts-trx (BTS — links TRX and BSC) ──────────────────────────
    echo "[entrypoint] Starting osmo-bts-trx …"
    osmo-bts-trx -c /etc/osmocom/osmo-bts.cfg \
        >"${LOG_DIR}/osmo-bts.log" 2>&1 &
    BTS_PID=$!

    # Wait for BTS to connect to BSC (OML link) and achieve POWERON.
    # The BTS sends POWERON to TRX during its phy_link_open.
    echo "[entrypoint] Waiting for BTS POWERON + OML link …"
    BTS_WAIT=0
    BTS_READY=0
    while [[ $BTS_WAIT -lt 60 ]]; do
        sleep 2
        BTS_WAIT=$((BTS_WAIT + 2))

        # Check if BTS process died
        if ! kill -0 "$BTS_PID" 2>/dev/null; then
            echo "[entrypoint] FATAL: osmo-bts-trx died during startup" >&2
            tail -30 "${LOG_DIR}/osmo-bts.log" >&2
            exit 1
        fi

        # Check BTS log for successful POWERON response
        if grep -q "POWERON" "${LOG_DIR}/osmo-bts.log" 2>/dev/null; then
            echo "[entrypoint] ✓ TRX POWERON acknowledged"
            BTS_READY=1
            break
        fi
    done

    if [[ $BTS_READY -eq 0 ]]; then
        echo "[entrypoint] WARNING: POWERON not confirmed in 60s" >&2
        echo "--- osmo-trx log (last 20 lines) ---" >&2
        tail -20 "${LOG_DIR}/osmo-trx.log" >&2
        echo "--- osmo-bts log (last 20 lines) ---" >&2
        tail -20 "${LOG_DIR}/osmo-bts.log" >&2
        echo "[entrypoint] Continuing anyway — check logs above for clues" >&2
    fi

else
    # ── 6b+7b. osmo-bts-virtual (no SDR needed) ─────────────────────────────
    echo "[entrypoint] Starting osmo-bts-virtual (BTS_MODE=virtual, no SDR) …"
    osmo-bts-virtual -c /etc/osmocom/osmo-bts-virtual.cfg \
        >"${LOG_DIR}/osmo-bts.log" 2>&1 &
    BTS_PID=$!
fi

# BTS doesn't have a fixed standalone port to poll; give it time to start + OML
sleep 5

# Check if BTS connected to BSC (OML link)
if pgrep -f "osmo-bts" >/dev/null 2>&1; then
    echo "[entrypoint] ✓ BTS started (mode=${BTS_MODE})"
else
    echo "[entrypoint] WARNING: BTS process not running" >&2
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  Osmocom GSM stack started.                                      ║"
echo "║                                                                  ║"
echo "║  BTS mode : ${BTS_MODE}                                                  ║"
echo "║  Fuzzer   : in-process (see /var/log/osmocom/fuzzer.log)        ║"
echo "║  Config   : FUZZ_RATE=${FUZZ_RATE:-100}%  FUZZ_SEED=${FUZZ_SEED:-random}              ║"
echo "║                                                                  ║"
echo "║  Logs: /var/log/osmocom/<daemon>.log                             ║"
echo "╚══════════════════════════════════════════════════════════════════╝"

echo ""

# ─── Keep the container alive; watch critical daemons ────────────────────────
# 'wait -n' exits as soon as ANY child exits (e.g. osmo-trx without B210),
# which silently kills the container.  Instead, poll the critical PID set
# every 10 s and only exit (non-zero) if a core daemon dies.
CRITICAL_PIDS=(
    "osmo-stp:$STP_PID"
    "osmo-hlr:$HLR_PID"
    "osmo-mgw:$MGW_PID"
    "osmo-msc:$MSC_PID"
    "osmo-bsc:$BSC_PID"
)

while true; do
    sleep 10
    for entry in "${CRITICAL_PIDS[@]}"; do
        name="${entry%%:*}"
        pid="${entry##*:}"
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "[entrypoint] FATAL: ${name} (PID ${pid}) exited unexpectedly" >&2
            logfile="${LOG_DIR}/${name}.log"
            if [[ -f "$logfile" ]]; then
                echo "--- last 30 lines of ${logfile} ---" >&2
                tail -30 "$logfile" >&2
            fi
            exit 1
        fi
    done
done
