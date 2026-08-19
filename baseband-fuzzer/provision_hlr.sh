#!/bin/bash
# ============================================================================
# provision_hlr.sh  —  Seed the osmo-hlr SQLite database with a test subscriber
#
# Usage:  provision_hlr.sh <IMSI> <Ki> [<algo>]
#
#   IMSI   15-digit subscriber identity  (e.g. 001010000000001)
#   Ki     32 hex chars, no spaces       (e.g. 00000000000000000000000000000000)
#   algo   comp128v1 | comp128v2 | comp128v3   (default: comp128v1)
#
# Strategy:
#   1. Try to run osmo-hlr briefly so it creates/migrates its own schema.
#      This is preferred because it tracks schema-version bumps automatically.
#   2. If the DB does not appear within the timeout, create the schema
#      directly with sqlite3 using osmo-hlr's known table structure.
#      This ensures the build never fails due to a transient startup issue.
#   3. Upsert the subscriber row and 2G authentication key.
# ============================================================================
set -euo pipefail

IMSI="${1:?Usage: provision_hlr.sh <IMSI> <Ki> [<algo>]}"
KI="${2:?Ki (32 hex chars) required}"
ALGO="${3:-comp128v1}"
HLR_DB="${HLR_DB:-/var/lib/osmocom/hlr.db}"
HLR_CFG="${HLR_CFG:-/etc/osmocom/osmo-hlr.cfg}"

# ── Validate Ki format ────────────────────────────────────────────────────────
if [[ ! "$KI" =~ ^[0-9a-fA-F]{32}$ ]]; then
    echo "ERROR: Ki must be exactly 32 hex characters (got '${KI}')" >&2
    exit 1
fi

# ── Map algorithm name → osmo-hlr internal algo_id_2g integer ────────────────
case "$ALGO" in
    comp128v1) ALGO_ID=1 ;;
    comp128v2) ALGO_ID=2 ;;
    comp128v3) ALGO_ID=3 ;;
    *)
        echo "ERROR: Unknown algorithm '${ALGO}'. Valid: comp128v1 comp128v2 comp128v3" >&2
        exit 1
        ;;
esac

mkdir -p "$(dirname "$HLR_DB")"

# ── Step 1: Let osmo-hlr initialise / migrate the schema ─────────────────────
# osmo-hlr creates the SQLite DB synchronously at startup before binding any
# network ports, so a 5-second window is ample.  Show stderr so failures are
# visible in the build log, then send SIGTERM.
echo "[provision_hlr] Starting osmo-hlr to initialise schema …"
timeout 5s osmo-hlr -c "$HLR_CFG" 2>&1 || true

# ── Step 2: Fallback schema creation ─────────────────────────────────────────
# If osmo-hlr did not create the DB (e.g. because autoreconf or config parsing
# failed in this build environment), create the schema directly.  This mirrors
# osmo-hlr 1.x db_bootstrap() as of the 2024 release train.
if [[ ! -f "$HLR_DB" ]]; then
    echo "[provision_hlr] WARNING: osmo-hlr did not create DB; bootstrapping schema directly …"
    sqlite3 "$HLR_DB" <<'SCHEMA'
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS hlr (
    id INTEGER PRIMARY KEY,
    db_schema_version INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO hlr (id, db_schema_version) VALUES (1, 8);

CREATE TABLE IF NOT EXISTS subscriber (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    imsi       TEXT UNIQUE NOT NULL,
    msisdn     TEXT DEFAULT NULL,
    nam_cs     INTEGER NOT NULL DEFAULT 1,
    nam_ps     INTEGER NOT NULL DEFAULT 1,
    vlr_number TEXT DEFAULT NULL,
    sgsn_number TEXT DEFAULT NULL,
    sgsn_address TEXT DEFAULT NULL,
    periodic_lu_tmr INTEGER DEFAULT NULL,
    periodic_rau_tau_tmr INTEGER DEFAULT NULL,
    lmsi       INTEGER DEFAULT NULL,
    ms_purged_cs INTEGER NOT NULL DEFAULT 0,
    ms_purged_ps INTEGER NOT NULL DEFAULT 0,
    last_lu_seen DATETIME DEFAULT NULL,
    last_lu_seen_ps DATETIME DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS auc_2g (
    subscriber_id INTEGER PRIMARY KEY,
    algo_id_2g   INTEGER NOT NULL,
    ki           BLOB NOT NULL,
    FOREIGN KEY (subscriber_id) REFERENCES subscriber(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auc_3g (
    subscriber_id INTEGER PRIMARY KEY,
    algo_id_3g   INTEGER NOT NULL,
    k            BLOB NOT NULL,
    op           BLOB DEFAULT NULL,
    opc          BLOB DEFAULT NULL,
    sqn          INTEGER NOT NULL DEFAULT 0,
    ind_bitlen   INTEGER NOT NULL DEFAULT 5,
    FOREIGN KEY (subscriber_id) REFERENCES subscriber(id) ON DELETE CASCADE
);
SCHEMA
    echo "[provision_hlr] Schema created directly."
fi

if [[ ! -f "$HLR_DB" ]]; then
    echo "ERROR: HLR database could not be created at ${HLR_DB}" >&2
    exit 1
fi

# ── Step 3: Upsert subscriber + 2G authentication key ────────────────────────
echo "[provision_hlr] Provisioning IMSI=${IMSI} algo=${ALGO} …"

sqlite3 "$HLR_DB" <<ENDSQL
-- Subscriber row (idempotent)
INSERT OR IGNORE INTO subscriber (imsi) VALUES ('${IMSI}');

-- 2G authentication vector (overwrite if already present)
INSERT OR REPLACE INTO auc_2g (subscriber_id, algo_id_2g, ki)
    SELECT id, ${ALGO_ID}, x'${KI}'
    FROM   subscriber
    WHERE  imsi = '${IMSI}';
ENDSQL

echo "[provision_hlr] Done.  IMSI=${IMSI}  algo=${ALGO}  DB=${HLR_DB}"
