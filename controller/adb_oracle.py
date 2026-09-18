#!/usr/bin/env python3
"""
adb_oracle.py — ADB crash oracle for the 2G/GSM baseband fuzzing pipeline
==========================================================================

Run alongside fuzzer.py on the Windows control node (or any host with ADB
access to the target phone):

    pip install pyserial
    python adb_oracle.py --log fuzzer_results.jsonl [--serial <device>]

What it does
────────────
1. Tails the ADB logcat stream on the attached target phone.
2. Watches for crash/reboot indicators in the baseband log sources:
     • RILJ / RILC / RILQ     — RIL (Radio Interface Layer) errors
     • kernel / klogd          — kernel panics, modem subsystem restarts
     • SSR (Subsystem Restart) — Qualcomm modem SSR events
     • android.hardware.radio  — HIDL/AIDL radio HAL crashes
3. When a crash indicator is detected it:
     a. Records the crash timestamp.
     b. Correlates it against the most recent fuzzer_results.jsonl entry
        (the mutation that was in-flight when the crash occurred).
     c. Appends a  crash_events.jsonl  record with:
          - crash timestamp
          - correlated fuzzer iteration + strategy + mutated bytes
          - raw logcat lines captured around the crash

Usage tips
──────────
• Run fuzzer.py first; fuzzer_results.jsonl will be written as mutations proceed.
• Run adb_oracle.py in a second terminal on the same Windows machine.
• After a crash: the phone may reboot; adb_oracle.py reconnects automatically.
• Cross-reference crash_events.jsonl with fuzzer_results.jsonl by iteration
  number to reproduce a specific crash.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from collections import deque
from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────────────────────────
# Crash-indicator patterns (case-insensitive substring matches in logcat lines)
# ─────────────────────────────────────────────────────────────────────────────
CRASH_PATTERNS = [
    # Qualcomm modem subsystem restart
    "subsystem restart",
    "modem subsystem failure",
    "ssr: modem",
    "wcnss_fatal",
    # RIL errors indicating the baseband fell off the bus
    "rilj: radio not available",
    "ril: baseband went offline",
    "ril: lost connection",
    "radio not available",
    # Kernel / modem panic
    "kernel panic",
    "fatal error on modem",
    "ramdump",
    # HAL layer
    "hidl service died",
    "android.hardware.radio",
    # Generic crash signals
    "fatal exception",
    "process died",
    "crash_dump",
    "tomb:",
    # IMS / voice stack (catches CC-layer state machine panics)
    "ims: fatal",
]


def is_crash_line(line: str) -> bool:
    lo = line.lower()
    return any(pat in lo for pat in CRASH_PATTERNS)


# ─────────────────────────────────────────────────────────────────────────────
# Read the most recent entry from fuzzer_results.jsonl
# ─────────────────────────────────────────────────────────────────────────────

def last_fuzzer_record(log_path: str) -> dict | None:
    if not os.path.isfile(log_path):
        return None
    last = None
    with open(log_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    last = json.loads(line)
                except json.JSONDecodeError:
                    pass
    return last


# ─────────────────────────────────────────────────────────────────────────────
# ADB logcat stream
# ─────────────────────────────────────────────────────────────────────────────

def adb_logcat(serial: str | None):
    """
    Generator: yields logcat lines as strings.
    Reconnects automatically if ADB disconnects (e.g., phone reboot).
    """
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += ["logcat", "-v", "threadtime"]

    while True:
        print(f"[oracle] Starting logcat: {' '.join(cmd)}")
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            for line in proc.stdout:
                yield line.rstrip()
            proc.wait()
            print(f"[oracle] logcat process ended (rc={proc.returncode}); reconnecting …")
        except FileNotFoundError:
            sys.exit("[oracle] ERROR: 'adb' not found on PATH. "
                     "Install Android platform-tools and add to PATH.")
        except Exception as exc:
            print(f"[oracle] logcat exception: {exc}; reconnecting in 3 s …")

        time.sleep(3)


# ─────────────────────────────────────────────────────────────────────────────
# Main oracle loop
# ─────────────────────────────────────────────────────────────────────────────

def run_oracle(serial: str | None, fuzzer_log: str, crash_log: str,
               context_lines: int) -> None:
    crash_out = open(crash_log, "a", encoding="utf-8")
    window: deque[str] = deque(maxlen=context_lines)
    crash_count = 0

    print(f"[oracle] Watching logcat for crash indicators …")
    print(f"[oracle] Fuzzer log:  {fuzzer_log}")
    print(f"[oracle] Crash log:   {crash_log}")

    for line in adb_logcat(serial):
        window.append(line)

        if is_crash_line(line):
            crash_count += 1
            ts = datetime.now(timezone.utc).isoformat()

            # Correlate with the most recent fuzzer mutation
            fuzz_rec = last_fuzzer_record(fuzzer_log)

            record = {
                "crash_id":     crash_count,
                "crash_ts":     ts,
                "trigger_line": line,
                "context":      list(window),
                "fuzzer":       fuzz_rec,   # None if fuzzer not running
            }

            crash_out.write(json.dumps(record) + "\n")
            crash_out.flush()

            print(f"\n[oracle] ═══ CRASH #{crash_count} DETECTED ═══")
            print(f"[oracle]  Time:      {ts}")
            print(f"[oracle]  Trigger:   {line}")
            if fuzz_rec:
                print(f"[oracle]  Iter:      {fuzz_rec.get('iteration')}")
                print(f"[oracle]  Strategy:  {fuzz_rec.get('strategy')}")
                print(f"[oracle]  Mutated:   {fuzz_rec.get('mutated')}")
            print(f"[oracle]  Logged to: {crash_log}\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ADB crash oracle — correlates baseband crashes with fuzzer mutations"
    )
    parser.add_argument("--serial", default=None,
                        help="ADB device serial (omit if only one device attached)")
    parser.add_argument("--log", default="fuzzer_results.jsonl",
                        help="fuzzer.py output log to correlate against (default: fuzzer_results.jsonl)")
    parser.add_argument("--crash-log", default="crash_events.jsonl",
                        help="Output crash event log (default: crash_events.jsonl)")
    parser.add_argument("--context", type=int, default=40,
                        help="Number of logcat lines to capture around each crash (default: 40)")
    args = parser.parse_args()

    run_oracle(args.serial, args.log, args.crash_log, args.context)


if __name__ == "__main__":
    main()
