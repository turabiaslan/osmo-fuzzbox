#!/usr/bin/env python3
"""
adb_auth_monitor.py — Monitor Android radio logs for SIM authentication failures.

Works on Windows (and Linux/Mac). Requires 'adb' in PATH.

Usage:
    python adb_auth_monitor.py              # live capture
    python adb_auth_monitor.py --duration 60  # capture for 60 seconds
    python adb_auth_monitor.py --save        # save full log to file

The script monitors:
  - MM/GMM reject causes (auth failure, PLMN not allowed, etc.)
  - RIL authentication events
  - Network registration state changes
  - SIM status transitions
"""

import subprocess
import sys
import time
import re
import os
import signal
from datetime import datetime
from collections import Counter

# ─── Configuration ────────────────────────────────────────────────────────────

# 3GPP TS 24.008 Table 10.5.95 — GMM/MM reject cause codes
REJECT_CAUSES = {
    2:  "IMSI unknown in HLR",
    3:  "Illegal MS",
    4:  "IMSI unknown in VLR",
    5:  "IMEI not accepted",
    6:  "Illegal ME",
    7:  "GPRS services not allowed",
    8:  "GPRS+non-GPRS not allowed",
    9:  "MS identity cannot be derived",
    10: "Implicitly detached",
    11: "PLMN not allowed",
    12: "Location Area not allowed",
    13: "Roaming not allowed in this LA",
    14: "GPRS not allowed in this PLMN",
    15: "No suitable cells in LA",
    17: "Network failure",
    20: "MAC failure",
    21: "Synch failure",
    22: "Congestion",
    23: "GSM authentication unacceptable",
    25: "Not authorized for this CSG",
    40: "No PDP context activated",
}

# Patterns that indicate auth-related events
AUTH_PATTERNS = [
    # Direct authentication
    (r"AUTHENTICATION[_ ]FAILURE",               "🔴 AUTH FAILURE"),
    (r"AUTHENTICATION[_ ]REJECT",                "🔴 AUTH REJECT"),
    (r"AUTH.*FAIL",                               "🔴 AUTH FAIL"),
    (r"MAC[_ ]FAILURE",                           "🔴 MAC FAILURE (SRES mismatch)"),
    (r"SYNCH[_ ]FAILURE",                         "🔴 SYNCH FAILURE"),

    # Reject causes
    (r"REJECT.*[Cc]ause\s*[#=:]\s*([1-9]\d*)",    "🔴 REJECT"),
    (r"rejectCause=([1-9]\d*)",                    "🔴 REJECT CAUSE"),
    (r"MM[_ ]REJECT",                              "🔴 MM REJECT"),
    (r"LU[_ ]REJECT",                              "🔴 LU REJECT"),
    (r"ATTACH[_ ]REJECT",                         "🔴 ATTACH REJECT"),
    (r"SERVICE[_ ]REJECT",                        "🔴 SERVICE REJECT"),
    (r"CM[_ ]SERVICE[_ ]REJECT",                  "🔴 CM SERVICE REJECT"),

    # Network rejection
    (r"PLMN[_ ]NOT[_ ]ALLOWED",                   "🔴 PLMN NOT ALLOWED"),
    (r"NOT[_ ]ALLOWED",                            "🟡 NOT ALLOWED"),
    (r"ILLEGAL[_ ]M[SE]",                          "🔴 ILLEGAL MS/ME"),
    (r"FORBIDDEN",                                 "🔴 FORBIDDEN"),
    (r"DENIED",                                    "🟡 DENIED"),

    # Registration events
    (r"REG.*STATE.*DENIED",                        "🟡 REG DENIED"),
    (r"REGISTRATION[_ ]FAILURE",                   "🔴 REG FAILURE"),

    # SIM events
    (r"SIM[_ ]ERROR",                              "🔴 SIM ERROR"),
    (r"SIM[_ ]NOT[_ ]READY",                       "🟡 SIM NOT READY"),
    (r"USIM.*AUTH",                                "🟢 USIM AUTH event"),

    # Registration state
    (r"mVoiceRegState=1",                          "🟡 OUT_OF_SERVICE"),
    (r"NOT_REG_OR_SEARCHING",                      "🟡 searching, no cell"),

    # Positive auth events (for flow tracking)
    (r"AUTH.*REQUEST",                             "🟢 AUTH REQUEST received"),
    (r"AUTH.*RESPONSE",                            "🟢 AUTH RESPONSE sent"),
    (r"mVoiceRegState=0",                          "🟢 IN_SERVICE (registered)"),
    (r"REGISTERED",                                "🟢 REGISTERED"),
    (r"CAMP.*ON",                                  "🟢 CAMPED ON cell"),
]

# Compile patterns
COMPILED_PATTERNS = [(re.compile(p, re.IGNORECASE), label) for p, label in AUTH_PATTERNS]


def check_adb():
    """Verify adb is available and a device is connected."""
    try:
        result = subprocess.run(
            ["adb", "devices"],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().split("\n")
        devices = [l for l in lines[1:] if l.strip() and "device" in l and "offline" not in l]
        if not devices:
            print("ERROR: No Android device found. Connect phone via USB and enable USB debugging.")
            print("       Run: adb devices")
            sys.exit(1)
        print(f"  ✓ ADB device found: {devices[0].split()[0]}")
        return True
    except FileNotFoundError:
        print("ERROR: 'adb' not found in PATH.")
        print("       Install Android SDK Platform-Tools:")
        print("       https://developer.android.com/studio/releases/platform-tools")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("ERROR: adb timed out. Is the ADB server running?")
        sys.exit(1)


def format_cause(cause_num):
    """Decode a 3GPP reject cause number."""
    try:
        n = int(cause_num)
        desc = REJECT_CAUSES.get(n, "Unknown cause")
        return f"Cause #{n}: {desc}"
    except (ValueError, TypeError):
        return ""


def monitor(duration=None, save_log=False):
    """Main monitoring loop."""
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  ADB Auth Monitor — SIM Authentication Failure Detector    ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()

    check_adb()

    # Clear logcat buffer for clean capture
    subprocess.run(["adb", "logcat", "-b", "radio", "-c"], timeout=5)
    print("  ✓ Radio log buffer cleared")
    print()

    if duration:
        print(f"  Monitoring for {duration} seconds...")
    else:
        print("  Monitoring indefinitely — press Ctrl+C to stop and see summary")
    print()
    print("─" * 64)

    # Start logcat
    proc = subprocess.Popen(
        ["adb", "logcat", "-b", "radio", "-v", "time"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    events = []
    event_counter = Counter()
    start_time = time.time()
    log_lines = []
    last_cause = None

    try:
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue

            if save_log:
                log_lines.append(line)

            # Check elapsed time
            if duration and (time.time() - start_time) >= duration:
                break

            # Match against patterns
            for pattern, label in COMPILED_PATTERNS:
                match = pattern.search(line)
                if match:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    event_counter[label] += 1

                    # Extract cause code if present
                    cause_info = ""
                    cause_match = re.search(r"[Cc]ause\s*[#=:]\s*(\d+)", line)
                    if cause_match:
                        cause_info = f" → {format_cause(cause_match.group(1))}"
                        last_cause = cause_match.group(1)

                    # Print the event
                    print(f"  [{timestamp}] {label}{cause_info}")

                    # For failures, show the raw line
                    if "🔴" in label:
                        # Truncate long lines
                        display = line[:120] + "..." if len(line) > 120 else line
                        print(f"             {display}")
                        print()

                    events.append({
                        "time": timestamp,
                        "label": label,
                        "cause": cause_info,
                        "raw": line[:200]
                    })
                    break  # Only match first pattern per line

    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    # ─── Summary ──────────────────────────────────────────────────────────────
    elapsed = int(time.time() - start_time)
    print()
    print("═" * 64)
    print("  SUMMARY")
    print("═" * 64)
    print(f"  Duration: {elapsed}s  |  Total events: {len(events)}")
    print()

    if event_counter:
        failures = {k: v for k, v in event_counter.items() if "🔴" in k}
        warnings = {k: v for k, v in event_counter.items() if "🟡" in k}
        success  = {k: v for k, v in event_counter.items() if "🟢" in k}

        if failures:
            print("  ❌ FAILURES:")
            for label, count in sorted(failures.items(), key=lambda x: -x[1]):
                print(f"     {count:3d}x  {label}")
            print()

            # Diagnosis
            print("  📋 DIAGNOSIS:")
            if any("MAC FAILURE" in k or "SRES" in k for k in failures):
                print("     → SRES mismatch: Ki in HLR doesn't match SIM card")
                print("       Check: Ki value, algorithm (COMP128v1 vs v2 vs v3)")
            if any("SYNCH" in k for k in failures):
                print("     → SQN desync: re-provision auth data in HLR")
            if any("PLMN" in k for k in failures):
                print("     → Phone's SIM doesn't allow this PLMN (MCC/MNC)")
                print("       Check: MCC=001, MNC=01 matches SIM's allowed PLMNs")
            if any("ILLEGAL" in k for k in failures):
                print("     → IMSI/IMEI rejected by network")
            if any("IMSI unknown" in str(last_cause) for _ in [1]):
                print("     → IMSI not provisioned in HLR")
            print()

        if warnings:
            print("  ⚠️  WARNINGS:")
            for label, count in sorted(warnings.items(), key=lambda x: -x[1]):
                print(f"     {count:3d}x  {label}")
            print()

        if success:
            print("  ✅ POSITIVE EVENTS:")
            for label, count in sorted(success.items(), key=lambda x: -x[1]):
                print(f"     {count:3d}x  {label}")
            print()
    else:
        print("  No auth-related events detected.")
        print("  → Is the phone trying to register? Toggle airplane mode.")
        print()

    # Save log if requested
    if save_log and log_lines:
        logfile = f"adb_radio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        with open(logfile, "w", encoding="utf-8") as f:
            f.write("\n".join(log_lines))
        print(f"  Full log saved: {logfile}")
        print()

    print("═" * 64)


if __name__ == "__main__":
    duration = None
    save_log = False

    for arg in sys.argv[1:]:
        if arg == "--save":
            save_log = True
        elif arg == "--duration":
            idx = sys.argv.index(arg)
            if idx + 1 < len(sys.argv):
                duration = int(sys.argv[idx + 1])
        elif arg.isdigit() and sys.argv[sys.argv.index(arg) - 1] == "--duration":
            pass  # already handled
        elif arg == "--help" or arg == "-h":
            print(__doc__)
            sys.exit(0)

    monitor(duration=duration, save_log=save_log)
