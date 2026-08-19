#!/usr/bin/env python3
"""
fuzzer.py — Windows-side Boofuzz orchestrator for the 2G/GSM baseband pipeline
==============================================================================

Run on the Windows control node (or any host with network access to the
Fedora container):

    pip install boofuzz
    python fuzzer.py --host <FedoraIP> --port 27017 [--iterations 1000]

Architecture
────────────
The Osmocom MSC has the fuzzer_hook compiled in.  Every time it is about to
transmit an MM Authentication Request or Identity Request downlink, it:

  1. Sends "READY <state_tag>"      (framed: [u16-BE len][bytes])
  2. Sends the original message bytes (framed: [u16-BE len][bytes])
  3. Blocks waiting for us to send back mutated bytes

We receive both frames, mutate the payload, and send it back.  The mutated
bytes replace the outgoing message in the MSC before it reaches the BTS/RF.

Mutation strategies (applied round-robin):
  • PassThrough      — original bytes unchanged (baseline)
  • BitFlip          — single-bit flips across the payload
  • ByteFlip         — single-byte substitutions (0x00, 0xFF, 0xFE, 0x7F …)
  • LengthTruncate   — progressively shorter payloads
  • LengthExtend     — append extra bytes beyond declared length
  • KeySeqCorrupt    — corrupt the GSM key-sequence nibble (byte 0, bits 3-0)
  • RandBytes        — random bytes replacing the entire payload
  • BoundaryValues   — structured GSM48 boundary patterns

Each mutation is logged to  fuzzer_results.jsonl  with:
  - iteration index
  - mutation strategy name
  - original bytes (hex)
  - mutated bytes (hex)
  - timestamp

Correlate with ADB output from  adb_oracle.py  on the same machine.
"""

import argparse
import json
import os
import random
import socket
import struct
import sys
import time
from datetime import datetime, timezone


# ─────────────────────────────────────────────────────────────────────────────
# Wire protocol helpers
# ─────────────────────────────────────────────────────────────────────────────

def send_frame(sock: socket.socket, data: bytes) -> None:
    """Send one length-prefixed frame: [u16-BE length][payload]."""
    sock.sendall(struct.pack(">H", len(data)) + data)


def recv_frame(sock: socket.socket) -> bytes:
    """Receive one length-prefixed frame; raises on disconnect."""
    raw_len = _recv_exact(sock, 2)
    length = struct.unpack(">H", raw_len)[0]
    if length == 0:
        return b""
    return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Hook socket closed unexpectedly")
        buf += chunk
    return buf


# ─────────────────────────────────────────────────────────────────────────────
# Mutation strategies
# ─────────────────────────────────────────────────────────────────────────────

class MutationEngine:
    """
    Stateful mutation engine.  Call next_mutation(original_bytes) to get the
    next mutated payload.  Iterates through strategies round-robin.
    """

    # GSM 04.08 §10.5.3.1 — Authentication Request layout (9 bytes minimum):
    #  Byte 0: PD = 0x05 (MM), MT = 0x12 (Auth Req)  [or split as L3 header]
    #  Byte 1: key sequence (bits 3-0)
    #  Bytes 2-17: RAND (16 bytes)
    # Total over L3: includes LAPDm/RLL header prepended by BTS layer.
    # We target the raw gsm48 msgb bytes as seen in the MSC (post-gsm48_hdr).

    INTERESTING_BYTES = [
        0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF,
        # GSM-specific
        0x05, 0x12, 0x18, 0x08, 0x0F,
    ]

    def __init__(self):
        self._strategies = [
            self._passthrough,
            self._bit_flip,
            self._byte_boundary,
            self._key_seq_corrupt,
            self._truncate,
            self._extend,
            self._rand_bytes,
            self._null_rand,
            self._all_ff_rand,
            self._structured_boundary,
        ]
        self._strategy_index = 0
        self._bit_offset = 0
        self._byte_pos = 0
        self._trunc_amount = 1
        self._iteration = 0

    @property
    def strategy_name(self) -> str:
        return self._strategies[self._strategy_index].__name__.lstrip("_")

    def next_mutation(self, original: bytes) -> bytes:
        strategy = self._strategies[self._strategy_index]
        result = strategy(original)
        self._iteration += 1

        # Advance strategy state
        self._bit_offset += 1
        if self._bit_offset >= len(original) * 8:
            self._bit_offset = 0
            self._strategy_index = (self._strategy_index + 1) % len(self._strategies)

        self._byte_pos = (self._byte_pos + 1) % max(1, len(original))
        return result

    # ── Individual strategies ─────────────────────────────────────────────

    def _passthrough(self, data: bytes) -> bytes:
        return data

    def _bit_flip(self, data: bytes) -> bytes:
        if not data:
            return data
        arr = bytearray(data)
        bit = self._bit_offset % (len(arr) * 8)
        byte_idx = bit // 8
        bit_idx  = bit % 8
        arr[byte_idx] ^= (1 << bit_idx)
        return bytes(arr)

    def _byte_boundary(self, data: bytes) -> bytes:
        if not data:
            return data
        arr = bytearray(data)
        pos = self._byte_pos % len(arr)
        idx = (self._iteration // len(arr)) % len(self.INTERESTING_BYTES)
        arr[pos] = self.INTERESTING_BYTES[idx]
        return bytes(arr)

    def _key_seq_corrupt(self, data: bytes) -> bytes:
        """Corrupt the key sequence nibble in the first byte after the L3 header."""
        if len(data) < 2:
            return data
        arr = bytearray(data)
        # Byte index 1 in the gsm48 auth req payload = key_seq field (lower nibble)
        # 0xF = "no key", 0x7 = "UMTS derived", etc.
        seq_values = [0x00, 0x07, 0x0F, 0x08, 0xFF]
        idx = (self._iteration) % len(seq_values)
        arr[1] = (arr[1] & 0xF0) | seq_values[idx]
        return bytes(arr)

    def _truncate(self, data: bytes) -> bytes:
        amount = max(1, self._trunc_amount)
        self._trunc_amount = (self._trunc_amount % max(1, len(data) - 1)) + 1
        return data[:-amount] if len(data) > amount else data[:1]

    def _extend(self, data: bytes) -> bytes:
        extra = bytes([0xAA] * (self._iteration % 32 + 1))
        return data + extra

    def _rand_bytes(self, data: bytes) -> bytes:
        return bytes(random.getrandbits(8) for _ in data)

    def _null_rand(self, data: bytes) -> bytes:
        """Replace the RAND field (bytes 2-17 in auth req) with 0x00…00."""
        arr = bytearray(data)
        for i in range(2, min(18, len(arr))):
            arr[i] = 0x00
        return bytes(arr)

    def _all_ff_rand(self, data: bytes) -> bytes:
        """Replace the RAND field with 0xFF…FF."""
        arr = bytearray(data)
        for i in range(2, min(18, len(arr))):
            arr[i] = 0xFF
        return bytes(arr)

    def _structured_boundary(self, data: bytes) -> bytes:
        """
        Craft a structurally valid-looking Auth Req with boundary values:
          PD=0x05 | MT=0x12 (correct header) but RAND = repeating 0x41 ('A').
        """
        if len(data) < 2:
            return data
        arr = bytearray(data)
        for i in range(2, min(18, len(arr))):
            arr[i] = 0x41
        return bytes(arr)


# ─────────────────────────────────────────────────────────────────────────────
# Main fuzzer loop
# ─────────────────────────────────────────────────────────────────────────────

def run_fuzzer(host: str, port: int, iterations: int, log_path: str) -> None:
    engine = MutationEngine()
    log_file = open(log_path, "a", encoding="utf-8")

    print(f"[fuzzer] Connecting to hook at {host}:{port} …")
    while True:
        try:
            sock = socket.create_connection((host, port), timeout=30)
            print(f"[fuzzer] Connected.  Starting {iterations} iterations.")
            break
        except (ConnectionRefusedError, TimeoutError) as exc:
            print(f"[fuzzer] Connection failed ({exc}); retrying in 5 s …")
            time.sleep(5)

    sock.settimeout(60)  # generous timeout per round-trip

    iteration = 0
    try:
        while iterations == 0 or iteration < iterations:
            # ── Receive READY frame ──
            try:
                ready_frame = recv_frame(sock)
            except ConnectionError as exc:
                print(f"[fuzzer] Disconnected: {exc}")
                break

            if not ready_frame.startswith(b"READY"):
                print(f"[fuzzer] Unexpected frame: {ready_frame!r}")
                continue

            state_tag = ready_frame.decode("ascii", errors="replace").split(" ", 1)[1]

            # ── Receive original bytes frame ──
            try:
                original = recv_frame(sock)
            except ConnectionError as exc:
                print(f"[fuzzer] Disconnected reading original: {exc}")
                break

            # ── Generate mutation ──
            strategy_name = engine.strategy_name
            mutated = engine.next_mutation(original)

            # ── Send mutated bytes back ──
            try:
                send_frame(sock, mutated)
            except (BrokenPipeError, ConnectionError) as exc:
                print(f"[fuzzer] Send failed: {exc}")
                break

            # ── Log result ──
            record = {
                "iteration":  iteration,
                "timestamp":  datetime.now(timezone.utc).isoformat(),
                "state_tag":  state_tag,
                "strategy":   strategy_name,
                "original":   original.hex(),
                "mutated":    mutated.hex(),
                "changed":    original != mutated,
            }
            log_file.write(json.dumps(record) + "\n")
            log_file.flush()

            print(
                f"[fuzzer] iter={iteration:5d}  tag={state_tag:<12s}"
                f"  strategy={strategy_name:<22s}"
                f"  orig={len(original):3d}B → mut={len(mutated):3d}B"
            )

            iteration += 1

    finally:
        sock.close()
        log_file.close()
        print(f"[fuzzer] Done. {iteration} iterations logged to {log_path}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="2G/GSM baseband fuzzer — Windows-side Boofuzz controller"
    )
    parser.add_argument("--host", required=True,
                        help="IP address of the Fedora RAN/Core node")
    parser.add_argument("--port", type=int, default=27017,
                        help="TCP port of the osmo-msc fuzzer hook (default: 27017)")
    parser.add_argument("--iterations", type=int, default=0,
                        help="Number of mutations to send (0 = unlimited)")
    parser.add_argument("--log", default="fuzzer_results.jsonl",
                        help="Output log file path (JSON Lines)")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducibility")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    run_fuzzer(args.host, args.port, args.iterations, args.log)


if __name__ == "__main__":
    main()
