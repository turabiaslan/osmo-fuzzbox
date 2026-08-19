/*
 * fuzzer_hook.h — L3/MM fuzzer hook for osmo-msc
 *
 * Compiled into libmsc by apply_hook.py (source injection at build time).
 * Exported symbols are intentionally minimal.
 *
 * Copyright (C) 2026  Open Source Guard Fuzzing Pipeline
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <osmocom/core/msgb.h>

/*
 * fuzzer_hook_mm_tx() — main hook entry point.
 *
 * Called by the patched TX functions in gsm_04_08.c immediately before
 * the msgb is handed to gscon_submit_rsl_dtap() (or equivalent) for
 * downlink transmission.
 *
 * @msg:       The outgoing message buffer (already L3-encoded).
 *             The hook may overwrite msg->data[0..msg->len-1] in-place
 *             with the fuzzer's mutated bytes.
 * @state_tag: Short ASCII label identifying the MM state transition.
 *             Currently used values: "auth_req"  "id_req"
 *
 * Return:  0  — mutation applied (or fuzzer not connected; msg unchanged).
 *         -1  — fatal error on the hook socket; caller continues unchanged.
 *
 * Wire protocol (both directions):
 *   [u16 big-endian length][payload bytes]
 *
 * Hook → fuzzer (two back-to-back frames):
 *   Frame 1:  "READY <state_tag>"           (ASCII, no NUL)
 *   Frame 2:  original message bytes        (binary)
 *
 * Fuzzer → hook (one frame):
 *   Frame 1:  mutated bytes to overwrite    (binary, same or different len)
 */
int fuzzer_hook_mm_tx(struct msgb *msg, const char *state_tag);
