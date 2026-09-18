/*
 * fuzzer_hook.c — In-process baseband fuzzer hook for osmo-msc.
 *
 * Intercepts outgoing GSM 04.08 Mobility Management messages and mutates
 * them in-place using the mutator engine.  The mutated messages are then
 * transmitted over the air interface to the target phone's baseband.
 *
 * CRITICAL DESIGN NOTES:
 *
 *  1. Hook placement:  apply_hook.py injects the call to fuzzer_hook_mm_tx()
 *     immediately BEFORE the final msc_a_tx_dtap_to_i() (or equivalent submit
 *     function).  At that point the msgb is fully encoded — all IEs, lengths,
 *     and TLVs are finalized.  The RSL/L2 wrapping happens AFTER the submit
 *     call, so it will read the (now mutated) msgb length correctly.
 *
 *  2. msgb length sync:  Truncation/Extension strategies change L3 payload
 *     length.  We adjust the msgb via msgb_put()/msgb_trim() so the RSL
 *     layer sees the correct total length.
 *
 *  3. Phased fuzzing:  The first FUZZ_SKIP messages pass through unfuzzed
 *     to let the phone complete registration (LU Accept must arrive clean
 *     at least once).  After that, all MM messages are fuzz-eligible.
 *
 *  4. Protocol filtering:  Only MM messages (PD=0x05) are fuzzed.
 *     Message type is extracted with (l3[1] & 0x3F) to mask sequence bits.
 *
 * Environment variables (set in Makefile/entrypoint):
 *   FUZZ_RATE  — % of messages to mutate (0-100, default 100)
 *   FUZZ_SEED  — PRNG seed for deterministic replay (default: random)
 *   FUZZ_SKIP  — # of initial messages to pass through clean (default: 10)
 *   FUZZ_LOG   — mutation log path (default: /var/log/osmocom/fuzzer.log)
 *
 * Copyright (c) 2026 OpenSrcGuard Lab.  All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

#include "mutator.h"

/* ─── 3GPP TS 04.08 §10.2 — Protocol Discriminator ──────────────────────── */
#define GSM48_PDISC_MM  0x05

/* ─── Module state ───────────────────────────────────────────────────────── */

static int g_initialized = 0;
static unsigned long g_total_msgs = 0;
static unsigned long g_total_fuzzed = 0;
static unsigned long g_total_skipped = 0;
static int g_fuzz_skip = 10;   /* skip first N messages for registration */

/* GSM 04.08 MM message type names (for logging) */
static const char *mm_msg_name(uint8_t msg_type)
{
	switch (msg_type) {
	case 0x01: return "CM_SERV_ACCEPT";
	case 0x02: return "TMSI_REALLOC_CMD";
	case 0x04: return "LU_REJECT";
	case 0x08: return "LU_ACCEPT";
	case 0x11: return "AUTH_REJECT";
	case 0x12: return "AUTH_REQUEST";
	case 0x14: return "AUTH_RESPONSE";
	case 0x18: return "IDENTITY_REQUEST";
	case 0x19: return "IDENTITY_RESPONSE";
	case 0x21: return "CM_SERV_REJECT";
	case 0x29: return "MM_INFORMATION";
	case 0x30: return "ABORT";
	case 0x31: return "MM_STATUS";
	default:   return "UNKNOWN";
	}
}

/* ─── Constructor: initialise mutator when osmo-msc loads ────────────────── */

static void __attribute__((constructor)) fuzzer_hook_autostart(void)
{
	const char *env;

	fprintf(stderr,
		"fuzzer_hook: in-process baseband fuzzer loading...\n");

	/* FUZZ_SKIP: how many initial messages to pass through clean */
	env = getenv("FUZZ_SKIP");
	if (env && *env)
		g_fuzz_skip = atoi(env);

	if (mutator_init() < 0) {
		fprintf(stderr,
			"fuzzer_hook: WARNING: mutator_init() failed; "
			"messages will pass through unfuzzed\n");
		return;
	}

	g_initialized = 1;
	fprintf(stderr,
		"fuzzer_hook: ready — skip=%d then mutating MM messages in-place\n",
		g_fuzz_skip);
}

/* ─── Destructor: clean shutdown ─────────────────────────────────────────── */

static void __attribute__((destructor)) fuzzer_hook_shutdown(void)
{
	fprintf(stderr,
		"fuzzer_hook: shutting down (total=%lu, fuzzed=%lu, skipped=%lu)\n",
		g_total_msgs, g_total_fuzzed, g_total_skipped);
	mutator_shutdown();
}

/* ─── Public hook: called from gsm_04_08.c on every outgoing MM message ── */

/*
 * fuzzer_hook_mm_tx — Intercept and possibly mutate an outgoing MM message.
 *
 * Called by the patched gsm_04_08.c immediately BEFORE the final submit
 * function (msc_a_tx_dtap_to_i or equivalent).  At this point:
 *   - The msgb L3 payload is fully encoded (all IEs, TLVs complete)
 *   - RSL/L2 wrapping has NOT happened yet (happens inside submit)
 *   - Mutating msgb_l3(msg) here will reach the baseband
 *
 * msg:       the message buffer (L3 payload starts at msgb_l3())
 * state_tag: descriptive string from the call site (for logging)
 *
 * Returns 0 always (message is sent regardless of mutation outcome).
 */
int fuzzer_hook_mm_tx(struct msgb *msg, const char *state_tag)
{
	uint8_t  *l3;
	uint16_t  l3_len;
	uint8_t   pd;
	uint8_t   msg_type;

	if (!g_initialized)
		return 0;  /* pass through if mutator failed to init */

	l3 = msgb_l3(msg);
	l3_len = msgb_l3len(msg);

	if (!l3 || l3_len < 2)
		return 0;  /* too short to be a valid L3 message */

	/* ── Issue #5: Proper L3 header decoding ──────────────────────────── */
	/* Byte 0: protocol discriminator (lower nibble) + skip/TI (upper)
	 * Byte 1: message type — lower 6 bits significant for MM,
	 *         upper 2 bits may contain send sequence number */
	pd = l3[0] & 0x0F;
	msg_type = l3[1] & 0x3F;

	/* Only fuzz Mobility Management messages (PD=5).
	 * CC (PD=3), SS (PD=11), SMS (PD=9) are left alone. */
	if (pd != GSM48_PDISC_MM)
		return 0;

	g_total_msgs++;

	/* ── Type whitelist — NEVER fuzz these, connection depends on them ── */
	/* 0x12 = Authentication Request: phone must complete auth to register
	 * 0x08 = Location Updating Accept: completes registration, assigns TMSI
	 * Without these, the phone never attaches and we have nothing to fuzz. */
	if (msg_type == 0x12 || msg_type == 0x08) {
		LOGP(DLGLOBAL, LOGL_INFO,
		     "fuzzer_hook: WHITELIST %s (0x%02x) — essential for registration\n",
		     mm_msg_name(msg_type), msg_type);
		return 0;
	}

	/* ── Phased fuzzing — let phone register first ───────────────────── */
	/* Skip the first N MM messages so the initial registration flow
	 * completes fully before any fuzzing begins. */
	if ((long)g_total_msgs <= g_fuzz_skip) {
		g_total_skipped++;
		LOGP(DLGLOBAL, LOGL_INFO,
		     "fuzzer_hook: PASS-THROUGH %s (0x%02x) [%lu/%d skip phase]\n",
		     mm_msg_name(msg_type), msg_type,
		     g_total_msgs, g_fuzz_skip);
		return 0;
	}

	/* ── Issue #2: Mutate in-place with msgb length sync ─────────────── */
	uint16_t new_len = l3_len;
	uint16_t maxlen = msg->data + msg->data_len - l3;  /* available buffer */

	int was_fuzzed = mutator_fuzz(l3, &new_len, maxlen, msg_type);

	if (was_fuzzed) {
		g_total_fuzzed++;

		/* Adjust msgb length if mutator changed it (truncate/extend).
		 * This is CRITICAL: the RSL layer reads msgb_length() to
		 * determine the L3 payload size.  Without this update,
		 * truncation/extension mutations would be silently dropped
		 * or padded by the lower layers. */
		if (new_len != l3_len) {
			int diff = (int)new_len - (int)l3_len;
			if (diff > 0)
				msgb_put(msg, diff);
			else
				msgb_trim(msg, msgb_length(msg) + diff);
		}

		LOGP(DLGLOBAL, LOGL_NOTICE,
		     "fuzzer_hook: FUZZED %s (0x%02x) %u→%u bytes [%lu/%lu]\n",
		     mm_msg_name(msg_type), msg_type,
		     l3_len, new_len,
		     g_total_fuzzed, g_total_msgs);
	}

	return 0;
}
