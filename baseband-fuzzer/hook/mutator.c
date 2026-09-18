/*
 * mutator.c — In-process L3 MM message mutator for baseband fuzzing.
 *
 * CRITICAL DESIGN RULE:
 *   Bytes l3[0] (protocol discriminator) and l3[1] (message type) are
 *   NEVER mutated.  All mutations operate on the PAYLOAD starting at
 *   l3[2] (the Information Elements).
 *
 *   Rationale: if the PD or message type is corrupted, the baseband's
 *   L3 demux drops the message before it reaches the MM parser — the
 *   actual target.  We want valid-type-but-corrupted-content to stress
 *   the IE/TLV parser inside the baseband.
 *
 * Mutation strategies (all operate on payload bytes only):
 *   0  BIT_FLIP     — flip 1-3 random bits in payload
 *   1  BYTE_REPLACE — replace 1 payload byte with 0x00/0x7F/0x80/0xFF/random
 *   2  BOUNDARY     — overwrite a payload byte with boundary value
 *   3  TRUNCATE     — shorten message (removes trailing IEs)
 *   4  EXTEND       — append 1-16 random bytes after last IE
 *   5  TLV_CORRUPT  — corrupt a TLV IE's tag, length, or value
 *
 * Every mutation is logged for reproducibility:
 *   [timestamp] seed=X strategy=N msg_type=0xYY orig_len=A new_len=B hex=...
 */

#include "mutator.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

/* ─── L3 header: PD(1) + MsgType(1) — NEVER MUTATED ─────────────────────── */
#define L3_HDR_LEN  2

/* ─── PRNG (xorshift64) ──────────────────────────────────────────────────── */

static uint64_t g_prng_state;
static uint64_t g_initial_seed;

static uint64_t xorshift64(void)
{
	uint64_t x = g_prng_state;
	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	g_prng_state = x;
	return x;
}

/* Random integer in [0, max) */
static uint32_t rand_range(uint32_t max)
{
	if (max == 0)
		return 0;
	return (uint32_t)(xorshift64() % max);
}

/* ─── Configuration ──────────────────────────────────────────────────────── */

static int   g_fuzz_rate = 100;   /* % of messages to mutate  */
static FILE *g_logfp     = NULL;
static int   g_initialized = 0;

/* Interesting boundary values for byte replacement */
static const uint8_t BOUNDARY_VALS[] = {
	0x00, 0x01, 0x7E, 0x7F, 0x80, 0x81, 0xFE, 0xFF
};
#define N_BOUNDARY (sizeof(BOUNDARY_VALS) / sizeof(BOUNDARY_VALS[0]))

/* ─── Hex dump helper ────────────────────────────────────────────────────── */

static void hex_dump(FILE *fp, const uint8_t *data, uint16_t len)
{
	for (uint16_t i = 0; i < len && i < 64; i++)
		fprintf(fp, "%02x", data[i]);
	if (len > 64)
		fprintf(fp, "...[%u total]", len);
}

/* ─── Mutation strategies ────────────────────────────────────────────────── */
/*
 * ALL strategies receive a pointer to the PAYLOAD (l3 + L3_HDR_LEN)
 * and the PAYLOAD length (total_len - L3_HDR_LEN).  They never see
 * or touch the PD or message type bytes.
 */

/* Strategy 0: Flip 1-3 random bits in payload */
static void mut_bit_flip(uint8_t *payload, uint16_t plen)
{
	if (plen == 0) return;
	int n_flips = 1 + rand_range(3);
	for (int i = 0; i < n_flips; i++) {
		uint16_t pos = rand_range(plen);
		uint8_t  bit = 1 << rand_range(8);
		payload[pos] ^= bit;
	}
}

/* Strategy 1: Replace a random payload byte with an interesting value */
static void mut_byte_replace(uint8_t *payload, uint16_t plen)
{
	if (plen == 0) return;
	uint16_t pos = rand_range(plen);
	uint32_t choice = rand_range(5);
	switch (choice) {
	case 0: payload[pos] = 0x00; break;
	case 1: payload[pos] = 0x7F; break;
	case 2: payload[pos] = 0x80; break;
	case 3: payload[pos] = 0xFF; break;
	default: payload[pos] = (uint8_t)rand_range(256); break;
	}
}

/* Strategy 2: Overwrite a payload byte with boundary value */
static void mut_boundary(uint8_t *payload, uint16_t plen)
{
	if (plen == 0) return;
	uint16_t pos = rand_range(plen);
	payload[pos] = BOUNDARY_VALS[rand_range(N_BOUNDARY)];
}

/* Strategy 3: Truncate — shorten message (remove trailing IEs).
 * Minimum result: header only (0 payload bytes). */
static void mut_truncate(uint8_t *payload, uint16_t *plen)
{
	(void)payload;
	if (*plen == 0) return;
	/* Remove 1 to plen bytes from the end */
	uint16_t cut = 1 + rand_range(*plen);
	*plen -= cut;
}

/* Strategy 4: Extend — append 1-16 random bytes after payload */
static void mut_extend(uint8_t *payload, uint16_t *plen, uint16_t max_plen)
{
	uint16_t room = max_plen - *plen;
	if (room == 0) return;
	uint16_t add = 1 + rand_range(room < 16 ? room : 16);
	for (uint16_t i = 0; i < add; i++)
		payload[*plen + i] = (uint8_t)rand_range(256);
	*plen += add;
}

/* Strategy 5: TLV corruption — find a TLV IE in payload and corrupt it.
 * GSM L3 TLV format: after the 2-byte L3 header, IEs are T, TV, TLV, or LV.
 * We look for TLV-like structures (tag, length, value...). */
static void mut_tlv_corrupt(uint8_t *payload, uint16_t plen)
{
	if (plen < 2) {
		/* Too short for TLV; just flip a bit if we have anything */
		if (plen > 0)
			payload[0] ^= (uint8_t)(1 << rand_range(8));
		return;
	}

	/* Walk forward to a random TLV-like position */
	uint16_t pos = 0;
	int skip = rand_range(4);
	while (skip > 0 && pos + 2 < plen) {
		uint8_t ie_len = payload[pos + 1];
		uint16_t next = pos + 2 + ie_len;
		if (next > plen) break;
		pos = next;
		skip--;
	}

	if (pos + 1 >= plen)
		pos = 0;  /* fallback to first IE */

	uint32_t what = rand_range(3);
	switch (what) {
	case 0: /* Corrupt tag */
		payload[pos] = (uint8_t)rand_range(256);
		break;
	case 1: /* Corrupt length — use boundary values */
		if (pos + 1 < plen)
			payload[pos + 1] = BOUNDARY_VALS[rand_range(N_BOUNDARY)];
		break;
	case 2: /* Corrupt value — flip bits in first value byte */
		if (pos + 2 < plen)
			payload[pos + 2] ^= (uint8_t)(1 << rand_range(8));
		break;
	}
}

/* ─── Public API ─────────────────────────────────────────────────────────── */

int mutator_init(void)
{
	const char *env;

	/* Seed */
	env = getenv("FUZZ_SEED");
	if (env && *env) {
		g_prng_state = (uint64_t)strtoull(env, NULL, 0);
	} else {
		/* Random seed from /dev/urandom */
		int fd = open("/dev/urandom", O_RDONLY);
		if (fd >= 0) {
			read(fd, &g_prng_state, sizeof(g_prng_state));
			close(fd);
		} else {
			g_prng_state = (uint64_t)time(NULL) ^ 0xDEADBEEFCAFE1234ULL;
		}
	}
	if (g_prng_state == 0)
		g_prng_state = 1;
	g_initial_seed = g_prng_state;

	/* Mutation rate */
	env = getenv("FUZZ_RATE");
	if (env && *env) {
		g_fuzz_rate = atoi(env);
		if (g_fuzz_rate < 0)   g_fuzz_rate = 0;
		if (g_fuzz_rate > 100) g_fuzz_rate = 100;
	}

	/* Log file */
	env = getenv("FUZZ_LOG");
	const char *logpath = env && *env ? env : "/var/log/osmocom/fuzzer.log";
	g_logfp = fopen(logpath, "a");
	if (!g_logfp) {
		fprintf(stderr, "mutator: cannot open log %s\n", logpath);
		g_logfp = stderr;
	}

	/* Banner */
	time_t now = time(NULL);
	fprintf(g_logfp,
		"\n=== FUZZER STARTED === %s"
		"  seed=%lu  rate=%d%%  log=%s\n"
		"  header protection: l3[0..1] (PD+MsgType) NEVER mutated\n\n",
		ctime(&now),
		(unsigned long)g_initial_seed, g_fuzz_rate, logpath);
	fflush(g_logfp);

	g_initialized = 1;
	fprintf(stderr,
		"mutator: initialized (seed=%lu, rate=%d%%, hdr_protect=2)\n",
		(unsigned long)g_initial_seed, g_fuzz_rate);

	return 0;
}

/*
 * mutator_fuzz — Possibly mutate an L3 message in-place.
 *
 * buf:      pointer to the FULL L3 message (including PD + msg_type)
 * len:      pointer to total L3 length (may be modified for truncate/extend)
 * maxlen:   maximum buffer capacity
 * msg_type: the MM message type byte (for logging only)
 *
 * INVARIANT: buf[0] and buf[1] are NEVER modified.
 *            All mutations operate on buf[2..len-1] (the payload/IEs).
 *
 * Returns 1 if the message was mutated, 0 if passed through.
 */
int mutator_fuzz(uint8_t *buf, uint16_t *len, uint16_t maxlen, uint8_t msg_type)
{
	if (!g_initialized)
		mutator_init();

	/* Rate limiting */
	if (g_fuzz_rate < 100) {
		if ((int)rand_range(100) >= g_fuzz_rate)
			return 0;  /* pass through */
	}

	/* Need at least header + 1 payload byte to mutate.
	 * Messages with only PD+Type (2 bytes) can only be extended. */
	if (!buf || *len < L3_HDR_LEN)
		return 0;

	/* Save original for logging */
	uint8_t  orig[256];
	uint16_t orig_len = *len < sizeof(orig) ? *len : sizeof(orig);
	memcpy(orig, buf, orig_len);

	/* Payload starts after the 2-byte L3 header */
	uint8_t  *payload = buf + L3_HDR_LEN;
	uint16_t  plen = *len - L3_HDR_LEN;
	uint16_t  max_plen = maxlen - L3_HDR_LEN;

	/* Pick a random strategy */
	uint64_t pre_state = g_prng_state;
	enum mutator_strategy strat;

	if (plen == 0) {
		/* Header-only message (e.g. CM Service Accept = 2 bytes).
		 * Only Extension makes sense — can't flip/truncate nothing. */
		strat = MUT_EXTEND;
	} else {
		strat = rand_range(MUT_NUM_STRATEGIES);
	}

	switch (strat) {
	case MUT_BIT_FLIP:     mut_bit_flip(payload, plen);               break;
	case MUT_BYTE_REPLACE: mut_byte_replace(payload, plen);           break;
	case MUT_BOUNDARY:     mut_boundary(payload, plen);               break;
	case MUT_TRUNCATE:     mut_truncate(payload, &plen);              break;
	case MUT_EXTEND:       mut_extend(payload, &plen, max_plen);      break;
	case MUT_TLV_CORRUPT:  mut_tlv_corrupt(payload, plen);            break;
	default:               mut_bit_flip(payload, plen);               break;
	}

	/* Update total length (header is unchanged, payload may have changed) */
	*len = L3_HDR_LEN + plen;

	/* Log */
	if (g_logfp) {
		static const char *strat_names[] = {
			"BIT_FLIP", "BYTE_REPLACE", "BOUNDARY",
			"TRUNCATE", "EXTEND", "TLV_CORRUPT"
		};
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);

		fprintf(g_logfp,
			"[%ld.%03ld] seed=%lu strat=%s msg_type=0x%02x "
			"orig_len=%u new_len=%u hdr=%02x%02x orig=",
			(long)ts.tv_sec, ts.tv_nsec / 1000000,
			(unsigned long)pre_state,
			strat_names[strat], msg_type,
			orig_len, *len,
			buf[0], buf[1]);  /* PD+Type always preserved */
		hex_dump(g_logfp, orig, orig_len);
		fprintf(g_logfp, " fuzzed=");
		hex_dump(g_logfp, buf, *len);
		fprintf(g_logfp, "\n");
		fflush(g_logfp);
	}

	return 1;  /* mutated */
}

void mutator_shutdown(void)
{
	if (g_logfp && g_logfp != stderr) {
		fprintf(g_logfp, "\n=== FUZZER STOPPED ===\n");
		fclose(g_logfp);
		g_logfp = NULL;
	}
	g_initialized = 0;
}
