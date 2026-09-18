/*
 * fuzz_preview.c — Standalone test harness for the mutator.
 *
 * Generates sample GSM 04.08 MM messages, runs them through the mutator,
 * and prints original vs fuzzed payloads side by side.
 *
 * No Osmocom dependencies — compiles standalone:
 *   gcc -o fuzz_preview fuzz_preview.c mutator.c -I. -lrt
 *
 * Usage:
 *   ./fuzz_preview                   # random seed, 20 rounds
 *   ./fuzz_preview 50                # 50 rounds
 *   FUZZ_SEED=12345 ./fuzz_preview   # deterministic
 *   FUZZ_RATE=50 ./fuzz_preview      # 50% mutation rate
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "mutator.h"

/* ─── Sample MM messages (3GPP TS 04.08) ─────────────────────────────────── */

struct sample_msg {
	const char *name;
	uint8_t     data[64];
	uint16_t    len;
};

/* PD=0x05 (MM), msg_type in byte[1] */
static struct sample_msg SAMPLES[] = {
	{
		"Authentication Request",
		/* PD=05, MT=12, Cipher key seq, RAND(16 bytes) */
		{0x05, 0x12, 0x00,
		 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
		 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00},
		19
	},
	{
		"Identity Request",
		/* PD=05, MT=18, Identity type=IMSI(1) */
		{0x05, 0x18, 0x01},
		3
	},
	{
		"Location Updating Accept",
		/* PD=05, MT=08, LAI(5 bytes), mobile identity TLV */
		{0x05, 0x08,
		 0x00, 0xF1, 0x10,  /* MCC=001, MNC=01 */
		 0x00, 0x01,        /* LAC=1 */
		 0x17, 0x05,        /* Mobile Identity TLV: tag=0x17, len=5 */
		 0xF4, 0x12, 0x34, 0x56, 0x78},  /* TMSI */
		14
	},
	{
		"Location Updating Reject",
		/* PD=05, MT=04, Reject cause */
		{0x05, 0x04, 0x02},  /* cause=IMSI unknown */
		3
	},
	{
		"CM Service Accept",
		/* PD=05, MT=21 */
		{0x05, 0x21},
		2
	},
	{
		"CM Service Reject",
		/* PD=05, MT=22, Reject cause */
		{0x05, 0x22, 0x05},  /* cause=IMSI unknown in VLR */
		3
	},
	{
		"TMSI Reallocation Command",
		/* PD=05, MT=1A, LAI(5), Mobile Identity TLV */
		{0x05, 0x1A,
		 0x00, 0xF1, 0x10,  /* MCC/MNC */
		 0x00, 0x01,        /* LAC */
		 0x17, 0x05,        /* MI TLV */
		 0xF4, 0xAB, 0xCD, 0xEF, 0x01},
		14
	},
	{
		"MM Information",
		/* PD=05, MT=32, Full network name TLV, Short name TLV, TZ */
		{0x05, 0x32,
		 0x43, 0x08,  /* Full name: tag=0x43, len=8 */
		 0x80, 0xD3, 0xB2, 0x9B, 0x4C, 0x07, 0xD1, 0xCB,  /* "OSG-Lab" GSM7 */
		 0x45, 0x04,  /* Short name: tag=0x45, len=4 */
		 0x80, 0xD3, 0xB2, 0x1B,
		 0x46, 0x01, 0x08},  /* TZ: tag=0x46, len=1, UTC+2 */
		21
	},
	{
		"MM Status",
		/* PD=05, MT=31, Reject cause */
		{0x05, 0x31, 0x1F},  /* cause=Semantically incorrect message */
		3
	},
	{
		"Authentication Reject",
		/* PD=05, MT=11 */
		{0x05, 0x11},
		2
	},
};

#define N_SAMPLES (sizeof(SAMPLES) / sizeof(SAMPLES[0]))

/* ─── Hex print helper ───────────────────────────────────────────────────── */

static void print_hex(const uint8_t *data, uint16_t len)
{
	for (uint16_t i = 0; i < len; i++) {
		printf("%02x", data[i]);
		if (i < len - 1) printf(" ");
	}
}

static void print_diff(const uint8_t *orig, uint16_t orig_len,
                       const uint8_t *fuzzed, uint16_t fuzz_len)
{
	uint16_t max = orig_len > fuzz_len ? orig_len : fuzz_len;
	for (uint16_t i = 0; i < max; i++) {
		if (i < orig_len && i < fuzz_len) {
			if (orig[i] != fuzzed[i])
				printf("\033[1;31m%02x\033[0m", fuzzed[i]);  /* red = changed */
			else
				printf("%02x", fuzzed[i]);
		} else if (i >= orig_len) {
			printf("\033[1;33m%02x\033[0m", fuzzed[i]);  /* yellow = added */
		}
		if (i < max - 1) printf(" ");
	}
	if (fuzz_len < orig_len)
		printf(" \033[1;35m[truncated -%d]\033[0m", orig_len - fuzz_len);
}

/* ─── Strategy name ──────────────────────────────────────────────────────── */

static const char *strat_names[] = {
	"BIT_FLIP", "BYTE_REPLACE", "BOUNDARY",
	"TRUNCATE", "EXTEND", "TLV_CORRUPT"
};

/* ─── Main ───────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
	int rounds = 20;
	if (argc > 1)
		rounds = atoi(argv[1]);

	printf("╔══════════════════════════════════════════════════════════════╗\n");
	printf("║  Fuzz Preview — Inspect mutated MM payloads offline        ║\n");
	printf("╚══════════════════════════════════════════════════════════════╝\n\n");

	/* Init mutator (reads FUZZ_SEED, FUZZ_RATE, FUZZ_LOG from env) */
	if (!getenv("FUZZ_LOG")) {
		/* Default to stdout logging for preview */
		setenv("FUZZ_LOG", "/dev/null", 0);
	}
	mutator_init();

	int total_mutated = 0;
	int total_passed = 0;

	printf("Generating %d rounds × %d message types = %d total\n\n",
	       rounds, (int)N_SAMPLES, rounds * (int)N_SAMPLES);

	for (int round = 0; round < rounds; round++) {
		printf("━━━ Round %d ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n",
		       round + 1);

		for (int s = 0; s < (int)N_SAMPLES; s++) {
			/* Copy the sample so original is preserved */
			uint8_t buf[128];
			uint16_t len = SAMPLES[s].len;
			memcpy(buf, SAMPLES[s].data, len);

			uint8_t orig_pd = buf[0];
			uint8_t orig_mt = buf[1];
			uint8_t msg_type = orig_mt & 0x3F;

			int fuzzed = mutator_fuzz(buf, &len, sizeof(buf), msg_type);

			if (fuzzed) {
				/* CRITICAL CHECK: header bytes must NEVER change */
				if (buf[0] != orig_pd || buf[1] != orig_mt) {
					printf("\n  \033[1;31m!!! HEADER CORRUPTED !!!\033[0m\n");
					printf("    %s: PD %02x→%02x  MT %02x→%02x\n",
					       SAMPLES[s].name, orig_pd, buf[0],
					       orig_mt, buf[1]);
					printf("    THIS IS A BUG — mutator touched protected bytes\n\n");
					return 1;
				}

				total_mutated++;
				printf("  %-28s  [PD=%02x MT=%02x]  FUZZED\n",
				       SAMPLES[s].name, buf[0], buf[1] & 0x3F);
				printf("    orig:   ");
				print_hex(SAMPLES[s].data, SAMPLES[s].len);
				printf("\n");
				printf("    fuzzed: ");
				print_diff(SAMPLES[s].data, SAMPLES[s].len, buf, len);
				printf("\n");
				printf("    len: %u → %u  hdr: %02x %02x (preserved)\n\n",
				       SAMPLES[s].len, len, buf[0], buf[1]);
			} else {
				total_passed++;
			}
		}
	}

	printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
	printf("SUMMARY: %d mutated, %d passed through, %d total\n",
	       total_mutated, total_passed, total_mutated + total_passed);
	printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

	mutator_shutdown();
	return 0;
}
