/*
 * mutator.h — In-process L3 MM message mutator for baseband fuzzing.
 *
 * No external dependencies. Uses xorshift64 PRNG.
 * Logs every mutation to FUZZ_LOG for reproducibility.
 *
 * Environment variables:
 *   FUZZ_RATE   — % of messages to mutate (0-100, default 100)
 *   FUZZ_SEED   — fixed PRNG seed for replay (default: random from /dev/urandom)
 *   FUZZ_LOG    — log file path (default: /var/log/osmocom/fuzzer.log)
 */

#ifndef MUTATOR_H
#define MUTATOR_H

#include <stdint.h>
#include <stddef.h>

/* Mutation strategies */
enum mutator_strategy {
	MUT_BIT_FLIP,       /* flip 1-3 random bits                    */
	MUT_BYTE_REPLACE,   /* replace random byte with interesting val */
	MUT_BOUNDARY,       /* overwrite with boundary value            */
	MUT_TRUNCATE,       /* shorten message                         */
	MUT_EXTEND,         /* append garbage bytes                    */
	MUT_TLV_CORRUPT,    /* corrupt TLV tag, length, or value       */
	MUT_NUM_STRATEGIES
};

/* Initialise the mutator (call once at startup).
 * Reads FUZZ_RATE, FUZZ_SEED, FUZZ_LOG from environment.
 * Returns 0 on success, -1 on error. */
int mutator_init(void);

/* Possibly mutate an L3 message in-place.
 * buf:     pointer to L3 payload (may be modified)
 * len:     pointer to payload length (may be modified for truncate/extend)
 * maxlen:  maximum buffer capacity
 * msg_type: the MM message type byte (for logging)
 *
 * Returns 1 if the message was mutated, 0 if passed through. */
int mutator_fuzz(uint8_t *buf, uint16_t *len, uint16_t maxlen, uint8_t msg_type);

/* Shut down the mutator (flush log). */
void mutator_shutdown(void);

#endif /* MUTATOR_H */
