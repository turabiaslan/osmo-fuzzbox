/*
 * fuzzer_hook.c — L3/MM fuzzer hook compiled into osmo-msc libmsc
 *
 * This file is injected into the osmo-msc source tree by apply_hook.py
 * before the build.  It is NOT a standalone shared library; it is compiled
 * directly into libmsc.la and therefore has full access to internal symbols.
 *
 * ─── Wire protocol ───────────────────────────────────────────────────────────
 *
 *   Both directions: [u16 big-endian length][payload bytes]
 *
 *   Hook → Boofuzz (two consecutive frames per invocation):
 *     Frame 1: "READY <state_tag>"   e.g. "READY auth_req"  (ASCII, no NUL)
 *     Frame 2: original message bytes (the un-mutated L3 payload)
 *
 *   Boofuzz → Hook (one frame):
 *     Frame 1: mutated bytes to substitute into the msgb
 *
 * ─── Threading model ─────────────────────────────────────────────────────────
 *
 *   osmo-msc runs its core state machine in a single-threaded osmo_select
 *   main loop.  The blocking recv() in this hook therefore pauses the entire
 *   MSC event loop for the duration of each fuzzer round-trip.  This is
 *   intentional: it serialises mutations and avoids race conditions with
 *   retransmission timers.  A Ctrl-C or fuzzer disconnect restores normal
 *   operation (g_client_fd is reset and future calls pass through unchanged).
 *
 *   A mutex guards the TCP fd against unexpected re-entrance (e.g. if the
 *   build system ever enables threads in libmsc).
 *
 * Copyright (C) 2026  Open Source Guard Fuzzing Pipeline
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "fuzzer_hook.h"

#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ─── Configuration ──────────────────────────────────────────────────────── */

#define FUZZER_HOOK_PORT    27017
#define FUZZER_HOOK_BACKLOG 1
#define MAX_PAYLOAD_LEN     4096   /* hard cap on received mutated bytes */

/* ─── Module-local state ─────────────────────────────────────────────────── */

static int             g_srv_fd      = -1;
static int             g_client_fd   = -1;
static int             g_initialized = 0;
static pthread_mutex_t g_lock        = PTHREAD_MUTEX_INITIALIZER;

/* ─── Internal helpers ───────────────────────────────────────────────────── */

static int hook_init(void)
{
	struct sockaddr_in addr;
	int opt = 1;

	g_srv_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (g_srv_fd < 0) {
		LOGP(DLGLOBAL, LOGL_ERROR,
		     "fuzzer_hook: socket() failed: %s\n", strerror(errno));
		return -1;
	}

	setsockopt(g_srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port        = htons(FUZZER_HOOK_PORT);

	if (bind(g_srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		LOGP(DLGLOBAL, LOGL_ERROR,
		     "fuzzer_hook: bind() on port %d failed: %s\n",
		     FUZZER_HOOK_PORT, strerror(errno));
		close(g_srv_fd);
		g_srv_fd = -1;
		return -1;
	}

	if (listen(g_srv_fd, FUZZER_HOOK_BACKLOG) < 0) {
		LOGP(DLGLOBAL, LOGL_ERROR,
		     "fuzzer_hook: listen() failed: %s\n", strerror(errno));
		close(g_srv_fd);
		g_srv_fd = -1;
		return -1;
	}

	LOGP(DLGLOBAL, LOGL_NOTICE,
	     "fuzzer_hook: TCP server listening on 0.0.0.0:%d\n",
	     FUZZER_HOOK_PORT);
	g_initialized = 1;
	return 0;
}

/* Accept a client or return existing fd.  Blocks until Boofuzz connects. */
static int hook_ensure_client(void)
{
	if (g_client_fd >= 0)
		return g_client_fd;

	LOGP(DLGLOBAL, LOGL_NOTICE,
	     "fuzzer_hook: waiting for Boofuzz connection on port %d …\n",
	     FUZZER_HOOK_PORT);

	g_client_fd = accept(g_srv_fd, NULL, NULL);
	if (g_client_fd < 0) {
		LOGP(DLGLOBAL, LOGL_ERROR,
		     "fuzzer_hook: accept() failed: %s\n", strerror(errno));
		g_client_fd = -1;
		return -1;
	}

	LOGP(DLGLOBAL, LOGL_NOTICE, "fuzzer_hook: Boofuzz connected\n");
	return g_client_fd;
}

static void hook_disconnect(void)
{
	if (g_client_fd >= 0) {
		close(g_client_fd);
		g_client_fd = -1;
	}
	LOGP(DLGLOBAL, LOGL_NOTICE,
	     "fuzzer_hook: Boofuzz disconnected; hook will wait for reconnect\n");
}

/*
 * Send one length-prefixed frame.
 * Returns 0 on success, -1 on error.
 */
static int send_frame(int fd, const uint8_t *data, uint16_t len)
{
	uint16_t nlen = htons(len);

	if (send(fd, &nlen, sizeof(nlen), MSG_NOSIGNAL) != sizeof(nlen))
		return -1;
	if (len == 0)
		return 0;
	if (send(fd, data, len, MSG_NOSIGNAL) != (ssize_t)len)
		return -1;
	return 0;
}

/*
 * Receive one length-prefixed frame into buf (max MAX_PAYLOAD_LEN bytes).
 * Returns 0 on success, -1 on error or oversized frame.
 */
static int recv_frame(int fd, uint8_t *buf, uint16_t *out_len)
{
	uint16_t nlen;
	ssize_t  r;

	r = recv(fd, &nlen, sizeof(nlen), MSG_WAITALL);
	if (r != sizeof(nlen))
		return -1;

	*out_len = ntohs(nlen);
	if (*out_len == 0) {
		return 0;          /* zero-length frame is valid (pass-through) */
	}
	if (*out_len > MAX_PAYLOAD_LEN) {
		LOGP(DLGLOBAL, LOGL_ERROR,
		     "fuzzer_hook: received oversized frame (%u bytes > %d)\n",
		     *out_len, MAX_PAYLOAD_LEN);
		return -1;
	}

	r = recv(fd, buf, *out_len, MSG_WAITALL);
	if (r != (ssize_t)*out_len)
		return -1;

	return 0;
}

/* ─── Public API ─────────────────────────────────────────────────────────── */

int fuzzer_hook_mm_tx(struct msgb *msg, const char *state_tag)
{
	uint8_t  mutated[MAX_PAYLOAD_LEN];
	uint16_t mut_len = 0;
	int      fd;
	int      rc = 0;   /* 0 = no mutation (pass-through), caller still sends */
	char     ready_str[64];

	if (!msg || !state_tag)
		return 0;

	pthread_mutex_lock(&g_lock);

	/* Lazy initialisation of the TCP server socket */
	if (!g_initialized) {
		if (hook_init() < 0)
			goto out;
	}

	/* If no client is connected, pass the message through unchanged */
	fd = hook_ensure_client();
	if (fd < 0)
		goto out;

	/* ── Frame 1 up: "READY <state_tag>" ── */
	snprintf(ready_str, sizeof(ready_str), "READY %s", state_tag);
	if (send_frame(fd, (uint8_t *)ready_str, (uint16_t)strlen(ready_str)) < 0) {
		hook_disconnect();
		goto out;
	}

	/* ── Frame 2 up: original message bytes as context ── */
	if (msg->len > 0 &&
	    send_frame(fd, msg->data, (uint16_t)msg->len) < 0) {
		hook_disconnect();
		goto out;
	}

	/* ── Frame 1 down: mutated bytes from Boofuzz ── */
	if (recv_frame(fd, mutated, &mut_len) < 0) {
		hook_disconnect();
		goto out;
	}

	/* ── Overwrite msgb payload (bounds-checked) ── */
	if (mut_len > 0) {
		/*
		 * Strategy: overwrite the existing bytes in-place up to the
		 * original length, then adjust msg->len and msg->tail to
		 * reflect the (possibly shorter or longer) mutated payload.
		 *
		 * We only expand if the buffer has headroom; otherwise we
		 * silently truncate to the available space.  The BTS/TRX
		 * layer will reject frames that are too short for the L3
		 * header anyway, which is itself a useful fuzzing outcome.
		 */
		uint16_t avail = (uint16_t)(msgb_tailroom(msg) + msg->len);
		uint16_t use   = (mut_len <= avail) ? mut_len : avail;

		memcpy(msg->data, mutated, use);
		msg->len  = use;
		msg->tail = msg->data + use;

		LOGP(DLGLOBAL, LOGL_NOTICE,
		     "fuzzer_hook: [%s] mutated %u → %u bytes (avail=%u)\n",
		     state_tag, (unsigned)msg->len, use, avail);
	} else {
		/* Zero-length response = pass-through (no mutation this round) */
		LOGP(DLGLOBAL, LOGL_DEBUG,
		     "fuzzer_hook: [%s] pass-through (zero-length response)\n",
		     state_tag);
	}

out:
	pthread_mutex_unlock(&g_lock);
	return rc;
}
