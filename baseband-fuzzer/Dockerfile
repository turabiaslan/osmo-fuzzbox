# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Open Source Guard — 2G/GSM Baseband Fuzzing Pipeline                  ║
# ║  Base:  fedora:44                                                       ║
# ║  RF:    USRP B210  (full-duplex, FPGA image baked in at build time)     ║
# ║  Stack: Osmocom GSM  (osmo-trx / osmo-bts / osmo-bsc / osmo-msc /      ║
# ║                       osmo-hlr / osmo-mgw / osmo-stp)                   ║
# ║  Hook:  L3/MM TCP socket → Boofuzz on Windows control node (port 27017) ║
# ║                                                                         ║
# ║  Build-time defaults (override with --build-arg):                       ║
# ║    TEST_IMSI   001010000000001                                           ║
# ║    TEST_KI     00000000000000000000000000000000  (replace with real Ki)  ║
# ║    TEST_ALGO   comp128v1                                                 ║
# ║    ARFCN       71   (GSM900; select an unused ARFCN for your cage)      ║
# ╚══════════════════════════════════════════════════════════════════════════╝
FROM fedora:44

LABEL org.opencontainers.image.title="baseband-fuzzer"
LABEL org.opencontainers.image.description="2G/GSM baseband fuzzing pipeline — Osmocom + Boofuzz L3/MM hook"
LABEL org.opencontainers.image.version="1.0.0"

# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 — System packages
#
# IMPORTANT: uhd-firmware installs the USRP B210 FPGA bitfiles into
#   /usr/share/uhd/images/  AT BUILD TIME so the radio can initialise
#   with ZERO network access at runtime (air-gap requirement).
# ─────────────────────────────────────────────────────────────────────────────
RUN dnf -y update && dnf -y install \
        \
        gcc gcc-c++ make autoconf automake libtool \
        pkgconf-pkg-config git patch python3 \
        \
        libtalloc-devel \
        libusb1-devel \
        pcsc-lite-devel \
        gnutls-devel \
        libmnl-devel \
        lksctp-tools-devel \
        sqlite-devel \
        libdbi-devel \
        libdbi-dbd-sqlite \
        libpcap-devel \
        c-ares-devel \
        liburing-devel \
        perl \
        \
        uhd \
        uhd-devel \
        fftw-devel \
        boost-devel \
        uhd-firmware \
        \
        hackrf \
        \
        iproute \
        procps-ng \
        nc \
        sqlite \
    && dnf clean all

# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — Build environment
#
# autoconf default prefix → /usr/local
# Expose pkg-config search path and dynamic linker for /usr/local.
# ─────────────────────────────────────────────────────────────────────────────
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64
# Prevent git from hanging on credential prompts in container builds.
# If a repo URL is wrong/private, git fails immediately with a clear error.
ENV GIT_TERMINAL_PROMPT=0

RUN echo '/usr/local/lib'   >  /etc/ld.so.conf.d/local.conf && \
    echo '/usr/local/lib64' >> /etc/ld.so.conf.d/local.conf && \
    ldconfig

WORKDIR /build

# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 — Osmocom stack (strict bottom-up; ldconfig after each step)
#
# Each layer is independent so Docker/Podman build cache can be reused.
# ─────────────────────────────────────────────────────────────────────────────

# 1. libosmocore  ─ foundational; everything links it
# NOTE: no --depth flag — shallow clones suppress git tags, causing
# `git describe` to fail and pkg-config Version to become UNKNOWN,
# breaking every downstream configure that checks `libosmocore >= x.y`.
RUN git clone \
        https://github.com/osmocom/libosmocore.git && \
    cd libosmocore && \
    autoreconf -fi && \
    ./configure --disable-pcsc && \
    make -j"$(nproc)" && make install && ldconfig

# 2. libosmo-netif  ─ network primitives; libosmo-abis now depends on this
RUN git clone \
        https://github.com/osmocom/libosmo-netif.git && \
    cd libosmo-netif && \
    autoreconf -fi && \
    ./configure && \
    make -j"$(nproc)" && make install && ldconfig

# 3. libosmo-abis  ─ Abis-over-IP; needed by BTS + BSC
#    (depends on libosmo-netif — must come after step 2)
#    ortp and dahdi are optional hardware drivers not available/needed here.
#    PINNED to 2.1.0: HEAD removed ipaccess_fd_cb which osmo-bsc 1.11.0
#    still uses. 2.1.0 is the exact minimum osmo-bsc 1.11.0 declares.
RUN git clone --branch 2.1.0 \
        https://github.com/osmocom/libosmo-abis.git && \
    cd libosmo-abis && \
    autoreconf -fi && \
    HELP="$(./configure --help 2>&1)" && \
    EXTRA="" && \
    echo "$HELP" | grep -q -- '--disable-ortp'  && EXTRA="$EXTRA --disable-ortp"  || true && \
    echo "$HELP" | grep -q -- '--disable-dahdi' && EXTRA="$EXTRA --disable-dahdi" || true && \
    ./configure $EXTRA && \
    make -j"$(nproc)" && make install && ldconfig

# 3b. libosmo-trau stub ─ libosmo-trau (provides osmocom/trau/osmo_ortp.h) has
#     no GitHub mirror and gitea.osmocom.org requires auth for archive downloads.
#     Create a minimal stub header so the #include compiles.  osmo-bts will be
#     configured with --disable-ortp so no oRTP functions are ever called.
RUN mkdir -p /usr/local/include/osmocom/trau && \
    printf '%s\n' \
      '#pragma once' \
      '/* oRTP stub — compiled without oRTP support (no ortp-devel available) */' \
      '#include <stdint.h>' \
      'struct osmo_rtp_socket { int fd; };' \
      'typedef struct osmo_rtp_socket osmo_rtp_socket;' \
      'struct osmo_rtp_ops { void *rx_cb; };' \
      'static inline int  osmo_rtp_init(void *ctx)                  { return 0; }' \
      'static inline void osmo_rtp_set_ops(void *s, void *o)        { (void)s; (void)o; }' \
      'static inline int  osmo_rtp_socket_create(void *c, int pt, void *ops) { return -1; }' \
      > /usr/local/include/osmocom/trau/osmo_ortp.h

# 4. libosmo-sccp  ─ provides  osmo-stp daemon  +  libosmo-sigtran
#                    (A-interface SCCP/M3UA for BSC ↔ MSC)
#    Pinned to 1.8.0: HEAD changed osmo_sccp_simple_client_on_ss7_instance()
#    in a way that is incompatible with osmo-msc/osmo-bsc 1.11.0 at runtime
#    ("Setting up SCCP client failed" → fatal exit).  1.8.0 was the release
#    current when osmo-msc 1.11.0 shipped.
RUN git clone --branch 1.8.0 --depth 1 \
        https://github.com/osmocom/libosmo-sccp.git && \
    cd libosmo-sccp && \
    autoreconf -fi && \
    ./configure && \
    make -j"$(nproc)" && make install && ldconfig && \
    # 1.8.0 installs libosmo-sccp.pc; keep symlink logic for safety
    for pcdir in /usr/local/lib/pkgconfig /usr/local/lib64/pkgconfig; do \
        if [ -f "$pcdir/libosmo-sigtran.pc" ] && \
           [ ! -f "$pcdir/libosmo-sccp.pc" ]; then \
            ln -sf "$pcdir/libosmo-sigtran.pc" "$pcdir/libosmo-sccp.pc" && \
            echo "Created $pcdir/libosmo-sccp.pc -> libosmo-sigtran.pc"; \
        fi; \
    done

# 5. libsmpp34  ─ SMPP protocol; osmo-msc links it for SMS routing
#    GitHub mirror used: gitea.osmocom.org/osmocom/libsmpp34 requires auth
#    (private or not yet migrated to gitea public).
RUN git clone \
        https://github.com/osmocom/libsmpp34.git && \
    cd libsmpp34 && \
    autoreconf -fi && \
    ./configure && \
    make -j"$(nproc)" && make install && ldconfig

# 6. osmo-mgw  ─ provides libosmo-mgcp-client; needed by BSC + MSC
#
# --disable-ortp: present in older releases, absent in newer ones.
# The sub-shell queries ./configure --help so the flag is only passed
# when the build system actually accepts it.
RUN git clone \
        https://github.com/osmocom/osmo-mgw.git && \
    cd osmo-mgw && \
    autoreconf -fi && \
    ORTP_FLAG="$(./configure --help 2>&1 | \
                 grep -q -- '--disable-ortp' && \
                 echo '--disable-ortp' || true)" && \
    ./configure ${ORTP_FLAG} && \
    make -j"$(nproc)" && make install && ldconfig

# 7. osmo-hlr  ─ provides libosmo-gsupclient + HLR daemon (holds Ki)
RUN git clone \
        https://github.com/osmocom/osmo-hlr.git && \
    cd osmo-hlr && \
    autoreconf -fi && \
    ./configure && \
    make -j"$(nproc)" && make install && ldconfig

# 8. osmo-bsc  ─ PINNED to 1.11.0 (same release train as osmo-msc 1.11.0)
#    osmo-bsc HEAD now requires libosmo-sigtran >= 2.2.0, but libosmo-sccp
#    HEAD only provides 1.9.x.  Pinning to 1.11.0 keeps all daemon versions
#    on the same release train where libosmo-sigtran 1.9.x was sufficient.
#    The patch script must be copied BEFORE the RUN that calls it.
COPY patches/ /build/patches/
RUN git clone --branch 1.11.0 \
        https://github.com/osmocom/osmo-bsc.git && \
    cd osmo-bsc && \
    sed -i '/SUBDIRS/ s/ ipaccess//' src/Makefile.am && \
    python3 /build/patches/bsc_e1_patch.py && \
    autoreconf -fi && \
    ./configure && \
    make -j"$(nproc)" && make install && ldconfig

# 9. osmo-msc  ─ PINNED to 1.11.0 (hook offsets verified against this tag)
#               links: core, abis, netif, sigtran, mgcp-client, smpp34,
#                      gsupclient (from osmo-hlr)
RUN git clone --branch 1.11.0 \
        https://github.com/osmocom/osmo-msc.git && \
    cd osmo-msc && \
    autoreconf -fi

# ── Hook injection ─────────────────────────────────────────────────────
# Copy the three hook artefacts into the osmo-msc source tree BEFORE
# building, so they are compiled in as first-class source.
# apply_hook.py modifies gsm_04_08.c and src/libmsc/Makefile.am in-place.
COPY hook/fuzzer_hook.c       /build/osmo-msc/src/libmsc/fuzzer_hook.c
COPY hook/fuzzer_hook.h       /build/osmo-msc/src/libmsc/fuzzer_hook.h
COPY hook/apply_hook.py       /build/osmo-msc/apply_hook.py

# ── Diagnostic: dump auth/identity TX function signatures so apply_hook.py
#    patterns can be tuned if they miss.  Output is always visible in build log.
RUN echo "=== AUTH TX candidates in libmsc ===" && \
    grep -rn "auth.*req\|tx.*auth\|mm_tx_auth\|gsm48.*auth" \
        /build/osmo-msc/src/libmsc/ --include="*.c" \
        | grep -v "^\s*//" | grep -i "req\|send\|tx" | head -40 || true && \
    echo "=== IDENTITY TX candidates in libmsc ===" && \
    grep -rn "id.*req\|identity.*req\|tx.*id\|mm_tx_id" \
        /build/osmo-msc/src/libmsc/ --include="*.c" \
        | grep -v "^\s*//" | head -30 || true

RUN cd osmo-msc && \
    python3 apply_hook.py && \
    ./configure && \
    make -j"$(nproc)" && make install && ldconfig

# 10. osmo-trx  ─ TRX transceiver; links UHD to drive the B210
RUN git clone \
        https://github.com/osmocom/osmo-trx.git && \
    cd osmo-trx && \
    autoreconf -fi && \
    ./configure --with-uhd && \
    make -j"$(nproc)" && make install && ldconfig

# 11. osmo-bts  (osmo-bts-trx backend)
#     links: core, abis, netif
#     Built without oRTP: the osmo_ortp.h stub satisfies the include but any
#     oRTP call sites are compiled out via --disable-ortp (if supported).
RUN git clone \
        https://github.com/osmocom/osmo-bts.git && \
    cd osmo-bts && \
    autoreconf -fi && \
    HELP="$(./configure --help 2>&1)" && \
    EXTRA="--enable-trx" && \
    echo "$HELP" | grep -q -- '--disable-ortp' && EXTRA="$EXTRA --disable-ortp" || true && \
    ./configure $EXTRA && \
    make -j"$(nproc)" && make install && ldconfig

# ─────────────────────────────────────────────────────────────────────────────
# Phase 4 — Config files, runtime directories, helper scripts
# ─────────────────────────────────────────────────────────────────────────────
RUN mkdir -p /etc/osmocom /var/log/osmocom /var/lib/osmocom

COPY configs/osmo-stp.cfg /etc/osmocom/osmo-stp.cfg
COPY configs/osmo-hlr.cfg /etc/osmocom/osmo-hlr.cfg
COPY configs/osmo-mgw.cfg /etc/osmocom/osmo-mgw.cfg
COPY configs/osmo-msc.cfg /etc/osmocom/osmo-msc.cfg
COPY configs/osmo-bsc.cfg /etc/osmocom/osmo-bsc.cfg
COPY configs/osmo-bts.cfg /etc/osmocom/osmo-bts.cfg
COPY configs/osmo-trx.cfg /etc/osmocom/osmo-trx.cfg

COPY provision_hlr.sh /usr/local/bin/provision_hlr.sh
COPY entrypoint.sh    /usr/local/bin/entrypoint.sh

RUN chmod +x /usr/local/bin/provision_hlr.sh \
             /usr/local/bin/entrypoint.sh

# ─────────────────────────────────────────────────────────────────────────────
# Phase 5 — Sanity checks
# ─────────────────────────────────────────────────────────────────────────────

# Verify that the B210 FPGA bitfile is present (build fails if missing)
RUN ls /usr/share/uhd/images/usrp_b200_fw.hex

# Verify all daemons are on PATH (use shell built-in; 'which' not installed)
RUN for d in osmo-msc osmo-bsc osmo-bts-trx osmo-trx-uhd \
             osmo-hlr osmo-mgw osmo-stp; do \
        p="$(command -v "$d" 2>/dev/null)" && \
        echo "OK: $d -> $p" || \
        { echo "MISSING: $d"; exit 1; }; \
    done

# ─────────────────────────────────────────────────────────────────────────────
# Phase 6 — HLR provisioning (build-time; placeholder credentials)
#
# Override with --build-arg TEST_IMSI=... TEST_KI=... before export.
# The Ki MUST be 32 hex characters (16 bytes, no spaces/dashes).
# The HLR DB is created here so the container is self-contained at runtime.
# ─────────────────────────────────────────────────────────────────────────────
ARG TEST_IMSI=001010000000001
ARG TEST_KI=00000000000000000000000000000000
ARG TEST_ALGO=comp128v1

RUN /usr/local/bin/provision_hlr.sh "${TEST_IMSI}" "${TEST_KI}" "${TEST_ALGO}"

# ─────────────────────────────────────────────────────────────────────────────
# Runtime
# ─────────────────────────────────────────────────────────────────────────────

# Fuzzer hook TCP port (Boofuzz → hook)
EXPOSE 27017/tcp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
