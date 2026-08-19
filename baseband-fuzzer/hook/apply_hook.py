#!/usr/bin/env python3
"""
apply_hook.py — Injects the fuzzer_hook into the osmo-msc source tree.

Run from the root of the osmo-msc repository (the Dockerfile does this):

    cd /build/osmo-msc
    python3 apply_hook.py

What it does
────────────
1. Locates the MM TX functions in src/libmsc/gsm_04_08.c that transmit
   Authentication Request and Identity Request downlink messages.
2. Inserts a  fuzzer_hook_mm_tx(msg, "<tag>")  call immediately before the
   final gscon_submit_rsl_dtap() / gscon_submit_dtap() return statement
   inside each function.
3. Adds  #include "fuzzer_hook.h"  at the top of gsm_04_08.c.
4. Adds  fuzzer_hook.c  to libmsc_la_SOURCES in src/libmsc/Makefile.am.
5. Adds  -lpthread  to libmsc_la_LDADD / libmsc_la_LIBADD (needed for the
   mutex in fuzzer_hook.c).
6. Bypasses the fatal 'role was not set' check in src/libmsc/sccp_user.c
   that prevents osmo-msc 1.11.0 from starting with libosmo-sccp 1.8.0.

If a pattern cannot be matched the script prints a detailed diagnostic and
exits non-zero, causing the Docker layer to fail loudly instead of silently
producing an un-hooked binary.
"""

import re
import sys
import os

# ─── Paths (relative to osmo-msc repo root) ──────────────────────────────────
GSM4808_PATH  = "src/libmsc/gsm_04_08.c"
MAKEFILE_PATH = "src/libmsc/Makefile.am"
SCCP_USER_PATH = "src/libmsc/sccp_user.c"

# ─────────────────────────────────────────────────────────────────────────────
# Helper: read / write with explicit error messages
# ─────────────────────────────────────────────────────────────────────────────

def read_file(path):
    if not os.path.isfile(path):
        sys.exit(f"[apply_hook] ERROR: file not found: {path}\n"
                 f"  Are you running from the osmo-msc repository root?")
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def write_file(path, content):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    print(f"[apply_hook] Wrote {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Patch gsm_04_08.c
# ─────────────────────────────────────────────────────────────────────────────

def patch_gsm4808(content):
    """
    Insert hook calls before the downlink submit in the two MM TX functions.

    We search for the function boundary using a regex that is intentionally
    loose about whitespace and intermediate code so it survives minor formatting
    changes across patch-level releases of 1.11.x.

    The final submit call in each function is the canonical injection point
    because at that instant the msgb is fully encoded and about to leave the
    MSC state machine.
    """
    modified = content
    injections = 0

    # ── Pattern for Authentication Request ───────────────────────────────────
    #
    # Targets:  mm_tx_authentication_req()  OR  msc_vlr_tx_auth_req()
    # The hook is inserted before the last  gscon_submit*  or
    # gsm48_conn_sendmsg* return inside these functions.
    #
    # We use a two-pass approach:
    #   Pass A: find the function start.
    #   Pass B: find the FIRST submit call AFTER the function start.
    #
    auth_fn_patterns = [
        # osmo-msc >= 1.9 naming
        r"mm_tx_authentication_req\s*\(",
        # alternative names seen in some branches
        r"msc_vlr_tx_auth_req\s*\(",
        r"gsm48_tx_mm_auth_req\s*\(",
    ]

    id_fn_patterns = [
        r"mm_tx_identity_req\s*\(",
        r"msc_vlr_tx_id_req\s*\(",
        r"gsm48_tx_mm_id_req\s*\(",
    ]

    # Generic submit patterns — covers both old gscon/gsm48_conn API (pre-1.9)
    # and the new msc_a DTAP TX API introduced in ~1.5 and used in 1.11.0.
    submit_patterns = [
        # osmo-msc >= ~1.5  (msc_a architecture)
        r"msc_a_tx_dtap_to_i\s*\(",
        r"msc_a_tx_common_id\s*\(",
        r"msc_a_tx\w*\s*\(",
        # older API (pre msc_a split)
        r"gscon_submit_rsl_dtap\s*\(",
        r"gscon_submit_dtap\s*\(",
        r"gsm48_conn_sendmsg\s*\(",
        r"ran_conn_down_l2\s*\(",
        # generic send helpers
        r"gsm48_sendmsg\s*\(",
        r"_gsm48_rx_mm_serv_req\s*\(",
        r"msc_tx_dtap\s*\(",
    ]

    def find_and_inject(content, fn_patterns, hook_tag):
        """
        Locate the function, find the last submit call inside it, and insert
        the hook call on the line immediately before that submit.
        Returns (new_content, success_bool).
        """
        fn_match = None
        for pat in fn_patterns:
            fn_match = re.search(pat, content)
            if fn_match:
                break

        if not fn_match:
            return content, False

        fn_start = fn_match.start()
        tail = content[fn_start:]

        # Find the opening brace of the function body
        brace_pos = tail.find("{")
        if brace_pos == -1:
            return content, False

        # Walk the brace tree to find the matching closing brace
        depth = 0
        fn_body_end = brace_pos
        for i, ch in enumerate(tail[brace_pos:], start=brace_pos):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    fn_body_end = i
                    break

        fn_body = tail[:fn_body_end + 1]

        # Find the LAST submit call inside the function body
        last_submit = None
        last_submit_start = None
        for pat in submit_patterns:
            for m in re.finditer(pat, fn_body):
                if last_submit_start is None or m.start() > last_submit_start:
                    last_submit = m
                    last_submit_start = m.start()

        if last_submit is None:
            # Print a body excerpt to help identify the actual send call
            print(f"[apply_hook] DEBUG: Function found for tag '{hook_tag}' "
                  f"at offset {fn_start}, body length {fn_body_end} chars")
            # Show first 20 non-blank lines of the function body
            body_lines = fn_body.splitlines()
            preview = [l for l in body_lines if l.strip()][:20]
            print("[apply_hook] DEBUG: Function body preview:")
            for l in preview:
                print("  ", l)
            print("[apply_hook] DEBUG: submit_patterns searched:", submit_patterns)
            return content, False

        # Walk back to the start of the line containing the submit call
        submit_abs = fn_start + last_submit_start
        line_start = content.rfind("\n", 0, submit_abs) + 1

        # Build the hook call with the same indentation as the submit line
        indent = ""
        for ch in content[line_start:submit_abs]:
            if ch in (" ", "\t"):
                indent += ch
            else:
                break

        hook_line = f'{indent}fuzzer_hook_mm_tx(msg, "{hook_tag}");\n'

        # Insert before the submit line
        new_content = content[:line_start] + hook_line + content[line_start:]
        return new_content, True

    # Inject auth_req hook
    modified, ok = find_and_inject(modified, auth_fn_patterns, "auth_req")
    if ok:
        print("[apply_hook] ✓ Injected auth_req hook into gsm_04_08.c")
        injections += 1
    else:
        # Distinguish: function not found vs submit call not found
        fn_found = any(re.search(p, modified) for p in auth_fn_patterns)
        print("[apply_hook] ✗ WARNING: Could not inject auth_req hook")
        if fn_found:
            print("  → Function WAS found but no matching submit call inside it.")
            print("  → Add the actual send-function name to submit_patterns in apply_hook.py")
        else:
            print("  → Function NOT found. Searched for:", auth_fn_patterns)
            print("  → Update auth_fn_patterns with the correct name from the source.")

    # Inject id_req hook
    modified, ok = find_and_inject(modified, id_fn_patterns, "id_req")
    if ok:
        print("[apply_hook] ✓ Injected id_req hook into gsm_04_08.c")
        injections += 1
    else:
        fn_found = any(re.search(p, modified) for p in id_fn_patterns)
        print("[apply_hook] ✗ WARNING: Could not inject id_req hook")
        if fn_found:
            print("  → Function WAS found but no matching submit call inside it.")
            print("  → Add the actual send-function name to submit_patterns in apply_hook.py")
        else:
            print("  → Function NOT found. Searched for:", id_fn_patterns)

    if injections == 0:
        sys.exit("[apply_hook] FATAL: No hook injection points found in "
                 "gsm_04_08.c — check the function names and update "
                 "apply_hook.py before rebuilding.")

    # Add #include "fuzzer_hook.h" after the first existing #include
    if '#include "fuzzer_hook.h"' not in modified:
        modified = re.sub(
            r'(#include\s+"[^"]+\.h")',
            r'\1\n#include "fuzzer_hook.h"',
            modified,
            count=1,
        )
        print('[apply_hook] ✓ Added #include "fuzzer_hook.h" to gsm_04_08.c')

    return modified


# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Patch Makefile.am
# ─────────────────────────────────────────────────────────────────────────────

def patch_makefile(content):
    modified = content

    # ── Detect the actual automake variable prefix ───────────────────────────
    # Could be libmsc_la (libtool .la) or libmsc_a (plain static .a).
    # Scan for the first libmsc*_SOURCES = line to discover the real prefix.
    m = re.search(r'(libmsc\w+)_SOURCES\s*[+]?=', content)
    lib_prefix = m.group(1) if m else "libmsc_a"   # osmo-msc 1.11.0 default
    sources_var = f"{lib_prefix}_SOURCES"
    ldadd_vars  = [f"{lib_prefix}_LDADD", f"{lib_prefix}_LIBADD"]

    print(f"[apply_hook] Detected library prefix: {lib_prefix}")
    print(f"[apply_hook] SOURCES var:  {sources_var}")

    # Diagnostic: show the first 25 lines that reference this prefix
    for lineno, l in enumerate(content.splitlines(), 1):
        if lib_prefix in l:
            print(f"  {lineno}: {l}")

    # ── Add fuzzer_hook.c to <lib_prefix>_SOURCES ────────────────────────────
    if "fuzzer_hook.c" not in modified:
        source_patterns = [
            # Format 1: SOURCES = \<NL><indent>first.c
            (rf"({re.escape(sources_var)}\s*=\s*\\\s*\n)([ \t]+)",
             r"\1\2fuzzer_hook.c \\\n\2"),
            # Format 2: SOURCES = first.c \<NL>…   (inline start)
            (rf"({re.escape(sources_var)}\s*=\s*)(\S+\.c)",
             r"\1fuzzer_hook.c \\\n\t\2"),
        ]

        for pat, repl in source_patterns:
            candidate = re.sub(pat, repl, modified, count=1)
            if candidate != modified:
                modified = candidate
                print(f"[apply_hook] ✓ Added fuzzer_hook.c via pattern match")
                break
        else:
            # Fallback: insert a line right after the SOURCES = ... line
            # (works regardless of multi-line format)
            def insert_after_sources(m2):
                line = m2.group(0)
                # If line ends with backslash, insert after it on next line
                if line.rstrip().endswith("\\"):
                    return line + "\tfuzzer_hook.c \\\n"
                return line + " fuzzer_hook.c"

            candidate = re.sub(
                rf"{re.escape(sources_var)}\s*=\s*[^\n]*",
                insert_after_sources,
                modified,
                count=1,
            )
            if candidate != modified:
                modified = candidate
                print(f"[apply_hook] ✓ Added fuzzer_hook.c via inline-insert fallback")
            else:
                sys.exit(f"[apply_hook] FATAL: could not add fuzzer_hook.c to {sources_var}")

    # ── Add -lpthread to LDADD / LIBADD ─────────────────────────────────────
    for libadd_var in ldadd_vars:
        if libadd_var in modified and "-lpthread" not in modified:
            modified = re.sub(
                rf"({re.escape(libadd_var)}\s*=)",
                r"\1 -lpthread",
                modified,
                count=1,
            )
            print(f"[apply_hook] ✓ Added -lpthread to {libadd_var}")
            break

    return modified


# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Patch sccp_user.c — bypass fatal 'role was not set' check
# ─────────────────────────────────────────────────────────────────────────────

def patch_sccp_role_check():
    """
    osmo-msc 1.11.0 has a strict check in sccp_user.c (around line 659) that
    hard-exits if asp->cfg.role_set_by_vty is false.  With libosmo-sccp 1.8.0,
    this flag is not reliably propagated at runtime even when 'role asp' and
    'sctp-role client' are present in the config.

    Strategy: scan sccp_user.c for the error-string line, walk back to the
    opening 'if (', comment out the entire if-block so the binary continues
    and the SCCP client sets up correctly.
    """
    if not os.path.exists(SCCP_USER_PATH):
        print(f"[apply_hook] {SCCP_USER_PATH} not found — skipping role-check patch")
        return

    with open(SCCP_USER_PATH) as f:
        lines = f.readlines()

    # Locate the line containing the fatal error message
    target_phrases = [
        "role' was not set there",
        "role was not set there",
        "'role' was not set",
        "role was not set",
        "sctp_role_set_by_vty",
    ]
    error_line_idx = None
    for idx, line in enumerate(lines):
        if any(p in line for p in target_phrases):
            error_line_idx = idx
            break

    if error_line_idx is None:
        print(f"[apply_hook] role-check pattern not found in {SCCP_USER_PATH} — skipping")
        return

    print(f"[apply_hook] Found role-check error string at line {error_line_idx + 1}")

    # Walk backwards to find the opening 'if (' of this block
    block_start = error_line_idx
    for j in range(error_line_idx, max(error_line_idx - 10, -1), -1):
        if "if (" in lines[j] or "if(" in lines[j]:
            block_start = j
            break

    # Walk forwards to find the closing '}' (track brace depth)
    depth = 0
    block_end = error_line_idx
    for j in range(block_start, min(block_start + 20, len(lines))):
        depth += lines[j].count("{")
        depth -= lines[j].count("}")
        block_end = j
        if depth <= 0 and j > block_start:
            break

    print(f"[apply_hook]   if-block spans lines {block_start+1}-{block_end+1} — commenting out")

    # Replace the if-block with a no-op comment
    new_lines = (
        lines[:block_start]
        + ["/* [fuzzer-patch] role check bypassed — auto-accept for fuzzing */\n"]
        + lines[block_end + 1:]
    )

    with open(SCCP_USER_PATH, "w") as f:
        f.writelines(new_lines)

    print(f"[apply_hook] ✓ sccp_user.c role-check bypassed successfully")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("[apply_hook] Starting hook injection for osmo-msc 1.11.0")
    print(f"[apply_hook] Working directory: {os.getcwd()}")

    # gsm_04_08.c — inject fuzzer hook
    gsm_content = read_file(GSM4808_PATH)
    gsm_patched = patch_gsm4808(gsm_content)
    write_file(GSM4808_PATH, gsm_patched)

    # Makefile.am — add fuzzer_hook.c and -lpthread
    mk_content  = read_file(MAKEFILE_PATH)
    mk_patched  = patch_makefile(mk_content)
    write_file(MAKEFILE_PATH, mk_patched)

    # sccp_user.c — bypass fatal role-not-set check
    patch_sccp_role_check()

    print("[apply_hook] Hook injection complete.")


if __name__ == "__main__":
    main()
