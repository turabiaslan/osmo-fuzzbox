#!/usr/bin/env python3
"""
bsc_e1_patch.py — Patches osmo-bsc e1_config.c to auto-create the IPA
E1 virtual line when it is not found.

Problem
-------
When osmo-bsc starts, the VTY config 'e1_line 0 driver ipa' tries to
create E1 line 0, but the IPA driver hasn't been registered yet
(ipaccess_setup() runs after VTY config parsing).  So line 0 doesn't
exist when e1_reconfig_bts() / e1_reconfig_trx() run, and the BSC dies
with "BTS OML link referring to non-existing E1 line 0".

Fix
---
After every  e1inp_line_find(e1_link->e1_nr)  call, insert a fallback:
    if (!line) line = e1inp_line_create(e1_link->e1_nr, "ipa");

By the time the e1_reconfig_* functions run, ipaccess_setup() has
already registered the IPA driver, so e1inp_line_create() succeeds.

Run from the root of the osmo-bsc repository:
    python3 /path/to/bsc_e1_patch.py
"""

import re
import sys
import os

E1_CONFIG_PATH = "src/osmo-bsc/e1_config.c"


def main():
    if not os.path.exists(E1_CONFIG_PATH):
        sys.exit(f"[bsc-patch] ERROR: {E1_CONFIG_PATH} not found — "
                 f"run from the osmo-bsc repository root")

    with open(E1_CONFIG_PATH) as f:
        content = f.read()

    # Pattern: line = e1inp_line_find(e1_link->e1_nr);
    # Insert:  if (!line) line = e1inp_line_create(e1_link->e1_nr, "ipa");
    # The existing  if (!line) { ... return -E...; }  block remains as a
    # safety net if the create also fails.
    pattern = r'([ \t]*)(line = e1inp_line_find\(e1_link->e1_nr\);)'
    
    def replacement(m):
        indent = m.group(1)
        orig   = m.group(2)
        create = (f'{indent}if (!line) '
                  f'line = e1inp_line_create(e1_link->e1_nr, "ipa");')
        return f'{indent}{orig}\n{create}'

    n = len(re.findall(pattern, content))
    if n == 0:
        print(f"[bsc-patch] WARNING: e1inp_line_find pattern not found "
              f"in {E1_CONFIG_PATH} — skipping (may already be patched)",
              file=sys.stderr)
        return

    patched = re.sub(pattern, replacement, content)

    with open(E1_CONFIG_PATH, "w") as f:
        f.write(patched)

    print(f"[bsc-patch] ✓ {E1_CONFIG_PATH} patched: {n} site(s) auto-create added")


if __name__ == "__main__":
    main()
