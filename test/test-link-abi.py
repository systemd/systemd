#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Verify two ABI properties of the supplied ELF objects:

  1. No imported GLIBC symbol is newer than the baseline (default 2.34).
  2. Each binary's NEEDED entries only reference glibc itself, our own internal
     shared libraries, or libraries explicitly allowed for that binary's
     category — anything else means we've grown a hard link-time dependency on
     a third-party library that should be dlopen()'d instead.

Inputs are grouped by category so the per-category allowlist of extra NEEDED
entries is implicit in how meson invokes the script — no per-binary exception
table. Categories without any binaries can just be omitted.
"""

import argparse
import re
import subprocess
import sys

GLIBC_RE: re.Pattern[str] = re.compile(r'\bGLIBC_(\d+)\.(\d+)(?:\.\d+)?\b')
NEEDED_RE: re.Pattern[str] = re.compile(r'\(NEEDED\)\s+Shared library:\s+\[([^\]]+)\]')

Version = tuple[int, int]

# Shared libraries that ship as part of glibc itself; always allowed.
GLIBC_LIBS: frozenset[str] = frozenset({
    'libc.so.6',
    'libm.so.6',
})

# GCC runtime support libraries (stack unwinding, soft-float helpers, C++ standard library). The
# toolchain pulls these in automatically and they're part of every glibc toolchain.
GCC_LIBS: frozenset[str] = frozenset({
    'libgcc_s.so.1',
    'libstdc++.so.6',
})

# Our own shared libraries; matched by prefix because the soname encodes the
# project version (libsystemd-shared-NNN.so, libsystemd-core-NNN.so).
INTERNAL_LIB_PREFIXES: tuple[str, ...] = (
    'libsystemd-shared-',
    'libsystemd-core-',
    'libsystemd.so.',
    'libudev.so.',
)

# Per-category extra NEEDED entries beyond the always-allowed set. The category
# name is also the argparse dest, so spelling matters.
CATEGORY_EXTRAS: dict[str, frozenset[str]] = {
    'executables':        frozenset(),
    'shared_libraries':   frozenset(),
    'nss_modules':        frozenset(),
    'pam_modules':        frozenset({'libpam.so.0', 'libpam_misc.so.0'}),
    'cryptsetup_tokens':  frozenset({'libcryptsetup.so.12'}),
}


def parse_baseline(s: str) -> Version:
    m = re.fullmatch(r'(\d+)\.(\d+)', s)
    if not m:
        raise argparse.ArgumentTypeError(f'baseline must be MAJOR.MINOR, got {s!r}')
    return (int(m.group(1)), int(m.group(2)))


def is_elf(path: str) -> bool:
    """Cheap ELF magic check so readelf isn't run on non-ELF inputs."""
    try:
        with open(path, 'rb') as f:
            return f.read(4) == b'\x7fELF'
    except OSError:
        return False


def is_internal(name: str) -> bool:
    return any(name.startswith(p) for p in INTERNAL_LIB_PREFIXES)


def is_dynamic_linker(name: str) -> bool:
    # The runtime linker's filename depends on the architecture (e.g.
    # ld-linux-x86-64.so.2, ld-linux-aarch64.so.1, ld-linux-armhf.so.3).
    return name.startswith('ld-')


def glibc_violations(path: str, baseline: Version) -> list[tuple[str, str]]:
    """Return a sorted list of (symbol, "GLIBC_X.Y") pairs above the baseline."""
    out = subprocess.check_output(
        ['readelf', '-W', '--dyn-syms', path],
        text=True,
        stderr=subprocess.DEVNULL,
    )

    found: set[tuple[str, str]] = set()
    for line in out.splitlines():
        m = GLIBC_RE.search(line)
        if not m:
            continue
        # readelf --dyn-syms lists both imported (Ndx=UND) and exported symbols;
        # only the former carry a real link-time dependency on the listed glibc
        # version. Skip anything that isn't UND.
        parts = line.split()
        if len(parts) < 8 or parts[6] != 'UND':
            continue
        ver: Version = (int(m.group(1)), int(m.group(2)))
        if ver <= baseline:
            continue
        sym = next((t for t in parts if '@' in t), line.strip())
        found.add((sym, m.group(0)))
    return sorted(found)


def needed_violations(path: str, allowed_extras: frozenset[str]) -> list[str]:
    """Return NEEDED entries outside the always-allowed sets and the
    category-specific allowlist."""
    out = subprocess.check_output(
        ['readelf', '-W', '-d', path],
        text=True,
        stderr=subprocess.DEVNULL,
    )

    bad: list[str] = []
    for line in out.splitlines():
        m = NEEDED_RE.search(line)
        if not m:
            continue
        name = m.group(1)
        if (name in GLIBC_LIBS
                or name in GCC_LIBS
                or is_dynamic_linker(name)
                or is_internal(name)
                or name in allowed_extras):
            continue
        bad.append(name)
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--baseline', type=parse_baseline, default=(2, 34),
                    help='Maximum allowed GLIBC version (default: 2.34)')
    for cat in CATEGORY_EXTRAS:
        ap.add_argument(f'--{cat.replace("_", "-")}', dest=cat, nargs='*',
                        default=[], metavar='PATH',
                        help=f'ELF files in the {cat!r} category')
    args = ap.parse_args()

    baseline: Version = args.baseline
    checked = 0
    failed = 0
    for cat, extras in CATEGORY_EXTRAS.items():
        paths: list[str] = getattr(args, cat)
        for path in paths:
            if not is_elf(path):
                # Some "executables" passed by meson may be scripts or non-ELF
                # generators; silently skip those rather than fail.
                continue
            checked += 1

            glibc_bad = glibc_violations(path, baseline)
            needed_bad = needed_violations(path, extras)

            if glibc_bad or needed_bad:
                failed += 1
                print(f'{path} (category: {cat}):', file=sys.stderr)
            if glibc_bad:
                print(f'  imports symbols newer than GLIBC_{baseline[0]}.{baseline[1]}:',
                      file=sys.stderr)
                for sym, ver_str in glibc_bad:
                    print(f'    {sym} ({ver_str})', file=sys.stderr)
            if needed_bad:
                print('  links against unexpected libraries (dlopen() them, or '
                      'move the binary to a category that permits them):',
                      file=sys.stderr)
                for name in needed_bad:
                    print(f'    {name}', file=sys.stderr)

    baseline_str = f'GLIBC_{baseline[0]}.{baseline[1]}'
    if failed:
        print(f'\nFAIL: {failed} of {checked} ELF objects failed the ABI checks.',
              file=sys.stderr)
        return 1
    print(f'OK: {checked} ELF objects checked; all within {baseline_str} '
          'and with only their category-allowed NEEDED entries.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
