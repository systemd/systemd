#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Verify two ABI properties of the supplied ELF objects:

1. No imported GLIBC symbol is newer than the baseline (default 2.34).
2. Each binary's NEEDED entries only reference glibc itself or our own
   internal shared libraries — anything else means we've grown a hard
   link-time dependency on a third-party library that should be dlopen()'d
   instead.
"""

import argparse
import re
import subprocess
import sys

GLIBC_RE: re.Pattern[str] = re.compile(r'\bGLIBC_(\d+)\.(\d+)(?:\.\d+)?\b')
NEEDED_RE: re.Pattern[str] = re.compile(r'\(NEEDED\)\s+Shared library:\s+\[([^\]]+)\]')

Version = tuple[int, int]

# Shared libraries that ship as part of the C library itself; always allowed.
# Matched by prefix so the soversion is not hardcoded. glibc splits libc/libm/etc.;
# musl bundles everything into a single libc whose soname encodes the architecture
# (e.g. libc.musl-x86_64.so.1, libc.musl-aarch64.so.1).
LIBC_LIB_PREFIXES: tuple[str, ...] = (
    'libc.so.',
    'libm.so.',
    'libresolv.so.',
    'libc.musl-',
    'libucontext.',
)

# GCC runtime support libraries (stack unwinding, soft-float helpers, C++ standard library). The
# toolchain pulls these in automatically and they're part of every glibc toolchain. Matched by
# prefix so the soversion is not hardcoded.
GCC_LIB_PREFIXES: tuple[str, ...] = (
    'libasan.so.',
    'libclang_rt.asan.so',
    'libclang_rt.ubsan.so',
    'libubsan.so.',
    'libgcc_s.so.',
    'libstdc++.so.',
)

# Our own shared libraries; matched by prefix because the soname encodes the
# project version (libsystemd-shared-NNN.so, libsystemd-core-NNN.so).
INTERNAL_LIB_PREFIXES: tuple[str, ...] = (
    'libsystemd-shared-',
    'libsystemd-core-',
    'libsystemd.so.',
    'libudev.so.',
)


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
    # The runtime linker's filename depends on the architecture: ld-linux-x86-64.so.2,
    # ld-linux-aarch64.so.1, ld-linux-armhf.so.3, ld-linux-riscv64-lp64d.so.1 on the
    # "ld-" naming; ld.so.1 (mips, ppc, s390 32-bit), ld64.so.1 (s390x, ppc64 BE),
    # and ld64.so.2 (ppc64le) on the older naming. musl uses ld-musl-<arch>.so.1
    # (already covered by the "ld-" prefix).
    return name.startswith(('ld-', 'ld.so.', 'ld64.so.'))


def is_libc(name: str) -> bool:
    return name.startswith(LIBC_LIB_PREFIXES)


def glibc_imports(path: str) -> list[tuple[str, str, Version]]:
    """Return a sorted list of (symbol, "GLIBC_X.Y", version) triples for every
    imported GLIBC-versioned symbol referenced by ``path``."""
    out = subprocess.check_output(
        ['readelf', '-W', '--dyn-syms', path],
        text=True,
        stderr=subprocess.DEVNULL,
    )

    found: set[tuple[str, str, Version]] = set()
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
        sym = next((t for t in parts if '@' in t), line.strip())
        found.add((sym, m.group(0), ver))
    return sorted(found)


def needed_violations(path: str) -> list[str]:
    """Return NEEDED entries outside the always-allowed set."""
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
        if (
            is_libc(name)
            or name.startswith(GCC_LIB_PREFIXES)
            or is_dynamic_linker(name)
            or is_internal(name)
        ):
            continue
        bad.append(name)
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        '--baseline',
        type=parse_baseline,
        default=(2, 34),
        help='Maximum allowed GLIBC version (default: 2.34)',
    )
    ap.add_argument('paths', nargs='*', metavar='PATH', help='ELF files to check')
    args = ap.parse_args()

    baseline: Version = args.baseline

    # First pass: collect all imports and NEEDED entries so we can derive an
    # effective baseline before reporting any violations.
    imports: dict[str, list[tuple[str, str, Version]]] = {}
    needed: dict[str, list[str]] = {}
    for path in args.paths:
        if not is_elf(path):
            # Some inputs passed by meson may be scripts or non-ELF
            # generators; silently skip those rather than fail.
            continue
        imports[path] = glibc_imports(path)
        needed[path] = needed_violations(path)

    # On architectures where glibc support was added after our baseline (e.g.
    # loongarch64, introduced in glibc 2.36), every imported symbol will be
    # tagged with a version newer than the baseline, so the baseline check
    # would spuriously fail. Detect this by taking the minimum version observed
    # across all binaries: if it exceeds the baseline, treat that minimum as
    # the effective baseline instead.
    observed = [v for syms in imports.values() for _, _, v in syms]
    effective_baseline = baseline
    if observed:
        observed_min = min(observed)
        if observed_min > baseline:
            effective_baseline = observed_min
            print(
                f'Note: lowest observed GLIBC import is '
                f'GLIBC_{observed_min[0]}.{observed_min[1]}, newer than the requested baseline '
                f'GLIBC_{baseline[0]}.{baseline[1]}; assuming this architecture has no older '
                f'symbols available and using GLIBC_{effective_baseline[0]}.{effective_baseline[1]} '
                f'as the effective baseline.',
                file=sys.stderr,
            )

    failed = 0
    for path, syms in imports.items():
        glibc_bad = sorted({(sym, ver_str) for sym, ver_str, ver in syms if ver > effective_baseline})
        needed_bad = needed[path]

        if glibc_bad or needed_bad:
            failed += 1
            print(f'{path}:', file=sys.stderr)
        if glibc_bad:
            print(
                f'  imports symbols newer than GLIBC_{effective_baseline[0]}.{effective_baseline[1]}:',
                file=sys.stderr,
            )
            for sym, ver_str in glibc_bad:
                print(f'    {sym} ({ver_str})', file=sys.stderr)
        if needed_bad:
            print('  links against unexpected libraries (dlopen() them instead):', file=sys.stderr)
            for name in needed_bad:
                print(f'    {name}', file=sys.stderr)

    checked = len(imports)
    baseline_str = f'GLIBC_{effective_baseline[0]}.{effective_baseline[1]}'
    if failed:
        print(f'\nFAIL: {failed} of {checked} ELF objects failed the ABI checks.', file=sys.stderr)
        return 1
    print(
        f'OK: {checked} ELF objects checked; all within {baseline_str} and with only allowed NEEDED entries.'
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
