#!/usr/bin/env python3
"""
Compare statically linked dlopen symbols against shared library ELF notes.

This script extracts surviving dlopen_* symbols from a statically linked
executable (representing the true minimal set of dynamically loaded features
actually invoked by the code after linker optimizations like --gc-sections)
and compares them against the embedded FDO .note.dlopen metadata inside a
shared library or dynamic executable.

It highlights missing metadata, over-included (dead) metadata, and detects
any unmapped symbols that require script updates.
"""

import argparse
import enum
import json
import os
import re
import sys
from functools import total_ordering
from pathlib import Path
from typing import Any

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import NoteSection, SymbolTableSection
except ImportError:
    print("Error: 'elftools' python module not found.", file=sys.stderr)
    sys.exit(1)


# Function filter: Maps wrapper/sentinel symbols to real symbols or an empty list (ignore).
FUNCTION_FILTER = {
    # Filtered out (internal helpers, verbose loggers, sentinels)
    'dlopen_safe': [],
    'dlopen_verbose': [],
    'dlopen_many_sym_or_warn_sentinel': [],
    'dlopen_dw_has_dwfl_set_sysroot': [],
    'dlopen_libcrypto_has_argon2id': [],
    # Mapped to multiple functions (expands generic wrappers into specific sub-layers)
    'dlopen_tpm2': [
        'dlopen_tpm2_esys',
        'dlopen_tpm2_mu',
        'dlopen_tpm2_rc',
        'dlopen_tpm2_tcti_device',
    ],
}


# Direct mapping from clean symbol name to expected FDO dlopen feature name.
FUNCTION_TO_FEATURE = {
    'dlopen_bpf': 'bpf',
    'dlopen_bzip2': 'bzip2',
    'dlopen_cryptsetup': 'cryptsetup',
    'dlopen_curl': 'curl',
    'dlopen_dw': 'dw',
    'dlopen_elf': 'elf',
    'dlopen_fdisk': 'fdisk',
    'dlopen_gnutls': 'gnutls',
    'dlopen_idn': 'idn',
    'dlopen_libacl': 'acl',
    'dlopen_libapparmor': 'apparmor',
    'dlopen_libarchive': 'archive',
    'dlopen_libaudit': 'audit',
    'dlopen_libblkid': 'blkid',
    'dlopen_libcrypt': 'crypt',
    'dlopen_libcrypto': 'libcrypto',
    'dlopen_libfido2': 'fido2',
    'dlopen_libkmod': 'kmod',
    'dlopen_libmount': 'mount',
    'dlopen_libpam': 'pam',
    'dlopen_libseccomp': 'seccomp',
    'dlopen_libselinux': 'selinux',
    'dlopen_libssl': 'libssl',
    'dlopen_lz4': 'lz4',
    'dlopen_microhttpd': 'microhttpd',
    'dlopen_p11kit': 'p11-kit',
    'dlopen_passwdqc': 'passwdqc',
    'dlopen_pcre2': 'pcre2',
    'dlopen_pwquality': 'pwquality',
    'dlopen_qrencode': 'qrencode',
    'dlopen_tpm2_esys': 'tpm (esys)',
    'dlopen_tpm2_mu': 'tpm (mu)',
    'dlopen_tpm2_rc': 'tpm (rc)',
    'dlopen_tpm2_tcti_device': 'tpm (tcti-device)',
    'dlopen_xkbcommon': 'xkbcommon',
    'dlopen_xz': 'lzma',
    'dlopen_zlib': 'zlib',
    'dlopen_zstd': 'zstd',
}


def dlopen_function_append(name: str, function_names: set[str]) -> None:
    """Add a symbol to the set, expanding or dropping based on FUNCTION_FILTER."""
    function_names.update(FUNCTION_FILTER.get(name, [name]))


def dlopen_functions_parse(path: Path) -> set[str]:
    """Parse ELF symbol tables and extract surviving dlopen_* function names."""
    function_names: set[str] = set()

    try:
        with path.open('rb') as f:
            elffile = ELFFile(f)
            for section in elffile.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue
                for symbol in section.iter_symbols():
                    # Ignore undefined (externally referenced) or non-function symbols
                    if symbol['st_info']['type'] != 'STT_FUNC' or symbol['st_shndx'] == 'SHN_UNDEF':
                        continue

                    if m := re.match(r'^(?:sym_)?(dlopen_[a-zA-Z0-9_]+)$', symbol.name):
                        dlopen_function_append(m.group(1), function_names)

    except Exception as e:
        print(f"Failed to read '{path}': {e}", file=sys.stderr)
        sys.exit(1)

    return function_names


def dlopen_note_get_feature(item: dict[str, Any]) -> str:
    if 'feature' not in item:
        return None

    feature = item['feature']
    if feature != 'tpm':
        return feature

    # TPM features are collapsed into "tpm" in the ELF note. We iterate over
    # sonames to correctly map them back to detailed granular layers.
    for soname in item.get('soname', []):
        if 'esys' in soname:
            return 'tpm (esys)'
        if 'mu' in soname:
            return 'tpm (mu)'
        if 'rc' in soname:
            return 'tpm (rc)'
        if 'tcti-device' in soname:
            return 'tpm (tcti-device)'
    else:
        return feature  # If not found, let's return 'tpm' as is, and warn later.


@total_ordering
class Priority(enum.Enum):
    suggested = 1
    recommended = 2
    required = 3

    def __lt__(self, other):
        return self.value < other.value

    def __str__(self):
        return self.name


def dlopen_note_append(item: dict[str, Any], entries: dict[str, dict[str, Any]]) -> None:
    """Store the parsed note item into the dictionary."""

    feat = dlopen_note_get_feature(item)
    prio = Priority[item.get('priority', 'recommended')]

    if feat in entries and Priority[entries[feat].get('priority', 'recommended')] >= prio:
        return

    entries[feat] = item


def dlopen_note_merge(
    a: dict[str, dict[str, Any]],
    b: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    c = a

    for item in b.values():
        dlopen_note_append(item, c)

    return c


def dlopen_note_parse(path: Path) -> dict[str, dict[str, Any]]:
    """Parse .note.dlopen ELF section and extract embedded JSON metadata."""
    entries: dict[str, dict[str, Any]] = {}

    try:
        with path.open('rb') as f:
            elffile = ELFFile(f)
            for section in elffile.iter_sections():
                # Verify section name and type safely
                if section.name != '.note.dlopen' or not isinstance(section, NoteSection):
                    continue

                for note in section.iter_notes():
                    desc = note['n_desc']
                    # Handle raw bytes or string payloads, stripping null-terminator bytes (\x00)
                    desc_str = (
                        desc.decode('utf-8', errors='ignore').rstrip('\x00')
                        if isinstance(desc, bytes)
                        else str(desc).rstrip('\x00')
                    )

                    try:
                        data = json.loads(desc_str)
                        # According to FDO specs, payload can be a JSON array or a single dict
                        items = data if isinstance(data, list) else [data]
                        for item in items:
                            if isinstance(item, dict):
                                dlopen_note_append(item, entries)
                    except json.JSONDecodeError:
                        continue

    except Exception as e:
        print(f"Failed to read '{path}': {e}", file=sys.stderr)
        sys.exit(1)

    return entries


def dlopen_note_dump(entries: dict[str, dict[str, Any]], path: str) -> None:
    print(f'=== Embedded .note.dlopen Metadata in: {path} ===')
    if not entries:
        print('  (No .note.dlopen metadata found)')
    else:
        for feat, item in sorted(entries.items()):
            p = item.get('priority', 'recommended')
            print(f"  - {feat.ljust(20)} : {p.ljust(15)} : {' '.join(item.get('soname', []))}")
    print()


def main():
    parser = argparse.ArgumentParser(description='Compare dlopen symbols vs metadata notes.')
    parser.add_argument('--static', required=True, help='Path to statically linked binary')
    parser.add_argument('--shared', required=True, help='Path to shared library or dynamic binary')
    args = parser.parse_args()

    unknown_functions = set()
    features_by_func = set()
    if check_function_symbol := os.getenv('SYSTEMD_BUILD_MODE') == 'developer':
        for name in dlopen_functions_parse(Path(args.static)):
            if name not in FUNCTION_TO_FEATURE:
                unknown_functions.add(name)
            else:
                features_by_func.add(FUNCTION_TO_FEATURE[name])

    note_static = dlopen_note_parse(Path(args.static))
    note_shared = dlopen_note_parse(Path(args.shared))
    note_merged = dlopen_note_merge(note_static, note_shared)

    dlopen_note_dump(note_static, args.static)
    dlopen_note_dump(note_shared, args.shared)

    print('=== [DIFF] Analysis & Verification ===')

    rc = 0

    for feat, item in sorted(note_merged.items()):
        if feat not in note_shared:
            print(f'  ❌ {feat} is missing.')
            rc = 1
            continue

        p = Priority[item.get('priority', 'recommended')]
        q = Priority[note_shared[feat].get('priority', 'recommended')]
        if q < p:
            print(f'  ⚠️ {feat} has weaker priority ({q} < {p}).')
            rc = 1
            continue

        if check_function_symbol and feat not in features_by_func:
            print(f'  💥 {feat} is set, but corresponding dlopen() is not called.')
            rc = 1
            continue

        if feat not in note_static:
            print(f'  👀 {feat} is missing in {args.static}.')
            rc = 1

    if unknown_functions:
        print('  💀  [UNKNOWN DLOPEN FUNCTIONS] Found unknown dlopen functions, please update tables:')
        for f in sorted(unknown_functions):
            print(f"     * Function '{f}'")
            rc = 1

    if rc == 0:
        print('  🎉 PERFECT MATCH! Exactly required dlopen notes are embedded.')

    sys.exit(rc)


if __name__ == '__main__':
    main()
