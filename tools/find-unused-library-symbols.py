#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Find unused symbols in a shared library.

This script analyzes a shared library and a list of executables that link
against it to determine which publicly exported symbols from the library
are not used by any of the executables or by the library itself internally.

The script checks for symbol usage in three ways:
1. Internal library references: Uses objdump -R to find relocations within
   the library that reference its own exported symbols
2. Executable dependencies: Uses nm to find undefined symbols in executables
   that match the library's exported symbols
3. Cross-references: Identifies symbols used across all provided binaries

This comprehensive approach ensures that symbols used internally by the
library are not incorrectly marked as unused.
"""

import argparse
import subprocess
import sys
from pathlib import Path


def get_exported_symbols(library_path):
    """
    Extract all exported (public) symbols from a shared library.

    Public API symbols (those starting with 'sd_') are excluded from the analysis
    since they cannot be removed or made private due to API compatibility requirements.

    Returns a set of symbol names that are defined and exported by the library.
    """
    try:
        result = subprocess.run(
            ['nm', '--dynamic', '--defined-only', '--extern-only', library_path],
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to run nm on {library_path}: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("Error: 'nm' command not found. Please install binutils.", file=sys.stderr)
        sys.exit(1)

    symbols = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            # Format: address type name
            symbol_type = parts[1]
            symbol_name = parts[2]
            # Include text (T) and data (D, B, R) symbols
            if symbol_type in ('T', 'D', 'B', 'R', 'W'):
                # Strip version information (e.g., @@SD_SHARED or @SD_SHARED)
                symbol_name = symbol_name.split('@')[0]
                # Skip public API symbols (those starting with sd_)
                if symbol_name.startswith('sd_'):
                    continue
                symbols.add(symbol_name)

    return symbols


def get_undefined_symbols(executable_path):
    """
    Extract all undefined symbols from an executable.

    These are symbols that the executable expects to be provided by
    shared libraries it links against.
    """
    try:
        result = subprocess.run(
            ['nm', '--dynamic', '--undefined-only', executable_path],
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Warning: Failed to run nm on {executable_path}: {e}", file=sys.stderr)
        return set()
    except FileNotFoundError:
        print("Error: 'nm' command not found. Please install binutils.", file=sys.stderr)
        sys.exit(1)

    symbols = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            # Format: type name (no address for undefined symbols)
            symbol_name = parts[1]
            # Strip version information (e.g., @SD_SHARED)
            symbol_name = symbol_name.split('@')[0]
            symbols.add(symbol_name)

    return symbols


def verify_executable_links_library(executable_path, library_name):
    """
    Verify that an executable actually links against the given library.

    Returns True if the executable links against a library with the given name.
    """
    try:
        result = subprocess.run(
            ['ldd', executable_path],
            capture_output=True,
            text=True,
            check=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        # If ldd fails or doesn't exist, we'll skip the verification
        return True

    # Check if library_name appears in the ldd output
    for line in result.stdout.splitlines():
        if library_name in line:
            return True

    return False


def get_library_internal_references(library_path, exported_symbols):
    """
    Find which exported symbols are referenced internally within the library itself.

    This uses objdump to look for relocations that reference the exported symbols.
    """
    try:
        result = subprocess.run(
            ['objdump', '-R', library_path],
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Warning: Failed to run objdump on {library_path}: {e}", file=sys.stderr)
        return set()
    except FileNotFoundError:
        print("Warning: 'objdump' command not found. Internal references won't be detected.",
              file=sys.stderr)
        return set()

    internal_refs = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            # objdump -R format: offset type symbol
            # The symbol is typically the last field
            symbol_name = parts[-1]
            # Strip version information
            symbol_name = symbol_name.split('@')[0]
            # Only include if it's one of our exported symbols
            if symbol_name in exported_symbols:
                internal_refs.add(symbol_name)

    return internal_refs


def find_unused_symbols(library_path, executable_paths, verify_linkage=True):
    """
    Find symbols exported by the library that are not used by any executable.

    Args:
        library_path: Path to the shared library
        executable_paths: List of paths to executables
        verify_linkage: Whether to verify executables link against the library

    Returns:
        Tuple of (unused_symbols, exported_symbols, used_symbols)
    """
    library_name = Path(library_path).name

    # Get all exported symbols from the library (excluding public API symbols)
    exported_symbols = get_exported_symbols(library_path)

    if not exported_symbols:
        print(f"Warning: No exported symbols found in {library_path}", file=sys.stderr)
        return set(), set(), set()

    # Collect all symbols used by the executables
    used_symbols = set()

    # First, check if the library references its own exported symbols internally
    internal_refs = get_library_internal_references(library_path, exported_symbols)
    used_symbols.update(internal_refs)

    for exe_path in executable_paths:
        # Optionally verify linkage
        if verify_linkage and not verify_executable_links_library(exe_path, library_name):
            print(f"Warning: {exe_path} does not appear to link against {library_name}",
                  file=sys.stderr)

        undefined_symbols = get_undefined_symbols(exe_path)
        # Only count symbols that are actually exported by our library
        used_symbols.update(undefined_symbols & exported_symbols)

    # Find unused symbols
    unused_symbols = exported_symbols - used_symbols

    return unused_symbols, exported_symbols, used_symbols


def main():
    parser = argparse.ArgumentParser(
        description='Find unused exported symbols in a shared library'
    )
    parser.add_argument(
        'library',
        help='Path to the shared library to analyze'
    )
    parser.add_argument(
        'executables',
        nargs='+',
        help='Paths to executables that link against the library'
    )
    parser.add_argument(
        '--no-verify-linkage',
        action='store_true',
        help='Skip verification that executables actually link against the library'
    )
    parser.add_argument(
        '--show-used',
        action='store_true',
        help='Also show used symbols'
    )
    parser.add_argument(
        '--stats-only',
        action='store_true',
        help='Only show statistics, not individual symbols'
    )

    args = parser.parse_args()

    # Verify library exists
    library_path = Path(args.library)
    if not library_path.exists():
        print(f"Error: Library not found: {library_path}", file=sys.stderr)
        sys.exit(1)

    # Verify executables exist
    executable_paths = []
    for exe in args.executables:
        exe_path = Path(exe)
        if not exe_path.exists():
            print(f"Warning: Executable not found: {exe_path}", file=sys.stderr)
        else:
            executable_paths.append(str(exe_path))

    if not executable_paths:
        print("Error: No valid executables provided", file=sys.stderr)
        sys.exit(1)

    # Analyze symbols
    unused, exported, used = find_unused_symbols(
        str(library_path),
        executable_paths,
        verify_linkage=not args.no_verify_linkage
    )

    # Print results
    print(f"Analysis of {library_path.name}")
    print("=" * 70)
    print(f"Total exported symbols: {len(exported)}")
    print(f"  (excluding public API symbols starting with 'sd_')")
    print(f"Used symbols: {len(used)}")
    print(f"Unused symbols: {len(unused)}")
    print(f"Usage rate: {len(used)/len(exported)*100:.1f}%" if exported else "N/A")
    print()

    if not args.stats_only:
        if unused:
            print("Unused symbols:")
            print("-" * 70)
            for symbol in sorted(unused):
                print(f"  {symbol}")
            print()
        else:
            print("All exported symbols are used!")
            print()

        if args.show_used and used:
            print("Used symbols:")
            print("-" * 70)
            for symbol in sorted(used):
                print(f"  {symbol}")
            print()

    # Exit with non-zero if there are unused symbols (useful for CI)
    sys.exit(0 if not unused else 1)


if __name__ == '__main__':
    main()
