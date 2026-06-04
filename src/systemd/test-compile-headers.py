#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Check that every public header compiles standalone as C and C++ in every supported standard.

This used to be expressed as one meson test per (header, language, standard) combination,
which produced hundreds of tests. Instead, meson invokes this script once and we run all the
combinations ourselves (in parallel)."""

import argparse
import asyncio
import os
import sys


async def check(semaphore, lang, compiler, std, common_args, header):
    """Compile header standalone. Returns None on success or a failure report otherwise."""
    cmd = [*compiler, '-c', '-x', lang]
    if std:
        cmd += [std]
    cmd += [*common_args, '-include', header, '-o', '/dev/null', '/dev/null']

    async with semaphore:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        output, _ = await proc.communicate()

    if proc.returncode != 0:
        report = f'FAIL: {header} ({lang} {std or "default"})'
        if output:
            report += '\n' + output.decode(errors='replace').rstrip('\n')
        return report

    return None


async def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cc', action='append', default=[],
                   help='one element of the C compiler command (repeat for each)')
    p.add_argument('--cxx', action='append', default=[],
                   help='one element of the C++ compiler command (repeat for each)')
    p.add_argument('--c-std', action='append', default=[],
                   help='a C standard flag to check (empty string for the compiler default)')
    p.add_argument('--cxx-std', action='append', default=[],
                   help='a C++ standard flag to check (empty string for the compiler default)')
    p.add_argument('--common-arg', action='append', default=[],
                   help='a flag passed to every compilation')
    p.add_argument('header', nargs='+', help='header to check')
    args = p.parse_args()

    # Bound the number of compilers running at once so we don't fork-bomb the machine.
    semaphore = asyncio.Semaphore(min(32, len(os.sched_getaffinity(0)) * 2))

    tasks = []
    for header in args.header:
        for std in args.c_std:
            tasks.append(check(semaphore, 'c', args.cc, std, args.common_arg, header))
        for std in args.cxx_std:
            tasks.append(check(semaphore, 'c++', args.cxx, std, args.common_arg, header))

    results = await asyncio.gather(*tasks)
    failures = [report for report in results if report is not None]

    if failures:
        # Print each report as a whole so concurrent failures don't interleave.
        for report in failures:
            print(report, file=sys.stderr)
        print(f'{len(failures)}/{len(results)} header compilation check(s) failed',
              file=sys.stderr)
        return 1

    print(f'{len(results)} header compilation check(s) passed')
    return 0


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
