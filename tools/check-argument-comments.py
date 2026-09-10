#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Report function arguments passed as a bare NULL, 0, false or true without a /* name= */ comment.

docs/CODING_STYLE.md asks for the argument name in a comment whenever NULL or another value meaning
"unset" is passed to a function. clang-tidy's bugprone-argument-comment cannot check that for C code:
it never sees NULL behind its cast, and asking it to comment integer literals flags every size and
mode as well. This walks the AST with libclang instead, takes the parameter names from the actual
prototypes and looks only at the literals the rule is about. A comment that names a different
parameter is reported too, those go stale when parameters are renamed.

The names come from the first declaration the caller sees, usually the header, which is also the one
bugprone-argument-comment compares against. Parameters whose name says nothing, a single letter, argN
or a reserved __name copied from a libc declaration, are left alone. Calls to functions declared outside
the source tree, e.g. libc, are skipped unless --system is given; calls through the sym_* pointers of
the dlopen() wrappers are ours and are checked against the function the pointer was declared from,
except that a comment naming none of its parameters is only warned about, library headers rename
parameters between versions. Calls produced by a macro body are skipped, the caller never spelled the
argument, while a call written inside a macro argument, assert_se(f(NULL)), is checked. The in-tree
headers a file includes are checked from its translation unit, which covers their static inline
functions. With --diff REV only lines that differ from REV are reported, which is what a review wants.
Rust code is not checked.

Usage: tools/check-argument-comments.py [-p BUILDDIR] [--root DIR] [--diff REV] [--fix] [-j JOBS] [--system] PATH...

PATH is a C file or a directory to search for them, BPF programs are skipped. The compile flags come
from compile_commands.json in the build directory, the generated headers must exist ("meson compile -C
BUILDDIR gensources"); a file that is not in there, or does not parse, is an error and fails the run,
except that --diff skips files the build does not compile. --fix leaves the comments that name the
wrong parameter and files whose translation unit did not parse to a human. Exits with 1 when something
is left to fix, 2 on errors and 77 when the libclang python bindings are missing.
"""

import argparse
import glob
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from collections.abc import Iterator
from concurrent.futures import BrokenExecutor, ProcessPoolExecutor
from ctypes import POINTER, byref, c_uint
from typing import Any, NamedTuple, Optional

try:
    import clang.cindex as ci  # type: ignore
except ImportError:
    print('python3-clang is not installed', file=sys.stderr)
    sys.exit(77)

LITERAL_RE = re.compile(rb'(NULL|0|false|true)\s*(?=[,)])')
COMMENT_RE = re.compile(rb'/\*\s*((?:(?!\*/|/\*)[\s\S])*?)\s*\*/\s*$')  # a * inside is fine, /* is not
UNINFORMATIVE_RE = re.compile(r'^(?:[a-z]|arg\d*|__.*)$')
# gcc-only flags of the EFI build that libclang rejects, .clang-tidy drops the same ones through RemovedArgs
DROPPED_FLAGS = frozenset({'-fwide-exec-charset=UCS2', '-maccumulate-outgoing-args'})

Command = tuple[str, list[str]]


class Finding(NamedTuple):
    file: str
    line: int
    column: int
    offset: int
    callee: str
    param: str
    literal: str
    comment: Optional[str]  # None when there is none, else one naming another parameter


class Result(NamedTuple):
    path: str
    findings: list[Finding]
    errors: list[str]
    warnings: list[str]


class Item(NamedTuple):
    path: str
    root: str
    build_dir: str
    command: Command
    include_system: bool
    only: Optional[dict[str, set[int]]]
    resources: Optional[str]
    library: Optional[str]


def setup_libclang(library_file: Optional[str] = None) -> Optional[str]:
    """Returns the library file the workers are to use, None when the bindings find it on their own."""
    if ci.Config.loaded:
        inherited: Optional[str] = ci.Config.library_file  # a forked worker inherits the parent's library
        return inherited
    if library_file:
        ci.Config.set_library_file(library_file)
        return library_file
    if os.environ.get('LIBCLANG_PATH'):
        ci.Config.set_library_file(os.environ['LIBCLANG_PATH'])
        return os.environ['LIBCLANG_PATH']
    try:
        ci.Index.create()
        return None
    except ci.LibclangError:
        pass
    libs = sorted(
        glob.glob('/usr/lib/llvm-*/lib/libclang-*.so.1') + glob.glob('/usr/lib*/libclang.so*'),
        key=lambda p: [int(x) if x.isdigit() else x for x in re.split(r'(\d+)', p)],
        reverse=True,
    )
    if not libs:
        print('no libclang shared library found', file=sys.stderr)
        sys.exit(77)
    ci.Config.set_library_file(libs[0])
    return libs[0]


def file_loc(loc: Any) -> tuple[Optional[str], int, int, int]:
    """(file, line, column, offset) of where a token was spelled if it came from a macro argument, or of
    the macro invocation if it came from a macro body. The bindings only wrap the expansion location, which
    puts every token of a macro argument on the macro name. Uses private parts of the bindings, verified
    with libclang 19 to 22."""
    fn = ci.conf.lib.clang_getFileLocation
    if not fn.argtypes:
        fn.argtypes = [
            ci.SourceLocation,
            POINTER(ci.c_object_p),
            POINTER(c_uint),
            POINTER(c_uint),
            POINTER(c_uint),
        ]
        fn.restype = None
    f, line, column, offset = ci.c_object_p(), c_uint(), c_uint(), c_uint()
    fn(loc, byref(f), byref(line), byref(column), byref(offset))
    return (os.path.abspath(ci.File(f).name) if f else None, line.value, column.value, offset.value)


def resource_dir() -> Optional[str]:
    """Where clang's builtin headers, stddef.h and friends, live. libclang derives that from its own location,
    which goes wrong when the library does not sit next to them, so ask the clang binary of the same major
    version instead."""
    try:
        fn = ci.conf.lib.clang_getClangVersion  # the bindings do not declare its return type
        fn.restype = ci._CXString
        version = str(ci._CXString.from_result(fn()))
    except AttributeError:
        return None
    m = re.search(r'clang version (\d+)', version)
    for name in ([f'clang-{m.group(1)}'] if m else []) + ['clang']:
        clang = shutil.which(name)
        if not clang:
            continue
        r = subprocess.run([clang, '-print-resource-dir'], capture_output=True, text=True)
        path = r.stdout.strip()
        if r.returncode == 0 and os.path.exists(os.path.join(path, 'include', 'stddef.h')):
            return path
    return None


def source_root(path: str) -> Optional[str]:
    """The tree the file belongs to, which need not be the one this script lives in."""
    try:
        r = subprocess.run(
            ['git', '-C', os.path.dirname(path), 'rev-parse', '--show-toplevel'],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def twin_header(path: str) -> Optional[str]:
    """The header a .c file is paired with."""
    header = path[:-2] + '.h'
    return header if os.path.exists(header) else None


def compile_commands(build_dir: str) -> dict[str, Command]:
    """file -> (directory, flags) from compile_commands.json, minus what only matters to a real compile."""
    with open(os.path.join(build_dir, 'compile_commands.json')) as f:
        entries = json.load(f)
    commands: dict[str, Command] = {}
    for e in entries:
        path = os.path.abspath(os.path.join(e['directory'], e['file']))
        argv = e['arguments'] if 'arguments' in e else shlex.split(e['command'])
        args, skip = [], False
        for a in argv[1:]:
            if skip:
                skip = False
            elif a in ('-o', '-MF', '-MQ', '-MT'):
                skip = True
            elif a in ('-c', '-MD', '-MMD') or a in DROPPED_FLAGS or a.startswith(('-W', '-fdiagnostics')):
                continue
            elif os.path.abspath(os.path.join(e['directory'], a)) != path:
                args.append(a)
        commands.setdefault(path, (e['directory'], args))
    return commands


WALKED: set[tuple[str, int]] = set()  # header definitions this worker has walked already


def in_tree(cursor: Any, files: dict[str, bytes], item: Item, mark: bool) -> Iterator[Any]:
    """The cursors defined in the file and in the in-tree headers it includes. A header definition is walked
    once per worker, the other files including it would only report the same findings again."""
    for c in cursor.get_children():
        if not c.location.file:
            continue
        f = os.path.abspath(c.location.file.name)
        if f != item.path:
            if not f.startswith(item.root + os.sep) or f.startswith(item.build_dir + os.sep):
                continue
            key = (f, c.extent.start.offset)
            if key in WALKED:
                continue
            if mark:
                WALKED.add(key)
        if f not in files:
            try:
                with open(f, 'rb') as fh:
                    files[f] = fh.read()  # libclang offsets are byte offsets
            except OSError:
                continue
        yield c


def check_file(item: Item) -> Result:
    directory, args = item.command
    os.chdir(directory)
    if item.resources:
        args = [f'-resource-dir={item.resources}'] + args
    try:
        tu = ci.Index.create().parse(item.path, args=args)
    except ci.TranslationUnitLoadError as e:
        return Result(item.path, [], [str(e)], [])
    errors = [
        f'{d.location.file}:{d.location.line}: {d.spelling}'
        for d in tu.diagnostics
        if d.severity >= ci.Diagnostic.Error
    ]
    files: dict[str, bytes] = {}
    findings: list[Finding] = []
    warnings: list[str] = []
    params_of: dict[str, list[str]] = {}
    functions: Optional[dict[str, Any]] = None
    seen: set[tuple[str, int]] = set()
    for top in in_tree(tu.cursor, files, item, mark=not errors):
        for call in top.walk_preorder():
            if call.kind != ci.CursorKind.CALL_EXPR:
                continue
            call_file, call_line, _, call_offset = file_loc(call.extent.start)
            if call_file is None:
                continue
            source = files.get(call_file)
            if source is None:
                continue
            only_lines = None
            if item.only is not None:
                only_lines = item.only.get(call_file)
                if only_lines is None or only_lines.isdisjoint(
                    range(call_line, file_loc(call.extent.end)[1] + 1)
                ):
                    continue
            callee = call.referenced
            if callee is None:
                continue
            if callee.kind == ci.CursorKind.FUNCTION_DECL:
                function = callee
                if not item.include_system and (
                    not function.location.file
                    or not os.path.abspath(function.location.file.name).startswith(item.root + os.sep)
                ):
                    continue
            elif callee.kind == ci.CursorKind.VAR_DECL and callee.spelling.startswith('sym_'):
                if functions is None:
                    functions = {
                        c.spelling: c
                        for c in tu.cursor.get_children()
                        if c.kind == ci.CursorKind.FUNCTION_DECL
                    }
                function = functions.get(callee.spelling[4:])
                if function is None:
                    continue
            else:
                continue
            via_sym = callee.kind == ci.CursorKind.VAR_DECL
            name = callee.spelling.encode()
            if not source.startswith(name, call_offset) or re.match(
                rb'\w', source[call_offset + len(name) : call_offset + len(name) + 1]
            ):
                continue  # the product of a macro body
            params = params_of.get(function.spelling)
            if params is None:
                params = params_of[function.spelling] = [
                    p.spelling for p in function.canonical.get_arguments()
                ]
            for i, arg in enumerate(call.get_arguments()):
                if i >= len(params):
                    break  # the rest is variadic
                if not params[i]:
                    continue
                if UNINFORMATIVE_RE.match(params[i]):
                    continue
                start_file, start_line, start_column, start_offset = file_loc(arg.extent.start)
                if start_file != call_file:
                    continue
                # The extent's end of an argument spelled inside a macro argument is the end of the macro
                # invocation, so lex the literal from where the argument starts instead.
                m = LITERAL_RE.match(source, start_offset)
                if not m:
                    continue
                literal = m.group(1)
                if only_lines is not None and start_line not in only_lines:
                    continue
                if (call_file, start_offset) in seen:
                    continue  # a macro such as ASSERT_EQ() evaluates its argument more than once
                seen.add((call_file, start_offset))
                m = COMMENT_RE.search(source, max(0, start_offset - 256), start_offset)
                comment = m.group(1).decode(errors='replace') if m else None
                if comment is not None:
                    # An underscore prefix dodges a clash and [] is how an array parameter is declared
                    named = comment.rstrip('= ').lstrip('_').removesuffix('[]')
                    if named == params[i].lstrip('_'):
                        continue
                    if via_sym and named not in {p.lstrip('_') for p in params}:
                        warnings.append(
                            f'{os.path.relpath(call_file, item.root)}:{start_line}:{start_column}: {callee.spelling}(): '
                            f"'{comment}' names no parameter of {function.spelling}(), "
                            f"its header calls argument {i + 1} '{params[i]}'"
                        )
                        continue
                findings.append(
                    Finding(
                        call_file,
                        start_line,
                        start_column,
                        start_offset,
                        callee.spelling,
                        params[i],
                        literal.decode(),
                        comment,
                    )
                )
    return Result(item.path, findings, errors, warnings)


def fix_files(findings: list[Finding]) -> None:
    by_file: dict[str, list[Finding]] = {}
    for finding in findings:
        by_file.setdefault(finding.file, []).append(finding)
    for path, items in by_file.items():
        with open(path, 'rb') as f:
            source = f.read()
        for finding in sorted(items, key=lambda x: x.offset, reverse=True):
            source = (
                source[: finding.offset] + f'/* {finding.param}= */ '.encode() + source[finding.offset :]
            )
        with open(path, 'wb') as f:
            f.write(source)


def changed_lines(root: str, rev: str, files: list[str]) -> dict[str, set[int]]:
    """Lines of files that differ from rev, from git's point of view."""

    def git(*args: str) -> str:
        return subprocess.run(
            ['git', '-c', 'core.quotePath=false', *args],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout

    lines: dict[str, set[int]] = {}
    for path in git('diff', '-z', '--name-only', rev, '--', *files).split('\0'):
        if not path:
            continue
        out = git('diff', '-U0', '--no-color', '--no-ext-diff', rev, '--', path)
        for m in re.finditer(r'^@@ -\S+ \+(\d+)(?:,(\d+))? @@', out, re.MULTILINE):
            start, count = int(m.group(1)), int(m.group(2)) if m.group(2) is not None else 1
            lines.setdefault(os.path.join(root, path), set()).update(range(start, start + count))
    return lines


def worker(item: Item) -> Result:
    setup_libclang(item.library)  # workers are separate processes, python 3.14 no longer forks them
    return check_file(item)


def default_jobs() -> int:
    try:
        return len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        return os.cpu_count() or 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0] if __doc__ else None)
    parser.add_argument(
        '-p', '--build-dir', default='build', help='build directory with compile_commands.json'
    )
    parser.add_argument(
        '--root',
        help='source tree whose functions are checked, the git toplevel of the first PATH by default',
    )
    parser.add_argument('-j', '--jobs', type=int, default=default_jobs(), help='parallel jobs')
    parser.add_argument('--diff', metavar='REV', help='only report lines that differ from this git revision')
    parser.add_argument('--fix', action='store_true', help='insert the missing comments in place')
    parser.add_argument(
        '--system', action='store_true', help='also check calls to functions declared outside the tree'
    )
    parser.add_argument(
        'paths', nargs='+', metavar='PATH', help='C files, or directories to search for them'
    )
    args = parser.parse_args()

    library = setup_libclang()
    build_dir = os.path.abspath(args.build_dir)
    files: list[str] = []
    for p in args.paths:
        p = os.path.abspath(p)
        files += sorted(glob.glob(os.path.join(p, '**', '*.c'), recursive=True)) if os.path.isdir(p) else [p]
    files = [
        f for f in files if not f.endswith('.bpf.c')
    ]  # BPF programs are not ours to style, and libclang cannot parse them
    files = list(dict.fromkeys(files))
    if not files:
        print('nothing to check', file=sys.stderr)
        return 2
    root = os.path.abspath(args.root) if args.root else source_root(files[0])
    if root is None:
        print(f'cannot tell which source tree {files[0]} belongs to, use --root', file=sys.stderr)
        return 2
    only = None
    if args.diff:
        headers = [h for h in map(twin_header, files) if h]
        only = changed_lines(root, args.diff, [os.path.abspath(p) for p in args.paths] + headers)
        # A header without a .c file of its own is checked from whichever file includes it, so keep them all
        if not any(f.endswith('.h') and f not in headers for f in only):
            files = [f for f in files if f in only or twin_header(f) in only]
    commands = compile_commands(build_dir)
    resources = resource_dir()
    n_errors = 0
    items = []
    for f in files:
        if f in commands:
            items.append(Item(f, root, build_dir, commands[f], args.system, only, resources, library))
        elif args.diff:
            print(
                f'{os.path.relpath(f, root)}: not in {build_dir}/compile_commands.json, skipping',
                file=sys.stderr,
            )
        else:
            print(
                f'{os.path.relpath(f, root)}: error: not in {build_dir}/compile_commands.json',
                file=sys.stderr,
            )
            n_errors += 1

    # A header is checked from every file that includes it, so collect first and act on each argument once.
    # A finding only counts as fixable when a translation unit that parsed cleanly produced it.
    findings: dict[tuple[str, int], tuple[Finding, bool]] = {}
    warnings: set[str] = set()
    if items:
        # A worker that dies, libclang crashing on a file say, ends the run instead of hanging it.
        try:
            with ProcessPoolExecutor(max(1, min(args.jobs, len(items)))) as pool:
                for result in pool.map(worker, items, chunksize=4):
                    for e in result.errors:
                        print(f'{os.path.relpath(result.path, root)}: error: {e}', file=sys.stderr)
                    n_errors += len(result.errors)
                    warnings.update(result.warnings)
                    for finding in result.findings:
                        key = (finding.file, finding.offset)
                        if key not in findings or (findings[key][1] and not result.errors):
                            findings[key] = (finding, bool(result.errors))
        except BrokenExecutor as e:
            print(f'error: {e}', file=sys.stderr)
            return 2

    for w in sorted(warnings):
        print(f'warning: {w}', file=sys.stderr)

    fixable = [x for x, dirty in findings.values() if x.comment is None and not dirty]
    if args.fix:
        fix_files(fixable)
        left = [x for x, dirty in findings.values() if x.comment is not None or dirty]
    else:
        left = [x for x, _ in findings.values()]
    for x in sorted(left):
        rel = os.path.relpath(x.file, root)
        if x.comment is not None:
            print(
                f"{rel}:{x.line}:{x.column}: {x.callee}(): argument '{x.param}' is commented as '{x.comment}'"
            )
        else:
            print(
                f"{rel}:{x.line}:{x.column}: {x.callee}(): argument '{x.param}' passed as bare {x.literal}, "
                f'comment it as /* {x.param}= */ {x.literal}'
            )

    print(
        (f'fixed {len(fixable)} argument(s), ' if args.fix else '')
        + f'{len(left)} argument(s) without a matching comment in {len(items)} file(s)'
        + (f', {n_errors} error(s)' if n_errors else ''),
        file=sys.stderr,
    )
    return 2 if n_errors else 1 if left else 0


if __name__ == '__main__':
    sys.exit(main())
