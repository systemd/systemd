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
except that an existing comment is taken as it is, library headers rename parameters between versions.
Calls produced by a macro body are skipped, the caller never spelled the argument, while a call written
inside a macro argument, assert_se(f(NULL)), is checked. A header next to a .c file of the same name is
checked from that file's translation unit, which covers its static inline functions. With --diff REV
only lines that differ from REV are reported, which is what a review wants.

Usage: tools/check-argument-comments.py [-p BUILDDIR] [--diff REV] [--fix] [-j JOBS] [--system] PATH...

PATH is a C file or a directory to search for them, BPF programs are skipped. The compile flags come
from compile_commands.json in the build directory; a file that is not in there, or does not parse, is
an error and fails the run, except that --diff skips files the build does not compile. Exits with 77
when the libclang python bindings are missing.
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
from concurrent.futures import BrokenExecutor, ProcessPoolExecutor
from ctypes import POINTER, byref, c_uint

try:
    import clang.cindex as ci
except ImportError:
    print('python3-clang is not installed', file=sys.stderr)
    sys.exit(77)

LITERAL_RE = re.compile(rb'(NULL|0|false|true)\s*(?=[,)])')
COMMENT_RE = re.compile(rb'/\*\s*((?:(?!\*/|/\*)[\s\S])*?)\s*\*/\s*$')  # a * inside is fine, /* is not
UNINFORMATIVE_RE = re.compile(r'^(?:[a-z]|arg\d*|__.*)$')
# gcc-only flags of the EFI build that libclang rejects, .clang-tidy drops the same ones through RemovedArgs
DROPPED_FLAGS = frozenset({'-fwide-exec-charset=UCS2', '-maccumulate-outgoing-args'})


def setup_libclang(library_file=None):
    """Returns the library file the workers are to use, None when the bindings find it on their own."""
    if library_file:
        ci.Config.set_library_file(library_file)
        return library_file
    if ci.Config.loaded:
        return ci.Config.library_file
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


def file_loc(loc):
    """(file, line, column, offset) of where a token was spelled if it came from a macro argument, or of
    the macro invocation if it came from a macro body. The bindings only wrap the expansion location, which
    puts every token of a macro argument on the macro name."""
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


def resource_dir():
    """Where clang's builtin headers, stddef.h and friends, live. libclang derives that from its own location,
    which goes wrong when the library does not sit next to them, so ask the clang binary of the same major
    version instead."""
    fn = ci.conf.lib.clang_getClangVersion  # the bindings do not declare its return type
    fn.restype = ci._CXString
    m = re.search(r'clang version (\d+)', ci._CXString.from_result(fn()))
    for name in ([f'clang-{m.group(1)}'] if m else []) + ['clang']:
        clang = shutil.which(name)
        if not clang:
            continue
        r = subprocess.run([clang, '-print-resource-dir'], capture_output=True, text=True)
        path = r.stdout.strip()
        if r.returncode == 0 and os.path.exists(os.path.join(path, 'include', 'stddef.h')):
            return path
    return None


def source_root(path):
    """The tree the file belongs to, which need not be the one this script lives in."""
    r = subprocess.run(
        ['git', '-C', os.path.dirname(path), 'rev-parse', '--show-toplevel'], capture_output=True, text=True
    )
    return r.stdout.strip() if r.returncode == 0 else os.getcwd()


def twin_header(path):
    """The header a .c file is paired with, checked from the same translation unit."""
    header = path[:-2] + '.h'
    return header if os.path.exists(header) else None


def compile_commands(build_dir):
    """file -> (directory, flags) from compile_commands.json, minus what only matters to a real compile."""
    with open(os.path.join(build_dir, 'compile_commands.json')) as f:
        entries = json.load(f)
    commands = {}
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


def in_files(cursor, files):
    """The cursors defined in the files of interest, other header declarations are many and of no interest."""
    for c in cursor.get_children():
        if c.location.file and os.path.abspath(c.location.file.name) in files:
            yield c


def check_file(path, root, command, include_system, only, resources):
    """Returns (findings, errors); a finding is (file, line, column, offset, callee, param, literal, comment)."""
    directory, args = command
    os.chdir(directory)
    if resources:
        args = [f'-resource-dir={resources}'] + args
    try:
        tu = ci.Index.create().parse(path, args=args)
    except ci.TranslationUnitLoadError as e:
        return [], [str(e)]
    errors = [
        f'{d.location.file}:{d.location.line}: {d.spelling}'
        for d in tu.diagnostics
        if d.severity >= ci.Diagnostic.Error
    ]
    files = {}
    for f in (path, twin_header(path)):
        if f and (only is None or f in only):
            try:
                with open(f, 'rb') as fh:
                    files[f] = fh.read()  # libclang offsets are byte offsets
            except OSError as e:
                return [], [str(e)]

    findings, params_of, functions, seen = [], {}, None, set()
    for top in in_files(tu.cursor, files):
        for call in top.walk_preorder():
            if call.kind != ci.CursorKind.CALL_EXPR:
                continue
            call_file, call_line, _, call_offset = file_loc(call.extent.start)
            source = files.get(call_file)
            if source is None:
                continue
            only_lines = only[call_file] if only is not None else None
            if only_lines is not None and only_lines.isdisjoint(
                range(call_line, file_loc(call.extent.end)[1] + 1)
            ):
                continue
            callee = call.referenced
            if callee is None:
                continue
            if callee.kind == ci.CursorKind.FUNCTION_DECL:
                function = callee
                if not include_system and (
                    not function.location.file
                    or not os.path.abspath(function.location.file.name).startswith(root + os.sep)
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
                # An underscore prefix dodges a clash and [] is how an array parameter is declared, neither is the name
                if comment is not None and (
                    via_sym or comment.rstrip('= ').lstrip('_').removesuffix('[]') == params[i].lstrip('_')
                ):
                    continue
                findings.append(
                    (
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
    return findings, errors


def fix_files(findings):
    by_file = {}
    for finding in findings:
        if finding[7] is None:  # a comment that says something else needs a human
            by_file.setdefault(finding[0], []).append(finding)
    for path, items in by_file.items():
        with open(path, 'rb') as f:
            source = f.read()
        for _, _, _, offset, _, param, _, _ in sorted(items, key=lambda x: x[3], reverse=True):
            source = source[:offset] + f'/* {param}= */ '.encode() + source[offset:]
        with open(path, 'wb') as f:
            f.write(source)


def changed_lines(root, rev, files):
    """Lines of files that differ from rev, from git's point of view."""
    out = subprocess.run(
        [
            'git',
            '-c',
            'core.quotePath=false',
            'diff',
            '-U0',
            '--no-color',
            '--no-ext-diff',
            '--src-prefix=a/',
            '--dst-prefix=b/',
            rev,
            '--',
            *files,
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    lines, path = {}, None
    for line in out.splitlines():
        m = re.match(r'diff --git a/(.*) b/(.*)$', line)
        if m:
            path = os.path.join(root, m.group(2))
            continue
        if not line.startswith('@@'):
            continue  # a changed line starts with + or -, it cannot be mistaken for a header
        m = re.match(r'@@ -\S+ \+(\d+)(?:,(\d+))? @@', line)
        if not m or path is None:
            sys.exit(f'cannot parse git diff output: {line}')
        start, count = int(m.group(1)), int(m.group(2)) if m.group(2) else 1
        lines.setdefault(path, set()).update(range(start, start + count))
    return lines


def worker(item):
    path, root, command, include_system, only, fix, resources, library = item
    setup_libclang(library)  # workers are separate processes, python 3.14 no longer forks them
    findings, errors = check_file(path, root, command, include_system, only, resources)
    if fix and findings:
        fix_files(findings)
    return path, findings, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument(
        '-p', '--build-dir', default='build', help='build directory with compile_commands.json'
    )
    parser.add_argument('-j', '--jobs', type=int, default=os.cpu_count() or 1, help='parallel jobs')
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
    files = []
    for p in args.paths:
        p = os.path.abspath(p)
        files += sorted(glob.glob(os.path.join(p, '**', '*.c'), recursive=True)) if os.path.isdir(p) else [p]
    files = [
        f for f in files if not f.endswith('.bpf.c')
    ]  # BPF programs are not ours to style, and libclang cannot parse them
    files = list(dict.fromkeys(files))
    if not files:
        sys.exit('nothing to check')
    root = source_root(files[0])
    only = None
    if args.diff:
        headers = [h for h in map(twin_header, files) if h]
        only = changed_lines(root, args.diff, files + headers)
        files = [f for f in files if f in only or twin_header(f) in only]
    commands = compile_commands(build_dir)
    resources = resource_dir()
    n_findings, n_errors = 0, 0
    items = []
    for f in files:
        if f in commands:
            items.append((f, root, commands[f], args.system, only, args.fix, resources, library))
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

    if items:
        # A worker that dies, libclang crashing on a file say, ends the run instead of hanging it.
        try:
            with ProcessPoolExecutor(max(1, min(args.jobs, len(items)))) as pool:
                for path, findings, errors in pool.map(worker, items):
                    for file, line, column, _, callee, param, literal, comment in sorted(findings):
                        rel = os.path.relpath(file, root)
                        if comment is not None:
                            print(
                                f"{rel}:{line}:{column}: {callee}(): argument '{param}' is commented as '{comment}'"
                            )
                        else:
                            print(
                                f"{rel}:{line}:{column}: {callee}(): argument '{param}' passed as bare {literal}, "
                                f'comment it as /* {param}= */ {literal}'
                            )
                    for e in errors:
                        print(f'{os.path.relpath(path, root)}: error: {e}', file=sys.stderr)
                    n_findings += len(findings)
                    n_errors += len(errors)
        except BrokenExecutor as e:
            print(f'error: {e}', file=sys.stderr)
            return 2

    print(
        f'{n_findings} argument(s) without a matching comment in {len(items)} file(s)'
        + (f', {n_errors} parse error(s)' if n_errors else ''),
        file=sys.stderr,
    )
    return 1 if n_findings else 2 if n_errors else 0


if __name__ == '__main__':
    sys.exit(main())
