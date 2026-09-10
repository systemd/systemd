#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Report function arguments passed as a bare NULL, 0, false or true without a /* name= */ comment.

docs/CODING_STYLE.md asks for the argument name in a comment whenever NULL or another value meaning
"unset" is passed to a function. clang-tidy's bugprone-argument-comment cannot check that for C code:
it never sees NULL behind its cast, and asking it to comment integer literals flags every size and
mode as well. This walks the AST with libclang instead, takes the parameter names from the actual
prototypes and looks only at the literals the rule is about. A comment that names a different
parameter is reported too, those go stale when parameters are renamed. As for bugprone-argument-comment
only a /* name= */ comment names a parameter, case and surrounding underscores aside, a /* name */ that
lost its '=' is reported as well, and any other comment, in front of the literal or after it, leaves it
bare.

The names come from the first declaration the caller sees, usually the header, which is also the one
bugprone-argument-comment compares against. Parameters whose name says nothing, a single letter, argN
or a reserved __name copied from a libc declaration, are left alone. Calls to functions declared outside
the source tree and the build directory, e.g. libc, are skipped unless --system is given; calls through
the sym_* pointers of the dlopen() wrappers are ours and are checked against the function the pointer
was declared from, except that a comment naming none of its parameters is only warned about, library
headers rename parameters between versions. Calls produced by a macro body are skipped, the caller never
spelled the argument, while a call written inside a macro argument, assert_se(f(NULL)), is checked, and
so is a call through a macro that only renames the function, #define f f_shim. The in-tree headers a
file includes are checked from its translation unit, which covers their static inline functions, and a
file built more than once, for userspace and for the boot loader say, is checked with each set of flags.
With --diff REV only lines that differ from REV, and files git does not track, are reported, which is
what a review wants. Rust code is not checked.

Usage: tools/check-argument-comments.py [-p BUILDDIR] [--root DIR] [--diff REV] [--fix] [-j JOBS] [--system] PATH...

PATH is a C file or a directory to search for them, BPF programs are skipped. The compile flags come
from compile_commands.json in the build directory, the generated headers must exist ("meson compile -C
BUILDDIR gensources"); a file that is not in there, or does not parse, is an error and fails the run,
except that --diff skips files the build does not compile. --fix leaves the comments that name the
wrong parameter and files whose translation unit did not parse to a human. libclang is the one the
bindings find, else the one LIBCLANG_PATH names, the library or its directory, else the newest one
installed, and has to be 19 or newer. Exits with 1 when something is left to fix, 2 on errors and 77
when the libclang python bindings are missing.
"""

import argparse
import bisect
import glob
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
from collections.abc import Iterator
from concurrent.futures import BrokenExecutor, ProcessPoolExecutor
from ctypes import POINTER, byref, c_uint, c_void_p, cast
from typing import Any, NamedTuple, Optional

try:
    import clang.cindex as ci  # type: ignore
except ImportError:
    print('python3-clang is not installed', file=sys.stderr)
    sys.exit(77)

# The argument lexer steps over comments, string and character literals and preprocessor lines, which can
# hold anything, and splits on the commas outside of nested brackets.
TOKEN_RE = re.compile(
    rb'/\*.*?\*/|//(?:\\\n|[^\n])*|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|^[ \t]*#(?:\\\n|[^\n])*|[()\[\]{},]',
    re.DOTALL | re.MULTILINE,
)
# What may surround an argument, a newline on its own so that a preprocessor line can start after it
GAP_RE = re.compile(
    rb'^[ \t]*#(?:\\\n|[^\n])*|[ \t\r\f\v]+|\n|/\*.*?\*/|//(?:\\\n|[^\n])*', re.DOTALL | re.MULTILINE
)
LITERAL_RE = re.compile(rb'(?:NULL|0|false|true)(?![\w.])')
# [] is how an array parameter is declared
NAME_COMMENT_RE = re.compile(rb'/\*\s*(\w+)(?:\[\])?\s*(=)?\s*\*/')
# The callee, maybe in parentheses, up to the parenthesis that opens the arguments
CALL_RE = re.compile(rb'((?:\(\s*)*)([A-Za-z_]\w*)\s*((?:\)\s*)*)\(')
ALIAS_RE = re.compile(
    rb'[ \t]*#[ \t]*define[ \t]+(\w+)[ \t]+(\w+)[ \t]*(?:/\*[^\n]*?\*/[ \t]*)*(?://[^\n]*)?(?=\n|\Z)'
)
INCLUDE_RE = re.compile(rb'^[ \t]*#[ \t]*include[ \t]*[<"]([^>"\n]+)[>"]', re.MULTILINE)
HUNK_RE = re.compile(r'@@ -\S+ \+(\d+)(?:,(\d+))? @@')
UNINFORMATIVE_RE = re.compile(r'^(?:[a-z]|arg\d*|__.*)$', re.IGNORECASE)
# gcc-only flags of the EFI build that libclang rejects, .clang-tidy drops the same ones through RemovedArgs
DROPPED_FLAGS = frozenset({'-fwide-exec-charset=UCS2', '-maccumulate-outgoing-args'})
LAUNCHERS = frozenset({'ccache', 'sccache', 'distcc', 'icecc'})
# A cross compiler named after its target, which clang's tooling turns into --target= as well
CROSS_COMPILER_RE = re.compile(
    r'((?:aarch64|alpha|arc|arm|csky|hppa|i[3-6]86|ia64|loongarch|m68k|microblaze|mips|or1k|powerpc|ppc|riscv'
    r'|s390|sh|sparc|x86_64|xtensa)\w*(?:-\w+)+)-(?:gcc|cc|clang)(?:-[\d.]+)?$'
)

CALL_EXPR = ci.CursorKind.CALL_EXPR.value
DECL_REF_EXPR = ci.CursorKind.DECL_REF_EXPR.value

Command = tuple[str, tuple[str, ...]]
Edit = tuple[int, int, str]


class Finding(NamedTuple):
    file: str
    line: int
    column: int
    offset: int
    callee: str
    param: str
    literal: str
    comment: Optional[str]  # None for a bare literal, else the text of the comment in front of it
    fix: Optional[Edit]  # what adds or completes the comment, None when a human has to look


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
    only: Optional[dict[str, list[int]]]
    resources: Optional[str]


class GitError(Exception):
    pass


def newest_first(libraries: list[str]) -> list[str]:
    return sorted(
        libraries, key=lambda p: [int(x) if x.isdigit() else x for x in re.split(r'(\d+)', p)], reverse=True
    )


def setup_libclang(library_file: Optional[str] = None) -> Optional[str]:
    """Loads libclang and returns the library file the workers are to load, None when the bindings find it
    on their own. A worker loads the one the parent passes."""
    if ci.Config.loaded:
        return library_file  # a forked worker inherits the parent's library
    if library_file is not None:
        ci.Config.set_library_file(library_file)
        ci.conf.lib
        return library_file
    try:
        ci.conf.lib
        return None
    except ci.LibclangError as e:
        error = e
    candidates = []
    path = os.environ.get('LIBCLANG_PATH')
    if path:
        path = os.path.realpath(path)  # a worker resolves relative paths elsewhere
        if os.path.isdir(path):  # the bindgen convention
            candidates += newest_first(glob.glob(os.path.join(glob.escape(path), 'libclang*.so*')))
        else:
            candidates.append(path)
    candidates += newest_first(
        glob.glob('/usr/lib/llvm-*/lib/libclang-*.so.1')
        + glob.glob('/usr/lib*/libclang.so*')
        + glob.glob('/usr/lib/*/libclang*.so*')
    )
    for candidate in candidates:
        ci.Config.set_library_file(candidate)  # refused only once a library has loaded
        try:
            ci.conf.lib
            return candidate
        except ci.LibclangError:
            continue
    print(f'error: cannot load libclang: {error}', file=sys.stderr)
    sys.exit(2)


def setup_worker(library_file: Optional[str]) -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)  # Ctrl-C is for the parent, which cancels the run
    setup_libclang(library_file)


# The libclang 19 bindings only have the callbacks dictionary
VISIT = getattr(ci, 'cursor_visit_callback', None) or ci.callbacks['cursor_visit']


def _children(child: Any, parent: Any, out: list[Any]) -> int:
    out.append(child)
    return 1  # CXChildVisit_Continue


def _calls(child: Any, parent: Any, out: list[Any]) -> int:
    if child._kind_id == CALL_EXPR:
        out.append(child)
    return 2  # CXChildVisit_Recurse


def _decl_refs(child: Any, parent: Any, out: list[Any]) -> int:
    if child._kind_id == DECL_REF_EXPR:
        out.append(child)
    return 2


CHILDREN, CALLS, DECL_REFS = VISIT(_children), VISIT(_calls), VISIT(_decl_refs)


def visit(cursor: Any, callback: Any) -> list[Any]:
    """The cursors below cursor the callback picks. libclang does the walking, which is a lot cheaper than
    walk_preorder() calling into it for every node, and does not recurse in python."""
    out: list[Any] = []
    ci.conf.lib.clang_visitChildren(cursor, callback, out)
    for c in out:
        c._tu = cursor._tu  # keeps the translation unit alive, as the bindings do
    return out


LOCATIONS: dict[str, Any] = {}


def location_function(name: str) -> Any:
    """clang_getFileLocation() gives where a token was spelled if it came from a macro argument and the macro
    invocation if it came from a macro body, clang_getSpellingLocation() the #define for the latter and
    clang_getExpansionLocation() always the invocation. The bindings only wrap the expansion location."""
    fn = LOCATIONS.get(name)
    if fn is None:
        fn = LOCATIONS[name] = getattr(ci.conf.lib, name)
        fn.argtypes = [
            ci.SourceLocation,
            POINTER(ci.c_object_p),
            POINTER(c_uint),
            POINTER(c_uint),
            POINTER(c_uint),
        ]
        fn.restype = None
    return fn


SOURCES: dict[str, Optional[bytes]] = {}
LINES: dict[str, list[int]] = {}
REAL_PATHS: dict[tuple[str, str], str] = {}
ARGUMENTS: dict[tuple[str, int], dict[int, tuple[bytes, list[tuple[int, int]]]]] = {}


def read(path: str) -> Optional[bytes]:
    if path not in SOURCES:
        try:
            with open(path, 'rb') as f:
                SOURCES[path] = f.read()  # libclang offsets are byte offsets
        except OSError:
            SOURCES[path] = None
    return SOURCES[path]


def position(path: str, offset: int) -> tuple[int, int]:
    """(line, column) of a byte offset."""
    starts = LINES.get(path)
    if starts is None:
        starts = LINES[path] = [0] + [m.end() for m in re.finditer(rb'\n', read(path) or b'')]
    line = bisect.bisect_right(starts, offset)
    return line, offset - starts[line - 1] + 1


def touches(lines: list[int], first: int, last: int) -> bool:
    """Whether one of the sorted lines lies in [first, last]."""
    i = bisect.bisect_left(lines, first)
    return i < len(lines) and lines[i] <= last


def real_path(directory: str, name: str) -> str:
    key = (directory, name)
    path = REAL_PATHS.get(key)
    if path is None:
        path = REAL_PATHS[key] = os.path.realpath(os.path.join(directory, name))
    return path


def source_path(path: str) -> str:
    """A file to check, its directories resolved but not the file itself. test-bus-vtable-cc.cc is a
    symlink to test-bus-vtable.c and a C++ translation unit of its own."""
    path = os.path.abspath(path)
    return os.path.join(os.path.realpath(os.path.dirname(path)), os.path.basename(path))


def display(path: str, root: str) -> str:
    return os.path.relpath(path, root) if path.startswith(root + os.sep) else path


def split_arguments(source: bytes, open_paren: int) -> Optional[list[tuple[int, int]]]:
    """[start, end) of each argument of the call whose argument list opens at open_paren, None when the
    brackets do not match up."""
    ranges: list[tuple[int, int]] = []
    depth, start = 0, open_paren + 1
    for m in TOKEN_RE.finditer(source, open_paren):
        token = m.group()
        if len(token) != 1:
            continue  # a comment, a literal or a preprocessor line
        if token in b'([{':
            depth += 1
        elif token in b')]}':
            depth -= 1
            if depth == 0:
                ranges.append((start, m.start()))
                return ranges if token == b')' else None
        elif token == b',' and depth == 1:
            ranges.append((start, m.start()))
            start = m.end()
    return None


def skip_gap(source: bytes, pos: int, end: int, comments: Optional[list[tuple[int, int]]] = None) -> int:
    """Steps over whitespace, comments and preprocessor lines and collects the block comments."""
    while pos < end:
        m = GAP_RE.match(source, pos, end)
        if not m:
            break
        if comments is not None and source.startswith(b'/*', pos):
            comments.append((pos, m.end()))
        pos = m.end()
    return pos


def bare_literal(source: bytes, start: int, end: int) -> Optional[tuple[int, bytes, list[tuple[int, int]]]]:
    """(offset, literal, block comments in front) when the argument in [start, end) is nothing but NULL, 0,
    false or true, in parentheses or not."""
    comments: list[tuple[int, int]] = []
    pos = arg = skip_gap(source, start, end, comments)
    depth = 0
    while pos < end and source[pos] == ord('('):
        depth += 1
        pos = skip_gap(source, pos + 1, end)
    m = LITERAL_RE.match(source, pos, end)
    if not m:
        return None
    pos = skip_gap(source, m.end(), end)
    while depth and pos < end and source[pos] == ord(')'):
        depth -= 1
        pos = skip_gap(source, pos + 1, end)
    return (arg, m.group(), comments) if depth == 0 and pos == end else None


def literal_arguments(
    path: str, source: bytes, open_paren: int
) -> dict[int, tuple[bytes, list[tuple[int, int]]]]:
    """The arguments of a call that are written as a bare literal, by offset. Headers come up in every file
    that includes them, so this is kept for the whole run of a worker."""
    key = (path, open_paren)
    found = ARGUMENTS.get(key)
    if found is None:
        found = ARGUMENTS[key] = {}
        for start, end in split_arguments(source, open_paren) or []:
            literal = bare_literal(source, start, end)
            if literal:
                found[literal[0]] = (literal[1], literal[2])
    return found


def name_comment(
    source: bytes, comments: list[tuple[int, int]], arg: int
) -> Optional[tuple[str, bool, int, int]]:
    """The parameter the comments in front of an argument name: (name, whether the '=' is there, start and end
    of the comment). A /* name= */ counts anywhere after the previous argument, a /* name */ only right in
    front of this one and any other comment names nothing."""
    for start, end in reversed(comments):
        m = NAME_COMMENT_RE.fullmatch(source, start, end)
        if m and m.group(2):
            return m.group(1).decode(), True, start, end
    if comments:
        start, end = comments[-1]
        m = NAME_COMMENT_RE.fullmatch(source, start, end)
        if m and not source[end:arg].strip(b' \t'):
            return m.group(1).decode(), False, start, end
    return None


def same_name(a: str, b: str) -> bool:
    """The comparison of bugprone-argument-comment without StrictMode."""
    return a.strip('_').lower() == b.strip('_').lower()


class Checker:
    """The calls of one translation unit."""

    def __init__(self, item: Item, tu: Any):
        self.item = item
        self.tu = tu
        self.directory = item.command[0]
        self.root = item.root + os.sep
        self.build_dir = item.build_dir + os.sep
        self.main = os.path.realpath(item.path)
        self.paths: dict[Optional[int], str] = {}
        self.ours_by_name: dict[str, bool] = {}
        self.params_by_name: dict[str, list[str]] = {}
        self.syms: dict[str, Optional[Any]] = {}
        self.functions: Optional[dict[str, Any]] = None
        self.done: set[tuple[str, int, str]] = set()
        self.findings: list[Finding] = []
        self.warnings: list[str] = []

    def locate(self, function: str, location: Any) -> tuple[Optional[str], int]:
        """(real path, offset) of a location, location_function() tells which one."""
        f, offset = ci.c_object_p(), c_uint()
        location_function(function)(location, byref(f), None, None, byref(offset))
        if not f:
            return None, 0
        key = cast(f, c_void_p).value
        path = self.paths.get(key)
        if path is None:
            path = self.paths[key] = real_path(self.directory, ci.File(f).name)
        return path, offset.value

    def ours(self, path: str) -> bool:
        """Whether a file is the one checked or one of the in-tree headers it includes."""
        return path == self.main or (path.startswith(self.root) and not path.startswith(self.build_dir))

    def top_level(self) -> Iterator[Any]:
        """The definitions in the file and in the in-tree headers it includes. Under --diff only those that
        span a changed line."""
        only = self.item.only
        for c in visit(self.tu.cursor, CHILDREN):
            path, _ = self.locate('clang_getExpansionLocation', c.location)
            if path is None or not self.ours(path):
                continue
            if only is not None:
                lines = only.get(path)
                if not lines:
                    continue
                extent = c.extent
                start = self.locate('clang_getExpansionLocation', extent.start)[1]
                end = self.locate('clang_getExpansionLocation', extent.end)[1]
                if not touches(lines, position(path, start)[0], position(path, end)[0]):
                    continue
            yield c

    def declared_by_us(self, function: Any) -> bool:
        """Whether a function's first declaration is in the source tree, or in a header generated into the
        build directory, which need not be below it."""
        ours = self.ours_by_name.get(function.spelling)
        if ours is None:
            path, _ = self.locate('clang_getExpansionLocation', function.canonical.location)
            ours = path is not None and (path.startswith(self.root) or path.startswith(self.build_dir))
            self.ours_by_name[function.spelling] = ours
        return ours

    def parameters(self, function: Any) -> list[str]:
        params = self.params_by_name.get(function.spelling)
        if params is None:
            params = self.params_by_name[function.spelling] = [
                p.spelling for p in function.canonical.get_arguments()
            ]
        return params

    def sym_function(self, var: Any) -> Optional[Any]:
        """The function a sym_* pointer was declared from with typeof(&function), which also sees through a
        library renaming its functions with macros, pcre2 does."""
        if var.spelling not in self.syms:
            function = None
            for ref in visit(var, DECL_REFS):
                target = ref.referenced
                if target is not None and target.kind == ci.CursorKind.FUNCTION_DECL:
                    function = target
                    break
            if function is None:
                if self.functions is None:
                    self.functions = {
                        c.spelling: c
                        for c in visit(self.tu.cursor, CHILDREN)
                        if c.kind == ci.CursorKind.FUNCTION_DECL
                    }
                function = self.functions.get(var.spelling[4:])
            self.syms[var.spelling] = function
        return self.syms[var.spelling]

    def alias(self, path: Optional[str], offset: int, name: bytes, target: str) -> bool:
        """Whether the token at offset is the body of '#define name target', a macro that only renames."""
        source = read(path) if path else None
        if source is None:
            return False
        m = ALIAS_RE.match(source, source.rfind(b'\n', 0, offset) + 1)
        return (
            m is not None and m.group(1) == name and m.group(2) == target.encode() and m.start(2) == offset
        )

    def callee(self, call: Any, name: bytes) -> Optional[tuple[Any, bool]]:
        """The function a call names and whether it does so through a sym_* pointer. None for calls through
        an expression, calls a macro body produced and functions that are not ours."""
        children = visit(call, CHILDREN)
        expr = children[0] if children else None
        while expr is not None and expr.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
            inner = visit(expr, CHILDREN)
            expr = inner[0] if len(inner) == 1 else None
        if expr is None or expr._kind_id != DECL_REF_EXPR:
            return None  # the pointer some expression yields, lookup(x)(NULL) say
        decl = expr.referenced
        if decl is None:
            return None
        spelled = self.locate('clang_getSpellingLocation', expr.location)
        if spelled != self.locate('clang_getFileLocation', expr.location) and not self.alias(
            *spelled, name, decl.spelling
        ):
            return None  # the product of a macro body, the caller never spelled the arguments
        if decl.kind == ci.CursorKind.FUNCTION_DECL:
            if not self.item.include_system and not self.declared_by_us(decl):
                return None
            return decl, False
        if decl.kind == ci.CursorKind.VAR_DECL and decl.spelling.startswith('sym_'):
            function = self.sym_function(decl)
            return (function, True) if function is not None else None
        return None

    def check(self, call: Any) -> None:
        path, offset = self.locate('clang_getFileLocation', call.location)
        if path is None or not self.ours(path):
            return
        only_lines = None
        if self.item.only is not None:
            only_lines = self.item.only.get(path)
            if not only_lines:
                return
        source = read(path)
        if source is None:
            return
        m = CALL_RE.match(source, offset)
        if not m or m.group(1).count(b'(') != m.group(3).count(b')'):
            return  # the call is not spelled out here, a macro body produced it
        open_paren = m.end() - 1
        literals = literal_arguments(path, source, open_paren)
        if not literals:
            return
        callee = self.callee(call, m.group(2))
        if callee is None:
            return
        function, via_sym = callee
        key = (path, open_paren, function.spelling)
        if key in self.done:
            return  # a macro such as ASSERT_EQ() has its argument more than once
        self.done.add(key)
        name = m.group(2).decode()
        params = self.parameters(function)
        for i, arg in enumerate(call.get_arguments()):
            if i >= len(params):
                break  # the rest is variadic
            param = params[i]
            if arg is None or not param or UNINFORMATIVE_RE.match(param):
                continue
            arg_path, arg_offset = self.locate('clang_getFileLocation', arg.location)
            found = literals.get(arg_offset) if arg_path == path else None
            if found is None:
                continue  # not written as a bare literal, or not at this position of the call
            line, column = position(path, arg_offset)
            if only_lines is not None and not touches(only_lines, line, line):
                continue
            literal, comments = found
            named = name_comment(source, comments, arg_offset)
            comment: Optional[str] = None
            fix: Optional[Edit] = None
            if named is None:
                fix = (arg_offset, arg_offset, f'/* {param}= */ ')
            else:
                text, has_equals, start, end = named
                if has_equals and same_name(text, param):
                    continue
                comment = source[start + 2 : end - 2].strip().decode(errors='replace')
                if via_sym and not any(p and same_name(text, p) for p in params):
                    self.warnings.append(
                        f'{display(path, self.item.root)}:{line}:{column}: {name}(): '
                        f"'{comment}' names no parameter of {function.spelling}(), "
                        f"its header calls argument {i + 1} '{param}'"
                    )
                    continue
                if not has_equals and same_name(text, param):
                    fix = (start, end, f'/* {param}= */')
            self.findings.append(
                Finding(path, line, column, arg_offset, name, param, literal.decode(), comment, fix)
            )


def describe(diagnostic: Any, root: str) -> str:
    location = diagnostic.location
    if not location.file:
        return str(diagnostic.spelling)
    return f'{display(os.path.realpath(location.file.name), root)}:{location.line}: {diagnostic.spelling}'


def check_file(item: Item) -> Result:
    directory, flags = item.command
    os.chdir(directory)
    args = ([f'-resource-dir={item.resources}'] if item.resources else []) + list(flags)
    try:
        tu = ci.Index.create().parse(item.path, args=args)
    except ci.TranslationUnitLoadError as e:
        return Result(item.path, [], [str(e)], [])
    errors = [describe(d, item.root) for d in tu.diagnostics if d.severity >= ci.Diagnostic.Error]
    checker = Checker(item, tu)
    for top in checker.top_level():
        for call in visit(top, CALLS):
            checker.check(call)
    return Result(item.path, checker.findings, errors, checker.warnings)


def worker(item: Item) -> Result:
    try:
        return check_file(item)
    except Exception as e:  # a compile directory that is gone, say, fails this file and not the run
        return Result(item.path, [], [f'{type(e).__name__}: {e}'], [])


def expand_response_files(argv: list[str], directory: str, depth: int = 0) -> list[str]:
    out: list[str] = []
    for a in argv:
        if a.startswith('@') and depth < 8:
            try:
                with open(os.path.join(directory, a[1:])) as f:
                    out += expand_response_files(shlex.split(f.read()), directory, depth + 1)
                continue
            except OSError:
                pass
        out.append(a)
    return out


def compile_flags(argv: list[str], directory: str, path: str) -> tuple[str, ...]:
    """The flags of a compile command minus what only matters to a real compile, with the target a cross
    compiler implies made explicit, as clang's tooling does."""
    while len(argv) > 1 and os.path.basename(argv[0]) in LAUNCHERS:
        argv = argv[1:]
    argv = expand_response_files(argv, directory)
    flags: list[str] = []
    skip = False
    for a in argv[1:]:
        if skip:
            skip = False
        elif a in ('-o', '-MF', '-MQ', '-MT'):
            skip = True
        elif a in ('-c', '-MD', '-MMD') or a in DROPPED_FLAGS or a.startswith('-fdiagnostics'):
            continue
        elif a.startswith('-Wp,'):
            if not any(p.startswith('-M') for p in a[4:].split(',')):
                flags.append(a)  # -D, -U and -include for the preprocessor, but no dependency files
        elif a.startswith('-W'):
            continue
        elif (
            a.startswith('-')
            or os.path.basename(a) != os.path.basename(path)
            or source_path(os.path.join(directory, a)) != path
        ):
            flags.append(a)
    m = CROSS_COMPILER_RE.match(os.path.basename(argv[0]))
    if m and not any(f.startswith('--target=') or f == '-target' for f in flags):
        flags.insert(0, f'--target={m.group(1)}')
    return tuple(flags)


def compile_commands(build_dir: str, wanted: set[str]) -> dict[str, list[Command]]:
    """file -> each distinct (directory, flags) it is compiled with, for the files asked for."""
    with open(os.path.join(build_dir, 'compile_commands.json')) as f:
        entries = json.load(f)
    commands: dict[str, list[Command]] = {}
    for e in entries:
        path = source_path(os.path.join(e['directory'], e['file']))
        if path not in wanted:
            continue
        argv = e['arguments'] if 'arguments' in e else shlex.split(e['command'])
        command = (e['directory'], compile_flags(argv, e['directory'], path))
        if command not in commands.setdefault(path, []):
            commands[path].append(command)
    return commands


def libclang_major() -> Optional[int]:
    try:
        fn = ci.conf.lib.clang_getClangVersion  # the bindings do not declare its return type
        fn.restype = ci._CXString
        version = str(ci._CXString.from_result(fn()))
    except AttributeError:
        return None
    m = re.search(r'clang version (\d+)', version)
    return int(m.group(1)) if m else None


def resource_dir() -> Optional[str]:
    """Where clang's builtin headers, stddef.h and friends, live. libclang derives that from its own location,
    which goes wrong when the library does not sit next to them, so ask the clang binary of the same major
    version instead. An unversioned clang only counts when it is that version, the headers of another one
    need not parse with this libclang."""
    major = libclang_major()
    if major is None:
        return None
    for name in (f'clang-{major}', 'clang'):
        clang = shutil.which(name)
        if not clang:
            continue
        r = subprocess.run([clang, '-print-resource-dir'], capture_output=True, text=True)
        path = r.stdout.strip()
        if (
            r.returncode == 0
            and os.path.basename(path).split('.')[0] == str(major)
            and os.path.exists(os.path.join(path, 'include', 'stddef.h'))
        ):
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
    return os.path.realpath(r.stdout.strip()) if r.returncode == 0 else None


def twin_header(path: str) -> Optional[str]:
    """The header a .c file is paired with."""
    header = path[:-2] + '.h'
    return header if os.path.exists(header) else None


def includes(path: str, header: str) -> bool:
    name = os.path.basename(header).encode()
    return any(os.path.basename(m.group(1)) == name for m in INCLUDE_RE.finditer(read(path) or b''))


def git(cwd: str, *args: str) -> str:
    try:
        r = subprocess.run(
            ['git', '-c', 'core.quotePath=false', *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            errors='surrogateescape',
        )
    except OSError as e:
        raise GitError(f'git: {e}') from e
    if r.returncode != 0:
        raise GitError(r.stderr.strip() or f'git {args[0]} failed')
    return r.stdout


def unquote(name: str) -> str:
    """Undoes git's C-style quoting of unusual file names."""
    if not name.startswith('"'):
        return name
    escapes = {'a': 7, 'b': 8, 't': 9, 'n': 10, 'v': 11, 'f': 12, 'r': 13}
    raw, out, i = name[1:-1].encode(errors='surrogateescape'), bytearray(), 0
    while i < len(raw):
        if raw[i] == ord('\\') and i + 1 < len(raw):
            c = chr(raw[i + 1])
            if c in '01234567':
                out.append(int(raw[i + 1 : i + 4], 8))
                i += 4
            else:
                out.append(escapes.get(c, raw[i + 1]))
                i += 2
        else:
            out.append(raw[i])
            i += 1
    return out.decode(errors='surrogateescape')


def changed_lines(root: str, rev: str, paths: list[str]) -> dict[str, list[int]]:
    """The lines of the files below paths that differ from rev, all of them for files git does not track.
    One diff over all of them pairs up renames, and git's settings must not widen the hunks."""
    if rev.startswith('-'):
        raise GitError(f'{rev}: not a revision')
    try:
        git(root, 'rev-parse', '--verify', rev + '^{commit}')
    except GitError as e:
        raise GitError(f'{rev}: {e}') from e
    top = os.path.realpath(git(root, 'rev-parse', '--show-toplevel').strip())
    diff = git(
        root,
        'diff',
        '-U0',
        '--inter-hunk-context=0',
        '--no-color',
        '--no-ext-diff',
        '--no-textconv',
        '--no-relative',
        '--src-prefix=a/',
        '--dst-prefix=b/',
        '-M',
        rev,
        '--',
        *paths,
    )
    lines: dict[str, set[int]] = {}
    current: Optional[set[int]] = None
    header = False
    for line in diff.split('\n'):
        if line.startswith('diff '):
            header, current = True, None
        elif header and line.startswith('+++ '):
            name = unquote(line[4:])
            current = None
            if name.startswith('b/'):
                current = lines.setdefault(os.path.realpath(os.path.join(top, name[2:])), set())
        elif line.startswith('@@'):
            header = False
            m = HUNK_RE.match(line)
            if m and current is not None:
                start = int(m.group(1))
                current.update(range(start, start + (int(m.group(2)) if m.group(2) is not None else 1)))
    untracked = git(root, 'ls-files', '-z', '--full-name', '--others', '--exclude-standard', '--', *paths)
    for name in untracked.split('\0'):
        if name:
            path = os.path.realpath(os.path.join(top, name))
            lines[path] = set(range(1, (read(path) or b'').count(b'\n') + 2))
    return {path: sorted(numbers) for path, numbers in lines.items() if numbers}


def diff_selection(
    files: list[str], only: dict[str, list[int]], commands: dict[str, list[Command]]
) -> list[str]:
    """The files --diff parses: the changed ones and those paired with a changed header. A changed header
    that no compiled file of its own includes is checked from whichever file includes it, so then all."""
    paired = set()
    for f in files:
        header = twin_header(f)
        if header and f in commands and includes(f, header):
            paired.add(os.path.realpath(header))
    if any(path.endswith('.h') and path not in paired for path in only):
        return files
    return [f for f in files if os.path.realpath(f) in only or os.path.realpath(twin_header(f) or f) in only]


def fix_files(edits: list[tuple[str, Edit]]) -> None:
    by_file: dict[str, list[Edit]] = {}
    for path, edit in edits:
        by_file.setdefault(path, []).append(edit)
    for path, items in by_file.items():
        with open(path, 'rb') as f:
            source = f.read()
        for start, end, text in sorted(items, reverse=True):
            source = source[:start] + text.encode() + source[end:]
        with open(path, 'wb') as f:
            f.write(source)


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
    if args.diff == '':
        print('error: --diff needs a revision', file=sys.stderr)
        return 2

    library = setup_libclang()
    major = libclang_major()
    if major is not None and major < 19:
        # Before 19 clang_getSpellingLocation() returns the file location, callee() needs the real one
        print(f'error: libclang {major} is too old, the checker needs 19 or newer', file=sys.stderr)
        return 2
    build_dir = os.path.realpath(args.build_dir)
    files: list[str] = []
    for p in args.paths:
        real = os.path.realpath(p)
        if os.path.isdir(real):
            found = glob.glob(os.path.join(glob.escape(real), '**', '*.c'), recursive=True)
            files += [source_path(f) for f in sorted(found)]
        elif os.path.isfile(real) and p.endswith('.c'):
            files.append(source_path(p))
        else:
            problem = 'not a .c file or a directory' if os.path.exists(real) else 'no such file or directory'
            print(f'{p}: error: {problem}', file=sys.stderr)
            return 2
    files = list(
        dict.fromkeys(f for f in files if not f.endswith('.bpf.c'))
    )  # BPF programs are not ours to style, and libclang cannot parse them
    if not files:
        print('nothing to check', file=sys.stderr)
        return 2
    root = os.path.realpath(args.root) if args.root else source_root(files[0])
    if root is None:
        print(f'cannot tell which source tree {files[0]} belongs to, use --root', file=sys.stderr)
        return 2
    try:
        commands = compile_commands(build_dir, set(files))
    except (OSError, ValueError, KeyError) as e:
        print(f'error: cannot read {build_dir}/compile_commands.json: {e!r}', file=sys.stderr)
        return 2
    only = None
    if args.diff is not None:
        dirs = [os.path.realpath(p) for p in args.paths if os.path.isdir(p)]
        twins = [h for h in map(twin_header, files) if h and not any(h.startswith(d + os.sep) for d in dirs)]
        try:
            only = changed_lines(root, args.diff, [os.path.realpath(p) for p in args.paths] + twins)
        except GitError as e:
            print(f'error: {e}', file=sys.stderr)
            return 2
        files = diff_selection(files, only, commands)
    resources = resource_dir()
    n_errors = 0
    checked = []
    items = []
    for f in files:
        if f in commands:
            checked.append(f)
            items += [Item(f, root, build_dir, c, args.system, only, resources) for c in commands[f]]
        elif args.diff is not None:
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
        items.sort(key=lambda item: -os.path.getsize(item.path))  # the big ones first keep every worker busy
        broken: Optional[BaseException] = None
        try:
            with ProcessPoolExecutor(
                max(1, min(args.jobs, len(items))), initializer=setup_worker, initargs=(library,)
            ) as pool:
                try:
                    for future in [pool.submit(worker, item) for item in items]:
                        try:
                            result = future.result()
                        except BrokenExecutor as e:
                            broken = e
                            continue
                        for error in result.errors:
                            print(f'{os.path.relpath(result.path, root)}: error: {error}', file=sys.stderr)
                        n_errors += len(result.errors)
                        warnings.update(result.warnings)
                        for finding in result.findings:
                            key = (finding.file, finding.offset)
                            if key not in findings or (findings[key][1] and not result.errors):
                                findings[key] = (finding, bool(result.errors))
                except KeyboardInterrupt:
                    # Wait here, the with's shutdown resets cancel_futures before the executor acts on it
                    pool.shutdown(cancel_futures=True)
                    raise
        except BrokenExecutor as e:
            broken = e
        if broken is not None:
            # A worker that dies, libclang crashing on a file say, ends the run instead of hanging it.
            print(f'error: {broken}', file=sys.stderr)
            n_errors += 1

    for w in sorted(warnings):
        print(f'warning: {w}', file=sys.stderr)

    fixable = [x for x, dirty in findings.values() if x.fix is not None and not dirty]
    if args.fix:
        fix_files([(x.file, x.fix) for x in fixable if x.fix is not None])
        left = [x for x, dirty in findings.values() if x.fix is None or dirty]
    else:
        left = [x for x, _ in findings.values()]
    for x in sorted(left, key=lambda x: (x.file, x.offset)):
        prefix = f"{os.path.relpath(x.file, root)}:{x.line}:{x.column}: {x.callee}(): argument '{x.param}'"
        if x.comment is None:
            print(f'{prefix} passed as bare {x.literal}, comment it as /* {x.param}= */ {x.literal}')
        elif x.fix is not None:
            print(f"{prefix} is commented as '{x.comment}', comment it as /* {x.param}= */ {x.literal}")
        else:
            print(f"{prefix} is commented as '{x.comment}'")

    print(
        (f'fixed {len(fixable)} argument(s), ' if args.fix else '')
        + f'{len(left)} argument(s) without a matching comment in {len(checked)} file(s)'
        + (f', {n_errors} error(s)' if n_errors else ''),
        file=sys.stderr,
    )
    return 2 if n_errors else 1 if left else 0


if __name__ == '__main__':
    sys.exit(main())
