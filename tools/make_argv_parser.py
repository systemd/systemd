#!/usr/bin/env python3
# pylint: disable=line-too-long,invalid-name,global-statement,redefined-outer-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
# SPDX-License-Identifier: LGPL-2.1-or-later

# Syntax of .args input files:
#
# The file is a sequence of 'option' statements, listing the short and long option names.
# Names may be followed by '=' to specify that the option takes parameters.
# The use of '=' must be consistent, i.e. all are none names must use it.
# At most of the the names with '=' may be followed by the argument name.
#
# After the 'option' line, one or more 'help' lines specify the string for --help.
# This string will be wrapped to fit in the available number of columns,
# specified b TARGET_LINE_WIDTH.
#
# A lone 'scope' specifies that the block should be wrapped in a scope.
# This is done automatically if any variables are defined with _cleanup_.
#
# After the 'option' line, a 'group' line may be used to specify
# option grouping. This string will be appended to the variable for
# the generated option help.
#
# This is followed by the indented body in C,
# passed through literally to the generated C file.
# A 'break' statement at the end will be added automatically, unless
# the block ends with an unindented return or _fallthrough_.
#
# 'skip' can be used in 'help' to skip the option in --help output,
# and in the body to skip the option from being parsed.
#
# A 'global' block with general setting can be specified.
# The following settings are understood:
#   help_key_width NN — how many columns should be used for the '-o --option'
#                       part of the --help string.
#   optstring_prefix c — add 'c' before the option string. Useful with '-' or '+'.
#   parser_option x y — add ', x y' into the signature of parse_argv_generated().
#
# An 'intro' and an 'outro' block can be used to specify additional lines to
# place near the beginning and end of the generated function.
#
# Lines with # at the beginning of the line are discarded.
# Normal C comments with /* */ or // are propagated.

import sys
import textwrap
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Generator

@dataclass
class Globals:
    target_line_width: int = 80
    target_help_key_width: int = 25

    help_key_width: int|None = None
    optstring_prefix: str = ''
    parser_options: list[str] = field(default_factory=list)
    intro: list[str] = field(default_factory=list)
    outro: list[str] = field(default_factory=list)

    def set(self, name: str, value: str) -> None:
        # A consumer for the 'global foo bar' settings.
        if name == 'help_key_width':
            self.help_key_width = int(value)
        elif name == 'optstring_prefix':
            self.optstring_prefix = value
        elif name == 'parser_option':
            self.parser_options += [value]
        else:
            raise ValueError(f'Uknown global setting {name!r}')


class ArgType(Enum):
    no_argument       = 0
    optional_argument = 1
    required_argument = 2
    positional        = 3


@dataclass
class Option:
    names: list[str]
    argtype: ArgType
    metavar: str | None
    group: str | None
    help: str
    body: list[str]
    scope: bool
    skip_code: bool = False

    def short_name(self) -> str | None:
        "First single letter name, if any"
        for name in self.names:
            if name.startswith('-') and not name.startswith('--'):
                return name[1:]
        return None

    def long_names(self) -> Generator[str]:
        "Long option names, if any"
        for name in self.names:
            if name.startswith('--'):
                # Single-letter "long name" doesn't make sense.
                # Currently the shortest option is --id.
                assert len(name) >= 4
                yield name[2:]

    def long_name(self) -> str | None:
        return next(self.long_names(), None)

    def enum_name(self) -> str:
        if self.argtype == ArgType.positional:
            # getopt_long() returns 1 if "-" was the first character of the
            # option string, and a non-option argument was discovered.
            return '1'

        if sn := self.short_name():
            return f"'{sn}'"
        ln = self.long_name()
        assert ln
        return 'ARG_' + ln.replace('-', '_').upper()

    def help_key(self) -> str | None:
        if self.help == 'skip':
            return None

        sn = self.short_name()
        lhs = ['-', sn] if sn else ['  ']
        rhs = []

        if ln := self.long_name():
            # Here the argument is specified with '='
            if self.argtype == ArgType.required_argument:
                rhs = [' --', ln, '=', self.metavar or '']
            elif self.argtype == ArgType.optional_argument:
                rhs = [' --', ln, '[=', self.metavar or '', ']']
            else:
                rhs = [' --', ln]
        elif self.metavar:
            # Here the argument is specified without '='
            assert sn
            if self.argtype == ArgType.required_argument:
                lhs += [' ', self.metavar]
            elif self.argtype == ArgType.optional_argument:
                lhs = [' [', self.metavar, ']']

        return ''.join((*lhs, *rhs))

    def _insert_defaults(self) -> None:
        if self.argtype == ArgType.positional:
            self.help = 'skip'

        match self.long_name():
            case 'help':
                help = 'Show this help'
                body = ['return help();']
            case 'version':
                help = 'Show package version'
                body = ['return version();']
            case 'no-pager':
                help = 'Do not start the pager'
                body = ['arg_pager_flags |= PAGER_DISABLE;']
            case _:
                help = 'XXXXXXXXXX'
                body = ['#warning TBD']

        if not self.help:
            self.help = help
        if not self.body:
            self.body = body

    def __post_init__(self) -> None:
        # trim empty lines at end of body
        while self.body and not self.body[-1]:
            del self.body[-1]

        self._insert_defaults()

        if self.body[0].strip() == 'skip':
            self.skip_code = True
        elif not self.body[-1].startswith((
                'return ',
                '_fallthrough_',
        )):
            self.body += ['break;']


def generate_lines(options: list[Option], globals: Globals) -> Generator[str]:
    # Figure out the optstring and other variables
    opt_names = []
    opt_args = []
    opt_enums = []
    opt_comments = []
    optstring = globals.optstring_prefix

    for option in options:
        if option.skip_code:
            continue

        for pos, ln in enumerate(option.long_names()):
            opt_names += [ln]
            opt_args += [option.argtype.name]
            opt_enums += [option.enum_name()]
            opt_comments += ['' if pos == 0 else ' /* Compatibility alias */']

        if sn := option.short_name():
            optstring += sn
            if option.argtype == ArgType.required_argument:
                optstring += ':'
            elif option.argtype == ArgType.optional_argument:
                optstring += '::'

    # 0. Generate forward declarations and defines
    yield f'#define OPTSTRING "{optstring}"'
    yield ''
    yield 'static int help(void);'
    yield ''
    yield 'static int _unused_ verb_help(int argc, char *argv[], void *userdata) {'
    yield '\treturn help();'
    yield '}'
    yield ''

    # 1. Generate help string
    if (help_key_width := globals.help_key_width) is None:
        # We assume keys which are above globals.target_help_key_width chars always get a linebreak.
        widths = [len(option.help_key() or '') for option in options]
        help_key_width = max(w for w in widths if w < globals.target_help_key_width)

        # initial value of help_expl_width
        help_expl_width = globals.target_line_width - help_key_width - 2 - 1
        maxwidth = 0
        for option in options:
            if option.help_key():
                widths = [len(line)
                          for line in textwrap.wrap(option.help, help_expl_width, break_on_hyphens=False)]
                maxwidth = max(maxwidth, *widths)

        # add an extra column if the space is not needed for the explanations
        if maxwidth < help_expl_width:
            help_key_width += 1
    else:
        # line is 'SP SP -s SP --long SP REST'.
        # '-s SP --long' is covered by 'key'
        help_expl_width = globals.target_line_width - help_key_width - 2 - 1

    groups = set(option.group for option in options)
    for group in groups:
        suffix = '_' + group.upper() if group else ''
        yield f'#define OPTION_HELP_GENERATED{suffix} \\';
        for option in options:
            if option.group == group:
                key = option.help_key()
                if not key:
                    continue
                expl = textwrap.wrap(option.help, help_expl_width, break_on_hyphens=False)

                if len(key) <= help_key_width:
                    # The common case
                    yield f'\t"  {key:{help_key_width}} {expl[0]}\\n" \\'
                else:
                    # We need to wrap the line :(
                    yield f'\t"  {key}\\n" \\'
                    yield f'\t"  {" ":{help_key_width}} {expl[0]}\\n" \\'
                for more in expl[1:]:
                    yield f'\t"  {" ":{help_key_width}} {more}\\n" \\'
        yield '\t""'

    # 2. Generate function header
    yield '';

    argstring = ', '.join(('int argc', 'char* argv[]', *globals.parser_options))
    yield f'static int parse_argv_generated({argstring}) {{'

    # 3. Walk over options and generate enum values for all options
    #    that don't have a single-leter param.
    enums = [option.enum_name()
             for option in options
             if not (option.skip_code or
                     option.short_name() or
                     option.argtype == ArgType.positional)]
    if enums:
        yield '\tenum {'
        yield f'\t\t{enums[0]} = 0x100,'
        for enum in enums[1:]:
            yield f'\t\t{enum},'
        yield '\t};'
        yield ''

    # 4. Generate 'static const struct option options[]'.
    opt_names_width = max(len(it) for it in opt_names) + 2
    opt_args_width = max(len(it) for it in opt_args)
    opt_enums_width = max(len(it) for it in opt_enums)

    yield '\tstatic const struct option options[] = {'

    for n,a,e,c in zip(opt_names, opt_args, opt_enums, opt_comments):
        yield '\t\t{{ {:{}} {:{}} NULL, {:{}} }},{}'.format(
            f'"{n}",', opt_names_width + 1,
            f'{a},', opt_args_width + 1,
            e, opt_enums_width,
            c,
        )
    yield '\t\t{}'
    yield '\t};'
    yield ''
    yield '\tassert(argc >= 0);'
    yield '\tassert(argv);'
    yield ''
    # Define the optstring as a variable to allow it to be dynamically overridden.
    yield '\tconst char *optstring = OPTSTRING;'
    yield '\tint c, _unused_ r;'
    yield ''

    if globals.intro:
        for line in globals.intro:
            yield f'\t{line}'
        yield ''

    if optstring.startswith('+'):
        yield "\t/* Resetting to 0 forces the invocation of an internal initialization routine of"
        yield "\t * getopt_long() that checks for GNU extensions in optstring ('-' or '+' at the beginning)."
        yield "\t */"
        yield '\toptind = 0;'
        yield ''

    yield '\twhile ((c = getopt_long(argc, argv, optstring, options, NULL)) >= 0)'
    yield '\t\tswitch (c) {'
    yield ''

    for option in options:
        if option.skip_code:
            continue

        yield f"\t\tcase {option.enum_name()}:{' {' if option.scope else ''}"
        for line in option.body:
            yield '\t\t\t' + line
        if option.scope:
            yield '\t\t}'
        yield ''

    yield "\t\tcase '?':"
    yield '\t\t\treturn -EINVAL;'
    yield ''
    yield '\t\tdefault:'
    yield '\t\t\tassert_not_reached();'
    yield '\t\t}'

    # 4. Close the function
    if globals.outro:
        yield ''
        for line in globals.outro:
            yield f'\t{line}'

    yield ''
    yield '\treturn 1;'
    yield '}'


def generate_c(options: list[Option], globals: Globals) -> None:
    for line in generate_lines(options, globals):
        print(line.rstrip().replace('\t', 8 * ' '))


class InputState(Enum):
    init       = 1
    directives = 2
    body       = 3


def parse_option_line(desc: str) -> tuple[list[str], ArgType, str | None]:
    split = desc.split()

    # Figure out if the argument is mandatory.
    # All options must either be followed by =, or none.
    # One option must specify the argument metavar.

    names = []
    argtype = None
    metavar = None

    if split == ['positional']:
        # handle positional args when '-' is the first character of the option string
        return [desc], ArgType.positional, None

    for word in split:
        m = re.match(r'^(?P<name>--?[a-zA-Z0-9_-]+)(?P<rest>\[?=.*)?$', word)
        if not m:
            raise ValueError(f'Bad option: {word!r}')
        name, rest = m.groups()

        if not rest:
            new_argtype = ArgType.no_argument
            val = None
        elif rest[0] == '=':
            new_argtype = ArgType.required_argument
            val = rest[1:]
        elif rest[0] == '[':
            if rest[-1] != ']':
                raise ValueError(f'Bad option: {word!r}')
            new_argtype = ArgType.optional_argument
            val = rest[2:-1]
        else:
            assert False

        if argtype is None:
            argtype = new_argtype
        elif new_argtype != argtype:
            raise ValueError(f'Inconsistent option definition: {desc}')

        names += [name]

        if val:
            if metavar:
                raise ValueError(f'Metavar specified twice: {desc}')
            metavar = val

    assert names
    assert argtype

    return names, argtype, metavar


def parse_input(lines: list[str]) -> tuple[list[Option], Globals]:
    state = InputState.init
    globals = Globals()
    options = []

    n = 0
    # We continue the loop even if we're dangling at the end to wrap up
    # an unfished 'option' stanza.
    while n < len(lines) or state != InputState.init:
        line = lines[n] if n < len(lines) else ''

        if line.startswith('#'):
            n += 1
            continue

        match state:
            case InputState.init:
                if not line:
                    n += 1
                    continue

                if m := re.match(r'global (?P<name>[a-z_]+) +(?P<value>.+)', line):
                    globals.set(*m.groups())
                    n += 1
                    continue

                m = re.match(r'(?P<block>intro$|outro$|option\b)(?P<config>.*)', line)
                if not m:
                    raise ValueError(f'unexpected line {n+1}: {line!r}')

                block, config = m.groups()
                if block == 'option':
                    names, argtype, metavar = parse_option_line(config)
                else:
                    names, argtype, metavar = [], ArgType.no_argument, None

                state = InputState.directives
                help = []
                group = None
                body: list[str] = []
                scope = False

                n += 1

            case InputState.directives:
                if line.startswith(' ') or not line:
                    state = InputState.body
                    continue

                if m := re.match(r'help (?P<help>.+)', line):
                    help += [m.group('help')]
                elif m := re.match(r'group (?P<group>.+)', line):
                    group = m.group('group')
                elif m := re.match(r'scope$', line):
                    scope = True
                else:
                    raise ValueError(f'unexpected directive {n+1}: {line!r}')

                n += 1

            case InputState.body:
                body_part = line.startswith(' ') or not line
                if body_part:
                    if line:
                        if not line.startswith(' ' * 8):
                            raise ValueError(f'improperly indented line {n+1}: {line!r}')
                        line = line[8:]
                        if not body and line.startswith(' '):
                            raise ValueError(f'improperly indented line {n+1}: {line!r}')

                    body += [line]
                    n += 1

                    if n < len(lines):
                        continue

                # end of body
                if block == 'option':
                    assert names

                    scope = scope or any(l.startswith(('_cleanup_', 'const')) for l in body)

                    opt = Option(
                        names,
                        argtype,
                        metavar,
                        group,
                        help=' '.join(help),
                        body=body,
                        scope=scope,
                    )
                    options += [opt]
                elif block in ('intro', 'outro'):
                    assert not names
                    assert not help
                    old = globals.intro if block == 'intro' else globals.outro
                    if old:
                        raise ValueError(f'block {block} duplicated')
                    old += body

                state = InputState.init

    return options, globals

if __name__ == '__main__':
    input = open(sys.argv[1]).read().splitlines()
    options, globals = parse_input(input)
    generate_c(options, globals)
