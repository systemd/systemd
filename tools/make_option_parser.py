#!/usr/bin/env python3
# pylint: disable=line-too-long,invalid-name,global-statement,redefined-outer-name
# pylint: disable=redefined-builtin,consider-using-f-string,consider-using-with
# pylint: disable=missing-function-docstring,missing-class-docstring
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
= Helper to generate option parsing code from the switch statement

== Syntax of option parsing annotations ==

case OPTION_<LONG_NAME>:
  // option: --long-name -s --long-alias
  // help: A description string for --help
  // help: with a second line if needed
  // group: <group_name>

The help strings are concatenated (when more than one help: line is present)
and wrapped to 80 columns.

If the help string is 'skip', then the option is not shown in --help output.

The required or optional argument must be specified consistently for all options.
The metavar (the argument to the option) should be specified just once.
(This is different then the shorthand notation we use in --help). Thus:
  option: --long-option-no-arg -s
  option: --long-option-required-arg=SOMETHING -s=
  option: --long-option-optional-arg=[SOMETHING] -s=

When the option doesn't have a long name, the enum field should be called
OPTION_SHORT_x or OPTION_SHORT_X, e.g. 'case OPTION_SHORT_j' for '-j'
and 'case OPTION_SHORT_J' for '-J'.

Variant with long option only and no argument:
in this trivial (but common) case, the 'case' line is enough:
case OPTION_<LONG_NAME>:
   <code…>
"""

from __future__ import annotations

import argparse
import re
import textwrap
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

@dataclass
class Globals:
    target_line_width: int = 80
    target_help_key_width: int = 25

    namespace: str|None = None
    help_key_width: int|None = None
    optstring_prefix: str = ''
    parser_options: list[str] = field(default_factory=list)
    intro: list[str] = field(default_factory=list)
    outro: list[str] = field(default_factory=list)

    def set(self, name: str, value: str) -> None:
        # A consumer for the 'global foo bar' settings.
        match name:
            case 'namespace':
                self.namespace = value
            case 'help_key_width':
                self.help_key_width = int(value)
            case 'optstring_prefix':
                self.optstring_prefix = value
            case 'parser_option':
                self.parser_options += [value]
            case _:
                raise ValueError(f'Uknown global setting {name!r}')


class ArgType(Enum):
    # This is the same as in <getopt.h>
    no_argument       = 0
    optional_argument = 1
    required_argument = 2

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}.{self.name}'


def parse_option_specs(specs: list[str]) -> tuple[list[str], ArgType, str|None]:
    # Determine argument names, type, and metavar from an argument list.
    #
    # All options must either be followed by =, or none.
    # Exactly one option must specify the argument metavar.
    #
    # Given ["--foo=BAR", "-f=", "--compat-foo="] extracts the names --foo, -f,
    # and --compat-foo, and ensures all have the same argument type (here, a
    # required argument) and that the metavar is specified once.

    names = []
    argtype = None
    metavar = None

    for word in specs:
        if not (m := re.match(r'^(?P<name>--?[a-zA-Z0-9_-]+)(?P<rest>\[?=.*)?$', word)):
            raise ValueError(f'bad option: {word!r}')
        name, rest = m.groups()

        if not rest:                                           # --option-no-value
            new_argtype = ArgType.no_argument
            val = None
        elif rest.startswith('='):                             # --option-value-any=…
            new_argtype = ArgType.required_argument
            val = rest[1:]
            if val.startswith('[') and not val.endswith(']'):  # --option-value-allowed-empty=[…]
                raise ValueError(f"bad option, expected ']' at end: {word!r}")
        elif rest.startswith('[='):                            # --option-value-optional-arg[=…]
            if not rest.endswith(']'):
                raise ValueError(f'bad option: {word!r}')
            new_argtype = ArgType.optional_argument
            val = rest[2:-1]
        else:
            raise ValueError(f'cannot parse option {word!r}')

        if argtype is None:
            argtype = new_argtype
        elif new_argtype != argtype:
            raise ValueError(f'inconsistent option definition: {specs}')

        names += [name]

        if val:
            if metavar:
                raise ValueError(f'metavar specified twice: {specs}')
            metavar = val

    assert names
    assert argtype

    return names, argtype, metavar


@dataclass
class Option:
    enum: str
    names: list[str]
    argtype: ArgType
    metavar: str|None
    group: str|None
    help: str

    @staticmethod
    def new(enum: str,
            specs: list[str],
            group: str|None,
            help: list[str]) -> Option:

        if enum.startswith('OPTION_SHORT_'):
            if len(enum) != len('OPTION_SHORT_X'):
                raise ValueError(f'Bad enum name {enum!r} (short option must be exactly one character)')
            spec = '-' + enum[-1]
        else:
            # Single-letter "long name" doesn't make sense.
            # Currently the shortest option is --id.
            if len(enum) < len('OPTION_XX'):
                raise ValueError(f'Bad enum name {enum!r} (long option must be at least two characters)')
            spec = '--' + enum[len('OPTION_'):].lower().replace('_', '-')

        if specs:
            names, argtype, metavar = parse_option_specs(specs)

            # If any options are named, check if the enum name matches one of
            # the options given.
            if spec not in names:
                raise ValueError(f'Enum name {enum!r} does not match any of {specs}')
        else:
            # Figure out the option specification based on the enum name.
            # This is good enough for the common case.
            # This only is supported for options which take no arguments.
            names = [spec]
            argtype = None
            metavar = None

        # Insert defaults
        _sn = _argtype = _metavar = None

        match enum:
            case 'OPTION_HELP':
                _help = 'Show this help'
                _sn = '-h'
            case 'OPTION_VERSION':
                _help = 'Show package version'
            case 'OPTION_NO_PAGER':
                _help = 'Do not start the pager'
            case 'OPTION_NO_ASK_PASSWORD':
                _help = 'Do not prompt for password'
            case 'OPTION_JSON':
                _help = 'Output as JSON (one of pretty, short, off)'
                _argtype = ArgType.required_argument
                _metavar = 'FORMAT'
            case 'OPTION_NO_LEGEND':
                _help = 'Do not show headers or footers'
            case 'OPTION_SHORT_j':
                _help = 'Equivalent to --json=pretty (on TTY) or --json=short (otherwise)'
            case 'OPTION_HOST':
                _help = 'Operate on remote host'
                _sn = '-H'
                _argtype = ArgType.required_argument
                _metavar = '[USER@]HOST'
            case 'OPTION_MACHINE':
                _help = 'Operate on local container'
                _sn = '-M'
                _argtype = ArgType.required_argument
                _metavar = 'CONTAINER'
            case 'OPTION_CAT_CONFIG':
                _help = 'Show configuration files'
            case 'OPTION_TLDR':
                _help = 'Show non-comment parts of configuration'
            case _:
                _help = 'XXXXXXXXXX'

        if not help:
            help += [_help]
        if _sn and all(n.startswith('--') for n in names):
            names += [_sn]
        if not argtype:
            argtype = _argtype or ArgType.no_argument
        if _metavar and not metavar:
            metavar = _metavar

        return Option(enum, names, argtype, metavar, group, ' '.join(help))

    def __post_init__(self) -> None:
        # Check that options are either short or long
        for name in self.names:
            if name.startswith('--'):
                assert len(name) >= 4
            else:
                assert len(name) == 2

    def short_name(self) -> str|None:
        # First single letter name, if any
        for name in self.names:
            if name.startswith('-') and not name.startswith('--'):
                return name[1]
        return None

    def long_names(self) -> Iterator[str]:
        # Long option names, if any
        return (name[2:] for name in self.names if name.startswith('--'))

    def long_name(self) -> str|None:
        # The primary long option name, shown in --help
        return next(self.long_names(), None)

    def help_key(self) -> str:
        if self.help == 'skip':
            return ''

        sn = self.short_name()
        lhs = ['-', sn] if sn else ['  ']
        rhs = []

        ln = self.long_name()
        if ln:
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


def generate_lines(options: list[Option], globals: Globals) -> Iterator[str]:
    # Figure out the optstring and other variables
    opt_names = []
    opt_args = []
    opt_enums = []
    opt_comments = []
    optstring = globals.optstring_prefix
    ns = f'_{globals.namespace}' if globals.namespace else ''

    for option in options:
        for pos, ln in enumerate(option.long_names()):
            opt_names += [ln]
            opt_args += [option.argtype.name]
            opt_enums += [option.enum]
            opt_comments += ['' if pos == 0 else ' /* Compatibility alias */']

        if sn := option.short_name():
            optstring += sn
            if option.argtype == ArgType.required_argument:
                optstring += ':'
            elif option.argtype == ArgType.optional_argument:
                optstring += '::'

    opt_names_width = max(len(it) for it in opt_names) + 2
    opt_args_width = max(len(it) for it in opt_args)
    opt_enums_width = max(len(it) for it in opt_enums)

    # 0. Generate forward declarations and defines
    opstring_name = 'OPTSTRING' + ns.upper()
    yield f'#define {opstring_name} "{optstring}"'
    yield ''
    yield f'static int help{ns}(void);'
    yield ''
    yield f'static int _unused_ verb_help{ns}(int argc, char *argv[], void *userdata) {{'
    yield f'\treturn help{ns}();'
    yield '}'
    yield ''

    # 1. Generate help string
    help_key_width = globals.help_key_width
    if help_key_width is not None:
        # line is 'SP SP -s SP --long SP REST'.
        # '-s SP --long' is covered by 'key'
        help_expl_width = globals.target_line_width - help_key_width - 2 - 1
    else:
        # We assume keys which are above globals.target_help_key_width chars always get a linebreak.
        widths = [len(option.help_key()) for option in options]
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

    groups = set(option.group for option in options)
    for group in groups:
        suffix = ns.upper() + ('_' + group.upper() if group else '')
        yield f'#define OPTION_HELP_GENERATED{suffix} \\'
        for option in options:
            if option.group == group:
                if not (key := option.help_key()):
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
        yield ''

    # 3. Walk over options and generate enums for all options.
    yield 'enum {'
    for num, option in enumerate(options, start=0x100):
        sn = option.short_name()
        value = f"'{sn}'" if sn else f"{num:#x}"
        yield f'\t{option.enum:{opt_enums_width}} = {value},'
    yield '};'
    yield ''

    # 4. Generate 'static const struct option options[]'.
    yield 'static const struct option options[] = {'

    for n,a,e,c in zip(opt_names, opt_args, opt_enums, opt_comments):
        name = f'"{n}",'
        args = f'{a},'
        yield f'\t{{ {name:{opt_names_width + 1}} {args:{opt_args_width + 1}} NULL, {e:{opt_enums_width}} }},{c}'

    yield '\t{}'
    yield '};'


def generate_c(options: list[Option], globals: Globals) -> None:
    for line in generate_lines(options, globals):
        print(line.rstrip().replace('\t', 8 * ' '))


class InputState(Enum):
    other      = 1
    option     = 2
    directives = 3


def parse_input(lines: list[str]) -> tuple[list[Option], Globals]:
    globals = Globals()
    options = []

    n = 0
    state = InputState.other
    while n < len(lines) or state != InputState.other:
        line = lines[n]

        match state:
            case InputState.other:
                if m := re.match(r'^\s*case (?P<enum>OPTION_.+):(?:\s*{)?$', line):
                    enum = m.group('enum')
                    print(f'// found {enum}')

                    state = InputState.option
                    specs: list[str] = []
                    group = None
                    help = []

                n += 1

            case InputState.option:
                if m := re.match(r'\s*// option: (?P<specs>.*)', line):
                    specs += m.group('specs').split()
                    n += 1

                state = InputState.directives

            case InputState.directives:
                if m := re.match(r'\s*// help: (?P<help>.*)', line):
                    help += [m.group('help').strip()]
                    n += 1

                elif m := re.match(r'\s*// group: (?P<group>.*)', line):
                    if group is not None:
                        raise ValueError('group specified again')
                    group = m.group('group').strip()
                    n += 1

                else:
                    # end of directives

                    options += [Option.new(enum, specs, group, help)]
                    state = InputState.other

    return options, globals


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('input', type=Path)

    args = parser.parse_args()

    input = open(args.input).read().splitlines()
    options, globals = parse_input(input)

    print('//', globals)
    for option in options:
        print('//', option)

    generate_c(options, globals)


if __name__ == '__main__':
    main()
