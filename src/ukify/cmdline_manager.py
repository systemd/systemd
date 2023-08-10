#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of systemd.
#
# systemd is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# systemd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with systemd; If not, see <https://www.gnu.org/licenses/>.

# pylint: disable=missing-docstring,invalid-name,import-outside-toplevel
# pylint: disable=consider-using-with,unspecified-encoding,line-too-long
# pylint: disable=too-many-locals,too-many-statements,too-many-return-statements
# pylint: disable=too-many-branches,too-many-lines,too-many-instance-attributes
# pylint: disable=too-many-arguments,unnecessary-lambda-assignment,fixme
# pylint: disable=unused-argument

import argparse
import dataclasses
import json
import os
import pathlib
import pydoc
import subprocess
import sys
import shutil
from typing import (Any,
                    Callable,
                    Optional,
                    Sequence,
                    Union,
                    NamedTuple)


__version__ = '{{PROJECT_VERSION}} ({{GIT_VERSION}})'
GLOBAL_ADDONS_PATH = '/efi/loader/addons'


@dataclasses.dataclass(frozen=True)
class ConfigItem:
    @staticmethod
    def config_list_prepend(
            namespace: argparse.Namespace,
            group: Optional[str],
            dest: str,
            value: Any,
    ) -> None:
        "Prepend value to namespace.<dest>"

        assert not group

        old = getattr(namespace, dest, [])
        if old is None:
            old = []
        setattr(namespace, dest, value + old)

    @staticmethod
    def config_set_if_unset(
            namespace: argparse.Namespace,
            group: Optional[str],
            dest: str,
            value: Any,
    ) -> None:
        "Set namespace.<dest> to value only if it was None"

        assert not group

        if getattr(namespace, dest) is None:
            setattr(namespace, dest, value)

    @staticmethod
    def config_set_group(
            namespace: argparse.Namespace,
            group: Optional[str],
            dest: str,
            value: Any,
    ) -> None:
        "Set namespace.<dest>[idx] to value, with idx derived from group"

        # pylint: disable=protected-access
        if group not in namespace._groups:
            namespace._groups += [group]
        idx = namespace._groups.index(group)

        old = getattr(namespace, dest, None)
        if old is None:
            old = []
        setattr(namespace, dest,
                old + ([None] * (idx - len(old))) + [value])

    @staticmethod
    def parse_boolean(s: str) -> bool:
        "Parse 1/true/yes/y/t/on as true and 0/false/no/n/f/off/None as false"
        s_l = s.lower()
        if s_l in {'1', 'true', 'yes', 'y', 't', 'on'}:
            return True
        if s_l in {'0', 'false', 'no', 'n', 'f', 'off'}:
            return False
        raise ValueError('f"Invalid boolean literal: {s!r}')

    # arguments for argparse.ArgumentParser.add_argument()
    name: Union[str, tuple[str, str]]
    dest: Optional[str] = None
    metavar: Optional[str] = None
    type: Optional[Callable] = None
    nargs: Optional[str] = None
    action: Optional[Union[str, Callable]] = None
    default: Any = None
    version: Optional[str] = None
    choices: Optional[tuple[str, ...]] = None
    const: Optional[Any] = None
    help: Optional[str] = None

    # metadata for config file parsing
    config_key: Optional[str] = None
    config_push: Callable[[argparse.Namespace, Optional[str], str, Any], None] = \
                    config_set_if_unset

    def _names(self) -> tuple[str, ...]:
        return self.name if isinstance(self.name, tuple) else (self.name,)

    def argparse_dest(self) -> str:
        # It'd be nice if argparse exported this, but I don't see that in the API
        if self.dest:
            return self.dest
        return self._names()[0].lstrip('-').replace('-', '_')

    def add_to(self, parser: argparse.ArgumentParser):
        kwargs = { key:val
                   for key in dataclasses.asdict(self)
                   if (key not in ('name', 'config_key', 'config_push') and
                       (val := getattr(self, key)) is not None) }
        args = self._names()
        parser.add_argument(*args, **kwargs)

    def apply_config(self, namespace, section, group, key, value) -> None:
        assert f'{section}/{key}' == self.config_key
        dest = self.argparse_dest()

        conv: Callable[[str], Any]
        if self.action == argparse.BooleanOptionalAction:
            # We need to handle this case separately: the options are called
            # --foo and --no-foo, and no argument is parsed. But in the config
            # file, we have Foo=yes or Foo=no.
            conv = self.parse_boolean
        elif self.type:
            conv = self.type
        else:
            conv = lambda s:s

        # This is a bit ugly, but --initrd is the only option which is specified
        # with multiple args on the command line and a space-separated list in the
        # config file.
        if self.name == '--initrd':
            value = [conv(v) for v in value.split()]
        else:
            value = conv(value)

        self.config_push(namespace, group, dest, value)

    def config_example(self) -> tuple[Optional[str], Optional[str], Optional[str]]:
        if not self.config_key:
            return None, None, None
        section_name, key = self.config_key.split('/', 1)
        if section_name.endswith(':'):
            section_name += 'NAME'
        if self.choices:
            value = '|'.join(self.choices)
        else:
            value = self.metavar or self.argparse_dest().upper()
        return (section_name, key, value)


def page(text: str, enabled: Optional[bool]) -> None:
    if enabled:
        # Initialize less options from $SYSTEMD_LESS or provide a suitable fallback.
        os.environ['LESS'] = os.getenv('SYSTEMD_LESS', 'FRSXMK')
        pydoc.pager(text)
    else:
        print(text)


class PagerHelpAction(argparse._HelpAction):  # pylint: disable=protected-access
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None] = None,
        option_string: Optional[str] = None
    ) -> None:
        page(parser.format_help(), True)
        parser.exit()


CONFIG_ITEMS_SHARED = [
    ConfigItem(
        '--efi-path',
        type = pathlib.Path,
        help = 'where UKIs are located, default is /efi/EFI/Linux',
        default = "/efi/EFI/Linux"
    ),

    ConfigItem(
        '--ukify',
        type = pathlib.Path,
        help = 'path to ukify script, default is ~/systemd/src/ukify/ukify.py',
        default = "~/systemd/src/ukify/ukify.py"
    ),

    ConfigItem(
        ('-h', '--help'),
        action=PagerHelpAction,
        help='show this help message and exit',
    )
]


CONFIG_ITEMS_JSON = [
    ConfigItem(
        '--json',
        choices = ('pretty', 'short', 'off'),
        default = 'off',
        help = 'generate JSON output',
    ),
    ConfigItem(
        '-j',
        dest='json',
        action='store_const',
        const='pretty',
        help='equivalent to --json=pretty',
    ),
]


CONFIG_ITEMS_CURRENT = [
    ConfigItem(
        'uki',
        nargs = '?',
        help = 'UKI name that we want to analyze',
    ),

    ConfigItem(
        '--no-globals',
        help = f'do not print the addons in {GLOBAL_ADDONS_PATH}',
        action = 'store_true',
    ),

    ConfigItem(
        '--all',
        help = 'print all addons found in the efi path specified with --efi-path',
        action = 'store_true',
    ),
]


CONFIG_ITEMS_LIST = [
    ConfigItem(
        '--folder',
        type = pathlib.Path,
        help = 'path to addons folder, default is /usr/share/uki/addons',
        default = '/usr/share/uki/addons'
    ),
]


CONFIG_ITEMS_ADD = [
    ConfigItem(
        'addons',
        nargs = '+',
        type = pathlib.Path,
        help = 'path to the addon(s) to install',
    ),

    ConfigItem(
        '--dest-uki',
        help = 'addons will be installed in the given uki.extra.d folder',
    ),

    ConfigItem(
        '--dest',
        type = pathlib.Path,
        default = GLOBAL_ADDONS_PATH,
        help = f'path to the folder where to install the addons. When --dest and --dest-uki are not specified, defaults to {GLOBAL_ADDONS_PATH}',
    ),
]


def create_generic_parser():
    p = argparse.ArgumentParser(
        description='Manage UKI command line addons. Note that this tool is not made to inspect a single addon, for that use the \"ukify inspect\" command',        allow_abbrev=False,
        add_help=False,
        usage='''\
cmdline_manager [current/list/add/rm] [options]
''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    for item in CONFIG_ITEMS_SHARED:
        item.add_to(p)

    # Suppress printing of usage synopsis on errors
    p.error = lambda message: p.exit(2, f'{p.prog}: error: {message}\n')

    p.add_argument(
        '-v', '--version',
        action = 'version',
        version = f'cmdline_manager {__version__}',
    )

    return p


def create_subparser(parser, name, descr, usage, config, func):
    p = parser.add_parser(
        name=name,
        description=descr,
        allow_abbrev=False,
        add_help=False,
        usage=usage,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    for item in config + CONFIG_ITEMS_SHARED:
        item.add_to(p)

    # Suppress printing of usage synopsis on errors
    p.error = lambda message: p.exit(2, f'{p.prog}: error: {message}\n')

    p.set_defaults(func=func)
    return p


class UkiCmdline(NamedTuple):
    uki_path: str
    cmdline: str

    def to_dict(self):
        return { self.uki_path : self.cmdline }


@dataclasses.dataclass
class UkiCmdlineStruct:
    uki: Union[UkiCmdline, None]
    uki_extra_d: list[UkiCmdline]
    global_addons: list[UkiCmdline] = dataclasses.field(default_factory=list)
    cmdline: str = ""

    def to_dict(self):
        obj = {}
        uki = self.uki
        obj['uki'] = {}
        if uki:
            obj['uki'][uki.uki_path] = uki.cmdline

        uki_extra_d = self.uki_extra_d
        obj['uki.extra.d'] = {}
        for el in uki_extra_d:
            obj['uki.extra.d'][el.uki_path] = el.cmdline

        global_addons = self.global_addons
        obj['global_addons'] = {}
        for el in global_addons:
            obj['global_addons'][el.uki_path] = el.cmdline

        obj['cmdline'] = self.cmdline

        return obj


def get_ukify_command(file, ukify):
    return f'{ukify} inspect {file} --section .cmdline:text -j'.split()


def get_text_from_addon(file, ukify, warning=True) -> str:
    cmd = get_ukify_command(file, ukify)
    out = subprocess.check_output(cmd, text=True)
    out = json.loads(out)
    if not '.cmdline' in out:
        if warning:
            print(f'Warning: file {file} has not a command line section, ignoring')
        return ""
    return out['.cmdline']['text']


def check_addon_has_cmdline(path, ukify, warning=True) -> str:
    if pathlib.Path(path).is_file():
        if path.endswith('.efi'):
            return get_text_from_addon(path, ukify, warning)
        elif warning:
            print(f'Warning: file {path} does not end with .efi, ignoring')
    elif warning:
        print(f'Warning: file {path} is not a file, ignoring')
    return ""


def list_uki_cmdline(uki, opts, warning=True) -> str:
    text = check_addon_has_cmdline(uki, opts.ukify)
    if text:
        text = text.replace('\u0000', '')
    elif warning:
        print(f'Warning: ignoring {uki}')
    return text


def search_addons_dir(path, ukify) -> list[UkiCmdline]:
    cmdlines = []
    for f in os.listdir(path):
            f_path = path + '/' + f
            text = check_addon_has_cmdline(f_path, ukify)
            if text:
                cmdlines.append(UkiCmdline(uki_path=f_path, cmdline=text))
    return cmdlines


def list_uki_extra_cmdline(uki, opts, warning=True):
    assert(uki.endswith('.extra.d'))
    cmdlines = []
    if pathlib.Path(uki).is_dir():
        cmdlines = search_addons_dir(uki, opts.ukify)
    elif warning:
        print(f'Warning: {uki} is not a folder, ignoring it')
    return cmdlines


def list_global_addons(opts, warning=True):
    cmdlines = []
    if pathlib.Path(GLOBAL_ADDONS_PATH).is_dir():
        cmdlines = search_addons_dir(GLOBAL_ADDONS_PATH, opts.ukify)
    elif warning:
        print(f'Warning: {GLOBAL_ADDONS_PATH} not found, ignoring it')
    return cmdlines


def build_command_line(struct : UkiCmdlineStruct):
    # first, uki built in
    if struct.uki:
        struct.cmdline = struct.uki.cmdline
    # then, global addons
    if struct.global_addons:
        for cmdline in struct.global_addons:
            struct.cmdline += ' ' + cmdline.cmdline
    # finally, uki.extra.d
    if struct.uki_extra_d:
        for cmdline in struct.uki_extra_d:
            struct.cmdline += ' ' + cmdline.cmdline


def print_list_cmdline(cmdlines : list[UkiCmdline]):
    for cmdline in cmdlines:
        print(f'{cmdline.uki_path}\n    {cmdline.cmdline}')


def print_uki_cmdline_struct(struct : UkiCmdlineStruct, name : str):
    print(f'UKI {name}.efi')
    if struct.uki:
        print(f'{struct.uki.uki_path}\nCmdline: {struct.uki.cmdline}')
    else:
        print('Not found')

    print('\nUKI.extra.d')
    if len(struct.uki_extra_d) == 0:
        print('Not found')
    else:
        print_list_cmdline(struct.uki_extra_d)

    print('\nGlobals')
    if len(struct.global_addons) == 0:
        print('Not found')
    else:
        print_list_cmdline(struct.global_addons)

    print(f'\nCommand line given to UKI{" " +struct.uki.uki_path if struct.uki else "s"}:\n{struct.cmdline}')


def json_dump(struct, json_opt):
    indent = 4 if json_opt == 'pretty' else None
    json.dump(struct, sys.stdout, indent=indent)


def process_uki_section(uki, opts, warnings=True) -> UkiCmdline:
    uki_path_str = str(opts.efi_path) + '/' + uki
    uki_cmdline = list_uki_cmdline(uki_path_str, opts, warning=warnings)
    return UkiCmdline(uki_path=uki_path_str, cmdline=uki_cmdline)


def process_uki_extra_section(uki_extra_d, opts, warnings=True) -> list[UkiCmdline]:
    uki_extra_path = str(opts.efi_path) + '/' + uki_extra_d
    return list_uki_extra_cmdline(uki_extra_path, opts, warning=warnings)


def process_single_uki(uki, opts, warnings=True) -> UkiCmdlineStruct:
    uki_cmdline = process_uki_section(uki, opts, warnings=warnings)
    uki_extra_cmdlines = process_uki_extra_section(uki + '.extra.d', opts, warnings=warnings)
    return UkiCmdlineStruct(uki=uki_cmdline, uki_extra_d=uki_extra_cmdlines)


def list_current_cmdline(opts):
    if opts.uki and opts.all:
        print("Error: cannot specify an uki and provide --all flag")
        return

    ukis : dict[str, UkiCmdlineStruct]= {}

    if opts.uki:
        ukis[opts.uki.replace('.efi','')] = process_single_uki(opts.uki, opts)
    elif opts.all:
        for uki in os.listdir(str(opts.efi_path)):
            if uki.endswith('.efi'):
                key = uki.replace('.efi', '')
                uki_cmdline = process_uki_section(uki, opts, warnings=False)
                if key not in ukis:
                    ukis[key] = UkiCmdlineStruct(uki_cmdline, [])
                else:
                    assert(ukis[key].uki is None)
                    assert(ukis[key].uki_extra_d != [])
                    ukis[key].uki = uki_cmdline
            elif uki.endswith('.efi.extra.d'):
                key = uki.replace('.efi.extra.d', '')
                uki_extra_cmdlines = process_uki_extra_section(uki, opts, warnings=False)
                if key not in ukis:
                    ukis[key] = UkiCmdlineStruct(None, uki_extra_cmdlines)
                else:
                    assert(ukis[key].uki != None)
                    assert(ukis[key].uki_extra_d == [])
                    ukis[key].uki_extra_d = uki_extra_cmdlines
            else:
                continue

    if not opts.no_globals:
        global_addons = list_global_addons(opts)
        if len(ukis.values()) == 0 and global_addons:
            ukis[""] = UkiCmdlineStruct(None, [], global_addons)
        for v in ukis.values():
            v.global_addons = global_addons
            build_command_line(v)

    for v in ukis.values():
        build_command_line(v)

    if opts.json == "off":
        for k,v in ukis.items():
            print_uki_cmdline_struct(v, k)
            print('\n')
    else:
        uki_list = []
        for v in ukis.values():
            uki_list.append(v.to_dict())
        json_dump(uki_list, opts.json)


def list_fs_cmdline(opts):
    folder_str = str(opts.folder)
    if opts.folder.is_dir():
        list_addons = search_addons_dir(folder_str, opts.ukify)
        if opts.json == "off":
            print_list_cmdline(list_addons)
        else:
            obj = {}
            for el in list_addons:
                obj[el.uki_path] = el.cmdline
            json_dump(obj, opts.json)
    else:
        print(f'Warning: folder {folder_str} does not exist')


def check_destination(opts):
    if str(opts.dest) != GLOBAL_ADDONS_PATH and opts.dest_uki:
        print('Error: do not provide both --dest and --dest-uki')
        return None

    destination = ''
    if opts.dest_uki:
        if not opts.dest_uki.endswith('.efi'):
            print('Error: --dest-uki parameter must end with .efi')
            return None
        uki_path = str(opts.efi_path) + '/' + opts.dest_uki + '.extra.d'
        if pathlib.Path(uki_path).is_dir():
            destination = uki_path
        else:
            print(f'Error: UKI {uki_path} is not a folder')
            return None

    if not destination:
        if opts.dest.is_dir():
            destination = opts.dest
        else:
            print(f'Error: destination {str(opts.dest)} is not a folder')
            return None

    return destination


def add_cmdline(opts):
    destination = check_destination(opts)
    if not destination:
        return

    for addon in opts.addons:
        addon_str = str(addon)
        if check_addon_has_cmdline(addon_str, opts.ukify):
            shutil.copy(addon_str, destination)
        else:
            print(f'Warning: addon {addon_str} ignored')
            return


def parse_args():
    parser = create_generic_parser()
    subparsers = parser.add_subparsers(help='Commands to manipulate the command line addons')

    create_subparser(subparsers, "current",
                     "List all cmdline addons (.efi) used with current uki",
                     "current [uki.efi] [options...]",
                     CONFIG_ITEMS_CURRENT + CONFIG_ITEMS_JSON,
                     list_current_cmdline)

    create_subparser(subparsers, "list",
                     "List all cmdline addons (.efi) present in a folder",
                     "list [options...]",
                     CONFIG_ITEMS_LIST + CONFIG_ITEMS_JSON,
                     list_fs_cmdline)

    create_subparser(subparsers, "add",
                     "Add the provided cmdline addons (.efi) to a specific UKI or global addons. If destination contains already the file, it will be replaced.",
                     "add source_addon(s) [options...]",
                     CONFIG_ITEMS_ADD,
                     add_cmdline)
    return parser.parse_args()


def main():
    opts = parse_args()
    opts.func(opts)


if __name__ == '__main__':
    main()
