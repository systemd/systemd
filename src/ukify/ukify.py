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
# pylint: disable=too-many-branches,fixme

import argparse
import configparser
import collections
import dataclasses
import fnmatch
import itertools
import json
import os
import pathlib
import pprint
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import typing

import pefile

__version__ = '{{PROJECT_VERSION}} ({{GIT_VERSION}})'

EFI_ARCH_MAP = {
        # host_arch glob : [efi_arch, 32_bit_efi_arch if mixed mode is supported]
        'x86_64'       : ['x64', 'ia32'],
        'i[3456]86'    : ['ia32'],
        'aarch64'      : ['aa64'],
        'arm[45678]*l' : ['arm'],
        'loongarch32'  : ['loongarch32'],
        'loongarch64'  : ['loongarch64'],
        'riscv32'      : ['riscv32'],
        'riscv64'      : ['riscv64'],
}
EFI_ARCHES: list[str] = sum(EFI_ARCH_MAP.values(), [])

def guess_efi_arch():
    arch = os.uname().machine

    for glob, mapping in EFI_ARCH_MAP.items():
        if fnmatch.fnmatch(arch, glob):
            efi_arch, *fallback = mapping
            break
    else:
        raise ValueError(f'Unsupported architecture {arch}')

    # This makes sense only on some architectures, but it also probably doesn't
    # hurt on others, so let's just apply the check everywhere.
    if fallback:
        fw_platform_size = pathlib.Path('/sys/firmware/efi/fw_platform_size')
        try:
            size = fw_platform_size.read_text().strip()
        except FileNotFoundError:
            pass
        else:
            if int(size) == 32:
                efi_arch = fallback[0]

    print(f'Host arch {arch!r}, EFI arch {efi_arch!r}')
    return efi_arch


def shell_join(cmd):
    # TODO: drop in favour of shlex.join once shlex.join supports pathlib.Path.
    return ' '.join(shlex.quote(str(x)) for x in cmd)


def round_up(x, blocksize=4096):
    return (x + blocksize - 1) // blocksize * blocksize


def try_import(modname, name=None):
    try:
        return __import__(modname)
    except ImportError as e:
        raise ValueError(f'Kernel is compressed with {name or modname}, but module unavailable') from e


def maybe_decompress(filename):
    """Decompress file if compressed. Return contents."""
    f = open(filename, 'rb')
    start = f.read(4)
    f.seek(0)

    if start.startswith(b'\x7fELF'):
        # not compressed
        return f.read()

    if start.startswith(b'MZ'):
        # not compressed aarch64 and riscv64
        return f.read()

    if start.startswith(b'\x1f\x8b'):
        gzip = try_import('gzip')
        return gzip.open(f).read()

    if start.startswith(b'\x28\xb5\x2f\xfd'):
        zstd = try_import('zstd')
        return zstd.uncompress(f.read())

    if start.startswith(b'\x02\x21\x4c\x18'):
        lz4 = try_import('lz4.frame', 'lz4')
        return lz4.frame.decompress(f.read())

    if start.startswith(b'\x04\x22\x4d\x18'):
        print('Newer lz4 stream format detected! This may not boot!')
        lz4 = try_import('lz4.frame', 'lz4')
        return lz4.frame.decompress(f.read())

    if start.startswith(b'\x89LZO'):
        # python3-lzo is not packaged for Fedora
        raise NotImplementedError('lzo decompression not implemented')

    if start.startswith(b'BZh'):
        bz2 = try_import('bz2', 'bzip2')
        return bz2.open(f).read()

    if start.startswith(b'\x5d\x00\x00'):
        lzma = try_import('lzma')
        return lzma.open(f).read()

    raise NotImplementedError(f'unknown file format (starts with {start})')


class Uname:
    # This class is here purely as a namespace for the functions

    VERSION_PATTERN = r'(?P<version>[a-z0-9._-]+) \([^ )]+\) (?:#.*)'

    NOTES_PATTERN = r'^\s+Linux\s+0x[0-9a-f]+\s+OPEN\n\s+description data: (?P<version>[0-9a-f ]+)\s*$'

    # Linux version 6.0.8-300.fc37.ppc64le (mockbuild@buildvm-ppc64le-03.iad2.fedoraproject.org)
    # (gcc (GCC) 12.2.1 20220819 (Red Hat 12.2.1-2), GNU ld version 2.38-24.fc37)
    # #1 SMP Fri Nov 11 14:39:11 UTC 2022
    TEXT_PATTERN = rb'Linux version (?P<version>\d\.\S+) \('

    @classmethod
    def scrape_x86(cls, filename, opts=None):
        # Based on https://gitlab.archlinux.org/archlinux/mkinitcpio/mkinitcpio/-/blob/master/functions#L136
        # and https://www.kernel.org/doc/html/latest/x86/boot.html#the-real-mode-kernel-header
        with open(filename, 'rb') as f:
            f.seek(0x202)
            magic = f.read(4)
            if magic != b'HdrS':
                raise ValueError('Real-Mode Kernel Header magic not found')
            f.seek(0x20E)
            offset = f.read(1)[0] + f.read(1)[0]*256  # Pointer to kernel version string
            f.seek(0x200 + offset)
            text = f.read(128)
        text = text.split(b'\0', maxsplit=1)[0]
        text = text.decode()

        if not (m := re.match(cls.VERSION_PATTERN, text)):
            raise ValueError(f'Cannot parse version-host-release uname string: {text!r}')
        return m.group('version')

    @classmethod
    def scrape_elf(cls, filename, opts=None):
        readelf = find_tool('readelf', opts=opts)

        cmd = [
            readelf,
            '--notes',
            filename,
        ]

        print('+', shell_join(cmd))
        try:
            notes = subprocess.check_output(cmd, stderr=subprocess.PIPE, text=True)
        except subprocess.CalledProcessError as e:
            raise ValueError(e.stderr.strip()) from e

        if not (m := re.search(cls.NOTES_PATTERN, notes, re.MULTILINE)):
            raise ValueError('Cannot find Linux version note')

        text = ''.join(chr(int(c, 16)) for c in m.group('version').split())
        return text.rstrip('\0')

    @classmethod
    def scrape_generic(cls, filename, opts=None):
        # import libarchive
        # libarchive-c fails with
        # ArchiveError: Unrecognized archive format (errno=84, retcode=-30, archive_p=94705420454656)

        # Based on https://gitlab.archlinux.org/archlinux/mkinitcpio/mkinitcpio/-/blob/master/functions#L209

        text = maybe_decompress(filename)
        if not (m := re.search(cls.TEXT_PATTERN, text)):
            raise ValueError(f'Cannot find {cls.TEXT_PATTERN!r} in {filename}')

        return m.group('version').decode()

    @classmethod
    def scrape(cls, filename, opts=None):
        for func in (cls.scrape_x86, cls.scrape_elf, cls.scrape_generic):
            try:
                version = func(filename, opts=opts)
                print(f'Found uname version: {version}')
                return version
            except ValueError as e:
                print(str(e))
        return None


@dataclasses.dataclass
class Section:
    name: str
    content: pathlib.Path
    tmpfile: typing.Optional[typing.IO] = None
    measure: bool = False

    @classmethod
    def create(cls, name, contents, **kwargs):
        if isinstance(contents, (str, bytes)):
            mode = 'wt' if isinstance(contents, str) else 'wb'
            tmp = tempfile.NamedTemporaryFile(mode=mode, prefix=f'tmp{name}')
            tmp.write(contents)
            tmp.flush()
            contents = pathlib.Path(tmp.name)
        else:
            tmp = None

        return cls(name, contents, tmpfile=tmp, **kwargs)

    @classmethod
    def parse_arg(cls, s):
        try:
            name, contents, *rest = s.split(':')
        except ValueError as e:
            raise ValueError(f'Cannot parse section spec (name or contents missing): {s!r}') from e
        if rest:
            raise ValueError(f'Cannot parse section spec (extraneous parameters): {s!r}')

        if contents.startswith('@'):
            contents = pathlib.Path(contents[1:])

        return cls.create(name, contents)

    def size(self):
        return self.content.stat().st_size

    def check_name(self):
        # PE section names with more than 8 characters are legal, but our stub does
        # not support them.
        if not self.name.isascii() or not self.name.isprintable():
            raise ValueError(f'Bad section name: {self.name!r}')
        if len(self.name) > 8:
            raise ValueError(f'Section name too long: {self.name!r}')


@dataclasses.dataclass
class UKI:
    executable: list[typing.Union[pathlib.Path, str]]
    sections: list[Section] = dataclasses.field(default_factory=list, init=False)

    def add_section(self, section):
        if section.name in [s.name for s in self.sections]:
            raise ValueError(f'Duplicate section {section.name}')

        self.sections += [section]


def parse_banks(s):
    banks = re.split(r',|\s+', s)
    # TODO: do some sanity checking here
    return banks


KNOWN_PHASES = (
    'enter-initrd',
    'leave-initrd',
    'sysinit',
    'ready',
    'shutdown',
    'final',
)

def parse_phase_paths(s):
    # Split on commas or whitespace here. Commas might be hard to parse visually.
    paths = re.split(r',|\s+', s)

    for path in paths:
        for phase in path.split(':'):
            if phase not in KNOWN_PHASES:
                raise argparse.ArgumentTypeError(f'Unknown boot phase {phase!r} ({path=})')

    return paths


def check_splash(filename):
    if filename is None:
        return

    # import is delayed, to avoid import when the splash image is not used
    try:
        from PIL import Image
    except ImportError:
        return

    img = Image.open(filename, formats=['BMP'])
    print(f'Splash image {filename} is {img.width}×{img.height} pixels')


def check_inputs(opts):
    for name, value in vars(opts).items():
        if name in {'output', 'tools'}:
            continue

        if isinstance(value, pathlib.Path):
            # Open file to check that we can read it, or generate an exception
            value.open().close()
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, pathlib.Path):
                    item.open().close()

    check_splash(opts.splash)


def find_tool(name, fallback=None, opts=None):
    if opts and opts.tools:
        for d in opts.tools:
            tool = d / name
            if tool.exists():
                return tool

    if shutil.which(name) is not None:
        return name

    return fallback


def combine_signatures(pcrsigs):
    combined = collections.defaultdict(list)
    for pcrsig in pcrsigs:
        for bank, sigs in pcrsig.items():
            for sig in sigs:
                if sig not in combined[bank]:
                    combined[bank] += [sig]
    return json.dumps(combined)


def call_systemd_measure(uki, linux, opts):
    measure_tool = find_tool('systemd-measure',
                             '/usr/lib/systemd/systemd-measure',
                             opts=opts)

    banks = opts.pcr_banks or ()

    # PCR measurement

    if opts.measure:
        pp_groups = opts.phase_path_groups or []

        cmd = [
            measure_tool,
            'calculate',
            f'--linux={linux}',
            *(f"--{s.name.removeprefix('.')}={s.content}"
              for s in uki.sections
              if s.measure),
            *(f'--bank={bank}'
              for bank in banks),
            # For measurement, the keys are not relevant, so we can lump all the phase paths
            # into one call to systemd-measure calculate.
            *(f'--phase={phase_path}'
              for phase_path in itertools.chain.from_iterable(pp_groups)),
        ]

        print('+', shell_join(cmd))
        subprocess.check_call(cmd)

    # PCR signing

    if opts.pcr_private_keys:
        n_priv = len(opts.pcr_private_keys or ())
        pp_groups = opts.phase_path_groups or [None] * n_priv
        pub_keys = opts.pcr_public_keys or [None] * n_priv

        pcrsigs = []

        cmd = [
            measure_tool,
            'sign',
            f'--linux={linux}',
            *(f"--{s.name.removeprefix('.')}={s.content}"
              for s in uki.sections
              if s.measure),
            *(f'--bank={bank}'
              for bank in banks),
        ]

        for priv_key, pub_key, group in zip(opts.pcr_private_keys,
                                            pub_keys,
                                            pp_groups):
            extra = [f'--private-key={priv_key}']
            if pub_key:
                extra += [f'--public-key={pub_key}']
            extra += [f'--phase={phase_path}' for phase_path in group or ()]

            print('+', shell_join(cmd + extra))
            pcrsig = subprocess.check_output(cmd + extra, text=True)
            pcrsig = json.loads(pcrsig)
            pcrsigs += [pcrsig]

        combined = combine_signatures(pcrsigs)
        uki.add_section(Section.create('.pcrsig', combined))


def join_initrds(initrds):
    if len(initrds) == 0:
        return None
    elif len(initrds) == 1:
        return initrds[0]

    seq = []
    for file in initrds:
        initrd = file.read_bytes()
        n = len(initrd)
        padding = b'\0' * (round_up(n, 4) - n)  # pad to 32 bit alignment
        seq += [initrd, padding]

    return b''.join(seq)


def pairwise(iterable):
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)


class PeError(Exception):
    pass


def pe_add_sections(uki: UKI, output: str):
    pe = pefile.PE(uki.executable, fast_load=True)

    # Old stubs do not have the symbol/string table stripped, even though image files should not have one.
    if symbol_table := pe.FILE_HEADER.PointerToSymbolTable:
        symbol_table_size = 18 * pe.FILE_HEADER.NumberOfSymbols
        if string_table_size := pe.get_dword_from_offset(symbol_table + symbol_table_size):
            symbol_table_size += string_table_size

        # Let's be safe and only strip it if it's at the end of the file.
        if symbol_table + symbol_table_size == len(pe.__data__):
            pe.__data__ = pe.__data__[:symbol_table]
            pe.FILE_HEADER.PointerToSymbolTable = 0
            pe.FILE_HEADER.NumberOfSymbols = 0
            pe.FILE_HEADER.IMAGE_FILE_LOCAL_SYMS_STRIPPED = True

    # Old stubs might have been stripped, leading to unaligned raw data values, so let's fix them up here.
    for i, section in enumerate(pe.sections):
        oldp = section.PointerToRawData
        oldsz = section.SizeOfRawData
        section.PointerToRawData = round_up(oldp, pe.OPTIONAL_HEADER.FileAlignment)
        section.SizeOfRawData = round_up(oldsz, pe.OPTIONAL_HEADER.FileAlignment)
        padp = section.PointerToRawData - oldp
        padsz = section.SizeOfRawData - oldsz

        for later_section in pe.sections[i+1:]:
            later_section.PointerToRawData += padp + padsz

        pe.__data__ = pe.__data__[:oldp] + bytes(padp) + pe.__data__[oldp:oldp+oldsz] + bytes(padsz) + pe.__data__[oldp+oldsz:]

    # We might not have any space to add new sections. Let's try our best to make some space by padding the
    # SizeOfHeaders to a multiple of the file alignment. This is safe because the first section's data starts
    # at a multiple of the file alignment, so all space before that is unused.
    pe.OPTIONAL_HEADER.SizeOfHeaders = round_up(pe.OPTIONAL_HEADER.SizeOfHeaders, pe.OPTIONAL_HEADER.FileAlignment)
    pe = pefile.PE(data=pe.write(), fast_load=True)

    warnings = pe.get_warnings()
    if warnings:
        raise PeError(f'pefile warnings treated as errors: {warnings}')

    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
    if security.VirtualAddress != 0:
        # We could strip the signatures, but why would anyone sign the stub?
        raise PeError(f'Stub image is signed, refusing.')

    for section in uki.sections:
        new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__, pe=pe)
        new_section.__unpack__(b'\0' * new_section.sizeof())

        offset = pe.sections[-1].get_file_offset() + new_section.sizeof()
        if offset + new_section.sizeof() > pe.OPTIONAL_HEADER.SizeOfHeaders:
            raise PeError(f'Not enough header space to add section {section.name}.')

        data = section.content.read_bytes()

        new_section.set_file_offset(offset)
        new_section.Name = section.name.encode()
        new_section.Misc_VirtualSize = len(data)
        # Non-stripped stubs might still have an unaligned symbol table at the end, making their size
        # unaligned, so we make sure to explicitly pad the pointer to new sections to an aligned offset.
        new_section.PointerToRawData = round_up(len(pe.__data__), pe.OPTIONAL_HEADER.FileAlignment)
        new_section.SizeOfRawData = round_up(len(data), pe.OPTIONAL_HEADER.FileAlignment)
        new_section.VirtualAddress = round_up(
            pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize,
            pe.OPTIONAL_HEADER.SectionAlignment,
        )

        new_section.IMAGE_SCN_MEM_READ = True
        if section.name == '.linux':
            # Old kernels that use EFI handover protocol will be executed inline.
            new_section.IMAGE_SCN_CNT_CODE = True
        else:
            new_section.IMAGE_SCN_CNT_INITIALIZED_DATA = True

        pe.__data__ = pe.__data__[:] + bytes(new_section.PointerToRawData - len(pe.__data__)) + data + bytes(new_section.SizeOfRawData - len(data))

        pe.FILE_HEADER.NumberOfSections += 1
        pe.OPTIONAL_HEADER.SizeOfInitializedData += new_section.Misc_VirtualSize
        pe.__structures__.append(new_section)
        pe.sections.append(new_section)

    pe.OPTIONAL_HEADER.CheckSum = 0
    pe.OPTIONAL_HEADER.SizeOfImage = round_up(
        pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize,
        pe.OPTIONAL_HEADER.SectionAlignment,
    )

    pe.write(output)


def make_uki(opts):
    # kernel payload signing

    sbsign_tool = find_tool('sbsign', opts=opts)
    sbsign_invocation = [
        sbsign_tool,
        '--key', opts.sb_key,
        '--cert', opts.sb_cert,
    ]

    if opts.signing_engine is not None:
        sbsign_invocation += ['--engine', opts.signing_engine]

    sign_kernel = opts.sign_kernel
    if sign_kernel is None and opts.sb_key:
        # figure out if we should sign the kernel
        sbverify_tool = find_tool('sbverify', opts=opts)

        cmd = [
            sbverify_tool,
            '--list',
            opts.linux,
        ]

        print('+', shell_join(cmd))
        info = subprocess.check_output(cmd, text=True)

        # sbverify has wonderful API
        if 'No signature table present' in info:
            sign_kernel = True

    if sign_kernel:
        linux_signed = tempfile.NamedTemporaryFile(prefix='linux-signed')
        linux = linux_signed.name

        cmd = [
            *sbsign_invocation,
            opts.linux,
            '--output', linux,
        ]

        print('+', shell_join(cmd))
        subprocess.check_call(cmd)
    else:
        linux = opts.linux

    if opts.uname is None:
        print('Kernel version not specified, starting autodetection 😖.')
        opts.uname = Uname.scrape(opts.linux, opts=opts)

    uki = UKI(opts.stub)
    initrd = join_initrds(opts.initrd)

    # TODO: derive public key from opts.pcr_private_keys?
    pcrpkey = opts.pcrpkey
    if pcrpkey is None:
        if opts.pcr_public_keys and len(opts.pcr_public_keys) == 1:
            pcrpkey = opts.pcr_public_keys[0]

    sections = [
        # name,      content,         measure?
        ('.osrel',   opts.os_release, True ),
        ('.cmdline', opts.cmdline,    True ),
        ('.dtb',     opts.devicetree, True ),
        ('.splash',  opts.splash,     True ),
        ('.pcrpkey', pcrpkey,         True ),
        ('.initrd',  initrd,          True ),
        ('.uname',   opts.uname,      False),

        # linux shall be last to leave breathing room for decompression.
        # We'll add it later.
    ]

    for name, content, measure in sections:
        if content:
            uki.add_section(Section.create(name, content, measure=measure))

    # systemd-measure doesn't know about those extra sections
    for section in opts.sections:
        uki.add_section(section)

    # PCR measurement and signing

    call_systemd_measure(uki, linux, opts=opts)

    # UKI creation

    uki.add_section(Section.create('.linux', linux, measure=True))

    if opts.sb_key:
        unsigned = tempfile.NamedTemporaryFile(prefix='uki')
        output = unsigned.name
    else:
        output = opts.output

    pe_add_sections(uki, output)

    # UKI signing

    if opts.sb_key:
        cmd = [
            *sbsign_invocation,
            unsigned.name,
            '--output', opts.output,
        ]
        print('+', shell_join(cmd))
        subprocess.check_call(cmd)

        # We end up with no executable bits, let's reapply them
        os.umask(umask := os.umask(0))
        os.chmod(opts.output, 0o777 & ~umask)

    print(f"Wrote {'signed' if opts.sb_key else 'unsigned'} {opts.output}")


@dataclasses.dataclass(frozen=True)
class ConfigItem:
    @staticmethod
    def config_list_prepend(namespace, group, dest, value):
        "Prepend value to namespace.<dest>"

        assert not group

        old = getattr(namespace, dest, [])
        setattr(namespace, dest, value + old)

    @staticmethod
    def config_set_if_unset(namespace, group, dest, value):
        "Set namespace.<dest> to value only if it was None"

        assert not group

        if getattr(namespace, dest) is None:
            setattr(namespace, dest, value)

    @staticmethod
    def config_set_group(namespace, group, dest, value):
        "Set namespace.<dest>[idx] to value, with idx derived from group"

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
    name: typing.Union[str, typing.List[str]]
    dest: str = None
    metavar: str = None
    type: typing.Callable = None
    nargs: str = None
    action: typing.Callable = None
    default: typing.Any = None
    version: str = None
    choices: typing.List[str] = None
    help: str = None

    # metadata for config file parsing
    config_key: str = None
    config_push: typing.Callable[..., ...] = config_set_if_unset

    def _names(self) -> typing.Tuple[str]:
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

        if self.action == argparse.BooleanOptionalAction:
            # We need to handle this case separately: the options are called
            # --foo and --no-foo, and no argument is parsed. But in the config
            # file, we have Foo=yes or Foo=no.
            conv = self.parse_boolean
        elif self.type:
            conv = self.type
        else:
            conv = lambda s:s

        if self.nargs == '*':
            value = [conv(v) for v in value.split()]
        else:
            value = conv(value)

        self.config_push(namespace, group, dest, value)

    def config_example(self) -> typing.Tuple[typing.Optional[str]]:
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


CONFIG_ITEMS = [
    ConfigItem(
        '--version',
        action = 'version',
        version = f'ukify {__version__}',
    ),

    ConfigItem(
        '--summary',
        help = 'print parsed config and exit',
        action = 'store_true',
    ),

    ConfigItem(
        'linux',
        metavar = 'LINUX',
        type = pathlib.Path,
        help = 'vmlinuz file [.linux section]',
        config_key = 'UKI/Linux',
    ),

    ConfigItem(
        'initrd',
        metavar = 'INITRD…',
        type = pathlib.Path,
        nargs = '*',
        help = 'initrd files [.initrd section]',
        config_key = 'UKI/Initrd',
        config_push = ConfigItem.config_list_prepend,
    ),

    ConfigItem(
        ('--config', '-c'),
        metavar = 'PATH',
        help = 'configuration file',
    ),

    ConfigItem(
        '--cmdline',
        metavar = 'TEXT|@PATH',
        help = 'kernel command line [.cmdline section]',
        config_key = 'UKI/Cmdline',
    ),

    ConfigItem(
        '--os-release',
        metavar = 'TEXT|@PATH',
        help = 'path to os-release file [.osrel section]',
        config_key = 'UKI/OSRelease',
    ),

    ConfigItem(
        '--devicetree',
        metavar = 'PATH',
        type = pathlib.Path,
        help = 'Device Tree file [.dtb section]',
        config_key = 'UKI/DeviceTree',
    ),
    ConfigItem(
        '--splash',
        metavar = 'BMP',
        type = pathlib.Path,
        help = 'splash image bitmap file [.splash section]',
        config_key = 'UKI/Splash',
    ),
    ConfigItem(
        '--pcrpkey',
        metavar = 'KEY',
        type = pathlib.Path,
        help = 'embedded public key to seal secrets to [.pcrpkey section]',
        config_key = 'UKI/PCRPKey',
    ),
    ConfigItem(
        '--uname',
        metavar='VERSION',
        help='"uname -r" information [.uname section]',
        config_key = 'UKI/Uname',
    ),

    ConfigItem(
        '--efi-arch',
        metavar = 'ARCH',
        choices = ('ia32', 'x64', 'arm', 'aa64', 'riscv64'),
        help = 'target EFI architecture',
        config_key = 'UKI/EFIArch',
    ),

    ConfigItem(
        '--stub',
        type = pathlib.Path,
        help = 'path to the sd-stub file [.text,.data,… sections]',
        config_key = 'UKI/Stub',
    ),

    ConfigItem(
        '--section',
        dest = 'sections',
        metavar = 'NAME:TEXT|@PATH',
        type = Section.parse_arg,
        action = 'append',
        default = [],
        help = 'additional section as name and contents [NAME section]',
    ),

    ConfigItem(
        '--pcr-banks',
        metavar = 'BANK…',
        type = parse_banks,
        config_key = 'UKI/PCRBanks',
    ),

    ConfigItem(
        '--signing-engine',
        metavar = 'ENGINE',
        help = 'OpenSSL engine to use for signing',
        config_key = 'UKI/SigningEngine',
    ),
    ConfigItem(
        '--secureboot-private-key',
        dest = 'sb_key',
        help = 'path to key file or engine-specific designation for SB signing',
        config_key = 'UKI/SecureBootPrivateKey',
    ),
    ConfigItem(
        '--secureboot-certificate',
        dest = 'sb_cert',
        help = 'path to certificate file or engine-specific designation for SB signing',
        config_key = 'UKI/SecureBootCertificate',
    ),

    ConfigItem(
        '--sign-kernel',
        action = argparse.BooleanOptionalAction,
        help = 'Sign the embedded kernel',
        config_key = 'UKI/SignKernel',
    ),

    ConfigItem(
        '--pcr-private-key',
        dest = 'pcr_private_keys',
        metavar = 'PATH',
        type = pathlib.Path,
        action = 'append',
        help = 'private part of the keypair for signing PCR signatures',
        config_key = 'PCRSignature:/PCRPrivateKey',
        config_push = ConfigItem.config_set_group,
    ),
    ConfigItem(
        '--pcr-public-key',
        dest = 'pcr_public_keys',
        metavar = 'PATH',
        type = pathlib.Path,
        action = 'append',
        help = 'public part of the keypair for signing PCR signatures',
        config_key = 'PCRSignature:/PCRPublicKey',
        config_push = ConfigItem.config_set_group,
    ),
    ConfigItem(
        '--phases',
        dest = 'phase_path_groups',
        metavar = 'PHASE-PATH…',
        type = parse_phase_paths,
        action = 'append',
        help = 'phase-paths to create signatures for',
        config_key = 'PCRSignature:/Phases',
        config_push = ConfigItem.config_set_group,
    ),

    ConfigItem(
        '--tools',
        type = pathlib.Path,
        action = 'append',
        help = 'Directories to search for tools (systemd-measure, …)',
    ),

    ConfigItem(
        ('--output', '-o'),
        type = pathlib.Path,
        help = 'output file path',
    ),

    ConfigItem(
        '--measure',
        action = argparse.BooleanOptionalAction,
        help = 'print systemd-measure output for the UKI',
    ),
]

CONFIGFILE_ITEMS = { item.config_key:item
                     for item in CONFIG_ITEMS
                     if item.config_key }


def apply_config(namespace, filename=None):
    if filename is None:
        filename = namespace.config
    if filename is None:
        return

    # Fill in ._groups based on --pcr-public-key=, --pcr-private-key=, and --phases=.
    assert '_groups' not in namespace
    n_pcr_priv = len(namespace.pcr_private_keys or ())
    namespace._groups = list(range(n_pcr_priv))

    cp = configparser.ConfigParser(
        comment_prefixes='#',
        inline_comment_prefixes='#',
        delimiters='=',
        empty_lines_in_values=False,
        interpolation=None,
        strict=False)
    # Do not make keys lowercase
    cp.optionxform = lambda option: option

    cp.read(filename)

    for section_name, section in cp.items():
        idx = section_name.find(':')
        if idx > 0:
            section_name, group = section_name[:idx+1], section_name[idx+1:]
            if ':' in group:
                raise ValueError('Section name cannot contain more than one ":"')
        else:
            group = None
        for key, value in section.items():
            if item := CONFIGFILE_ITEMS.get(f'{section_name}/{key}'):
                item.apply_config(namespace, section_name, group, key, value)
            else:
                print(f'Unknown config setting [{section_name}] {key}=')


def config_example():
    prev_section = None
    for item in CONFIG_ITEMS:
        section, key, value = item.config_example()
        if section:
            if prev_section != section:
                if prev_section:
                    yield ''
                yield f'[{section}]'
                prev_section = section
            yield f'{key} = {value}'


def create_parser():
    p = argparse.ArgumentParser(
        description='Build and sign Unified Kernel Images',
        allow_abbrev=False,
        usage='''\
ukify [options…] LINUX INITRD…
''',
        epilog='\n  '.join(('config file:', *config_example())),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    for item in CONFIG_ITEMS:
        item.add_to(p)

    # Suppress printing of usage synopsis on errors
    p.error = lambda message: p.exit(2, f'{p.prog}: error: {message}\n')

    return p


def finalize_options(opts):
    if opts.cmdline and opts.cmdline.startswith('@'):
        opts.cmdline = pathlib.Path(opts.cmdline[1:])
    elif opts.cmdline:
        # Drop whitespace from the commandline. If we're reading from a file,
        # we copy the contents verbatim. But configuration specified on the commandline
        # or in the config file may contain additional whitespace that has no meaning.
        opts.cmdline = ' '.join(opts.cmdline.split())

    if opts.os_release and opts.os_release.startswith('@'):
        opts.os_release = pathlib.Path(opts.os_release[1:])
    elif opts.os_release is None:
        p = pathlib.Path('/etc/os-release')
        if not p.exists():
            p = pathlib.Path('/usr/lib/os-release')
        opts.os_release = p

    if opts.efi_arch is None:
        opts.efi_arch = guess_efi_arch()

    if opts.stub is None:
        opts.stub = pathlib.Path(f'/usr/lib/systemd/boot/efi/linux{opts.efi_arch}.efi.stub')

    if opts.signing_engine is None:
        if opts.sb_key:
            opts.sb_key = pathlib.Path(opts.sb_key)
        if opts.sb_cert:
            opts.sb_cert = pathlib.Path(opts.sb_cert)

    if bool(opts.sb_key) ^ bool(opts.sb_cert):
        raise ValueError('--secureboot-private-key= and --secureboot-certificate= must be specified together')

    if opts.sign_kernel and not opts.sb_key:
        raise ValueError('--sign-kernel requires --secureboot-private-key= and --secureboot-certificate= to be specified')

    if opts.output is None:
        suffix = '.efi' if opts.sb_key else '.unsigned.efi'
        opts.output = opts.linux.name + suffix

    for section in opts.sections:
        section.check_name()

    if opts.summary:
        # TODO: replace pprint() with some fancy formatting.
        pprint.pprint(vars(opts))
        sys.exit()


def parse_args(args=None):
    p = create_parser()
    opts = p.parse_args(args)

    # Check that --pcr-public-key=, --pcr-private-key=, and --phases=
    # have either the same number of arguments are are not specified at all.
    n_pcr_pub = None if opts.pcr_public_keys is None else len(opts.pcr_public_keys)
    n_pcr_priv = None if opts.pcr_private_keys is None else len(opts.pcr_private_keys)
    n_phase_path_groups = None if opts.phase_path_groups is None else len(opts.phase_path_groups)
    if n_pcr_pub is not None and n_pcr_pub != n_pcr_priv:
        raise ValueError('--pcr-public-key= specifications must match --pcr-private-key=')
    if n_phase_path_groups is not None and n_phase_path_groups != n_pcr_priv:
        raise ValueError('--phases= specifications must match --pcr-private-key=')

    apply_config(opts)

    finalize_options(opts)

    return opts


def main():
    opts = parse_args()
    check_inputs(opts)
    make_uki(opts)


if __name__ == '__main__':
    main()
