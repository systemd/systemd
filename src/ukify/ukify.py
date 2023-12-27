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

# pylint: disable=import-outside-toplevel,consider-using-with,unused-argument
# pylint: disable=unnecessary-lambda-assignment

import argparse
import configparser
import contextlib
import collections
import dataclasses
import datetime
import fnmatch
import itertools
import json
import os
import pathlib
import pprint
import pydoc
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import struct
from hashlib import sha256
from typing import (Any,
                    Callable,
                    IO,
                    Optional,
                    Sequence,
                    Union)

import pefile  # type: ignore

__version__ = '{{PROJECT_VERSION}} ({{GIT_VERSION}})'

EFI_ARCH_MAP = {
    # host_arch glob : [efi_arch, 32_bit_efi_arch if mixed mode is supported]
    'x86_64'       : ['x64', 'ia32'],
    'i[3456]86'    : ['ia32'],
    'aarch64'      : ['aa64'],
    'armv[45678]*l': ['arm'],
    'loongarch32'  : ['loongarch32'],
    'loongarch64'  : ['loongarch64'],
    'riscv32'      : ['riscv32'],
    'riscv64'      : ['riscv64'],
}
EFI_ARCHES: list[str] = sum(EFI_ARCH_MAP.values(), [])

# Default configuration directories and file name.
# When the user does not specify one, the directories are searched in this order and the first file found is used.
DEFAULT_CONFIG_DIRS = ['/run/systemd', '/etc/systemd', '/usr/local/lib/systemd', '/usr/lib/systemd']
DEFAULT_CONFIG_FILE = 'ukify.conf'

class Style:
    bold = "\033[0;1;39m" if sys.stderr.isatty() else ""
    gray = "\033[0;38;5;245m" if sys.stderr.isatty() else ""
    red = "\033[31;1m" if sys.stderr.isatty() else ""
    yellow = "\033[33;1m" if sys.stderr.isatty() else ""
    reset = "\033[0m" if sys.stderr.isatty() else ""


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

    # print(f'Host arch {arch!r}, EFI arch {efi_arch!r}')
    return efi_arch


def page(text: str, enabled: Optional[bool]) -> None:
    if enabled:
        # Initialize less options from $SYSTEMD_LESS or provide a suitable fallback.
        os.environ['LESS'] = os.getenv('SYSTEMD_LESS', 'FRSXMK')
        pydoc.pager(text)
    else:
        print(text)


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

def get_zboot_kernel(f):
    """Decompress zboot efistub kernel if compressed. Return contents."""
    # See linux/drivers/firmware/efi/libstub/Makefile.zboot
    # and linux/drivers/firmware/efi/libstub/zboot-header.S

    # Reading 4 bytes from address 0x08 is the starting offset of compressed data
    f.seek(8)
    _start = f.read(4)
    start = struct.unpack('<i', _start)[0]

    # Reading 4 bytes from address 0x0c is the size of compressed data,
    # but it needs to be corrected according to the compressed type.
    f.seek(0xc)
    _sizes = f.read(4)
    size = struct.unpack('<i', _sizes)[0]

    # Read 6 bytes from address 0x18, which is a nul-terminated
    # string representing the compressed type.
    f.seek(0x18)
    comp_type = f.read(6)
    f.seek(start)
    if comp_type.startswith(b'gzip'):
        gzip = try_import('gzip')
        return gzip.open(f).read(size)
    if comp_type.startswith(b'lz4'):
        lz4 = try_import('lz4.frame', 'lz4')
        return lz4.frame.decompress(f.read(size))
    if comp_type.startswith(b'lzma'):
        lzma = try_import('lzma')
        return lzma.open(f).read(size)
    if comp_type.startswith(b'lzo'):
        raise NotImplementedError('lzo decompression not implemented')
    if comp_type.startswith(b'xzkern'):
        raise NotImplementedError('xzkern decompression not implemented')
    if comp_type.startswith(b'zstd22'):
        zstd = try_import('zstd')
        return zstd.uncompress(f.read(size))

def maybe_decompress(filename):
    """Decompress file if compressed. Return contents."""
    f = open(filename, 'rb')
    start = f.read(4)
    f.seek(0)

    if start.startswith(b'\x7fELF'):
        # not compressed
        return f.read()

    if start.startswith(b'MZ'):
        f.seek(4)
        img_type = f.read(4)
        if img_type.startswith(b'zimg'):
            # zboot efistub kernel
            return get_zboot_kernel(f)
        else:
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

DEFAULT_SECTIONS_TO_SHOW = {
        '.linux'    : 'binary',
        '.initrd'   : 'binary',
        '.splash'   : 'binary',
        '.dtb'      : 'binary',
        '.cmdline'  : 'text',
        '.osrel'    : 'text',
        '.uname'    : 'text',
        '.pcrpkey'  : 'text',
        '.pcrsig'   : 'text',
        '.sbat'     : 'text',
        '.sbom'     : 'binary',
}

@dataclasses.dataclass
class Section:
    name: str
    content: Optional[pathlib.Path]
    tmpfile: Optional[IO] = None
    measure: bool = False
    output_mode: Optional[str] = None

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
    def parse_input(cls, s):
        try:
            name, contents, *rest = s.split(':')
        except ValueError as e:
            raise ValueError(f'Cannot parse section spec (name or contents missing): {s!r}') from e
        if rest:
            raise ValueError(f'Cannot parse section spec (extraneous parameters): {s!r}')

        if contents.startswith('@'):
            contents = pathlib.Path(contents[1:])

        sec = cls.create(name, contents)
        sec.check_name()
        return sec

    @classmethod
    def parse_output(cls, s):
        if not (m := re.match(r'([a-zA-Z0-9_.]+):(text|binary)(?:@(.+))?', s)):
            raise ValueError(f'Cannot parse section spec: {s!r}')

        name, ttype, out = m.groups()
        out = pathlib.Path(out) if out else None

        return cls.create(name, out, output_mode=ttype)

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
    executable: list[Union[pathlib.Path, str]]
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


def check_cert_and_keys_nonexistent(opts):
    # Raise if any of the keys and certs are found on disk
    paths = itertools.chain(
        (opts.sb_key, opts.sb_cert),
        *((priv_key, pub_key)
          for priv_key, pub_key, _ in key_path_groups(opts)))
    for path in paths:
        if path and path.exists():
            raise ValueError(f'{path} is present')


def find_tool(name, fallback=None, opts=None):
    if opts and opts.tools:
        for d in opts.tools:
            tool = d / name
            if tool.exists():
                return tool

    if shutil.which(name) is not None:
        return name

    if fallback is None:
        print(f"Tool {name} not installed!")

    return fallback

def combine_signatures(pcrsigs):
    combined = collections.defaultdict(list)
    for pcrsig in pcrsigs:
        for bank, sigs in pcrsig.items():
            for sig in sigs:
                if sig not in combined[bank]:
                    combined[bank] += [sig]
    return json.dumps(combined)


def key_path_groups(opts):
    if not opts.pcr_private_keys:
        return

    n_priv = len(opts.pcr_private_keys)
    pub_keys = opts.pcr_public_keys or [None] * n_priv
    pp_groups = opts.phase_path_groups or [None] * n_priv

    yield from zip(opts.pcr_private_keys,
                   pub_keys,
                   pp_groups)


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

        for priv_key, pub_key, group in key_path_groups(opts):
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
    if not initrds:
        return None
    if len(initrds) == 1:
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


class PEError(Exception):
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
    # pylint thinks that Structure doesn't have various members that it has…
    # pylint: disable=no-member

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
        raise PEError(f'pefile warnings treated as errors: {warnings}')

    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
    if security.VirtualAddress != 0:
        # We could strip the signatures, but why would anyone sign the stub?
        raise PEError('Stub image is signed, refusing.')

    for section in uki.sections:
        new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__, pe=pe)
        new_section.__unpack__(b'\0' * new_section.sizeof())

        offset = pe.sections[-1].get_file_offset() + new_section.sizeof()
        if offset + new_section.sizeof() > pe.OPTIONAL_HEADER.SizeOfHeaders:
            raise PEError(f'Not enough header space to add section {section.name}.')

        assert section.content
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

        # Special case, mostly for .sbat: the stub will already have a .sbat section, but we want to append
        # the one from the kernel to it. It should be small enough to fit in the existing section, so just
        # swap the data.
        for i, s in enumerate(pe.sections):
            if s.Name.rstrip(b"\x00").decode() == section.name:
                if new_section.Misc_VirtualSize > s.SizeOfRawData:
                    raise PEError(f'Not enough space in existing section {section.name} to append new data.')

                padding = bytes(new_section.SizeOfRawData - new_section.Misc_VirtualSize)
                pe.__data__ = pe.__data__[:s.PointerToRawData] + data + padding + pe.__data__[pe.sections[i+1].PointerToRawData:]
                s.SizeOfRawData = new_section.SizeOfRawData
                s.Misc_VirtualSize = new_section.Misc_VirtualSize
                break
        else:
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

def merge_sbat(input_pe: [pathlib.Path], input_text: [str]) -> str:
    sbat = []

    for f in input_pe:
        try:
            pe = pefile.PE(f, fast_load=True)
        except pefile.PEFormatError:
            print(f"{f} is not a valid PE file, not extracting SBAT section.")
            continue

        for section in pe.sections:
            if section.Name.rstrip(b"\x00").decode() == ".sbat":
                split = section.get_data().rstrip(b"\x00").decode().splitlines()
                if not split[0].startswith('sbat,'):
                    print(f"{f} does not contain a valid SBAT section, skipping.")
                    continue
                # Filter out the sbat line, we'll add it back later, there needs to be only one and it
                # needs to be first.
                sbat += split[1:]

    for t in input_text:
        if t.startswith('@'):
            t = pathlib.Path(t[1:]).read_text()
        split = t.splitlines()
        if not split[0].startswith('sbat,'):
            print(f"{t} does not contain a valid SBAT section, skipping.")
            continue
        sbat += split[1:]

    return 'sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n' + '\n'.join(sbat) + "\n\x00"

def signer_sign(cmd):
    print('+', shell_join(cmd))
    subprocess.check_call(cmd)

def find_sbsign(opts=None):
    return find_tool('sbsign', opts=opts)

def sbsign_sign(sbsign_tool, input_f, output_f, opts=None):
    sign_invocation = [
        sbsign_tool,
        '--key', opts.sb_key,
        '--cert', opts.sb_cert,
        input_f,
        '--output', output_f,
    ]
    if opts.signing_engine is not None:
        sign_invocation += ['--engine', opts.signing_engine]
    signer_sign(sign_invocation)

def find_pesign(opts=None):
    return find_tool('pesign', opts=opts)

def pesign_sign(pesign_tool, input_f, output_f, opts=None):
    sign_invocation = [
        pesign_tool, '-s', '--force',
        '-n', opts.sb_certdir,
        '-c', opts.sb_cert_name,
        '-i', input_f,
        '-o', output_f,
    ]
    signer_sign(sign_invocation)

SBVERIFY = {
    'name': 'sbverify',
    'option': '--list',
    'output': 'No signature table present',
}

PESIGCHECK = {
    'name': 'pesign',
    'option': '-i',
    'output': 'No signatures found.',
    'flags': '-S'
}

def verify(tool, opts):
    verify_tool = find_tool(tool['name'], opts=opts)
    cmd = [
        verify_tool,
        tool['option'],
        opts.linux,
    ]
    if 'flags' in tool:
        cmd.append(tool['flags'])

    print('+', shell_join(cmd))
    info = subprocess.check_output(cmd, text=True)

    return tool['output'] in info

def make_uki(opts):
    # kernel payload signing

    sign_tool = None
    sign_args_present = opts.sb_key or opts.sb_cert_name
    sign_kernel = opts.sign_kernel
    sign = None
    linux = opts.linux

    if sign_args_present:
        if opts.signtool == 'sbsign':
            sign_tool = find_sbsign(opts=opts)
            sign = sbsign_sign
            verify_tool = SBVERIFY
        else:
            sign_tool = find_pesign(opts=opts)
            sign = pesign_sign
            verify_tool = PESIGCHECK

        if sign_tool is None:
            raise ValueError(f'{opts.signtool}, required for signing, is not installed')

        if sign_kernel is None and opts.linux is not None:
            # figure out if we should sign the kernel
            sign_kernel = verify(verify_tool, opts)

        if sign_kernel:
            linux_signed = tempfile.NamedTemporaryFile(prefix='linux-signed')
            linux = pathlib.Path(linux_signed.name)
            sign(sign_tool, opts.linux, linux, opts=opts)

    if opts.uname is None and opts.linux is not None:
        print('Kernel version not specified, starting autodetection 😖.')
        opts.uname = Uname.scrape(opts.linux, opts=opts)

    uki = UKI(opts.stub)
    initrd = join_initrds(opts.initrd)

    pcrpkey = opts.pcrpkey
    if pcrpkey is None:
        if opts.pcr_public_keys and len(opts.pcr_public_keys) == 1:
            pcrpkey = opts.pcr_public_keys[0]
        elif opts.pcr_private_keys and len(opts.pcr_private_keys) == 1:
            from cryptography.hazmat.primitives import serialization
            privkey = serialization.load_pem_private_key(opts.pcr_private_keys[0].read_bytes(), password=None)
            pcrpkey = privkey.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

    sections = [
        # name,      content,         measure?
        ('.osrel',   opts.os_release, True ),
        ('.cmdline', opts.cmdline,    True ),
        ('.dtb',     opts.devicetree, True ),
        ('.uname',   opts.uname,      True ),
        ('.splash',  opts.splash,     True ),
        ('.pcrpkey', pcrpkey,         True ),
        ('.initrd',  initrd,          True ),

        # linux shall be last to leave breathing room for decompression.
        # We'll add it later.
    ]

    for name, content, measure in sections:
        if content:
            uki.add_section(Section.create(name, content, measure=measure))

    # systemd-measure doesn't know about those extra sections
    for section in opts.sections:
        uki.add_section(section)

    if linux is not None:
        # Merge the .sbat sections from stub, kernel and parameter, so that revocation can be done on either.
        uki.add_section(Section.create('.sbat', merge_sbat([opts.stub, linux], opts.sbat), measure=True))
    else:
        # Addons don't use the stub so we add SBAT manually
        if not opts.sbat:
            opts.sbat = ["""sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
uki,1,UKI,uki,1,https://www.freedesktop.org/software/systemd/man/systemd-stub.html
"""]
        uki.add_section(Section.create('.sbat', merge_sbat([], opts.sbat), measure=False))

    # PCR measurement and signing

    # We pass in the contents for .linux separately because we need them to do the measurement but can't add
    # the section yet because we want .linux to be the last section. Make sure any other sections are added
    # before this function is called.
    call_systemd_measure(uki, linux, opts=opts)

    # UKI creation

    if linux is not None:
        uki.add_section(Section.create('.linux', linux, measure=True))

    if sign_args_present:
        unsigned = tempfile.NamedTemporaryFile(prefix='uki')
        unsigned_output = unsigned.name
    else:
        unsigned_output = opts.output

    pe_add_sections(uki, unsigned_output)

    # UKI signing

    if sign_args_present:
        assert sign
        sign(sign_tool, unsigned_output, opts.output, opts=opts)

        # We end up with no executable bits, let's reapply them
        os.umask(umask := os.umask(0))
        os.chmod(opts.output, 0o777 & ~umask)

    print(f"Wrote {'signed' if sign_args_present else 'unsigned'} {opts.output}")


@contextlib.contextmanager
def temporary_umask(mask: int):
    # Drop <mask> bits from umask
    old = os.umask(0)
    os.umask(old | mask)
    try:
        yield
    finally:
        os.umask(old)


def generate_key_cert_pair(
        common_name: str,
        valid_days: int,
        keylength: int = 2048,
) -> tuple[bytes]:

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import rsa

    # We use a keylength of 2048 bits. That is what Microsoft documents as
    # supported/expected:
    # https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance?view=windows-11#12-public-key-cryptography

    now = datetime.datetime.now(datetime.UTC)

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=keylength,
    )
    cert = x509.CertificateBuilder(
    ).subject_name(
        x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)])
    ).issuer_name(
        x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)])
    ).not_valid_before(
        now,
    ).not_valid_after(
        now + datetime.timedelta(days=valid_days)
    ).serial_number(
        x509.random_serial_number()
    ).public_key(
        key.public_key()
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).sign(
        private_key=key,
        algorithm=hashes.SHA256(),
    )

    cert_pem = cert.public_bytes(
        encoding=serialization.Encoding.PEM,
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return key_pem, cert_pem


def generate_priv_pub_key_pair(keylength : int = 2048) -> tuple[bytes]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=keylength,
    )
    priv_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_key_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return priv_key_pem, pub_key_pem


def generate_keys(opts):
    work = False

    # This will generate keys and certificates and write them to the paths that
    # are specified as input paths.
    if opts.sb_key or opts.sb_cert:
        fqdn = socket.getfqdn()
        cn = f'SecureBoot signing key on host {fqdn}'
        key_pem, cert_pem = generate_key_cert_pair(
            common_name=cn,
            valid_days=opts.sb_cert_validity,
        )
        print(f'Writing SecureBoot private key to {opts.sb_key}')
        with temporary_umask(0o077):
            opts.sb_key.write_bytes(key_pem)
        print(f'Writing SecureBoot certificate to {opts.sb_cert}')
        opts.sb_cert.write_bytes(cert_pem)

        work = True

    for priv_key, pub_key, _ in key_path_groups(opts):
        priv_key_pem, pub_key_pem = generate_priv_pub_key_pair()

        print(f'Writing private key for PCR signing to {priv_key}')
        with temporary_umask(0o077):
            priv_key.write_bytes(priv_key_pem)
        if pub_key:
            print(f'Writing public key for PCR signing to {pub_key}')
            pub_key.write_bytes(pub_key_pem)

        work = True

    if not work:
        raise ValueError('genkey: --secureboot-private-key=/--secureboot-certificate= or --pcr-private-key/--pcr-public-key must be specified')


def inspect_section(opts, section):
    name = section.Name.rstrip(b"\x00").decode()

    # find the config for this section in opts and whether to show it
    config = opts.sections_by_name.get(name, None)
    show = (config or
            opts.all or
            (name in DEFAULT_SECTIONS_TO_SHOW and not opts.sections))
    if not show:
        return name, None

    ttype = config.output_mode if config else DEFAULT_SECTIONS_TO_SHOW.get(name, 'binary')

    size = section.Misc_VirtualSize
    # TODO: Use ignore_padding once we can depend on a newer version of pefile
    data = section.get_data(length=size)
    digest = sha256(data).hexdigest()

    struct = {
        'size' : size,
        'sha256' : digest,
    }

    if ttype == 'text':
        try:
            struct['text'] = data.decode()
        except UnicodeDecodeError as e:
            print(f"Section {name!r} is not valid text: {e}")
            struct['text'] = '(not valid UTF-8)'

    if config and config.content:
        assert isinstance(config.content, pathlib.Path)
        config.content.write_bytes(data)

    if opts.json == 'off':
        print(f"{name}:\n  size: {size} bytes\n  sha256: {digest}")
        if ttype == 'text':
            text = textwrap.indent(struct['text'].rstrip(), ' ' * 4)
            print(f"  text:\n{text}")

    return name, struct


def inspect_sections(opts):
    indent = 4 if opts.json == 'pretty' else None

    for file in opts.files:
        pe = pefile.PE(file, fast_load=True)
        gen = (inspect_section(opts, section) for section in pe.sections)
        descs = {key:val for (key, val) in gen if val}
        if opts.json != 'off':
            json.dump(descs, sys.stdout, indent=indent)


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
    def config_set(
            namespace: argparse.Namespace,
            group: Optional[str],
            dest: str,
            value: Any,
    ) -> None:
        "Set namespace.<dest> to value only if it was None"

        assert not group

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


VERBS = ('build', 'genkey', 'inspect')

CONFIG_ITEMS = [
    ConfigItem(
        'positional',
        metavar = 'VERB',
        nargs = '*',
        help = argparse.SUPPRESS,
    ),

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
        '--linux',
        type = pathlib.Path,
        help = 'vmlinuz file [.linux section]',
        config_key = 'UKI/Linux',
    ),

    ConfigItem(
        '--initrd',
        metavar = 'INITRD',
        type = pathlib.Path,
        action = 'append',
        help = 'initrd file [part of .initrd section]',
        config_key = 'UKI/Initrd',
        config_push = ConfigItem.config_list_prepend,
    ),

    ConfigItem(
        ('--config', '-c'),
        metavar = 'PATH',
        type = pathlib.Path,
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
        '--sbat',
        metavar = 'TEXT|@PATH',
        help = 'SBAT policy [.sbat section]',
        default = [],
        action = 'append',
        config_key = 'UKI/SBAT',
    ),

    ConfigItem(
        '--section',
        dest = 'sections',
        metavar = 'NAME:TEXT|@PATH',
        action = 'append',
        default = [],
        help = 'section as name and contents [NAME section] or section to print',
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
        '--signtool',
        choices = ('sbsign', 'pesign'),
        dest = 'signtool',
        help = 'whether to use sbsign or pesign. It will also be inferred by the other \
        parameters given: when using --secureboot-{private-key/certificate}, sbsign \
        will be used, otherwise pesign will be used',
        config_key = 'UKI/SecureBootSigningTool',
    ),
    ConfigItem(
        '--secureboot-private-key',
        dest = 'sb_key',
        help = 'required by --signtool=sbsign. Path to key file or engine-specific designation for SB signing',
        config_key = 'UKI/SecureBootPrivateKey',
    ),
    ConfigItem(
        '--secureboot-certificate',
        dest = 'sb_cert',
        help = 'required by --signtool=sbsign. sbsign needs a path to certificate file or engine-specific designation for SB signing',
        config_key = 'UKI/SecureBootCertificate',
    ),
    ConfigItem(
        '--secureboot-certificate-dir',
        dest = 'sb_certdir',
        default = '/etc/pki/pesign',
        help = 'required by --signtool=pesign. Path to nss certificate database directory for PE signing. Default is /etc/pki/pesign',
        config_key = 'UKI/SecureBootCertificateDir',
        config_push = ConfigItem.config_set
    ),
    ConfigItem(
        '--secureboot-certificate-name',
        dest = 'sb_cert_name',
        help = 'required by --signtool=pesign. pesign needs a certificate nickname of nss certificate database entry to use for PE signing',
        config_key = 'UKI/SecureBootCertificateName',
    ),
    ConfigItem(
        '--secureboot-certificate-validity',
        metavar = 'DAYS',
        type = int,
        dest = 'sb_cert_validity',
        default = 365 * 10,
        help = "period of validity (in days) for a certificate created by 'genkey'",
        config_key = 'UKI/SecureBootCertificateValidity',
        config_push = ConfigItem.config_set
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

    ConfigItem(
        '--all',
        help = 'print all sections',
        action = 'store_true',
    ),
]

CONFIGFILE_ITEMS = { item.config_key:item
                     for item in CONFIG_ITEMS
                     if item.config_key }


def apply_config(namespace, filename=None):
    if filename is None:
        if namespace.config:
            # Config set by the user, use that.
            filename = namespace.config
            print(f'Using config file: {filename}')
        else:
            # Try to look for a config file then use the first one found.
            for config_dir in DEFAULT_CONFIG_DIRS:
                filename = pathlib.Path(config_dir) / DEFAULT_CONFIG_FILE
                if filename.is_file():
                    # Found a config file, use it.
                    print(f'Using found config file: {filename}')
                    break
            else:
                # No config file specified or found, nothing to do.
                return

    # Fill in ._groups based on --pcr-public-key=, --pcr-private-key=, and --phases=.
    assert '_groups' not in namespace
    n_pcr_priv = len(namespace.pcr_private_keys or ())
    namespace._groups = list(range(n_pcr_priv))  # pylint: disable=protected-access

    cp = configparser.ConfigParser(
        comment_prefixes='#',
        inline_comment_prefixes='#',
        delimiters='=',
        empty_lines_in_values=False,
        interpolation=None,
        strict=False)
    # Do not make keys lowercase
    cp.optionxform = lambda option: option

    # The API is not great.
    read = cp.read(filename)
    if not read:
        raise IOError(f'Failed to read {filename}')

    for section_name, section in cp.items():
        idx = section_name.find(':')
        if idx >= 0:
            section_name, group = section_name[:idx+1], section_name[idx+1:]
            if not section_name or not group:
                raise ValueError('Section name components cannot be empty')
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


def create_parser():
    p = argparse.ArgumentParser(
        description='Build and sign Unified Kernel Images',
        usage='\n  ' + textwrap.dedent('''\
          ukify {b}build{e} [--linux=LINUX] [--initrd=INITRD] [options…]
            ukify {b}genkey{e} [options…]
            ukify {b}inspect{e} FILE… [options…]
        ''').format(b=Style.bold, e=Style.reset),
        allow_abbrev=False,
        add_help=False,
        epilog='\n  '.join(('config file:', *config_example())),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    for item in CONFIG_ITEMS:
        item.add_to(p)

    # Suppress printing of usage synopsis on errors
    p.error = lambda message: p.exit(2, f'{p.prog}: error: {message}\n')

    # Make --help paged
    p.add_argument(
        '-h', '--help',
        action=PagerHelpAction,
        help='show this help message and exit',
    )

    return p


def finalize_options(opts):
    # Figure out which syntax is being used, one of:
    # ukify verb --arg --arg --arg
    # ukify linux initrd…
    if len(opts.positional) >= 1 and opts.positional[0] == 'inspect':
        opts.verb = opts.positional[0]
        opts.files = opts.positional[1:]
        if not opts.files:
            raise ValueError('file(s) to inspect must be specified')
        if len(opts.files) > 1 and opts.json != 'off':
            # We could allow this in the future, but we need to figure out the right structure
            raise ValueError('JSON output is not allowed with multiple files')
    elif len(opts.positional) == 1 and opts.positional[0] in VERBS:
        opts.verb = opts.positional[0]
    elif opts.linux or opts.initrd:
        raise ValueError('--linux/--initrd options cannot be used with positional arguments')
    else:
        print("Assuming obsolete command line syntax with no verb. Please use 'build'.")
        if opts.positional:
            opts.linux = pathlib.Path(opts.positional[0])
        # If we have initrds from parsing config files, append our positional args at the end
        opts.initrd = (opts.initrd or []) + [pathlib.Path(arg) for arg in opts.positional[1:]]
        opts.verb = 'build'

    # Check that --pcr-public-key=, --pcr-private-key=, and --phases=
    # have either the same number of arguments are are not specified at all.
    n_pcr_pub = None if opts.pcr_public_keys is None else len(opts.pcr_public_keys)
    n_pcr_priv = None if opts.pcr_private_keys is None else len(opts.pcr_private_keys)
    n_phase_path_groups = None if opts.phase_path_groups is None else len(opts.phase_path_groups)
    if n_pcr_pub is not None and n_pcr_pub != n_pcr_priv:
        raise ValueError('--pcr-public-key= specifications must match --pcr-private-key=')
    if n_phase_path_groups is not None and n_phase_path_groups != n_pcr_priv:
        raise ValueError('--phases= specifications must match --pcr-private-key=')

    if opts.cmdline and opts.cmdline.startswith('@'):
        opts.cmdline = pathlib.Path(opts.cmdline[1:])
    elif opts.cmdline:
        # Drop whitespace from the command line. If we're reading from a file,
        # we copy the contents verbatim. But configuration specified on the command line
        # or in the config file may contain additional whitespace that has no meaning.
        opts.cmdline = ' '.join(opts.cmdline.split())

    if opts.os_release and opts.os_release.startswith('@'):
        opts.os_release = pathlib.Path(opts.os_release[1:])
    elif not opts.os_release and opts.linux:
        p = pathlib.Path('/etc/os-release')
        if not p.exists():
            p = pathlib.Path('/usr/lib/os-release')
        opts.os_release = p

    if opts.efi_arch is None:
        opts.efi_arch = guess_efi_arch()

    if opts.stub is None:
        if opts.linux is not None:
            opts.stub = pathlib.Path(f'/usr/lib/systemd/boot/efi/linux{opts.efi_arch}.efi.stub')
        else:
            opts.stub = pathlib.Path(f'/usr/lib/systemd/boot/efi/addon{opts.efi_arch}.efi.stub')

    if opts.signing_engine is None:
        if opts.sb_key:
            opts.sb_key = pathlib.Path(opts.sb_key)
        if opts.sb_cert:
            opts.sb_cert = pathlib.Path(opts.sb_cert)

    if bool(opts.sb_key) ^ bool(opts.sb_cert):
        # one param only given, sbsign needs both
        raise ValueError('--secureboot-private-key= and --secureboot-certificate= must be specified together')
    elif bool(opts.sb_key) and bool(opts.sb_cert):
        # both param given, infer sbsign and in case it was given, ensure signtool=sbsign
        if opts.signtool and opts.signtool != 'sbsign':
            raise ValueError(f'Cannot provide --signtool={opts.signtool} with --secureboot-private-key= and --secureboot-certificate=')
        opts.signtool = 'sbsign'
    elif bool(opts.sb_cert_name):
        # sb_cert_name given, infer pesign and in case it was given, ensure signtool=pesign
        if opts.signtool and opts.signtool != 'pesign':
            raise ValueError(f'Cannot provide --signtool={opts.signtool} with --secureboot-certificate-name=')
        opts.signtool = 'pesign'

    if opts.sign_kernel and not opts.sb_key and not opts.sb_cert_name:
        raise ValueError('--sign-kernel requires either --secureboot-private-key= and --secureboot-certificate= (for sbsign) or --secureboot-certificate-name= (for pesign) to be specified')

    if opts.verb == 'build' and opts.output is None:
        if opts.linux is None:
            raise ValueError('--output= must be specified when building a PE addon')
        suffix = '.efi' if opts.sb_key or opts.sb_cert_name else '.unsigned.efi'
        opts.output = opts.linux.name + suffix

    # Now that we know if we're inputting or outputting, really parse section config
    f = Section.parse_output if opts.verb == 'inspect' else Section.parse_input
    opts.sections = [f(s) for s in opts.sections]
    # A convenience dictionary to make it easy to look up sections
    opts.sections_by_name = {s.name:s for s in opts.sections}

    if opts.summary:
        # TODO: replace pprint() with some fancy formatting.
        pprint.pprint(vars(opts))
        sys.exit()


def parse_args(args=None):
    opts = create_parser().parse_args(args)
    apply_config(opts)
    finalize_options(opts)
    return opts


def main():
    opts = parse_args()
    if opts.verb == 'build':
        check_inputs(opts)
        make_uki(opts)
    elif opts.verb == 'genkey':
        check_cert_and_keys_nonexistent(opts)
        generate_keys(opts)
    elif opts.verb == 'inspect':
        inspect_sections(opts)
    else:
        assert False


if __name__ == '__main__':
    main()
