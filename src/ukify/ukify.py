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
import builtins
import collections
import configparser
import contextlib
import dataclasses
import datetime
import fnmatch
import inspect
import itertools
import json
import os
import pprint
import pydoc
import re
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import textwrap
import uuid
from collections.abc import Iterable, Iterator, Sequence
from hashlib import sha256
from pathlib import Path
from types import ModuleType
from typing import (
    IO,
    Any,
    Callable,
    Literal,
    Optional,
    TypeVar,
    Union,
    cast,
)

import pefile  # type: ignore

__version__ = '{{PROJECT_VERSION}} ({{VERSION_TAG}})'

EFI_ARCH_MAP = {
    # host_arch glob : [efi_arch, 32_bit_efi_arch if mixed mode is supported]
    'x86_64':        ['x64', 'ia32'],
    'i[3456]86':     ['ia32'],
    'aarch64':       ['aa64'],
    'armv[45678]*l': ['arm'],
    'loongarch32':   ['loongarch32'],
    'loongarch64':   ['loongarch64'],
    'riscv32':       ['riscv32'],
    'riscv64':       ['riscv64'],
}  # fmt: skip
EFI_ARCHES: list[str] = sum(EFI_ARCH_MAP.values(), [])

# Default configuration directories and file name.
# When the user does not specify one, the directories are searched in this order and the first file found is
# used.
DEFAULT_CONFIG_DIRS = ['/etc/systemd', '/run/systemd', '/usr/local/lib/systemd', '/usr/lib/systemd']
DEFAULT_CONFIG_FILE = 'ukify.conf'


class Style:
    bold = '\033[0;1;39m' if sys.stderr.isatty() else ''
    gray = '\033[0;38;5;245m' if sys.stderr.isatty() else ''
    red = '\033[31;1m' if sys.stderr.isatty() else ''
    yellow = '\033[33;1m' if sys.stderr.isatty() else ''
    reset = '\033[0m' if sys.stderr.isatty() else ''


def guess_efi_arch() -> str:
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
        fw_platform_size = Path('/sys/firmware/efi/fw_platform_size')
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


def shell_join(cmd: list[Union[str, Path]]) -> str:
    # TODO: drop in favour of shlex.join once shlex.join supports Path.
    return ' '.join(shlex.quote(str(x)) for x in cmd)


def round_up(x: int, blocksize: int = 4096) -> int:
    return (x + blocksize - 1) // blocksize * blocksize


def try_import(modname: str, name: Optional[str] = None) -> ModuleType:
    try:
        return __import__(modname)
    except ImportError as e:
        raise ValueError(f'Kernel is compressed with {name or modname}, but module unavailable') from e


def read_env_file(text: str) -> dict[str, str]:
    result = {}

    for line in text.splitlines():
        line = line.rstrip()
        if not line or line.startswith('#'):
            continue
        if m := re.match(r'([A-Z][A-Z_0-9]+)=(.*)', line):
            name, val = m.groups()
            if val and val[0] in '"\'':
                val = next(shlex.shlex(val, posix=True))

            result[name] = val
        else:
            print(f'bad line {line!r}', file=sys.stderr)

    return result


def get_zboot_kernel(f: IO[bytes]) -> bytes:
    """Decompress zboot efistub kernel if compressed. Return contents."""
    # See linux/drivers/firmware/efi/libstub/Makefile.zboot
    # and linux/drivers/firmware/efi/libstub/zboot-header.S

    # 4 bytes at offset 0x08 contain the starting offset of compressed data
    f.seek(8)
    _start = f.read(4)
    start = struct.unpack('<i', _start)[0]

    # Reading 4 bytes from address 0x0c is the size of compressed data,
    # but it needs to be corrected according to the compressed type.
    f.seek(0xC)
    _sizes = f.read(4)
    size = struct.unpack('<i', _sizes)[0]

    # Read 6 bytes from address 0x18, which is a nul-terminated
    # string representing the compressed type.
    f.seek(0x18)
    comp_type = f.read(6)
    f.seek(start)
    if comp_type.startswith(b'gzip'):
        gzip = try_import('gzip')
        return cast(bytes, gzip.open(f).read(size))
    elif comp_type.startswith(b'lz4'):
        lz4 = try_import('lz4.frame', 'lz4')
        return cast(bytes, lz4.frame.decompress(f.read(size)))
    elif comp_type.startswith(b'lzma'):
        lzma = try_import('lzma')
        return cast(bytes, lzma.open(f).read(size))
    elif comp_type.startswith(b'lzo'):
        raise NotImplementedError('lzo decompression not implemented')
    elif comp_type.startswith(b'xzkern'):
        raise NotImplementedError('xzkern decompression not implemented')
    elif comp_type.startswith(b'zstd22'):
        zstd = try_import('zstd')
        return cast(bytes, zstd.uncompress(f.read(size)))

    raise NotImplementedError(f'unknown compressed type: {comp_type!r}')


def maybe_decompress(filename: Union[str, Path]) -> bytes:
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
        return cast(bytes, gzip.open(f).read())

    if start.startswith(b'\x28\xb5\x2f\xfd'):
        zstd = try_import('zstd')
        return cast(bytes, zstd.uncompress(f.read()))

    if start.startswith(b'\x02\x21\x4c\x18'):
        lz4 = try_import('lz4.frame', 'lz4')
        return cast(bytes, lz4.frame.decompress(f.read()))

    if start.startswith(b'\x04\x22\x4d\x18'):
        print('Newer lz4 stream format detected! This may not boot!')
        lz4 = try_import('lz4.frame', 'lz4')
        return cast(bytes, lz4.frame.decompress(f.read()))

    if start.startswith(b'\x89LZO'):
        # python3-lzo is not packaged for Fedora
        raise NotImplementedError('lzo decompression not implemented')

    if start.startswith(b'BZh'):
        bz2 = try_import('bz2', 'bzip2')
        return cast(bytes, bz2.open(f).read())

    if start.startswith(b'\x5d\x00\x00'):
        lzma = try_import('lzma')
        return cast(bytes, lzma.open(f).read())

    raise NotImplementedError(f'unknown file format (starts with {start!r})')


@dataclasses.dataclass
class UkifyConfig:
    all: bool
    cmdline: Union[str, Path, None]
    devicetree: Path
    devicetree_auto: list[Path]
    efi_arch: str
    hwids: Path
    initrd: list[Path]
    efifw: list[Path]
    join_profiles: list[Path]
    sign_profiles: list[str]
    json: Union[Literal['pretty'], Literal['short'], Literal['off']]
    linux: Optional[Path]
    measure: bool
    microcode: Path
    os_release: Union[str, Path, None]
    output: Optional[str]
    pcr_banks: list[str]
    pcr_private_keys: list[str]
    pcr_public_keys: list[str]
    pcrpkey: Optional[Path]
    phase_path_groups: Optional[list[str]]
    policy_digest: bool
    profile: Union[str, Path, None]
    sb_cert: Union[str, Path, None]
    sb_cert_name: Optional[str]
    sb_cert_validity: int
    sb_certdir: Path
    sb_key: Union[str, Path, None]
    sbat: Optional[list[str]]
    sections: list['Section']
    sections_by_name: dict[str, 'Section']
    sign_kernel: Optional[bool]
    signing_engine: Optional[str]
    signing_provider: Optional[str]
    certificate_provider: Optional[str]
    signtool: Optional[str]
    splash: Optional[Path]
    stub: Path
    summary: bool
    tools: list[Path]
    uname: Optional[str]
    verb: str
    files: list[str] = dataclasses.field(default_factory=list)

    @classmethod
    def from_namespace(cls, ns: argparse.Namespace) -> 'UkifyConfig':
        return cls(**{k: v for k, v in vars(ns).items() if k in inspect.signature(cls).parameters})


class Uname:
    # This class is here purely as a namespace for the functions

    VERSION_PATTERN = r'(?P<version>[a-z0-9._-]+) \([^ )]+\) (?:#.*)'

    NOTES_PATTERN = r'^\s+Linux\s+0x[0-9a-f]+\s+OPEN\n\s+description data: (?P<version>[0-9a-f ]+)\s*$'

    # Linux version 6.0.8-300.fc37.ppc64le (mockbuild@buildvm-ppc64le-03.iad2.fedoraproject.org)
    # (gcc (GCC) 12.2.1 20220819 (Red Hat 12.2.1-2), GNU ld version 2.38-24.fc37)
    # #1 SMP Fri Nov 11 14:39:11 UTC 2022
    TEXT_PATTERN = rb'Linux version (?P<version>\d\.\S+) \('

    @classmethod
    def scrape_x86(cls, filename: Path, opts: Optional[UkifyConfig] = None) -> str:
        # Based on https://gitlab.archlinux.org/archlinux/mkinitcpio/mkinitcpio/-/blob/master/functions#L136
        # and https://docs.kernel.org/arch/x86/boot.html#the-real-mode-kernel-header
        with open(filename, 'rb') as f:
            f.seek(0x202)
            magic = f.read(4)
            if magic != b'HdrS':
                raise ValueError('Real-Mode Kernel Header magic not found')
            f.seek(0x20E)
            offset = f.read(1)[0] + f.read(1)[0] * 256  # Pointer to kernel version string
            f.seek(0x200 + offset)
            text = f.read(128)
        text = text.split(b'\0', maxsplit=1)[0]
        decoded = text.decode()

        if not (m := re.match(cls.VERSION_PATTERN, decoded)):
            raise ValueError(f'Cannot parse version-host-release uname string: {text!r}')
        return m.group('version')

    @classmethod
    def scrape_elf(cls, filename: Path, opts: Optional[UkifyConfig] = None) -> str:
        readelf = find_tool('readelf', opts=opts)

        cmd = [
            readelf,
            '--notes',
            filename,
        ]

        print('+', shell_join(cmd), file=sys.stderr)
        try:
            notes = subprocess.check_output(cmd, stderr=subprocess.PIPE, text=True)
        except subprocess.CalledProcessError as e:
            raise ValueError(e.stderr.strip()) from e

        if not (m := re.search(cls.NOTES_PATTERN, notes, re.MULTILINE)):
            raise ValueError('Cannot find Linux version note')

        text = ''.join(chr(int(c, 16)) for c in m.group('version').split())
        return text.rstrip('\0')

    @classmethod
    def scrape_generic(cls, filename: Path, opts: Optional[UkifyConfig] = None) -> str:
        # import libarchive
        # libarchive-c fails with
        # ArchiveError: Unrecognized archive format (errno=84, retcode=-30, archive_p=94705420454656)

        # Based on https://gitlab.archlinux.org/archlinux/mkinitcpio/mkinitcpio/-/blob/master/functions#L209

        text = maybe_decompress(filename)
        if not (m := re.search(cls.TEXT_PATTERN, text)):
            raise ValueError(f'Cannot find {cls.TEXT_PATTERN!r} in {filename}')

        return m.group('version').decode()

    @classmethod
    def scrape(cls, filename: Path, opts: Optional[UkifyConfig] = None) -> Optional[str]:
        for func in (cls.scrape_x86, cls.scrape_elf, cls.scrape_generic):
            try:
                version = func(filename, opts=opts)
                print(f'Found uname version: {version}', file=sys.stderr)
                return version
            except ValueError as e:
                print(str(e))
        return None


DEFAULT_SECTIONS_TO_SHOW = {
    '.linux':   'binary',
    '.initrd':  'binary',
    '.ucode':   'binary',
    '.splash':  'binary',
    '.dtb':     'binary',
    '.dtbauto': 'binary',
    '.hwids':   'binary',
    '.efifw':   'binary',
    '.cmdline': 'text',
    '.osrel':   'text',
    '.uname':   'text',
    '.pcrpkey': 'text',
    '.pcrsig':  'text',
    '.sbat':    'text',
    '.sbom':    'binary',
    '.profile': 'text',
}  # fmt: skip


@dataclasses.dataclass
class Section:
    name: str
    content: Optional[Path]
    tmpfile: Optional[IO[Any]] = None
    measure: bool = False
    output_mode: Optional[str] = None
    virtual_size: Optional[int] = None

    @classmethod
    def create(cls, name: str, contents: Union[str, bytes, Path, None], **kwargs: Any) -> 'Section':
        if isinstance(contents, (str, bytes)):
            mode = 'wt' if isinstance(contents, str) else 'wb'
            tmp = tempfile.NamedTemporaryFile(mode=mode, prefix=f'tmp{name}')
            tmp.write(contents)
            tmp.flush()
            contents = Path(tmp.name)
        else:
            tmp = None

        return cls(name, contents, tmpfile=tmp, **kwargs)

    @classmethod
    def parse_input(cls, s: str) -> 'Section':
        try:
            name, contents, *rest = s.split(':')
        except ValueError as e:
            raise ValueError(f'Cannot parse section spec (name or contents missing): {s!r}') from e
        if rest:
            raise ValueError(f'Cannot parse section spec (extraneous parameters): {s!r}')

        if contents.startswith('@'):
            sec = cls.create(name, Path(contents[1:]))
        else:
            sec = cls.create(name, contents)

        sec.check_name()
        return sec

    @classmethod
    def parse_output(cls, s: str) -> 'Section':
        if not (m := re.match(r'([a-zA-Z0-9_.]+):(text|binary)(?:@(.+))?', s)):
            raise ValueError(f'Cannot parse section spec: {s!r}')

        name, ttype, out = m.groups()
        out = Path(out) if out else None

        return cls.create(name, out, output_mode=ttype)

    def check_name(self) -> None:
        # PE section names with more than 8 characters are legal, but our stub does
        # not support them.
        if not self.name.isascii() or not self.name.isprintable():
            raise ValueError(f'Bad section name: {self.name!r}')
        if len(self.name) > 8:
            raise ValueError(f'Section name too long: {self.name!r}')


@dataclasses.dataclass
class UKI:
    executable: Path
    sections: list[Section] = dataclasses.field(default_factory=list, init=False)

    def add_section(self, section: Section) -> None:
        start = 0

        # Start search at last .profile section, if there is one
        for i, s in enumerate(self.sections):
            if s.name == '.profile':
                start = i + 1

        multiple_allowed_sections = ['.dtbauto', '.efifw']
        if any(
            section.name == s.name for s in self.sections[start:] if s.name not in multiple_allowed_sections
        ):
            raise ValueError(f'Duplicate section {section.name}')

        self.sections += [section]


class SignTool:
    @staticmethod
    def sign(input_f: str, output_f: str, opts: UkifyConfig) -> None:
        raise NotImplementedError()

    @staticmethod
    def verify(opts: UkifyConfig) -> bool:
        raise NotImplementedError()

    @staticmethod
    def from_string(name: str) -> type['SignTool']:
        if name == 'pesign':
            return PeSign
        elif name == 'sbsign':
            return SbSign
        elif name == 'systemd-sbsign':
            return SystemdSbSign
        else:
            raise ValueError(f'Invalid sign tool: {name!r}')


class PeSign(SignTool):
    @staticmethod
    def sign(input_f: str, output_f: str, opts: UkifyConfig) -> None:
        assert opts.sb_certdir is not None
        assert opts.sb_cert_name is not None

        tool = find_tool('pesign', opts=opts, msg='pesign, required for signing, is not installed')
        cmd = [
            tool,
            '-s',
            '--force',
            '-n', opts.sb_certdir,
            '-c', opts.sb_cert_name,
            '-i', input_f,
            '-o', output_f,
        ]  # fmt: skip

        print('+', shell_join(cmd), file=sys.stderr)
        subprocess.check_call(cmd)

    @staticmethod
    def verify(opts: UkifyConfig) -> bool:
        assert opts.linux is not None

        tool = find_tool('pesign', opts=opts)
        cmd = [tool, '-i', opts.linux, '-S']

        print('+', shell_join(cmd), file=sys.stderr)
        info = subprocess.check_output(cmd, text=True)

        return 'No signatures found.' in info


class SbSign(SignTool):
    @staticmethod
    def sign(input_f: str, output_f: str, opts: UkifyConfig) -> None:
        assert opts.sb_key is not None
        assert opts.sb_cert is not None

        tool = find_tool('sbsign', opts=opts, msg='sbsign, required for signing, is not installed')
        cmd = [
            tool,
            '--key', opts.sb_key,
            '--cert', opts.sb_cert,
            *(['--engine', opts.signing_engine] if opts.signing_engine is not None else []),
            input_f,
            '--output', output_f,
        ]  # fmt: skip

        print('+', shell_join(cmd), file=sys.stderr)
        subprocess.check_call(cmd)

    @staticmethod
    def verify(opts: UkifyConfig) -> bool:
        assert opts.linux is not None

        tool = find_tool('sbverify', opts=opts)
        cmd = [tool, '--list', opts.linux]

        print('+', shell_join(cmd), file=sys.stderr)
        info = subprocess.check_output(cmd, text=True)

        return 'No signature table present' in info


class SystemdSbSign(SignTool):
    @staticmethod
    def sign(input_f: str, output_f: str, opts: UkifyConfig) -> None:
        assert opts.sb_key is not None
        assert opts.sb_cert is not None

        tool = find_tool(
            'systemd-sbsign',
            '/usr/lib/systemd/systemd-sbsign',
            opts=opts,
            msg='systemd-sbsign, required for signing, is not installed',
        )
        cmd = [
            tool,
            "sign",
            '--private-key', opts.sb_key,
            '--certificate', opts.sb_cert,
            *(
                ['--private-key-source', f'engine:{opts.signing_engine}']
                if opts.signing_engine is not None
                else []
            ),
            *(
                ['--private-key-source', f'provider:{opts.signing_provider}']
                if opts.signing_provider is not None
                else []
            ),
            *(
                ['--certificate-source', f'provider:{opts.certificate_provider}']
                if opts.certificate_provider is not None
                else []
            ),
            input_f,
            '--output', output_f,
        ]  # fmt: skip

        print('+', shell_join(cmd), file=sys.stderr)
        subprocess.check_call(cmd)

    @staticmethod
    def verify(opts: UkifyConfig) -> bool:
        raise NotImplementedError('systemd-sbsign cannot yet verify if existing PE binaries are signed')


def parse_banks(s: str) -> list[str]:
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


def parse_phase_paths(s: str) -> list[str]:
    # Split on commas or whitespace here. Commas might be hard to parse visually.
    paths = re.split(r',|\s+', s)

    for path in paths:
        for phase in path.split(':'):
            if phase not in KNOWN_PHASES:
                raise argparse.ArgumentTypeError(f'Unknown boot phase {phase!r} ({path=})')

    return paths


def check_splash(filename: Optional[Path]) -> None:
    if filename is None:
        return

    # import is delayed, to avoid import when the splash image is not used
    try:
        from PIL import Image
    except ImportError:
        return

    img = Image.open(filename, formats=['BMP'])
    print(f'Splash image {filename} is {img.width}×{img.height} pixels', file=sys.stderr)


def check_inputs(opts: UkifyConfig) -> None:
    for name, value in vars(opts).items():
        if name in {'output', 'tools'}:
            continue

        if isinstance(value, Path):
            # Check that we can open the directory or file, or generate and exception
            if value.is_dir():
                value.iterdir()
            else:
                value.open().close()
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, Path):
                    if item.is_dir():
                        item.iterdir()
                    else:
                        item.open().close()

    check_splash(opts.splash)


def check_cert_and_keys_nonexistent(opts: UkifyConfig) -> None:
    # Raise if any of the keys and certs are found on disk
    paths: Iterator[Union[str, Path, None]] = itertools.chain(
        (opts.sb_key, opts.sb_cert),
        *((priv_key, pub_key) for priv_key, pub_key, _ in key_path_groups(opts)),
    )
    for path in paths:
        if path and Path(path).exists():
            raise ValueError(f'{path} is present')


def find_tool(
    name: str,
    fallback: Optional[str] = None,
    opts: Optional[UkifyConfig] = None,
    msg: str = 'Tool {name} not installed!',
) -> Union[str, Path]:
    if opts and opts.tools:
        for d in opts.tools:
            tool = d / name
            if tool.exists():
                return tool

    if shutil.which(name) is not None:
        return name

    if fallback is None:
        raise ValueError(msg.format(name=name))

    return fallback


def combine_signatures(pcrsigs: list[dict[str, str]]) -> str:
    combined: collections.defaultdict[str, list[str]] = collections.defaultdict(list)
    for pcrsig in pcrsigs:
        for bank, sigs in pcrsig.items():
            for sig in sigs:
                if sig not in combined[bank]:
                    combined[bank] += [sig]
    return json.dumps(combined)


def key_path_groups(opts: UkifyConfig) -> Iterator[tuple[str, Optional[str], Optional[str]]]:
    if not opts.pcr_private_keys:
        return

    n_priv = len(opts.pcr_private_keys)
    pub_keys = opts.pcr_public_keys or []
    pp_groups = opts.phase_path_groups or []

    yield from itertools.zip_longest(
        opts.pcr_private_keys,
        pub_keys[:n_priv],
        pp_groups[:n_priv],
        fillvalue=None,
    )


def pe_strip_section_name(name: bytes) -> str:
    return name.rstrip(b'\x00').decode()


def call_systemd_measure(uki: UKI, opts: UkifyConfig, profile_start: int = 0) -> None:
    measure_tool = find_tool(
        'systemd-measure',
        '/usr/lib/systemd/systemd-measure',
        opts=opts,
    )

    banks = opts.pcr_banks or ()

    # PCR measurement

    # First, pick up either the base sections or the profile specific sections we shall measure now
    unique_to_measure = {
        s.name: s for s in uki.sections[profile_start:] if s.measure and s.name != '.dtbauto'
    }

    dtbauto_to_measure: list[Optional[Section]] = [
        s for s in uki.sections[profile_start:] if s.measure and s.name == '.dtbauto'
    ]

    if len(dtbauto_to_measure) == 0:
        dtbauto_to_measure = [None]

    # Then, if we're measuring a profile, lookup the missing sections from the base image.
    if profile_start != 0:
        for section in uki.sections:
            # If we reach the first .profile section the base is over
            if section.name == '.profile':
                break

            # Only some sections are measured
            if not section.measure:
                continue

            # Check if this is a section we already covered above
            if section.name in unique_to_measure:
                continue

            unique_to_measure[section.name] = section

    if opts.measure or opts.policy_digest:
        to_measure = unique_to_measure.copy()

        for dtbauto in dtbauto_to_measure:
            if dtbauto is not None:
                to_measure[dtbauto.name] = dtbauto

            pp_groups = opts.phase_path_groups or []

            cmd = [
                measure_tool,
                'calculate' if opts.measure else 'policy-digest',
                '--json',
                opts.json,
                *(f'--{s.name.removeprefix(".")}={s.content}' for s in to_measure.values()),
                *(f'--bank={bank}' for bank in banks),
                # For measurement, the keys are not relevant, so we can lump all the phase paths
                # into one call to systemd-measure calculate.
                *(f'--phase={phase_path}' for phase_path in itertools.chain.from_iterable(pp_groups)),
            ]

            # The JSON object will be used for offline signing, include the public key
            # so that the fingerprint is included too.
            if opts.policy_digest and opts.pcr_public_keys:
                cmd += [f'--public-key={opts.pcr_public_keys[0]}']

            print('+', shell_join(cmd), file=sys.stderr)
            subprocess.check_call(cmd)

    # PCR signing

    if opts.pcr_private_keys:
        pcrsigs = []
        to_measure = unique_to_measure.copy()

        for dtbauto in dtbauto_to_measure:
            if dtbauto is not None:
                to_measure[dtbauto.name] = dtbauto

            cmd = [
                measure_tool,
                'sign',
                *(f'--{s.name.removeprefix(".")}={s.content}' for s in to_measure.values()),
                *(f'--bank={bank}' for bank in banks),
            ]

            for priv_key, pub_key, group in key_path_groups(opts):
                extra = [f'--private-key={priv_key}']
                if opts.signing_engine is not None:
                    assert pub_key
                    extra += [f'--private-key-source=engine:{opts.signing_engine}']
                    extra += [f'--certificate={pub_key}']
                elif opts.signing_provider is not None:
                    assert pub_key
                    extra += [f'--private-key-source=provider:{opts.signing_provider}']
                    extra += [f'--certificate={pub_key}']
                elif pub_key:
                    extra += [f'--public-key={pub_key}']

                if opts.certificate_provider is not None:
                    extra += [f'--certificate-source=provider:{opts.certificate_provider}']

                extra += [f'--phase={phase_path}' for phase_path in group or ()]

                print('+', shell_join(cmd + extra), file=sys.stderr)  # type: ignore
                pcrsig = subprocess.check_output(cmd + extra, text=True)  # type: ignore
                pcrsig = json.loads(pcrsig)
                pcrsigs += [pcrsig]

        combined = combine_signatures(pcrsigs)
        uki.add_section(Section.create('.pcrsig', combined))


def join_initrds(initrds: list[Path]) -> Union[Path, bytes, None]:
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


T = TypeVar('T')


def pairwise(iterable: Iterable[T]) -> Iterator[tuple[T, Optional[T]]]:
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)


class PEError(Exception):
    pass


def pe_add_sections(uki: UKI, output: str) -> None:
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

        for later_section in pe.sections[i + 1 :]:
            later_section.PointerToRawData += padp + padsz

        pe.__data__ = (
            pe.__data__[:oldp]
            + bytes(padp)
            + pe.__data__[oldp : oldp + oldsz]
            + bytes(padsz)
            + pe.__data__[oldp + oldsz :]
        )

    # We might not have any space to add new sections. Let's try our best to make some space by padding the
    # SizeOfHeaders to a multiple of the file alignment. This is safe because the first section's data starts
    # at a multiple of the file alignment, so all space before that is unused.
    pe.OPTIONAL_HEADER.SizeOfHeaders = round_up(
        pe.OPTIONAL_HEADER.SizeOfHeaders, pe.OPTIONAL_HEADER.FileAlignment
    )
    pe = pefile.PE(data=pe.write(), fast_load=True)

    warnings = pe.get_warnings()
    if warnings:
        raise PEError(f'pefile warnings treated as errors: {warnings}')

    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
    if security.VirtualAddress != 0:
        # We could strip the signatures, but why would anyone sign the stub?
        raise PEError('Stub image is signed, refusing.')

    # Remember how many sections originate from systemd-stub
    n_original_sections = len(pe.sections)

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
        if section.virtual_size is not None:
            new_section.Misc_VirtualSize = section.virtual_size
        else:
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
        for i, s in enumerate(pe.sections[:n_original_sections]):
            if pe_strip_section_name(s.Name) == section.name and section.name != '.dtbauto':
                if new_section.Misc_VirtualSize > s.SizeOfRawData:
                    raise PEError(f'Not enough space in existing section {section.name} to append new data.')

                padding = bytes(new_section.SizeOfRawData - new_section.Misc_VirtualSize)
                pe.__data__ = (
                    pe.__data__[: s.PointerToRawData]
                    + data
                    + padding
                    + pe.__data__[pe.sections[i + 1].PointerToRawData :]
                )
                s.SizeOfRawData = new_section.SizeOfRawData
                s.Misc_VirtualSize = new_section.Misc_VirtualSize
                break
        else:
            pe.__data__ = (
                pe.__data__[:]
                + bytes(new_section.PointerToRawData - len(pe.__data__))
                + data
                + bytes(new_section.SizeOfRawData - len(data))
            )

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


def merge_sbat(input_pe: list[Path], input_text: list[str]) -> str:
    sbat = []

    for f in input_pe:
        try:
            pe = pefile.PE(f, fast_load=True)
        except pefile.PEFormatError:
            print(f'{f} is not a valid PE file, not extracting SBAT section.')
            continue

        for section in pe.sections:
            if pe_strip_section_name(section.Name) == '.sbat':
                split = section.get_data().rstrip(b'\x00').decode().splitlines()
                if not split[0].startswith('sbat,'):
                    print(f'{f} does not contain a valid SBAT section, skipping.')
                    continue
                # Filter out the sbat line, we'll add it back later, there needs to be only one and it
                # needs to be first.
                sbat += split[1:]

    for t in input_text:
        if t.startswith('@'):
            t = Path(t[1:]).read_text()
        split = t.splitlines()
        if not split[0].startswith('sbat,'):
            print(f'{t} does not contain a valid SBAT section, skipping.')
            continue
        sbat += split[1:]

    return (
        'sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n'
        + '\n'.join(sbat)
        + '\n\x00'
    )


# Keep in sync with Device from src/boot/chid.h
# uint32_t descriptor, EFI_GUID chid, uint32_t name_offset, uint32_t compatible_offset
DEVICE_STRUCT_SIZE = 4 + 16 + 4 + 4
NULL_DEVICE = b'\0' * DEVICE_STRUCT_SIZE
DEVICE_TYPE_DEVICETREE = 1
DEVICE_TYPE_UEFI_FW = 2

# Keep in sync with efifirmware.h
FWHEADERMAGIC = 'feeddead'
EFIFW_HEADER_SIZE = 4 + 4 + 4 + 4


def device_make_descriptor(device_type: int, size: int) -> int:
    return (size) | (device_type << 28)


def pack_device(
    offsets: dict[str, int], devtype: int, name: str, compatible_or_fwid: str, chids: set[uuid.UUID]
) -> bytes:
    data = b''
    descriptor = device_make_descriptor(devtype, DEVICE_STRUCT_SIZE)
    for chid in sorted(chids):
        data += struct.pack('<I', descriptor)
        data += chid.bytes_le
        data += struct.pack('<II', offsets[name], offsets[compatible_or_fwid])

    assert len(data) == DEVICE_STRUCT_SIZE * len(chids)
    return data


def pack_strings(strings: set[str], base: int) -> tuple[bytes, dict[str, int]]:
    blob = b''
    offsets = {}

    for string in sorted(strings):
        offsets[string] = base + len(blob)
        blob += string.encode('utf-8') + b'\00'

    return (blob, offsets)


def parse_hwid_dir(path: Path) -> bytes:
    hwid_files = path.rglob('*.json')
    devstr_to_type: dict[str, int] = {
        'devicetree': DEVICE_TYPE_DEVICETREE,
        'uefi-fw': DEVICE_TYPE_UEFI_FW,
    }

    # all attributes in the mandatory attributes list must be present
    mandatory_attribute = ['type', 'name', 'hwids']

    # at least one of the following attributes must be present
    one_of = ['compatible', 'fwid']

    one_of_key_to_devtype: dict[str, int] = {
        'compatible': DEVICE_TYPE_DEVICETREE,
        'fwid': DEVICE_TYPE_UEFI_FW,
    }

    strings: set[str] = set()
    devices: collections.defaultdict[tuple[int, str, str], set[uuid.UUID]] = collections.defaultdict(set)

    for hwid_file in hwid_files:
        data = json.loads(hwid_file.read_text(encoding='UTF-8'))

        for k in mandatory_attribute:
            if k not in data:
                raise ValueError(f'hwid description file "{hwid_file}" does not contain "{k}"')

        if not any(key in data for key in one_of):
            required_keys = ','.join(one_of)
            raise ValueError(f'hwid description file "{hwid_file}" must contain one of {required_keys}')

        # (devtype, name, compatible/fwid) pair uniquely identifies the device
        devtype = devstr_to_type[data['type']]

        for k in one_of:
            if k in data:
                if one_of_key_to_devtype[k] != devtype:
                    raise ValueError(
                        f'wrong attribute "{k}" for hwid description file "{hwid_file}", '
                        'device type: "%s"' % devtype
                    )
                strings |= {data['name'], data[k]}
                devices[(devtype, data['name'], data[k])] |= {uuid.UUID(u) for u in data['hwids']}

    total_device_structs = 1
    for dev, uuids in devices.items():
        total_device_structs += len(uuids)

    strings_blob, offsets = pack_strings(strings, total_device_structs * DEVICE_STRUCT_SIZE)

    devices_blob = b''
    for (devtype, name, compatible_or_fwid), uuids in devices.items():
        devices_blob += pack_device(offsets, devtype, name, compatible_or_fwid, uuids)

    devices_blob += NULL_DEVICE

    return devices_blob + strings_blob


def parse_efifw_dir(path: Path) -> bytes:
    if not path.is_dir():
        raise ValueError(f'{path} is not a directory or it does not exist.')

    # only one firmware image must be present in the directory
    # to uniquely identify that firmware with its ID.
    if len(list(path.glob('*'))) != 1:
        raise ValueError(f'{path} must contain exactly one firmware image file.')

    payload_blob = b''
    for fw in path.iterdir():
        payload_blob += fw.read_bytes()

    payload_len = len(payload_blob)
    if payload_len == 0:
        raise ValueError(f'{fw} is a zero byte file!')

    dirname = path.parts[-1]
    # firmware id is the name of the directory the firmware bundle is in,
    # terminated by NULL.
    fwid = b'' + dirname.encode() + b'\0'
    fwid_len = len(fwid)
    magic = bytes.fromhex(FWHEADERMAGIC)

    efifw_header_blob = b''
    efifw_header_blob += struct.pack('<p', magic)
    efifw_header_blob += struct.pack('<I', EFIFW_HEADER_SIZE)
    efifw_header_blob += struct.pack('<I', fwid_len)
    efifw_header_blob += struct.pack('<I', payload_len)

    efifw_blob = b''
    efifw_blob += efifw_header_blob + fwid + payload_blob

    return efifw_blob


STUB_SBAT = """\
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
uki,1,UKI,uki,1,https://uapi-group.org/specifications/specs/unified_kernel_image/
"""

ADDON_SBAT = """\
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
uki-addon,1,UKI Addon,addon,1,https://www.freedesktop.org/software/systemd/man/latest/systemd-stub.html
"""


def make_uki(opts: UkifyConfig) -> None:
    assert opts.output is not None

    # kernel payload signing

    sign_args_present = opts.sb_key or opts.sb_cert_name
    sign_kernel = opts.sign_kernel
    linux = opts.linux

    if opts.linux and sign_args_present:
        assert opts.signtool is not None
        signtool = SignTool.from_string(opts.signtool)

        if sign_kernel is None:
            # figure out if we should sign the kernel
            sign_kernel = signtool.verify(opts)

        if sign_kernel:
            linux_signed = tempfile.NamedTemporaryFile(prefix='linux-signed')
            linux = Path(linux_signed.name)
            signtool.sign(os.fspath(opts.linux), os.fspath(linux), opts=opts)

    if opts.uname is None and opts.linux is not None:
        print('Kernel version not specified, starting autodetection 😖.', file=sys.stderr)
        opts.uname = Uname.scrape(opts.linux, opts=opts)

    uki = UKI(opts.stub)
    initrd = join_initrds(opts.initrd)

    pcrpkey: Union[bytes, Path, None] = opts.pcrpkey
    if pcrpkey is None:
        keyutil_tool = find_tool('systemd-keyutil', '/usr/lib/systemd/systemd-keyutil')
        cmd = [keyutil_tool, 'public']

        if opts.pcr_public_keys and len(opts.pcr_public_keys) == 1:
            # If we're using an engine or provider, the public key will be an X.509 certificate.
            if opts.signing_engine or opts.signing_provider:
                cmd += ['--certificate', opts.pcr_public_keys[0]]
                if opts.certificate_provider:
                    cmd += ['--certificate-source', f'provider:{opts.certificate_provider}']

                print('+', shell_join(cmd), file=sys.stderr)
                pcrpkey = subprocess.check_output(cmd)
            else:
                pcrpkey = Path(opts.pcr_public_keys[0])
        elif opts.pcr_private_keys and len(opts.pcr_private_keys) == 1:
            cmd += ['--private-key', Path(opts.pcr_private_keys[0])]

            if opts.signing_engine:
                cmd += ['--private-key-source', f'engine:{opts.signing_engine}']
            if opts.signing_provider:
                cmd += ['--private-key-source', f'provider:{opts.signing_provider}']

            print('+', shell_join(cmd), file=sys.stderr)
            pcrpkey = subprocess.check_output(cmd)

    hwids = None

    if opts.hwids is not None:
        hwids = parse_hwid_dir(opts.hwids)

    sections = [
        # name,      content,         measure?
        ('.osrel',   opts.os_release, True),
        ('.cmdline', opts.cmdline,    True),
        ('.dtb',     opts.devicetree, True),
        *(('.dtbauto', dtb, True) for dtb in opts.devicetree_auto),
        ('.hwids',   hwids,           True),
        ('.uname',   opts.uname,      True),
        ('.splash',  opts.splash,     True),
        ('.pcrpkey', pcrpkey,         True),
        ('.initrd',  initrd,          True),
        *(('.efifw', parse_efifw_dir(fw), False) for fw in opts.efifw),
        ('.ucode',   opts.microcode,  True),
    ]  # fmt: skip

    # If we're building a PE profile binary, the ".profile" section has to be the first one.
    if opts.profile and not opts.join_profiles:
        uki.add_section(Section.create('.profile', opts.profile, measure=True))

    for name, content, measure in sections:
        if content:
            uki.add_section(Section.create(name, content, measure=measure))

    # systemd-measure doesn't know about those extra sections
    for section in opts.sections:
        uki.add_section(section)

    if linux is not None:
        try:
            virtual_size = pefile.PE(linux, fast_load=True).OPTIONAL_HEADER.SizeOfImage
        except pefile.PEFormatError:
            print(f'{linux} is not a valid PE file, not using SizeOfImage.')
            virtual_size = None

        uki.add_section(Section.create('.linux', linux, measure=True, virtual_size=virtual_size))

    # Don't add a sbat section to profile PE binaries.
    if opts.join_profiles or not opts.profile:
        if linux is not None:
            # Merge the .sbat sections from stub, kernel and parameter, so that revocation can be done on
            # either.
            input_pes = [opts.stub, linux]
            if not opts.sbat:
                opts.sbat = [STUB_SBAT]
        else:
            # Addons don't use the stub so we add SBAT manually
            input_pes = []
            if not opts.sbat:
                opts.sbat = [ADDON_SBAT]
        uki.add_section(Section.create('.sbat', merge_sbat(input_pes, opts.sbat), measure=linux is not None))

    # If we're building a UKI with additional profiles, the .profile section for the base profile has to be
    # the last one so that everything before it is shared between profiles. The only thing we don't share
    # between profiles is the .pcrsig section which is appended later and doesn't make sense to share.
    if opts.profile and opts.join_profiles:
        uki.add_section(Section.create('.profile', opts.profile, measure=True))

    # PCR measurement and signing

    if (opts.join_profiles or not opts.profile) and (
        not opts.sign_profiles or opts.profile in opts.sign_profiles
    ):
        call_systemd_measure(uki, opts=opts)

    # UKI profiles

    to_import = {
        '.linux',
        '.osrel',
        '.cmdline',
        '.initrd',
        '.efifw',
        '.ucode',
        '.splash',
        '.dtb',
        '.uname',
        '.sbat',
        '.profile',
    }

    for profile in opts.join_profiles:
        pe = pefile.PE(profile, fast_load=True)
        prev_len = len(uki.sections)

        names = [pe_strip_section_name(s.Name) for s in pe.sections]
        names = [n for n in names if n in to_import]

        if len(names) == 0:
            raise ValueError(f'Found no valid sections in PE profile binary {profile}')

        if names[0] != '.profile':
            raise ValueError(
                f'Expected .profile section as first valid section in PE profile binary {profile} but got {names[0]}'  # noqa: E501
            )

        if names.count('.profile') > 1:
            raise ValueError(f'Profile PE binary {profile} contains multiple .profile sections')

        for pesection in pe.sections:
            n = pe_strip_section_name(pesection.Name)

            if n not in to_import:
                continue

            print(
                f"Copying section '{n}' from '{profile}': {pesection.Misc_VirtualSize} bytes",
                file=sys.stderr,
            )
            uki.add_section(
                Section.create(n, pesection.get_data(length=pesection.Misc_VirtualSize), measure=True)
            )

        if opts.sign_profiles:
            pesection = next(s for s in pe.sections if pe_strip_section_name(s.Name) == '.profile')
            id = read_env_file(pesection.get_data(length=pesection.Misc_VirtualSize).decode()).get('ID')
            if not id or id not in opts.sign_profiles:
                print(f'Not signing expected PCR measurements for "{id}" profile')
                continue

        call_systemd_measure(uki, opts=opts, profile_start=prev_len)

    # UKI creation

    if sign_args_present:
        unsigned = tempfile.NamedTemporaryFile(prefix='uki')
        unsigned_output = unsigned.name
    else:
        unsigned_output = opts.output

    pe_add_sections(uki, unsigned_output)

    # UKI signing

    if sign_args_present:
        assert opts.signtool is not None
        signtool = SignTool.from_string(opts.signtool)

        signtool.sign(os.fspath(unsigned_output), os.fspath(opts.output), opts)

        # We end up with no executable bits, let's reapply them
        os.umask(umask := os.umask(0))
        os.chmod(opts.output, 0o777 & ~umask)

    print(f'Wrote {"signed" if sign_args_present else "unsigned"} {opts.output}', file=sys.stderr)


@contextlib.contextmanager
def temporary_umask(mask: int) -> Iterator[None]:
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
) -> tuple[bytes, bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    # We use a keylength of 2048 bits. That is what Microsoft documents as
    # supported/expected:
    # https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance?view=windows-11#12-public-key-cryptography

    now = datetime.datetime.now(datetime.timezone.utc)

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=keylength,
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)]),
        )
        .issuer_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)]),
        )
        .not_valid_before(
            now,
        )
        .not_valid_after(
            now + datetime.timedelta(days=valid_days),
        )
        .serial_number(
            x509.random_serial_number(),
        )
        .public_key(
            key.public_key(),
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(
            private_key=key,
            algorithm=hashes.SHA256(),
        )
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


def generate_priv_pub_key_pair(keylength: int = 2048) -> tuple[bytes, bytes]:
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


def generate_keys(opts: UkifyConfig) -> None:
    work = False

    # This will generate keys and certificates and write them to the paths that
    # are specified as input paths.
    if opts.sb_key and opts.sb_cert:
        fqdn = socket.getfqdn()

        cn = f'SecureBoot signing key on host {fqdn}'
        if len(cn) > 64:
            # The length of CN must not exceed 64 bytes
            cn = cn[:61] + '...'

        key_pem, cert_pem = generate_key_cert_pair(
            common_name=cn,
            valid_days=opts.sb_cert_validity,
        )
        print(f'Writing SecureBoot private key to {opts.sb_key}')
        with temporary_umask(0o077):
            Path(opts.sb_key).write_bytes(key_pem)
        print(f'Writing SecureBoot certificate to {opts.sb_cert}')
        Path(opts.sb_cert).write_bytes(cert_pem)

        work = True

    for priv_key, pub_key, _ in key_path_groups(opts):
        priv_key_pem, pub_key_pem = generate_priv_pub_key_pair()

        print(f'Writing private key for PCR signing to {priv_key}')
        with temporary_umask(0o077):
            Path(priv_key).write_bytes(priv_key_pem)
        if pub_key:
            print(f'Writing public key for PCR signing to {pub_key}')
            Path(pub_key).write_bytes(pub_key_pem)

        work = True

    if not work:
        raise ValueError(
            'genkey: --secureboot-private-key=/--secureboot-certificate= or --pcr-private-key/--pcr-public-key must be specified'  # noqa: E501
        )


def inspect_section(
    opts: UkifyConfig,
    section: pefile.SectionStructure,
) -> tuple[str, Optional[dict[str, Union[int, str]]]]:
    name = pe_strip_section_name(section.Name)

    # find the config for this section in opts and whether to show it
    config = opts.sections_by_name.get(name, None)
    show = config or opts.all or (name in DEFAULT_SECTIONS_TO_SHOW and not opts.sections)
    if not show:
        return name, None

    ttype = config.output_mode if config else DEFAULT_SECTIONS_TO_SHOW.get(name, 'binary')

    size = section.Misc_VirtualSize
    # TODO: Use ignore_padding once we can depend on a newer version of pefile
    data = section.get_data(length=size)
    digest = sha256(data).hexdigest()

    struct = {
        'size': size,
        'sha256': digest,
    }

    if ttype == 'text':
        try:
            struct['text'] = data.decode()
        except UnicodeDecodeError as e:
            print(f'Section {name!r} is not valid text: {e}')
            struct['text'] = '(not valid UTF-8)'

    if config and config.content:
        assert isinstance(config.content, Path)
        config.content.write_bytes(data)

    if opts.json == 'off':
        print(f'{name}:\n  size: {size} bytes\n  sha256: {digest}')
        if ttype == 'text':
            text = textwrap.indent(struct['text'].rstrip(), ' ' * 4)
            print(f'  text:\n{text}')

    return name, struct


def inspect_sections(opts: UkifyConfig) -> None:
    indent = 4 if opts.json == 'pretty' else None

    for file in opts.files:
        pe = pefile.PE(file, fast_load=True)
        gen = (inspect_section(opts, section) for section in pe.sections)
        descs = {key: val for (key, val) in gen if val}
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
        setattr(
            namespace,
            dest,
            old + ([None] * (idx - len(old))) + [value],
        )

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
    type: Optional[Callable[[str], Any]] = None
    nargs: Optional[str] = None
    action: Optional[Union[str, Callable[[str], Any], builtins.type[argparse.Action]]] = None
    default: Any = None
    version: Optional[str] = None
    choices: Optional[tuple[str, ...]] = None
    const: Optional[Any] = None
    help: Optional[str] = None

    # metadata for config file parsing
    config_key: Optional[str] = None
    config_push: Callable[[argparse.Namespace, Optional[str], str, Any], None] = config_set_if_unset

    def _names(self) -> tuple[str, ...]:
        return self.name if isinstance(self.name, tuple) else (self.name,)

    def argparse_dest(self) -> str:
        # It'd be nice if argparse exported this, but I don't see that in the API
        if self.dest:
            return self.dest
        return self._names()[0].lstrip('-').replace('-', '_')

    def add_to(self, parser: argparse.ArgumentParser) -> None:
        kwargs = {
            key: val
            for key in dataclasses.asdict(self)
            if (key not in ('name', 'config_key', 'config_push') and (val := getattr(self, key)) is not None)
        }
        args = self._names()
        parser.add_argument(*args, **kwargs)

    def apply_config(
        self,
        namespace: argparse.Namespace,
        section: str,
        group: Optional[str],
        key: str,
        value: Any,
    ) -> None:
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
            conv = lambda s: s  # noqa: E731

        # This is a bit ugly, but --initrd and --devicetree-auto are the only options
        # with multiple args on the command line and a space-separated list in the
        # config file.
        if self.name in ['--initrd', '--devicetree-auto']:
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
        metavar='VERB',
        nargs='*',
        help=argparse.SUPPRESS,
    ),
    ConfigItem(
        '--version',
        action='version',
        version=f'ukify {__version__}',
    ),
    ConfigItem(
        '--summary',
        help='print parsed config and exit',
        action='store_true',
    ),
    ConfigItem(
        ('--config', '-c'),
        metavar='PATH',
        type=Path,
        help='configuration file',
    ),
    ConfigItem(
        '--linux',
        type=Path,
        help='vmlinuz file [.linux section]',
        config_key='UKI/Linux',
    ),
    ConfigItem(
        '--os-release',
        metavar='TEXT|@PATH',
        help='path to os-release file [.osrel section]',
        config_key='UKI/OSRelease',
    ),
    ConfigItem(
        '--cmdline',
        metavar='TEXT|@PATH',
        help='kernel command line [.cmdline section]',
        config_key='UKI/Cmdline',
    ),
    ConfigItem(
        '--initrd',
        metavar='INITRD',
        type=Path,
        action='append',
        help='initrd file [part of .initrd section]',
        config_key='UKI/Initrd',
        config_push=ConfigItem.config_list_prepend,
    ),
    ConfigItem(
        '--efifw',
        metavar='DIR',
        type=Path,
        action='append',
        default=[],
        help='Directory with efi firmware binary file [.efifw section]',
        config_key='UKI/Firmware',
        config_push=ConfigItem.config_list_prepend,
    ),
    ConfigItem(
        '--microcode',
        metavar='UCODE',
        type=Path,
        help='microcode file [.ucode section]',
        config_key='UKI/Microcode',
    ),
    ConfigItem(
        '--splash',
        metavar='BMP',
        type=Path,
        help='splash image bitmap file [.splash section]',
        config_key='UKI/Splash',
    ),
    ConfigItem(
        '--devicetree',
        metavar='PATH',
        type=Path,
        help='Device Tree file [.dtb section]',
        config_key='UKI/DeviceTree',
    ),
    ConfigItem(
        '--devicetree-auto',
        metavar='PATH',
        type=Path,
        action='append',
        help='DeviceTree file for automatic selection [.dtbauto section]',
        default=[],
        config_key='UKI/DeviceTreeAuto',
        config_push=ConfigItem.config_list_prepend,
    ),
    ConfigItem(
        '--hwids',
        metavar='DIR',
        type=Path,
        help='Directory with HWID text files [.hwids section]',
        config_key='UKI/HWIDs',
    ),
    ConfigItem(
        '--uname',
        metavar='VERSION',
        help='"uname -r" information [.uname section]',
        config_key='UKI/Uname',
    ),
    ConfigItem(
        '--sbat',
        metavar='TEXT|@PATH',
        help='SBAT policy [.sbat section]',
        default=[],
        action='append',
        config_key='UKI/SBAT',
    ),
    ConfigItem(
        '--pcrpkey',
        metavar='KEY',
        type=Path,
        help='embedded public key to seal secrets to [.pcrpkey section]',
        config_key='UKI/PCRPKey',
    ),
    ConfigItem(
        '--section',
        dest='sections',
        metavar='NAME:TEXT|@PATH',
        action='append',
        default=[],
        help='section as name and contents [NAME section] or section to print',
    ),
    ConfigItem(
        '--profile',
        metavar='TEST|@PATH',
        help='Profile information [.profile section]',
        config_key='UKI/Profile',
    ),
    ConfigItem(
        '--join-profile',
        dest='join_profiles',
        metavar='PATH',
        action='append',
        default=[],
        help='A PE binary containing an additional profile to add to the UKI',
    ),
    ConfigItem(
        '--sign-profile',
        dest='sign_profiles',
        metavar='ID',
        action='append',
        default=[],
        help='Which profiles to sign expected PCR measurements for',
    ),
    ConfigItem(
        '--efi-arch',
        metavar='ARCH',
        choices=('ia32', 'x64', 'arm', 'aa64', 'riscv32', 'riscv64', 'loongarch32', 'loongarch64'),
        help='target EFI architecture',
        config_key='UKI/EFIArch',
    ),
    ConfigItem(
        '--stub',
        type=Path,
        help='path to the sd-stub file [.text,.data,… sections]',
        config_key='UKI/Stub',
    ),
    ConfigItem(
        '--pcr-banks',
        metavar='BANK…',
        type=parse_banks,
        config_key='UKI/PCRBanks',
    ),
    ConfigItem(
        '--signing-engine',
        metavar='ENGINE',
        help='OpenSSL engine to use for signing',
        config_key='UKI/SigningEngine',
    ),
    ConfigItem(
        '--signing-provider',
        metavar='PROVIDER',
        help='OpenSSL provider to use for signing',
        config_key='UKI/SigningProvider',
    ),
    ConfigItem(
        '--certificate-provider',
        metavar='PROVIDER',
        help='OpenSSL provider to load certificate from',
        config_key='UKI/CertificateProvider',
    ),
    ConfigItem(
        '--signtool',
        choices=('sbsign', 'pesign', 'systemd-sbsign'),
        dest='signtool',
        help=(
            'whether to use sbsign or pesign. It will also be inferred by the other '
            'parameters given: when using --secureboot-{private-key/certificate}, sbsign '
            'will be used, otherwise pesign will be used'
        ),
        config_key='UKI/SecureBootSigningTool',
    ),
    ConfigItem(
        '--secureboot-private-key',
        dest='sb_key',
        help='required by --signtool=sbsign|systemd-sbsign. Path to key file or engine/provider designation for SB signing',  # noqa: E501
        config_key='UKI/SecureBootPrivateKey',
    ),
    ConfigItem(
        '--secureboot-certificate',
        dest='sb_cert',
        help=(
            'required by --signtool=sbsign. sbsign needs a path to certificate file or engine-specific designation for SB signing'  # noqa: E501
        ),
        config_key='UKI/SecureBootCertificate',
    ),
    ConfigItem(
        '--secureboot-certificate-dir',
        dest='sb_certdir',
        default='/etc/pki/pesign',
        help=(
            'required by --signtool=pesign. Path to nss certificate database directory for PE signing. Default is /etc/pki/pesign'  # noqa: E501
        ),
        config_key='UKI/SecureBootCertificateDir',
        config_push=ConfigItem.config_set,
    ),
    ConfigItem(
        '--secureboot-certificate-name',
        dest='sb_cert_name',
        help=(
            'required by --signtool=pesign. pesign needs a certificate nickname of nss certificate database entry to use for PE signing'  # noqa: E501
        ),
        config_key='UKI/SecureBootCertificateName',
    ),
    ConfigItem(
        '--secureboot-certificate-validity',
        metavar='DAYS',
        type=int,
        dest='sb_cert_validity',
        default=365 * 10,
        help="period of validity (in days) for a certificate created by 'genkey'",
        config_key='UKI/SecureBootCertificateValidity',
        config_push=ConfigItem.config_set,
    ),
    ConfigItem(
        '--sign-kernel',
        action=argparse.BooleanOptionalAction,
        help='Sign the embedded kernel',
        config_key='UKI/SignKernel',
    ),
    ConfigItem(
        '--pcr-private-key',
        dest='pcr_private_keys',
        action='append',
        help='private part of the keypair or engine/provider designation for signing PCR signatures',
        config_key='PCRSignature:/PCRPrivateKey',
        config_push=ConfigItem.config_set_group,
    ),
    ConfigItem(
        '--pcr-public-key',
        dest='pcr_public_keys',
        metavar='PATH',
        action='append',
        help='public part of the keypair or engine/provider designation for signing PCR signatures',
        config_key='PCRSignature:/PCRPublicKey',
        config_push=ConfigItem.config_set_group,
    ),
    ConfigItem(
        '--phases',
        dest='phase_path_groups',
        metavar='PHASE-PATH…',
        type=parse_phase_paths,
        action='append',
        help='phase-paths to create signatures for',
        config_key='PCRSignature:/Phases',
        config_push=ConfigItem.config_set_group,
    ),
    ConfigItem(
        '--tools',
        type=Path,
        action='append',
        help='Directories to search for tools (systemd-measure, …)',
    ),
    ConfigItem(
        ('--output', '-o'),
        type=Path,
        help='output file path',
    ),
    ConfigItem(
        '--measure',
        action=argparse.BooleanOptionalAction,
        help='print systemd-measure output for the UKI',
    ),
    ConfigItem(
        '--policy-digest',
        action=argparse.BooleanOptionalAction,
        help='print systemd-measure policy digests for the UKI',
    ),
    ConfigItem(
        '--json',
        choices=('pretty', 'short', 'off'),
        default='off',
        help='generate JSON output',
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
        help='print all sections',
        action='store_true',
    ),
]

CONFIGFILE_ITEMS = {item.config_key: item for item in CONFIG_ITEMS if item.config_key}


def apply_config(namespace: argparse.Namespace, filename: Union[str, Path, None] = None) -> None:
    if filename is None:
        if namespace.config:
            # Config set by the user, use that.
            filename = namespace.config
            print(f'Using config file: {filename}', file=sys.stderr)
        else:
            # Try to look for a config file then use the first one found.
            for config_dir in DEFAULT_CONFIG_DIRS:
                filename = Path(config_dir) / DEFAULT_CONFIG_FILE
                if filename.is_file():
                    # Found a config file, use it.
                    print(f'Using found config file: {filename}', file=sys.stderr)
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
        strict=False,
    )
    # Do not make keys lowercase
    cp.optionxform = lambda option: option  # type: ignore

    # The API is not great.
    read = cp.read(filename)
    if not read:
        raise OSError(f'Failed to read {filename}')

    for section_name, section in cp.items():
        idx = section_name.find(':')
        if idx >= 0:
            section_name, group = section_name[: idx + 1], section_name[idx + 1 :]
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


def config_example() -> Iterator[str]:
    prev_section: Optional[str] = None
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
        option_string: Optional[str] = None,
    ) -> None:
        page(parser.format_help(), True)
        parser.exit()


def create_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description='Build and sign Unified Kernel Images',
        usage='\n  '
        + textwrap.dedent("""\
          ukify {b}build{e} [--linux=LINUX] [--initrd=INITRD] [options…]
            ukify {b}genkey{e} [options…]
            ukify {b}inspect{e} FILE… [options…]
        """).format(b=Style.bold, e=Style.reset),
        allow_abbrev=False,
        add_help=False,
        epilog='\n  '.join(('config file:', *config_example())),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    for item in CONFIG_ITEMS:
        item.add_to(p)

    # Suppress printing of usage synopsis on errors
    p.error = lambda message: p.exit(2, f'{p.prog}: error: {message}\n')  # type: ignore

    # Make --help paged
    p.add_argument(
        '-h', '--help',
        action=PagerHelpAction,
        help='show this help message and exit',
    )  # fmt: skip

    return p


def resolve_at_path(value: Optional[str]) -> Union[Path, str, None]:
    if value and value.startswith('@'):
        return Path(value[1:])

    return value


def finalize_options(opts: argparse.Namespace) -> None:
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
        raise ValueError('--linux=/--initrd= options cannot be used with positional arguments')
    else:
        print("Assuming obsolete command line syntax with no verb. Please use 'build'.", file=sys.stderr)
        if opts.positional:
            opts.linux = Path(opts.positional[0])
        # If we have initrds from parsing config files, append our positional args at the end
        opts.initrd = (opts.initrd or []) + [Path(arg) for arg in opts.positional[1:]]
        opts.verb = 'build'

    # Check that --pcr-public-key=, --pcr-private-key=, and --phases=
    # have either the same number of arguments or are not specified at all.
    # But allow a single public key, for offline PCR signing, to pre-populate the JSON object
    # with the certificate's fingerprint.
    n_pcr_pub = None if opts.pcr_public_keys is None else len(opts.pcr_public_keys)
    n_pcr_priv = None if opts.pcr_private_keys is None else len(opts.pcr_private_keys)
    n_phase_path_groups = None if opts.phase_path_groups is None else len(opts.phase_path_groups)
    if opts.policy_digest and n_pcr_priv is not None:
        raise ValueError('--pcr-private-key= cannot be specified with --policy-digest')
    if opts.policy_digest and (n_pcr_pub is None or n_pcr_pub != 1):
        raise ValueError('--policy-digest requires exactly one --pcr-public-key=')
    if n_pcr_pub is not None and n_pcr_priv is not None and n_pcr_pub != n_pcr_priv:
        raise ValueError('--pcr-public-key= specifications must match --pcr-private-key=')
    if n_phase_path_groups is not None and n_phase_path_groups != n_pcr_priv:
        raise ValueError('--phases= specifications must match --pcr-private-key=')

    opts.cmdline = resolve_at_path(opts.cmdline)

    if isinstance(opts.cmdline, str):
        # Drop whitespace from the command line. If we're reading from a file,
        # we copy the contents verbatim. But configuration specified on the command line
        # or in the config file may contain additional whitespace that has no meaning.
        opts.cmdline = ' '.join(opts.cmdline.split())

    opts.os_release = resolve_at_path(opts.os_release)

    if not opts.os_release and opts.linux:
        p = Path('/etc/os-release')
        if not p.exists():
            p = Path('/usr/lib/os-release')
        opts.os_release = p

    if opts.efi_arch is None:
        opts.efi_arch = guess_efi_arch()

    if opts.stub is None:
        if opts.linux is not None:
            opts.stub = Path(f'/usr/lib/systemd/boot/efi/linux{opts.efi_arch}.efi.stub')
        else:
            opts.stub = Path(f'/usr/lib/systemd/boot/efi/addon{opts.efi_arch}.efi.stub')

    if opts.signing_engine and opts.signing_provider:
        raise ValueError('Only one of --signing-engine= and --signing-provider= may be specified')

    if opts.signing_engine is None and opts.signing_provider is None and opts.sb_key:
        opts.sb_key = Path(opts.sb_key)

    if opts.certificate_provider is None and opts.sb_cert:
        opts.sb_cert = Path(opts.sb_cert)

    if bool(opts.sb_key) ^ bool(opts.sb_cert):
        # one param only given, sbsign needs both
        raise ValueError(
            '--secureboot-private-key= and --secureboot-certificate= must be specified together'
        )
    elif bool(opts.sb_key) and bool(opts.sb_cert):
        # both param given, infer sbsign and in case it was given, ensure signtool=sbsign
        if opts.signtool and opts.signtool not in ('sbsign', 'systemd-sbsign'):
            raise ValueError(
                f'Cannot provide --signtool={opts.signtool} with --secureboot-private-key= and --secureboot-certificate='  # noqa: E501
            )
        if not opts.signtool:
            opts.signtool = 'sbsign'
    elif bool(opts.sb_cert_name):
        # sb_cert_name given, infer pesign and in case it was given, ensure signtool=pesign
        if opts.signtool and opts.signtool != 'pesign':
            raise ValueError(
                f'Cannot provide --signtool={opts.signtool} with --secureboot-certificate-name='
            )
        opts.signtool = 'pesign'

    if opts.signing_provider and opts.signtool != 'systemd-sbsign':
        raise ValueError('--signing-provider= can only be used with --signtool=systemd-sbsign')

    if opts.certificate_provider and opts.signtool != 'systemd-sbsign':
        raise ValueError('--certificate-provider= can only be used with --signtool=systemd-sbsign')

    if opts.sign_kernel and not opts.sb_key and not opts.sb_cert_name:
        raise ValueError(
            '--sign-kernel requires either --secureboot-private-key= and --secureboot-certificate= (for sbsign) or --secureboot-certificate-name= (for pesign) to be specified'  # noqa: E501
        )

    opts.profile = resolve_at_path(opts.profile)

    if opts.join_profiles and not opts.profile:
        # If any additional profiles are added, we need a base profile as well so add one if
        # one wasn't explicitly provided
        opts.profile = 'ID=main'

    if opts.verb == 'build' and opts.output is None:
        if opts.linux is None:
            raise ValueError('--output= must be specified when building a PE addon')
        suffix = '.efi' if opts.sb_key or opts.sb_cert_name else '.unsigned.efi'
        opts.output = opts.linux.name + suffix

    # Now that we know if we're inputting or outputting, really parse section config
    f = Section.parse_output if opts.verb == 'inspect' else Section.parse_input
    opts.sections = [f(s) for s in opts.sections]
    # A convenience dictionary to make it easy to look up sections
    opts.sections_by_name = {s.name: s for s in opts.sections}


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    opts = create_parser().parse_args(args)
    apply_config(opts)
    finalize_options(opts)
    return opts


def main() -> None:
    opts = UkifyConfig.from_namespace(parse_args())
    if opts.summary:
        # TODO: replace pprint() with some fancy formatting.
        pprint.pprint(vars(opts))
    elif opts.verb == 'build':
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
