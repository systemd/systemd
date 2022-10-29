#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1+

# pylint: disable=missing-docstring,invalid-name,import-outside-toplevel
# pylint: disable=consider-using-with,unspecified-encoding,line-too-long
# pylint: disable=too-many-locals,too-many-statements,too-many-branches

import argparse
import dataclasses
import fnmatch
import itertools
import os
import pathlib
import shlex
import subprocess
import tempfile
import typing

import pefile

EFI_ARCH_MAP = {
        # host_arch glob : [efi_arch, 32_bit_efi_arch?]
        'x86_64'       : ['x64', 'ia32'],
        'i[3456]86'    : ['ia32'],
        'aarch64'      : ['aa64', 'arm'],
        'arm[45678]*l' : ['arm'],
        'riscv64'      : ['riscv64'],
}
EFI_ARCHES = sum(EFI_ARCH_MAP.values(), [])

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


def pe_executable_size(filename):
    pe = pefile.PE(filename)
    section = pe.sections[-1]
    return section.VirtualAddress + section.Misc_VirtualSize


def round_to_page(x, page_size=4096):
    return (x + page_size - 1) // page_size * page_size


@dataclasses.dataclass
class Section:
    name: str
    content: pathlib.Path
    tmpfile: typing.Optional[typing.IO] = None
    offset: typing.Optional[int] = None
    measure: bool = False

    @classmethod
    def create(cls, name, contents, measure=False):
        if isinstance(contents, str):
            tmp = tempfile.NamedTemporaryFile(mode='wt', prefix=f'tmp{name}')
            tmp.write(contents)
            tmp.flush()
            contents = pathlib.Path(tmp.name)
        else:
            tmp = None

        return cls(name, contents, tmpfile=tmp, measure=measure)

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
        # not support them. A dot is prepended, so the name must be at most 7 chars.
        name = f'.{self.name}'
        if not name.isascii() or not name.isprintable():
            raise ValueError(f'Bad section name: {name!r}')
        if len(name) > 8:
            raise ValueError(f'Section name too long: {name!r}')


@dataclasses.dataclass
class UKI:
    executable: [pathlib.Path|str]
    sections: list[Section] = dataclasses.field(default_factory=list, init=False)
    offset: int = dataclasses.field(default=None, init=False)

    def __post_init__(self):
        self.offset = round_to_page(pe_executable_size(self.executable))

    def add_section(self, section):
        assert self.offset
        assert section.offset is None
        section.offset = self.offset
        self.offset += round_to_page(section.size())
        self.sections += [section]


def parse_banks(s):
    banks = s.split(',')
    # TODO: do some sanity checking here
    return banks


def check_splash(filename):
    if filename is None:
        return

    # import is delayed, to avoid import when the splash image is not used
    try:
        from PIL import Image
    except ImportError:
        return

    img = Image.open(filename)
    print(f'Splash image {filename} is {img.width}×{img.height} pixels')


def check_inputs(opts):
    for name, value in vars(opts).items():
        if name in {'output', 'tools'}:
            continue

        if not isinstance(value, pathlib.Path):
            continue

        # Open file to check that we can read it, or generate an exception
        value.open().close()

    check_splash(opts.splash)


def find_tool(name, fallback=None, opts=None):
    if opts and opts.tools:
        tool = opts.tools / name
        if tool.exists():
            return tool

    return fallback or name


def make_uki(opts):
    # kernel payload signing

    sbsign_tool = find_tool('sbsign', opts=opts)
    sbsign_invocation = [
        sbsign_tool,
        '--key', opts.sb_key,
        '--cert', opts.sb_cert,
    ]

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

    uki = UKI(opts.stub)

    # TODO: derive public key from from opts.pcr_private_key?
    pcrpkey = opts.pcrpkey or opts.pcr_public_key

    sections = [
        # name,     content,         measure?
        ('osrel',   opts.os_release, True ),
        ('cmdline', opts.cmdline,    True ),
        ('dtb',     opts.devicetree, True ),
        ('splash',  opts.splash,     True ),
        ('pcrpkey', pcrpkey,         True ),
        ('initrd',  opts.initrd,     True ),
        ('uname',   opts.uname,      False),

        # linux shall be last to leave breathing room for decompression.
        # We'll add it later.
    ]

    for name, content, measure in sections:
        if content:
            uki.add_section(Section.create(name, content, measure=measure))

    # systemd-measure doesn't know about those extra sections
    for section in opts.sections:
        uki.add_section(section)

    # PCR measurement
    measure_tool = find_tool('systemd-measure',
                             '/usr/lib/systemd/systemd-measure',
                             opts=opts)

    if opts.measure:
        cmd = [
            measure_tool,
            'calculate',
            f'--linux={linux}',
            *(f'--{s.name}={s.content}'
              for s in uki.sections
              if s.measure),
            *(f'--bank={bank}'
              for bank in opts.pcr_banks),
        ]
        print('+', shell_join(cmd))
        subprocess.check_call(cmd)

    # PCR signing

    if opts.pcr_private_key:
        cmd = [
            measure_tool,
            'sign',
            f'--linux={linux}',
            *(f'--{s.name}={s.content}'
              for s in uki.sections
              if s.measure),
            *(f'--bank={bank}'
              for bank in opts.pcr_banks),
            f'--private-key={opts.pcr_private_key}',
        ]
        if opts.pcr_public_key:
            cmd += [f'--public-key={opts.pcr_public_key}']

        print('+', shell_join(cmd))
        pcrsig = subprocess.check_output(cmd, text=True)

        uki.add_section(Section.create('pcrsig', pcrsig))

    # UKI creation

    uki.add_section(Section.create('linux', linux, measure=True))

    if opts.sb_key:
        unsigned = tempfile.NamedTemporaryFile(prefix='uki')
        output = unsigned.name
    else:
        output = opts.output

    objcopy_tool = find_tool('objcopy', opts=opts)

    cmd = [
        objcopy_tool,
        opts.stub,
        *itertools.chain.from_iterable(
            ('--add-section',        f'.{s.name}={s.content}',
             '--change-section-vma', f'.{s.name}=0x{s.offset:x}')
            for s in uki.sections),
        output,
    ]
    print('+', shell_join(cmd))
    subprocess.check_call(cmd)

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


def parse_args(args=None):
    p = argparse.ArgumentParser(
        description='Build and sign Unified Kernel Images',
        allow_abbrev=False,
        usage='''\
usage: ukify [options…] linux initrd
       ukify -h | --help
''')

    # Suppress printing of usage synopsis on errors
    p.error = lambda message: p.exit(2, f'{p.prog}: error: {message}\n')

    p.add_argument('linux',
                   type=pathlib.Path,
                   help='vmlinuz file [.linux section]')
    p.add_argument('initrd',
                   type=pathlib.Path,
                   help='initrd file [.initrd section]')

    p.add_argument('--cmdline',
                   metavar='TEXT|@PATH',
                   help='kernel command line [.cmdline section]')

    p.add_argument('--os-release',
                   metavar='TEXT|@PATH',
                   help='path to os-release file [.osrel section]')

    p.add_argument('--devicetree',
                   metavar='DTB',
                   type=pathlib.Path,
                   help='Device Tree file [.dtb section]')
    p.add_argument('--splash',
                   metavar='BMP',
                   type=pathlib.Path,
                   help='splash image bitmap file [.splash section]')
    p.add_argument('--pcrpkey',
                   metavar='KEY',
                   type=pathlib.Path,
                   help='embedded public key to seal secrets to [.pcrpkey section]')
    p.add_argument('--uname',
                   metavar='VERSION',
                   help='"uname -r" information [.uname section]')

    p.add_argument('--efi-arch',
                   metavar='ARCH',
                   choices=('ia32', 'x64', 'arm', 'aa64', 'riscv64'),
                   help='target EFI architecture')

    p.add_argument('--stub',
                   type=pathlib.Path,
                   help='path the the sd-stub file [.text,.data,… sections]')

    p.add_argument('--section',
                   dest='sections',
                   metavar='NAME:TEXT|@PATH',
                   type=Section.parse_arg,
                   action='append',
                   default=[],
                   help='additional section as name and contents [.NAME section]')

    p.add_argument('--pcr-private-key',
                   metavar='PATH',
                   type=pathlib.Path,
                   help='private part of the keypair for signing PCR signatures')
    p.add_argument('--pcr-public-key',
                   metavar='PATH',
                   type=pathlib.Path,
                   help='public part of the keypair for signing PCR signatures')
    p.add_argument('--pcr-banks',
                   metavar='BANK…',
                   type=parse_banks)

    p.add_argument('--secureboot-engine',
                   dest='sb_engine',
                   help='OpenSSL engine to use for signing')
    p.add_argument('--secureboot-private-key',
                   dest='sb_key',
                   help='path to key file or engine-specific designation for SB signing')
    p.add_argument('--secureboot-certificate',
                   dest='sb_cert',
                   help='path to certificate file or engine-specific designation for SB signing')

    p.add_argument('--sign-kernel',
                   action=argparse.BooleanOptionalAction,
                   help='Sign the embedded kernel')

    p.add_argument('--tools',
                   type=pathlib.Path,
                   help='a directory with systemd-measure and other tools')

    p.add_argument('--output', '-o',
                   type=pathlib.Path,
                   help='output file path')

    p.add_argument('--measure',
                   action=argparse.BooleanOptionalAction,
                   help='print systemd-measure output for the UKI')

    opts = p.parse_args(args)

    if opts.cmdline and opts.cmdline.startswith('@'):
        opts.cmdline = pathlib.Path(opts.cmdline[1:])

    if opts.os_release is not None and opts.os_release.startswith('@'):
        opts.os_release = pathlib.Path(opts.os_release[1:])
    elif opts.os_release is None:
        p = pathlib.Path('/etc/os-release')
        if not p.exists():
            p = pathlib.Path('/usr/lib/os-release')
        opts.os_release = p

    if opts.efi_arch is None:
        opts.efi_arch = guess_efi_arch()

    if opts.stub is None:
        opts.stub = f'/usr/lib/systemd/boot/efi/linux{opts.efi_arch}.efi.stub'

    if opts.sb_engine is None:
        opts.sb_key = pathlib.Path(opts.sb_key) if opts.sb_key else None
        opts.sb_cert = pathlib.Path(opts.sb_cert) if opts.sb_cert else None

    if bool(opts.sb_key) ^ bool(opts.sb_cert):
        raise ValueError('--secureboot-private-key= and --secureboot-certificate= must be specified together')

    if opts.sign_kernel and not opts.sb_key:
        raise ValueError('--sign-kernel requires --secureboot-private-key= and --secureboot-certificate= to be specified')

    if opts.output is None:
        suffix = '.efi' if opts.sb_key else '.unsigned.efi'
        opts.output = opts.linux.name + suffix

    for section in opts.sections:
        section.check_name()

    return opts


def main():
    opts = parse_args()
    check_inputs(opts)
    make_uki(opts)


if __name__ == '__main__':
    main()
