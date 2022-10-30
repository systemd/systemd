#!/usr/bin/python
# SPDX-License-Identifier: LGPL-2.1+

import argparse
import dataclasses
import itertools
import pathlib
import os
import shlex
import subprocess
import tempfile
import typing

efi_arches = {
        # host_arch: efi_arch
        'x86'    : 'ia32',
        'x86_64' : 'x64',
        'arm'    : 'arm',
        'aarch64': 'aa64',
        'riscv64': 'riscv64',
}

def guess_efi_arch():
    arch = os.uname().machine
    efi_arch = efi_arches[arch]

    if arch == 'x86_64':
        try:
            size = open('/sys/firmware/efi/fw_platform_size').read().strip()
        except FileNotFoundError:
            pass
        else:
            if int(size) == 32:
                efi_arch = 'ia32'

    print(f'Host arch {arch!r}, efi arch {efi_arch!r}')
    return efi_arch

def shell_join(cmd):
    return ' '.join(shlex.quote(str(x)) for x in cmd)

@dataclasses.dataclass
class Section:
    name: str
    content: str
    offset: int
    tmpfile: typing.Optional[typing.IO] = None

    @classmethod
    def create(cls, name, content, offset):
        if isinstance(content, str):
            tmp = tempfile.NamedTemporaryFile(mode='wt', prefix=f'tmp{name}')
            tmp.write(content)
            tmp.flush()
            content = tmp.name
        else:
            tmp = None

        return cls(name, content, offset, tmpfile=tmp)

    @classmethod
    def parse_arg(cls, s):
        parts = s.split(':')
        if len(parts) < 2 or len(parts) > 3:
            raise ValueError(f'Cannot parse section spec: {s!r}')
        name, content = parts[:2]
        offset = int(parts[2], base=0) if len(parts) >= 3 else None
        return cls.create(name, content, offset)


def parse_args():
    p = argparse.ArgumentParser(
        description='Build and sign Unified Kernel Images',
        usage='''\
usage: ukify [options…] linux initrd
       ukify -h | --help
''')

    # Suppress printing of usage synopsis on errors
    p.error = lambda message: p.exit(2, f'{p.prog}: error: {message}\n')

    p.add_argument('linux',
                   type=pathlib.Path)
    p.add_argument('initrd',
                   type=pathlib.Path)

    p.add_argument('--cmdline')

    p.add_argument('--os-release',
                   type=pathlib.Path)

    p.add_argument('--devicetree',
                   type=pathlib.Path)
    p.add_argument('--splash',
                   type=pathlib.Path)

    p.add_argument('--efi-arch',
                   choices=('ia32', 'x64', 'arm', 'aa64', 'riscv64'))

    p.add_argument('--stub',
                   type=pathlib.Path)

    p.add_argument('--section',
                   dest='sections',
                   metavar='NAME:CONTENTS[:OFFSET]',
                   type=Section.parse_arg,
                   action='append')

    p.add_argument('--output', '-o',
                   nargs='?')

    p.add_argument('--key',
                   type=pathlib.Path)
    p.add_argument('--cert',
                   type=pathlib.Path)

    p.add_argument('--measure',
                   action='store_true')

    args = p.parse_args()

    if bool(args.key) ^ bool(args.cert):
        raise ValueError('--key and --cert must be specified together')

    if args.os_release is None:
        p = pathlib.Path('/etc/os-release')
        if not p.exists():
            p = pathlib.Path('/usr/lib/os-release')
        args.os_release = p

    if args.efi_arch is None:
        args.efi_arch = guess_efi_arch()

    if args.stub is None:
        args.stub = f'/usr/lib/systemd/boot/efi/linux{args.efi_arch}.efi.stub'

    if args.output is None:
        suffix = '.efi' if args.key else '.unsigned.efi'
        args.output = args.linux.name + suffix

    return args


def check_inputs(args):
    for name, value in vars(args).items():
        if name == 'output':
            continue

        if not isinstance(value, pathlib.Path):
            continue

        # Open file to check that we can read it, or generate an exception
        open(value).close()


def make_uki(args):
    sections = [
        # FIXME: calculate offsets based on content size
        ('osrel',   args.os_release,    0x20_000),
        ('cmdline', args.cmdline,       0x30_000),
        ('dtb',     args.devicetree,    0x40_000),
        ('splash',  args.splash,       0x100_000),
        ('initrd',  args.initrd,     0x3_000_000),
        # linux shall be last to leave breathing room for decompression
        ('linux',   args.linux,      0x2_000_000),
    ]

    sections = [Section.create(name, content, offset)
                for name, content, offset in sections
                if content]

    # Insert extra sections just before .linux
    objcopy_sections = sections[:-1] + args.sections + sections[-1:]

    if args.key:
        unsigned = tempfile.NamedTemporaryFile(prefix='linux')
        output = unsigned.name
    else:
        output = args.output

    objcopy = [
        'objcopy',
        args.stub,
        *itertools.chain.from_iterable(
            ('--add-section',        f'.{s.name}={s.content}',
             '--change-section-vma', f'.{s.name}=0x{s.offset:x}')
            for s in objcopy_sections),
        output,
    ]
    print('+', shell_join(objcopy))
    subprocess.check_call(objcopy)

    # signing

    if args.key:
        sbsign = [
            'sbsign',
            '--key', args.key,
            '--cert', args.cert,
            unsigned.name,
            '--output', args.output,
        ]
        print('+', shell_join(sbsign))
        subprocess.check_call(sbsign)

        # We end up with no executable bits, let's reapply them
        os.umask(umask := os.umask(0))
        os.chmod(args.output, 0o777 & ~umask)

    print(f"Wrote {'signed' if args.key else 'unsigned'} {args.output}")

    # measurement

    if args.measure:
        measure = [
            '/usr/lib/systemd/systemd-measure',
            'calculate',
            *itertools.chain.from_iterable(
                (f'--{s.name}', s.content)
                for s in sections),
        ]
        print('+', shell_join(measure))
        subprocess.check_call(measure)


def main():
    args = parse_args()
    check_inputs(args)
    make_uki(args)


if __name__ == '__main__':
    main()
