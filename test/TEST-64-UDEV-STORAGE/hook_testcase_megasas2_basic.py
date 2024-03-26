#!/usr/bin/python3

from contextlib import contextmanager
from os import uname
from re import match
from shlex import quote
from shutil import which
from subprocess import run, DEVNULL


def find_qemu():
    arch = uname().machine
    if arch == 'x86_64':
        return which("qemu-system-x86_64")
    elif match('i.*86', arch):
        return which("qemu-system-i386")
    elif match('ppc64.*', arch):
        return which("qemu-system-ppc64")
    else:
        return which(f"qemu-system-{arch}")


@contextmanager
def setup(mkosi_args):
    result = run([find_qemu(), '-device', 'help'],
                 check=True, capture_output=True, stdin=DEVNULL)
    if b'name "megasas-gen2"' not in result.stdout:
        print("megasas-gen2 device driver is not available, skipping test...")
        exit(77)

    qemu_args = []
    qemu_drives = []

    for i in range(4):
        qemu_args += ['-device', f"megasas-gen2,id=scsi{i}"]

    for i in range(128):
        drive_id = f"drive{i}"
        qemu_args += [
            '-device',
            f"scsi-hd,drive={drive_id},bus=scsi{i // 32}.0,channel=0,"
            f"scsi-id={i % 32},lun=0",
        ]
        qemu_drives += [f"{drive_id}:1M::cache=unsafe"]

    mkosi_args += [
        f"--qemu-args={' '.join(quote(v) for v in qemu_args)}",
        f"--qemu-drive={' '.join(qemu_drives)}",
    ]
    yield
