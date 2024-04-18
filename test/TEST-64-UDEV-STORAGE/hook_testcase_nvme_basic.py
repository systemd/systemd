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
    if b'name "nvme"' not in result.stdout:
        print("nvme device driver is not available, skipping test...")
        exit(77)

    qemu_args = []
    qemu_drives = []

    for i in range(4):
        qemu_args += ['-device', f"megasas-gen2,id=scsi{i}"]

    def add_drive(i, serial):
        nonlocal qemu_args
        nonlocal qemu_drives
        drive_id = f"nvme{i}"
        qemu_args += ['-device', f"nvme,drive={drive_id},serial={serial},num_queues=8"]
        qemu_drives += [f"{drive_id}:1M::cache=unsafe"]

    for i in range(5):
        add_drive(i, serial=f"deadbeef{i}")
    for i in range(5, 10):
        add_drive(i, serial=f"    deadbeef  {i}   ")
    for i in range(10, 15):
        add_drive(i, serial=f"    dead/beef/{i}   ")
    for i in range(15, 20):
        add_drive(i, serial=f"dead/../../beef/{i}")

    mkosi_args += [
        f"--qemu-args={' '.join(quote(v) for v in qemu_args)}",
        f"--qemu-drive={' '.join(qemu_drives)}",
    ]
    yield
