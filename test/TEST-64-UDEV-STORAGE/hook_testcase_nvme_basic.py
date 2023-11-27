#!/usr/bin/python3

from contextlib import contextmanager
from os import uname
from pathlib import Path
from re import match
from shutil import which
from subprocess import run, DEVNULL
from tempfile import TemporaryDirectory


ONE_MIBIBYTE = 1024 * 1024


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
def setup(mkosi_args, qemu_opts):
    result = run([find_qemu(), '-device', 'help'],
                 check=True, capture_output=True, stdin=DEVNULL)
    if b'name "nvme"' not in result.stdout:
        print("nvme device driver is not available, skipping test...")
        exit(77)
    for i in range(4):
        qemu_opts += ['-device', f"megasas-gen2,id=scsi{i}"]
    with TemporaryDirectory() as td:
        td = Path(td)
        for i in range(20):
            disk = td / f"disk{i}.img"
            with open(disk, 'w') as f:
                f.truncate(ONE_MIBIBYTE)
                f.write(f"device{i}")

        def add_drive(i, serial):
            nonlocal qemu_opts
            disk = str(td / f"disk{i}.img").replace(',', ',,')
            qemu_opts += [
                '-device', f"nvme,drive=nvme{i},serial={serial},num_queues=8",
                '-drive',
                f"format=raw,cache=unsafe,file={disk},if=none,id=nvme{i}",
            ]

        for i in range(5):
            add_drive(i, serial=f"deadbeef{i}")
        for i in range(5, 10):
            add_drive(i, serial=f"    deadbeef  {i}   ")
        for i in range(10, 15):
            add_drive(i, serial=f"    dead/beef/{i}   ")
        for i in range(15, 20):
            add_drive(i, serial=f"dead/../../beef/{i}")
        yield
