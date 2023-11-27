#!/usr/bin/python3

from contextlib import contextmanager
from os import uname
from pathlib import Path
from re import match
from shutil import copy, which
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
    result = run([find_qemu(), '-device', 'help'], check=True, capture_output=True, stdin=DEVNULL)
    if b'name "virtio-scsi-pci"' not in result.stdout:
        print("virtio-scsi-pci device driver is not available, skipping test...")
        exit(77)

    num_disk = 16
    num_part = 8

    qemu_opts += ['-device', 'virtio-scsi-pci,id=scsi0,num_queues=4']

    with TemporaryDirectory() as td:
        td = Path(td)
        repart_d = td / 'repart.d'
        repart_d.mkdir()
        namedpart0 = td / f"namedpart0.img"

        for i in range(num_part):
            with open(repart_d / f"{i:02d}-part.conf", 'w') as f:
                f.write("[Partition]\n"
                        "Type=linux-generic\n"
                        "Label=Hello world\n"
                        "SizeMinBytes=2M\n")

        run(['systemd-repart',
             '--empty=create',
             '--size=auto',
             '--offline=true',
             '--definitions', repart_d,
             namedpart0], check=True, stdin=DEVNULL)

        for i in range(0, num_disk):
            disk = td / f"namedpart{i}.img"
            if i > 0:
                copy(namedpart0, disk)
            qemu_opts += [
                '-device',
                f"scsi-hd,drive=drive{i},bus=scsi0.0,channel=0,scsi-id=0,lun={i}",
                '-drive',
                f"format=raw,cache=unsafe,file={str(disk).replace(',', ',,')},if=none,id=drive{i}",
            ]

        mkosi_args += ['--qemu-smp=1']
        yield
