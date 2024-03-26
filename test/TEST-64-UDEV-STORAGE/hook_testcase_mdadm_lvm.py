#!/usr/bin/python3

from contextlib import contextmanager
from shlex import quote


@contextmanager
def setup(mkosi_args):
    qemu_args = ['-device', 'ahci,id=ahci0']
    qemu_drives = []

    for i in range(5):
        drive_id = f"drivemdadmlvm{i}"
        qemu_args += [
            '-device',
            f"ide-hd,bus=ahci0.{i},drive={drive_id},model=foobar,"
            f"serial=deadbeefmdadmlvm{i}",
        ]
        qemu_drives += [f"{drive_id}:64M::cache=unsafe"]

    mkosi_args += [
        f"--qemu-args={' '.join(quote(v) for v in qemu_args)}",
        f"--qemu-drive={' '.join(qemu_drives)}",
    ]
    yield
