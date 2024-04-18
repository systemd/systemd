#!/usr/bin/python3

from contextlib import contextmanager
from shlex import quote


@contextmanager
def setup(mkosi_args):
    qemu_args = ['-device', 'ahci,id=ahci0']
    qemu_drives = []

    for i in range(4):
        drive_id = f"drivebtrfsbasic{i}"
        qemu_args += [
            '-device',
            f"ide-hd,bus=ahci0.{i},drive={drive_id},model=foobar,"
            f"serial=deadbeefbtrfs{i}",
        ]
        qemu_drives += [f"{drive_id}:{350 if i == 0 else 128}M::cache=unsafe"]

    mkosi_args += [
        f"--qemu-args={' '.join(quote(v) for v in qemu_args)}",
        f"--qemu-drive={' '.join(qemu_drives)}",
    ]
    yield
