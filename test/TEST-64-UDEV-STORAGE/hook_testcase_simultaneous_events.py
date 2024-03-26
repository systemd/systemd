#!/usr/bin/python3

from contextlib import contextmanager
from shlex import quote


@contextmanager
def setup(mkosi_args):
    qemu_args = []
    qemu_drives = []

    for i in range(10):
        drive_id = f"drivesimultaneousevents{i}"
        qemu_args += [
            '-device',
            f"scsi-hd,drive={drive_id},serial=deadbeeftest{i}",
        ]
        qemu_drives += [f"{drive_id}:128M::cache=unsafe"]

    mkosi_args += [
        f"--qemu-args={' '.join(quote(v) for v in qemu_args)}",
        f"--qemu-drive={' '.join(qemu_drives)}",
    ]
    yield
