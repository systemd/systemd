#!/usr/bin/python3

from contextlib import contextmanager
from os import environ
from pathlib import Path
from subprocess import run, DEVNULL
from tempfile import TemporaryDirectory


ONE_MIBIBYTE = 1024 * 1024


@contextmanager
def setup(mkosi_args, qemu_opts):
    qemu_opts += ['-device', 'ahci,id=ahci0']

    with TemporaryDirectory() as td:
        td = Path(td)
        for i in range(4):
            disk = td / f"btrfsbasic{i}.img"
            with open(disk, 'w') as f:
                f.truncate((350 if i == 0 else 128) * ONE_MIBIBYTE)

            qemu_opts += [
                '-device',
                f"ide-hd,bus=ahci0.{i},drive=drive{i},model=foobar,"
                f"serial=deadbeefbtrfs{i}",
                '-drive',
                f"format=raw,cache=unsafe,"
                f"file={str(disk).replace(',', ',,')},if=none,id=drive{i}",
            ]

        yield
