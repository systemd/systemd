#!/usr/bin/python3

from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory


ONE_MIBIBYTE = 1024 * 1024


@contextmanager
def setup(mkosi_args, qemu_opts):
    qemu_opts += ['-device', 'ahci,id=ahci0']
    with TemporaryDirectory() as td:
        td = Path(td)

        for i in range(5):
            disk = td / f"mdadmbasic{i}.img"
            with open(disk, 'w') as f:
                f.truncate(64 * ONE_MIBIBYTE)

            qemu_opts += [
                '-device',
                f"ide-hd,bus=ahci0.{i},drive=drive{i},model=foobar,"
                f"serial=deadbeefmdadm{i}",
                '-drive',
                f"format=raw,cache=unsafe,file={str(disk).replace(',', ',,')},"
                f"if=none,id=drive{i}",
            ]

        yield
