#!/usr/bin/python3

from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory


ONE_MIBIBYTE = 1024 * 1024


@contextmanager
def setup(mkosi_args, qemu_opts):
    with TemporaryDirectory() as td:
        td = Path(td)
        for i in range(10):
            diskpath = td / f"simultaneousevents{i}.img"
            with open(diskpath, 'w') as f:
                f.truncate(128 * ONE_MIBIBYTE)

            qemu_opts += [
                '-device',
                f"scsi-hd,drive=drive{i},serial=deadbeeftest{i}",
                '-drive',
                f"format=raw,cache=unsafe,"
                f"file={str(diskpath).replace(',', ',,')},"
                f"if=none,id=drive{i}",
            ]

        yield
