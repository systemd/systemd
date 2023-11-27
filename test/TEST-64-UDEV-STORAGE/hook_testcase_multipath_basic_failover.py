#!/usr/bin/python3

from contextlib import contextmanager
from os import environ
from pathlib import Path
from subprocess import run, DEVNULL
from tempfile import TemporaryDirectory


ONE_MIBIBYTE = 1024 * 1024


@contextmanager
def setup(mkosi_args, qemu_opts):
    with TemporaryDirectory() as td:
        td = Path(td)
        repart_d = td / 'repart.d'
        repart_d.mkdir()
        partdisk = td / 'multipathpartitioned.img'

        with open(repart_d / f"01-empty.conf", 'w') as f:
            f.write("[Partition]\n"
                    "Type=linux-generic\n"
                    "Label=first_partition\n"
                    "SizeMinBytes=5M\n")

        with open(repart_d / f"02-failover.conf", 'w') as f:
            f.write("[Partition]\n"
                    "Type=linux-generic\n"
                    "Label=failover_part\n"
                    "UUID=deadbeef-dead-dead-beef-000000000000\n"
                    "Format=ext4\n"
                    "SizeMinBytes=5M\n")

        run(['systemd-repart',
             '--empty=create',
             '--size=16M',
             '--offline=true',
             '--definitions', repart_d,
             partdisk],
            check=True, stdin=DEVNULL,
            # TODO: If repart gains volume label/uuid specifiers, use those
            env=dict(environ,
                     SYSTEMD_REPART_MKFS_OPTIONS_EXT4="-U deadbeef-dead-dead-beef-111111111111 -L failover_vol"))

        # Add 16 multipath devices, each backed by 4 paths
        for ndisk in range(16):
            wwn = f"0xDEADDEADBEEF{ndisk:04d}"
            if ndisk == 0:
                image = partdisk
            else:
                image = td / f"disk{ndisk}.img"
                with open(image, 'w') as f:
                    f.truncate(ONE_MIBIBYTE)
                    f.write(f"device{ndisk}")
            for nback in range(4):
                qemu_opts += [
                    '-device',
                    f"scsi-hd,drive=drive{ndisk}x{nback},serial=MPIO{ndisk},"
                    f"wwn={wwn}",
                    '-drive',
                    f"format=raw,cache=unsafe,"
                    f"file={str(image).replace(',', ',,')},file.locking=off,"
                    f"if=none,id=drive{ndisk}x{nback}"
                ]

        yield
