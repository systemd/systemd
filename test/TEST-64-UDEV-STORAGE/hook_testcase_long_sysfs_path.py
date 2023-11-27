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
        partdisk = td / 'longsysfspath.img'
        qemu_opts += [
            '-drive',
            "if=none,id=drive0,format=raw,cache=unsafe,"
            f"file={str(partdisk).replace(',', ',,')}",
            '-device', 'pci-bridge,id=pci_bridge0,chassis_nr=64',
        ]

        with open(repart_d / f"01-swap.conf", 'w') as f:
            f.write("[Partition]\n"
                    "Type=swap\n"
                    "Label=test_swap\n"
                    "Format=swap\n"
                    "SizeMinBytes=32M\n")

        with open(repart_d / f"02-part.conf", 'w') as f:
            f.write("[Partition]\n"
                    "Type=linux-generic\n"
                    "Label=test_part\n"
                    "UUID=deadbeef-dead-dead-beef-000000000000\n"
                    "Format=ext4\n"
                    "SizeMinBytes=5M\n")

        run(['systemd-repart',
             '--empty=create',
             '--size=64M',
             '--offline=true',
             '--definitions', repart_d,
             partdisk],
            check=True, stdin=DEVNULL,
            # TODO: If repart gains volume label/uuid specifiers, use those
            env=dict(environ,
                     SYSTEMD_REPART_MKFS_OPTIONS_SWAP="-U deadbeef-dead-dead-beef-111111111111 -L swap_vol",
                     SYSTEMD_REPART_MKFS_OPTIONS_EXT4="-U deadbeef-dead-dead-beef-222222222222 -L data_vol"))

        # Create 25 additional PCI bridges, each one connected to the previous one
        # (basically a really long extension cable), and attach a virtio drive to
        # the last one. This should force udev into attempting to create a device
        # unit with a _really_ long name.
        for brid in range(1, 26):
            qemu_opts += [
                '-device',
                f"pci-bridge,id=pci_bridge{brid},bus=pci_bridge{brid - 1},"
                f"chassis_nr={64 + brid}"
            ]
        qemu_opts += [
            '-device',
            f"virtio-blk-pci,drive=drive0,scsi=off,bus=pci_bridge{brid}"
        ]

        yield
