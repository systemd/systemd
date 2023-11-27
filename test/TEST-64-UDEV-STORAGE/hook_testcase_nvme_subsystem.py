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
    if b'name "nvme-subsys"' not in result.stdout:
        print("nvme-subsystem device driver is not available, skipping test...")
        exit(77)

    with TemporaryDirectory() as td:
        td = Path(td)
        for i in range(2):
            disk = td / f"disk{i}.img"
            with open(disk, 'w') as f:
                f.truncate(ONE_MIBIBYTE)
                f.write(f"device{i}")
        qemu_opts += [
            # Create an NVM Subsystem Device
            '-device', 'nvme-subsys,id=nvme-subsys-64,nqn=subsys64',
            # Attach two NVM controllers to it
            '-device', 'nvme,subsys=nvme-subsys-64,serial=deadbeef',
            '-device', 'nvme,subsys=nvme-subsys-64,serial=deadbeef',
            # And create two shared namespaces attached to both controllers
            '-device', 'nvme-ns,drive=nvme0,nsid=16,shared=on',
            '-drive', f'format=raw,cache=unsafe,file={str(td).replace(",", ",,")}/disk0.img,if=none,id=nvme0',
            '-device', 'nvme-ns,drive=nvme1,nsid=17,shared=on',
            '-drive', f'format=raw,cache=unsafe,file={str(td).replace(",", ",,")}/disk1.img,if=none,id=nvme1',
        ]
        yield
