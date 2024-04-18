#!/usr/bin/python3

from contextlib import contextmanager
from os import uname
from re import match
from shlex import quote
from shutil import which
from subprocess import run, DEVNULL


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
def setup(mkosi_args):
    result = run([find_qemu(), '-device', 'help'],
                 check=True, capture_output=True, stdin=DEVNULL)
    if b'name "nvme-subsys"' not in result.stdout:
        print("nvme-subsystem device driver is not available, skipping test...")
        exit(77)

    qemu_args = [
        # Create an NVM Subsystem Device
        '-device', 'nvme-subsys,id=nvme-subsys-64,nqn=subsys64',
        # Attach two NVM controllers to it
        '-device', 'nvme,subsys=nvme-subsys-64,serial=deadbeef',
        '-device', 'nvme,subsys=nvme-subsys-64,serial=deadbeef',
        # And create two shared namespaces attached to both controllers
        '-device', 'nvme-ns,drive=nvme0,nsid=16,shared=on',
        '-device', 'nvme-ns,drive=nvme1,nsid=17,shared=on',
    ]
    qemu_drives = [
        "nvme0:1M::cache=unsafe",
        "nvme1:1M::cache=unsafe",
    ]

    mkosi_args += [
        f"--qemu-args={' '.join(quote(v) for v in qemu_args)}",
        f"--qemu-drive={' '.join(qemu_drives)}",
    ]
    yield
