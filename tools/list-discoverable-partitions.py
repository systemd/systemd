#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import re
import sys
import uuid

HEADER = f'''\
| Name | Partition Type UUID | Allowed File Systems | Explanation |
|------|---------------------|----------------------|-------------|
'''

ARCHITECTURES = {
    'ALPHA':       'Alpha',
    'ARC':         'ARC',
    'ARM':         '32-bit ARM',
    'ARM64':       '64-bit ARM/AArch64',
    'IA64':        'Itanium/IA-64',
    'LOONGARCH64': 'LoongArch 64-bit',
    'MIPS_LE':     '32-bit MIPS LittleEndian (mipsel)',
    'MIPS64_LE':   '64-bit MIPS LittleEndian (mips64el)',
    'PARISC':      'HPPA/PARISC',
    'PPC':         '32-bit PowerPC',
    'PPC64':       '64-bit PowerPC BigEndian',
    'PPC64_LE':    '64-bit PowerPC LittleEndian',
    'RISCV32':     'RISC-V 32-bit',
    'RISCV64':     'RISC-V 64-bit',
    'S390':        's390',
    'S390X':       's390x',
    'TILEGX':      'TILE-Gx',
    'X86':         'x86',
    'X86_64':      'amd64/x86_64',
}

TYPES = {
    'ROOT' :            'Root Partition',
    'ROOT_VERITY' :     'Root Verity Partition',
    'ROOT_VERITY_SIG' : 'Root Verity Signature Partition',
    'USR' :             '`/usr/` Partition',
    'USR_VERITY' :      '`/usr/` Verity Partition',
    'USR_VERITY_SIG' :  '`/usr/` Verity Signature Partition',

    'ESP':              'EFI System Partition',
    'SRV':              'Server Data Partition',
    'VAR':              'Variable Data Partition',
    'TMP':              'Temporary Data Partition',
    'SWAP':             'Swap',
    'HOME':             'Home Partition',
    'USER_HOME':        'Per-user Home Partition',
    'LINUX_GENERIC':    'Generic Linux Data Partition',
    'XBOOTLDR':         'Extended Boot Loader Partition',
}

DESCRIPTIONS = {
    'ROOT': (
        'Any native, optionally in LUKS',
        'On systems with matching architecture, the first partition with this type UUID on the disk '
        'containing the active EFI ESP is automatically mounted to the root directory `/`. '
        'If the partition is encrypted with LUKS or has dm-verity integrity data (see below), the '
        'device mapper file will be named `/dev/mapper/root`.'),
    'USR': (
        'Any native, optionally in LUKS',
        'Similar semantics to root partition, but just the `/usr/` partition.'),
    'ROOT_VERITY': (
        'A dm-verity superblock followed by hash data',
        'Contains dm-verity integrity hash data for the matching root partition. If this feature is '
        'used the partition UUID of the root partition should be the first 128 bits of the root hash '
        'of the dm-verity hash data, and the partition UUID of this dm-verity partition should be the '
        'final 128 bits of it, so that the root partition and its Verity partition can be discovered '
        'easily, simply by specifying the root hash.'),
    'USR_VERITY': (
        'A dm-verity superblock followed by hash data',
        'Similar semantics to root Verity partition, but just for the `/usr/` partition.'),
    'ROOT_VERITY_SIG': (
        'A serialized JSON object, see below',
        'Contains a root hash and a PKCS#7 signature for it, permitting signed dm-verity GPT images.'),
    'USR_VERITY_SIG': (
        'A serialized JSON object, see below',
        'Similar semantics to root Verity signature partition, but just for the `/usr/` partition.'),

    'ESP': (
        'VFAT',
        'The ESP used for the current boot is automatically mounted to `/efi/` (or `/boot/` as '
        'fallback), unless a different partition is mounted there (possibly via `/etc/fstab`, or '
        'because the Extended Boot Loader Partition — see below — exists) or the directory is '
        'non-empty on the root disk.  This partition type is defined by the '
        '[UEFI Specification](http://www.uefi.org/specifications).'),
    'XBOOTLDR': (
        'Typically VFAT',
        'The Extended Boot Loader Partition (XBOOTLDR) used for the current boot is automatically '
        'mounted to `/boot/`, unless a different partition is mounted there (possibly via '
        '`/etc/fstab`) or the directory is non-empty on the root disk. This partition type '
        'is defined by the [Boot Loader Specification](https://systemd.io/BOOT_LOADER_SPECIFICATION).'),
    'SWAP': (
        'Swap, optionally in LUKS',
        'All swap partitions on the disk containing the root partition are automatically enabled. '
        'If the partition is encrypted with LUKS, the device mapper file will be named '
        '`/dev/mapper/swap`. This partition type predates the Discoverable Partitions Specification.'),
    'HOME': (
        'Any native, optionally in LUKS',
        'The first partition with this type UUID on the disk containing the root partition is '
        'automatically mounted to `/home/`. If the partition is encrypted with LUKS, the device '
        'mapper file will be named `/dev/mapper/home`.'),
    'SRV': (
        'Any native, optionally in LUKS',
        'The first partition with this type UUID on the disk containing the root partition is '
        'automatically mounted to `/srv/`. If the partition is encrypted with LUKS, the device '
        'mapper file will be named `/dev/mapper/srv`.'),
    'VAR': (
        'Any native, optionally in LUKS',
        'The first partition with this type UUID on the disk containing the root partition is '
        'automatically mounted to `/var/` — under the condition that its partition UUID matches '
        'the first 128 bits of `HMAC-SHA256(machine-id, 0x4d21b016b53445c2a9fb5c16e091fd2d)` '
        '(i.e. the SHA256 HMAC hash of the binary type UUID keyed by the machine ID as read from '
        '[`/etc/machine-id`](https://www.freedesktop.org/software/systemd/man/machine-id.html). '
        'This special requirement is made because `/var/` (unlike the other partition types '
        'listed here) is inherently private to a specific installation and cannot possibly be '
        'shared between multiple OS installations on the same disk, and thus should be bound to '
        'a specific instance of the OS, identified by its machine ID. If the partition is '
        'encrypted with LUKS, the device mapper file will be named `/dev/mapper/var`.'),
    'TMP': (
        'Any native, optionally in LUKS',
        'The first partition with this type UUID on the disk containing the root partition is '
        'automatically mounted to `/var/tmp/`. If the partition is encrypted with LUKS, the '
        'device mapper file will be named `/dev/mapper/tmp`. Note that the intended mount point '
        'is indeed `/var/tmp/`, not `/tmp/`. The latter is typically maintained in memory via '
        '`tmpfs` and does not require a partition on disk. In some cases it might be '
        'desirable to make `/tmp/` persistent too, in which case it is recommended to make it '
        'a symlink or bind mount to `/var/tmp/`, thus not requiring its own partition type UUID.'),
    'USER_HOME': (
        'Any native, optionally in LUKS',
        'A home partition of a user, managed by '
        '[`systemd-homed`](https://www.freedesktop.org/software/systemd/man/systemd-homed.html).'),
    'LINUX_GENERIC': (
        'Any native, optionally in LUKS',
        'No automatic mounting takes place for other Linux data partitions. This partition type '
        'should be used for all partitions that carry Linux file systems. The installer needs '
        'to mount them explicitly via entries in `/etc/fstab`. Optionally, these partitions may '
        'be encrypted with LUKS. This partition type predates the Discoverable Partitions Specification.'),
}

def extract(file):
    for line in file:
        # print(line)
        m = re.match(r'^#define\s+SD_GPT_(.*SD_ID128_MAKE\(.*\))', line)
        if not m:
            continue

        name = line.split()[1]
        if m2 := re.match(r'^(ROOT|USR)_([A-Z0-9]+|X86_64|PPC64_LE|MIPS_LE|MIPS64_LE)(|_VERITY|_VERITY_SIG)\s+SD_ID128_MAKE\((.*)\)', m.group(1)):
            type, arch, suffix, u = m2.groups()
            u = uuid.UUID(u.replace(',', ''))
            assert arch in ARCHITECTURES, f'{arch} not in f{ARCHITECTURES}'
            type = f'{type}{suffix}'
            assert type in TYPES

            yield name, type, arch, u

        elif m2 := re.match(r'(\w+)\s+SD_ID128_MAKE\((.*)\)', m.group(1)):
            type, u = m2.groups()
            u = uuid.UUID(u.replace(',', ''))
            yield name, type, None, u

        else:
            raise Exception(f'Failed to match: {m.group(1)}')

def generate(defines):
    prevtype = None

    print(HEADER, end='')

    uuids = set()

    for name, type, arch, uuid in defines:
        tdesc = TYPES[type]
        adesc = '' if arch is None else f' ({ARCHITECTURES[arch]})'

        # Let's make sure that we didn't select&paste the same value twice
        assert uuid not in uuids
        uuids.add(uuid)

        if type != prevtype:
            prevtype = type
            morea, moreb = DESCRIPTIONS[type]
        else:
            morea = moreb = 'ditto'

        print(f'| _{tdesc}{adesc}_ | `{uuid}` `{name}` | {morea} | {moreb} |')

if __name__ == '__main__':
    known = extract(sys.stdin)
    generate(known)
