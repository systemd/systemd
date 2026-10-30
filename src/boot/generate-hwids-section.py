#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import collections
import json
import struct
import sys
import uuid
from pathlib import Path

BYTES_PER_LINE = 16

# Keep in sync with Device from src/boot/chid.h
# uint32_t descriptor, EFI_GUID chid, uint32_t name_offset, uint32_t compatible_offset
DEVICE_STRUCT_SIZE = 4 + 16 + 4 + 4
NULL_DEVICE = b'\0' * DEVICE_STRUCT_SIZE
DEVICE_TYPE_DEVICETREE = 1
DEVICE_TYPE_UEFI_FW = 2


def device_make_descriptor(device_type: int, size: int) -> int:
    return (size) | (device_type << 28)


def pack_device(
    offsets: dict[str, int], devtype: int, name: str, compatible_or_fwid: str, chids: set[uuid.UUID]
) -> bytes:
    data = b''
    descriptor = device_make_descriptor(devtype, DEVICE_STRUCT_SIZE)
    for chid in sorted(chids):
        data += struct.pack('<I', descriptor)
        data += chid.bytes_le
        data += struct.pack('<II', offsets[name], offsets[compatible_or_fwid])

    assert len(data) == DEVICE_STRUCT_SIZE * len(chids)
    return data


def pack_strings(strings: set[str], base: int) -> tuple[bytes, dict[str, int]]:
    blob = b''
    offsets = {}

    for string in sorted(strings):
        offsets[string] = base + len(blob)
        blob += string.encode('utf-8') + b'\00'

    return (blob, offsets)


def parse_hwid_dir(path: Path) -> bytes:
    hwid_files = sorted(path.rglob('*.json'))
    devstr_to_type: dict[str, int] = {
        'devicetree': DEVICE_TYPE_DEVICETREE,
        'uefi-fw': DEVICE_TYPE_UEFI_FW,
    }

    # all attributes in the mandatory attributes list must be present
    mandatory_attribute = ['type', 'name', 'hwids']

    # at least one of the following attributes must be present
    one_of = ['compatible', 'fwid']

    one_of_key_to_devtype: dict[str, int] = {
        'compatible': DEVICE_TYPE_DEVICETREE,
        'fwid': DEVICE_TYPE_UEFI_FW,
    }

    strings: set[str] = set()
    devices: collections.defaultdict[tuple[int, str, str], set[uuid.UUID]] = collections.defaultdict(set)

    for hwid_file in hwid_files:
        data = json.loads(hwid_file.read_text(encoding='UTF-8'))

        for k in mandatory_attribute:
            if k not in data:
                raise ValueError(f'hwid description file "{hwid_file}" does not contain "{k}"')

        if not any(key in data for key in one_of):
            required_keys = ','.join(one_of)
            raise ValueError(f'hwid description file "{hwid_file}" must contain one of {required_keys}')

        # (devtype, name, compatible/fwid) pair uniquely identifies the device
        devtype = devstr_to_type[data['type']]

        for k in one_of:
            if k in data:
                if one_of_key_to_devtype[k] != devtype:
                    raise ValueError(
                        f'wrong attribute "{k}" for hwid description file "{hwid_file}", '
                        'device type: "%s"' % devtype
                    )
                strings |= {data['name'], data[k]}
                devices[(devtype, data['name'], data[k])] |= {uuid.UUID(u) for u in data['hwids']}

    total_device_structs = 1
    for dev, uuids in devices.items():
        total_device_structs += len(uuids)

    strings_blob, offsets = pack_strings(strings, total_device_structs * DEVICE_STRUCT_SIZE)

    devices_blob = b''
    for (devtype, name, compatible_or_fwid), uuids in devices.items():
        devices_blob += pack_device(offsets, devtype, name, compatible_or_fwid, uuids)

    devices_blob += NULL_DEVICE

    return devices_blob + strings_blob


hwids = parse_hwid_dir(Path(sys.argv[1]))

print(
    '''/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <stddef.h>
#include <stdint.h>

// NOLINTNEXTLINE(misc-use-internal-linkage)
const uint8_t hwids_section_data[] = {
    ''',
    end='',
)

for i, b in enumerate(hwids):
    print(f'0x{b:02X}, ', end='')
    if i % BYTES_PER_LINE == BYTES_PER_LINE - 1:
        print('\n    ', end='')
    elif i == len(hwids) - 1:
        print('')

print(
    '''};

// NOLINTNEXTLINE(misc-use-internal-linkage)
const size_t hwids_section_len =''',
    f'{len(hwids)};',
)
