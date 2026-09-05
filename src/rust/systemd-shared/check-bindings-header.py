#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Check that bindings.h includes every header of the given directories.

Usage: check-bindings-header.py BINDINGS_H DIR...

Headers listed in EXCLUDED are expected to be missing from bindings.h.
"""

import re
import sys
from pathlib import Path

# Public headers whose functions are implemented by libsystemd-network rather than libsystemd-shared, and the
# internal header the public ones share.
EXCLUDED = {
    '_sd-common.h',
    'sd-dhcp-client.h',
    'sd-dhcp-client-id.h',
    'sd-dhcp-duid.h',
    'sd-dhcp-lease.h',
    'sd-dhcp-protocol.h',
    'sd-dhcp-relay.h',
    'sd-dhcp-server.h',
    'sd-dhcp-server-lease.h',
    'sd-dhcp6-client.h',
    'sd-dhcp6-lease.h',
    'sd-dhcp6-option.h',
    'sd-dhcp6-protocol.h',
    'sd-dns-resolver.h',
    'sd-ipv4acd.h',
    'sd-ipv4ll.h',
    'sd-lldp.h',
    'sd-lldp-rx.h',
    'sd-lldp-tx.h',
    'sd-ndisc.h',
    'sd-ndisc-neighbor.h',
    'sd-ndisc-protocol.h',
    'sd-ndisc-redirect.h',
    'sd-ndisc-router.h',
    'sd-ndisc-router-solicit.h',
    'sd-radv.h',
}


def main() -> int:
    bindings_h = Path(sys.argv[1])
    dirs = [Path(d) for d in sys.argv[2:]]

    included = set(re.findall(r'^#include "([^"]+)"$', bindings_h.read_text(), re.MULTILINE))
    available = {p.name for d in dirs for p in d.glob('*.h')}

    missing = sorted(available - EXCLUDED - included)
    stale = sorted(included - available - {p.name for p in Path(bindings_h.parent).glob('*.h')})
    wrongly_excluded = sorted(EXCLUDED & included)

    rc = 0
    for h in missing:
        print(f'{bindings_h}: {h} is not included, add it (or list it in {Path(__file__).name} if it cannot be)')
        rc = 1
    for h in stale:
        print(f'{bindings_h}: {h} does not exist anymore, drop it')
        rc = 1
    for h in wrongly_excluded:
        print(f'{Path(__file__).name}: {h} is listed as excluded but bindings.h includes it')
        rc = 1

    return rc


if __name__ == '__main__':
    sys.exit(main())
