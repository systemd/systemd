#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Wait for the mDNS query that systemd-resolved on this host sends for a name, and check that it lists no
# Known-Answers. Prints "ready" to stdout once it listens, so that the caller can then trigger the query.
#
# Usage: TEST-89-RESOLVED-MDNS.listener.py <local IPv4 address> <name, e.g. _foo._udp.local>

import socket
import struct
import sys
import time

MDNS_ADDR = '224.0.0.251'
MDNS_PORT = 5353

FLAG_QR = 0x8000

TIMEOUT = 30.0


def decode_name(packet, offset):
    labels = []
    end = None
    for _ in range(128):
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | packet[offset + 1]
            continue
        offset += 1
        if length == 0:
            break
        labels.append(packet[offset : offset + length].decode())
        offset += length
    else:
        raise ValueError('Name compression loop')

    return '.'.join(labels), (end if end is not None else offset)


def parse_query(packet):
    """Return the header flags, the question names and the Answer section count"""
    _, flags, qdcount, ancount, _, _ = struct.unpack('!6H', packet[:12])
    offset = 12
    names = []
    for _ in range(qdcount):
        name, offset = decode_name(packet, offset)
        names.append(name.lower())
        offset += 4
    return flags, names, ancount


def main():
    local_address, name = sys.argv[1:3]
    name = name.rstrip('.').lower()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # systemd-resolved sets SO_REUSEADDR on its mDNS socket too, so we can share the port with it
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', MDNS_PORT))
    sock.setsockopt(
        socket.IPPROTO_IP,
        socket.IP_ADD_MEMBERSHIP,
        socket.inet_aton(MDNS_ADDR) + socket.inet_aton(local_address),
    )
    print('ready', flush=True)

    deadline = time.monotonic() + TIMEOUT
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            sys.exit(f'FAIL: no query for {name} seen')

        sock.settimeout(remaining)
        try:
            packet, sender = sock.recvfrom(9000)
        except socket.timeout:
            continue

        try:
            flags, names, ancount = parse_query(packet)
        except (ValueError, IndexError, struct.error, UnicodeDecodeError):
            continue
        if flags & FLAG_QR or name not in names:
            continue

        # Nothing but systemd-resolved on this host queries for this name. Its source address can be any of
        # the link's addresses, so don't filter on it.
        print(f'Query for {name} from {sender[0]} lists {ancount} Known-Answer(s)', file=sys.stderr)
        if ancount != 0:
            sys.exit('FAIL: a query that bypasses the cache listed cached records as Known-Answers')
        return


if __name__ == '__main__':
    main()
