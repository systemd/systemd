#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import ipaddress
import json
import os
import socket
import struct


DHCP6_CLIENT_PORT = 546
DHCP6_SERVER_PORT = 547
DHCP6_INFORMATION_REQUEST = 11
DHCP6_REPLY = 7
DHCP6_ADDR_REG_INFORM = 36
DHCP6_ADDR_REG_REPLY = 37
OPTION_CLIENTID = 1
OPTION_SERVERID = 2
OPTION_ORO = 6
OPTION_IAADDR = 5
OPTION_ADDR_REG_ENABLE = 148
ALL_DHCP_RELAY_AGENTS_AND_SERVERS = 'ff02::1:2'


def dhcp6_option(code, data=b''):
    return struct.pack('!HH', code, len(data)) + data


def parse_options(data):
    options = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise ValueError('truncated DHCPv6 option header')
        code, length = struct.unpack_from('!HH', data, offset)
        offset += 4
        if length > len(data) - offset:
            raise ValueError('truncated DHCPv6 option')
        options.append((code, data[offset : offset + length]))
        offset += length
    return options


def write_event(path, event):
    line = (json.dumps(event, sort_keys=True) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC, 0o644)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('interface')
    parser.add_argument('log')
    parser.add_argument('--unsupported', action='store_true')
    args = parser.parse_args()

    ifindex = socket.if_nametoindex(args.interface)
    server_id = b'\x00\x03\x00\x01\x02\x00\x00\x00' + struct.pack('!H', ifindex)

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.interface.encode() + b'\0')
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
    group = socket.inet_pton(socket.AF_INET6, ALL_DHCP_RELAY_AGENTS_AND_SERVERS)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, group + struct.pack('=I', ifindex))
    sock.bind(('::', DHCP6_SERVER_PORT))

    write_event(args.log, {'event': 'ready', 'interface': args.interface})

    def send_reply(reply, address):
        packet_info = socket.inet_pton(socket.AF_INET6, '::') + struct.pack('=I', ifindex)
        sock.sendmsg(
            [reply],
            [(socket.IPPROTO_IPV6, socket.IPV6_PKTINFO, packet_info)],
            0,
            (address, DHCP6_CLIENT_PORT, 0, ifindex),
        )

    while True:
        packet, ancillary, flags, sender = sock.recvmsg(65535, 256)
        if flags & socket.MSG_TRUNC or len(packet) < 4:
            continue

        destination = None
        received_ifindex = 0
        for level, kind, data in ancillary:
            if level == socket.IPPROTO_IPV6 and kind == socket.IPV6_PKTINFO:
                packed_address, received_ifindex = struct.unpack('=16sI', data)
                destination = socket.inet_ntop(socket.AF_INET6, packed_address)

        try:
            options = parse_options(packet[4:])
        except ValueError:
            continue

        transaction_id = packet[1:4]
        option_map = {}
        for code, data in options:
            option_map.setdefault(code, []).append(data)

        if packet[0] == DHCP6_INFORMATION_REQUEST:
            client_ids = option_map.get(OPTION_CLIENTID, [])
            requested = {
                code
                for value in option_map.get(OPTION_ORO, [])
                for (code,) in struct.iter_unpack('!H', value)
            }
            write_event(
                args.log,
                {
                    'event': 'information-request',
                    'interface': args.interface,
                    'address_registration_requested': OPTION_ADDR_REG_ENABLE in requested,
                },
            )
            reply = bytes([DHCP6_REPLY]) + transaction_id
            if client_ids:
                reply += dhcp6_option(OPTION_CLIENTID, client_ids[0])
            reply += dhcp6_option(OPTION_SERVERID, server_id)
            if not args.unsupported:
                reply += dhcp6_option(OPTION_ADDR_REG_ENABLE)
            send_reply(reply, sender[0])
            continue

        if packet[0] != DHCP6_ADDR_REG_INFORM:
            continue

        ia_addresses = option_map.get(OPTION_IAADDR, [])
        client_ids = option_map.get(OPTION_CLIENTID, [])
        if (
            len(ia_addresses) != 1
            or len(ia_addresses[0]) != 24
            or len(client_ids) != 1
            or OPTION_SERVERID in option_map
            or OPTION_ORO in option_map
        ):
            continue

        address_bytes, preferred, valid = struct.unpack('!16sII', ia_addresses[0])
        address = str(ipaddress.IPv6Address(address_bytes))
        write_event(
            args.log,
            {
                'event': 'registration',
                'interface': args.interface,
                'address': address,
                'source': sender[0],
                'source_port': sender[1],
                'destination': destination,
                'ifindex': received_ifindex,
                'transaction_id': transaction_id.hex(),
                'preferred_lifetime': preferred,
                'valid_lifetime': valid,
            },
        )

        reply = bytes([DHCP6_ADDR_REG_REPLY]) + transaction_id
        reply += dhcp6_option(OPTION_IAADDR, ia_addresses[0])
        send_reply(reply, sender[0])


if __name__ == '__main__':
    main()
