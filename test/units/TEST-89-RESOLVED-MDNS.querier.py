#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Minimal mDNS querier used to exercise Known-Answer Suppression (RFC 6762, Sections 7.1 and 7.2) in
# systemd-resolved. Sends hand-crafted queries from port 5353 (so that the responder treats us as a full
# mDNS querier rather than a legacy one) and checks whether the responder answers.
#
# Usage: TEST-89-RESOLVED-MDNS.querier.py <local IPv4 address> <service type, e.g. _foo._udp.local>

import socket
import struct
import sys
import time

MDNS_ADDR = '224.0.0.251'
MDNS_PORT = 5353

TYPE_PTR = 12
CLASS_IN = 1

FLAG_TC = 0x0200
FLAG_QR = 0x8000

# The responder delays replies to TC queries by 400-500ms
TC_DELAY_MIN = 0.4
TC_DELAY_MAX = 0.5
# How long to wait for a reply before deciding that none is coming
REPLY_TIMEOUT = 2.0


def encode_name(name):
    out = b''
    for label in name.rstrip('.').split('.'):
        raw = label.encode()
        out += bytes([len(raw)]) + raw
    return out + b'\0'


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


def parse_records(packet):
    """Return the header flags and the Answer section as (name, type, ttl, rdata) tuples

    PTR rdata is returned decompressed.
    """
    _, flags, qdcount, ancount, _, _ = struct.unpack('!6H', packet[:12])
    offset = 12
    for _ in range(qdcount):
        _, offset = decode_name(packet, offset)
        offset += 4

    records = []
    for _ in range(ancount):
        name, offset = decode_name(packet, offset)
        rtype, _, ttl, rdlength = struct.unpack('!HHIH', packet[offset : offset + 10])
        offset += 10
        rdata = packet[offset : offset + rdlength]
        if rtype == TYPE_PTR:
            target, _ = decode_name(packet, offset)
            rdata = encode_name(target)
        records.append((name, rtype, ttl, rdata))
        offset += rdlength

    return flags, records


def build_packet(flags, questions, known_answers):
    packet = struct.pack('!6H', 0, flags, len(questions), len(known_answers), 0, 0)
    for name in questions:
        packet += encode_name(name) + struct.pack('!HH', TYPE_PTR, CLASS_IN)
    for name, ttl, rdata in known_answers:
        packet += encode_name(name) + struct.pack('!HHIH', TYPE_PTR, CLASS_IN, ttl, len(rdata)) + rdata
    return packet


class Querier:
    def __init__(self, local_address, service_type):
        self.service_type = service_type.rstrip('.').lower()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        # systemd-resolved sets SO_REUSEADDR on its mDNS socket too, so we can share the port with it
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', MDNS_PORT))
        self.sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_ADD_MEMBERSHIP,
            socket.inet_aton(MDNS_ADDR) + socket.inet_aton(local_address),
        )
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_address))
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

    def send(self, packet):
        self.sock.sendto(packet, (MDNS_ADDR, MDNS_PORT))

    def wait_for_reply(self, timeout=REPLY_TIMEOUT, start=None):
        """Wait for a response carrying a PTR for our service type, return (delay, ttl, rdata) or None

        The delay is measured from start, which defaults to now.
        """
        if start is None:
            start = time.monotonic()
        while True:
            remaining = timeout - (time.monotonic() - start)
            if remaining <= 0:
                return None

            self.sock.settimeout(remaining)
            try:
                packet, sender = self.sock.recvfrom(9000)
            except socket.timeout:
                return None

            try:
                flags, records = parse_records(packet)
            except (ValueError, IndexError, struct.error, UnicodeDecodeError):
                continue
            if not flags & FLAG_QR:
                continue  # A query, possibly our own looped back

            for name, rtype, ttl, rdata in records:
                if rtype == TYPE_PTR and name.lower() == self.service_type:
                    delay = time.monotonic() - start
                    print(f'  got reply from {sender[0]} after {delay:.3f}s (TTL {ttl})')
                    return delay, ttl, rdata

    def drain(self):
        """Wait out any replies still in flight, so they don't leak into the next check"""
        while self.wait_for_reply(timeout=1.0):
            pass

    def query(self, known_answers=(), tc=False, follow_ups=()):
        self.drain()
        self.send(build_packet(FLAG_TC if tc else 0, [self.service_type], known_answers))
        for i, kas in enumerate(follow_ups):
            last = i == len(follow_ups) - 1
            self.send(build_packet(0 if last else FLAG_TC, [], kas))
        return self.wait_for_reply()


def check(description, result, expect_reply, min_delay=None, max_delay=None):
    print(f'{description}: expecting {"a reply" if expect_reply else "no reply"}')
    if expect_reply and result is None:
        sys.exit(f'FAIL: {description}: no reply received')
    if not expect_reply and result is not None:
        sys.exit(f'FAIL: {description}: unexpected reply received')
    if min_delay is not None and result[0] < min_delay:
        sys.exit(f'FAIL: {description}: reply after {result[0]:.3f}s, expected at least {min_delay}s')
    if max_delay is not None and result[0] > max_delay:
        sys.exit(f'FAIL: {description}: reply after {result[0]:.3f}s, expected at most {max_delay}s')


def main():
    local_address, service_type = sys.argv[1:3]
    q = Querier(local_address, service_type)
    name = q.service_type

    # Learn the record the responder announces, so we can echo it back as a Known-Answer
    result = None
    for _ in range(10):
        result = q.query()
        if result:
            break
    check('Plain query', result, expect_reply=True)
    _, ttl, rdata = result

    full = [(name, ttl, rdata)]
    half = [(name, ttl // 2, rdata)]
    below_half = [(name, ttl // 2 - 1, rdata)]
    other = [(name, ttl, encode_name('Some Other Instance.' + name))]

    # RFC 6762, Section 7.1: Known-Answers in the query itself
    check('Known-Answer with full TTL', q.query(full), expect_reply=False)
    check('Known-Answer with half TTL', q.query(half), expect_reply=False)
    check('Known-Answer with TTL below half', q.query(below_half), expect_reply=True)
    check('Known-Answer for a different instance', q.query(other), expect_reply=True)

    # RFC 6762, Section 7.2: TC set, Known-Answers in follow-up packets
    check('TC query without follow-up', q.query(tc=True), expect_reply=True, min_delay=TC_DELAY_MIN)
    check('TC query, Known-Answer in follow-up', q.query(tc=True, follow_ups=[full]), expect_reply=False)
    check(
        'TC query, Known-Answer in second follow-up',
        q.query(tc=True, follow_ups=[other, full]),
        expect_reply=False,
    )
    check(
        'TC query, follow-up Known-Answer with TTL below half',
        q.query(tc=True, follow_ups=[below_half]),
        expect_reply=True,
        min_delay=TC_DELAY_MIN,
    )
    check(
        'TC query, follow-up for a different instance',
        q.query(tc=True, follow_ups=[other]),
        expect_reply=True,
        min_delay=TC_DELAY_MIN,
    )

    # A follow-up that carries a question of its own still counts: its Known-Answers apply to the pending
    # reply. Ask for a service type nobody publishes, so the follow-up gets no reply of its own either.
    q.drain()
    q.send(build_packet(FLAG_TC, [name], []))
    q.send(build_packet(0, ['_nobody._udp.local'], full))
    check('TC query, Known-Answer in a follow-up with a question', q.wait_for_reply(), expect_reply=False)

    # A repeated TC query before the reply is due is merged into the pending reply, and keeps its timer:
    # one reply, due 400-500ms after the first query, not after the second
    repeat_after = 0.3
    q.drain()
    start = time.monotonic()
    q.send(build_packet(FLAG_TC, [name], []))
    time.sleep(repeat_after)
    q.send(build_packet(FLAG_TC, [name], []))
    check(
        'Repeated TC query',
        q.wait_for_reply(start=start),
        expect_reply=True,
        min_delay=TC_DELAY_MIN,
        max_delay=TC_DELAY_MAX + repeat_after / 2,
    )
    check('Repeated TC query, no second reply', q.wait_for_reply(), expect_reply=False)

    # A Known-Answer-only packet without a pending reply must be ignored, and not break anything
    q.drain()
    q.send(build_packet(0, [], full))
    check('Stray Known-Answer packet', q.wait_for_reply(), expect_reply=False)
    check('Plain query after stray Known-Answer packet', q.query(), expect_reply=True)

    print('All Known-Answer suppression checks passed')


if __name__ == '__main__':
    main()
