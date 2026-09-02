#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""mDNS test peer for TEST-89-RESOLVED-MDNS.

A minimal mDNS peer (RFC 6762/6763, python stdlib only) that drives
systemd-resolved from the network side. It speaks just enough mDNS for the
conformance scorecard testcase:

  publish  Announce one service instance on one interface: send two unsolicited
           announcements one second apart (RFC 6762 section 8.3), then keep
           answering matching queries (case-insensitively, section 16) until
           terminated. With --subtype, an additional subtype PTR
           (RFC 6763 section 7.1) is announced and answered. On SIGTERM,
           optionally announce goodbyes (TTL=0, section 10.1) before exiting;
           killing the publisher with SIGKILL simulates a publisher vanishing
           without goodbye. Probing (section 8.1) is intentionally omitted: the
           test links are dedicated and conflict-free, and the device under
           test is the host's resolved, not this peer.

  listen   Passively capture mDNS traffic on one interface and print one
           greppable line per question/record seen, e.g.:

             12.345 Q name=RefPub89._refpub._udp.local qtype=255 qu=0 probe=1
             23.456 R qr=1 dst=224.0.0.251 sec=an name=RefPub89._refpub._udp.local type=33 ttl=120 flush=1

           Every packet is preceded by a P line carrying its QR bit, header
           transaction ID, destination address, length, authoritative-answer
           bit and response code -- rcode last, greps anchor on that -- e.g.:

             12.344 P qr=0 id=0 dst=224.0.0.251 len=46 aa=0 rcode=0

           A response that repeats the question, as a legacy reply must, logs
           it as a QE line so that Q lines stay a count of queries.

           A question line carries probe=1 when the query carries records in
           its authority section (i.e. it is an RFC 6762 section 8.1 probe).
           Record lines carry the packet's QR bit (qr=0 lines are records
           inside queries, e.g. known answers) and the packet's destination
           address (multicast group vs unicast). PTR records additionally
           carry their target, e.g.:

             34.567 R qr=1 dst=224.0.0.251 sec=an name=_refpub._udp.local type=12 ttl=0 flush=0 ptr=RefPub89._refpub._udp.local

  query    Send one crafted query on an interface, then capture like listen
           for --duration. Supports the QU bit (unicast-response requested,
           section 5.4), legacy queries from an ephemeral source port
           (section 6.7, --source-port 0), and a known answer in the answer
           section (section 7.1, --known-answer-ptr). With --tc the query sets
           the TC bit, and --followup-known-answer NAME sends a second packet
           100ms later carrying a further known answer for NAME, as a section
           7.2 continuation -- the inline known answer stays in the first
           packet, the way a querier that ran out of room would send them.

Known-answer suppression (section 7.1) is deliberately not implemented in
publish mode: re-answering maintenance queries merely refreshes the cache of
the device under test, which is what the "service stays alive" scenarios want.
"""

import argparse
import selectors
import signal
import socket
import struct
import sys
import time

MDNS_GROUP = '224.0.0.251'
MDNS_PORT = 5353

TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_SRV = 33
TYPE_ANY = 255

CLASS_IN = 1
CACHE_FLUSH = 0x8000  # in record classes; the same bit is QU in question classes
FLAG_QR = 0x8000  # header: this packet is a response
FLAG_AA = 0x0400  # header: authoritative answer
FLAG_TC = 0x0200  # header: truncated, more known answers follow (RFC 6762 section 7.2)
RCODE_MASK = 0x000F  # header: response code

# The socket module only exposes this since python 3.12; the Linux ABI value
# is 8, and this script is Linux-only anyway (SO_BINDTODEVICE, ip_mreqn).
IP_PKTINFO = getattr(socket, 'IP_PKTINFO', 8)

QUERY_ID = 0x8909

START = time.monotonic()


def log(msg):
    print(f'{time.monotonic() - START:.3f} {msg}', flush=True)


def loggable(name):
    """DNS labels carry arbitrary octets, but the log format is one whitespace
    separated line per record, which the test greps. Escape anything that could
    forge a line or a field."""
    return ''.join(c if c.isprintable() and not c.isspace() else f'\\x{ord(c):02x}' for c in name)


def names_equal(a, b):
    """DNS names compare case-insensitively, ASCII only (RFC 6762 section 16)."""
    return a.encode().lower() == b.encode().lower()


def encode_name(labels):
    out = b''
    for label in labels:
        encoded = label.encode() if isinstance(label, str) else label
        assert 0 < len(encoded) < 64
        out += bytes([len(encoded)]) + encoded
    return out + b'\0'


def parse_name(buf, offset):
    """Returns (name as dotted string, offset after the name). Follows compression pointers."""
    labels = []
    next_offset = None
    jumps = 0
    total = 0
    while True:
        if offset >= len(buf):
            raise ValueError('truncated name')
        length = buf[offset]
        if length & 0xC0 == 0xC0:
            if next_offset is None:
                next_offset = offset + 2
            jumps += 1
            if jumps > 128:
                raise ValueError('compression loop')
            target = struct.unpack_from('>H', buf, offset)[0] & 0x3FFF
            # RFC 1035 section 4.1.4 defines a pointer as a *prior* occurrence of a name:
            # backward only, and never into the header. A forward pointer or one into the
            # header assembles a "name" from bytes that are not one, and this parser is the
            # oracle MALFORMED verdicts rest on, so it must flag that rather than fabricate.
            if not 12 <= target < offset:
                raise ValueError('bad compression pointer target')
            offset = target
        elif length == 0:
            if next_offset is None:
                next_offset = offset + 1
            break
        elif length & 0xC0:
            # RFC 1035 section 4.1.4 reserves the 01 and 10 top-bit patterns; treating one
            # as a label length would fabricate a plausible name out of an undecodable
            # packet, and this parser is the oracle MALFORMED verdicts rest on.
            raise ValueError('reserved label length bits')
        else:
            total += length + 1
            if total > 255:
                raise ValueError('name too long')
            labels.append(buf[offset + 1 : offset + 1 + length].decode('utf-8', 'replace'))
            offset += 1 + length
    return '.'.join(labels), next_offset


def parse_packet(buf, record_errors=None):
    """Returns (id, flags, questions, records): questions as (name, qtype, qclass) tuples,
    records as (section, name, rtype, rclass, ttl, ptr-target-or-None) tuples. With
    record_errors set to a list, a malformed record stops the parse there and appends the
    reason, keeping the records parsed so far, instead of raising."""
    if len(buf) < 12:
        raise ValueError('truncated header')
    pid, flags, qdcount, ancount, nscount, arcount = struct.unpack_from('>HHHHHH', buf, 0)
    offset = 12
    questions = []
    for _ in range(qdcount):
        name, offset = parse_name(buf, offset)
        qtype, qclass = struct.unpack_from('>HH', buf, offset)
        offset += 4
        questions.append((name, qtype, qclass))
    records = []
    for section, count in (('an', ancount), ('ns', nscount), ('ar', arcount)):
        for _ in range(count):
            try:
                name, offset = parse_name(buf, offset)
                rtype, rclass, ttl, rdlength = struct.unpack_from('>HHIH', buf, offset)
                offset += 10
                if offset + rdlength > len(buf):
                    raise ValueError('rdlength past buffer end')
                target = None
                if rtype == TYPE_PTR:
                    # The target may legitimately chase compression pointers outside the
                    # RDATA, but it must terminate inside it -- a root label or a complete
                    # pointer -- or the "target" is assembled from the next record's bytes.
                    target, name_end = parse_name(buf, offset)
                    if name_end > offset + rdlength:
                        raise ValueError('PTR target escapes its rdata')
            except (ValueError, struct.error) as e:
                if record_errors is None:
                    raise
                # One clipped or lying record must not hide the ones that parsed: keep
                # them, note the reason, stop here (past a bad rdlength there is no
                # trustworthy record boundary to resume at).
                record_errors.append(f'{section}: {e}')
                return pid, flags, questions, records
            offset += rdlength
            records.append((section, name, rtype, rclass, ttl, target))
    return pid, flags, questions, records


def make_record(name, rtype, ttl, rdata, flush):
    rclass = CLASS_IN | (CACHE_FLUSH if flush else 0)
    return encode_name(name) + struct.pack('>HHIH', rtype, rclass, ttl, len(rdata)) + rdata


def make_response(answers, additionals=()):
    header = struct.pack('>HHHHHH', 0, FLAG_QR | FLAG_AA, 0, len(answers), 0, len(additionals))
    return header + b''.join(answers) + b''.join(additionals)


def open_socket(iface, port=MDNS_PORT, addr='0.0.0.0'):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode() + b'\0')
    sock.bind(('', port))
    # Send from the address we advertise, not whichever one the kernel picks for the interface:
    # two publishers on one link are only distinguishable to a peer if their packets carry
    # different source addresses.
    mreqn = (
        socket.inet_aton(MDNS_GROUP)
        + socket.inet_aton(addr)
        + struct.pack('@i', socket.if_nametoindex(iface))
    )
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreqn)
    # Needs the full 12-byte ip_mreqn: a shorter value is read as a plain
    # in_addr and the ifindex would be ignored.
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    # Loop multicast back to local sockets, too: it lets a listener in the
    # same namespace double as a liveness canary for crafted queries.
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    # Deliver the packet's destination address, to tell unicast from multicast.
    sock.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
    return sock


def recv_with_dst(sock):
    """Returns (data, destination-address-string) for one datagram."""
    data, ancdata, msg_flags, _ = sock.recvmsg(9000, socket.CMSG_SPACE(16))
    if msg_flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        # A clipped datagram (or clipped control data, which loses the destination) must
        # poison the capture the way any other undecodable input does, not shorten it
        # silently: an over-long packet is itself the kind of malformed input to expose.
        log('MALFORMED truncated datagram')
    dst = '?'
    for level, ctype, cdata in ancdata:
        # struct in_pktinfo: int ipi_ifindex; struct in_addr ipi_spec_dst, ipi_addr;
        if level == socket.IPPROTO_IP and ctype == IP_PKTINFO and len(cdata) >= 12:
            dst = socket.inet_ntoa(cdata[8:12])
    return data, dst


def log_packet(buf, dst):
    """Prints the greppable per-question/per-record lines for one packet."""
    record_errors = []
    try:
        pid, flags, questions, records = parse_packet(buf, record_errors=record_errors)
    except (ValueError, struct.error) as e:
        log(f'MALFORMED {e}')
        return
    for e in record_errors:
        log(f'MALFORMED-RECORD {e}')
    qr = 1 if flags & FLAG_QR else 0
    aa = 1 if flags & FLAG_AA else 0
    log(f'P qr={qr} id={pid} dst={dst} len={len(buf)} aa={aa} rcode={flags & RCODE_MASK}')
    if qr:
        # A response repeating the question, as RFC 6762 section 6.7 requires
        # of legacy unicast replies. Kept apart from the Q lines above so that
        # counting queries stays a matter of counting Q lines.
        for name, qtype, _ in questions:
            log(f'QE name={loggable(name)} qtype={qtype}')
    else:
        probe = 1 if any(record[0] == 'ns' for record in records) else 0
        for name, qtype, qclass in questions:
            # The top qclass bit is QU in questions (RFC 6762 section 5.4) -- the one
            # protocol-relevant question field the line was missing.
            log(f'Q name={loggable(name)} qtype={qtype} qu={1 if qclass & CACHE_FLUSH else 0} probe={probe}')
    for section, name, rtype, rclass, ttl, target in records:
        flush = 1 if rclass & CACHE_FLUSH else 0
        suffix = f' ptr={loggable(target)}' if target is not None else ''
        log(
            f'R qr={qr} dst={dst} sec={section} name={loggable(name)} '
            f'type={rtype} ttl={ttl} flush={flush}{suffix}'
        )


class Publisher:
    def __init__(self, args):
        self.sock = open_socket(args.iface, addr=args.addr)
        service_labels = tuple(args.service.split('.'))
        self.ptr_name = service_labels + ('local',)
        self.instance_name = (args.instance,) + service_labels + ('local',)
        self.subtype_name = (args.subtype, '_sub') + service_labels + ('local',) if args.subtype else None
        self.host_name = tuple(args.hostname.split('.'))
        self.port = args.port
        self.ttl = args.ttl
        self.addr = socket.inet_aton(args.addr)
        self.txt_rdata = b'\0'  # an empty TXT is a single zero byte (RFC 6763 section 6.1)
        self.goodbye_on_exit = args.goodbye_on_exit
        self.suppress_known_answers = args.suppress_known_answers
        self.announce_count = args.announce_count

    def records(self, ttl):
        srv_rdata = struct.pack('>HHH', 0, 0, self.port) + encode_name(self.host_name)
        records = {
            'ptr': make_record(self.ptr_name, TYPE_PTR, ttl, encode_name(self.instance_name), flush=False),
            'srv': make_record(self.instance_name, TYPE_SRV, ttl, srv_rdata, flush=True),
            'txt': make_record(self.instance_name, TYPE_TXT, ttl, self.txt_rdata, flush=True),
            'a': make_record(self.host_name, TYPE_A, ttl, self.addr, flush=True),
        }
        if self.subtype_name:
            records['sub'] = make_record(
                self.subtype_name, TYPE_PTR, ttl, encode_name(self.instance_name), flush=False
            )
        return records

    def send_all_records(self, ttl):
        self.sock.sendto(make_response(self.records(ttl).values()), (MDNS_GROUP, MDNS_PORT))

    def suppressed(self, known, owner, target):
        """RFC 6762 section 7.1: a known answer suppresses our reply when it is
        the same record with at least half of its true TTL left. Only PTR rdata
        is compared -- the shared records this publisher owns are all PTRs, and
        those are the ones section 7.1 is about."""
        for section, name, rtype, _, ttl, rdata_target in known:
            if section != 'an' or rtype != TYPE_PTR or rdata_target is None:
                continue
            if (
                names_equal(name, '.'.join(owner))
                and names_equal(rdata_target, '.'.join(target))
                and ttl * 2 >= self.ttl
            ):
                return True
        return False

    def handle_query(self, buf):
        try:
            _, flags, questions, known = parse_packet(buf)
        except (ValueError, struct.error) as e:
            log(f'MALFORMED {e}')
            return
        if flags & FLAG_QR:  # not a query
            return
        answers = []
        additionals = []
        r = self.records(self.ttl)
        for name, qtype, _ in questions:
            if names_equal(name, '.'.join(self.ptr_name)) and qtype in (TYPE_PTR, TYPE_ANY):
                if self.suppress_known_answers and self.suppressed(known, self.ptr_name, self.instance_name):
                    log(f'SUPPRESSED name={loggable(".".join(self.ptr_name))}')
                    continue
                answers.append(r['ptr'])
                additionals += [r['srv'], r['txt'], r['a']]
            elif (
                self.subtype_name
                and names_equal(name, '.'.join(self.subtype_name))
                and qtype in (TYPE_PTR, TYPE_ANY)
            ):
                if self.suppress_known_answers and self.suppressed(
                    known, self.subtype_name, self.instance_name
                ):
                    log(f'SUPPRESSED name={loggable(".".join(self.subtype_name))}')
                    continue
                answers.append(r['sub'])
                additionals += [r['srv'], r['txt'], r['a']]
            elif names_equal(name, '.'.join(self.instance_name)):
                if qtype in (TYPE_SRV, TYPE_ANY):
                    answers.append(r['srv'])
                    additionals.append(r['a'])
                if qtype in (TYPE_TXT, TYPE_ANY):
                    answers.append(r['txt'])
            elif names_equal(name, '.'.join(self.host_name)) and qtype in (TYPE_A, TYPE_ANY):
                answers.append(r['a'])
        if answers:
            self.sock.sendto(make_response(answers, additionals), (MDNS_GROUP, MDNS_PORT))
            log(f'REPLY questions={",".join(loggable(q[0]) for q in questions)}')

    def run(self):
        stopping = []
        signal.signal(signal.SIGTERM, lambda *_: stopping.append(True))

        selector = selectors.DefaultSelector()
        selector.register(self.sock, selectors.EVENT_READ)

        # RFC 6762 section 8.3: multiple announcements, at least one second apart.
        announced = 0
        next_announce = time.monotonic()
        while not stopping:
            try:
                if announced < self.announce_count and time.monotonic() >= next_announce:
                    self.send_all_records(self.ttl)
                    announced += 1
                    next_announce += 1.0
                    log(f'ANNOUNCE n={announced}')
                    if announced == self.announce_count:
                        # Readiness marker: the test waits for this before doing
                        # anything that races the announcements, such as killing
                        # the publisher to provoke a goodbye.
                        log(f'ANNOUNCED total={announced}')
                for key, _ in selector.select(timeout=0.1):
                    self.handle_query(key.fileobj.recv(9000))
            except OSError as e:
                # Scenarios score absences on the assumption the publisher kept
                # answering; a send that dies (ENOBUFS, a link going away) must
                # leave a greppable marker, not just a traceback, before we go.
                log(f'PUBLISHER-ERROR {e}')
                raise

        if self.goodbye_on_exit:
            # Goodbyes are announcements with TTL=0 (RFC 6762 section 10.1),
            # repeated for robustness against loss.
            #
            # A second apart, as a publisher repeating its announcements
            # would space them. This is also the spacing that trips resolved
            # over: it defers deleting a goodbye'd record by a second, arms
            # that timer only when none is already armed, and then decides
            # whether to re-arm by measuring the cache against the timer's
            # *scheduled* time rather than the current one. A goodbye landing
            # in the gap between the two refreshes the record past the horizon
            # the callback checks, so nothing re-arms and the browser is not
            # told until the maintenance ladder comes round, some hundred
            # seconds later. The scenarios watching for a goodbye fail when
            # that happens, which is the point of publishing like a publisher
            # does rather than picking a spacing that steps around it.
            for i in range(2):
                if i > 0:
                    time.sleep(1.0)
                self.send_all_records(0)
                log(f'GOODBYE n={i + 1}')


def capture(sock, duration):
    selector = selectors.DefaultSelector()
    selector.register(sock, selectors.EVENT_READ)
    deadline = time.monotonic() + duration
    while (now := time.monotonic()) < deadline:
        for key, _ in selector.select(timeout=min(0.25, deadline - now)):
            buf, dst = recv_with_dst(key.fileobj)
            log_packet(buf, dst)


def listen(args):
    sock = open_socket(args.iface)
    log(f'LISTENING iface={args.iface}')
    capture(sock, args.duration)


def query(args):
    sock = open_socket(args.iface, port=args.source_port)
    qname_labels = tuple(args.qname.split('.'))
    qclass = CLASS_IN | (CACHE_FLUSH if args.qu else 0)  # top bit is QU in questions
    answers = []
    if args.known_answer_ptr:
        # Suppression only applies at >= half the true TTL (section 7.1), and
        # resolved's MDNS_DEFAULT_TTL is 120, so carry the full 120.
        answers.append(
            make_record(
                qname_labels,
                TYPE_PTR,
                120,
                encode_name(tuple(args.known_answer_ptr.split('.'))),
                flush=False,
            )
        )
    # Multicast queries carry ID 0 (RFC 6762 section 18.1); a legacy query
    # from an ephemeral port uses a real ID that the reply must echo.
    qid = QUERY_ID if args.source_port != MDNS_PORT else 0
    # TC in a query means "more known answers follow in a separate packet"
    # (RFC 6762 section 7.2). A real querier sets it because more did NOT fit, so the
    # inline list stays and the continuation carries a further known answer for a
    # different target: a responder has to merge both halves to decide.
    flags = (FLAG_TC if args.tc else 0) | (args.rcode & RCODE_MASK)
    inline = answers
    # An optional second question the known answer does not cover. A reply to
    # it proves this packet was delivered, so that silence on the first
    # question means the responder chose not to answer rather than never
    # having heard the question.
    witness = b''
    if args.witness_qname:
        # A pointer to offset 12, where the first question's name starts. Only
        # correct when both questions name the same owner, which main() checks.
        witness_name = (
            struct.pack('>H', 0xC00C)
            if args.compress_witness
            else encode_name(tuple(args.witness_qname.split('.')))
        )
        # Same qclass as the first question, so --qu asks for both answers by
        # unicast rather than quietly downgrading the witness to multicast.
        witness = witness_name + struct.pack('>HH', args.witness_qtype, qclass)
    packet = (
        struct.pack('>HHHHHH', qid, flags, 2 if witness else 1, len(inline), 0, 0)
        + encode_name(qname_labels)
        + struct.pack('>HH', args.qtype, qclass)
        + witness
        + b''.join(inline)
    )
    log(f'LISTENING iface={args.iface}')
    for i in range(args.repeat):
        sock.sendto(packet, (MDNS_GROUP, MDNS_PORT))
        if args.followup_known_answer:
            time.sleep(0.1)
            continuation = make_record(
                qname_labels,
                TYPE_PTR,
                120,
                encode_name(tuple(args.followup_known_answer.split('.'))),
                flush=False,
            )
            sock.sendto(
                struct.pack('>HHHHHH', qid, 0, 0, 1, 0, 0) + continuation,
                (MDNS_GROUP, MDNS_PORT),
            )
            log('FOLLOWUP known answers')
        log(
            f'QUERY name={loggable(args.qname)} qtype={args.qtype} qu={1 if args.qu else 0} '
            f'ka={loggable(args.known_answer_ptr) if args.known_answer_ptr else "-"} '
            f'witness={loggable(args.witness_qname) if args.witness_qname else "-"}'
        )
        if i + 1 < args.repeat:
            time.sleep(args.interval)
    capture(sock, args.duration)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest='mode', required=True)

    publish_parser = subparsers.add_parser('publish')
    publish_parser.add_argument('--iface', required=True)
    publish_parser.add_argument('--addr', required=True, help='IPv4 address to advertise (A record)')
    publish_parser.add_argument('--instance', required=True, help='service instance name (single label)')
    publish_parser.add_argument('--service', required=True, help='service type, e.g. _ref._udp')
    publish_parser.add_argument(
        '--subtype', help='service subtype label, e.g. _vendor (RFC 6763 section 7.1)'
    )
    publish_parser.add_argument('--port', type=int, default=42089)
    publish_parser.add_argument('--ttl', type=int, default=120)
    publish_parser.add_argument(
        '--hostname', required=True, help='host name to advertise, e.g. refpeer1.local'
    )
    publish_parser.add_argument(
        '--announce-count',
        type=int,
        default=2,
        help='how many announcements to send (RFC 6762 section 8.3 wants at least two)',
    )
    publish_parser.add_argument(
        '--suppress-known-answers',
        action='store_true',
        help='honour known answers in queries (RFC 6762 section 7.1) instead of always replying',
    )
    publish_parser.add_argument('--goodbye-on-exit', action='store_true')

    listen_parser = subparsers.add_parser('listen')
    listen_parser.add_argument('--iface', required=True)
    listen_parser.add_argument('--duration', type=float, default=15)

    query_parser = subparsers.add_parser('query')
    query_parser.add_argument('--iface', required=True)
    query_parser.add_argument('--qname', required=True)
    query_parser.add_argument('--qtype', type=int, default=TYPE_PTR)
    query_parser.add_argument('--qu', action='store_true', help='request a unicast response (QU bit)')
    query_parser.add_argument('--tc', action='store_true', help='set TC: more known answers follow')
    query_parser.add_argument(
        '--followup-known-answer',
        metavar='PTR_TARGET',
        help='send a follow-up packet carrying a further known answer for this target',
    )
    query_parser.add_argument(
        '--source-port',
        type=int,
        default=MDNS_PORT,
        help='0 = ephemeral, i.e. a legacy query (RFC 6762 section 6.7)',
    )
    query_parser.add_argument(
        '--known-answer-ptr', help='include this PTR target for qname as a known answer (section 7.1)'
    )
    query_parser.add_argument(
        '--witness-qname',
        help='ask this in the same packet as qname; a reply to it proves the packet arrived',
    )
    query_parser.add_argument('--witness-qtype', type=int, default=TYPE_SRV)
    query_parser.add_argument(
        '--compress-witness',
        action='store_true',
        help='name the witness question with a compression pointer to the first question',
    )
    query_parser.add_argument(
        '--rcode',
        type=int,
        default=0,
        help='response code to put in the query header (RFC 6762 section 18.11)',
    )
    query_parser.add_argument('--duration', type=float, default=5)
    query_parser.add_argument('--repeat', type=int, default=1, help='send the query this many times')
    query_parser.add_argument('--interval', type=float, default=1.0, help='seconds between repeated queries')

    args = parser.parse_args()
    if args.mode == 'query' and args.compress_witness and args.witness_qname != args.qname:
        parser.error('--compress-witness needs --witness-qname to equal --qname')
    if args.mode == 'publish':
        Publisher(args).run()
    elif args.mode == 'listen':
        listen(args)
    elif args.mode == 'query':
        query(args)
    else:
        parser.error(f'unknown mode {args.mode}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
