/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>
#include <netinet/tcp.h>

#include "capability-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "missing_network.h"
#include "missing_socket.h"
#include "resolved-dns-stub.h"
#include "socket-netlink.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-table.h"

/* The MTU of the loopback device is 64K on Linux, advertise that as maximum datagram size, but subtract the Ethernet,
 * IP and UDP header sizes */
#define ADVERTISE_DATAGRAM_SIZE_MAX (65536U-14U-20U-8U)

/* On the extra stubs, use a more conservative choice */
#define ADVERTISE_EXTRA_DATAGRAM_SIZE_MAX DNS_PACKET_UNICAST_SIZE_LARGE_MAX

static int manager_dns_stub_fd_extra(Manager *m, DnsStubListenerExtra *l, int type);
static int manager_dns_stub_fd(Manager *m, int family, const union in_addr_union *listen_address, int type);

static void dns_stub_listener_extra_hash_func(const DnsStubListenerExtra *a, struct siphash *state) {
        assert(a);

        siphash24_compress_typesafe(a->mode, state);
        siphash24_compress_typesafe(a->family, state);
        in_addr_hash_func(&a->address, a->family, state);
        siphash24_compress_typesafe(a->port, state);
}

static int dns_stub_listener_extra_compare_func(const DnsStubListenerExtra *a, const DnsStubListenerExtra *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->mode, b->mode);
        if (r != 0)
                return r;

        r = CMP(a->family, b->family);
        if (r != 0)
                return r;

        r = memcmp(&a->address, &b->address, FAMILY_ADDRESS_SIZE(a->family));
        if (r != 0)
                return r;

        return CMP(a->port, b->port);
}

DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                dns_stub_listener_extra_hash_ops,
                DnsStubListenerExtra,
                dns_stub_listener_extra_hash_func,
                dns_stub_listener_extra_compare_func,
                dns_stub_listener_extra_free);

int dns_stub_listener_extra_new(
                Manager *m,
                DnsStubListenerExtra **ret) {

        DnsStubListenerExtra *l;

        l = new(DnsStubListenerExtra, 1);
        if (!l)
                return -ENOMEM;

        *l = (DnsStubListenerExtra) {
                .manager = m,
        };

        *ret = TAKE_PTR(l);
        return 0;
}

DnsStubListenerExtra *dns_stub_listener_extra_free(DnsStubListenerExtra *p) {
        if (!p)
                return NULL;

        p->udp_event_source = sd_event_source_disable_unref(p->udp_event_source);
        p->tcp_event_source = sd_event_source_disable_unref(p->tcp_event_source);

        hashmap_free(p->queries_by_packet);

        return mfree(p);
}

static void stub_packet_hash_func(const DnsPacket *p, struct siphash *state) {
        assert(p);

        siphash24_compress_typesafe(p->protocol, state);
        siphash24_compress_typesafe(p->family, state);
        siphash24_compress_typesafe(p->sender, state);
        siphash24_compress_typesafe(p->ipproto, state);
        siphash24_compress_typesafe(p->sender_port, state);
        siphash24_compress(DNS_PACKET_HEADER(p), sizeof(DnsPacketHeader), state);

        /* We don't bother hashing the full packet here, just the header */
}

static int stub_packet_compare_func(const DnsPacket *x, const DnsPacket *y) {
        int r;

        r = CMP(x->protocol, y->protocol);
        if (r != 0)
                return r;

        r = CMP(x->family, y->family);
        if (r != 0)
                return r;

        r = memcmp(&x->sender, &y->sender, sizeof(x->sender));
        if (r != 0)
                return r;

        r = CMP(x->ipproto, y->ipproto);
        if (r != 0)
                return r;

        r = CMP(x->sender_port, y->sender_port);
        if (r != 0)
                return r;

        return memcmp(DNS_PACKET_HEADER(x), DNS_PACKET_HEADER(y), sizeof(DnsPacketHeader));
}

DEFINE_HASH_OPS(stub_packet_hash_ops, DnsPacket, stub_packet_hash_func, stub_packet_compare_func);

static int reply_add_with_rrsig(
                DnsAnswer **reply,
                DnsResourceRecord *rr,
                int ifindex,
                DnsAnswerFlags flags,
                DnsResourceRecord *rrsig,
                bool with_rrsig) {
        int r;

        assert(reply);
        assert(rr);

        r = dns_answer_add_extend(reply, rr, ifindex, flags, rrsig);
        if (r < 0)
                return r;

        if (with_rrsig && rrsig) {
                r = dns_answer_add_extend(reply, rrsig, ifindex, flags, NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dns_stub_collect_answer_by_question(
                DnsAnswer **reply,
                DnsAnswer *answer,
                DnsQuestion *question,
                bool with_rrsig) { /* Add RRSIG RR matching each RR */

        DnsAnswerItem *item;
        int r;

        assert(reply);

        /* Copies all RRs from 'answer' into 'reply', if they match 'question'. */

        DNS_ANSWER_FOREACH_ITEM(item, answer) {

                /* We have a question, let's see if this RR matches it */
                r = dns_question_matches_rr(question, item->rr, NULL);
                if (r < 0)
                        return r;
                if (!r) {
                        /* Maybe there's a CNAME/DNAME in here? If so, that's an answer too */
                        r = dns_question_matches_cname_or_dname(question, item->rr, NULL);
                        if (r < 0)
                                return r;
                        if (!r)
                                continue;
                }

                /* Mask the section info, we want the primary answers to always go without section
                 * info, so that it is added to the answer section when we synthesize a reply. */

                r = reply_add_with_rrsig(
                                reply,
                                item->rr,
                                item->ifindex,
                                item->flags & ~DNS_ANSWER_MASK_SECTIONS,
                                item->rrsig,
                                with_rrsig);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dns_stub_collect_answer_by_section(
                DnsAnswer **reply,
                DnsAnswer *answer,
                DnsAnswerFlags section,
                DnsAnswer *exclude1,
                DnsAnswer *exclude2,
                bool with_dnssec) { /* Include DNSSEC RRs. RRSIG, NSEC, … */

        DnsAnswerItem *item;
        int r;

        assert(reply);

        /* Copies all RRs from 'answer' into 'reply', if they originate from the specified section. Also,
         * avoid any RRs listed in 'exclude'. */

        DNS_ANSWER_FOREACH_ITEM(item, answer) {

                if (dns_answer_contains(exclude1, item->rr) ||
                    dns_answer_contains(exclude2, item->rr))
                        continue;

                if (!with_dnssec &&
                    dns_type_is_dnssec(item->rr->key->type))
                        continue;

                if (((item->flags ^ section) & DNS_ANSWER_MASK_SECTIONS) != 0)
                        continue;

                r = reply_add_with_rrsig(
                                reply,
                                item->rr,
                                item->ifindex,
                                item->flags,
                                item->rrsig,
                                with_dnssec);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dns_stub_assign_sections(
                DnsQuery *q,
                DnsQuestion *question,
                bool edns0_do) {

        int r;

        assert(q);
        assert(question);

        /* Let's assign the 'answer' RRs we collected to their respective sections in the reply datagram. We
         * try to reproduce a section assignment similar to what the upstream DNS server responded to us. We
         * use the DNS_ANSWER_SECTION_xyz flags to match things up, which is where the original upstream's
         * packet section assignment is stored in the DnsAnswer object. Not all RRs in the 'answer' objects
         * come with section information though (for example, because they were synthesized locally, and not
         * from a DNS packet). To deal with that we extend the assignment logic a bit: anything from the
         * 'answer' object that directly matches the original question is always put in the ANSWER section,
         * regardless if it carries section info, or what that section info says. Then, anything from the
         * 'answer' objects that is from the ANSWER or AUTHORITY sections, and wasn't already added to the
         * ANSWER section is placed in the AUTHORITY section. Everything else from either object is added to
         * the ADDITIONAL section. */

        /* Include all RRs that directly answer the question in the answer section */
        r = dns_stub_collect_answer_by_question(
                        &q->reply_answer,
                        q->answer,
                        question,
                        edns0_do);
        if (r < 0)
                return r;

        /* Include all RRs that originate from the authority sections, and aren't already listed in the
         * answer section, in the authority section */
        r = dns_stub_collect_answer_by_section(
                        &q->reply_authoritative,
                        q->answer,
                        DNS_ANSWER_SECTION_AUTHORITY,
                        q->reply_answer, NULL,
                        edns0_do);
        if (r < 0)
                return r;

        /* Include all RRs that originate from the answer or additional sections in the additional section
         * (except if already listed in the other two sections). Also add all RRs with no section marking. */
        r = dns_stub_collect_answer_by_section(
                        &q->reply_additional,
                        q->answer,
                        DNS_ANSWER_SECTION_ANSWER,
                        q->reply_answer, q->reply_authoritative,
                        edns0_do);
        if (r < 0)
                return r;
        r = dns_stub_collect_answer_by_section(
                        &q->reply_additional,
                        q->answer,
                        DNS_ANSWER_SECTION_ADDITIONAL,
                        q->reply_answer, q->reply_authoritative,
                        edns0_do);
        if (r < 0)
                return r;
        r = dns_stub_collect_answer_by_section(
                        &q->reply_additional,
                        q->answer,
                        0,
                        q->reply_answer, q->reply_authoritative,
                        edns0_do);
        if (r < 0)
                return r;

        return 0;
}

static int dns_stub_make_reply_packet(
                DnsPacket **ret,
                size_t max_size,
                DnsQuestion *q,
                bool *ret_truncated) {

        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        bool tc = false;
        int r;

        assert(ret);

        r = dns_packet_new(&p, DNS_PROTOCOL_DNS, 0, max_size);
        if (r < 0)
                return r;

        r = dns_packet_append_question(p, q);
        if (r == -EMSGSIZE)
                tc = true;
        else if (r < 0)
                return r;

        if (ret_truncated)
                *ret_truncated = tc;
        else if (tc)
                return -EMSGSIZE;

        DNS_PACKET_HEADER(p)->qdcount = htobe16(dns_question_size(q));

        *ret = TAKE_PTR(p);
        return 0;
}

static int dns_stub_add_reply_packet_body(
                DnsPacket *p,
                DnsAnswer *answer,
                DnsAnswer *authoritative,
                DnsAnswer *additional,
                bool edns0_do, /* Client expects DNSSEC RRs? */
                bool *truncated) {

        unsigned n_answer = 0, n_authoritative = 0, n_additional = 0;
        bool tc = false;
        int r;

        assert(p);

        /* Add the three sections to the packet. If the answer section doesn't fit we'll signal that as
         * truncation. If the authoritative section doesn't fit and we are in DNSSEC mode, also signal
         * truncation. In all other cases where things don't fit don't signal truncation, as for those cases
         * the dropped RRs should not be essential. */

        r = dns_packet_append_answer(p, answer, &n_answer);
        if (r == -EMSGSIZE)
                tc = true;
        else if (r < 0)
                return r;
        else {
                r = dns_packet_append_answer(p, authoritative, &n_authoritative);
                if (r == -EMSGSIZE) {
                        if (edns0_do)
                                tc = true;
                } else if (r < 0)
                        return r;
                else {
                        r = dns_packet_append_answer(p, additional, &n_additional);
                        if (r < 0 && r != -EMSGSIZE)
                                return r;
                }
        }

        if (tc) {
                if (!truncated)
                        return -EMSGSIZE;

                *truncated = true;
        }

        DNS_PACKET_HEADER(p)->ancount = htobe16(n_answer);
        DNS_PACKET_HEADER(p)->nscount = htobe16(n_authoritative);
        DNS_PACKET_HEADER(p)->arcount = htobe16(n_additional);
        return 0;
}

static const char *nsid_string(void) {
        static char buffer[SD_ID128_STRING_MAX + STRLEN(".resolved.systemd.io")] = "";
        sd_id128_t id;
        int r;

        /* Let's generate a string that we can use as RFC5001 NSID identifier. The string shall identify us
         * as systemd-resolved, and return a different string for each resolved instance without leaking host
         * identity. Hence let's use a fixed suffix that identifies resolved, and a prefix generated from the
         * machine ID but from which the machine ID cannot be determined.
         *
         * Clients can use this to determine whether an answer is originating locally or is proxied from
         * upstream. */

        if (!isempty(buffer))
                return buffer;

        r = sd_id128_get_machine_app_specific(
                        SD_ID128_MAKE(ed,d3,12,5d,16,b9,41,f9,a1,49,5f,ab,15,62,ab,27),
                        &id);
        if (r < 0) {
                log_debug_errno(r, "Failed to determine machine ID, ignoring: %m");
                return NULL;
        }

        xsprintf(buffer, SD_ID128_FORMAT_STR ".resolved.systemd.io", SD_ID128_FORMAT_VAL(id));
        return buffer;
}

static int dns_stub_finish_reply_packet(
                DnsPacket *p,
                uint16_t id,
                int rcode,
                bool tc,        /* set the Truncated bit? */
                bool aa,        /* set the Authoritative Answer bit? */
                bool rd,        /* set the Recursion Desired bit? */
                bool add_opt,   /* add an OPT RR to this packet? */
                bool edns0_do,  /* set the EDNS0 DNSSEC OK bit? */
                bool ad,        /* set the DNSSEC authenticated data bit? */
                bool cd,        /* set the DNSSEC checking disabled bit? */
                uint16_t max_udp_size, /* The maximum UDP datagram size to advertise to clients */
                bool nsid) {    /* whether to add NSID */

        int r;

        assert(p);

        if (add_opt) {
                r = dns_packet_append_opt(p, max_udp_size, edns0_do, /* include_rfc6975 = */ false, nsid ? nsid_string() : NULL, rcode, NULL);
                if (r == -EMSGSIZE) /* Hit the size limit? then indicate truncation */
                        tc = true;
                else if (r < 0)
                        return r;
        } else {
                /* If the client can't to EDNS0, don't do DO either */
                edns0_do = false;

                /* If we don't do EDNS, clamp the rcode to 4 bit */
                if (rcode > 0xF)
                        rcode = DNS_RCODE_SERVFAIL;
        }

        /* Note that we allow the AD bit to be set even if client didn't signal DO, as per RFC 6840, section
         * 5.7 */

        DNS_PACKET_HEADER(p)->id = id;

        DNS_PACKET_HEADER(p)->flags = htobe16(DNS_PACKET_MAKE_FLAGS(
                                                              1  /* qr */,
                                                              0  /* opcode */,
                                                              aa /* aa */,
                                                              tc /* tc */,
                                                              rd /* rd */,
                                                              1  /* ra */,
                                                              ad /* ad */,
                                                              cd /* cd */,
                                                              rcode));

        return 0;
}

static bool address_is_proxy(int family, const union in_addr_union *a) {
        assert(a);

        /* Returns true if the specified address is the DNS "proxy" stub, i.e. where we unconditionally enable bypass mode */

        if (family != AF_INET)
                return false;

        return be32toh(a->in.s_addr) == INADDR_DNS_PROXY_STUB;
}

static int find_socket_fd(
                Manager *m,
                DnsStubListenerExtra *l,
                int family,
                const union in_addr_union *listen_address,
                int type) {

        assert(m);

        /* Finds the right socket to use for sending. If we know the extra listener, otherwise go via the
         * address to send from */
        if (l)
                return manager_dns_stub_fd_extra(m, l, type);

        return manager_dns_stub_fd(m, family, listen_address, type);
}

static int dns_stub_send(
                Manager *m,
                DnsStubListenerExtra *l,
                DnsStream *s,
                DnsPacket *p,
                DnsPacket *reply) {

        int r;

        assert(m);
        assert(p);
        assert(reply);

        if (s)
                r = dns_stream_write_packet(s, reply);
        else {
                int fd, ifindex;

                fd = find_socket_fd(m, l, p->family, &p->destination, SOCK_DGRAM);
                if (fd < 0)
                        return fd;

                if (address_is_proxy(p->family, &p->destination))
                        /* Force loopback iface if this is the loopback proxy stub
                         * and ifindex was normalized to 0 by manager_recv(). */
                        ifindex = p->ifindex ?: LOOPBACK_IFINDEX;
                else
                        /* Force loopback iface if this is the main listener stub. */
                        ifindex = l ? p->ifindex : LOOPBACK_IFINDEX;

                /* Note that it is essential here that we explicitly choose the source IP address for this
                 * packet. This is because otherwise the kernel will choose it automatically based on the
                 * routing table and will thus pick 127.0.0.1 rather than 127.0.0.53/54. */
                r = manager_send(m,
                                 fd,
                                 ifindex,
                                 p->family, &p->sender, p->sender_port, &p->destination,
                                 reply);
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to send reply packet: %m");

        return 0;
}

static int dns_stub_reply_with_edns0_do(DnsQuery *q) {
         assert(q);

        /* Reply with DNSSEC DO set? Only if client supports it; and we did any DNSSEC verification
         * ourselves, or consider the data fully authenticated because we generated it locally, or the client
         * set cd */

         return DNS_PACKET_DO(q->request_packet) &&
                 (q->answer_dnssec_result >= 0 ||        /* we did proper DNSSEC validation … */
                  dns_query_fully_authenticated(q) ||    /* … or we considered it authentic otherwise … */
                  DNS_PACKET_CD(q->request_packet));     /* … or client set CD */
}

static void dns_stub_suppress_duplicate_section_rrs(DnsQuery *q) {
        /* If we follow a CNAME/DNAME chain we might end up populating our sections with redundant RRs
         * because we built up the sections from multiple reply packets (one from each CNAME/DNAME chain
         * element). E.g. it could be that an RR that was included in the first reply's additional section
         * ends up being relevant as main answer in a subsequent reply in the chain. Let's clean this up, and
         * remove everything in the "higher priority" sections from the "lower priority" sections.
         *
         * Note that this removal matches by RR keys instead of the full RRs. This is because RRsets should
         * always end up in one section fully or not at all, but never be split among sections.
         *
         * Specifically: we remove ANSWER section RRs from the AUTHORITATIVE and ADDITIONAL sections, as well
         * as AUTHORITATIVE section RRs from the ADDITIONAL section. */

        dns_answer_remove_by_answer_keys(&q->reply_authoritative, q->reply_answer);
        dns_answer_remove_by_answer_keys(&q->reply_additional, q->reply_answer);
        dns_answer_remove_by_answer_keys(&q->reply_additional, q->reply_authoritative);
}

static int dns_stub_send_reply(
                DnsQuery *q,
                int rcode) {

        _cleanup_(dns_packet_unrefp) DnsPacket *reply = NULL;
        bool truncated, edns0_do;
        int r;

        assert(q);

        edns0_do = dns_stub_reply_with_edns0_do(q); /* let's check if we shall reply with EDNS0 DO? */

        r = dns_stub_make_reply_packet(
                        &reply,
                        DNS_PACKET_PAYLOAD_SIZE_MAX(q->request_packet),
                        q->request_packet->question,
                        &truncated);
        if (r < 0)
                return log_debug_errno(r, "Failed to build reply packet: %m");

        dns_stub_suppress_duplicate_section_rrs(q);

        r = dns_stub_add_reply_packet_body(
                        reply,
                        q->reply_answer,
                        q->reply_authoritative,
                        q->reply_additional,
                        edns0_do,
                        &truncated);
        if (r < 0)
                return log_debug_errno(r, "Failed to append reply packet body: %m");

        r = dns_stub_finish_reply_packet(
                        reply,
                        DNS_PACKET_ID(q->request_packet),
                        rcode,
                        truncated,
                        dns_query_fully_authoritative(q),
                        DNS_PACKET_RD(q->request_packet),
                        !!q->request_packet->opt,
                        edns0_do,
                        (DNS_PACKET_AD(q->request_packet) || DNS_PACKET_DO(q->request_packet)) && dns_query_fully_authenticated(q),
                        FLAGS_SET(q->flags, SD_RESOLVED_NO_VALIDATE),
                        q->stub_listener_extra ? ADVERTISE_EXTRA_DATAGRAM_SIZE_MAX : ADVERTISE_DATAGRAM_SIZE_MAX,
                        dns_packet_has_nsid_request(q->request_packet) > 0 && !q->stub_listener_extra);
        if (r < 0)
                return log_debug_errno(r, "Failed to build failure packet: %m");

        return dns_stub_send(q->manager, q->stub_listener_extra, q->request_stream, q->request_packet, reply);
}

static int dns_stub_send_failure(
                Manager *m,
                DnsStubListenerExtra *l,
                DnsStream *s,
                DnsPacket *p,
                int rcode,
                bool authenticated) {

        _cleanup_(dns_packet_unrefp) DnsPacket *reply = NULL;
        bool truncated;
        int r;

        assert(m);
        assert(p);

        r = dns_stub_make_reply_packet(
                        &reply,
                        DNS_PACKET_PAYLOAD_SIZE_MAX(p),
                        p->question,
                        &truncated);
        if (r < 0)
                return log_debug_errno(r, "Failed to make failure packet: %m");

        r = dns_stub_finish_reply_packet(
                        reply,
                        DNS_PACKET_ID(p),
                        rcode,
                        truncated,
                        false,
                        DNS_PACKET_RD(p),
                        !!p->opt,
                        DNS_PACKET_DO(p),
                        (DNS_PACKET_AD(p) || DNS_PACKET_DO(p)) && authenticated,
                        DNS_PACKET_CD(p),
                        l ? ADVERTISE_EXTRA_DATAGRAM_SIZE_MAX : ADVERTISE_DATAGRAM_SIZE_MAX,
                        dns_packet_has_nsid_request(p) > 0 && !l);
        if (r < 0)
                return log_debug_errno(r, "Failed to build failure packet: %m");

        return dns_stub_send(m, l, s, p, reply);
}

static int dns_stub_patch_bypass_reply_packet(
                DnsPacket **ret,       /* Where to place the patched packet */
                DnsPacket *original,   /* The packet to patch */
                DnsPacket *request,    /* The packet the patched packet shall look like a reply to */
                bool validated,
                bool authenticated) {
        _cleanup_(dns_packet_unrefp) DnsPacket *c = NULL;
        int r;

        assert(ret);
        assert(original);
        assert(request);

        r = dns_packet_dup(&c, original);
        if (r < 0)
                return r;

        /* Extract the packet, so that we know where the OPT field is */
        r = dns_packet_extract(c);
        if (r < 0)
                return r;

        /* Copy over the original client request ID, so that we can make the upstream query look like our own reply. */
        DNS_PACKET_HEADER(c)->id = DNS_PACKET_HEADER(request)->id;

        /* Patch in our own maximum datagram size, if EDNS0 was on */
        r = dns_packet_patch_max_udp_size(c, ADVERTISE_DATAGRAM_SIZE_MAX);
        if (r < 0)
                return r;

        /* Lower all TTLs by the time passed since we received the datagram. */
        if (timestamp_is_set(original->timestamp)) {
                r = dns_packet_patch_ttls(c, original->timestamp);
                if (r < 0)
                        return r;
        }

        /* Our upstream connection might have supported larger DNS requests than our downstream one, hence
         * set the TC bit if our reply is larger than what the client supports, and truncate. */
        if (c->size > DNS_PACKET_PAYLOAD_SIZE_MAX(request)) {
                log_debug("Artificially truncating stub response, as advertised size of client is smaller than upstream one.");
                dns_packet_truncate(c, DNS_PACKET_PAYLOAD_SIZE_MAX(request));
                DNS_PACKET_HEADER(c)->flags = htobe16(be16toh(DNS_PACKET_HEADER(c)->flags) | DNS_PACKET_FLAG_TC);
        }

        /* Patch the cd bit to reflect the state of validation: set when both we and the upstream
         * resolver have checking disabled. */
        DNS_PACKET_HEADER(c)->flags = htobe16(UPDATE_FLAG(be16toh(DNS_PACKET_HEADER(c)->flags),
                                DNS_PACKET_FLAG_CD, DNS_PACKET_CD(original) && !validated));

        /* Ensure we don't pass along an untrusted ad flag for bypass packets */
        DNS_PACKET_HEADER(c)->flags = htobe16(UPDATE_FLAG(be16toh(DNS_PACKET_HEADER(c)->flags),
                                DNS_PACKET_FLAG_AD, authenticated));

        *ret = TAKE_PTR(c);
        return 0;
}

static void dns_stub_query_complete(DnsQuery *query) {
        _cleanup_(dns_query_freep) DnsQuery *q = query;
        int r;

        assert(q);
        assert(q->request_packet);

        if (q->question_bypass) {
                /* This is a bypass reply. If so, let's propagate the upstream packet, if we have it and it
                 * is regular DNS. (We can't do this if the upstream packet is LLMNR or mDNS, since the
                 * packets are not 100% compatible.) */

                if (q->answer_full_packet &&
                    q->answer_full_packet->protocol == DNS_PROTOCOL_DNS) {
                        _cleanup_(dns_packet_unrefp) DnsPacket *reply = NULL;

                        r = dns_stub_patch_bypass_reply_packet(&reply, q->answer_full_packet, q->request_packet,
                                        /* validated = */ !FLAGS_SET(q->flags, SD_RESOLVED_NO_VALIDATE),
                                        FLAGS_SET(q->answer_query_flags, SD_RESOLVED_AUTHENTICATED));
                        if (r < 0)
                                log_debug_errno(r, "Failed to patch bypass reply packet: %m");
                        else
                                (void) dns_stub_send(q->manager, q->stub_listener_extra, q->request_stream, q->request_packet, reply);

                        return;
                }
        }

        /* Take all data from the current reply, and merge it into the three reply sections we are building
         * up. We do this before processing CNAME redirects, so that we gradually build up our sections, and
         * and keep adding all RRs in the CNAME chain. */
        r = dns_stub_assign_sections(
                        q,
                        dns_query_question_for_protocol(q, DNS_PROTOCOL_DNS),
                        dns_stub_reply_with_edns0_do(q));
        if (r < 0)
                return (void) log_debug_errno(r, "Failed to assign sections: %m");

        switch (q->state) {

        case DNS_TRANSACTION_SUCCESS: {
                bool first = true;

                for (;;) {
                        int cname_result;

                        cname_result = dns_query_process_cname_one(q);
                        if (cname_result == -ELOOP) { /* CNAME loop, let's send what we already have */
                                log_debug("Detected CNAME loop, returning what we already have.");
                                (void) dns_stub_send_reply(q, q->answer_rcode);
                                break;
                        }
                        if (cname_result < 0) {
                                log_debug_errno(cname_result, "Failed to process CNAME: %m");
                                break;
                        }

                        if (cname_result == DNS_QUERY_NOMATCH) {
                                /* This answer doesn't contain any RR that would answer our question
                                 * positively, i.e. neither directly nor via CNAME. */

                                if (first) /* We never followed a CNAME and the answer doesn't match our
                                            * question at all? Then this is final, the empty answer is the
                                            * answer. */
                                        break;

                                /* Otherwise, we already followed a CNAME once within this packet, and the
                                 * packet doesn't answer our question. In that case let's restart the query,
                                 * now with the redirected question. We'll */
                                r = dns_query_go(q);
                                if (r < 0)
                                        return (void) log_debug_errno(r, "Failed to restart query: %m");

                                TAKE_PTR(q);
                                return;
                        }

                        r = dns_stub_assign_sections(
                                        q,
                                        dns_query_question_for_protocol(q, DNS_PROTOCOL_DNS),
                                        dns_stub_reply_with_edns0_do(q));
                        if (r < 0)
                                return (void) log_debug_errno(r, "Failed to assign sections: %m");

                        if (cname_result == DNS_QUERY_MATCH) /* A match? Then we are done, let's return what we got */
                                break;

                        /* We followed a CNAME. and collected the RRs that answer the redirected question
                         * successfully. Let's not try to do this again. */
                        assert(cname_result == DNS_QUERY_CNAME);
                        first = false;
                }

                _fallthrough_;
        }

        case DNS_TRANSACTION_RCODE_FAILURE:
                (void) dns_stub_send_reply(q, q->answer_rcode);
                break;

        case DNS_TRANSACTION_NOT_FOUND:
                (void) dns_stub_send_reply(q, DNS_RCODE_NXDOMAIN);
                break;

        case DNS_TRANSACTION_TIMEOUT:
        case DNS_TRANSACTION_ATTEMPTS_MAX_REACHED:
                /* Propagate a timeout as a no packet, i.e. that the client also gets a timeout */
                break;

        case DNS_TRANSACTION_NO_SERVERS:
                /* We're not configured to give answers for this question. Refuse it. */
                (void) dns_stub_send_reply(q, DNS_RCODE_REFUSED);
                break;

        case DNS_TRANSACTION_RR_TYPE_UNSUPPORTED:
                /* This RR Type is not implemented */
                (void) dns_stub_send_reply(q, DNS_RCODE_NOTIMP);
                break;

        case DNS_TRANSACTION_INVALID_REPLY:
        case DNS_TRANSACTION_ERRNO:
        case DNS_TRANSACTION_ABORTED:
        case DNS_TRANSACTION_DNSSEC_FAILED:
        case DNS_TRANSACTION_NO_TRUST_ANCHOR:
        case DNS_TRANSACTION_NETWORK_DOWN:
        case DNS_TRANSACTION_NO_SOURCE:
        case DNS_TRANSACTION_STUB_LOOP:
                (void) dns_stub_send_reply(q, DNS_RCODE_SERVFAIL);
                break;

        case DNS_TRANSACTION_NULL:
        case DNS_TRANSACTION_PENDING:
        case DNS_TRANSACTION_VALIDATING:
        default:
                assert_not_reached();
        }
}

static int dns_stub_stream_complete(DnsStream *s, int error) {
        assert(s);

        log_debug_errno(error, "DNS TCP connection terminated, destroying queries: %m");

        for (;;) {
                DnsQuery *q;

                q = set_first(s->queries);
                if (!q)
                        break;

                dns_query_free(q);
        }

        /* This drops the implicit ref we keep around since it was allocated, as incoming stub connections
         * should be kept as long as the client wants to. */
        dns_stream_unref(s);
        return 0;
}

static void dns_stub_process_query(Manager *m, DnsStubListenerExtra *l, DnsStream *s, DnsPacket *p) {
        uint64_t protocol_flags = SD_RESOLVED_PROTOCOLS_ALL;
        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        Hashmap **queries_by_packet;
        DnsQuery *existing;
        bool bypass = false;
        int r;

        assert(m);
        assert(p);
        assert(p->protocol == DNS_PROTOCOL_DNS);

        if (!l && /* l == NULL if this is the main stub */
            !address_is_proxy(p->family, &p->destination) && /* don't restrict needlessly for 127.0.0.54 */
            (in_addr_is_localhost(p->family, &p->sender) <= 0 ||
             in_addr_is_localhost(p->family, &p->destination) <= 0)) {
                log_warning("Got packet on unexpected (i.e. non-localhost) IP range, ignoring.");
                return;
        }

        if (manager_packet_from_our_transaction(m, p)) {
                log_debug("Got our own packet looped back, ignoring.");
                return;
        }

        queries_by_packet = l ? &l->queries_by_packet : &m->stub_queries_by_packet;
        existing = hashmap_get(*queries_by_packet, p);
        if (existing && dns_packet_equal(existing->request_packet, p)) {
                log_debug("Got repeat packet from client, ignoring.");
                return;
        }

        r = dns_packet_extract(p);
        if (r < 0) {
                log_debug_errno(r, "Failed to extract resources from incoming packet, ignoring packet: %m");
                dns_stub_send_failure(m, l, s, p, DNS_RCODE_FORMERR, false);
                return;
        }

        if (!DNS_PACKET_VERSION_SUPPORTED(p)) {
                log_debug("Got EDNS OPT field with unsupported version number.");
                dns_stub_send_failure(m, l, s, p, DNS_RCODE_BADVERS, false);
                return;
        }

        if (dns_type_is_obsolete(dns_question_first_key(p->question)->type)) {
                log_debug("Got message with obsolete key type, refusing.");
                dns_stub_send_failure(m, l, s, p, DNS_RCODE_REFUSED, false);
                return;
        }

        if (dns_type_is_zone_transfer(dns_question_first_key(p->question)->type)) {
                log_debug("Got request for zone transfer, refusing.");
                dns_stub_send_failure(m, l, s, p, DNS_RCODE_REFUSED, false);
                return;
        }

        if (!DNS_PACKET_RD(p))  {
                /* If the "rd" bit is off (i.e. recursion was not requested), then refuse operation */
                log_debug("Got request with recursion disabled, refusing.");
                dns_stub_send_failure(m, l, s, p, DNS_RCODE_REFUSED, false);
                return;
        }

        r = hashmap_ensure_allocated(queries_by_packet, &stub_packet_hash_ops);
        if (r < 0) {
                log_oom();
                return;
        }

        if (address_is_proxy(p->family, &p->destination)) {
                _cleanup_free_ char *dipa = NULL;

                r = in_addr_to_string(p->family, &p->destination, &dipa);
                if (r < 0)
                        return (void) log_error_errno(r, "Failed to format destination address: %m");

                log_debug("Got request to DNS proxy address 127.0.0.54, enabling bypass logic.");
                bypass = true;
                protocol_flags = SD_RESOLVED_DNS|SD_RESOLVED_NO_ZONE; /* Turn off mDNS/LLMNR for proxy stub. */
        } else if (DNS_PACKET_DO(p)) {
                log_debug("Got request with DNSSEC enabled, enabling bypass logic.");
                bypass = true;
        }

        if (bypass)
                r = dns_query_new(m, &q, NULL, NULL, p, 0,
                                  protocol_flags|
                                  SD_RESOLVED_NO_CNAME|
                                  SD_RESOLVED_NO_SEARCH|
                                  (DNS_PACKET_CD(p) ? SD_RESOLVED_NO_VALIDATE | SD_RESOLVED_NO_CACHE : 0)|
                                  SD_RESOLVED_REQUIRE_PRIMARY|
                                  SD_RESOLVED_CLAMP_TTL|
                                  SD_RESOLVED_RELAX_SINGLE_LABEL);
        else
                r = dns_query_new(m, &q, p->question, p->question, NULL, 0,
                                  protocol_flags|
                                  SD_RESOLVED_NO_SEARCH|
                                  (DNS_PACKET_CD(p) ? SD_RESOLVED_NO_VALIDATE | SD_RESOLVED_NO_CACHE : 0)|
                                  (DNS_PACKET_DO(p) ? SD_RESOLVED_REQUIRE_PRIMARY : 0)|
                                  SD_RESOLVED_CLAMP_TTL);
        if (r < 0) {
                log_error_errno(r, "Failed to generate query object: %m");
                dns_stub_send_failure(m, l, s, p, DNS_RCODE_SERVFAIL, false);
                return;
        }

        q->request_packet = dns_packet_ref(p);
        q->request_stream = dns_stream_ref(s); /* make sure the stream stays around until we can send a reply through it */
        q->stub_listener_extra = l;
        q->complete = dns_stub_query_complete;

        if (s) {
                /* Remember which queries belong to this stream, so that we can cancel them when the stream
                 * is disconnected early */

                r = set_ensure_put(&s->queries, NULL, q);
                if (r < 0) {
                        log_oom();
                        return;
                }
                assert(r > 0);
        }

        /* Add the query to the hash table we use to determine repeat packets now. We don't care about
         * failures here, since in the worst case we'll not recognize duplicate incoming requests, which
         * isn't particularly bad. */
        (void) hashmap_put(*queries_by_packet, q->request_packet, q);

        r = dns_query_go(q);
        if (r < 0) {
                log_error_errno(r, "Failed to start query: %m");
                dns_stub_send_failure(m, l, s, p, DNS_RCODE_SERVFAIL, false);
                return;
        }

        log_debug("Processing query...");
        TAKE_PTR(q);
}

static int on_dns_stub_packet_internal(sd_event_source *s, int fd, uint32_t revents, Manager *m, DnsStubListenerExtra *l) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        int r;

        r = manager_recv(m, fd, DNS_PROTOCOL_DNS, &p);
        if (r <= 0)
                return r;

        if (dns_packet_validate_query(p) > 0) {
                log_debug("Got DNS stub UDP query packet for id %u", DNS_PACKET_ID(p));

                dns_stub_process_query(m, l, NULL, p);
        } else
                log_debug("Invalid DNS stub UDP packet, ignoring.");

        return 0;
}

static int on_dns_stub_packet(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        return on_dns_stub_packet_internal(s, fd, revents, userdata, NULL);
}

static int on_dns_stub_packet_extra(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        DnsStubListenerExtra *l = ASSERT_PTR(userdata);

        return on_dns_stub_packet_internal(s, fd, revents, l->manager, l);
}

static int on_dns_stub_stream_packet(DnsStream *s, DnsPacket *p) {
        assert(s);
        assert(s->manager);
        assert(p);

        if (dns_packet_validate_query(p) > 0) {
                log_debug("Got DNS stub TCP query packet for id %u", DNS_PACKET_ID(p));

                dns_stub_process_query(s->manager, s->stub_listener_extra, s, p);
        } else
                log_debug("Invalid DNS stub TCP packet, ignoring.");

        return 0;
}

static int on_dns_stub_stream_internal(sd_event_source *s, int fd, uint32_t revents, Manager *m, DnsStubListenerExtra *l) {
        DnsStream *stream;
        int cfd, r;

        cfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (cfd < 0) {
                if (ERRNO_IS_ACCEPT_AGAIN(errno))
                        return 0;

                return -errno;
        }

        r = dns_stream_new(m, &stream, DNS_STREAM_STUB, DNS_PROTOCOL_DNS, cfd, NULL,
                           on_dns_stub_stream_packet, dns_stub_stream_complete, DNS_STREAM_STUB_TIMEOUT_USEC);
        if (r < 0) {
                safe_close(cfd);
                return r;
        }

        stream->stub_listener_extra = l;

        /* We let the reference to the stream dangle here, it will be dropped later by the complete callback. */

        return 0;
}

static int on_dns_stub_stream(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        return on_dns_stub_stream_internal(s, fd, revents, userdata, NULL);
}

static int on_dns_stub_stream_extra(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        DnsStubListenerExtra *l = ASSERT_PTR(userdata);

        return on_dns_stub_stream_internal(s, fd, revents, l->manager, l);
}

static int set_dns_stub_common_socket_options(int fd, int family) {
        int r;

        assert(fd >= 0);
        assert(IN_SET(family, AF_INET, AF_INET6));

        r = setsockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, true);
        if (r < 0)
                return r;

        r = socket_set_recvpktinfo(fd, family, true);
        if (r < 0)
                return r;

        r = socket_set_recvttl(fd, family, true);
        if (r < 0)
                return r;

        return 0;
}

static int set_dns_stub_common_tcp_socket_options(int fd) {
        int r;

        assert(fd >= 0);

        r = setsockopt_int(fd, IPPROTO_TCP, TCP_FASTOPEN, 5); /* Everybody appears to pick qlen=5, let's do the same here. */
        if (r < 0)
                log_debug_errno(r, "Failed to enable TCP_FASTOPEN on TCP listening socket, ignoring: %m");

        r = setsockopt_int(fd, IPPROTO_TCP, TCP_NODELAY, true);
        if (r < 0)
                log_debug_errno(r, "Failed to enable TCP_NODELAY mode, ignoring: %m");

        return 0;
}

static int manager_dns_stub_fd(
                Manager *m,
                int family,
                const union in_addr_union *listen_addr,
                int type) {

        sd_event_source **event_source;
        _cleanup_close_ int fd = -EBADF;
        union sockaddr_union sa;
        int r;

        assert(m);
        assert(listen_addr);

        if (type == SOCK_DGRAM)
                event_source = address_is_proxy(family, listen_addr) ? &m->dns_proxy_stub_udp_event_source : &m->dns_stub_udp_event_source;
        else if (type == SOCK_STREAM)
                event_source = address_is_proxy(family, listen_addr) ? &m->dns_proxy_stub_tcp_event_source : &m->dns_stub_tcp_event_source;
        else
                return -EPROTONOSUPPORT;

        if (*event_source)
                return sd_event_source_get_io_fd(*event_source);

        fd = socket(family, type | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        r = set_dns_stub_common_socket_options(fd, family);
        if (r < 0)
                return r;

        if (type == SOCK_STREAM) {
                r = set_dns_stub_common_tcp_socket_options(fd);
                if (r < 0)
                        return r;
        }

        /* Set slightly different socket options for the non-proxy and the proxy binding. The former we want
         * to be accessible only from the local host, for the latter it's OK if people use NAT redirects or
         * so to redirect external traffic to it. */

        if (!address_is_proxy(family, listen_addr)) {
                /* Make sure no traffic from outside the local host can leak to onto this socket */
                r = socket_bind_to_ifindex(fd, LOOPBACK_IFINDEX);
                if (r < 0)
                        return r;

                r = socket_set_ttl(fd, family, 1);
                if (r < 0)
                        return r;
        } else if (type == SOCK_DGRAM) {
                /* Turn off Path MTU Discovery for UDP, for security reasons. See socket_disable_pmtud() for
                 * a longer discussion. (We only do this for sockets that are potentially externally
                 * accessible, i.e. the proxy stub one. For the non-proxy one we instead set the TTL to 1,
                 * see above, so that packets don't get routed at all.) */
                r = socket_disable_pmtud(fd, family);
                if (r < 0)
                        log_debug_errno(r, "Failed to disable UDP PMTUD, ignoring: %m");

                r = socket_set_recvfragsize(fd, family, true);
                if (r < 0)
                        log_debug_errno(r, "Failed to enable fragment size reception, ignoring: %m");
        }

        r = sockaddr_set_in_addr(&sa, family, listen_addr, 53);
        if (r < 0)
                return r;

        if (bind(fd, &sa.sa, sizeof(sa.in)) < 0)
                return -errno;

        if (type == SOCK_STREAM &&
            listen(fd, SOMAXCONN_DELUXE) < 0)
                return -errno;

        r = sd_event_add_io(m->event, event_source, fd, EPOLLIN,
                            type == SOCK_DGRAM ? on_dns_stub_packet : on_dns_stub_stream,
                            m);
        if (r < 0)
                return r;

        r = sd_event_source_set_io_fd_own(*event_source, true);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(*event_source,
                                               type == SOCK_DGRAM ? "dns-stub-udp" : "dns-stub-tcp");

        return TAKE_FD(fd);
}

static int manager_dns_stub_fd_extra(Manager *m, DnsStubListenerExtra *l, int type) {
        _cleanup_free_ char *pretty = NULL;
        _cleanup_close_ int fd = -EBADF;
        union sockaddr_union sa;
        int r;

        assert(m);
        assert(l);
        assert(IN_SET(type, SOCK_DGRAM, SOCK_STREAM));

        sd_event_source **event_source = type == SOCK_DGRAM ? &l->udp_event_source : &l->tcp_event_source;
        if (*event_source)
                return sd_event_source_get_io_fd(*event_source);

        if (!have_effective_cap(CAP_NET_BIND_SERVICE) && dns_stub_listener_extra_port(l) < 1024) {
                log_warning("Missing CAP_NET_BIND_SERVICE capability, not creating extra stub listener on port %hu.",
                            dns_stub_listener_extra_port(l));
                return 0;
        }

        if (l->family == AF_INET)
                sa = (union sockaddr_union) {
                        .in.sin_family = l->family,
                        .in.sin_port = htobe16(dns_stub_listener_extra_port(l)),
                        .in.sin_addr = l->address.in,
                };
        else
                sa = (union sockaddr_union) {
                        .in6.sin6_family = l->family,
                        .in6.sin6_port = htobe16(dns_stub_listener_extra_port(l)),
                        .in6.sin6_addr = l->address.in6,
                };

        fd = socket(l->family, type | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0) {
                r = -errno;
                goto fail;
        }

        r = set_dns_stub_common_socket_options(fd, l->family);
        if (r < 0)
                goto fail;

        if (type == SOCK_STREAM) {
                r = set_dns_stub_common_tcp_socket_options(fd);
                if (r < 0)
                        goto fail;
        }

        /* Do not set IP_TTL for extra DNS stub listeners, as the address may not be local and in that case
         * people may want ttl > 1. */

        r = socket_set_freebind(fd, l->family, true);
        if (r < 0)
                goto fail;

        if (type == SOCK_DGRAM) {
                r = socket_disable_pmtud(fd, l->family);
                if (r < 0)
                        log_debug_errno(r, "Failed to disable UDP PMTUD, ignoring: %m");

                r = socket_set_recvfragsize(fd, l->family, true);
                if (r < 0)
                        log_debug_errno(r, "Failed to enable fragment size reception, ignoring: %m");
        }

        r = RET_NERRNO(bind(fd, &sa.sa, SOCKADDR_LEN(sa)));
        if (r < 0)
                goto fail;

        if (type == SOCK_STREAM &&
            listen(fd, SOMAXCONN_DELUXE) < 0) {
                r = -errno;
                goto fail;
        }

        r = sd_event_add_io(m->event, event_source, fd, EPOLLIN,
                            type == SOCK_DGRAM ? on_dns_stub_packet_extra : on_dns_stub_stream_extra,
                            l);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_io_fd_own(*event_source, true);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(*event_source,
                                               type == SOCK_DGRAM ? "dns-stub-udp-extra" : "dns-stub-tcp-extra");

        if (DEBUG_LOGGING) {
                (void) in_addr_port_to_string(l->family, &l->address, l->port, &pretty);
                log_debug("Listening on %s socket %s.",
                          type == SOCK_DGRAM ? "UDP" : "TCP",
                          strnull(pretty));
        }

        return TAKE_FD(fd);

fail:
        assert(r < 0);
        (void) in_addr_port_to_string(l->family, &l->address, l->port, &pretty);
        return log_warning_errno(r,
                                 r == -EADDRINUSE ? "Another process is already listening on %s socket %s: %m" :
                                                    "Failed to listen on %s socket %s: %m",
                                 type == SOCK_DGRAM ? "UDP" : "TCP",
                                 strnull(pretty));
}

int manager_dns_stub_start(Manager *m) {
        int r;

        assert(m);

        if (m->dns_stub_listener_mode == DNS_STUB_LISTENER_NO)
                log_debug("Not creating stub listener.");
        else if (!have_effective_cap(CAP_NET_BIND_SERVICE))
                log_warning("Missing CAP_NET_BIND_SERVICE capability, not creating stub listener on port 53.");
        else {
                static const struct {
                        uint32_t addr;
                        int socket_type;
                } stub_sockets[] = {
                        { INADDR_DNS_STUB,       SOCK_DGRAM  },
                        { INADDR_DNS_STUB,       SOCK_STREAM },
                        { INADDR_DNS_PROXY_STUB, SOCK_DGRAM  },
                        { INADDR_DNS_PROXY_STUB, SOCK_STREAM },
                };

                log_debug("Creating stub listener using %s.",
                          m->dns_stub_listener_mode == DNS_STUB_LISTENER_UDP ? "UDP" :
                          m->dns_stub_listener_mode == DNS_STUB_LISTENER_TCP ? "TCP" :
                          "UDP/TCP");

                FOREACH_ELEMENT(s, stub_sockets) {
                        union in_addr_union a = {
                                .in.s_addr = htobe32(s->addr),
                        };

                        if (m->dns_stub_listener_mode == DNS_STUB_LISTENER_UDP && s->socket_type == SOCK_STREAM)
                                continue;
                        if (m->dns_stub_listener_mode == DNS_STUB_LISTENER_TCP && s->socket_type == SOCK_DGRAM)
                                continue;

                        r = manager_dns_stub_fd(m, AF_INET, &a, s->socket_type);
                        if (r < 0) {
                                _cleanup_free_ char *busy_socket = NULL;

                                if (asprintf(&busy_socket,
                                             "%s socket " IPV4_ADDRESS_FMT_STR ":53",
                                             s->socket_type == SOCK_DGRAM ? "UDP" : "TCP",
                                             IPV4_ADDRESS_FMT_VAL(a.in)) < 0)
                                        return log_oom();

                                if (IN_SET(r, -EADDRINUSE, -EPERM)) {
                                        log_warning_errno(r,
                                                          r == -EADDRINUSE ? "Another process is already listening on %s.\n"
                                                          "Turning off local DNS stub support." :
                                                          "Failed to listen on %s: %m.\n"
                                          "Turning off local DNS stub support.",
                                                          busy_socket);
                                        manager_dns_stub_stop(m);
                                        break;
                                }

                                return log_error_errno(r, "Failed to listen on %s: %m", busy_socket);
                        }
                }
        }

        if (!ordered_set_isempty(m->dns_extra_stub_listeners)) {
                DnsStubListenerExtra *l;

                log_debug("Creating extra stub listeners.");

                ORDERED_SET_FOREACH(l, m->dns_extra_stub_listeners) {
                        if (FLAGS_SET(l->mode, DNS_STUB_LISTENER_UDP))
                                (void) manager_dns_stub_fd_extra(m, l, SOCK_DGRAM);
                        if (FLAGS_SET(l->mode, DNS_STUB_LISTENER_TCP))
                                (void) manager_dns_stub_fd_extra(m, l, SOCK_STREAM);
                }
        }

        return 0;
}

void manager_dns_stub_stop(Manager *m) {
        assert(m);

        m->dns_stub_udp_event_source = sd_event_source_disable_unref(m->dns_stub_udp_event_source);
        m->dns_stub_tcp_event_source = sd_event_source_disable_unref(m->dns_stub_tcp_event_source);
        m->dns_proxy_stub_udp_event_source = sd_event_source_disable_unref(m->dns_proxy_stub_udp_event_source);
        m->dns_proxy_stub_tcp_event_source = sd_event_source_disable_unref(m->dns_proxy_stub_tcp_event_source);
}

static const char* const dns_stub_listener_mode_table[_DNS_STUB_LISTENER_MODE_MAX] = {
        [DNS_STUB_LISTENER_NO]  = "no",
        [DNS_STUB_LISTENER_UDP] = "udp",
        [DNS_STUB_LISTENER_TCP] = "tcp",
        [DNS_STUB_LISTENER_YES] = "yes",
};
DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(dns_stub_listener_mode, DnsStubListenerMode, DNS_STUB_LISTENER_YES);
