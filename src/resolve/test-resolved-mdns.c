/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "sd-event.h"

#include "dns-packet.h"
#include "dns-rr.h"
#include "dns-type.h"
#include "resolve-util.h"
#include "resolved-dns-cache.h"
#include "resolved-dns-scope.h"
#include "resolved-manager.h"
#include "resolved-mdns.h"
#include "tests.h"
#include "time-util.h"

/* Tests for the mDNS goodbye timer, which drops the records of a goodbye from the cache a second after
 * receipt, as RFC 6762 section 10.1 asks, and then tells the browsers. The tests hand packets to
 * mdns_scope_process_packet(), as on_mdns_packet() does after the socket read. */

/* A DNS scope, not an mDNS one: dns_scope_new() joins the multicast group for the multicast
 * protocols, which needs a link and a real socket. The reply path does not care, and with no browsers
 * or transactions on the manager, what it passes on reaches nobody. */
static DnsScope* test_scope_new(Manager *manager, sd_event **ret_event) {
        DnsScope *scope = NULL;

        assert(manager);
        assert(ret_event);

        ASSERT_OK(sd_event_new(ret_event));
        manager->event = *ret_event;
        manager->enable_cache = DNS_CACHE_MODE_YES;
        manager->cache_max[DNS_PROTOCOL_DNS] = DEFAULT_CACHE_MAX;

        ASSERT_OK(dns_scope_new(manager, &scope, DNS_SCOPE_GLOBAL, /* link= */ NULL,
                                /* delegate= */ NULL, DNS_PROTOCOL_DNS, AF_INET));

        return scope;
}

static DnsResourceRecord* new_a(const char *name, uint32_t ttl) {
        DnsResourceRecord *rr;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, name);
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a80101);
        rr->ttl = ttl;

        return rr;
}

/* An mDNS reply from 10.0.0.1, port 5353, carrying the records. With DNS_ANSWER_CACHE_FLUSH in 'flags',
 * each carries the cache-flush bit. */
static DnsPacket* make_reply(DnsResourceRecord **rrs, size_t n, DnsAnswerFlags flags) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;

        ASSERT_OK(dns_packet_new(&p, DNS_PROTOCOL_MDNS, /* min_alloc_dsize= */ 0, DNS_PACKET_SIZE_MAX));
        DNS_PACKET_HEADER(p)->flags = htobe16(DNS_PACKET_MAKE_FLAGS(
                                                              1 /* qr */,
                                                              0 /* opcode */,
                                                              1 /* aa */,
                                                              0 /* tc */,
                                                              0 /* rd */,
                                                              0 /* ra */,
                                                              0 /* ad */,
                                                              0 /* cd */,
                                                              DNS_RCODE_SUCCESS));
        FOREACH_ARRAY(rr, rrs, n)
                ASSERT_OK(dns_packet_append_rr(p, *rr, flags, /* start= */ NULL, /* rdata_start= */ NULL));
        DNS_PACKET_HEADER(p)->ancount = htobe16(n);

        p->family = AF_INET;
        p->sender.in.s_addr = htobe32(0x0a000001);
        p->sender_port = MDNS_PORT;
        p->ifindex = 1;

        return TAKE_PTR(p);
}

static void receive(DnsScope *scope, DnsResourceRecord **rrs, size_t n) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;

        p = make_reply(rrs, n, /* flags= */ 0);
        ASSERT_OK(mdns_scope_process_packet(scope, p));
}

/* Receive a reply carrying an A record for 'name'. With TTL 0, that is a goodbye. */
static void receive_a(DnsScope *scope, const char *name, uint32_t ttl) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = new_a(name, ttl);
        receive(scope, &rr, 1);
}

/* Cache 'name', then receive a goodbye for it: the cache only takes the goodbye's TTL 1 for a record it
 * already holds. */
static void receive_goodbye(DnsScope *scope, const char *name) {
        receive_a(scope, name, 120);
        receive_a(scope, name, /* ttl= */ 0);
}

/* Leave the armed goodbye timer's deadline in the past, as if its dispatch had run late. The next event
 * loop iteration dispatches it at once. */
static void make_deadline_stale(DnsScope *scope) {
        ASSERT_NOT_NULL(scope->mdns_goodbye_event_source);
        ASSERT_OK(sd_event_source_set_time(scope->mdns_goodbye_event_source,
                                           usec_sub_unsigned(now(CLOCK_BOOTTIME), 5 * USEC_PER_SEC)));
}

/* A goodbye received after the timer came due, but before a busy event loop dispatched it: the pass has
 * to look a second ahead of now, or it finds the goodbye's record outside that window and arms no pass
 * for it. A deadline left in the past stands in for the late dispatch. */
TEST(mdns_goodbye_after_the_deadline_rearms) {
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        usec_t accuracy;

        scope = test_scope_new(&manager, &event);

        for (unsigned i = 0;; i++) {
                receive_goodbye(scope, "goodbye.local");

                make_deadline_stale(scope);
                ASSERT_OK_POSITIVE(sd_event_run(event, /* timeout= */ 0));

                /* The case under test: the record had not expired yet when the pass looked. A runner
                 * that stalled for a second misses it, so start over. */
                if (dns_cache_size(&scope->cache) == 1)
                        break;

                scope->mdns_goodbye_event_source =
                        sd_event_source_disable_unref(scope->mdns_goodbye_event_source);
                ASSERT_LT(i, 8u);
        }

        /* So the pass armed another, at most the default accuracy (250ms) late. */
        ASSERT_NOT_NULL(scope->mdns_goodbye_event_source);
        ASSERT_OK(sd_event_source_get_time_accuracy(scope->mdns_goodbye_event_source, &accuracy));
        ASSERT_LE(accuracy, 250 * USEC_PER_MSEC);

        /* That pass drops the record and releases the timer. */
        ASSERT_OK_POSITIVE(sd_event_run(event, 3 * USEC_PER_SEC));
        ASSERT_TRUE(dns_cache_is_empty(&scope->cache));
        ASSERT_NULL(scope->mdns_goodbye_event_source);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
