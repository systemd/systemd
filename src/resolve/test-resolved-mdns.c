/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <sys/socket.h>

#include "sd-event.h"

#include "dns-answer.h"
#include "dns-packet.h"
#include "dns-rr.h"
#include "dns-type.h"
#include "resolve-util.h"
#include "resolved-dns-cache.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-transaction.h"
#include "resolved-manager.h"
#include "resolved-mdns.h"
#include "tests.h"
#include "time-util.h"

/* Tests for the mDNS reply path and its goodbye timer, which drops the records of a goodbye from the
 * cache a second after receipt, as RFC 6762 section 10.1 asks, and then tells the browsers. The tests
 * hand packets to mdns_scope_process_packet(), as on_mdns_packet() does after the socket read. */

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

static DnsResourceRecord* new_ptr(const char *name, const char *target) {
        DnsResourceRecord *rr;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, name);
        ASSERT_NOT_NULL(rr);
        ASSERT_NOT_NULL(rr->ptr.name = strdup(target));
        rr->ttl = 120;

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

/* The TTL the cache holds for the A record of 'name'. */
static uint32_t cached_ttl(DnsScope *scope, const char *name) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsResourceRecord *rr;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, name);
        ASSERT_NOT_NULL(key);
        ASSERT_OK_POSITIVE(dns_cache_lookup(&scope->cache, key, /* query_flags= */ 0, /* ret_rcode= */ NULL,
                                            &answer, /* ret_full_packet= */ NULL,
                                            /* ret_query_flags= */ NULL, /* ret_dnssec_result= */ NULL));
        ASSERT_EQ(dns_answer_size(answer), 1u);

        DNS_ANSWER_FOREACH(rr, answer)
                return rr->ttl;

        assert_not_reached();
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

/* A failure to arm the timer is only logged: returning it from the packet handler made sd-event switch
 * off mDNS reception. A finished event loop refuses to arm timers. */
TEST(mdns_goodbye_arm_failure_is_not_returned) {
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *bye = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;

        scope = test_scope_new(&manager, &event);
        receive_a(scope, "goodbye.local", 120);

        ASSERT_OK(sd_event_exit(event, /* code= */ 0));
        ASSERT_OK(sd_event_run(event, /* timeout= */ 0));
        ASSERT_EQ(sd_event_get_state(event), SD_EVENT_FINISHED);

        bye = new_a("goodbye.local", /* ttl= */ 0);
        p = make_reply(&bye, 1, /* flags= */ 0);
        ASSERT_RETURN_EXPECTED(ASSERT_OK(mdns_scope_process_packet(scope, p)));

        /* The packet was handled all the same: the goodbye reached the cache. */
        ASSERT_EQ(cached_ttl(scope, "goodbye.local"), 1u);
        ASSERT_NULL(scope->mdns_goodbye_event_source);
}

/* Nor does it cut the rest of the reply's handling short: a transaction waiting for the record still
 * takes the reply. The scope is an mDNS one without a link, built by hand: a transaction on a DNS scope
 * would treat the reply as one from a unicast DNS server. */
TEST(mdns_goodbye_arm_failure_still_answers_transactions) {
        Manager manager = {
                .enable_cache = DNS_CACHE_MODE_YES,
        };
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *bye = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        DnsTransaction *t;

        ASSERT_OK(sd_event_new(&event));
        manager.event = event;
        DnsScope scope = {
                .manager = &manager,
                .protocol = DNS_PROTOCOL_MDNS,
                .family = AF_INET,
                .cache.cache_max = DEFAULT_CACHE_MAX,
        };

        ASSERT_OK(sd_event_exit(event, /* code= */ 0));
        ASSERT_OK(sd_event_run(event, /* timeout= */ 0));
        ASSERT_EQ(sd_event_get_state(event), SD_EVENT_FINISHED);

        /* Sent, and waiting for an answer. Kept around for inspection once it completes. */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "goodbye.local"));
        ASSERT_OK(dns_transaction_new(&t, &scope, key, /* bypass= */ NULL, /* flags= */ 0));
        t->block_gc++;
        t->state = DNS_TRANSACTION_PENDING;
        t->n_attempts = 1;
        t->wait_for_answer = true;

        /* Without a link, the reply comes in on no interface either. */
        bye = new_a("goodbye.local", /* ttl= */ 0);
        p = make_reply(&bye, 1, /* flags= */ 0);
        p->ifindex = 0;
        ASSERT_RETURN_EXPECTED(ASSERT_OK(mdns_scope_process_packet(&scope, p)));

        ASSERT_NULL(scope.mdns_goodbye_event_source);
        ASSERT_EQ(t->state, DNS_TRANSACTION_SUCCESS);
        ASSERT_EQ(dns_answer_size(t->answer), 1u);

        t->block_gc--;
        ASSERT_NULL(dns_transaction_gc(t));
        ASSERT_NULL(scope.transactions);

        hashmap_free(scope.transactions_by_key);
        hashmap_free(manager.dns_transactions);
        dns_cache_flush(&scope.cache);
}

/* RFC 6762 section 10.1: each goodbye record of a reply is cached with TTL 1, not dropped at once, and
 * a live record between them keeps its TTL. */
TEST(mdns_goodbye_records_are_cached_with_ttl_1) {
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *bye = NULL, *stays = NULL, *bye2 = NULL;

        scope = test_scope_new(&manager, &event);
        receive_a(scope, "bye.local", 120);
        receive_a(scope, "stays.local", 120);
        receive_a(scope, "bye2.local", 120);

        bye = new_a("bye.local", /* ttl= */ 0);
        stays = new_a("stays.local", 120);
        bye2 = new_a("bye2.local", /* ttl= */ 0);
        DnsResourceRecord *rrs[] = { bye, stays, bye2 };
        receive(scope, rrs, ELEMENTSOF(rrs));

        ASSERT_EQ(cached_ttl(scope, "bye.local"), 1u);
        ASSERT_EQ(cached_ttl(scope, "stays.local"), 120u);
        ASSERT_EQ(cached_ttl(scope, "bye2.local"), 1u);
        ASSERT_NOT_NULL(scope->mdns_goodbye_event_source);
}

/* Only a goodbye arms the pass: a reply with nothing but live records leaves the timer alone, even if
 * one has TTL 1. */
TEST(mdns_reply_without_goodbye_arms_nothing) {
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *live = NULL, *brief = NULL;

        scope = test_scope_new(&manager, &event);

        live = new_a("live.local", 120);
        brief = new_a("brief.local", 1);
        DnsResourceRecord *rrs[] = { live, brief };
        receive(scope, rrs, ELEMENTSOF(rrs));

        ASSERT_EQ(cached_ttl(scope, "live.local"), 120u);
        ASSERT_NULL(scope->mdns_goodbye_event_source);
}

/* A reply carrying any record outside .local and the reverse zones is discarded whole: its goodbye
 * neither gets cached nor arms the pass. */
TEST(mdns_reply_failing_the_name_check_arms_nothing) {
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *bye = NULL, *foreign = NULL;

        scope = test_scope_new(&manager, &event);
        receive_a(scope, "goodbye.local", 120);

        bye = new_a("goodbye.local", /* ttl= */ 0);
        foreign = new_a("example.com", 120);
        DnsResourceRecord *rrs[] = { bye, foreign };
        receive(scope, rrs, ELEMENTSOF(rrs));

        ASSERT_EQ(cached_ttl(scope, "goodbye.local"), 120u);
        ASSERT_NULL(scope->mdns_goodbye_event_source);
}

/* RFC 6762 section 6: a reply from a source port other than 5353 is ignored, its goodbye included. */
TEST(mdns_reply_from_another_port_arms_nothing) {
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *bye = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;

        scope = test_scope_new(&manager, &event);
        receive_a(scope, "goodbye.local", 120);

        bye = new_a("goodbye.local", /* ttl= */ 0);
        p = make_reply(&bye, 1, /* flags= */ 0);
        p->sender_port = MDNS_PORT + 1;
        ASSERT_OK(mdns_scope_process_packet(scope, p));

        ASSERT_EQ(cached_ttl(scope, "goodbye.local"), 120u);
        ASSERT_NULL(scope->mdns_goodbye_event_source);
}

/* The reverse zones pass the name check too: a reply for them is cached. */
TEST(mdns_reply_for_the_reverse_zones_is_cached) {
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *v4 = NULL, *v6 = NULL;

        scope = test_scope_new(&manager, &event);

        v4 = new_ptr("1.1.168.192.in-addr.arpa", "host.local");
        v6 = new_ptr("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
                     "host.local");

        receive(scope, &v4, 1);
        receive(scope, &v6, 1);
        ASSERT_EQ(dns_cache_size(&scope->cache), 2u);
}

/* A reply that fails to parse is dropped, not returned as a failure: that would make sd-event switch off
 * mDNS reception. */
TEST(mdns_malformed_reply_is_dropped) {
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *bye = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;

        scope = test_scope_new(&manager, &event);

        /* It announces a second record it does not carry. */
        bye = new_a("goodbye.local", /* ttl= */ 0);
        p = make_reply(&bye, 1, /* flags= */ 0);
        DNS_PACKET_HEADER(p)->ancount = htobe16(2);
        ASSERT_OK(mdns_scope_process_packet(scope, p));

        ASSERT_TRUE(dns_cache_is_empty(&scope->cache));
        ASSERT_NULL(scope->mdns_goodbye_event_source);
}

/* So is a query that fails to parse. */
TEST(mdns_malformed_query_is_dropped) {
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;

        scope = test_scope_new(&manager, &event);

        /* It announces a question it does not carry. */
        ASSERT_OK(dns_packet_new_query(&p, DNS_PROTOCOL_MDNS, /* min_alloc_dsize= */ 0,
                                       /* dnssec_checking_disabled= */ false));
        DNS_PACKET_HEADER(p)->qdcount = htobe16(1);
        p->family = AF_INET;
        p->sender.in.s_addr = htobe32(0x0a000001);
        p->sender_port = MDNS_PORT;
        p->ifindex = 1;
        ASSERT_OK(mdns_scope_process_packet(scope, p));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
