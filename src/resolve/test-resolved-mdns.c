/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "sd-event.h"

#include "dns-answer.h"
#include "dns-rr.h"
#include "dns-type.h"
#include "resolve-util.h"
#include "resolved-dns-cache.h"
#include "resolved-dns-scope.h"
#include "resolved-manager.h"
#include "resolved-mdns.h"
#include "tests.h"
#include "time-util.h"

/* Covers the re-arm decision in mdns_goodbye_callback(). A goodbye rewrites the record's TTL to 1 and arms a
 * one-second timer to drop it, and on firing the callback has to keep looking for as long as something is
 * still due to expire. It used to ask about the time the timer was scheduled for rather than the time it was
 * running at, and those differ by up to the timer's accuracy window: a goodbye landing in that gap pushes
 * the record's expiry beyond what the callback goes on to check, so nothing is dropped and the service
 * browsers are never told the service went away.
 *
 * That gap cannot be aimed at from the wire, so the callback is called directly with a deadline left in the
 * past, which puts it in the same state without having to win the race. */

static void put_a(DnsScope *scope, const char *name, uint32_t ttl) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        union in_addr_union owner = { .in.s_addr = htobe32(0x0a000001) };

        answer = dns_answer_new(1);
        ASSERT_NOT_NULL(answer);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, name);
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a80101);
        rr->ttl = ttl;

        ASSERT_OK(dns_answer_add(answer, rr, 1, DNS_ANSWER_CACHEABLE|DNS_ANSWER_SHARED_OWNER, NULL));

        ASSERT_OK(dns_cache_put(&scope->cache,
                                DNS_CACHE_MODE_YES,
                                DNS_PROTOCOL_MDNS,
                                /* key= */ NULL,
                                DNS_RCODE_SUCCESS,
                                answer,
                                /* full_packet= */ NULL,
                                /* query_flags= */ 0,
                                DNSSEC_UNSIGNED,
                                /* nsec_ttl= */ UINT32_MAX,
                                AF_INET,
                                &owner,
                                /* stale_retention_usec= */ 0));
}

/* A DNS scope, not an mDNS one: dns_scope_new() joins the multicast group for the multicast protocols,
 * which asserts on a link and needs a real socket. Only the cache matters here, and the records go in with
 * mDNS semantics in put_a(). */
static DnsScope* test_scope_new(Manager *manager, sd_event **ret_event) {
        DnsScope *scope = NULL;

        assert(manager);
        assert(ret_event);

        ASSERT_OK(sd_event_new(ret_event));
        manager->event = *ret_event;
        manager->cache_max[DNS_PROTOCOL_DNS] = DEFAULT_CACHE_MAX;

        ASSERT_OK(dns_scope_new(manager, &scope, DNS_SCOPE_GLOBAL, /* link= */ NULL,
                                /* delegate= */ NULL, DNS_PROTOCOL_DNS, AF_INET));

        return scope;
}

/* The record is still a second from expiring, so nothing is pruned and no browser is notified either way;
 * whether another pass gets scheduled is the whole question. Measured against the stale deadline the answer
 * is no, and the withdrawal then waits for the per-service maintenance ladder. */
TEST(mdns_goodbye_rearms_against_current_time) {
        /* Declared before the cleanup variables: they are released in reverse order, and
         * dns_scope_free() reaches into the manager. */
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = test_scope_new(&manager, &event);
        usec_t stale_deadline;

        /* Cache the record, then overwrite it with the TTL=1 rewrite a goodbye leaves behind. */
        put_a(scope, "goodbye.local", 120);
        put_a(scope, "goodbye.local", 1);
        ASSERT_EQ(dns_cache_size(&scope->cache), 1u);

        stale_deadline = usec_sub_unsigned(now(CLOCK_BOOTTIME), 5 * USEC_PER_SEC);
        ASSERT_OK(sd_event_add_time(event, &scope->mdns_goodbye_event_source, CLOCK_BOOTTIME,
                                    stale_deadline, 0, NULL, NULL));

        ASSERT_OK(mdns_goodbye_callback(scope->mdns_goodbye_event_source, stale_deadline, scope));

        ASSERT_EQ(dns_cache_size(&scope->cache), 1u);
        ASSERT_NOT_NULL(scope->mdns_goodbye_event_source);
}

/* The complementary case: with nothing left in the cache there is nothing to wait for, so the timer has to
 * be released rather than re-armed. */
TEST(mdns_goodbye_does_not_rearm_when_cache_empty) {
        /* Declared before the cleanup variables: they are released in reverse order, and
         * dns_scope_free() reaches into the manager. */
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = test_scope_new(&manager, &event);

        ASSERT_OK(sd_event_add_time(event, &scope->mdns_goodbye_event_source, CLOCK_BOOTTIME,
                                    now(CLOCK_BOOTTIME), 0, NULL, NULL));

        ASSERT_OK(mdns_goodbye_callback(scope->mdns_goodbye_event_source, now(CLOCK_BOOTTIME), scope));

        ASSERT_NULL(scope->mdns_goodbye_event_source);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
