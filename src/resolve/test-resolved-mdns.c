/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "sd-event.h"

#include "dns-answer.h"
#include "dns-packet.h"
#include "dns-rr.h"
#include "dns-type.h"
#include "in-addr-util.h"
#include "resolve-util.h"
#include "resolved-dns-cache.h"
#include "resolved-dns-dnssec.h"
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
 * The callback now measures against a fresh clock reading and ignores its scheduled-time argument; the
 * tests hand it a stale deadline to pin exactly that. */

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

        ASSERT_OK(dns_answer_add(answer, rr, /* ifindex= */ 1, DNS_ANSWER_CACHEABLE|DNS_ANSWER_SHARED_OWNER, /* rrsig= */ NULL));

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

/* Arm the goodbye timer the way a previous firing would have left it, with a deadline already in the
 * past. The real callback and userdata keep the source inert-but-faithful should an event loop ever run. */
static usec_t arm_stale_goodbye_timer(sd_event *event, DnsScope *scope) {
        usec_t stale_deadline;

        stale_deadline = usec_sub_unsigned(now(CLOCK_BOOTTIME), 5 * USEC_PER_SEC);
        ASSERT_OK(sd_event_add_time(event, &scope->mdns_goodbye_event_source, CLOCK_BOOTTIME,
                                    stale_deadline, /* accuracy= */ 0, mdns_goodbye_callback, scope));

        return stale_deadline;
}

/* The record is still a second from expiring, so nothing is pruned and no browser is notified either way;
 * whether another pass gets scheduled — and for when — is the whole question. */
TEST(mdns_goodbye_rearms_against_current_time) {
        /* Declared before the cleanup variables: they are released in reverse order, and
         * dns_scope_free() reaches into the manager. */
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = test_scope_new(&manager, &event);
        usec_t stale_deadline, deadline, expected_until;

        /* Cache the record, then overwrite it with the TTL=1 rewrite a goodbye leaves behind. */
        put_a(scope, "goodbye.local", 120);
        put_a(scope, "goodbye.local", 1);
        ASSERT_EQ(dns_cache_size(&scope->cache), 1u);
        /* Pin the fixture: the TTL=1 put must have taken the update path, leaving the record about a
         * second from expiry — otherwise a failure below would point at the re-arm instead of here.
         * Capturing the expiry also lets the re-arm assertion below be exact. */
        expected_until = dns_cache_next_expiry(&scope->cache);
        ASSERT_LE(expected_until, usec_add(now(CLOCK_BOOTTIME), MDNS_GOODBYE_DELAY));

        stale_deadline = arm_stale_goodbye_timer(event, scope);

        ASSERT_OK(mdns_goodbye_callback(scope->mdns_goodbye_event_source, stale_deadline, scope));

        ASSERT_EQ(dns_cache_size(&scope->cache), 1u);
        ASSERT_NOT_NULL(scope->mdns_goodbye_event_source);

        /* Not just re-armed, but armed exactly for the record's expiry: nothing between the
         * fixture assertion and the callback changes the single item's 'until', and
         * sd_event_source_get_time() returns the armed deadline verbatim. */
        ASSERT_OK(sd_event_source_get_time(scope->mdns_goodbye_event_source, &deadline));
        ASSERT_EQ(deadline, expected_until);
}

/* The complementary case: with nothing left in the cache there is nothing to wait for, so the timer has to
 * be released rather than re-armed. */
TEST(mdns_goodbye_does_not_rearm_when_cache_empty) {
        /* Declared before the cleanup variables: they are released in reverse order, and
         * dns_scope_free() reaches into the manager. */
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = test_scope_new(&manager, &event);
        usec_t stale_deadline;

        stale_deadline = arm_stale_goodbye_timer(event, scope);

        ASSERT_OK(mdns_goodbye_callback(scope->mdns_goodbye_event_source, stale_deadline, scope));

        ASSERT_NULL(scope->mdns_goodbye_event_source);
}

/* The reverse direction: a record minutes from expiring must not keep the one-second timer alive, or the
 * callback would spin once a second for the whole TTL. Unlike the empty-cache case this exercises the
 * head-of-queue comparison rather than the empty-queue shortcut. */
TEST(mdns_goodbye_does_not_rearm_for_far_expiry) {
        /* Declared before the cleanup variables: they are released in reverse order, and
         * dns_scope_free() reaches into the manager. */
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = test_scope_new(&manager, &event);
        usec_t stale_deadline;

        put_a(scope, "staying.local", 120);
        ASSERT_EQ(dns_cache_size(&scope->cache), 1u);

        stale_deadline = arm_stale_goodbye_timer(event, scope);

        ASSERT_OK(mdns_goodbye_callback(scope->mdns_goodbye_event_source, stale_deadline, scope));

        ASSERT_EQ(dns_cache_size(&scope->cache), 1u);
        ASSERT_NULL(scope->mdns_goodbye_event_source);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
