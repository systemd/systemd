/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>
#include <unistd.h>

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

/* Covers the mDNS goodbye deadline arithmetic, on both sides of it: the re-arm decision in
 * mdns_goodbye_callback() — which has to measure against a fresh clock reading, so the cases that
 * drive it hand it a stale scheduled-time argument to pin exactly that — and the deadline
 * mdns_goodbye_arm_on_receipt() picks when a goodbye lands.
 *
 * The receipt cases call mdns_goodbye_arm_on_receipt() directly: a goodbye must always leave a timer
 * behind — falling back to the far end of the window when the cache holds nothing sooner — and must not
 * push out a deadline already armed for earlier. */

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

        ASSERT_OK(dns_answer_add(answer, rr, /* ifindex= */ 1,
                                 DNS_ANSWER_CACHEABLE|DNS_ANSWER_SHARED_OWNER, /* rrsig= */ NULL));

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

/* Cache 'name', then apply the TTL=1 rewrite a goodbye leaves behind, re-applying it until the
 * recorded expiry still has more than the re-arm floor of margin left. The exact-deadline
 * assertions the callers make hold only while that expiry stays beyond MDNS_GOODBYE_MIN_INTERVAL
 * of the clock reading inside the arm -- past the floor the arm returns the floor, and past the
 * second the prune drops the record -- so a stalled runner refreshes rather than failing bogusly.
 * Bounded, because the rewrite only lands through dns_cache_put_positive()'s existing-entry
 * branch, one line ahead of its mDNS TTL<=1 bail: a rewrite that stops landing leaves the expiry
 * the full TTL out, which the far-end check below reports as the fixture's failure rather than
 * letting it surface as a wrong deadline later. Returns the expiry the last rewrite recorded. */
static usec_t put_goodbye_with_margin(DnsScope *scope, const char *name) {
        for (unsigned i = 0;; i++) {
                usec_t until;

                put_a(scope, name, 1);

                until = dns_cache_next_expiry(&scope->cache);
                if (until > usec_add(now(CLOCK_BOOTTIME),
                                     MDNS_GOODBYE_DELAY - MDNS_GOODBYE_MIN_INTERVAL)) {
                        ASSERT_LE(until, usec_add(now(CLOCK_BOOTTIME), MDNS_GOODBYE_DELAY));
                        return until;
                }

                ASSERT_LT(i, 100u);
        }
}

/* A DNS scope, not an mDNS one: dns_scope_new() joins the multicast group for the multicast protocols,
 * which asserts on a link and needs a real socket. Only the cache matters here, and the records go in with
 * mDNS semantics in put_a().
 *
 * Known limitation of that shortcut: the browser notification the callback also performs is inert in
 * these tests. mdns_browser_revisit_cache() only ever reads mDNS scopes, and the manager carries no
 * browsers anyway, so removing that call from the callback would leave every assertion below passing.
 * What is scored here is the deadline arithmetic and the timer's fate, nothing beyond. */
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
 * past. The real callback and userdata keep the source inert-but-faithful should an event loop ever run.
 *
 * The caller is handed a reference of its own: these tests call the callback directly rather than
 * through sd-event's dispatch, so the source is not marked as dispatching and the callback's
 * sd_event_source_disable_unref() would drop the last reference and free it outright — where under a
 * real dispatch the source stays alive for the rest of the handler. */
static usec_t arm_stale_goodbye_timer(sd_event *event, DnsScope *scope, sd_event_source **ret_source) {
        usec_t stale_deadline;

        assert(event);
        assert(scope);
        assert(ret_source);

        stale_deadline = usec_sub_unsigned(now(CLOCK_BOOTTIME), 5 * USEC_PER_SEC);
        ASSERT_OK(sd_event_add_time(event, &scope->mdns_goodbye_event_source, CLOCK_BOOTTIME,
                                    stale_deadline, /* accuracy= */ 0, mdns_goodbye_callback, scope));

        *ret_source = sd_event_source_ref(scope->mdns_goodbye_event_source);

        return stale_deadline;
}

/* The record is still a second from expiring, so nothing is pruned and no browser is notified either way;
 * whether another pass gets scheduled — and for when — is the whole question. */
TEST(mdns_goodbye_rearms_against_current_time) {
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *goodbye_source = NULL;
        usec_t stale_deadline, deadline, expected_until;

        scope = test_scope_new(&manager, &event);

        /* Cache the record, then overwrite it with the TTL=1 rewrite a goodbye leaves behind,
         * capturing the expiry so the re-arm assertion below can be exact. */
        put_a(scope, "goodbye.local", 120);
        expected_until = put_goodbye_with_margin(scope, "goodbye.local");
        ASSERT_EQ(dns_cache_size(&scope->cache), 1u);

        stale_deadline = arm_stale_goodbye_timer(event, scope, &goodbye_source);

        ASSERT_OK(mdns_goodbye_callback(scope->mdns_goodbye_event_source, stale_deadline, scope));

        ASSERT_EQ(dns_cache_size(&scope->cache), 1u);
        ASSERT_NOT_NULL(scope->mdns_goodbye_event_source);

        /* Not just re-armed, but armed exactly for the record's expiry: nothing between the
         * fixture assertion and the callback changes the single item's 'until', and
         * sd_event_source_get_time() returns the armed deadline verbatim. */
        ASSERT_OK(sd_event_source_get_time(scope->mdns_goodbye_event_source, &deadline));
        ASSERT_EQ(deadline, expected_until);

        /* And the chain terminates: let the event loop dispatch that re-armed source for real —
         * everything above drove the callback by hand — and the pass it runs finds the record due,
         * drops it, and releases the timer instead of arming a third one. */
        ASSERT_OK_POSITIVE(sd_event_run(event, 3 * USEC_PER_SEC));
        ASSERT_TRUE(dns_cache_is_empty(&scope->cache));
        ASSERT_NULL(scope->mdns_goodbye_event_source);
}

/* The complementary case: with nothing left in the cache there is nothing to wait for, so the timer has to
 * be released rather than re-armed. */
TEST(mdns_goodbye_does_not_rearm_when_cache_empty) {
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *goodbye_source = NULL;
        usec_t stale_deadline;

        scope = test_scope_new(&manager, &event);

        stale_deadline = arm_stale_goodbye_timer(event, scope, &goodbye_source);

        ASSERT_OK(mdns_goodbye_callback(scope->mdns_goodbye_event_source, stale_deadline, scope));

        ASSERT_NULL(scope->mdns_goodbye_event_source);
}

/* The reverse direction: a record minutes from expiring must not keep the one-second timer alive, or the
 * callback would spin once a second for the whole TTL. Unlike the empty-cache case this exercises the
 * head-of-queue comparison rather than the empty-queue shortcut. */
TEST(mdns_goodbye_does_not_rearm_for_far_expiry) {
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *goodbye_source = NULL;
        usec_t stale_deadline;

        scope = test_scope_new(&manager, &event);

        put_a(scope, "staying.local", 120);
        ASSERT_EQ(dns_cache_size(&scope->cache), 1u);

        stale_deadline = arm_stale_goodbye_timer(event, scope, &goodbye_source);

        ASSERT_OK(mdns_goodbye_callback(scope->mdns_goodbye_event_source, stale_deadline, scope));

        ASSERT_EQ(dns_cache_size(&scope->cache), 1u);
        ASSERT_NULL(scope->mdns_goodbye_event_source);
}

/* The payoff path the re-arm exists for: a record that has actually come due is dropped by the prune
 * inside the callback, and with nothing left to wait for the timer is released. The other cases each
 * stop short of that — one starts from an empty cache, the other never has anything become due. */
TEST(mdns_goodbye_prunes_due_record_and_releases_timer) {
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *goodbye_source = NULL;
        usec_t stale_deadline;

        scope = test_scope_new(&manager, &event);

        /* Cache the record, then apply the goodbye rewrite — a bare TTL=1 put would be dropped, a
         * goodbye only ever rewrites a record already held. */
        put_a(scope, "going.local", 120);
        put_a(scope, "going.local", 1);
        ASSERT_EQ(dns_cache_size(&scope->cache), 1u);

        /* Pin that the rewrite actually landed: the size alone is satisfied by the 120s put, and the
         * TTL=1 one only takes effect through dns_cache_put_positive()'s existing-entry branch, one
         * line ahead of its mDNS TTL<=1 bail. Were it to stop landing, the record would expire 120s
         * out, the sleep below would not make it due, and the failure would surface at the prune
         * assertion instead of here. */
        ASSERT_LE(dns_cache_next_expiry(&scope->cache),
                  usec_add(now(CLOCK_BOOTTIME), MDNS_GOODBYE_DELAY));

        /* Let the record come due, so the prune in the callback is what drops it. */
        sleep(2);

        stale_deadline = arm_stale_goodbye_timer(event, scope, &goodbye_source);

        ASSERT_OK(mdns_goodbye_callback(scope->mdns_goodbye_event_source, stale_deadline, scope));

        ASSERT_TRUE(dns_cache_is_empty(&scope->cache));
        ASSERT_NULL(scope->mdns_goodbye_event_source);
}

/* The receipt side. The arm here used to be a flat one-second relative timer, which meant a goodbye
 * always left one behind; deriving the deadline from the cache instead is what makes that worth
 * pinning, because the derivation reports "nothing due" for exactly the cases a goodbye most often
 * produces — a record we never held, a cache-flush goodbye that dropped its record outright, caching
 * off. Arming nothing there would leave no pass to reconcile the withdrawal at all. Hence the
 * fallback to the far end of the RFC 6762 § 10.1 window, which this pins. */
TEST(mdns_goodbye_receipt_arms_without_cached_record) {
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        usec_t deadline, before;

        scope = test_scope_new(&manager, &event);

        /* Exactly the state a cache-flush goodbye, or one for a record we never held, leaves. */
        ASSERT_TRUE(dns_cache_is_empty(&scope->cache));

        before = now(CLOCK_BOOTTIME);
        mdns_goodbye_arm_on_receipt(scope);

        ASSERT_NOT_NULL(scope->mdns_goodbye_event_source);
        ASSERT_OK(sd_event_source_get_time(scope->mdns_goodbye_event_source, &deadline));
        ASSERT_GE(deadline, usec_add(before, MDNS_GOODBYE_DELAY));
        ASSERT_LE(deadline, usec_add(now(CLOCK_BOOTTIME), MDNS_GOODBYE_DELAY));
}

/* What makes a received packet a goodbye, and the only thing that decides whether any of the above
 * ever runs: the arm had to move behind dns_cache_put() -- the expiry it reads is the one the put
 * computes -- so on_mdns_packet() carries the answer's verdict across in a flag. Nothing else here
 * would notice that flag going missing. */
TEST(mdns_answer_rewrite_goodbye_ttls) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *bye = NULL, *stays = NULL;

        answer = dns_answer_new(2);
        ASSERT_NOT_NULL(answer);

        bye = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "bye.local");
        ASSERT_NOT_NULL(bye);
        bye->a.in_addr.s_addr = htobe32(0xc0a80101);
        bye->ttl = 0;
        ASSERT_OK(dns_answer_add(answer, bye, /* ifindex= */ 1, /* flags= */ 0, /* rrsig= */ NULL));

        stays = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "stays.local");
        ASSERT_NOT_NULL(stays);
        stays->a.in_addr.s_addr = htobe32(0xc0a80102);
        stays->ttl = 120;
        ASSERT_OK(dns_answer_add(answer, stays, /* ifindex= */ 1, /* flags= */ 0, /* rrsig= */ NULL));

        ASSERT_TRUE(mdns_answer_rewrite_goodbye_ttls(answer));

        /* RFC 6762 section 10.1: cached for one more second, not dropped -- and its neighbours are
         * left alone, so a goodbye packet does not shorten whatever else it carries. */
        ASSERT_EQ(bye->ttl, 1u);
        ASSERT_EQ(stays->ttl, 120u);

        /* And the negative control: no TTL 0, no pass. */
        ASSERT_FALSE(mdns_answer_rewrite_goodbye_ttls(answer));
        ASSERT_EQ(bye->ttl, 1u);
}

/* Goodbyes arriving behind an armed timer coalesce onto it instead of pushing its deadline out: that
 * is what bounds the reconciliation a flood can ask for, now that no goodbye is ever dropped. */
TEST(mdns_goodbye_receipt_keeps_the_earlier_deadline) {
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        usec_t deadline, armed;

        scope = test_scope_new(&manager, &event);

        /* A record due inside the window arms for its own expiry, ahead of the window's far end. */
        put_a(scope, "going.local", 120);
        (void) put_goodbye_with_margin(scope, "going.local");

        mdns_goodbye_arm_on_receipt(scope);
        ASSERT_NOT_NULL(scope->mdns_goodbye_event_source);
        ASSERT_OK(sd_event_source_get_time(scope->mdns_goodbye_event_source, &armed));
        ASSERT_EQ(armed, dns_cache_next_expiry(&scope->cache));

        /* A second goodbye that wants a strictly later deadline: with the cache drained there is
         * nothing due, so on its own it would arm the far end of the window. The armed source keeps
         * its earlier deadline instead -- which is what force_reset=false buys, and what an equal
         * second deadline could not tell apart from force_reset=true. */
        dns_cache_flush(&scope->cache);
        ASSERT_EQ(dns_cache_next_expiry(&scope->cache), USEC_INFINITY);

        mdns_goodbye_arm_on_receipt(scope);
        ASSERT_OK(sd_event_source_get_time(scope->mdns_goodbye_event_source, &deadline));
        ASSERT_EQ(deadline, armed);
        ASSERT_LT(deadline, usec_add(now(CLOCK_BOOTTIME), MDNS_GOODBYE_DELAY));
}

/* The receipt path's other route to "nothing due": not an empty cache, but a cache holding only
 * records that expire beyond the RFC 6762 § 10.1 window. Without that gate the arm would take an
 * unrelated record's expiry minutes out, and since a later goodbye leaves an armed timer alone, no
 * reconciliation would happen for a full TTL. The empty-cache case below cannot catch that: it never
 * reaches the gate. */
TEST(mdns_goodbye_receipt_ignores_expiry_beyond_the_window) {
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        usec_t deadline, before;

        scope = test_scope_new(&manager, &event);

        /* Two minutes out, far past the window. */
        put_a(scope, "staying.local", 120);
        ASSERT_EQ(dns_cache_size(&scope->cache), 1u);

        before = now(CLOCK_BOOTTIME);
        mdns_goodbye_arm_on_receipt(scope);

        ASSERT_NOT_NULL(scope->mdns_goodbye_event_source);
        ASSERT_OK(sd_event_source_get_time(scope->mdns_goodbye_event_source, &deadline));

        /* Armed for the far end of the window, not for the record the cache reports. */
        ASSERT_GE(deadline, usec_add(before, MDNS_GOODBYE_DELAY));
        ASSERT_LE(deadline, usec_add(now(CLOCK_BOOTTIME), MDNS_GOODBYE_DELAY));
        ASSERT_LT(deadline, dns_cache_next_expiry(&scope->cache));
}

/* The prune in mdns_goodbye_arm_on_receipt(). Nothing else prunes this cache while no browse
 * question is live, so a record left due by an earlier goodbye is still in the prioq when the next
 * goodbye arrives. Without the prune it is the soonest "expiry" mdns_goodbye_next_deadline() finds,
 * and the floor then clamps the deadline to a quarter window -- an extra prune-and-reconcile pass
 * ahead of the one this goodbye actually needs. */
TEST(mdns_goodbye_receipt_prunes_a_stale_record) {
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        usec_t before, deadline;

        scope = test_scope_new(&manager, &event);

        /* The callback's prune fixture: cache the record, apply the goodbye rewrite, let it come
         * due. */
        put_a(scope, "gone.local", 120);
        put_a(scope, "gone.local", 1);
        ASSERT_EQ(dns_cache_size(&scope->cache), 1u);

        /* And pin the rewrite the way the sibling case does: the size above is satisfied by the
         * 120s put alone, so without this a rewrite that stopped landing would leave the record
         * 120s out, the sleep would make nothing due, and the failure would read as the receipt
         * path's prune regressing rather than as the fixture. */
        ASSERT_LE(dns_cache_next_expiry(&scope->cache),
                  usec_add(now(CLOCK_BOOTTIME), MDNS_GOODBYE_DELAY));

        sleep(2);

        before = now(CLOCK_BOOTTIME);
        mdns_goodbye_arm_on_receipt(scope);

        ASSERT_TRUE(dns_cache_is_empty(&scope->cache));
        ASSERT_NOT_NULL(scope->mdns_goodbye_event_source);
        ASSERT_OK(sd_event_source_get_time(scope->mdns_goodbye_event_source, &deadline));

        /* The far end of the window, which is where an empty cache arms. A deadline a quarter
         * window out is exactly what the stale entry would have produced, so this discriminates. */
        ASSERT_GE(deadline, usec_add(before, MDNS_GOODBYE_DELAY));
        ASSERT_LE(deadline, usec_add(now(CLOCK_BOOTTIME), MDNS_GOODBYE_DELAY));
}

/* The re-arm floor: the only thing here that can delay a removal, and the newest line in the fix.
 * Arming at the exact next expiry is what makes a removal land on time, but nothing else bounds the
 * rate -- goodbyes for records expiring microseconds apart would chain a prune-and-reconcile pass
 * each, and sd-event does not coalesce them (process_timer() marks a source pending on its deadline
 * alone, and a flood keeps the loop awake regardless). So the floor trades a bounded overshoot for a
 * bounded rate, and this pins that it actually wins over a nearer expiry. */
TEST(mdns_goodbye_rearm_is_floored) {
        Manager manager = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *goodbye_source = NULL;
        usec_t stale_deadline, deadline, before, after;

        scope = test_scope_new(&manager, &event);

        /* Drive the cache into the state the floor exists for: a goodbye'd record still pending, but
         * due sooner than the floor. Its expiry is one second from the put, so wait until under a
         * quarter window is left. Re-put and retry rather than assuming the wait lands there, since a
         * stalled runner could sleep past the expiry entirely. */
        for (unsigned i = 0;; i++) {
                usec_t expiry, t, wait;

                put_a(scope, "soon.local", 120);
                put_a(scope, "soon.local", 1);

                /* Sleep to the middle of the floor's window rather than for a fixed duration. The
                 * band below is measured against the record's expiry, so deriving the wait from the
                 * cache self-corrects for however slow the runner is; a fixed sleep leaves the
                 * margin to be eaten by the put and the sleep's own overshoot, and a runner slow
                 * enough to miss the band once misses it the same way on every retry. */
                expiry = dns_cache_next_expiry(&scope->cache);
                t = now(CLOCK_BOOTTIME);
                wait = expiry > usec_add(t, MDNS_GOODBYE_MIN_INTERVAL / 2) ?
                        expiry - t - MDNS_GOODBYE_MIN_INTERVAL / 2 : 0;
                usleep_safe(wait);

                expiry = dns_cache_next_expiry(&scope->cache);
                t = now(CLOCK_BOOTTIME);

                /* Bounded from both sides: inside the floor, so the floor is what decides the
                 * re-arm, but with enough left that the callback's own prune does not drop the
                 * record first -- an overshooting sleep would otherwise fail this on the cache
                 * size rather than on the floor. */
                if (expiry > usec_add(t, MDNS_GOODBYE_MIN_INTERVAL / 4) &&
                    expiry < usec_add(t, MDNS_GOODBYE_MIN_INTERVAL))
                        break;

                /* A derived wait lands in the band on the first pass unless the runner stalled
                 * mid-sleep, so a handful of retries is plenty -- and keeps a genuine failure well
                 * inside the 30s meson default rather than spending it on retries. */
                ASSERT_LT(i, 8u);
        }

        stale_deadline = arm_stale_goodbye_timer(event, scope, &goodbye_source);

        /* Bracket the callback's own clock reading, so the deadline can be pinned to the floor's
         * value rather than merely to "later than the expiry" -- the latter would also hold for a
         * coarser divisor, or for an implementation that ignored the expiry altogether. */
        before = now(CLOCK_BOOTTIME);
        ASSERT_OK(mdns_goodbye_callback(scope->mdns_goodbye_event_source, stale_deadline, scope));
        after = now(CLOCK_BOOTTIME);

        /* Nothing was due, so the record is still there and the timer re-armed. */
        ASSERT_EQ(dns_cache_size(&scope->cache), 1u);
        ASSERT_NOT_NULL(scope->mdns_goodbye_event_source);
        ASSERT_OK(sd_event_source_get_time(scope->mdns_goodbye_event_source, &deadline));

        /* Exactly one floor away from a clock reading taken inside those two samples, and past the
         * expiry the cache reports -- i.e. the floor decided this, not the expiry. */
        ASSERT_GE(deadline, usec_add(before, MDNS_GOODBYE_MIN_INTERVAL));
        ASSERT_LE(deadline, usec_add(after, MDNS_GOODBYE_MIN_INTERVAL));
        ASSERT_GT(deadline, dns_cache_next_expiry(&scope->cache));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
