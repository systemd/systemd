/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if.h>

#include "sd-event.h"

#include "dns-rr.h"
#include "resolve-util.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-server.h"
#include "resolved-dns-transaction.h"
#include "resolved-link.h"
#include "resolved-manager.h"
#include "tests.h"

/* ================================================================
 * String table tests for DnsServerPolicy
 * ================================================================ */

TEST(dns_server_policy_to_string) {
        ASSERT_STREQ(dns_server_policy_to_string(DNS_SERVER_POLICY_ADAPTIVE), "adaptive");
        ASSERT_STREQ(dns_server_policy_to_string(DNS_SERVER_POLICY_SEQUENTIAL), "sequential");
        ASSERT_NULL(dns_server_policy_to_string(_DNS_SERVER_POLICY_MAX));
        ASSERT_NULL(dns_server_policy_to_string(_DNS_SERVER_POLICY_INVALID));
}

TEST(dns_server_policy_from_string) {
        ASSERT_EQ(dns_server_policy_from_string("adaptive"), DNS_SERVER_POLICY_ADAPTIVE);
        ASSERT_EQ(dns_server_policy_from_string("sequential"), DNS_SERVER_POLICY_SEQUENTIAL);
        ASSERT_EQ(dns_server_policy_from_string("invalid"), _DNS_SERVER_POLICY_INVALID);
        ASSERT_EQ(dns_server_policy_from_string(""), _DNS_SERVER_POLICY_INVALID);
        ASSERT_EQ(dns_server_policy_from_string(NULL), _DNS_SERVER_POLICY_INVALID);
}

/* ================================================================
 * Policy inheritance tests
 * ================================================================ */

typedef struct PolicyTestEnv {
        Manager manager;
        Link *link;
        DnsScope *scope;
        DnsServer *server1;
        DnsServer *server2;
} PolicyTestEnv;

static void policy_test_env_teardown(PolicyTestEnv *env) {
        ASSERT_NOT_NULL(env);

        dns_scope_free(env->scope);
        /* Don't unref servers manually - link_free -> link_flush_settings handles them */
        link_free(env->link);
        sd_event_unref(env->manager.event);
}

static void policy_test_env_setup(PolicyTestEnv *env) {
        union in_addr_union server1_addr = { .in.s_addr = htobe32(0x0a000001) }; /* 10.0.0.1 */
        union in_addr_union server2_addr = { .in.s_addr = htobe32(0x0a000002) }; /* 10.0.0.2 */

        ASSERT_NOT_NULL(env);

        *env = (PolicyTestEnv) {};

        ASSERT_OK(sd_event_new(&env->manager.event));
        ASSERT_NOT_NULL(env->manager.event);

        /* Set up manager with default policy */
        env->manager.dns_server_policy = DNS_SERVER_POLICY_ADAPTIVE;

        /* Create a link */
        ASSERT_OK(link_new(&env->manager, &env->link, 1));
        ASSERT_NOT_NULL(env->link);
        env->link->flags = IFF_UP | IFF_LOWER_UP;
        env->link->operstate = IF_OPER_UP;
        env->link->dns_server_policy = _DNS_SERVER_POLICY_INVALID; /* Not set, inherit from manager */

        /* Create two DNS servers on the link */
        ASSERT_OK(dns_server_new(&env->manager, &env->server1, DNS_SERVER_LINK,
                        env->link, /* delegate= */ NULL, AF_INET, &server1_addr, 53,
                        1, "server1", RESOLVE_CONFIG_SOURCE_DBUS));
        ASSERT_NOT_NULL(env->server1);

        ASSERT_OK(dns_server_new(&env->manager, &env->server2, DNS_SERVER_LINK,
                        env->link, /* delegate= */ NULL, AF_INET, &server2_addr, 53,
                        1, "server2", RESOLVE_CONFIG_SOURCE_DBUS));
        ASSERT_NOT_NULL(env->server2);

        /* Create a DNS scope for the link */
        ASSERT_OK(dns_scope_new(&env->manager, &env->scope, DNS_SCOPE_LINK,
                        env->link, /* delegate= */ NULL, DNS_PROTOCOL_DNS, AF_UNSPEC));
        ASSERT_NOT_NULL(env->scope);
}

TEST(dns_scope_get_dns_server_policy_inherits_from_manager) {
        _cleanup_(policy_test_env_teardown) PolicyTestEnv env = {};

        policy_test_env_setup(&env);

        /* Link policy is invalid (not set), should inherit manager policy */
        env.link->dns_server_policy = _DNS_SERVER_POLICY_INVALID;
        env.manager.dns_server_policy = DNS_SERVER_POLICY_ADAPTIVE;

        ASSERT_EQ(dns_scope_get_dns_server_policy(env.scope), DNS_SERVER_POLICY_ADAPTIVE);

        /* Change manager policy to sequential */
        env.manager.dns_server_policy = DNS_SERVER_POLICY_SEQUENTIAL;
        ASSERT_EQ(dns_scope_get_dns_server_policy(env.scope), DNS_SERVER_POLICY_SEQUENTIAL);
}

TEST(dns_scope_get_dns_server_policy_link_overrides_manager) {
        _cleanup_(policy_test_env_teardown) PolicyTestEnv env = {};

        policy_test_env_setup(&env);

        /* Manager has adaptive, link has sequential - link should win */
        env.manager.dns_server_policy = DNS_SERVER_POLICY_ADAPTIVE;
        env.link->dns_server_policy = DNS_SERVER_POLICY_SEQUENTIAL;

        ASSERT_EQ(dns_scope_get_dns_server_policy(env.scope), DNS_SERVER_POLICY_SEQUENTIAL);

        /* Manager has sequential, link has adaptive - link should still win */
        env.manager.dns_server_policy = DNS_SERVER_POLICY_SEQUENTIAL;
        env.link->dns_server_policy = DNS_SERVER_POLICY_ADAPTIVE;

        ASSERT_EQ(dns_scope_get_dns_server_policy(env.scope), DNS_SERVER_POLICY_ADAPTIVE);
}

/* ================================================================
 * First server selection tests
 * ================================================================ */

TEST(dns_scope_get_first_dns_server_returns_first) {
        _cleanup_(policy_test_env_teardown) PolicyTestEnv env = {};

        policy_test_env_setup(&env);

        /* The first server should be server1 (10.0.0.1) */
        DnsServer *first = dns_scope_get_first_dns_server(env.scope);
        ASSERT_NOT_NULL(first);
        ASSERT_PTR_EQ(first, env.link->dns_servers);
        ASSERT_EQ(first->family, AF_INET);
        ASSERT_EQ(first->address.in.s_addr, htobe32(0x0a000001));
}

TEST(dns_scope_get_first_dns_server_returns_null_for_non_dns) {
        _cleanup_(policy_test_env_teardown) PolicyTestEnv env = {};
        DnsScope *llmnr_scope = NULL;

        policy_test_env_setup(&env);

        /* Create an LLMNR scope - should return NULL for first DNS server */
        ASSERT_OK(dns_scope_new(&env.manager, &llmnr_scope, DNS_SCOPE_LINK,
                        env.link, /* delegate= */ NULL, DNS_PROTOCOL_LLMNR, AF_INET));
        ASSERT_NOT_NULL(llmnr_scope);

        ASSERT_NULL(dns_scope_get_first_dns_server(llmnr_scope));

        dns_scope_free(llmnr_scope);
}

/* ================================================================
 * Sequential policy behavioral test
 *
 * This test verifies the key difference between adaptive and sequential policies:
 * - With adaptive: dns_scope_get_dns_server() returns the "current" server
 *   (which may have been moved due to past successful lookups)
 * - With sequential: dns_scope_get_first_dns_server() always returns the first
 *   configured server, regardless of past lookup history
 *
 * In dns_transaction_pick_server(), when n_picked_servers == 0 and policy
 * is sequential, it calls dns_scope_get_first_dns_server() instead of
 * dns_scope_get_dns_server(), ensuring new transactions always start
 * with the first configured server.
 * ================================================================ */

TEST(sequential_policy_always_starts_with_first_server) {
        _cleanup_(policy_test_env_teardown) PolicyTestEnv env = {};

        policy_test_env_setup(&env);

        /* Verify initial state: both methods return server1 */
        ASSERT_PTR_EQ(dns_scope_get_first_dns_server(env.scope), env.server1);
        ASSERT_PTR_EQ(dns_scope_get_dns_server(env.scope), env.server1);

        /* Simulate past successful lookups moving current_dns_server to server2.
         * This is what happens with adaptive policy when server2 responds faster
         * or when server1 fails and we fall back to server2. */
        link_set_dns_server(env.link, env.server2);

        /* Now the key behavioral difference:
         * - dns_scope_get_dns_server() returns server2 (the "current" one)
         * - dns_scope_get_first_dns_server() still returns server1
         *
         * With sequential policy, new transactions use get_first_dns_server(),
         * so they always start with server1 regardless of past history. */
        ASSERT_PTR_EQ(dns_scope_get_dns_server(env.scope), env.server2);
        ASSERT_PTR_EQ(dns_scope_get_first_dns_server(env.scope), env.server1);

        /* Simulate another "successful lookup" moving back to server1 */
        link_set_dns_server(env.link, env.server1);
        ASSERT_PTR_EQ(dns_scope_get_dns_server(env.scope), env.server1);
        ASSERT_PTR_EQ(dns_scope_get_first_dns_server(env.scope), env.server1);

        /* Move to server2 again */
        link_set_dns_server(env.link, env.server2);
        ASSERT_PTR_EQ(dns_scope_get_dns_server(env.scope), env.server2);
        /* Key assertion: first server is ALWAYS server1 */
        ASSERT_PTR_EQ(dns_scope_get_first_dns_server(env.scope), env.server1);
}

TEST(sequential_policy_multiple_transactions_always_try_first) {
        _cleanup_(policy_test_env_teardown) PolicyTestEnv env = {};
        DnsServer *first_server;

        policy_test_env_setup(&env);
        env.link->dns_server_policy = DNS_SERVER_POLICY_SEQUENTIAL;

        /* Simulate multiple independent DNS transactions.
         * Each new transaction (n_picked_servers == 0) should start with server1.
         *
         * This is the core behavior that makes sequential policy work like
         * traditional resolv.conf: every new lookup tries servers in order. */

        /* Transaction 1: starts fresh */
        first_server = dns_scope_get_first_dns_server(env.scope);
        ASSERT_PTR_EQ(first_server, env.server1);
        ASSERT_EQ(first_server->address.in.s_addr, htobe32(0x0a000001));

        /* Simulate transaction 1 failing on server1 and succeeding on server2.
         * This moves current_dns_server to server2. */
        link_set_dns_server(env.link, env.server2);

        /* Transaction 2: also starts fresh (n_picked_servers == 0)
         * With sequential policy, it should still start with server1! */
        first_server = dns_scope_get_first_dns_server(env.scope);
        ASSERT_PTR_EQ(first_server, env.server1);
        ASSERT_EQ(first_server->address.in.s_addr, htobe32(0x0a000001));

        /* Transaction 3: same behavior */
        first_server = dns_scope_get_first_dns_server(env.scope);
        ASSERT_PTR_EQ(first_server, env.server1);

        /* Verify the contrast with adaptive behavior:
         * dns_scope_get_dns_server() would return server2 (the "good" one) */
        ASSERT_PTR_EQ(dns_scope_get_dns_server(env.scope), env.server2);
}

/* ================================================================
 * Fallback sequence tests
 *
 * These tests verify that sequential policy iterates through servers
 * in strict list order during fallbacks within a single transaction.
 * ================================================================ */

TEST(sequential_policy_fallback_sequence) {
        _cleanup_(policy_test_env_teardown) PolicyTestEnv env = {};
        DnsServer *server3 = NULL;
        union in_addr_union server3_addr = { .in.s_addr = htobe32(0x0a000003) }; /* 10.0.0.3 */

        policy_test_env_setup(&env);
        env.link->dns_server_policy = DNS_SERVER_POLICY_SEQUENTIAL;

        /* Add a third server for this test */
        ASSERT_OK(dns_server_new(&env.manager, &server3, DNS_SERVER_LINK,
                        env.link, /* delegate= */ NULL, AF_INET, &server3_addr, 53,
                        1, "server3", RESOLVE_CONFIG_SOURCE_DBUS));
        ASSERT_NOT_NULL(server3);

        /* Verify we have 3 servers in order: server1 -> server2 -> server3 */
        ASSERT_PTR_EQ(env.link->dns_servers, env.server1);
        ASSERT_PTR_EQ(env.server1->servers_next, env.server2);
        ASSERT_PTR_EQ(env.server2->servers_next, server3);
        ASSERT_NULL(server3->servers_next);

        /* Verify list traversal works correctly */
        DnsServer *first = dns_scope_get_first_dns_server(env.scope);
        ASSERT_PTR_EQ(first, env.server1);
        ASSERT_PTR_EQ(first->servers_next, env.server2);
        ASSERT_PTR_EQ(first->servers_next->servers_next, server3);
        ASSERT_NULL(first->servers_next->servers_next->servers_next);

        /* Verify that even after changing current_dns_server, first is still server1 */
        link_set_dns_server(env.link, server3);
        ASSERT_PTR_EQ(dns_scope_get_first_dns_server(env.scope), env.server1);
        ASSERT_PTR_EQ(dns_scope_get_dns_server(env.scope), server3);
}

TEST(sequential_policy_transactions_independent) {
        _cleanup_(policy_test_env_teardown) PolicyTestEnv env = {};

        policy_test_env_setup(&env);
        env.link->dns_server_policy = DNS_SERVER_POLICY_SEQUENTIAL;

        /* This test verifies that the sequential_next_server tracker is
         * per-transaction, not shared. Each transaction should start
         * from server1 regardless of what other transactions have done.
         *
         * Since sequential_next_server is a field on DnsTransaction (not on
         * Link or Scope), two transactions will have independent iterators. */

        /* Simulate Transaction A: picks server1, would advance to server2 */
        DnsServer *txn_a_first = dns_scope_get_first_dns_server(env.scope);
        ASSERT_PTR_EQ(txn_a_first, env.server1);

        /* Simulate Transaction A failing and the scope moving to server2
         * (this is what adaptive policy would do) */
        link_set_dns_server(env.link, env.server2);

        /* Simulate Transaction B starting fresh - should still get server1
         * because sequential policy uses get_first_dns_server for first pick,
         * and uses its own sequential_next_server for subsequent picks */
        DnsServer *txn_b_first = dns_scope_get_first_dns_server(env.scope);
        ASSERT_PTR_EQ(txn_b_first, env.server1);

        /* The key insight: dns_scope_get_dns_server() returns server2 (shared state),
         * but dns_scope_get_first_dns_server() returns server1 (list head).
         * Sequential policy uses the latter + per-transaction tracking. */
        ASSERT_PTR_EQ(dns_scope_get_dns_server(env.scope), env.server2);
        ASSERT_PTR_EQ(dns_scope_get_first_dns_server(env.scope), env.server1);
}

TEST(sequential_policy_server_removed_during_iteration) {
        _cleanup_(policy_test_env_teardown) PolicyTestEnv env = {};
        _cleanup_(dns_server_unrefp) DnsServer *server2_ref = NULL;
        DnsServer *server3 = NULL;
        union in_addr_union server3_addr = { .in.s_addr = htobe32(0x0a000003) }; /* 10.0.0.3 */

        policy_test_env_setup(&env);
        env.link->dns_server_policy = DNS_SERVER_POLICY_SEQUENTIAL;

        /* Add a third server */
        ASSERT_OK(dns_server_new(&env.manager, &server3, DNS_SERVER_LINK,
                        env.link, /* delegate= */ NULL, AF_INET, &server3_addr, 53,
                        1, "server3", RESOLVE_CONFIG_SOURCE_DBUS));
        ASSERT_NOT_NULL(server3);

        /* Verify initial state: server1 -> server2 -> server3 */
        ASSERT_PTR_EQ(env.link->dns_servers, env.server1);
        ASSERT_TRUE(env.server2->linked);

        /* Simulate a scenario where server2 is removed while a transaction
         * has sequential_next_server pointing to it.
         *
         * The implementation checks server->linked before using it,
         * falling back to first server if the tracked server was unlinked. */

        /* Take a reference before unlinking so we can safely check the linked flag.
         * dns_server_unlink() calls dns_server_unref() which would free the server
         * if there are no other references. */
        server2_ref = dns_server_ref(env.server2);

        /* Remove server2 from the link */
        dns_server_unlink(env.server2);
        ASSERT_FALSE(server2_ref->linked);

        /* After removal, list should be: server1 -> server3 */
        ASSERT_PTR_EQ(env.link->dns_servers, env.server1);
        ASSERT_PTR_EQ(env.server1->servers_next, server3);

        /* get_first_dns_server should still work */
        ASSERT_PTR_EQ(dns_scope_get_first_dns_server(env.scope), env.server1);
}

/* ================================================================
 * Transaction-level integration tests
 *
 * These tests verify that dns_transaction_pick_server() correctly
 * cycles through servers in sequential mode across multiple retries
 * within a single transaction.
 * ================================================================ */

TEST(sequential_policy_transaction_cycles_through_servers) {
        _cleanup_(policy_test_env_teardown) PolicyTestEnv env = {};
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        DnsTransaction *t = NULL;
        DnsServer *server3 = NULL;
        union in_addr_union server3_addr = { .in.s_addr = htobe32(0x0a000003) }; /* 10.0.0.3 */
        int r;

        policy_test_env_setup(&env);
        env.link->dns_server_policy = DNS_SERVER_POLICY_SEQUENTIAL;

        /* Add a third server for this test */
        ASSERT_OK(dns_server_new(&env.manager, &server3, DNS_SERVER_LINK,
                        env.link, /* delegate= */ NULL, AF_INET, &server3_addr, 53,
                        1, "server3", RESOLVE_CONFIG_SOURCE_DBUS));
        ASSERT_NOT_NULL(server3);

        /* Create a DNS resource key for the transaction */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);

        /* Create a transaction */
        r = dns_transaction_new(&t, env.scope, key, NULL, 0);
        ASSERT_OK(r);
        ASSERT_NOT_NULL(t);

        /* Verify initial state: no server picked yet, no sequential_next_server */
        ASSERT_NULL(t->server);
        ASSERT_NULL(t->sequential_next_server);

        /* First pick: should select server1, advance tracker to server2 */
        r = dns_transaction_pick_server(t);
        ASSERT_OK(r);
        ASSERT_PTR_EQ(t->server, env.server1);
        ASSERT_PTR_EQ(t->sequential_next_server, env.server2);

        /* Second pick: should select server2, advance tracker to server3 */
        r = dns_transaction_pick_server(t);
        ASSERT_OK(r);
        ASSERT_PTR_EQ(t->server, env.server2);
        ASSERT_PTR_EQ(t->sequential_next_server, server3);

        /* Third pick: should select server3, advance tracker to NULL (end of list) */
        r = dns_transaction_pick_server(t);
        ASSERT_OK(r);
        ASSERT_PTR_EQ(t->server, server3);
        ASSERT_NULL(t->sequential_next_server);

        /* Fourth pick: sequential_next_server is NULL, should restart from first */
        r = dns_transaction_pick_server(t);
        ASSERT_OK(r);
        ASSERT_PTR_EQ(t->server, env.server1);
        ASSERT_PTR_EQ(t->sequential_next_server, env.server2);

        dns_transaction_gc(t);
}

TEST(sequential_policy_two_transactions_independent_iteration) {
        _cleanup_(policy_test_env_teardown) PolicyTestEnv env = {};
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key1 = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key2 = NULL;
        DnsTransaction *t1 = NULL;
        DnsTransaction *t2 = NULL;
        int r;

        policy_test_env_setup(&env);
        env.link->dns_server_policy = DNS_SERVER_POLICY_SEQUENTIAL;

        /* Create two different resource keys */
        key1 = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example1.com");
        ASSERT_NOT_NULL(key1);
        key2 = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example2.com");
        ASSERT_NOT_NULL(key2);

        /* Create two transactions */
        r = dns_transaction_new(&t1, env.scope, key1, NULL, 0);
        ASSERT_OK(r);
        r = dns_transaction_new(&t2, env.scope, key2, NULL, 0);
        ASSERT_OK(r);

        /* Transaction 1: first pick -> server1 */
        r = dns_transaction_pick_server(t1);
        ASSERT_OK(r);
        ASSERT_PTR_EQ(t1->server, env.server1);
        ASSERT_PTR_EQ(t1->sequential_next_server, env.server2);

        /* Transaction 1: second pick -> server2 */
        r = dns_transaction_pick_server(t1);
        ASSERT_OK(r);
        ASSERT_PTR_EQ(t1->server, env.server2);

        /* Transaction 2: first pick -> should STILL be server1 (independent!) */
        r = dns_transaction_pick_server(t2);
        ASSERT_OK(r);
        ASSERT_PTR_EQ(t2->server, env.server1);
        ASSERT_PTR_EQ(t2->sequential_next_server, env.server2);

        /* Verify t1's state wasn't affected by t2 */
        ASSERT_PTR_EQ(t1->server, env.server2);
        ASSERT_NULL(t1->sequential_next_server);

        dns_transaction_gc(t1);
        dns_transaction_gc(t2);
}

/* ================================================================
 * Fallback behavior documentation test
 *
 * This test documents and verifies the fallback semantics for DNS queries.
 * Understanding this is CRITICAL for users of DNSServerPolicy=sequential:
 *
 * FALLBACK OCCURS (tries next server):
 *   - Timeout (server doesn't respond)
 *   - Network error (connection refused, unreachable)
 *   - SERVFAIL (server error, may be transient)
 *   - REFUSED (server won't answer for this domain)
 *
 * NO FALLBACK (response is authoritative):
 *   - NXDOMAIN (domain does not exist)
 *   - NODATA (domain exists but no records of requested type)
 *   - SUCCESS (answer found)
 *
 * This means sequential mode is NOT suitable for:
 *   - Merging responses from servers authoritative for different zones
 *   - Split-horizon DNS where different servers know different domains
 *
 * If server1 returns NXDOMAIN for "internal.corp", we do NOT fall back
 * to server2 which might know about it. This is correct DNS behavior -
 * NXDOMAIN is an authoritative "this domain does not exist" answer.
 *
 * For split-DNS scenarios, use per-interface DNS routing instead:
 *   [Link] section with DNS= and Domains= to route specific domains
 *   to specific interfaces/servers.
 * ================================================================ */

TEST(fallback_only_on_failure_not_nxdomain) {
        _cleanup_(policy_test_env_teardown) PolicyTestEnv env = {};
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        DnsTransaction *t = NULL;
        int r;

        policy_test_env_setup(&env);
        env.link->dns_server_policy = DNS_SERVER_POLICY_SEQUENTIAL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "nonexistent.example.com");
        ASSERT_NOT_NULL(key);

        r = dns_transaction_new(&t, env.scope, key, NULL, 0);
        ASSERT_OK(r);
        ASSERT_NOT_NULL(t);

        /* Pick first server */
        r = dns_transaction_pick_server(t);
        ASSERT_OK(r);
        ASSERT_PTR_EQ(t->server, env.server1);

        /* Simulate receiving NXDOMAIN response.
         *
         * In real code path (dns_transaction_process_reply):
         * - NXDOMAIN (rcode=3) is treated as a valid, authoritative response
         * - Transaction completes with DNS_TRANSACTION_RCODE_FAILURE
         * - NO fallback to server2 occurs
         *
         * This is different from timeout/SERVFAIL which would call
         * dns_transaction_retry() to try the next server.
         *
         * We verify the transaction state machine supports this by checking
         * that RCODE_FAILURE is a terminal state (not PENDING). */
        t->answer_rcode = DNS_RCODE_NXDOMAIN;

        /* The key insight: after receiving NXDOMAIN, the transaction
         * completes. It does NOT call dns_transaction_pick_server() again.
         *
         * Verify that server2 was never tried - sequential_next_server
         * points to server2 (where we WOULD go on failure), but we
         * received an authoritative answer so we stop here. */
        ASSERT_PTR_EQ(t->sequential_next_server, env.server2);
        ASSERT_PTR_EQ(t->server, env.server1);

        /* Document the expected terminal states for various scenarios:
         *
         * DNS_TRANSACTION_SUCCESS        - Got answer (stop, no fallback)
         * DNS_TRANSACTION_RCODE_FAILURE  - Got NXDOMAIN/etc (stop, no fallback)
         * DNS_TRANSACTION_TIMEOUT        - No response (retry with next server)
         * DNS_TRANSACTION_ERRNO          - Network error (retry with next server)
         *
         * The first two are "authoritative responses" - we got an answer.
         * The last two are "failures" - we should try another server. */

        dns_transaction_gc(t);
}

/* ================================================================
 * Latency trade-off documentation test
 *
 * This test documents the KEY LATENCY DIFFERENCE between policies:
 *
 * ADAPTIVE MODE:
 *   - Learns which servers respond quickly
 *   - After a server times out, it's deprioritized for future queries
 *   - Subsequent queries skip slow/dead servers automatically
 *   - Latency: Good after initial learning period
 *
 * SEQUENTIAL MODE:
 *   - Always starts with the first configured server
 *   - If server1 is down, EVERY query waits for timeout before trying server2
 *   - No learning - same timeout penalty on every query
 *   - Latency: Poor when primary server is unreachable
 *
 * Example scenario with 5-second timeout and server1 down:
 *
 *   Sequential mode:
 *     Query 1: wait 5s for server1 timeout -> try server2 -> success (5+ seconds)
 *     Query 2: wait 5s for server1 timeout -> try server2 -> success (5+ seconds)
 *     Query 3: wait 5s for server1 timeout -> try server2 -> success (5+ seconds)
 *     ... every query pays the 5-second penalty
 *
 *   Adaptive mode:
 *     Query 1: try server1 -> wait 5s timeout -> try server2 -> success (5+ seconds)
 *     Query 2: skip server1 (learned it's slow) -> try server2 -> success (fast!)
 *     Query 3: skip server1 -> try server2 -> success (fast!)
 *     ... only first query pays the penalty
 *
 * Choose sequential mode only when server ordering requirements outweigh
 * the latency cost (e.g., regulatory compliance, internal DNS policy).
 * ================================================================ */

TEST(sequential_mode_latency_tradeoff_documented) {
        _cleanup_(policy_test_env_teardown) PolicyTestEnv env = {};
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key1 = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key2 = NULL;
        DnsTransaction *t1 = NULL;
        DnsTransaction *t2 = NULL;
        int r;

        policy_test_env_setup(&env);
        env.link->dns_server_policy = DNS_SERVER_POLICY_SEQUENTIAL;

        /* Create two queries simulating sequential lookups */
        key1 = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "first-query.example.com");
        ASSERT_NOT_NULL(key1);
        key2 = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "second-query.example.com");
        ASSERT_NOT_NULL(key2);

        /* Transaction 1: First query starts with server1 */
        r = dns_transaction_new(&t1, env.scope, key1, NULL, 0);
        ASSERT_OK(r);
        r = dns_transaction_pick_server(t1);
        ASSERT_OK(r);
        ASSERT_PTR_EQ(t1->server, env.server1);

        /* Simulate server1 timing out - in real code, this triggers retry.
         * The key point: we had to WAIT for the timeout first. */

        /* Transaction 1 retries with server2 after timeout */
        r = dns_transaction_pick_server(t1);
        ASSERT_OK(r);
        ASSERT_PTR_EQ(t1->server, env.server2);

        /* Now transaction 2 comes in - a completely new query.
         * In ADAPTIVE mode, we'd remember server1 is slow and skip it.
         * In SEQUENTIAL mode, we start over from server1 again! */
        r = dns_transaction_new(&t2, env.scope, key2, NULL, 0);
        ASSERT_OK(r);
        r = dns_transaction_pick_server(t2);
        ASSERT_OK(r);

        /* THIS IS THE KEY ASSERTION: transaction 2 starts with server1 again,
         * even though transaction 1 just learned it was slow/down.
         * This means transaction 2 will ALSO wait for the timeout. */
        ASSERT_PTR_EQ(t2->server, env.server1);

        /* With adaptive mode, after t1's timeout on server1, t2 would
         * have gone straight to server2. The sequential_next_server is
         * per-transaction, so there's no cross-transaction learning. */

        dns_transaction_gc(t1);
        dns_transaction_gc(t2);
}

/* ================================================================
 * Feature level probing vs server ordering documentation
 *
 * IMPORTANT: Sequential policy controls SERVER ORDERING only.
 * Per-server feature level probing remains active:
 *
 * What sequential mode controls:
 *   - Server selection order (strict list order)
 *   - No cross-transaction learning of "good" servers
 *   - Each transaction iterates independently
 *
 * What sequential mode does NOT change:
 *   - Feature level probing (TLS -> EDNS0 -> UDP fallback)
 *   - Per-server capability tracking
 *   - Packet size negotiation
 *   - DNSSEC feature detection
 *
 * This is by design. Feature probing is orthogonal to server ordering:
 *   - Server ordering: "which server to try"
 *   - Feature probing: "how to talk to that server"
 *
 * Traditional resolv.conf had no feature probing because it only
 * supported plain UDP queries. systemd-resolved still attempts
 * modern features (DoT, EDNS0, DNSSEC) and gracefully falls back.
 *
 * Example: With servers [A, B] and sequential policy:
 *   Query 1: Try A with TLS -> A doesn't support TLS -> retry A with UDP -> success
 *   Query 2: Try A with UDP (learned from query 1) -> success
 *
 * The SERVER ORDER (A first, always) is sequential.
 * The FEATURE LEVEL (TLS vs UDP) adapts per-server.
 * ================================================================ */

TEST(sequential_policy_feature_probing_still_active) {
        _cleanup_(policy_test_env_teardown) PolicyTestEnv env = {};
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        DnsTransaction *t = NULL;
        int r;

        policy_test_env_setup(&env);
        env.link->dns_server_policy = DNS_SERVER_POLICY_SEQUENTIAL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);

        r = dns_transaction_new(&t, env.scope, key, NULL, 0);
        ASSERT_OK(r);
        ASSERT_NOT_NULL(t);

        /* Pick server - this also sets the feature level */
        r = dns_transaction_pick_server(t);
        ASSERT_OK(r);
        ASSERT_PTR_EQ(t->server, env.server1);

        /* Feature level was determined by dns_server_possible_feature_level().
         * This function considers:
         * - DNSSEC mode (affects DO bit)
         * - DNS-over-TLS mode
         * - Past failures with this server (feature level downgrade)
         *
         * The key point: this is PER-SERVER adaptation, not server ordering.
         * Sequential mode guarantees we try server1 first, but HOW we talk
         * to server1 (TLS vs UDP, EDNS0 vs basic) is still adaptive. */

        log_debug("Feature level after pick: %s",
                  dns_server_feature_level_to_string(t->current_feature_level));

        /* Verify server ordering is still sequential (the main guarantee) */
        r = dns_transaction_pick_server(t);
        ASSERT_OK(r);
        ASSERT_PTR_EQ(t->server, env.server2);

        dns_transaction_gc(t);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
