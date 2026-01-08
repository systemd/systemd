/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if.h>

#include "sd-event.h"

#include "resolve-util.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-server.h"
#include "resolved-link.h"
#include "resolved-manager.h"
#include "tests.h"

/* ================================================================
 * String table tests for DnsServerPolicy
 * ================================================================ */

TEST(dns_server_policy_to_string) {
        ASSERT_STREQ(dns_server_policy_to_string(DNS_SERVER_POLICY_PICK_BEST), "pick-best");
        ASSERT_STREQ(dns_server_policy_to_string(DNS_SERVER_POLICY_ORDERED), "ordered");
        ASSERT_NULL(dns_server_policy_to_string(_DNS_SERVER_POLICY_MAX));
        ASSERT_NULL(dns_server_policy_to_string(_DNS_SERVER_POLICY_INVALID));
}

TEST(dns_server_policy_from_string) {
        ASSERT_EQ(dns_server_policy_from_string("pick-best"), DNS_SERVER_POLICY_PICK_BEST);
        ASSERT_EQ(dns_server_policy_from_string("ordered"), DNS_SERVER_POLICY_ORDERED);
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
        env->manager.dns_server_policy = DNS_SERVER_POLICY_PICK_BEST;

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
        env.manager.dns_server_policy = DNS_SERVER_POLICY_PICK_BEST;

        ASSERT_EQ(dns_scope_get_dns_server_policy(env.scope), DNS_SERVER_POLICY_PICK_BEST);

        /* Change manager policy to ordered */
        env.manager.dns_server_policy = DNS_SERVER_POLICY_ORDERED;
        ASSERT_EQ(dns_scope_get_dns_server_policy(env.scope), DNS_SERVER_POLICY_ORDERED);
}

TEST(dns_scope_get_dns_server_policy_link_overrides_manager) {
        _cleanup_(policy_test_env_teardown) PolicyTestEnv env = {};

        policy_test_env_setup(&env);

        /* Manager has pick-best, link has ordered - link should win */
        env.manager.dns_server_policy = DNS_SERVER_POLICY_PICK_BEST;
        env.link->dns_server_policy = DNS_SERVER_POLICY_ORDERED;

        ASSERT_EQ(dns_scope_get_dns_server_policy(env.scope), DNS_SERVER_POLICY_ORDERED);

        /* Manager has ordered, link has pick-best - link should still win */
        env.manager.dns_server_policy = DNS_SERVER_POLICY_ORDERED;
        env.link->dns_server_policy = DNS_SERVER_POLICY_PICK_BEST;

        ASSERT_EQ(dns_scope_get_dns_server_policy(env.scope), DNS_SERVER_POLICY_PICK_BEST);
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
 * Ordered policy behavioral test
 *
 * This test verifies the key difference between pick-best and ordered policies:
 * - With pick-best: dns_scope_get_dns_server() returns the "current" server
 *   (which may have been moved due to past successful lookups)
 * - With ordered: dns_scope_get_first_dns_server() always returns the first
 *   configured server, regardless of past lookup history
 *
 * In dns_transaction_pick_server(), when n_picked_servers == 0 and policy
 * is ordered, it calls dns_scope_get_first_dns_server() instead of
 * dns_scope_get_dns_server(), ensuring new transactions always start
 * with the first configured server.
 * ================================================================ */

TEST(ordered_policy_always_starts_with_first_server) {
        _cleanup_(policy_test_env_teardown) PolicyTestEnv env = {};

        policy_test_env_setup(&env);

        /* Verify initial state: both methods return server1 */
        ASSERT_PTR_EQ(dns_scope_get_first_dns_server(env.scope), env.server1);
        ASSERT_PTR_EQ(dns_scope_get_dns_server(env.scope), env.server1);

        /* Simulate past successful lookups moving current_dns_server to server2.
         * This is what happens with pick-best policy when server2 responds faster
         * or when server1 fails and we fall back to server2. */
        link_set_dns_server(env.link, env.server2);

        /* Now the key behavioral difference:
         * - dns_scope_get_dns_server() returns server2 (the "current" one)
         * - dns_scope_get_first_dns_server() still returns server1
         *
         * With ordered policy, new transactions use get_first_dns_server(),
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

TEST(ordered_policy_multiple_transactions_always_try_first) {
        _cleanup_(policy_test_env_teardown) PolicyTestEnv env = {};
        DnsServer *first_server;

        policy_test_env_setup(&env);
        env.link->dns_server_policy = DNS_SERVER_POLICY_ORDERED;

        /* Simulate multiple independent DNS transactions.
         * Each new transaction (n_picked_servers == 0) should start with server1.
         *
         * This is the core behavior that makes ordered policy work like
         * traditional resolv.conf: every new lookup tries servers in order. */

        /* Transaction 1: starts fresh */
        first_server = dns_scope_get_first_dns_server(env.scope);
        ASSERT_PTR_EQ(first_server, env.server1);
        ASSERT_EQ(first_server->address.in.s_addr, htobe32(0x0a000001));

        /* Simulate transaction 1 failing on server1 and succeeding on server2.
         * This moves current_dns_server to server2. */
        link_set_dns_server(env.link, env.server2);

        /* Transaction 2: also starts fresh (n_picked_servers == 0)
         * With ordered policy, it should still start with server1! */
        first_server = dns_scope_get_first_dns_server(env.scope);
        ASSERT_PTR_EQ(first_server, env.server1);
        ASSERT_EQ(first_server->address.in.s_addr, htobe32(0x0a000001));

        /* Transaction 3: same behavior */
        first_server = dns_scope_get_first_dns_server(env.scope);
        ASSERT_PTR_EQ(first_server, env.server1);

        /* Verify the contrast with pick-best behavior:
         * dns_scope_get_dns_server() would return server2 (the "good" one) */
        ASSERT_PTR_EQ(dns_scope_get_dns_server(env.scope), env.server2);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
