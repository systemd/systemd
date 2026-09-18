/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "dns-answer.h"
#include "dns-packet.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-server.h"
#include "resolved-dns-transaction.h"
#include "resolved-manager.h"
#include "set.h"
#include "tests.h"

typedef struct TransactionEnv {
        Manager manager;
        DnsScope *scope;
        DnsServer *server;
} TransactionEnv;

static void transaction_env_teardown(TransactionEnv *env) {
        assert(env);

        dns_scope_free(env->scope);
        if (env->server)
                dns_server_unlink(env->server);
        hashmap_free(env->manager.dns_transactions);
        sd_event_unref(env->manager.event);
}

static void transaction_env_setup(TransactionEnv *env, DnssecMode dnssec_mode) {
        union in_addr_union server_addr = { .in.s_addr = htobe32(0xc0000201) }; /* 192.0.2.1 */

        assert(env);

        env->manager = (Manager) {
                .dnssec_mode = dnssec_mode,
        };

        ASSERT_OK(sd_event_new(&env->manager.event));

        ASSERT_OK(dns_scope_new(&env->manager, &env->scope, DNS_SCOPE_GLOBAL, /* link= */ NULL, /* delegate= */ NULL, DNS_PROTOCOL_DNS, AF_INET));
        ASSERT_NOT_NULL(env->scope);
        ASSERT_EQ(env->scope->dnssec_mode, dnssec_mode);

        ASSERT_OK(dns_server_new(&env->manager, &env->server, DNS_SERVER_SYSTEM, /* link= */ NULL, /* delegate= */ NULL,
                                 AF_INET, &server_addr, 53, /* ifindex= */ 0, /* server_name= */ NULL, RESOLVE_CONFIG_SOURCE_DBUS));
        ASSERT_NOT_NULL(env->server);
}

/* Sets up a transaction as if its query had been sent at the specified feature level, and builds a matching
 * reply with a single unsigned A RR and no OPT RR. */
static void transaction_setup_sent(
                TransactionEnv *env,
                DnsServerFeatureLevel level,
                DnsTransaction **ret_transaction,
                DnsPacket **ret_reply) {

        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *reply = NULL;
        DnsTransaction *t = NULL;

        assert(env);
        assert(ret_transaction);
        assert(ret_reply);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);

        /* NO_NETWORK, so that auxiliary DNSSEC transactions fail at once instead of using the network */
        ASSERT_OK(dns_transaction_new(&t, env->scope, key, /* bypass= */ NULL, SD_RESOLVED_NO_NETWORK));
        ASSERT_NOT_NULL(t);

        /* Keep the transaction around for inspection once it completed */
        t->block_gc++;

        /* What dns_transaction_pick_server() and dns_transaction_prepare() would have done. */
        t->server = dns_server_ref(env->server);
        t->n_picked_servers = 1;
        t->current_feature_level = level;
        t->state = DNS_TRANSACTION_PENDING;
        t->n_attempts = 1;

        ASSERT_OK(dns_packet_new_query(&t->sent, DNS_PROTOCOL_DNS, 0, /* dnssec_checking_disabled= */ true));
        ASSERT_OK(dns_packet_append_key(t->sent, key, 0, NULL));
        DNS_PACKET_HEADER(t->sent)->qdcount = htobe16(1);
        DNS_PACKET_HEADER(t->sent)->id = t->id;

        rr = dns_resource_record_new(key);
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0000202); /* 192.0.2.2 */
        rr->ttl = 3600;

        question = dns_question_new(1);
        ASSERT_NOT_NULL(question);
        ASSERT_OK(dns_question_add(question, key, 0));

        answer = dns_answer_new(1);
        ASSERT_NOT_NULL(answer);
        ASSERT_OK(dns_answer_add(answer, rr, /* ifindex= */ 0, 0, /* rrsig= */ NULL));

        ASSERT_OK(dns_scope_make_reply_packet(env->scope, t->id, DNS_RCODE_SUCCESS, question, answer, /* soa= */ NULL, /* tentative= */ false, &reply));
        reply->ipproto = IPPROTO_UDP;
        reply->family = env->server->family;
        reply->sender = env->server->address;

        *ret_transaction = t;
        *ret_reply = TAKE_PTR(reply);
}

/* ================================================================
 * dns_transaction_process_reply()
 * ================================================================ */

/* Feeds an unsigned reply to a transaction sent at the TCP feature level, i.e. without EDNS0 and DO, to a
 * server degraded to that level without being marked DNSSEC-incapable, as packet loss does. */
static DnsTransaction* process_reply_no_do(TransactionEnv *env, DnssecMode dnssec_mode) {
        _cleanup_(dns_packet_unrefp) DnsPacket *reply = NULL;
        DnsTransaction *t;

        assert(env);

        transaction_env_setup(env, dnssec_mode);

        env->server->verified_feature_level = DNS_SERVER_FEATURE_LEVEL_TCP;
        env->server->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_TCP;
        ASSERT_TRUE(dns_server_dnssec_supported(env->server));

        transaction_setup_sent(env, DNS_SERVER_FEATURE_LEVEL_TCP, &t, &reply);

        dns_transaction_process_reply(t, reply, /* encrypted= */ false);

        return t;
}

TEST(dns_transaction_process_reply_no_do_allow_downgrade) {
        _cleanup_(transaction_env_teardown) TransactionEnv env = {};
        DnsTransaction *t;

        t = process_reply_no_do(&env, DNSSEC_ALLOW_DOWNGRADE);

        /* Accepted as unsigned, without auxiliary lookups, and without blaming the server */
        ASSERT_EQ(t->state, DNS_TRANSACTION_SUCCESS);
        ASSERT_EQ(t->answer_dnssec_result, DNSSEC_INCOMPATIBLE_SERVER);
        ASSERT_FALSE(FLAGS_SET(t->answer_query_flags, SD_RESOLVED_AUTHENTICATED));
        ASSERT_TRUE(set_isempty(t->dnssec_transactions));
        ASSERT_EQ(dns_answer_size(t->answer), 1u);
        ASSERT_FALSE(env.server->warned_downgrade);

        t->block_gc--;
        ASSERT_NULL(dns_transaction_gc(t));
}

TEST(dns_transaction_process_reply_no_do_strict) {
        _cleanup_(transaction_env_teardown) TransactionEnv env = {};
        DnsTransaction *t;

        t = process_reply_no_do(&env, DNSSEC_YES);

        /* Still validated, so it fails on the DS lookup this needs, not on the server */
        ASSERT_EQ(t->state, DNS_TRANSACTION_DNSSEC_FAILED);
        ASSERT_EQ(t->answer_dnssec_result, DNSSEC_FAILED_AUXILIARY);
        ASSERT_FALSE(FLAGS_SET(t->answer_query_flags, SD_RESOLVED_AUTHENTICATED));

        t->block_gc--;
        ASSERT_NULL(dns_transaction_gc(t));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
