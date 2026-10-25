/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "dns-answer.h"
#include "dns-packet.h"
#include "dns-rr.h"
#include "hashmap.h"
#include "resolved-dns-cache.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-zone.h"
#include "resolved-manager.h"
#include "tests.h"

typedef struct ScopeEnv {
        Manager manager;
        DnsScope scope;
} ScopeEnv;

static void scope_env_setup(ScopeEnv *env, DnsProtocol protocol) {
        assert(env);

        *env = (ScopeEnv) {
                .manager.enable_cache = DNS_CACHE_MODE_YES,
        };

        ASSERT_OK(sd_event_new(&env->manager.event));

        /* Not created via dns_scope_new(), as multicast scopes require a link and would join the multicast
         * groups on real sockets. Only what dns_scope_check_conflicts() needs is set up here. */
        env->scope = (DnsScope) {
                .manager = &env->manager,
                .protocol = protocol,
                .family = AF_INET,
                .cache.cache_max = DEFAULT_CACHE_MAX,
        };
}

static void scope_env_teardown(ScopeEnv *env) {
        assert(env);

        /* The conflict queue holds references on its keys and records, drop them like
         * on_conflict_dispatch() does. */
        for (;;) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                key = ordered_hashmap_first_key(env->scope.conflict_queue);
                if (!key)
                        break;

                rr = ordered_hashmap_remove(env->scope.conflict_queue, key);
                ASSERT_NOT_NULL(rr);
        }

        ordered_hashmap_free(env->scope.conflict_queue);
        sd_event_source_disable_unref(env->scope.conflict_event_source);
        dns_cache_flush(&env->scope.cache);
        dns_zone_flush(&env->scope.zone);
        sd_event_unref(env->manager.event);
}

static DnsResourceRecord* a_rr(const char *name, uint32_t addr) {
        DnsResourceRecord *rr;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, name);
        ASSERT_NOT_NULL(rr);
        rr->ttl = 120;
        rr->a.in_addr.s_addr = htobe32(addr);

        return rr;
}

static void cache_put_from(DnsScope *scope, DnsResourceRecord *rr, const union in_addr_union *owner) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;

        answer = dns_answer_new(1);
        ASSERT_NOT_NULL(answer);
        ASSERT_OK(dns_answer_add(answer, rr, /* ifindex= */ 0, DNS_ANSWER_CACHEABLE, /* rrsig= */ NULL));

        ASSERT_OK(dns_cache_put(&scope->cache, DNS_CACHE_MODE_YES, scope->protocol, rr->key,
                                DNS_RCODE_SUCCESS, answer, /* full_packet= */ NULL, /* query_flags= */ 0,
                                DNSSEC_UNSIGNED, /* nsec_ttl= */ UINT32_MAX, AF_INET, owner,
                                /* stale_retention_usec= */ 0));
}

/* Builds a reply carrying the specified record, as received from the specified sender. */
static DnsPacket* make_reply(DnsProtocol protocol, DnsResourceRecord *rr, const union in_addr_union *sender) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;

        ASSERT_OK(dns_packet_new(&p, protocol, /* min_alloc_dsize= */ 0, DNS_PACKET_SIZE_MAX));

        /* mDNS replies are authoritative, LLMNR replies must not carry the "C" bit (which is the AA bit) */
        DNS_PACKET_HEADER(p)->flags = htobe16(DNS_PACKET_MAKE_FLAGS(
                                                              1 /* qr */,
                                                              0 /* opcode */,
                                                              protocol == DNS_PROTOCOL_MDNS /* aa */,
                                                              0 /* tc */,
                                                              0 /* rd */,
                                                              0 /* ra */,
                                                              0 /* ad */,
                                                              0 /* cd */,
                                                              DNS_RCODE_SUCCESS));
        ASSERT_OK(dns_packet_append_rr(p, rr, /* flags= */ 0, /* start= */ NULL, /* rdata_start= */ NULL));
        DNS_PACKET_HEADER(p)->ancount = htobe16(1);

        p->family = AF_INET;
        p->sender = *sender;

        return TAKE_PTR(p);
}

/* ================================================================
 * dns_scope_check_conflicts()
 * ================================================================ */

/* Two responders answer for the same name with different data: the first answer is cached, the second
 * one is checked for conflicts against it. */
static void check_conflicts_between_two_responders(ScopeEnv *env) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *cached = NULL, *received = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        union in_addr_union first = { .in.s_addr = htobe32(0xc0000201) },  /* 192.0.2.1 */
                            second = { .in.s_addr = htobe32(0xc0000202) }; /* 192.0.2.2 */

        assert(env);

        cached = a_rr("host.local", 0xc0000264);   /* 192.0.2.100 */
        received = a_rr("host.local", 0xc0000265); /* 192.0.2.101 */

        cache_put_from(&env->scope, cached, &first);
        ASSERT_EQ(dns_cache_size(&env->scope.cache), 1u);
        ASSERT_TRUE(dns_cache_check_conflicts(&env->scope.cache, received, AF_INET, &second));

        p = make_reply(env->scope.protocol, received, &second);
        dns_scope_check_conflicts(&env->scope, p);
}

TEST(dns_scope_check_conflicts_llmnr_sends_advisory) {
        _cleanup_(scope_env_teardown) ScopeEnv env = {};

        scope_env_setup(&env, DNS_PROTOCOL_LLMNR);
        check_conflicts_between_two_responders(&env);

        /* LLMNR announces the conflict with a query that has the "C" bit set */
        ASSERT_EQ(ordered_hashmap_size(env.scope.conflict_queue), 1u);
        ASSERT_NOT_NULL(env.scope.conflict_event_source);
}

TEST(dns_scope_check_conflicts_mdns_no_advisory) {
        _cleanup_(scope_env_teardown) ScopeEnv env = {};

        scope_env_setup(&env, DNS_PROTOCOL_MDNS);
        check_conflicts_between_two_responders(&env);

        /* mDNS has no such advisory, differing answers from several responders are not our business */
        ASSERT_TRUE(ordered_hashmap_isempty(env.scope.conflict_queue));
        ASSERT_NULL(env.scope.conflict_event_source);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
