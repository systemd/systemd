/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>
#include <sys/uio.h>

#include "sd-event.h"

#include "bitmap.h"
#include "dns-answer.h"
#include "dns-packet.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "fd-util.h"
#include "hashmap.h"
#include "resolved-dns-cache.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-transaction.h"
#include "resolved-dns-zone.h"
#include "resolved-link.h"
#include "resolved-llmnr.h"
#include "resolved-manager.h"
#include "tests.h"

typedef struct ScopeEnv {
        Manager manager;
        DnsScope scope;
        Link link;
        int sockets[2];
} ScopeEnv;

/* Wrap the libc boundary: LTO can resolve calls to the internal manager_send() before linker wrapping. */
/* NOLINTNEXTLINE(misc-use-internal-linkage) */
_public_ ssize_t __wrap_sendmsg(int fd, const struct msghdr *message, int flags);
/* glibc redirects sendmsg() to __sendmsg64() on 32-bit systems with 64-bit time_t. */
/* NOLINTNEXTLINE(misc-use-internal-linkage) */
_public_ ssize_t __wrap___sendmsg64(int fd, const struct msghdr *message, int flags);

ssize_t __wrap_sendmsg(int fd, const struct msghdr *message, int flags) {
        const struct sockaddr_in *destination;

        assert(message);

        destination = message->msg_name;

        ASSERT_NOT_NULL(destination);
        ASSERT_EQ(destination->sin_family, AF_INET);
        ASSERT_EQ(be16toh(destination->sin_port), LLMNR_PORT);
        ASSERT_EQ(message->msg_iovlen, (typeof(message->msg_iovlen)) 1);

        /* Preserve the datagram bytes, but deliver them only to the local socketpair. */
        return send(fd, message->msg_iov[0].iov_base, message->msg_iov[0].iov_len, flags);
}

ssize_t __wrap___sendmsg64(int fd, const struct msghdr *message, int flags) {
        return __wrap_sendmsg(fd, message, flags);
}

static void scope_env_setup(ScopeEnv *env, DnsProtocol protocol) {
        assert(env);

        *env = (ScopeEnv) {
                .manager.enable_cache = DNS_CACHE_MODE_YES,
                .sockets = EBADF_PAIR,
        };

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0, env->sockets));
        env->manager.llmnr_ipv4_udp_fd = env->sockets[0];
        env->manager.mdns_ipv4_fd = env->sockets[0];
        ASSERT_OK(sd_event_new(&env->manager.event));
        env->link = (Link) { .manager = &env->manager, .ifindex = 1 };

        /* Not created via dns_scope_new(), as multicast scopes require a link and would join the multicast
         * groups on real sockets. Only what dns_scope_check_conflicts() needs is set up here. */
        env->scope = (DnsScope) {
                .manager = &env->manager,
                .link = &env->link,
                .protocol = protocol,
                .family = AF_INET,
                .cache.cache_max = DEFAULT_CACHE_MAX,
        };
}

static void scope_env_teardown(ScopeEnv *env) {
        assert(env);

        ordered_hashmap_free(env->scope.conflict_queue);
        sd_event_source_disable_unref(env->scope.conflict_event_source);
        dns_cache_flush(&env->scope.cache);
        dns_zone_flush(&env->scope.zone);
        while (env->scope.transactions)
                dns_transaction_free(env->scope.transactions);
        hashmap_free(env->scope.transactions_by_key);
        hashmap_free(env->manager.dns_transactions);
        safe_close_pair(env->sockets);
        sd_event_unref(env->manager.event);
}

static void assert_no_packet(ScopeEnv *env) {
        uint8_t byte;

        assert(env);

        ASSERT_ERROR_ERRNO(recv(env->sockets[1], &byte, sizeof(byte), MSG_DONTWAIT), EAGAIN);
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

        assert(sender);

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
        ASSERT_OK_POSITIVE(dns_cache_check_conflicts(&env->scope.cache, received, AF_INET, &second));

        p = make_reply(env->scope.protocol, received, &second);
        dns_scope_check_conflicts(&env->scope, p);
}

TEST(dns_scope_check_conflicts_llmnr_sends_advisory) {
        _cleanup_(scope_env_teardown) ScopeEnv env = {};
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *expected = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *sent = NULL;

        scope_env_setup(&env, DNS_PROTOCOL_LLMNR);
        check_conflicts_between_two_responders(&env);

        /* LLMNR announces the conflict with a query that has the "C" bit set */
        ASSERT_EQ(ordered_hashmap_size(env.scope.conflict_queue), 1u);
        ASSERT_NOT_NULL(env.scope.conflict_event_source);

        ASSERT_OK(sd_event_source_set_time(env.scope.conflict_event_source, 0));
        ASSERT_OK_POSITIVE(sd_event_run(env.manager.event, 0));
        ASSERT_OK(dns_packet_new(&sent, DNS_PROTOCOL_LLMNR, DNS_PACKET_SIZE_MAX, DNS_PACKET_SIZE_MAX));
        ssize_t n = ASSERT_OK_ERRNO(recv(env.sockets[1], DNS_PACKET_DATA(sent), sent->allocated, MSG_DONTWAIT));
        ASSERT_GE(n, (ssize_t) DNS_PACKET_HEADER_SIZE);
        sent->size = (size_t) n;
        assert_no_packet(&env);
        ASSERT_EQ(DNS_PACKET_QR(sent), 0);
        ASSERT_EQ(DNS_PACKET_LLMNR_C(sent), 1);
        ASSERT_EQ(DNS_PACKET_QDCOUNT(sent), 1);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(sent), 0);
        ASSERT_EQ(DNS_PACKET_NSCOUNT(sent), 0);
        ASSERT_EQ(DNS_PACKET_ARCOUNT(sent), 1);
        ASSERT_OK(dns_packet_extract(sent));
        expected = a_rr("host.local", 0xc0000265);
        ASSERT_EQ(dns_question_size(sent->question), 1u);
        ASSERT_OK_POSITIVE(dns_question_contains_key(sent->question, expected->key));
        ASSERT_EQ(dns_answer_size(sent->answer), 1u);
        ASSERT_TRUE(dns_answer_contains(sent->answer, expected));
        ASSERT_TRUE(ordered_hashmap_isempty(env.scope.conflict_queue));
        ASSERT_NULL(env.scope.conflict_event_source);
}

TEST(dns_scope_check_conflicts_mdns_no_advisory) {
        _cleanup_(scope_env_teardown) ScopeEnv env = {};

        scope_env_setup(&env, DNS_PROTOCOL_MDNS);
        check_conflicts_between_two_responders(&env);

        /* mDNS has no such advisory, differing answers from several responders are not our business */
        ASSERT_TRUE(ordered_hashmap_isempty(env.scope.conflict_queue));
        ASSERT_NULL(env.scope.conflict_event_source);
        ASSERT_OK(sd_event_run(env.manager.event, 0));
        assert_no_packet(&env);
}

TEST(dns_scope_check_conflicts_mdns_nsec_no_advisory) {
        _cleanup_(scope_env_teardown) ScopeEnv env = {};
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *cached = NULL, *received = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        union in_addr_union first = { .in.s_addr = htobe32(0xc0000201) },
                            second = { .in.s_addr = htobe32(0xc0000202) };

        scope_env_setup(&env, DNS_PROTOCOL_MDNS);
        cached = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NSEC, "host.local");
        ASSERT_NOT_NULL(cached);
        cached->ttl = 120;
        cached->nsec.next_domain_name = strdup("host.local");
        ASSERT_NOT_NULL(cached->nsec.next_domain_name);
        cached->nsec.types = bitmap_new();
        ASSERT_NOT_NULL(cached->nsec.types);
        ASSERT_OK(bitmap_set(cached->nsec.types, DNS_TYPE_AAAA));

        received = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NSEC, "host.local");
        ASSERT_NOT_NULL(received);
        received->ttl = 120;
        received->nsec.next_domain_name = strdup("host.local");
        ASSERT_NOT_NULL(received->nsec.next_domain_name);
        received->nsec.types = bitmap_new();
        ASSERT_NOT_NULL(received->nsec.types);
        ASSERT_OK(bitmap_set(received->nsec.types, DNS_TYPE_AAAA));
        ASSERT_OK(bitmap_set(received->nsec.types, DNS_TYPE_A));

        cache_put_from(&env.scope, cached, &first);
        ASSERT_OK_POSITIVE(dns_cache_check_conflicts(&env.scope.cache, received, AF_INET, &second));
        p = make_reply(DNS_PROTOCOL_MDNS, received, &second);
        dns_scope_check_conflicts(&env.scope, p);
        ASSERT_TRUE(ordered_hashmap_isempty(env.scope.conflict_queue));
        ASSERT_NULL(env.scope.conflict_event_source);
        ASSERT_OK(sd_event_run(env.manager.event, 0));
        assert_no_packet(&env);
}

TEST(dns_scope_check_conflicts_mdns_own_record) {
        _cleanup_(scope_env_teardown) ScopeEnv env = {};
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *own = NULL, *received = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        union in_addr_union sender = { .in.s_addr = htobe32(0xc0000202) };
        DnsTransaction *t;
        DnsZoneItem *item;

        scope_env_setup(&env, DNS_PROTOCOL_MDNS);
        own = a_rr("host.local", 0xc0000264);
        received = a_rr("host.local", 0xc0000265);
        ASSERT_OK(dns_zone_put(&env.scope.zone, &env.scope, own, /* probe= */ false));
        item = dns_zone_get(&env.scope.zone, own);
        ASSERT_NOT_NULL(item);
        ASSERT_EQ((int) item->state, DNS_ZONE_ITEM_ESTABLISHED);

        /* Reuse a pending probe so verification does not need real sockets or multicast membership. */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_ANY, "host.local");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_transaction_new(&t, &env.scope, key, /* bypass= */ NULL,
                                      SD_RESOLVED_NO_CACHE|SD_RESOLVED_NO_ZONE));
        t->state = DNS_TRANSACTION_PENDING;

        p = make_reply(DNS_PROTOCOL_MDNS, own, &sender);
        dns_scope_check_conflicts(&env.scope, p);
        ASSERT_EQ((int) item->state, DNS_ZONE_ITEM_ESTABLISHED);
        ASSERT_NULL(item->probe_transaction);

        p = dns_packet_unref(p);
        p = make_reply(DNS_PROTOCOL_MDNS, received, &sender);
        dns_scope_check_conflicts(&env.scope, p);
        ASSERT_EQ((int) item->state, DNS_ZONE_ITEM_VERIFYING);
        ASSERT_PTR_EQ(item->probe_transaction, t);
        ASSERT_TRUE(t->probing);
        ASSERT_TRUE(ordered_hashmap_isempty(env.scope.conflict_queue));
        ASSERT_NULL(env.scope.conflict_event_source);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
