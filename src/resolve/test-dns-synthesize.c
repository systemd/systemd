/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>

#include "sd-netlink.h"

#include "dns-answer.h"
#include "dns-packet.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "in-addr-util.h"
#include "netlink-util.h"
#include "resolved-dns-synthesize.h"
#include "resolved-manager.h"
#include "strv.h"
#include "sysctl-util.h"
#include "tests.h"

/* ================================================================
 * dns_synthesize_family(), dns_synthesize_protocol()
 * ================================================================ */

TEST(dns_synthesize_family_and_protocol) {
        int flags;

        flags = SD_RESOLVED_FLAGS_MAKE(DNS_PROTOCOL_DNS, AF_INET, false, false);
        ASSERT_EQ(dns_synthesize_family(flags), AF_UNSPEC);
        ASSERT_EQ(dns_synthesize_protocol(flags), DNS_PROTOCOL_DNS);

        flags = SD_RESOLVED_FLAGS_MAKE(DNS_PROTOCOL_LLMNR, AF_INET6, false, false);
        ASSERT_EQ(dns_synthesize_family(flags), AF_INET6);
        ASSERT_EQ(dns_synthesize_protocol(flags), DNS_PROTOCOL_LLMNR);

        flags = SD_RESOLVED_FLAGS_MAKE(DNS_PROTOCOL_MDNS, AF_INET, false, false);
        ASSERT_EQ(dns_synthesize_family(flags), AF_INET);
        ASSERT_EQ(dns_synthesize_protocol(flags), DNS_PROTOCOL_MDNS);
}

/* ================================================================
 * dns_synthesize_answer()
 * ================================================================ */

TEST(dns_synthesize_answer_empty) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;

        question = dns_question_new(1);
        ASSERT_NOT_NULL(question);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);

        ASSERT_OK(dns_question_add(question, key, 0));

        answer = dns_answer_new(0);
        ASSERT_NOT_NULL(answer);

        ASSERT_FALSE(dns_synthesize_answer(&manager, question, 0, /* allow_link_local= */ true, &answer));
        ASSERT_TRUE(dns_answer_isempty(answer));
}

TEST(dns_synthesize_answer_reverse) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;

        question = dns_question_new(1);
        ASSERT_NOT_NULL(question);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "127.0.0.0.in-addr.arpa");
        ASSERT_NOT_NULL(key);

        ASSERT_OK(dns_question_add(question, key, 0));

        answer = dns_answer_new(0);
        ASSERT_NOT_NULL(answer);

        ASSERT_ERROR(dns_synthesize_answer(&manager, question, 0, /* allow_link_local= */ true, &answer),
                     ENXIO);
        ASSERT_TRUE(dns_answer_isempty(answer));
}

TEST(dns_synthesize_answer_localhost) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        question = dns_question_new(1);
        ASSERT_NOT_NULL(question);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "localhost");
        ASSERT_NOT_NULL(key);

        ASSERT_OK(dns_question_add(question, key, 0));

        ASSERT_TRUE(dns_synthesize_answer(&manager, question, 0, /* allow_link_local= */ true, &answer));

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "localhost");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0x7f000001);

        ASSERT_TRUE(dns_answer_contains(answer, rr));
}

TEST(dns_synthesize_answer_own_hostname) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        question = dns_question_new(1);
        ASSERT_NOT_NULL(question);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "resolver.local");
        ASSERT_NOT_NULL(key);

        ASSERT_OK(dns_question_add(question, key, 0));

        manager.full_hostname = (char *)"resolver.local";

        ASSERT_TRUE(dns_synthesize_answer(&manager, question, 0, /* allow_link_local= */ true, &answer));

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "resolver.local");
        ASSERT_NOT_NULL(rr);

        ASSERT_TRUE(dns_answer_match_key(answer, rr->key, NULL));
}

TEST(dns_synthesize_answer_stub) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        question = dns_question_new(1);
        ASSERT_NOT_NULL(question);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "_localdnsstub");
        ASSERT_NOT_NULL(key);

        ASSERT_OK(dns_question_add(question, key, 0));

        ASSERT_TRUE(dns_synthesize_answer(&manager, question, 0, /* allow_link_local= */ true, &answer));

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "_localdnsstub");
        ASSERT_NOT_NULL(rr);

        ASSERT_TRUE(dns_answer_match_key(answer, rr->key, NULL));
}

TEST(dns_synthesize_answer_localhost_ptr) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        question = dns_question_new(1);
        ASSERT_NOT_NULL(question);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "1.0.0.127.in-addr.arpa");
        ASSERT_NOT_NULL(key);

        ASSERT_OK(dns_question_add(question, key, 0));

        ASSERT_TRUE(dns_synthesize_answer(&manager, question, 0, /* allow_link_local= */ true, &answer));

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "1.0.0.127.in-addr.arpa");
        ASSERT_NOT_NULL(rr);

        rr->ptr.name = strdup("localhost");
        ASSERT_NOT_NULL(rr->ptr.name);
        ASSERT_TRUE(dns_answer_contains(answer, rr));
}

TEST(dns_synthesize_answer_address) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;

        question = dns_question_new(1);
        ASSERT_NOT_NULL(question);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "0.1.254.169.in-addr.arpa");
        ASSERT_NOT_NULL(key);

        ASSERT_OK(dns_question_add(question, key, 0));

        manager.full_hostname = (char *)"resolver.local";
        manager.llmnr_hostname = (char *)"llmnr.resolver.local";
        manager.mdns_hostname = (char *)"mdns.resolver.local";

        answer = dns_answer_new(0);
        ASSERT_NOT_NULL(answer);

        ASSERT_FALSE(dns_synthesize_answer(&manager, question, 0, /* allow_link_local= */ true, &answer));
        ASSERT_TRUE(dns_answer_isempty(answer));
}

TEST(dns_synthesize_answer_address_local_hostname) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsResourceRecord *rr = NULL;

        question = dns_question_new(1);
        ASSERT_NOT_NULL(question);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "2.0.0.127.in-addr.arpa");
        ASSERT_NOT_NULL(key);

        ASSERT_OK(dns_question_add(question, key, 0));

        manager.full_hostname = (char *)"resolver.local";
        manager.llmnr_hostname = (char *)"llmnr.resolver.local";
        manager.mdns_hostname = (char *)"mdns.resolver.local";

        ASSERT_TRUE(dns_synthesize_answer(&manager, question, 0, /* allow_link_local= */ true, &answer));

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "2.0.0.127.in-addr.arpa");
        ASSERT_NOT_NULL(rr);
        rr->ptr.name = strdup("resolver.local");
        ASSERT_NOT_NULL(rr->ptr.name);
        ASSERT_TRUE(dns_answer_contains(answer, rr));
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "2.0.0.127.in-addr.arpa");
        ASSERT_NOT_NULL(rr);
        rr->ptr.name = strdup("llmnr.resolver.local");
        ASSERT_NOT_NULL(rr->ptr.name);
        ASSERT_TRUE(dns_answer_contains(answer, rr));
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "2.0.0.127.in-addr.arpa");
        ASSERT_NOT_NULL(rr);
        rr->ptr.name = strdup("mdns.resolver.local");
        ASSERT_NOT_NULL(rr->ptr.name);
        ASSERT_TRUE(dns_answer_contains(answer, rr));
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "2.0.0.127.in-addr.arpa");
        ASSERT_NOT_NULL(rr);
        rr->ptr.name = strdup("localhost");
        ASSERT_NOT_NULL(rr->ptr.name);
        ASSERT_TRUE(dns_answer_contains(answer, rr));
        dns_resource_record_unref(rr);
}

TEST(dns_synthesize_answer_address_local_dns_stub) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        question = dns_question_new(1);
        ASSERT_NOT_NULL(question);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "53.0.0.127.in-addr.arpa");
        ASSERT_NOT_NULL(key);

        ASSERT_OK(dns_question_add(question, key, 0));

        manager.full_hostname = (char *)"resolver.local";
        manager.llmnr_hostname = (char *)"llmnr.resolver.local";
        manager.mdns_hostname = (char *)"mdns.resolver.local";

        ASSERT_TRUE(dns_synthesize_answer(&manager, question, 0, /* allow_link_local= */ true, &answer));

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "53.0.0.127.in-addr.arpa");
        ASSERT_NOT_NULL(rr);
        rr->ptr.name = strdup("_localdnsstub");
        ASSERT_NOT_NULL(rr->ptr.name);
        ASSERT_TRUE(dns_answer_contains(answer, rr));
}

TEST(dns_synthesize_answer_address_local_dns_proxy) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        question = dns_question_new(1);
        ASSERT_NOT_NULL(question);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "54.0.0.127.in-addr.arpa");
        ASSERT_NOT_NULL(key);

        ASSERT_OK(dns_question_add(question, key, 0));

        manager.full_hostname = (char *)"resolver.local";
        manager.llmnr_hostname = (char *)"llmnr.resolver.local";
        manager.mdns_hostname = (char *)"mdns.resolver.local";

        ASSERT_TRUE(dns_synthesize_answer(&manager, question, 0, /* allow_link_local= */ true, &answer));

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "54.0.0.127.in-addr.arpa");
        ASSERT_NOT_NULL(rr);
        rr->ptr.name = strdup("_localdnsproxy");
        ASSERT_NOT_NULL(rr->ptr.name);
        ASSERT_TRUE(dns_answer_contains(answer, rr));
}

static bool rr_is_link_local(const DnsResourceRecord *rr) {
        assert(rr);

        switch (rr->key->type) {
        case DNS_TYPE_A:
                return in4_addr_is_link_local(&rr->a.in_addr);
        case DNS_TYPE_AAAA:
                return in6_addr_is_link_local(&rr->aaaa.in6_addr);
        default:
                return false;
        }
}

static void check_link_local_omitted(Manager *m, int ifindex, const char *name, int family) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *with = NULL, *without = NULL;
        DnsResourceRecord *rr;
        int r;

        ASSERT_OK(dns_question_new_address(&question, family, name, /* convert_idna= */ false));

        r = dns_synthesize_answer(m, question, ifindex, /* allow_link_local= */ true, &with);
        ASSERT_EQ(dns_synthesize_answer(m, question, ifindex, /* allow_link_local= */ false, &without), r);

        /* Without link-local addresses, we get the same answer minus the link-local addresses. */
        DNS_ANSWER_FOREACH(rr, with)
                ASSERT_EQ(dns_answer_contains(without, rr), !rr_is_link_local(rr));
        DNS_ANSWER_FOREACH(rr, without)
                ASSERT_TRUE(dns_answer_contains(with, rr));
}

TEST(dns_synthesize_answer_link_local) {
        Manager manager = {
                .full_hostname = (char *) "resolver.local",
        };
        int family;

        FOREACH_STRING(name, "resolver.local", "_gateway", "_outbound")
                FOREACH_ARGUMENT(family, AF_INET, AF_INET6, AF_UNSPEC)
                        check_link_local_omitted(&manager, /* ifindex= */ 0, name, family);
}

static void check_answer(
                Manager *m,
                int ifindex,
                const char *name,
                int family,
                bool allow_link_local,
                const char *address,
                bool only) {

        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        union in_addr_union u;

        ASSERT_OK(dns_question_new_address(&question, family, name, /* convert_idna= */ false));
        ASSERT_OK_POSITIVE(dns_synthesize_answer(m, question, ifindex, allow_link_local, &answer));

        if (!address) {
                /* NODATA */
                ASSERT_TRUE(dns_answer_isempty(answer));
                return;
        }

        ASSERT_OK(in_addr_from_string(family, address, &u));
        ASSERT_OK(dns_resource_record_new_address(&rr, family, &u, name));
        ASSERT_TRUE(dns_answer_contains(answer, rr));
        if (only)
                ASSERT_EQ(dns_answer_size(answer), 1u);
}

/* With link-local addresses allowed, the answer must include 'with_link_local'. Without, it must consist of
 * exactly 'without_link_local', or be empty (NODATA) if that is NULL. */
static void check_answers(
                Manager *m,
                int ifindex,
                const char *name,
                int family,
                const char *with_link_local,
                const char *without_link_local) {

        check_answer(m, ifindex, name, family, /* allow_link_local= */ true, with_link_local,
                     /* only= */ false);
        check_answer(m, ifindex, name, family, /* allow_link_local= */ false, without_link_local,
                     /* only= */ true);
}

static void update_address(
                sd_netlink *rtnl,
                uint16_t type,
                int ifindex,
                int family,
                const char *address,
                unsigned char prefixlen) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;
        union in_addr_union u;
        unsigned char scope;

        ASSERT_OK(in_addr_from_string(family, address, &u));
        scope = in_addr_is_link_local(family, &u) > 0 ? RT_SCOPE_LINK : RT_SCOPE_UNIVERSE;

        if (type == RTM_NEWADDR)
                ASSERT_OK(sd_rtnl_message_new_addr_update(rtnl, &message, ifindex, family));
        else
                ASSERT_OK(sd_rtnl_message_new_addr(rtnl, &message, type, ifindex, family));
        ASSERT_OK(sd_rtnl_message_addr_set_prefixlen(message, prefixlen));
        ASSERT_OK(sd_rtnl_message_addr_set_scope(message, scope));
        ASSERT_OK(netlink_message_append_in_addr_union(message, IFA_LOCAL, family, &u));
        if (family == AF_INET6)
                ASSERT_OK(sd_netlink_message_append_u32(message, IFA_FLAGS, IFA_F_NODAD));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
}

TEST(dns_synthesize_answer_link_local_with_dummy) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL, *reply = NULL;
        Manager manager = {
                .full_hostname = (char *) "resolver.local",
        };
        union in_addr_union u;
        int r, ifindex, family;

        ASSERT_OK(sd_netlink_open(&rtnl));

        /* Create a dummy interface */
        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_NEWLINK, 0));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_IFNAME, "test-dns-synth"));
        ASSERT_OK(sd_netlink_message_open_container(message, IFLA_LINKINFO));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_INFO_KIND, "dummy"));
        r = sd_netlink_call(rtnl, message, 0, NULL);
        if (r == -EPERM)
                return (void) log_tests_skipped("missing required capabilities");
        if (r == -EOPNOTSUPP)
                return (void) log_tests_skipped("dummy network interface is not supported");
        ASSERT_OK(r);
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_GETLINK, 0));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_IFNAME, "test-dns-synth"));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, &reply));
        ASSERT_OK(sd_rtnl_message_link_get_ifindex(reply, &ifindex));
        ASSERT_GT(ifindex, 0);
        message = sd_netlink_message_unref(message);
        reply = sd_netlink_message_unref(reply);

        ASSERT_OK(sysctl_write_ip_property_boolean(AF_INET6, "test-dns-synth", "disable_ipv6", false,
                                                   /* shadow= */ NULL));

        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_SETLINK, ifindex));
        ASSERT_OK(sd_rtnl_message_link_set_flags(message, IFF_UP, IFF_UP));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        update_address(rtnl, RTM_NEWADDR, ifindex, AF_INET, "192.0.2.1", 24);
        update_address(rtnl, RTM_NEWADDR, ifindex, AF_INET, "169.254.1.1", 16);
        update_address(rtnl, RTM_NEWADDR, ifindex, AF_INET6, "2001:db8::1", 64);
        update_address(rtnl, RTM_NEWADDR, ifindex, AF_INET6, "fe80::1", 64);

        /* Add an IPv6 default gateway with a link-local address, as is common with router advertisements */
        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET6, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 1234));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(in_addr_from_string(AF_INET6, "fe80::fe", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, RTA_GATEWAY, &u.in6));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, ifindex));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        FOREACH_STRING(name, "resolver.local", "_gateway", "_outbound")
                FOREACH_ARGUMENT(family, AF_INET, AF_INET6, AF_UNSPEC)
                        check_link_local_omitted(&manager, ifindex, name, family);

        check_answers(&manager, ifindex, "resolver.local", AF_INET, "169.254.1.1", "192.0.2.1");
        check_answers(&manager, ifindex, "resolver.local", AF_INET6, "fe80::1", "2001:db8::1");
        check_answers(&manager, ifindex, "_gateway", AF_INET6, "fe80::fe", NULL);

        /* With only link-local addresses left, we get NODATA rather than the loopback fallback. */
        update_address(rtnl, RTM_DELADDR, ifindex, AF_INET, "192.0.2.1", 24);
        update_address(rtnl, RTM_DELADDR, ifindex, AF_INET6, "2001:db8::1", 64);

        check_answers(&manager, ifindex, "resolver.local", AF_INET, "169.254.1.1", NULL);
        check_answers(&manager, ifindex, "resolver.local", AF_INET6, "fe80::1", NULL);

        /* Cleanup */
        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_DELLINK, ifindex));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
