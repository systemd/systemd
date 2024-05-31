/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-type.h"
#include "resolved-dns-rr.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-zone.h"
#include "resolved-link.h"
#include "resolved-manager.h"

#include "log.h"
#include "tests.h"

static void dns_scope_freep(DnsScope **s) {
        if (s != NULL && *s != NULL)
                dns_scope_free(*s);
}

/* ================================================================
 * dns_zone_put()
 * ================================================================ */

TEST(dns_zone_put_simple) {
        Manager manager = {};
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        DnsZone *zone = NULL;
        DnsZoneItem *item = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_scope_new(&manager, &scope, NULL, DNS_PROTOCOL_DNS, AF_INET));
        ASSERT_NOT_NULL(scope);
        zone = &scope->zone;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr);

        ASSERT_TRUE(dns_zone_is_empty(zone));

        ASSERT_OK(dns_zone_put(zone, scope, rr, 0));

        ASSERT_FALSE(dns_zone_is_empty(zone));

        item = dns_zone_get(zone, rr);
        ASSERT_NOT_NULL(item);
        ASSERT_EQ((int)item->state, DNS_ZONE_ITEM_ESTABLISHED);
}

TEST(dns_zone_put_any_class_is_invalid) {
        Manager manager = {};
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        DnsZone *zone = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        dns_scope_new(&manager, &scope, NULL, DNS_PROTOCOL_DNS, AF_INET);
        ASSERT_NOT_NULL(scope);
        zone = &scope->zone;

        rr = dns_resource_record_new_full(DNS_CLASS_ANY, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr);

        ASSERT_ERROR(dns_zone_put(zone, scope, rr, 0), EINVAL);

        ASSERT_TRUE(dns_zone_is_empty(zone));
}

TEST(dns_zone_put_any_type_is_invalid) {
        Manager manager = {};
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        DnsZone *zone = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        dns_scope_new(&manager, &scope, NULL, DNS_PROTOCOL_DNS, AF_INET);
        ASSERT_NOT_NULL(scope);
        zone = &scope->zone;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_ANY, "www.example.com");
        ASSERT_NOT_NULL(rr);

        ASSERT_ERROR(dns_zone_put(zone, scope, rr, 0), EINVAL);

        ASSERT_TRUE(dns_zone_is_empty(zone));
}

/* ================================================================
 * dns_zone_remove_rr()
 * ================================================================ */

TEST(dns_zone_remove_rr_match) {
        Manager manager = {};
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        DnsZone *zone = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr_in = NULL, *rr_out = NULL;

        dns_scope_new(&manager, &scope, NULL, DNS_PROTOCOL_DNS, AF_INET);
        ASSERT_NOT_NULL(scope);
        zone = &scope->zone;

        rr_in = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr_in);
        rr_in->a.in_addr.s_addr = htobe32(0xc0a8017f);

        ASSERT_OK(dns_zone_put(zone, scope, rr_in, 0));

        rr_out = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr_out);
        rr_out->a.in_addr.s_addr = htobe32(0xc0a8017f);

        ASSERT_NOT_NULL(dns_zone_get(zone, rr_in));
        dns_zone_remove_rr(zone, rr_out);
        ASSERT_NULL(dns_zone_get(zone, rr_in));
}

TEST(dns_zone_remove_rr_match_one) {
        Manager manager = {};
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        DnsZone *zone = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr_in = NULL, *rr_out = NULL;

        dns_scope_new(&manager, &scope, NULL, DNS_PROTOCOL_DNS, AF_INET);
        ASSERT_NOT_NULL(scope);
        zone = &scope->zone;

        rr_in = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr_in);
        rr_in->a.in_addr.s_addr = htobe32(0xc0a8017f);

        ASSERT_OK(dns_zone_put(zone, scope, rr_in, 0));
        dns_resource_record_unref(rr_in);

        rr_in = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "example.com");
        ASSERT_NOT_NULL(rr_in);
        rr_in->cname.name = strdup("www.example.com");

        ASSERT_OK(dns_zone_put(zone, scope, rr_in, 0));

        rr_out = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr_out);
        rr_out->a.in_addr.s_addr = htobe32(0xc0a8017f);

        ASSERT_NOT_NULL(dns_zone_get(zone, rr_out));
        dns_zone_remove_rr(zone, rr_out);
        ASSERT_NULL(dns_zone_get(zone, rr_out));
        ASSERT_NOT_NULL(dns_zone_get(zone, rr_in));
}

TEST(dns_zone_remove_rr_different_payload) {
        Manager manager = {};
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        DnsZone *zone = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr_in = NULL, *rr_out = NULL;

        dns_scope_new(&manager, &scope, NULL, DNS_PROTOCOL_DNS, AF_INET);
        ASSERT_NOT_NULL(scope);
        zone = &scope->zone;

        rr_in = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr_in);
        rr_in->a.in_addr.s_addr = htobe32(0xc0a8017f);

        ASSERT_OK(dns_zone_put(zone, scope, rr_in, 0));

        rr_out = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr_out);
        rr_out->a.in_addr.s_addr = htobe32(0xc0a80180);

        ASSERT_NOT_NULL(dns_zone_get(zone, rr_in));
        dns_zone_remove_rr(zone, rr_out);
        ASSERT_NOT_NULL(dns_zone_get(zone, rr_in));
}

/* ================================================================
 * dns_zone_remove_rrs_by_key()
 * ================================================================ */

TEST(dns_zone_remove_rrs_by_key) {
        Manager manager = {};
        _cleanup_(dns_scope_freep) DnsScope *scope = NULL;
        DnsZone *zone = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr1 = NULL, *rr2 = NULL, *rr3 = NULL;
        DnsResourceKey *key = NULL;

        dns_scope_new(&manager, &scope, NULL, DNS_PROTOCOL_DNS, AF_INET);
        ASSERT_NOT_NULL(scope);
        zone = &scope->zone;

        rr1 = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr1);
        dns_zone_put(zone, scope, rr1, 0);

        rr2 = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com");
        ASSERT_NOT_NULL(rr2);
        dns_zone_put(zone, scope, rr2, 0);

        rr3 = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "example.com");
        ASSERT_NOT_NULL(rr3);
        rr3->cname.name = strdup("www.example.com");
        dns_zone_put(zone, scope, rr3, 0);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_zone_remove_rrs_by_key(zone, key));
        ASSERT_NOT_NULL(dns_zone_get(zone, rr3));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_zone_remove_rrs_by_key(zone, key));
        ASSERT_NULL(dns_zone_get(zone, rr3));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_ANY, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_zone_remove_rrs_by_key(zone, key));
        ASSERT_NULL(dns_zone_get(zone, rr1));
        ASSERT_NULL(dns_zone_get(zone, rr2));
        dns_resource_key_unref(key);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
