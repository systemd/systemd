/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-domain.h"
#include "dns-packet.h"
#include "hashmap.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-zone.h"
#include "resolved-dnssd.h"
#include "resolved-manager.h"
#include "tests.h"

static DnssdRegisteredService* add_service(Manager *manager, const char *id, ResolveConfigSource source) {
        DnssdRegisteredService *service;

        service = new0(DnssdRegisteredService, 1);
        ASSERT_NOT_NULL(service);

        service->id = strdup(id);
        ASSERT_NOT_NULL(service->id);
        service->manager = manager;
        service->config_source = source;

        ASSERT_OK(hashmap_ensure_put(&manager->dnssd_registered_services, &string_hash_ops, service->id, service));

        return service;
}

static DnssdRegisteredService* add_published_service(
                Manager *manager,
                const char *id,
                const char *type,
                ResolveConfigSource source) {

        DnssdRegisteredService *service;
        char *instance;

        service = add_service(manager, id, source);
        ASSERT_OK(dns_name_concat(type, "local", 0, &service->type));
        ASSERT_OK(dns_name_concat(id, service->type, 0, &instance));

        service->ptr_rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, service->type);
        ASSERT_NOT_NULL(service->ptr_rr);
        service->ptr_rr->ptr.name = instance;
        service->ptr_rr->ttl = MDNS_DEFAULT_TTL;

        service->srv_rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SRV, instance);
        ASSERT_NOT_NULL(service->srv_rr);
        service->srv_rr->srv.name = strdup("host.local");
        ASSERT_NOT_NULL(service->srv_rr->srv.name);
        service->srv_rr->ttl = MDNS_DEFAULT_TTL;

        return service;
}

static size_t enumeration_record_count(DnsScope *scope) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL, *soa = NULL;
        bool tentative;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "_services._dns-sd._udp.local");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_zone_lookup(&scope->zone, key, 0, &answer, &soa, &tentative));

        return dns_answer_size(answer);
}

static void establish_service_records(
                DnsScope *scope,
                DnssdRegisteredService *a,
                DnssdRegisteredService *b,
                DnssdRegisteredService *c) {

        ASSERT_OK(dns_zone_put(&scope->zone, scope, a->srv_rr, false));
        ASSERT_OK(dns_zone_put(&scope->zone, scope, b->srv_rr, false));
        ASSERT_OK(dns_zone_put(&scope->zone, scope, c->srv_rr, false));
}

static void add_txt_record(DnssdRegisteredService *service, const char *text) {
        DnssdTxtData *txt_data;

        txt_data = new0(DnssdTxtData, 1);
        ASSERT_NOT_NULL(txt_data);
        ASSERT_OK(dnssd_txt_item_new_from_string(text, NULL, &txt_data->txts));
        txt_data->rr = dns_resource_record_new_full(
                        DNS_CLASS_IN, DNS_TYPE_TXT, dns_resource_key_name(service->srv_rr->key));
        ASSERT_NOT_NULL(txt_data->rr);
        txt_data->rr->ttl = MDNS_DEFAULT_TTL;
        txt_data->rr->txt.items = dns_txt_item_copy(txt_data->txts);
        ASSERT_NOT_NULL(txt_data->rr->txt.items);
        LIST_APPEND(items, service->txt_data_items, txt_data);
}

static void assert_goodbye_packet(
                DnsPacket *packet,
                DnsResourceRecord * const *expected,
                size_t n_expected) {

        bool found[6] = {};
        DnsAnswerFlags flags;
        DnsResourceRecord *rr;
        size_t i;

        ASSERT_NOT_NULL(packet);
        ASSERT_EQ(packet->protocol, DNS_PROTOCOL_MDNS);
        ASSERT_EQ(DNS_PACKET_ID(packet), 0);
        ASSERT_EQ(DNS_PACKET_QR(packet), 1);
        ASSERT_EQ(DNS_PACKET_AA(packet), 1);
        ASSERT_EQ(dns_packet_rcode(packet), DNS_RCODE_SUCCESS);
        ASSERT_EQ(DNS_PACKET_QDCOUNT(packet), 0);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packet), n_expected);
        ASSERT_EQ(DNS_PACKET_NSCOUNT(packet), 0);
        ASSERT_EQ(DNS_PACKET_ARCOUNT(packet), 0);
        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_answer_size(packet->answer), n_expected);

        DNS_ANSWER_FOREACH_FLAGS(rr, flags, packet->answer) {
                ASSERT_EQ(rr->ttl, 0u);
                ASSERT_TRUE(FLAGS_SET(flags, DNS_ANSWER_SECTION_ANSWER));

                for (i = 0; i < n_expected; i++)
                        if (dns_resource_record_equal(rr, expected[i]) > 0)
                                break;

                ASSERT_LT(i, n_expected);
                ASSERT_FALSE(found[i]);
                found[i] = true;

                if (rr->key->type == DNS_TYPE_PTR)
                        ASSERT_TRUE(FLAGS_SET(flags, DNS_ANSWER_SHARED_OWNER));
                else {
                        ASSERT_TRUE(IN_SET(rr->key->type, DNS_TYPE_SRV, DNS_TYPE_TXT));
                        ASSERT_FALSE(FLAGS_SET(flags, DNS_ANSWER_SHARED_OWNER));
                }
        }

        for (i = 0; i < n_expected; i++)
                ASSERT_TRUE(found[i]);
}

TEST(clear_on_reload) {
        Manager manager = {};
        DnssdRegisteredService *dynamic;

        add_service(&manager, "static-one", RESOLVE_CONFIG_SOURCE_FILE);
        dynamic = add_service(&manager, "dynamic-one", RESOLVE_CONFIG_SOURCE_DBUS);

        dnssd_registered_service_clear_on_reload(manager.dnssd_registered_services);

        ASSERT_EQ(hashmap_size(manager.dnssd_registered_services), 1u);
        ASSERT_PTR_EQ(hashmap_get(manager.dnssd_registered_services, "dynamic-one"), dynamic);

        dnssd_registered_service_remove(dynamic, /* send_goodbye= */ false);
        ASSERT_TRUE(hashmap_isempty(manager.dnssd_registered_services));
        manager.dnssd_registered_services = hashmap_free(manager.dnssd_registered_services);
}

TEST(remove_without_goodbye) {
        Manager manager = {};
        DnssdRegisteredService *service;

        service = add_service(&manager, "shutdown", RESOLVE_CONFIG_SOURCE_DBUS);
        ASSERT_NULL(dnssd_registered_service_remove(service, /* send_goodbye= */ false));
        ASSERT_TRUE(hashmap_isempty(manager.dnssd_registered_services));

        manager.dnssd_registered_services = hashmap_free(manager.dnssd_registered_services);
}

TEST(free_unpublished) {
        _cleanup_(dnssd_registered_service_freep) DnssdRegisteredService *service = NULL;
        Manager manager = {};

        service = new0(DnssdRegisteredService, 1);
        ASSERT_NOT_NULL(service);
        service->id = strdup("unpublished");
        ASSERT_NOT_NULL(service->id);
        service->manager = &manager;
}

TEST(service_type_reference_counting) {
        DnssdRegisteredService *dynamic, *other, *statik;
        Manager manager = {};
        DnsScope scope = {
                .manager = &manager,
                .protocol = DNS_PROTOCOL_MDNS,
        };

        statik = add_published_service(&manager, "static-http", "_http._tcp", RESOLVE_CONFIG_SOURCE_FILE);
        dynamic = add_published_service(&manager, "dynamic-http", "_http._tcp", RESOLVE_CONFIG_SOURCE_DBUS);
        other = add_published_service(&manager, "dynamic-printer", "_ipp._tcp", RESOLVE_CONFIG_SOURCE_DBUS);

        establish_service_records(&scope, statik, dynamic, other);
        ASSERT_OK(dns_scope_add_dnssd_registered_services(&scope));
        ASSERT_EQ(enumeration_record_count(&scope), 2u);

        ASSERT_EQ(dns_scope_remove_dnssd_service(&scope, statik, false), 1);
        ASSERT_EQ(enumeration_record_count(&scope), 2u);
        ASSERT_EQ(dns_scope_remove_dnssd_service(&scope, dynamic, false), 1);
        ASSERT_EQ(enumeration_record_count(&scope), 1u);
        ASSERT_EQ(dns_scope_remove_dnssd_service(&scope, other, false), 1);
        ASSERT_EQ(enumeration_record_count(&scope), 0u);

        establish_service_records(&scope, statik, dynamic, other);
        ASSERT_OK(dns_scope_add_dnssd_registered_services(&scope));
        ASSERT_EQ(enumeration_record_count(&scope), 2u);
        ASSERT_OK(dns_scope_remove_dnssd_registered_services(&scope));
        ASSERT_EQ(enumeration_record_count(&scope), 0u);
        establish_service_records(&scope, statik, dynamic, other);
        ASSERT_OK(dns_scope_add_dnssd_registered_services(&scope));
        ASSERT_EQ(enumeration_record_count(&scope), 2u);

        ASSERT_OK(dns_scope_remove_dnssd_registered_services(&scope));
        dns_zone_flush(&scope.zone);
        scope.dnssd_services = hashmap_free(scope.dnssd_services);
        scope.dnssd_service_types = hashmap_free(scope.dnssd_service_types);

        dnssd_registered_service_remove(statik, false);
        dnssd_registered_service_remove(dynamic, false);
        dnssd_registered_service_remove(other, false);
        manager.dnssd_registered_services = hashmap_free(manager.dnssd_registered_services);
}

TEST(targeted_goodbye_packet) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *aaaa = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *enumeration = NULL;
        DnssdRegisteredService *other, *removed;
        DnsResourceRecord *expected[6];
        Manager manager = {};
        DnsScope scope = {
                .manager = &manager,
                .protocol = DNS_PROTOCOL_MDNS,
        };
        union in_addr_union address = { .in.s_addr = htobe32(0xc0000201) };

        removed = add_published_service(&manager, "removed", "_http._tcp", RESOLVE_CONFIG_SOURCE_DBUS);
        other = add_published_service(&manager, "other", "_http._tcp", RESOLVE_CONFIG_SOURCE_FILE);

        removed->sub_ptr_rr = dns_resource_record_new_full(
                        DNS_CLASS_IN, DNS_TYPE_PTR, "_printer._sub._http._tcp.local");
        ASSERT_NOT_NULL(removed->sub_ptr_rr);
        removed->sub_ptr_rr->ptr.name = strdup(dns_resource_key_name(removed->srv_rr->key));
        ASSERT_NOT_NULL(removed->sub_ptr_rr->ptr.name);
        removed->sub_ptr_rr->ttl = MDNS_DEFAULT_TTL;
        add_txt_record(removed, "path=/one");
        add_txt_record(removed, "version=2");

        ASSERT_OK(dns_zone_put(&scope.zone, &scope, removed->ptr_rr, false));
        ASSERT_OK(dns_zone_put(&scope.zone, &scope, removed->sub_ptr_rr, false));
        ASSERT_OK(dns_zone_put(&scope.zone, &scope, removed->srv_rr, false));
        LIST_FOREACH(items, txt_data, removed->txt_data_items)
                ASSERT_OK(dns_zone_put(&scope.zone, &scope, txt_data->rr, false));
        ASSERT_OK(dns_zone_put(&scope.zone, &scope, other->ptr_rr, false));
        ASSERT_OK(dns_zone_put(&scope.zone, &scope, other->srv_rr, false));

        ASSERT_OK(dns_resource_record_new_address(&a, AF_INET, &address, "host.local"));
        address.in6 = (struct in6_addr) {
                .s6_addr = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        };
        ASSERT_OK(dns_resource_record_new_address(&aaaa, AF_INET6, &address, "host.local"));
        ASSERT_OK(dns_zone_put(&scope.zone, &scope, a, false));
        ASSERT_OK(dns_zone_put(&scope.zone, &scope, aaaa, false));

        ASSERT_OK(dns_scope_add_dnssd_registered_services(&scope));

        enumeration = dns_resource_record_new_full(
                        DNS_CLASS_IN, DNS_TYPE_PTR, "_services._dns-sd._udp.local");
        ASSERT_NOT_NULL(enumeration);
        enumeration->ptr.name = strdup("_http._tcp.local");
        ASSERT_NOT_NULL(enumeration->ptr.name);
        enumeration->ttl = MDNS_DEFAULT_TTL;

        expected[0] = removed->ptr_rr;
        expected[1] = removed->sub_ptr_rr;
        expected[2] = removed->srv_rr;
        expected[3] = removed->txt_data_items->rr;
        expected[4] = removed->txt_data_items->items_next->rr;
        ASSERT_OK(dns_scope_build_dnssd_service_packet(&scope, removed, true, &packet));
        assert_goodbye_packet(packet, expected, 5);
        ASSERT_FALSE(dns_answer_contains(packet->answer, enumeration));
        ASSERT_FALSE(dns_answer_contains(packet->answer, other->ptr_rr));
        ASSERT_FALSE(dns_answer_contains(packet->answer, other->srv_rr));
        ASSERT_FALSE(dns_answer_contains(packet->answer, a));
        ASSERT_FALSE(dns_answer_contains(packet->answer, aaaa));

        ASSERT_EQ(dns_scope_remove_dnssd_service(&scope, other, false), 1);
        expected[5] = enumeration;

        packet = dns_packet_unref(packet);
        ASSERT_OK(dns_scope_build_dnssd_service_packet(&scope, removed, true, &packet));
        assert_goodbye_packet(packet, expected, 6);

        ASSERT_EQ(dns_scope_remove_dnssd_service(&scope, removed, false), 1);
        packet = dns_packet_unref(packet);
        ASSERT_OK(dns_scope_build_dnssd_service_packet(&scope, removed, true, &packet));
        ASSERT_NULL(packet);
        dns_zone_flush(&scope.zone);
        scope.dnssd_services = hashmap_free(scope.dnssd_services);
        scope.dnssd_service_types = hashmap_free(scope.dnssd_service_types);
        dnssd_registered_service_remove(removed, false);
        dnssd_registered_service_remove(other, false);
        manager.dnssd_registered_services = hashmap_free(manager.dnssd_registered_services);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
