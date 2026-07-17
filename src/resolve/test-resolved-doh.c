/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-id128.h"

#include "dns-packet.h"
#include "resolved-dns-server.h"
#include "resolved-doh.h"
#include "resolved-manager.h"
#include "siphash24.h"
#include "tests.h"
#include "unaligned.h"

#define HASH_KEY SD_ID128_MAKE(d3,1e,48,90,4b,fa,4c,fe,af,9d,d5,a1,d7,2e,8a,b1)

TEST(content_type) {
        ASSERT_TRUE(dns_over_https_content_type_is_valid("application/dns-message"));
        ASSERT_TRUE(dns_over_https_content_type_is_valid("Application/DNS-Message"));
        ASSERT_FALSE(dns_over_https_content_type_is_valid(NULL));
        ASSERT_FALSE(dns_over_https_content_type_is_valid(""));
        ASSERT_TRUE(dns_over_https_content_type_is_valid("application/dns-message; charset=binary"));
        ASSERT_TRUE(dns_over_https_content_type_is_valid("application/dns-message ; charset=binary"));
        ASSERT_TRUE(dns_over_https_content_type_is_valid(" application/dns-message"));
        ASSERT_TRUE(dns_over_https_content_type_is_valid("application/dns-message \t"));
        ASSERT_FALSE(dns_over_https_content_type_is_valid("application/dns-messagex"));
        ASSERT_FALSE(dns_over_https_content_type_is_valid("application/octet-stream"));
}

TEST(age) {
        uint64_t age = UINT64_MAX;

        ASSERT_TRUE(dns_over_https_age_parse("0", &age));
        ASSERT_EQ(age, 0u);
        ASSERT_TRUE(dns_over_https_age_parse("250", &age));
        ASSERT_EQ(age, 250u);
        ASSERT_TRUE(dns_over_https_age_parse(" 250 \t", &age));
        ASSERT_EQ(age, 250u);
        ASSERT_TRUE(dns_over_https_age_parse("250, 999", &age));
        ASSERT_EQ(age, 250u);
        ASSERT_TRUE(dns_over_https_age_parse("999999999999999999999999999999999999", &age));
        ASSERT_EQ(age, UINT64_MAX);

        ASSERT_FALSE(dns_over_https_age_parse(NULL, &age));
        ASSERT_FALSE(dns_over_https_age_parse("", &age));
        ASSERT_FALSE(dns_over_https_age_parse(" ", &age));
        ASSERT_FALSE(dns_over_https_age_parse("-1", &age));
        ASSERT_FALSE(dns_over_https_age_parse("1.0", &age));
        ASSERT_FALSE(dns_over_https_age_parse("invalid", &age));
}

TEST(uri_expand_for_method) {
        const uint8_t dns_message[] = { 0xfb, 0xff };
        _cleanup_free_ char *uri = NULL;

        ASSERT_OK(dns_over_https_uri_expand_for_method("https://resolver.example/dns-query{?dns}", DNS_OVER_HTTPS_METHOD_POST, dns_message, sizeof(dns_message), &uri));
        ASSERT_STREQ(uri, "https://resolver.example/dns-query");

        uri = mfree(uri);
        ASSERT_OK(dns_over_https_uri_expand_for_method("https://resolver.example/dns-query{?dns}", DNS_OVER_HTTPS_METHOD_GET, dns_message, sizeof(dns_message), &uri));
        ASSERT_STREQ(uri, "https://resolver.example/dns-query?dns=-_8");

        uri = mfree(uri);
        ASSERT_OK(dns_over_https_uri_expand_for_method("https://resolver.example/custom?foo=bar{?dns}", DNS_OVER_HTTPS_METHOD_GET, dns_message, sizeof(dns_message), &uri));
        ASSERT_STREQ(uri, "https://resolver.example/custom?foo=bar&dns=-_8");

        uri = mfree(uri);
        ASSERT_OK(dns_over_https_uri_expand_for_method("https://resolver.example/custom?foo=bar{?dns}", DNS_OVER_HTTPS_METHOD_POST, dns_message, sizeof(dns_message), &uri));
        ASSERT_STREQ(uri, "https://resolver.example/custom?foo=bar");

        uri = mfree(uri);
        ASSERT_OK(dns_over_https_uri_expand_for_method("https://resolver.example/{?dns}/suffix", DNS_OVER_HTTPS_METHOD_GET, "foo", 3, &uri));
        ASSERT_STREQ(uri, "https://resolver.example/?dns=Zm9v/suffix");

        ASSERT_ERROR(dns_over_https_uri_expand_for_method("https://resolver.example/dns-query", DNS_OVER_HTTPS_METHOD_GET, dns_message, sizeof(dns_message), &uri), EINVAL);
        ASSERT_ERROR(dns_over_https_uri_expand_for_method("https://resolver.example/dns-query{?dns}", _DNS_OVER_HTTPS_METHOD_INVALID, dns_message, sizeof(dns_message), &uri), EINVAL);
        ASSERT_ERROR(dns_over_https_uri_expand_for_method("https://resolver.example/dns-query{?dns}", DNS_OVER_HTTPS_METHOD_GET, NULL, sizeof(dns_message), &uri), EINVAL);
}

TEST(uri_for_request) {
        _cleanup_free_ uint8_t *large_dns_message = new0(uint8_t, 6000);
        _cleanup_free_ char *uri = NULL;
        DnsOverHttpsMethod method;
        const uint8_t dns_message[] = { 0xfb, 0xff };

        ASSERT_NOT_NULL(large_dns_message);

        ASSERT_OK(dns_over_https_uri_for_request("https://resolver.example/dns-query{?dns}", "https://resolver.example/dns-query", dns_message, sizeof(dns_message), &method, &uri));
        ASSERT_EQ(method, DNS_OVER_HTTPS_METHOD_GET);
        ASSERT_STREQ(uri, "https://resolver.example/dns-query?dns=-_8");

        uri = mfree(uri);
        ASSERT_OK(dns_over_https_uri_for_request("https://resolver.example/dns-query", "https://resolver.example/dns-query", dns_message, sizeof(dns_message), &method, &uri));
        ASSERT_EQ(method, DNS_OVER_HTTPS_METHOD_POST);
        ASSERT_STREQ(uri, "https://resolver.example/dns-query");

        uri = mfree(uri);
        ASSERT_OK(dns_over_https_uri_for_request("https://resolver.example/dns-query{?dns}", "https://resolver.example/dns-query", large_dns_message, 6000, &method, &uri));
        ASSERT_EQ(method, DNS_OVER_HTTPS_METHOD_POST);
        ASSERT_STREQ(uri, "https://resolver.example/dns-query");
}

static void test_uri_parse_one(const char *uri_template, const char *expected_uri, const char *expected_uri_template, const char *expected_auth_name, uint16_t expected_port) {
        _cleanup_free_ char *auth_name = NULL, *normalized_template = NULL, *uri = NULL;
        uint16_t port = 0;

        ASSERT_OK(dns_over_https_uri_parse(uri_template, &uri, &normalized_template, &auth_name, &port));
        ASSERT_STREQ(uri, expected_uri);
        ASSERT_STREQ(normalized_template, expected_uri_template);
        ASSERT_STREQ(auth_name, expected_auth_name);
        ASSERT_EQ(port, expected_port);
}

TEST(uri_parse) {
        test_uri_parse_one("https://resolver.example", "https://resolver.example/", "https://resolver.example/", "resolver.example", 443);
        test_uri_parse_one("https://resolver.example/dns-query", "https://resolver.example/dns-query", "https://resolver.example/dns-query", "resolver.example", 443);
        test_uri_parse_one("https://resolver.example/dns-query{?dns}", "https://resolver.example/dns-query", "https://resolver.example/dns-query{?dns}", "resolver.example", 443);
        test_uri_parse_one("https://resolver.example:8443/custom{?dns}", "https://resolver.example:8443/custom", "https://resolver.example:8443/custom{?dns}", "resolver.example", 8443);
        test_uri_parse_one("https://resolver.example:/dns-query", "https://resolver.example/dns-query", "https://resolver.example/dns-query", "resolver.example", 443);
        test_uri_parse_one("HTTPS://resolver.example/dns-query{?dns}", "https://resolver.example/dns-query", "https://resolver.example/dns-query{?dns}", "resolver.example", 443);
        test_uri_parse_one("https://resolver.example/custom?foo=bar{?dns}", "https://resolver.example/custom?foo=bar", "https://resolver.example/custom?foo=bar{?dns}", "resolver.example", 443);
        test_uri_parse_one("https://192.0.2.1/dns-query", "https://192.0.2.1/dns-query", "https://192.0.2.1/dns-query", "192.0.2.1", 443);
        test_uri_parse_one("https://[2001:db8::1]/dns-query", "https://[2001:db8::1]/dns-query", "https://[2001:db8::1]/dns-query", "2001:db8::1", 443);
        test_uri_parse_one("https://[fe80::1%25eth0]/dns-query", "https://[fe80::1%25eth0]/dns-query", "https://[fe80::1%25eth0]/dns-query", "fe80::1", 443);
}

TEST(uri_parse_invalid) {
        ASSERT_ERROR(dns_over_https_uri_parse("http://resolver.example/dns-query", NULL, NULL, NULL, NULL), EPROTONOSUPPORT);
        ASSERT_ERROR(dns_over_https_uri_parse("https:///dns-query", NULL, NULL, NULL, NULL), EINVAL);
        ASSERT_ERROR(dns_over_https_uri_parse("https://user@resolver.example/dns-query", NULL, NULL, NULL, NULL), EINVAL);
        ASSERT_ERROR(dns_over_https_uri_parse("https://resolver.example/dns-query#fragment", NULL, NULL, NULL, NULL), EINVAL);
        ASSERT_ERROR(dns_over_https_uri_parse("https://resolver.example/dns-query{dns}", NULL, NULL, NULL, NULL), EOPNOTSUPP);
        ASSERT_ERROR(dns_over_https_uri_parse("https://resolver.example/dns-query{?dns}{?dns}", NULL, NULL, NULL, NULL), EOPNOTSUPP);
        ASSERT_ERROR(dns_over_https_uri_parse("https://resolver.example/dns-query}{?dns}", NULL, NULL, NULL, NULL), EINVAL);
        ASSERT_ERROR(dns_over_https_uri_parse("https://[2001:db8::invalid]/dns-query", NULL, NULL, NULL, NULL), EINVAL);
        ASSERT_ERROR(dns_over_https_uri_parse("resolver.example/dns-query", NULL, NULL, NULL, NULL), EINVAL);
        ASSERT_ERROR(dns_over_https_uri_parse("", NULL, NULL, NULL, NULL), EINVAL);
}

static uint64_t dns_server_hash(const DnsServer *server) {
        struct siphash state;

        siphash24_init(&state, HASH_KEY.bytes);
        dns_server_hash_ops.hash(server, &state);
        return siphash24_finalize(&state);
}

TEST(server_configuration_ipv4) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *configuration = NULL, *state = NULL;
        Manager manager = {}, duplicate_manager = {};

        ASSERT_OK(manager_parse_dns_server_string_and_warn(&manager, DNS_SERVER_SYSTEM, "1.1.1.1#https://resolver.example/dns-query{?dns}"));

        DnsServer *server = ASSERT_PTR(manager.dns_servers);
        ASSERT_EQ(server->protocol, DNS_SERVER_PROTOCOL_HTTPS);
        ASSERT_EQ(server->family, AF_INET);
        ASSERT_EQ(server->port, 443);
        ASSERT_EQ(dns_server_port(server), 443);
        ASSERT_EQ(server->ifindex, 0);
        ASSERT_STREQ(server->server_name, "resolver.example");
        ASSERT_STREQ(server->doh_uri, "https://resolver.example/dns-query");
        ASSERT_STREQ(server->doh_uri_template, "https://resolver.example/dns-query{?dns}");
        ASSERT_STREQ(dns_server_string_full(server), "1.1.1.1#https://resolver.example/dns-query{?dns}");

        ASSERT_NULL(dns_server_find(manager.dns_servers, AF_INET, &server->address, 443, 0, "resolver.example"));

        ASSERT_OK(dns_server_dump_configuration_to_json(server, &configuration));
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(configuration, "protocol")), "https");
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(configuration, "uri")), "https://resolver.example/dns-query{?dns}");
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(configuration, "name")), "resolver.example");
        ASSERT_EQ(sd_json_variant_unsigned(sd_json_variant_by_key(configuration, "port")), 443u);

        ASSERT_OK(dns_server_dump_state_to_json(server, &state));
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(state, "Protocol")), "https");
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(state, "URI")), "https://resolver.example/dns-query{?dns}");

        ASSERT_OK(manager_parse_dns_server_string_and_warn(&duplicate_manager, DNS_SERVER_SYSTEM, "1.1.1.1#HTTPS://resolver.example/dns-query{?dns}"));
        DnsServer *duplicate = ASSERT_PTR(duplicate_manager.dns_servers);
        ASSERT_EQ(dns_server_hash_ops.compare(server, duplicate), 0);
        ASSERT_EQ(dns_server_hash(server), dns_server_hash(duplicate));

        ASSERT_OK(manager_parse_dns_server_string_and_warn(&manager, DNS_SERVER_SYSTEM, "1.1.1.1#https://resolver.example/dns-query"));
        ASSERT_EQ(manager.n_dns_servers, 2u);

        ASSERT_OK(manager_parse_dns_server_string_and_warn(&manager, DNS_SERVER_SYSTEM, "1.1.1.1#https://resolver.example/other-query"));
        ASSERT_EQ(manager.n_dns_servers, 3u);
        ASSERT_NE(dns_server_hash_ops.compare(server, server->servers_next), 0);

        ASSERT_OK(manager_parse_dns_server_string_and_warn(&manager, DNS_SERVER_SYSTEM, "1.1.1.1:443#resolver.example"));
        ASSERT_EQ(manager.n_dns_servers, 4u);
        DnsServer *classic = ASSERT_PTR(dns_server_find(manager.dns_servers, AF_INET, &server->address, 443, 0, "resolver.example"));
        ASSERT_EQ(classic->protocol, DNS_SERVER_PROTOCOL_DNS);
        ASSERT_NE(dns_server_hash_ops.compare(server, classic), 0);

        dns_server_unlink_all(manager.dns_servers);
        dns_server_unlink_all(duplicate_manager.dns_servers);
}

TEST(server_configuration_ipv6) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *configuration = NULL, *state = NULL;
        Manager manager = {};

        ASSERT_OK(manager_parse_dns_server_string_and_warn(&manager, DNS_SERVER_SYSTEM, "[fe80::1]:8443%lo#https://resolver.example:8443/dns-query{?dns}"));

        DnsServer *server = ASSERT_PTR(manager.dns_servers);
        ASSERT_EQ(server->protocol, DNS_SERVER_PROTOCOL_HTTPS);
        ASSERT_EQ(server->family, AF_INET6);
        ASSERT_EQ(server->port, 8443);
        ASSERT_EQ(server->ifindex, LOOPBACK_IFINDEX);
        ASSERT_EQ(dns_server_ifindex(server), LOOPBACK_IFINDEX);
        ASSERT_STREQ(server->server_name, "resolver.example");
        ASSERT_STREQ(server->doh_uri, "https://resolver.example:8443/dns-query");
        ASSERT_STREQ(server->doh_uri_template, "https://resolver.example:8443/dns-query{?dns}");
        ASSERT_STREQ(dns_server_string_full(server), "[fe80::1]:8443%1#https://resolver.example:8443/dns-query{?dns}");

        ASSERT_OK(dns_server_dump_configuration_to_json(server, &configuration));
        ASSERT_EQ(sd_json_variant_unsigned(sd_json_variant_by_key(configuration, "ifindex")), (uint64_t) LOOPBACK_IFINDEX);
        ASSERT_OK(dns_server_dump_state_to_json(server, &state));
        ASSERT_EQ(sd_json_variant_unsigned(sd_json_variant_by_key(state, "InterfaceIndex")), (uint64_t) LOOPBACK_IFINDEX);

        dns_server_unlink_all(manager.dns_servers);

        ASSERT_OK(manager_parse_dns_server_string_and_warn(&manager, DNS_SERVER_SYSTEM, "fe80::2%1#https://resolver.example/dns-query{?dns}"));
        server = ASSERT_PTR(manager.dns_servers);
        ASSERT_EQ(server->family, AF_INET6);
        ASSERT_EQ(server->ifindex, LOOPBACK_IFINDEX);
        ASSERT_EQ(server->port, 443);

        dns_server_unlink_all(manager.dns_servers);

        ASSERT_OK(manager_parse_dns_server_string_and_warn(&manager, DNS_SERVER_SYSTEM, "2001:db8::1#https://[2001:db8::53]:8443/dns-query"));
        server = ASSERT_PTR(manager.dns_servers);
        ASSERT_EQ(server->family, AF_INET6);
        ASSERT_EQ(server->port, 8443);
        ASSERT_STREQ(server->server_name, "2001:db8::53");
        ASSERT_STREQ(server->doh_uri, "https://[2001:db8::53]:8443/dns-query");

        dns_server_unlink_all(manager.dns_servers);
}

TEST(server_configuration_link) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;

        ASSERT_OK(link_new(&manager, &link, 42));
        ASSERT_OK(dns_server_new_from_string(&manager, DNS_SERVER_LINK, link, NULL, "192.0.2.1#https://resolver.example/dns-query{?dns}", RESOLVE_CONFIG_SOURCE_NETWORKD));

        DnsServer *server = ASSERT_PTR(link->dns_servers);
        ASSERT_EQ(server->type, DNS_SERVER_LINK);
        ASSERT_EQ(server->protocol, DNS_SERVER_PROTOCOL_HTTPS);
        ASSERT_TRUE(server->link == link);
        ASSERT_EQ(server->config_source, RESOLVE_CONFIG_SOURCE_NETWORKD);
        ASSERT_EQ(server->ifindex, 0);
        ASSERT_EQ(dns_server_ifindex(server), 42);
        ASSERT_STREQ(server->doh_uri_template, "https://resolver.example/dns-query{?dns}");

        ASSERT_ERROR(dns_server_new_from_string(&manager, DNS_SERVER_LINK, link, NULL, "fe80::1%1#https://resolver.example/dns-query{?dns}", RESOLVE_CONFIG_SOURCE_NETWORKD), EINVAL);
        ASSERT_EQ(link->n_dns_servers, 1u);

        link = link_free(link);
}

TEST(server_configuration_invalid) {
        Manager manager = {};

        ASSERT_OK(manager_parse_dns_server_string_and_warn(&manager, DNS_SERVER_SYSTEM, "1.1.1.1:8443#https://resolver.example/dns-query"));
        ASSERT_NULL(manager.dns_servers);

        ASSERT_OK(manager_parse_dns_server_string_and_warn(&manager, DNS_SERVER_SYSTEM, "1.1.1.1#http://resolver.example/dns-query"));
        ASSERT_NULL(manager.dns_servers);

        ASSERT_OK(manager_parse_dns_server_string_and_warn(&manager, DNS_SERVER_SYSTEM, "1.1.1.1#https:/resolver.example/dns-query"));
        ASSERT_NULL(manager.dns_servers);
}

TEST(curl_connection_override_serialization) {
        _cleanup_free_ char *entry = NULL;
        Manager manager = {};
        bool use_resolve;

        ASSERT_OK(manager_parse_dns_server_string_and_warn(&manager, DNS_SERVER_SYSTEM, "1.1.1.1#https://resolver.example/dns-query"));
        ASSERT_OK(dns_over_https_make_connection_override(ASSERT_PTR(manager.dns_servers), CURL_VERSION_BITS(7, 83, 0), &use_resolve, &entry));
        ASSERT_TRUE(use_resolve);
        ASSERT_STREQ(entry, "resolver.example:443:1.1.1.1");
        dns_server_unlink_all(manager.dns_servers);

        entry = mfree(entry);
        ASSERT_OK(manager_parse_dns_server_string_and_warn(&manager, DNS_SERVER_SYSTEM, "[fe80::1]:8443%lo#https://resolver.example:8443/dns-query"));
        ASSERT_OK(dns_over_https_make_connection_override(ASSERT_PTR(manager.dns_servers), CURL_VERSION_BITS(7, 83, 0), &use_resolve, &entry));
        ASSERT_TRUE(use_resolve);
        ASSERT_STREQ(entry, "resolver.example:8443:[fe80::1]");
        dns_server_unlink_all(manager.dns_servers);

        entry = mfree(entry);
        ASSERT_OK(manager_parse_dns_server_string_and_warn(&manager, DNS_SERVER_SYSTEM, "2001:db8::1#https://[2001:db8::53]:8443/dns-query"));
        ASSERT_OK(dns_over_https_make_connection_override(ASSERT_PTR(manager.dns_servers), CURL_VERSION_BITS(8, 12, 1), &use_resolve, &entry));
        ASSERT_FALSE(use_resolve);
        ASSERT_STREQ(entry, ":8443:[2001:db8::1]:8443");

        entry = mfree(entry);
        ASSERT_OK(dns_over_https_make_connection_override(ASSERT_PTR(manager.dns_servers), CURL_VERSION_BITS(8, 13, 0), &use_resolve, &entry));
        ASSERT_TRUE(use_resolve);
        ASSERT_STREQ(entry, "[2001:db8::53]:8443:[2001:db8::1]");
        dns_server_unlink_all(manager.dns_servers);
}

TEST(server_transport_features) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        Manager manager = {};

        /* Verify that DoH uses DNS message capabilities without modifying UDP, TCP, or DoT transport state. */

        ASSERT_OK(sd_event_default(&event));
        manager.event = event;
        manager.dns_over_tls_mode = DNS_OVER_TLS_YES;
        manager.dnssec_mode = DNSSEC_YES;

        ASSERT_OK(manager_parse_dns_server_string_and_warn(&manager, DNS_SERVER_SYSTEM, "1.1.1.1#https://resolver.example/dns-query"));
        DnsServer *server = ASSERT_PTR(manager.dns_servers);

        dns_server_reset_features(server);
        ASSERT_EQ(dns_server_possible_capability_level(server), DNS_SERVER_CAPABILITY_LEVEL_DO);

        ASSERT_OK(dns_packet_new_query(&packet, DNS_PROTOCOL_DNS, 0, false));
        ASSERT_OK(dns_server_adjust_opt(server, packet, DNS_SERVER_CAPABILITY_LEVEL_EDNS0));
        ASSERT_EQ(unaligned_read_be16(DNS_PACKET_DATA(packet) + DNS_PACKET_HEADER_SIZE + 3), UINT16_MAX);

        server->n_failed_udp = 1;
        server->n_failed_tcp = 2;
        server->n_failed_tls = 3;
        server->received_udp_fragment_max = 1232;
        dns_server_packet_received(server, DNS_TRANSACTION_TRANSPORT_HTTPS, DNS_SERVER_TRANSPORT_TLS, 9000);
        ASSERT_EQ(server->n_failed_udp, 1u);
        ASSERT_EQ(server->n_failed_tcp, 2u);
        ASSERT_EQ(server->n_failed_tls, 3u);
        ASSERT_EQ(server->received_udp_fragment_max, 1232u);

        dns_server_packet_lost(server, DNS_TRANSACTION_TRANSPORT_HTTPS, DNS_SERVER_TRANSPORT_TLS);
        ASSERT_EQ(server->n_failed_udp, 1u);
        ASSERT_EQ(server->n_failed_tcp, 2u);
        ASSERT_EQ(server->n_failed_tls, 3u);

        server->n_failed_tcp = UINT_MAX;
        ASSERT_TRUE(dns_server_dnssec_supported(server));

        dns_server_unlink_all(manager.dns_servers);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
