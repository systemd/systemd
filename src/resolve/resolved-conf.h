/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"

typedef enum DnsStubListenerMode DnsStubListenerMode;

enum DnsStubListenerMode {
        DNS_STUB_LISTENER_NO,
        DNS_STUB_LISTENER_UDP = 1 << 0,
        DNS_STUB_LISTENER_TCP = 1 << 1,
        DNS_STUB_LISTENER_YES = DNS_STUB_LISTENER_UDP | DNS_STUB_LISTENER_TCP,
        _DNS_STUB_LISTENER_MODE_MAX,
        _DNS_STUB_LISTENER_MODE_INVALID = -1
};

#include "resolved-dns-server.h"

int manager_parse_config_file(Manager *m);

int manager_parse_search_domains_and_warn(Manager *m, const char *string);
int manager_parse_dns_server_string_and_warn(Manager *m, DnsServerType type, const char *string);

const struct ConfigPerfItem* resolved_gperf_lookup(const char *key, GPERF_LEN_TYPE length);
const struct ConfigPerfItem* resolved_dnssd_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

CONFIG_PARSER_PROTOTYPE(config_parse_dns_servers);
CONFIG_PARSER_PROTOTYPE(config_parse_search_domains);
CONFIG_PARSER_PROTOTYPE(config_parse_dns_stub_listener_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_dnssd_service_name);
CONFIG_PARSER_PROTOTYPE(config_parse_dnssd_service_type);
CONFIG_PARSER_PROTOTYPE(config_parse_dnssd_txt);
CONFIG_PARSER_PROTOTYPE(config_parse_dns_stub_listener_extra);
CONFIG_PARSER_PROTOTYPE(config_parse_resolve_restrict_interfaces);

const char* dns_stub_listener_mode_to_string(DnsStubListenerMode p) _const_;
DnsStubListenerMode dns_stub_listener_mode_from_string(const char *s) _pure_;
