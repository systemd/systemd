/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"

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
CONFIG_PARSER_PROTOTYPE(config_parse_dnssd_service_subtype);
CONFIG_PARSER_PROTOTYPE(config_parse_dnssd_service_type);
CONFIG_PARSER_PROTOTYPE(config_parse_dnssd_txt);
CONFIG_PARSER_PROTOTYPE(config_parse_dns_stub_listener_extra);
