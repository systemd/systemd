/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"

typedef enum ResolveConfigSource {
        RESOLVE_CONFIG_SOURCE_FILE,
        RESOLVE_CONFIG_SOURCE_NETWORKD,
        RESOLVE_CONFIG_SOURCE_DBUS,
        _RESOLVE_CONFIG_SOURCE_MAX,
        _RESOLVE_CONFIG_SOURCE_INVALID = -EINVAL,
} ResolveConfigSource;

#include "resolved-dns-server.h"

int manager_parse_config_file(Manager *m);

int manager_parse_search_domains_and_warn(Manager *m, const char *string);
int manager_parse_dns_server_string_and_warn(Manager *m, DnsServerType type, const char *string);

const struct ConfigPerfItem* resolved_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

CONFIG_PARSER_PROTOTYPE(config_parse_dns_servers);
CONFIG_PARSER_PROTOTYPE(config_parse_search_domains);
CONFIG_PARSER_PROTOTYPE(config_parse_dns_stub_listener_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_dns_stub_listener_extra);
