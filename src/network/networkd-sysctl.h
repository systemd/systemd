/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "conf-parser.h"

typedef struct Link Link;

typedef enum IPv6PrivacyExtensions {
        /* These values map to the kernel's /proc/sys/net/ipv6/conf/xxx/use_tempaddr values. Do not reorder! */
        IPV6_PRIVACY_EXTENSIONS_NO,
        IPV6_PRIVACY_EXTENSIONS_PREFER_PUBLIC,
        IPV6_PRIVACY_EXTENSIONS_YES,    /* aka prefer-temporary */
        IPV6_PRIVACY_EXTENSIONS_KERNEL, /* keep the kernel's default value */
        _IPV6_PRIVACY_EXTENSIONS_MAX,
        _IPV6_PRIVACY_EXTENSIONS_INVALID = -EINVAL,
} IPv6PrivacyExtensions;

typedef enum IPReversePathFilter {
        /* These values map to the kernel's  /proc/sys/net/ipv6/conf/xxx/rp_filter values. Do not reorder! */
        IP_REVERSE_PATH_FILTER_NO,
        IP_REVERSE_PATH_FILTER_STRICT,
        IP_REVERSE_PATH_FILTER_LOOSE,
        _IP_REVERSE_PATH_FILTER_MAX,
        _IP_REVERSE_PATH_FILTER_INVALID = -EINVAL,
} IPReversePathFilter;

int link_set_sysctl(Link *link);
int link_set_ipv6_mtu(Link *link);

const char* ipv6_privacy_extensions_to_string(IPv6PrivacyExtensions i) _const_;
IPv6PrivacyExtensions ipv6_privacy_extensions_from_string(const char *s) _pure_;

const char* ip_reverse_path_filter_to_string(IPReversePathFilter i) _const_;
IPReversePathFilter ip_reverse_path_filter_from_string(const char *s) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_privacy_extensions);
CONFIG_PARSER_PROTOTYPE(config_parse_ip_reverse_path_filter);
