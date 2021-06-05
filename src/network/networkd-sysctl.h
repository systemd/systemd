/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "conf-parser.h"

typedef struct Link Link;

typedef enum IPv6PrivacyExtensions {
        /* The values map to the kernel's /proc/sys/net/ipv6/conf/xxx/use_tempaddr values */
        IPV6_PRIVACY_EXTENSIONS_NO,
        IPV6_PRIVACY_EXTENSIONS_PREFER_PUBLIC,
        IPV6_PRIVACY_EXTENSIONS_YES, /* aka prefer-temporary */
        _IPV6_PRIVACY_EXTENSIONS_MAX,
        _IPV6_PRIVACY_EXTENSIONS_INVALID = -EINVAL,
} IPv6PrivacyExtensions;

int link_set_sysctl(Link *link);
int link_set_ipv6_mtu(Link *link);

const char* ipv6_privacy_extensions_to_string(IPv6PrivacyExtensions i) _const_;
IPv6PrivacyExtensions ipv6_privacy_extensions_from_string(const char *s) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_privacy_extensions);
