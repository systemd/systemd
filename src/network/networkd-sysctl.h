/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "conf-parser.h"

typedef struct Link Link;
typedef struct Manager Manager;

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

#if HAVE_VMLINUX_H
int manager_install_sysctl_monitor(Manager *manager);
void manager_remove_sysctl_monitor(Manager *manager);
int link_clear_sysctl_shadows(Link *link);
#else
static inline int manager_install_sysctl_monitor(Manager *manager) { return 0; }
static inline void manager_remove_sysctl_monitor(Manager *manager) { }
static inline int link_clear_sysctl_shadows(Link *link) { return 0; }
#endif

void manager_set_sysctl(Manager *manager);

int link_get_ip_forwarding(Link *link, int family);
int link_set_sysctl(Link *link);
int link_set_ipv6_mtu(Link *link, int log_level);
int link_set_ipv6_mtu_async(Link *link);

const char* ipv6_privacy_extensions_to_string(IPv6PrivacyExtensions i) _const_;
IPv6PrivacyExtensions ipv6_privacy_extensions_from_string(const char *s) _pure_;

const char* ip_reverse_path_filter_to_string(IPReversePathFilter i) _const_;
IPReversePathFilter ip_reverse_path_filter_from_string(const char *s) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_privacy_extensions);
CONFIG_PARSER_PROTOTYPE(config_parse_ip_reverse_path_filter);
CONFIG_PARSER_PROTOTYPE(config_parse_ip_forward_deprecated);

typedef enum IPv4ForceIgmpVersion {
        /* These values map to the kernel's /proc/sys/net/ipv4/conf/INTERFACE/force_igmp_version values. Do not reorder! */
        IPV4_FORCE_IGMP_VERSION_NO = 0,
        IPV4_FORCE_IGMP_VERSION_1  = 1,
        IPV4_FORCE_IGMP_VERSION_2  = 2,
        IPV4_FORCE_IGMP_VERSION_3  = 3,
        _IPV4_FORCE_IGMP_VERSION_MAX,
        _IPV4_FORCE_IGMP_VERSION_INVALID = -EINVAL,
} IPv4ForceIgmpVersion;

const char* ipv4_force_igmp_version_to_string(IPv4ForceIgmpVersion i) _const_;
IPv4ForceIgmpVersion ipv4_force_igmp_version_from_string(const char *s) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_ipv4_force_igmp_version);
