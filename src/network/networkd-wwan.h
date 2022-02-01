/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include "sd-bus.h"

#include "in-addr-util.h"
#include "network-util.h"

typedef struct Link Link;
typedef struct Manager Manager;

typedef struct Bearer {
        Manager *manager;

        sd_bus_slot *slot;     /* for GetAll method */

        char *path;            /* DBus path e.g /org/freedesktop/ModemManager/Bearer/0 */
        char *name;            /* Interface property, e.g. wwan0 */
        char *apn;             /* "apn" field in Properties */
        AddressFamily ip_type; /* "ip-type" field in Properties */

        /* Ip4Config or IP6Config property */
        unsigned ip4_method;
        unsigned ip6_method;
        unsigned ip4_prefixlen;
        unsigned ip6_prefixlen;
        union in_addr_union ip4_address;
        union in_addr_union ip6_address;
        union in_addr_union ip4_gateway;
        union in_addr_union ip6_gateway;
        struct in_addr_data *dns;
        size_t n_dns;
        uint32_t ip4_mtu;
        uint32_t ip6_mtu;

        bool connected;        /* Connected property */
} Bearer;

int bearer_new(Manager *m, const char *path, Bearer **ret);
Bearer *bearer_free(Bearer *b);
DEFINE_TRIVIAL_CLEANUP_FUNC(Bearer*, bearer_free);

int bearer_set_name(Bearer *b, const char *name);

int bearer_get_by_path(Manager *m, const char *path, Bearer **ret);
int link_get_bearer(Link *link, Bearer **ret);

int link_dhcp_enabled_by_bearer(Link *link, int family);

int link_apply_bearer(Link *link);
int bearer_update_link(Bearer *b);
void bearer_drop(Bearer *b);
