/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include "sd-bus.h"

#include "in-addr-util.h"
#include "network-util.h"
#include "networkd-wwan-bus.h"

typedef struct Link Link;
typedef struct Manager Manager;
typedef struct Modem Modem;

typedef struct Bearer {
        Modem *modem;

        sd_bus_slot *slot_getall;       /* for GetAll method */

        char *path;                     /* DBus path e.g /org/freedesktop/ModemManager/Bearer/0 */
        char *name;                     /* Interface property, e.g. wwan0 */
        char *apn;                      /* "apn" field in Properties */
        AddressFamily ip_type;          /* "ip-type" field in Properties */

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

        bool connected;                 /* Connected property */
} Bearer;

typedef struct Modem {
        Manager *manager;

        sd_bus_slot *slot_getall;
        sd_bus_slot *slot_propertieschanged;
        sd_bus_slot *slot_statechanged;
        sd_bus_slot *slot_connect;

        char *path;                     /* DBus path e.g /org/freedesktop/ModemManager/Modem/0 */
        char *manufacturer;             /* The "Manufacturer" property */
        char *model;                    /* The "Model" property */
        char *port_name;                /* MM_MODEM_PORT_TYPE_NET of Ports property */

        Hashmap *bearers_by_path;
        Hashmap *bearers_by_name;

        MMModemState state;
        MMModemStateFailedReason state_fail_reason;
        ModemReconnectState reconnect_state;
} Modem;

int bearer_new(Modem *modem, const char *path, Bearer **ret);
Bearer *bearer_free(Bearer *b);
DEFINE_TRIVIAL_CLEANUP_FUNC(Bearer*, bearer_free);

int bearer_set_name(Bearer *b, const char *name);

int bearer_get_by_path(Manager *manager, const char *path, Modem **ret_modem, Bearer **ret_bearer);
int link_get_bearer(Link *link, Bearer **ret);

int link_dhcp_enabled_by_bearer(Link *link, int family);

int link_apply_bearer(Link *link);
int bearer_update_link(Bearer *b);
void bearer_drop(Bearer *b);

int modem_new(Manager *m, const char *path, Modem **ret);
Modem *modem_free(Modem *modem);
DEFINE_TRIVIAL_CLEANUP_FUNC(Modem*, modem_free);

int modem_get_by_path(Manager *m, const char *path, Modem **ret);
void modem_drop(Modem *modem);
void modem_drop_all(Manager *m);
