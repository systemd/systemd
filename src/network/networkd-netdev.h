/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#pragma once

#include "networkd.h"
#include "hashmap.h"
#include "list.h"
#include "set.h"
#include "in-addr-util.h"

typedef struct NetDevVTable NetDevVTable;

typedef struct netdev_join_callback netdev_join_callback;

struct netdev_join_callback {
        sd_rtnl_message_handler_t callback;
        Link *link;

        LIST_FIELDS(netdev_join_callback, callbacks);
};

typedef enum NetDevKind {
        NETDEV_KIND_BRIDGE,
        NETDEV_KIND_BOND,
        NETDEV_KIND_VLAN,
        NETDEV_KIND_MACVLAN,
        NETDEV_KIND_VXLAN,
        NETDEV_KIND_IPIP,
        NETDEV_KIND_GRE,
        NETDEV_KIND_SIT,
        NETDEV_KIND_VETH,
        NETDEV_KIND_VTI,
        NETDEV_KIND_DUMMY,
        NETDEV_KIND_TUN,
        NETDEV_KIND_TAP,
        _NETDEV_KIND_MAX,
        _NETDEV_KIND_INVALID = -1
} NetDevKind;

typedef enum NetDevState {
        NETDEV_STATE_FAILED,
        NETDEV_STATE_CREATING,
        NETDEV_STATE_READY,
        NETDEV_STATE_LINGER,
        _NETDEV_STATE_MAX,
        _NETDEV_STATE_INVALID = -1,
} NetDevState;

typedef enum NetDevCreateType {
        NETDEV_CREATE_INDEPENDENT,
        NETDEV_CREATE_MASTER,
        NETDEV_CREATE_STACKED,
        _NETDEV_CREATE_MAX,
        _NETDEV_CREATE_INVALID = -1,
} NetDevCreateType;

struct NetDev {
        Manager *manager;

        int n_ref;

        char *filename;

        Condition *match_host;
        Condition *match_virt;
        Condition *match_kernel;
        Condition *match_arch;

        NetDevState state;
        NetDevKind kind;
        char *description;
        char *ifname;
        struct ether_addr *mac;
        size_t mtu;
        int ifindex;

        LIST_HEAD(netdev_join_callback, callbacks);
};

#include "networkd-netdev-bridge.h"
#include "networkd-netdev-bond.h"
#include "networkd-netdev-vlan.h"
#include "networkd-netdev-macvlan.h"
#include "networkd-netdev-vxlan.h"
#include "networkd-netdev-veth.h"
#include "networkd-netdev-tunnel.h"
#include "networkd-netdev-dummy.h"
#include "networkd-netdev-tuntap.h"

struct NetDevVTable {
        /* How much memory does an object of this unit type need */
        size_t object_size;

        /* Config file sections this netdev kind understands, separated
         * by NUL chars */
        const char *sections;

        /* This should reset all type-specific variables. This should
         * not allocate memory, and is called with zero-initialized
         * data. It should hence only initialize variables that need
         * to be set != 0. */
        void (*init)(NetDev *n);

        /* This should free all kind-specific variables. It should be
         * idempotent. */
        void (*done)(NetDev *n);

        /* fill in message to create netdev */
        int (*fill_message_create)(NetDev *netdev, Link *link, sd_rtnl_message *message);

        /* specifies if netdev is independent, or a master device or a stacked device */
        NetDevCreateType create_type;

        /* create netdev, if not done via rtnl */
        int (*create)(NetDev *netdev);

        /* verify that compulsory configuration options were specified */
        int (*config_verify)(NetDev *netdev, const char *filename);
};

extern const NetDevVTable * const netdev_vtable[_NETDEV_KIND_MAX];

#define NETDEV_VTABLE(n) netdev_vtable[(n)->kind]

/* For casting a netdev into the various netdev kinds */
#define DEFINE_CAST(UPPERCASE, MixedCase)                                   \
        static inline MixedCase* UPPERCASE(NetDev *n) {                     \
                if (_unlikely_(!n || n->kind != NETDEV_KIND_##UPPERCASE))   \
                        return NULL;                                        \
                                                                            \
                return (MixedCase*) n;                                      \
        }

/* For casting the various netdev kinds into a netdev */
#define NETDEV(n) (&(n)->meta)

DEFINE_CAST(BRIDGE, Bridge);
DEFINE_CAST(BOND, Bond);
DEFINE_CAST(VLAN, VLan);
DEFINE_CAST(MACVLAN, MacVlan);
DEFINE_CAST(VXLAN, VxLan);
DEFINE_CAST(IPIP, Tunnel);
DEFINE_CAST(GRE, Tunnel);
DEFINE_CAST(SIT, Tunnel);
DEFINE_CAST(VTI, Tunnel);
DEFINE_CAST(VETH, Veth);
DEFINE_CAST(DUMMY, Dummy);
DEFINE_CAST(TUN, TunTap);
DEFINE_CAST(TAP, TunTap);

int netdev_load(Manager *manager);
void netdev_drop(NetDev *netdev);

NetDev *netdev_unref(NetDev *netdev);
NetDev *netdev_ref(NetDev *netdev);

DEFINE_TRIVIAL_CLEANUP_FUNC(NetDev*, netdev_unref);
#define _cleanup_netdev_unref_ _cleanup_(netdev_unrefp)

int netdev_get(Manager *manager, const char *name, NetDev **ret);
int netdev_set_ifindex(NetDev *netdev, sd_rtnl_message *newlink);
int netdev_enslave(NetDev *netdev, Link *link, sd_rtnl_message_handler_t callback);
int netdev_get_mac(const char *ifname, struct ether_addr **ret);
int netdev_join(NetDev *netdev, Link *link, sd_rtnl_message_handler_t cb);

const char *netdev_kind_to_string(NetDevKind d) _const_;
NetDevKind netdev_kind_from_string(const char *d) _pure_;

int config_parse_netdev_kind(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

/* gperf */
const struct ConfigPerfItem* network_netdev_gperf_lookup(const char *key, unsigned length);

/* Macros which append INTERFACE= to the message */

#define log_full_netdev(level, netdev, fmt, ...) log_object_internal(level, 0, __FILE__, __LINE__, __func__, "INTERFACE=", netdev->ifname, "%-*s: " fmt, IFNAMSIZ, netdev->ifname, ##__VA_ARGS__)
#define log_netdev_debug(netdev, ...)       log_full_netdev(LOG_DEBUG, netdev, ##__VA_ARGS__)
#define log_info_netdev(netdev, ...)        log_full_netdev(LOG_INFO, netdev, ##__VA_ARGS__)
#define log_notice_netdev(netdev, ...)      log_full_netdev(LOG_NOTICE, netdev, ##__VA_ARGS__)
#define log_warning_netdev(netdev, ...)     log_full_netdev(LOG_WARNING, netdev,## __VA_ARGS__)
#define log_netdev_error(netdev, ...)       log_full_netdev(LOG_ERR, netdev, ##__VA_ARGS__)

#define log_struct_netdev(level, netdev, ...) log_struct(level, "INTERFACE=%s", netdev->ifname, __VA_ARGS__)

#define NETDEVIF(netdev) "INTERFACE=%s", netdev->ifname
