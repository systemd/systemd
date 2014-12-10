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

typedef enum LinkState {
        LINK_STATE_PENDING,
        LINK_STATE_ENSLAVING,
        LINK_STATE_SETTING_ADDRESSES,
        LINK_STATE_SETTING_ROUTES,
        LINK_STATE_CONFIGURED,
        LINK_STATE_UNMANAGED,
        LINK_STATE_FAILED,
        LINK_STATE_LINGER,
        _LINK_STATE_MAX,
        _LINK_STATE_INVALID = -1
} LinkState;

typedef enum LinkOperationalState {
        LINK_OPERSTATE_OFF,
        LINK_OPERSTATE_NO_CARRIER,
        LINK_OPERSTATE_DORMANT,
        LINK_OPERSTATE_CARRIER,
        LINK_OPERSTATE_DEGRADED,
        LINK_OPERSTATE_ROUTABLE,
        _LINK_OPERSTATE_MAX,
        _LINK_OPERSTATE_INVALID = -1
} LinkOperationalState;

struct Link {
        Manager *manager;

        int n_ref;

        int ifindex;
        char *ifname;
        char *state_file;
        struct ether_addr mac;
        uint32_t mtu;
        struct udev_device *udev_device;

        unsigned flags;
        uint8_t kernel_operstate;

        Network *network;

        LinkState state;
        LinkOperationalState operstate;

        unsigned link_messages;
        unsigned enslaving;

        LIST_HEAD(Address, addresses);

        sd_dhcp_client *dhcp_client;
        sd_dhcp_lease *dhcp_lease;
        char *lease_file;
        uint16_t original_mtu;
        unsigned dhcp4_messages;
        bool dhcp4_configured;

        sd_ipv4ll *ipv4ll;
        bool ipv4ll_address;
        bool ipv4ll_route;

        bool static_configured;

        LIST_HEAD(Address, pool_addresses);

        sd_dhcp_server *dhcp_server;

        sd_icmp6_nd *icmp6_router_discovery;
        sd_dhcp6_client *dhcp6_client;
};

Link *link_unref(Link *link);
Link *link_ref(Link *link);
int link_get(Manager *m, int ifindex, Link **ret);
int link_add(Manager *manager, sd_rtnl_message *message, Link **ret);
void link_drop(Link *link);

int link_address_drop_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata);
int link_route_drop_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata);

void link_enter_failed(Link *link);
int link_initialized(Link *link, struct udev_device *device);

void link_client_handler(Link *link);

int link_update(Link *link, sd_rtnl_message *message);
int link_rtnl_process_address(sd_rtnl *rtnl, sd_rtnl_message *message, void *userdata);

int link_save(Link *link);

bool link_has_carrier(Link *link);

int link_set_mtu(Link *link, uint32_t mtu);
int link_set_hostname(Link *link, const char *hostname);

int ipv4ll_configure(Link *link);
int dhcp4_configure(Link *link);
int icmp6_configure(Link *link);

const char* link_state_to_string(LinkState s) _const_;
LinkState link_state_from_string(const char *s) _pure_;

const char* link_operstate_to_string(LinkOperationalState s) _const_;
LinkOperationalState link_operstate_from_string(const char *s) _pure_;

DEFINE_TRIVIAL_CLEANUP_FUNC(Link*, link_unref);
#define _cleanup_link_unref_ _cleanup_(link_unrefp)

/* Macros which append INTERFACE= to the message */

#define log_link_full(link, level, error, fmt, ...) \
        log_object_internal(level, error, __FILE__, __LINE__, __func__, "INTERFACE=", link->ifname, "%-*s: " fmt, IFNAMSIZ, link->ifname, ##__VA_ARGS__)

#define log_link_debug(link, ...)       log_link_full(link, LOG_DEBUG, 0, ##__VA_ARGS__)
#define log_link_info(link, ...)        log_link_full(link, LOG_INFO, 0, ##__VA_ARGS__)
#define log_link_notice(link, ...)      log_link_full(link, LOG_NOTICE, 0, ##__VA_ARGS__)
#define log_link_warning(link, ...)     log_link_full(link, LOG_WARNING, 0, ##__VA_ARGS__)
#define log_link_error(link, ...)       log_link_full(link, LOG_ERR, 0, ##__VA_ARGS__)

#define log_link_debug_errno(link, error, ...)   log_link_full(link, LOG_DEBUG, error, ##__VA_ARGS__)
#define log_link_info_errno(link, error, ...)    log_link_full(link, LOG_INFO, error, ##__VA_ARGS__)
#define log_link_notice_errno(link, error, ...)  log_link_full(link, LOG_NOTICE, error, ##__VA_ARGS__)
#define log_link_warning_errno(link, error, ...) log_link_full(link, LOG_WARNING, error, ##__VA_ARGS__)
#define log_link_error_errno(link, error, ...)   log_link_full(link, LOG_ERR, error, ##__VA_ARGS__)

#define log_link_struct(link, level, ...) log_struct(level, "INTERFACE=%s", link->ifname, __VA_ARGS__)

#define ADDRESS_FMT_VAL(address)            \
        (address).s_addr & 0xFF,            \
        ((address).s_addr >> 8) & 0xFF,     \
        ((address).s_addr >> 16) & 0xFF,    \
        (address).s_addr >> 24
