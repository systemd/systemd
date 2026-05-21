/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <netinet/in.h>

#include "sd-dhcp-server.h"

#include "dhcp-forward.h"
#include "dhcp-message.h"
#include "network-common.h"

typedef struct sd_dhcp_server {
        unsigned n_ref;

        sd_event *event;
        int event_priority;
        sd_event_source *io_event_source;
        uint8_t ip_service_type;
        int socket_fd; /* socket fd set externally, used by unit tests */
        int raw_socket_fd; /* send-only raw socket fd, used on sending L2 unicast message. */

        int ifindex;
        char *ifname;
        be32_t address;
        be32_t netmask;
        be32_t subnet;
        uint32_t pool_offset;
        uint32_t pool_size;

        char *timezone;
        char *domain_name;

        DHCPServerData servers[_SD_DHCP_LEASE_SERVER_TYPE_MAX];
        struct in_addr boot_server_address;
        char *boot_server_name;
        char *boot_filename;

        TLV *extra_options;
        TLV *vendor_options;

        bool emit_router;
        struct in_addr router_address;

        Hashmap *bound_leases_by_client_id;
        Hashmap *bound_leases_by_address;
        Hashmap *static_leases_by_client_id;
        Hashmap *static_leases_by_address;

        usec_t max_lease_time;
        usec_t default_lease_time;
        usec_t ipv6_only_preferred_usec;
        bool rapid_commit;

        sd_dhcp_server_callback_t callback;
        void *callback_userdata;

        int lease_dir_fd;
        char *lease_file;
} sd_dhcp_server;

int dhcp_server_set_extra_options(sd_dhcp_server *server, TLV *options);
int dhcp_server_set_vendor_options(sd_dhcp_server *server, TLV *options);

void dhcp_server_on_lease_change(sd_dhcp_server *server);
bool dhcp_server_address_is_in_pool(sd_dhcp_server *server, be32_t address);
bool dhcp_server_address_available(sd_dhcp_server *server, be32_t address);

#define log_dhcp_server_errno(server, error, fmt, ...)          \
        log_interface_prefix_full_errno(                        \
                "DHCPv4 server: ",                              \
                sd_dhcp_server, server,                         \
                error, fmt, ##__VA_ARGS__)
#define log_dhcp_server(server, fmt, ...)                       \
        log_interface_prefix_full_errno_zerook(                 \
                "DHCPv4 server: ",                              \
                sd_dhcp_server, server,                         \
                0, fmt, ##__VA_ARGS__)
