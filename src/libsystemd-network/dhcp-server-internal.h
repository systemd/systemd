/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include "sd-dhcp-server.h"
#include "sd-event.h"

#include "dhcp-client-id-internal.h"
#include "dhcp-option.h"
#include "network-common.h"
#include "ordered-set.h"
#include "time-util.h"

typedef enum DHCPRawOption {
        DHCP_RAW_OPTION_DATA_UINT8,
        DHCP_RAW_OPTION_DATA_UINT16,
        DHCP_RAW_OPTION_DATA_UINT32,
        DHCP_RAW_OPTION_DATA_STRING,
        DHCP_RAW_OPTION_DATA_IPV4ADDRESS,
        DHCP_RAW_OPTION_DATA_IPV6ADDRESS,
        _DHCP_RAW_OPTION_DATA_MAX,
        _DHCP_RAW_OPTION_DATA_INVALID,
} DHCPRawOption;

struct sd_dhcp_server {
        unsigned n_ref;

        sd_event *event;
        int event_priority;
        sd_event_source *receive_message;
        sd_event_source *receive_broadcast;
        int fd;
        int fd_raw;
        int fd_broadcast;

        int ifindex;
        char *ifname;
        bool bind_to_interface;
        be32_t address;
        be32_t netmask;
        be32_t subnet;
        uint32_t pool_offset;
        uint32_t pool_size;

        char *timezone;

        DHCPServerData servers[_SD_DHCP_LEASE_SERVER_TYPE_MAX];
        struct in_addr boot_server_address;
        char *boot_server_name;
        char *boot_filename;

        OrderedSet *extra_options;
        OrderedSet *vendor_options;

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

        struct in_addr relay_target;

        char *agent_circuit_id;
        char *agent_remote_id;
};

typedef struct DHCPRequest {
        /* received message */
        DHCPMessage *message;

        /* options */
        sd_dhcp_client_id client_id;
        size_t max_optlen;
        be32_t server_id;
        be32_t requested_ip;
        usec_t lifetime;
        const uint8_t *agent_info_option;
        char *hostname;
        const uint8_t *parameter_request_list;
        size_t parameter_request_list_len;
        bool rapid_commit;
        triple_timestamp timestamp;
} DHCPRequest;

int dhcp_server_handle_message(sd_dhcp_server *server, DHCPMessage *message,
                               size_t length, const triple_timestamp *timestamp);
int dhcp_server_send_packet(sd_dhcp_server *server,
                            DHCPRequest *req, DHCPPacket *packet,
                            int type, size_t optoffset);

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
