/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include "sd-dhcp-server.h"
#include "sd-event.h"

#include "dhcp-internal.h"
#include "ordered-set.h"
#include "log.h"
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

typedef struct DHCPClientId {
        size_t length;
        void *data;
} DHCPClientId;

typedef struct DHCPLease {
        DHCPClientId client_id;

        be32_t address;
        be32_t gateway;
        uint8_t chaddr[16];
        usec_t expiration;
} DHCPLease;

struct sd_dhcp_server {
        unsigned n_ref;

        sd_event *event;
        int event_priority;
        sd_event_source *receive_message;
        int fd;
        int fd_raw;

        int ifindex;
        be32_t address;
        be32_t netmask;
        be32_t subnet;
        uint32_t pool_offset;
        uint32_t pool_size;

        char *timezone;

        DHCPServerData servers[_SD_DHCP_LEASE_SERVER_TYPE_MAX];

        OrderedSet *extra_options;
        OrderedSet *vendor_options;

        bool emit_router;

        Hashmap *leases_by_client_id;
        DHCPLease **bound_leases;
        DHCPLease invalid_lease;

        uint32_t max_lease_time, default_lease_time;

        sd_dhcp_server_callback_t callback;
        void *callback_userdata;
};

typedef struct DHCPRequest {
        /* received message */
        DHCPMessage *message;

        /* options */
        DHCPClientId client_id;
        size_t max_optlen;
        be32_t server_id;
        be32_t requested_ip;
        uint32_t lifetime;
} DHCPRequest;

#define log_dhcp_server(client, fmt, ...) log_internal(LOG_DEBUG, 0, PROJECT_FILE, __LINE__, __func__, "DHCP SERVER: " fmt, ##__VA_ARGS__)
#define log_dhcp_server_errno(client, error, fmt, ...) log_internal(LOG_DEBUG, error, PROJECT_FILE, __LINE__, __func__, "DHCP SERVER: " fmt, ##__VA_ARGS__)

int dhcp_server_handle_message(sd_dhcp_server *server, DHCPMessage *message,
                               size_t length);
int dhcp_server_send_packet(sd_dhcp_server *server,
                            DHCPRequest *req, DHCPPacket *packet,
                            int type, size_t optoffset);

void client_id_hash_func(const DHCPClientId *p, struct siphash *state);
int client_id_compare_func(const DHCPClientId *a, const DHCPClientId *b);
