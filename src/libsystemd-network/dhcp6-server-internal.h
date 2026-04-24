/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp6-server.h"
#include "sd-event.h"

#include "dhcp-duid-internal.h"
#include "dhcp6-option.h"
#include "dhcp6-protocol.h"
#include "hashmap.h"
#include "network-common.h"
#include "time-util.h"

typedef struct DHCP6ServerLease {
        struct in6_addr address;

        uint8_t *client_id;
        size_t client_id_len;

        usec_t expiration;
} DHCP6ServerLease;

struct sd_dhcp6_server {
        unsigned n_ref;

        sd_event *event;
        int event_priority;
        sd_event_source *receive_message;
        int fd;

        int ifindex;
        char *ifname;

        struct in6_addr address;
        unsigned char prefixlen;

        /* Server DUID - auto-generated from machine ID */
        uint8_t server_id[MAX_DUID_LEN];
        size_t server_id_len;

        /* Address pool */
        struct in6_addr pool_start;
        uint64_t pool_size;
        uint8_t *pool_bitmap; /* track which addresses are in use */

        char *timezone;

        struct in6_addr *dns;
        size_t n_dns;
        struct in6_addr *ntp;
        size_t n_ntp;

        Hashmap *leases; /* client_id -> DHCP6ServerLease */

        usec_t max_lease_time;
        usec_t default_lease_time;
        bool rapid_commit;
};

DHCP6ServerLease *dhcp6_server_lease_free(DHCP6ServerLease *lease);

#define log_dhcp6_server_errno(server, error, fmt, ...)         \
        log_interface_prefix_full_errno(                        \
                "DHCPv6 server: ",                              \
                sd_dhcp6_server, server,                        \
                error, fmt, ##__VA_ARGS__)
#define log_dhcp6_server(server, fmt, ...)                      \
        log_interface_prefix_full_errno_zerook(                 \
                "DHCPv6 server: ",                              \
                sd_dhcp6_server, server,                        \
                0, fmt, ##__VA_ARGS__)
