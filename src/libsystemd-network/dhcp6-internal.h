/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2014-2015 Intel Corporation. All rights reserved.
***/

#include <net/ethernet.h>
#include <netinet/in.h>

#include "sd-event.h"
#include "sd-dhcp6-client.h"

#include "dhcp-duid-internal.h"
#include "dhcp6-client-internal.h"
#include "dhcp6-option.h"
#include "dhcp6-protocol.h"
#include "ether-addr-util.h"
#include "hashmap.h"
#include "macro.h"
#include "network-common.h"
#include "ordered-set.h"
#include "sparse-endian.h"
#include "time-util.h"

/* what to request from the server, addresses (IA_NA) and/or prefixes (IA_PD) */
typedef enum DHCP6RequestIA {
        DHCP6_REQUEST_IA_NA = 1 << 0,
        DHCP6_REQUEST_IA_TA = 1 << 1, /* currently not used */
        DHCP6_REQUEST_IA_PD = 1 << 2,
} DHCP6RequestIA;

struct sd_dhcp6_client {
        unsigned n_ref;

        int ifindex;
        char *ifname;

        struct in6_addr local_address;
        struct hw_addr_data hw_addr;
        uint16_t arp_type;

        sd_event *event;
        sd_event_source *receive_message;
        sd_event_source *timeout_resend;
        sd_event_source *timeout_expire;
        sd_event_source *timeout_t1;
        sd_event_source *timeout_t2;
        int event_priority;
        int fd;

        sd_device *dev;

        DHCP6State state;
        bool information_request;
        usec_t information_request_time_usec;
        usec_t information_refresh_time_usec;
        be32_t transaction_id;
        usec_t transaction_start;
        usec_t retransmit_time;
        uint8_t retransmit_count;

        bool iaid_set;
        DHCP6IA ia_na;
        DHCP6IA ia_pd;
        DHCP6RequestIA request_ia;
        sd_dhcp_duid duid;
        be16_t *req_opts;
        size_t n_req_opts;
        char *fqdn;
        char *mudurl;
        char **user_class;
        char **vendor_class;
        OrderedHashmap *extra_options;
        OrderedSet *vendor_options;
        bool rapid_commit;

        struct sd_dhcp6_lease *lease;

        sd_dhcp6_client_callback_t callback;
        void *userdata;
        sd_dhcp6_client_callback_t state_callback;
        void *state_userdata;
        bool send_release;
};

int dhcp6_network_bind_udp_socket(int ifindex, const struct in6_addr *address);
int dhcp6_network_send_udp_socket(int s, const struct in6_addr *address, const void *packet, size_t len);

int dhcp6_client_send_message(sd_dhcp6_client *client);
int dhcp6_client_set_transaction_id(sd_dhcp6_client *client, uint32_t transaction_id);

#define log_dhcp6_client_errno(client, error, fmt, ...)         \
        log_interface_prefix_full_errno(                        \
                "DHCPv6 client: ",                              \
                sd_dhcp6_client, client,                        \
                error, fmt, ##__VA_ARGS__)
#define log_dhcp6_client(client, fmt, ...)                      \
        log_interface_prefix_full_errno_zerook(                 \
                "DHCPv6 client: ",                              \
                sd_dhcp6_client, client,                        \
                0, fmt, ##__VA_ARGS__)
