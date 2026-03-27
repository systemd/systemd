/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/in.h>

#include "sd-dhcp6-relay.h"
#include "sd-forward.h"

#include "network-common.h"

#define DHCP6_HOP_COUNT_LIMIT 32

/* DHCPv6 Relay message header: msg-type(1) + hop-count(1) + link-address(16) + peer-address(16) = 34 */
#define DHCP6_RELAY_HEADER_SIZE 34

struct sd_dhcp6_relay {
        unsigned n_ref;

        int ifindex;
        char *ifname;

        sd_event *event;
        int64_t event_priority;
        sd_event_source *receive_message;

        int fd;

        struct in6_addr link_address;
        struct in6_addr relay_target;

        char *interface_id;

        bool running;
};

#define log_dhcp6_relay_errno(relay, error, fmt, ...)           \
        log_interface_prefix_full_errno(                        \
                "DHCPv6 relay: ",                               \
                sd_dhcp6_relay, relay,                          \
                error, fmt, ##__VA_ARGS__)
#define log_dhcp6_relay(relay, fmt, ...)                        \
        log_interface_prefix_full_errno_zerook(                 \
                "DHCPv6 relay: ",                               \
                sd_dhcp6_relay, relay,                          \
                0, fmt, ##__VA_ARGS__)
