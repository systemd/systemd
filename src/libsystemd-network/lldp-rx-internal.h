/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"
#include "sd-json.h"
#include "sd-lldp-rx.h"

#include "hashmap.h"
#include "network-common.h"
#include "prioq.h"

struct sd_lldp_rx {
        unsigned n_ref;

        int ifindex;
        char *ifname;
        int fd;

        sd_event *event;
        int64_t event_priority;
        sd_event_source *io_event_source;
        sd_event_source *timer_event_source;

        Prioq *neighbor_by_expiry;
        Hashmap *neighbor_by_id;

        uint64_t neighbors_max;

        sd_lldp_rx_callback_t callback;
        void *userdata;

        uint16_t capability_mask;

        struct ether_addr filter_address;
};

const char* lldp_rx_event_to_string(sd_lldp_rx_event_t e) _const_;
sd_lldp_rx_event_t lldp_rx_event_from_string(const char *s) _pure_;

int lldp_rx_build_neighbors_json(sd_lldp_rx *lldp_rx, sd_json_variant **ret);

#define log_lldp_rx_errno(lldp_rx, error, fmt, ...)     \
        log_interface_prefix_full_errno(                \
                "LLDP Rx: ",                            \
                sd_lldp_rx, lldp_rx,                    \
                error, fmt, ##__VA_ARGS__)
#define log_lldp_rx(lldp_rx, fmt, ...)                  \
        log_interface_prefix_full_errno_zerook(         \
                "LLDP Rx: ",                            \
                sd_lldp_rx, lldp_rx,                    \
                0, fmt, ##__VA_ARGS__)
