/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include "sd-ndisc.h"

#include "network-common.h"
#include "time-util.h"

#define NDISC_ROUTER_SOLICITATION_INTERVAL (4U * USEC_PER_SEC)
#define NDISC_MAX_ROUTER_SOLICITATION_INTERVAL (3600U * USEC_PER_SEC)
#define NDISC_MAX_ROUTER_SOLICITATIONS 3U

/* RFC 8781: PREF64 (NAT64 prefix) */
#define NDISC_PREF64_SCALED_LIFETIME_MASK      0xfff8
#define NDISC_PREF64_PLC_MASK                  0x0007
#define NDISC_MAX_PREF64_LIFETIME              65528
#define NDISC_PREF64_PLC_32                    5
#define NDISC_PREF64_PLC_40                    4
#define NDISC_PREF64_PLC_48                    3
#define NDISC_PREF64_PLC_56                    2
#define NDISC_PREF64_PLC_64                    1
#define NDISC_PREF64_PLC_96                    0

struct nd_opt_prefix64_info {
        uint8_t type;
        uint8_t length;
        uint16_t lifetime_and_plc;
        uint8_t prefix[12];
} __attribute__((__packed__));

struct sd_ndisc {
        unsigned n_ref;

        int ifindex;
        char *ifname;
        int fd;

        sd_event *event;
        int event_priority;

        struct ether_addr mac_addr;

        sd_event_source *recv_event_source;
        sd_event_source *timeout_event_source;
        sd_event_source *timeout_no_ra;

        usec_t retransmit_time;

        sd_ndisc_callback_t callback;
        void *userdata;
};

const char* ndisc_event_to_string(sd_ndisc_event_t e) _const_;
sd_ndisc_event_t ndisc_event_from_string(const char *s) _pure_;

#define log_ndisc_errno(ndisc, error, fmt, ...)         \
        log_interface_prefix_full_errno(                \
                "NDISC: ",                              \
                sd_ndisc, ndisc,                        \
                error, fmt, ##__VA_ARGS__)
#define log_ndisc(ndisc, fmt, ...)                      \
        log_interface_prefix_full_errno_zerook(         \
                "NDISC: ",                              \
                sd_ndisc, ndisc,                        \
                0, fmt, ##__VA_ARGS__)
