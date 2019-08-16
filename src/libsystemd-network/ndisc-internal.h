/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include "log.h"
#include "time-util.h"

#include "sd-ndisc.h"

#define NDISC_ROUTER_SOLICITATION_INTERVAL (4U * USEC_PER_SEC)
#define NDISC_MAX_ROUTER_SOLICITATION_INTERVAL (3600U * USEC_PER_SEC)
#define NDISC_MAX_ROUTER_SOLICITATIONS 3U

struct sd_ndisc {
        unsigned n_ref;

        int ifindex;
        int fd;

        sd_event *event;
        int event_priority;

        struct ether_addr mac_addr;
        uint8_t hop_limit;
        uint32_t mtu;

        sd_event_source *recv_event_source;
        sd_event_source *timeout_event_source;
        sd_event_source *timeout_no_ra;

        usec_t retransmit_time;

        sd_ndisc_callback_t callback;
        void *userdata;
};

#define log_ndisc_errno(error, fmt, ...) log_internal(LOG_DEBUG, error, PROJECT_FILE, __LINE__, __func__, "NDISC: " fmt, ##__VA_ARGS__)
#define log_ndisc(fmt, ...) log_ndisc_errno(0, fmt, ##__VA_ARGS__)

const char* ndisc_event_to_string(sd_ndisc_event e) _const_;
sd_ndisc_event ndisc_event_from_string(const char *s) _pure_;
