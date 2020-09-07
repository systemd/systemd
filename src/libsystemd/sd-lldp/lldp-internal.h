/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-event.h"
#include "sd-lldp.h"

#include "hashmap.h"
#include "log.h"
#include "prioq.h"

struct sd_lldp {
        unsigned n_ref;

        int ifindex;
        int fd;

        sd_event *event;
        int64_t event_priority;
        sd_event_source *io_event_source;
        sd_event_source *timer_event_source;

        Prioq *neighbor_by_expiry;
        Hashmap *neighbor_by_id;

        uint64_t neighbors_max;

        sd_lldp_callback_t callback;
        void *userdata;

        uint16_t capability_mask;

        struct ether_addr filter_address;
};

#define log_lldp_errno(error, fmt, ...) log_internal(LOG_DEBUG, error, PROJECT_FILE, __LINE__, __func__, "LLDP: " fmt, ##__VA_ARGS__)
#define log_lldp(fmt, ...) log_lldp_errno(0, fmt, ##__VA_ARGS__)

const char* lldp_event_to_string(sd_lldp_event e) _const_;
sd_lldp_event lldp_event_from_string(const char *s) _pure_;
