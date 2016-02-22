#pragma once

/***
  This file is part of systemd.

  Copyright (C) 2014 Tom Gundersen
  Copyright (C) 2014 Susant Sahani

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "sd-event.h"
#include "sd-lldp.h"

#include "hashmap.h"
#include "log.h"
#include "prioq.h"

struct sd_lldp {
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

#define log_lldp_errno(error, fmt, ...) log_internal(LOG_DEBUG, error, __FILE__, __LINE__, __func__, "LLDP: " fmt, ##__VA_ARGS__)
#define log_lldp(fmt, ...) log_lldp_errno(0, fmt, ##__VA_ARGS__)
