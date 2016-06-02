#pragma once

/***
  This file is part of systemd.

  Copyright (C) 2014 Intel Corporation. All rights reserved.

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

#include "log.h"

#include "sd-ndisc.h"

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

        unsigned nd_sent;

        sd_ndisc_callback_t callback;
        void *userdata;
};

#define log_ndisc_errno(error, fmt, ...) log_internal(LOG_DEBUG, error, __FILE__, __LINE__, __func__, "NDISC: " fmt, ##__VA_ARGS__)
#define log_ndisc(fmt, ...) log_ndisc_errno(0, fmt, ##__VA_ARGS__)
