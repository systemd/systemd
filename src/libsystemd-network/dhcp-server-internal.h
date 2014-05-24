/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2013 Intel Corporation. All rights reserved.
  Copyright (C) 2014 Tom Gundersen

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
#include "sd-dhcp-server.h"

#include "refcnt.h"
#include "util.h"
#include "log.h"

struct sd_dhcp_server {
        RefCount n_ref;

        sd_event *event;
        int event_priority;
        sd_event_source *receive_message;
        int fd;
};

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_dhcp_server*, sd_dhcp_server_unref);
#define _cleanup_dhcp_server_unref_ _cleanup_(sd_dhcp_server_unrefp)

#define log_dhcp_server(client, fmt, ...) log_meta(LOG_DEBUG, __FILE__, __LINE__, __func__, "DHCP SERVER: " fmt, ##__VA_ARGS__)
