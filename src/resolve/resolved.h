/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

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

#pragma once

#include "sd-event.h"
#include "sd-network.h"

#include "util.h"
#include "list.h"

typedef struct Address Address;
typedef struct Manager Manager;

struct Address {
        unsigned char family;

        union {
                struct in_addr in;
                struct in6_addr in6;
        } in_addr;

        LIST_FIELDS(Address, addresses);
};

struct Manager {
        sd_event *event;

        LIST_HEAD(Address, fallback_dns);

        /* network */
        sd_event_source *network_event_source;
        sd_network_monitor *network_monitor;
};

/* Manager */

int manager_new(Manager **ret);
void manager_free(Manager *m);

int manager_update_resolv_conf(Manager *m);
int manager_network_monitor_listen(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);
#define _cleanup_manager_free_ _cleanup_(manager_freep)

const struct ConfigPerfItem* resolved_gperf_lookup(const char *key, unsigned length);

int config_parse_dnsv(const char *unit, const char *filename, unsigned line,
                     const char *section, unsigned section_line, const char *lvalue,
                     int ltype, const char *rvalue, void *data, void *userdata);
