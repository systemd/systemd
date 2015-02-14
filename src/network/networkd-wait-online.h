/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Tom Gundersen <teg@jklm.no>

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
#include "sd-rtnl.h"
#include "sd-network.h"

#include "hashmap.h"

typedef struct Manager Manager;

#include "networkd-wait-online-link.h"

struct Manager {
        Hashmap *links;
        Hashmap *links_by_name;

        char **interfaces;
        char **ignore;

        sd_rtnl *rtnl;
        sd_event_source *rtnl_event_source;

        sd_network_monitor *network_monitor;
        sd_event_source *network_monitor_event_source;

        sd_event *event;
};

void manager_free(Manager *m);
int manager_new(Manager **ret, char **interfaces, char **ignore, usec_t timeout);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

bool manager_all_configured(Manager *m);
bool manager_ignore_link(Manager *m, Link *link);
