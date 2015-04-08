/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Kay Sievers, Lennart Poettering

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
#include "sd-resolve.h"
#include "sd-network.h"
#include "list.h"
#include "ratelimit.h"

typedef struct Manager Manager;

#include "timesyncd-server.h"

struct Manager {
        sd_event *event;
        sd_resolve *resolve;

        LIST_HEAD(ServerName, system_servers);
        LIST_HEAD(ServerName, link_servers);
        LIST_HEAD(ServerName, fallback_servers);

        RateLimit ratelimit;
        bool exhausted_servers;

        /* network */
        sd_event_source *network_event_source;
        sd_network_monitor *network_monitor;

        /* peer */
        sd_resolve_query *resolve_query;
        sd_event_source *event_receive;
        ServerName *current_server_name;
        ServerAddress *current_server_address;
        int server_socket;
        int missed_replies;
        uint64_t packet_count;
        sd_event_source *event_timeout;
        bool good;

        /* last sent packet */
        struct timespec trans_time_mon;
        struct timespec trans_time;
        usec_t retry_interval;
        bool pending;

        /* poll timer */
        sd_event_source *event_timer;
        usec_t poll_interval_usec;
        bool poll_resync;

        /* history data */
        struct {
                double offset;
                double delay;
        } samples[8];
        unsigned int samples_idx;
        double samples_jitter;

        /* last change */
        bool jumped;
        bool sync;
        int drift_ppm;

        /* watch for time changes */
        sd_event_source *event_clock_watch;
        int clock_watch_fd;

        /* Retry connections */
        sd_event_source *event_retry;

        /* RTC runs in local time, leave it alone */
        bool rtc_local_time;
};

int manager_new(Manager **ret);
void manager_free(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

void manager_set_server_name(Manager *m, ServerName *n);
void manager_set_server_address(Manager *m, ServerAddress *a);
void manager_flush_server_names(Manager *m, ServerType t);

int manager_connect(Manager *m);
void manager_disconnect(Manager *m);
