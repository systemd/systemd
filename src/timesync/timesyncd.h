/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "list.h"
#include "socket-util.h"
#include "ratelimit.h"
#include "sd-event.h"
#include "sd-resolve.h"
#include "sd-network.h"

typedef struct Manager Manager;
typedef struct ServerAddress ServerAddress;
typedef struct ServerName ServerName;

struct ServerAddress {
        union sockaddr_union sockaddr;
        socklen_t socklen;
        LIST_FIELDS(ServerAddress, addresses);
};

struct ServerName {
        char *string;
        LIST_HEAD(ServerAddress, addresses);
        LIST_FIELDS(ServerName, names);
};

struct Manager {
        sd_event *event;
        sd_resolve *resolve;

        LIST_HEAD(ServerName, servers);

        RateLimit ratelimit;

        /* network */
        sd_event_source *network_event_source;
        sd_network_monitor *network_monitor;

        /* peer */
        sd_resolve_query *resolve_query;
        sd_event_source *event_receive;
        ServerName *current_server_name;
        ServerAddress *current_server_address;
        int server_socket;
        uint64_t packet_count;
        sd_event_source *event_timeout;

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
};

const struct ConfigPerfItem* timesyncd_gperf_lookup(const char *key, unsigned length);

int config_parse_servers(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
