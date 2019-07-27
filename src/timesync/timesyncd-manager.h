/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <sys/timex.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-network.h"
#include "sd-resolve.h"

#include "list.h"
#include "ratelimit.h"
#include "time-util.h"
#include "timesyncd-ntp-message.h"

typedef struct Manager Manager;

#include "timesyncd-server.h"

/*
 * "A client MUST NOT under any conditions use a poll interval less
 * than 15 seconds."
 */
#define NTP_POLL_INTERVAL_MIN_USEC      (32 * USEC_PER_SEC)
#define NTP_POLL_INTERVAL_MAX_USEC      (2048 * USEC_PER_SEC)

struct Manager {
        sd_bus *bus;
        sd_event *event;
        sd_resolve *resolve;

        LIST_HEAD(ServerName, system_servers);
        LIST_HEAD(ServerName, link_servers);
        LIST_HEAD(ServerName, fallback_servers);

        bool have_fallbacks:1;

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
        usec_t poll_interval_min_usec;
        usec_t poll_interval_max_usec;
        bool poll_resync;

        /* history data */
        struct {
                double offset;
                double delay;
        } samples[8];
        unsigned samples_idx;
        double samples_jitter;
        usec_t max_root_distance_usec;

        /* last change */
        bool jumped;
        bool sync;
        int64_t drift_freq;

        /* watch for time changes */
        sd_event_source *event_clock_watch;
        int clock_watch_fd;

        /* Retry connections */
        sd_event_source *event_retry;

        /* RTC runs in local time, leave it alone */
        bool rtc_local_time;

        /* NTP response */
        struct ntp_msg ntpmsg;
        struct timespec origin_time, dest_time;
        bool spike;
};

int manager_new(Manager **ret);
void manager_free(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

void manager_set_server_name(Manager *m, ServerName *n);
void manager_set_server_address(Manager *m, ServerAddress *a);
void manager_flush_server_names(Manager *m, ServerType t);

int manager_connect(Manager *m);
void manager_disconnect(Manager *m);
