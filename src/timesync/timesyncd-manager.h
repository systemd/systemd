/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "list.h"
#include "ratelimit.h"
#include "time-util.h"
#include "timesyncd-forward.h"
#include "timesyncd-ntp-message.h"

/*
 * "A client MUST NOT under any conditions use a poll interval less
 * than 15 seconds."
 */
#define NTP_POLL_INTERVAL_MIN_USEC      (32 * USEC_PER_SEC)
#define NTP_POLL_INTERVAL_MAX_USEC      (2048 * USEC_PER_SEC)

#define NTP_RETRY_INTERVAL_MIN_USEC     (15 * USEC_PER_SEC)
#define NTP_RETRY_INTERVAL_MAX_USEC     (6 * 60 * USEC_PER_SEC) /* 6 minutes */

#define DEFAULT_CONNECTION_RETRY_USEC   (30 * USEC_PER_SEC)

#define DEFAULT_SAVE_TIME_INTERVAL_USEC (60 * USEC_PER_SEC)

typedef struct Manager {
        sd_bus *bus;
        sd_event *event;
        sd_resolve *resolve;

        LIST_HEAD(ServerName, system_servers);
        LIST_HEAD(ServerName, link_servers);
        LIST_HEAD(ServerName, runtime_servers);
        LIST_HEAD(ServerName, fallback_servers);

        RateLimit ratelimit;
        bool exhausted_servers;
        bool fallback_set; /* Indicate if FallbackNTP= is explicitly configured. */

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
        bool talking;

        /* PolicyKit */
        Hashmap *polkit_registry;

        /* last sent packet */
        struct timespec trans_time_mon;
        struct timespec trans_time;
        struct ntp_ts request_nonce;
        usec_t retry_interval;
        usec_t connection_retry_usec;
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
        usec_t root_distance_max_usec;

        /* last change */
        bool jumped;
        int64_t drift_freq;

        /* watch for time changes */
        sd_event_source *event_clock_watch;

        /* Retry connections */
        sd_event_source *event_retry;

        /* RTC runs in local time, leave it alone */
        bool rtc_local_time;

        /* NTP response */
        struct ntp_msg ntpmsg;
        struct timespec origin_time, dest_time;
        bool spike;

        /* Indicates whether we ever managed to set the local clock from NTP */
        bool synchronized;

        /* save time event */
        sd_event_source *event_save_time;
        usec_t save_time_interval_usec;

        /* Used to coalesce bus PropertiesChanged events */
        sd_event_source *deferred_ntp_server_event_source;
        unsigned ntp_server_change_mask;
} Manager;

int manager_new(Manager **ret);
Manager* manager_free(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

void manager_set_server_name(Manager *m, ServerName *n);
void manager_set_server_address(Manager *m, ServerAddress *a);
void manager_flush_server_names(Manager *m, ServerType t);
void manager_flush_runtime_servers(Manager *m);

int manager_connect(Manager *m);
void manager_disconnect(Manager *m);

int manager_setup_save_time_event(Manager *m);

int bus_manager_emit_ntp_server_changed(Manager *m);
