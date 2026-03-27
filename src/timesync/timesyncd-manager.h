/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_GNUTLS
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#endif

#include "list.h"
#include "ratelimit.h"
#include "time-util.h"
#include "timesyncd-forward.h"
#include "timesyncd-ntp-extension.h"
#include "timesyncd-ntp-message.h"
#include "timesyncd-ntske-protocol.h"

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
        LIST_HEAD(ServerName, ntske_servers);

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

        /* NTSKE */
        bool ntske;
        bool ntske_done;
        int ntske_server_socket;
        int handshake;

        sd_resolve_query *resolve_query_ntske;
        sd_event_source *ntske_event_receive;

        ServerName *current_ntske_server_name;
        ServerAddress *current_ntske_server_address;

        NTSKEPacket *ntske_packet;

        uint8_t nonce[NTS_NONCE_SIZE];
        uint8_t uid[NTS_UID_SIZE];

        uint16_t port;
        uint16_t next_protocol;
        uint16_t aead_algorithm;
        uint8_t c2s_key[NTS_KE_KEY_SIZE_MAX];
        uint8_t s2c_key[NTS_KE_KEY_SIZE_MAX];

        size_t c2s_key_size;
        size_t s2c_key_size;

        NTSCookie *cookies;
        size_t n_cookies;

#if HAVE_GNUTLS
        gnutls_session_t tls_session;
        gnutls_priority_t priority_cache;
        gnutls_certificate_credentials_t cert_cred;

        gnutls_aead_cipher_hd_t c2s_hd;
        gnutls_aead_cipher_hd_t s2c_hd;
#endif

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

void manager_set_ntske_server_name(Manager *m, ServerName *n);
void manager_set_ntske_server_address(Manager *m, ServerAddress *a);

int manager_connect(Manager *m);
void manager_disconnect(Manager *m);

int manager_setup_save_time_event(Manager *m);

int bus_manager_emit_ntp_server_changed(Manager *m);
