/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <resolv.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <time.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "dns-domain.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "list.h"
#include "log.h"
#include "missing.h"
#include "network-util.h"
#include "ratelimit.h"
#include "resolve-private.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "timesyncd-conf.h"
#include "timesyncd-manager.h"
#include "util.h"

#ifndef ADJ_SETOFFSET
#define ADJ_SETOFFSET                   0x0100  /* add 'time' to current time */
#endif

/* expected accuracy of time synchronization; used to adjust the poll interval */
#define NTP_ACCURACY_SEC                0.2

/*
 * Maximum delta in seconds which the system clock is gradually adjusted
 * (slewed) to approach the network time. Deltas larger that this are set by
 * letting the system time jump. The kernel's limit for adjtime is 0.5s.
 */
#define NTP_MAX_ADJUST                  0.4

/* Default of maximum acceptable root distance in microseconds. */
#define NTP_MAX_ROOT_DISTANCE           (5 * USEC_PER_SEC)

/* Maximum number of missed replies before selecting another source. */
#define NTP_MAX_MISSED_REPLIES          2

#define RETRY_USEC (30*USEC_PER_SEC)
#define RATELIMIT_INTERVAL_USEC (10*USEC_PER_SEC)
#define RATELIMIT_BURST 10

#define TIMEOUT_USEC (10*USEC_PER_SEC)

static int manager_arm_timer(Manager *m, usec_t next);
static int manager_clock_watch_setup(Manager *m);
static int manager_listen_setup(Manager *m);
static void manager_listen_stop(Manager *m);

static double ntp_ts_short_to_d(const struct ntp_ts_short *ts) {
        return be16toh(ts->sec) + (be16toh(ts->frac) / 65536.0);
}

static double ntp_ts_to_d(const struct ntp_ts *ts) {
        return be32toh(ts->sec) + ((double)be32toh(ts->frac) / UINT_MAX);
}

static double ts_to_d(const struct timespec *ts) {
        return ts->tv_sec + (1.0e-9 * ts->tv_nsec);
}

static int manager_timeout(sd_event_source *source, usec_t usec, void *userdata) {
        _cleanup_free_ char *pretty = NULL;
        Manager *m = userdata;

        assert(m);
        assert(m->current_server_name);
        assert(m->current_server_address);

        server_address_pretty(m->current_server_address, &pretty);
        log_info("Timed out waiting for reply from %s (%s).", strna(pretty), m->current_server_name->string);

        return manager_connect(m);
}

static int manager_send_request(Manager *m) {
        _cleanup_free_ char *pretty = NULL;
        struct ntp_msg ntpmsg = {
                /*
                 * "The client initializes the NTP message header, sends the request
                 * to the server, and strips the time of day from the Transmit
                 * Timestamp field of the reply.  For this purpose, all the NTP
                 * header fields are set to 0, except the Mode, VN, and optional
                 * Transmit Timestamp fields."
                 */
                .field = NTP_FIELD(0, 4, NTP_MODE_CLIENT),
        };
        ssize_t len;
        int r;

        assert(m);
        assert(m->current_server_name);
        assert(m->current_server_address);

        m->event_timeout = sd_event_source_unref(m->event_timeout);

        r = manager_listen_setup(m);
        if (r < 0)
                return log_warning_errno(r, "Failed to setup connection socket: %m");

        /*
         * Set transmit timestamp, remember it; the server will send that back
         * as the origin timestamp and we have an indication that this is the
         * matching answer to our request.
         *
         * The actual value does not matter, We do not care about the correct
         * NTP UINT_MAX fraction; we just pass the plain nanosecond value.
         */
        assert_se(clock_gettime(clock_boottime_or_monotonic(), &m->trans_time_mon) >= 0);
        assert_se(clock_gettime(CLOCK_REALTIME, &m->trans_time) >= 0);
        ntpmsg.trans_time.sec = htobe32(m->trans_time.tv_sec + OFFSET_1900_1970);
        ntpmsg.trans_time.frac = htobe32(m->trans_time.tv_nsec);

        server_address_pretty(m->current_server_address, &pretty);

        len = sendto(m->server_socket, &ntpmsg, sizeof(ntpmsg), MSG_DONTWAIT, &m->current_server_address->sockaddr.sa, m->current_server_address->socklen);
        if (len == sizeof(ntpmsg)) {
                m->pending = true;
                log_debug("Sent NTP request to %s (%s).", strna(pretty), m->current_server_name->string);
        } else {
                log_debug_errno(errno, "Sending NTP request to %s (%s) failed: %m", strna(pretty), m->current_server_name->string);
                return manager_connect(m);
        }

        /* re-arm timer with increasing timeout, in case the packets never arrive back */
        if (m->retry_interval > 0) {
                if (m->retry_interval < m->poll_interval_max_usec)
                        m->retry_interval *= 2;
        } else
                m->retry_interval = m->poll_interval_min_usec;

        r = manager_arm_timer(m, m->retry_interval);
        if (r < 0)
                return log_error_errno(r, "Failed to rearm timer: %m");

        m->missed_replies++;
        if (m->missed_replies > NTP_MAX_MISSED_REPLIES) {
                r = sd_event_add_time(
                                m->event,
                                &m->event_timeout,
                                clock_boottime_or_monotonic(),
                                now(clock_boottime_or_monotonic()) + TIMEOUT_USEC, 0,
                                manager_timeout, m);
                if (r < 0)
                        return log_error_errno(r, "Failed to arm timeout timer: %m");
        }

        return 0;
}

static int manager_timer(sd_event_source *source, usec_t usec, void *userdata) {
        Manager *m = userdata;

        assert(m);

        return manager_send_request(m);
}

static int manager_arm_timer(Manager *m, usec_t next) {
        int r;

        assert(m);

        if (next == 0) {
                m->event_timer = sd_event_source_unref(m->event_timer);
                return 0;
        }

        if (m->event_timer) {
                r = sd_event_source_set_time(m->event_timer, now(clock_boottime_or_monotonic()) + next);
                if (r < 0)
                        return r;

                return sd_event_source_set_enabled(m->event_timer, SD_EVENT_ONESHOT);
        }

        return sd_event_add_time(
                        m->event,
                        &m->event_timer,
                        clock_boottime_or_monotonic(),
                        now(clock_boottime_or_monotonic()) + next, 0,
                        manager_timer, m);
}

static int manager_clock_watch(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;

        assert(m);

        /* rearm timer */
        manager_clock_watch_setup(m);

        /* skip our own jumps */
        if (m->jumped) {
                m->jumped = false;
                return 0;
        }

        /* resync */
        log_debug("System time changed. Resyncing.");
        m->poll_resync = true;

        return manager_send_request(m);
}

/* wake up when the system time changes underneath us */
static int manager_clock_watch_setup(Manager *m) {
        int r;

        assert(m);

        m->event_clock_watch = sd_event_source_unref(m->event_clock_watch);
        safe_close(m->clock_watch_fd);

        m->clock_watch_fd = time_change_fd();
        if (m->clock_watch_fd < 0)
                return log_error_errno(m->clock_watch_fd, "Failed to create timerfd: %m");

        r = sd_event_add_io(m->event, &m->event_clock_watch, m->clock_watch_fd, EPOLLIN, manager_clock_watch, m);
        if (r < 0)
                return log_error_errno(r, "Failed to create clock watch event source: %m");

        return 0;
}

static int manager_adjust_clock(Manager *m, double offset, int leap_sec) {
        struct timex tmx = {};
        int r;

        assert(m);

        /*
         * For small deltas, tell the kernel to gradually adjust the system
         * clock to the NTP time, larger deltas are just directly set.
         */
        if (fabs(offset) < NTP_MAX_ADJUST) {
                tmx.modes = ADJ_STATUS | ADJ_NANO | ADJ_OFFSET | ADJ_TIMECONST | ADJ_MAXERROR | ADJ_ESTERROR;
                tmx.status = STA_PLL;
                tmx.offset = offset * NSEC_PER_SEC;
                tmx.constant = log2i(m->poll_interval_usec / USEC_PER_SEC) - 4;
                tmx.maxerror = 0;
                tmx.esterror = 0;
                log_debug("  adjust (slew): %+.3f sec", offset);
        } else {
                tmx.modes = ADJ_STATUS | ADJ_NANO | ADJ_SETOFFSET | ADJ_MAXERROR | ADJ_ESTERROR;

                /* ADJ_NANO uses nanoseconds in the microseconds field */
                tmx.time.tv_sec = (long)offset;
                tmx.time.tv_usec = (offset - tmx.time.tv_sec) * NSEC_PER_SEC;
                tmx.maxerror = 0;
                tmx.esterror = 0;

                /* the kernel expects -0.3s as {-1, 7000.000.000} */
                if (tmx.time.tv_usec < 0) {
                        tmx.time.tv_sec  -= 1;
                        tmx.time.tv_usec += NSEC_PER_SEC;
                }

                m->jumped = true;
                log_debug("  adjust (jump): %+.3f sec", offset);
        }

        /*
         * An unset STA_UNSYNC will enable the kernel's 11-minute mode,
         * which syncs the system time periodically to the RTC.
         *
         * In case the RTC runs in local time, never touch the RTC,
         * we have no way to properly handle daylight saving changes and
         * mobile devices moving between time zones.
         */
        if (m->rtc_local_time)
                tmx.status |= STA_UNSYNC;

        switch (leap_sec) {
        case 1:
                tmx.status |= STA_INS;
                break;
        case -1:
                tmx.status |= STA_DEL;
                break;
        }

        r = clock_adjtime(CLOCK_REALTIME, &tmx);
        if (r < 0)
                return -errno;

        /* If touch fails, there isn't much we can do. Maybe it'll work next time. */
        (void) touch("/var/lib/systemd/timesync/clock");
        (void) touch("/run/systemd/timesync/synchronized");

        m->drift_freq = tmx.freq;

        log_debug("  status       : %04i %s\n"
                  "  time now     : %"PRI_TIME".%03"PRI_USEC"\n"
                  "  constant     : %"PRI_TIMEX"\n"
                  "  offset       : %+.3f sec\n"
                  "  freq offset  : %+"PRI_TIMEX" (%+"PRI_TIMEX" ppm)\n",
                  tmx.status, tmx.status & STA_UNSYNC ? "unsync" : "sync",
                  tmx.time.tv_sec, tmx.time.tv_usec / NSEC_PER_MSEC,
                  tmx.constant,
                  (double)tmx.offset / NSEC_PER_SEC,
                  tmx.freq, tmx.freq / 65536);

        return 0;
}

static bool manager_sample_spike_detection(Manager *m, double offset, double delay) {
        unsigned i, idx_cur, idx_new, idx_min;
        double jitter;
        double j;

        assert(m);

        m->packet_count++;

        /* ignore initial sample */
        if (m->packet_count == 1)
                return false;

        /* store the current data in our samples array */
        idx_cur = m->samples_idx;
        idx_new = (idx_cur + 1) % ELEMENTSOF(m->samples);
        m->samples_idx = idx_new;
        m->samples[idx_new].offset = offset;
        m->samples[idx_new].delay = delay;

        /* calculate new jitter value from the RMS differences relative to the lowest delay sample */
        jitter = m->samples_jitter;
        for (idx_min = idx_cur, i = 0; i < ELEMENTSOF(m->samples); i++)
                if (m->samples[i].delay > 0 && m->samples[i].delay < m->samples[idx_min].delay)
                        idx_min = i;

        j = 0;
        for (i = 0; i < ELEMENTSOF(m->samples); i++)
                j += pow(m->samples[i].offset - m->samples[idx_min].offset, 2);
        m->samples_jitter = sqrt(j / (ELEMENTSOF(m->samples) - 1));

        /* ignore samples when resyncing */
        if (m->poll_resync)
                return false;

        /* always accept offset if we are farther off than the round-trip delay */
        if (fabs(offset) > delay)
                return false;

        /* we need a few samples before looking at them */
        if (m->packet_count < 4)
                return false;

        /* do not accept anything worse than the maximum possible error of the best sample */
        if (fabs(offset) > m->samples[idx_min].delay)
                return true;

        /* compare the difference between the current offset to the previous offset and jitter */
        return fabs(offset - m->samples[idx_cur].offset) > 3 * jitter;
}

static void manager_adjust_poll(Manager *m, double offset, bool spike) {
        assert(m);

        if (m->poll_resync) {
                m->poll_interval_usec = m->poll_interval_min_usec;
                m->poll_resync = false;
                return;
        }

        /* set to minimal poll interval */
        if (!spike && fabs(offset) > NTP_ACCURACY_SEC) {
                m->poll_interval_usec = m->poll_interval_min_usec;
                return;
        }

        /* increase polling interval */
        if (fabs(offset) < NTP_ACCURACY_SEC * 0.25) {
                if (m->poll_interval_usec < m->poll_interval_max_usec)
                        m->poll_interval_usec *= 2;
                return;
        }

        /* decrease polling interval */
        if (spike || fabs(offset) > NTP_ACCURACY_SEC * 0.75) {
                if (m->poll_interval_usec > m->poll_interval_min_usec)
                        m->poll_interval_usec /= 2;
                return;
        }
}

static int manager_receive_response(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        struct ntp_msg ntpmsg;

        struct iovec iov = {
                .iov_base = &ntpmsg,
                .iov_len = sizeof(ntpmsg),
        };
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(struct timeval))];
        } control;
        union sockaddr_union server_addr;
        struct msghdr msghdr = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
                .msg_name = &server_addr,
                .msg_namelen = sizeof(server_addr),
        };
        struct cmsghdr *cmsg;
        struct timespec *recv_time = NULL;
        ssize_t len;
        double origin, receive, trans, dest;
        double delay, offset;
        double root_distance;
        bool spike;
        int leap_sec;
        int r;

        assert(source);
        assert(m);

        if (revents & (EPOLLHUP|EPOLLERR)) {
                log_warning("Server connection returned error.");
                return manager_connect(m);
        }

        len = recvmsg(fd, &msghdr, MSG_DONTWAIT);
        if (len < 0) {
                if (errno == EAGAIN)
                        return 0;

                log_warning("Error receiving message. Disconnecting.");
                return manager_connect(m);
        }

        /* Too short or too long packet? */
        if (iov.iov_len < sizeof(struct ntp_msg) || (msghdr.msg_flags & MSG_TRUNC)) {
                log_warning("Invalid response from server. Disconnecting.");
                return manager_connect(m);
        }

        if (!m->current_server_name ||
            !m->current_server_address ||
            !sockaddr_equal(&server_addr, &m->current_server_address->sockaddr)) {
                log_debug("Response from unknown server.");
                return 0;
        }

        CMSG_FOREACH(cmsg, &msghdr) {
                if (cmsg->cmsg_level != SOL_SOCKET)
                        continue;

                switch (cmsg->cmsg_type) {
                case SCM_TIMESTAMPNS:
                        recv_time = (struct timespec *) CMSG_DATA(cmsg);
                        break;
                }
        }
        if (!recv_time)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid packet timestamp.");

        if (!m->pending) {
                log_debug("Unexpected reply. Ignoring.");
                return 0;
        }

        m->missed_replies = 0;

        /* check our "time cookie" (we just stored nanoseconds in the fraction field) */
        if (be32toh(ntpmsg.origin_time.sec) != m->trans_time.tv_sec + OFFSET_1900_1970 ||
            be32toh(ntpmsg.origin_time.frac) != (unsigned long) m->trans_time.tv_nsec) {
                log_debug("Invalid reply; not our transmit time. Ignoring.");
                return 0;
        }

        m->event_timeout = sd_event_source_unref(m->event_timeout);

        if (be32toh(ntpmsg.recv_time.sec) < TIME_EPOCH + OFFSET_1900_1970 ||
            be32toh(ntpmsg.trans_time.sec) < TIME_EPOCH + OFFSET_1900_1970) {
                log_debug("Invalid reply, returned times before epoch. Ignoring.");
                return manager_connect(m);
        }

        if (NTP_FIELD_LEAP(ntpmsg.field) == NTP_LEAP_NOTINSYNC ||
            ntpmsg.stratum == 0 || ntpmsg.stratum >= 16) {
                log_debug("Server is not synchronized. Disconnecting.");
                return manager_connect(m);
        }

        if (!IN_SET(NTP_FIELD_VERSION(ntpmsg.field), 3, 4)) {
                log_debug("Response NTPv%d. Disconnecting.", NTP_FIELD_VERSION(ntpmsg.field));
                return manager_connect(m);
        }

        if (NTP_FIELD_MODE(ntpmsg.field) != NTP_MODE_SERVER) {
                log_debug("Unsupported mode %d. Disconnecting.", NTP_FIELD_MODE(ntpmsg.field));
                return manager_connect(m);
        }

        root_distance = ntp_ts_short_to_d(&ntpmsg.root_delay) / 2 + ntp_ts_short_to_d(&ntpmsg.root_dispersion);
        if (root_distance > (double) m->max_root_distance_usec / (double) USEC_PER_SEC) {
                log_debug("Server has too large root distance. Disconnecting.");
                return manager_connect(m);
        }

        /* valid packet */
        m->pending = false;
        m->retry_interval = 0;

        /* Stop listening */
        manager_listen_stop(m);

        /* announce leap seconds */
        if (NTP_FIELD_LEAP(ntpmsg.field) & NTP_LEAP_PLUSSEC)
                leap_sec = 1;
        else if (NTP_FIELD_LEAP(ntpmsg.field) & NTP_LEAP_MINUSSEC)
                leap_sec = -1;
        else
                leap_sec = 0;

        /*
         * "Timestamp Name          ID   When Generated
         *  ------------------------------------------------------------
         *  Originate Timestamp     T1   time request sent by client
         *  Receive Timestamp       T2   time request received by server
         *  Transmit Timestamp      T3   time reply sent by server
         *  Destination Timestamp   T4   time reply received by client
         *
         *  The round-trip delay, d, and system clock offset, t, are defined as:
         *  d = (T4 - T1) - (T3 - T2)     t = ((T2 - T1) + (T3 - T4)) / 2"
         */
        origin = ts_to_d(&m->trans_time) + OFFSET_1900_1970;
        receive = ntp_ts_to_d(&ntpmsg.recv_time);
        trans = ntp_ts_to_d(&ntpmsg.trans_time);
        dest = ts_to_d(recv_time) + OFFSET_1900_1970;

        offset = ((receive - origin) + (trans - dest)) / 2;
        delay = (dest - origin) - (trans - receive);

        spike = manager_sample_spike_detection(m, offset, delay);

        manager_adjust_poll(m, offset, spike);

        log_debug("NTP response:\n"
                  "  leap         : %u\n"
                  "  version      : %u\n"
                  "  mode         : %u\n"
                  "  stratum      : %u\n"
                  "  precision    : %.6f sec (%d)\n"
                  "  root distance: %.6f sec\n"
                  "  reference    : %.4s\n"
                  "  origin       : %.3f\n"
                  "  receive      : %.3f\n"
                  "  transmit     : %.3f\n"
                  "  dest         : %.3f\n"
                  "  offset       : %+.3f sec\n"
                  "  delay        : %+.3f sec\n"
                  "  packet count : %"PRIu64"\n"
                  "  jitter       : %.3f%s\n"
                  "  poll interval: " USEC_FMT "\n",
                  NTP_FIELD_LEAP(ntpmsg.field),
                  NTP_FIELD_VERSION(ntpmsg.field),
                  NTP_FIELD_MODE(ntpmsg.field),
                  ntpmsg.stratum,
                  exp2(ntpmsg.precision), ntpmsg.precision,
                  root_distance,
                  ntpmsg.stratum == 1 ? ntpmsg.refid : "n/a",
                  origin - OFFSET_1900_1970,
                  receive - OFFSET_1900_1970,
                  trans - OFFSET_1900_1970,
                  dest - OFFSET_1900_1970,
                  offset, delay,
                  m->packet_count,
                  m->samples_jitter, spike ? " spike" : "",
                  m->poll_interval_usec / USEC_PER_SEC);

        if (!spike) {
                m->sync = true;
                r = manager_adjust_clock(m, offset, leap_sec);
                if (r < 0)
                        log_error_errno(r, "Failed to call clock_adjtime(): %m");
        }

        /* Save NTP response */
        m->ntpmsg = ntpmsg;
        m->origin_time = m->trans_time;
        m->dest_time = *recv_time;
        m->spike = spike;

        log_debug("interval/delta/delay/jitter/drift " USEC_FMT "s/%+.3fs/%.3fs/%.3fs/%+"PRIi64"ppm%s",
                  m->poll_interval_usec / USEC_PER_SEC, offset, delay, m->samples_jitter, m->drift_freq / 65536,
                  spike ? " (ignored)" : "");

        (void) sd_bus_emit_properties_changed(m->bus, "/org/freedesktop/timesync1", "org.freedesktop.timesync1.Manager", "NTPMessage", NULL);

        if (!m->good) {
                _cleanup_free_ char *pretty = NULL;

                m->good = true;

                server_address_pretty(m->current_server_address, &pretty);
                /* "for the first time", as further successful syncs will not be logged. */
                log_info("Synchronized to time server for the first time %s (%s).", strna(pretty), m->current_server_name->string);
                sd_notifyf(false, "STATUS=Synchronized to time server for the first time %s (%s).", strna(pretty), m->current_server_name->string);
        }

        r = manager_arm_timer(m, m->poll_interval_usec);
        if (r < 0)
                return log_error_errno(r, "Failed to rearm timer: %m");

        return 0;
}

static int manager_listen_setup(Manager *m) {
        union sockaddr_union addr = {};
        int r;

        assert(m);

        if (m->server_socket >= 0)
                return 0;

        assert(!m->event_receive);
        assert(m->current_server_address);

        addr.sa.sa_family = m->current_server_address->sockaddr.sa.sa_family;

        m->server_socket = socket(addr.sa.sa_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (m->server_socket < 0)
                return -errno;

        r = bind(m->server_socket, &addr.sa, m->current_server_address->socklen);
        if (r < 0)
                return -errno;

        r = setsockopt_int(m->server_socket, SOL_SOCKET, SO_TIMESTAMPNS, true);
        if (r < 0)
                return r;

        (void) setsockopt_int(m->server_socket, IPPROTO_IP, IP_TOS, IPTOS_LOWDELAY);

        return sd_event_add_io(m->event, &m->event_receive, m->server_socket, EPOLLIN, manager_receive_response, m);
}

static void manager_listen_stop(Manager *m) {
        assert(m);

        m->event_receive = sd_event_source_unref(m->event_receive);
        m->server_socket = safe_close(m->server_socket);
}

static int manager_begin(Manager *m) {
        _cleanup_free_ char *pretty = NULL;
        int r;

        assert(m);
        assert_return(m->current_server_name, -EHOSTUNREACH);
        assert_return(m->current_server_address, -EHOSTUNREACH);

        m->good = false;
        m->missed_replies = NTP_MAX_MISSED_REPLIES;
        if (m->poll_interval_usec == 0)
                m->poll_interval_usec = m->poll_interval_min_usec;

        server_address_pretty(m->current_server_address, &pretty);
        log_debug("Connecting to time server %s (%s).", strna(pretty), m->current_server_name->string);
        sd_notifyf(false, "STATUS=Connecting to time server %s (%s).", strna(pretty), m->current_server_name->string);

        r = manager_clock_watch_setup(m);
        if (r < 0)
                return r;

        return manager_send_request(m);
}

void manager_set_server_name(Manager *m, ServerName *n) {
        assert(m);

        if (m->current_server_name == n)
                return;

        m->current_server_name = n;
        m->current_server_address = NULL;

        manager_disconnect(m);

        if (n)
                log_debug("Selected server %s.", n->string);
}

void manager_set_server_address(Manager *m, ServerAddress *a) {
        assert(m);

        if (m->current_server_address == a)
                return;

        m->current_server_address = a;
        /* If a is NULL, we are just clearing the address, without
         * changing the name. Keep the existing name in that case. */
        if (a)
                m->current_server_name = a->name;

        manager_disconnect(m);

        if (a) {
                _cleanup_free_ char *pretty = NULL;
                server_address_pretty(a, &pretty);
                log_debug("Selected address %s of server %s.", strna(pretty), a->name->string);
        }
}

static int manager_resolve_handler(sd_resolve_query *q, int ret, const struct addrinfo *ai, Manager *m) {
        int r;

        assert(q);
        assert(m);
        assert(m->current_server_name);

        m->resolve_query = sd_resolve_query_unref(m->resolve_query);

        if (ret != 0) {
                log_debug("Failed to resolve %s: %s", m->current_server_name->string, gai_strerror(ret));

                /* Try next host */
                return manager_connect(m);
        }

        for (; ai; ai = ai->ai_next) {
                _cleanup_free_ char *pretty = NULL;
                ServerAddress *a;

                assert(ai->ai_addr);
                assert(ai->ai_addrlen >= offsetof(struct sockaddr, sa_data));

                if (!IN_SET(ai->ai_addr->sa_family, AF_INET, AF_INET6)) {
                        log_warning("Unsuitable address protocol for %s", m->current_server_name->string);
                        continue;
                }

                r = server_address_new(m->current_server_name, &a, (const union sockaddr_union*) ai->ai_addr, ai->ai_addrlen);
                if (r < 0)
                        return log_error_errno(r, "Failed to add server address: %m");

                server_address_pretty(a, &pretty);
                log_debug("Resolved address %s for %s.", pretty, m->current_server_name->string);
        }

        if (!m->current_server_name->addresses) {
                log_error("Failed to find suitable address for host %s.", m->current_server_name->string);

                /* Try next host */
                return manager_connect(m);
        }

        manager_set_server_address(m, m->current_server_name->addresses);

        return manager_begin(m);
}

static int manager_retry_connect(sd_event_source *source, usec_t usec, void *userdata) {
        Manager *m = userdata;

        assert(m);

        return manager_connect(m);
}

int manager_connect(Manager *m) {
        int r;

        assert(m);

        manager_disconnect(m);

        m->event_retry = sd_event_source_unref(m->event_retry);
        if (!ratelimit_below(&m->ratelimit)) {
                log_debug("Delaying attempts to contact servers.");

                r = sd_event_add_time(m->event, &m->event_retry, clock_boottime_or_monotonic(), now(clock_boottime_or_monotonic()) + RETRY_USEC, 0, manager_retry_connect, m);
                if (r < 0)
                        return log_error_errno(r, "Failed to create retry timer: %m");

                return 0;
        }

        /* If we already are operating on some address, switch to the
         * next one. */
        if (m->current_server_address && m->current_server_address->addresses_next)
                manager_set_server_address(m, m->current_server_address->addresses_next);
        else {
                struct addrinfo hints = {
                        .ai_flags = AI_NUMERICSERV|AI_ADDRCONFIG,
                        .ai_socktype = SOCK_DGRAM,
                };

                /* Hmm, we are through all addresses, let's look for the next host instead */
                if (m->current_server_name && m->current_server_name->names_next)
                        manager_set_server_name(m, m->current_server_name->names_next);
                else {
                        ServerName *f;
                        bool restart = true;

                        /* Our current server name list is exhausted,
                         * let's find the next one to iterate. First
                         * we try the system list, then the link list.
                         * After having processed the link list we
                         * jump back to the system list. However, if
                         * both lists are empty, we change to the
                         * fallback list. */
                        if (!m->current_server_name || m->current_server_name->type == SERVER_LINK) {
                                f = m->system_servers;
                                if (!f)
                                        f = m->link_servers;
                        } else {
                                f = m->link_servers;
                                if (!f)
                                        f = m->system_servers;
                                else
                                        restart = false;
                        }

                        if (!f)
                                f = m->fallback_servers;

                        if (!f) {
                                manager_set_server_name(m, NULL);
                                log_debug("No server found.");
                                return 0;
                        }

                        if (restart && !m->exhausted_servers && m->poll_interval_usec) {
                                log_debug("Waiting after exhausting servers.");
                                r = sd_event_add_time(m->event, &m->event_retry, clock_boottime_or_monotonic(), now(clock_boottime_or_monotonic()) + m->poll_interval_usec, 0, manager_retry_connect, m);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to create retry timer: %m");

                                m->exhausted_servers = true;

                                /* Increase the polling interval */
                                if (m->poll_interval_usec < m->poll_interval_max_usec)
                                        m->poll_interval_usec *= 2;

                                return 0;
                        }

                        m->exhausted_servers = false;

                        manager_set_server_name(m, f);
                }

                /* Tell the resolver to reread /etc/resolv.conf, in
                 * case it changed. */
                res_init();

                /* Flush out any previously resolved addresses */
                server_name_flush_addresses(m->current_server_name);

                log_debug("Resolving %s...", m->current_server_name->string);

                r = resolve_getaddrinfo(m->resolve, &m->resolve_query, m->current_server_name->string, "123", &hints, manager_resolve_handler, NULL, m);
                if (r < 0)
                        return log_error_errno(r, "Failed to create resolver: %m");

                return 1;
        }

        r = manager_begin(m);
        if (r < 0)
                return r;

        return 1;
}

void manager_disconnect(Manager *m) {
        assert(m);

        m->resolve_query = sd_resolve_query_unref(m->resolve_query);

        m->event_timer = sd_event_source_unref(m->event_timer);

        manager_listen_stop(m);

        m->event_clock_watch = sd_event_source_unref(m->event_clock_watch);
        m->clock_watch_fd = safe_close(m->clock_watch_fd);

        m->event_timeout = sd_event_source_unref(m->event_timeout);

        sd_notifyf(false, "STATUS=Idle.");
}

void manager_flush_server_names(Manager  *m, ServerType t) {
        assert(m);

        if (t == SERVER_SYSTEM)
                while (m->system_servers)
                        server_name_free(m->system_servers);

        if (t == SERVER_LINK)
                while (m->link_servers)
                        server_name_free(m->link_servers);

        if (t == SERVER_FALLBACK)
                while (m->fallback_servers)
                        server_name_free(m->fallback_servers);
}

void manager_free(Manager *m) {
        if (!m)
                return;

        manager_disconnect(m);
        manager_flush_server_names(m, SERVER_SYSTEM);
        manager_flush_server_names(m, SERVER_LINK);
        manager_flush_server_names(m, SERVER_FALLBACK);

        sd_event_source_unref(m->event_retry);

        sd_event_source_unref(m->network_event_source);
        sd_network_monitor_unref(m->network_monitor);

        sd_resolve_unref(m->resolve);
        sd_event_unref(m->event);

        sd_bus_flush_close_unref(m->bus);

        free(m);
}

static int manager_network_read_link_servers(Manager *m) {
        _cleanup_strv_free_ char **ntp = NULL;
        ServerName *n, *nx;
        char **i;
        bool changed = false;
        int r;

        assert(m);

        r = sd_network_get_ntp(&ntp);
        if (r < 0) {
                if (r == -ENOMEM)
                        log_oom();
                else
                        log_debug_errno(r, "Failed to get link NTP servers: %m");
                goto clear;
        }

        LIST_FOREACH(names, n, m->link_servers)
                n->marked = true;

        STRV_FOREACH(i, ntp) {
                bool found = false;

                r = dns_name_is_valid_or_address(*i);
                if (r < 0) {
                        log_error_errno(r, "Failed to check validity of NTP server name or address '%s': %m", *i);
                        goto clear;
                } else if (r == 0) {
                        log_error("Invalid NTP server name or address, ignoring: %s", *i);
                        continue;
                }

                LIST_FOREACH(names, n, m->link_servers)
                        if (streq(n->string, *i)) {
                                n->marked = false;
                                found = true;
                                break;
                        }

                if (!found) {
                        r = server_name_new(m, NULL, SERVER_LINK, *i);
                        if (r < 0) {
                                log_oom();
                                goto clear;
                        }

                        changed = true;
                }
        }

        LIST_FOREACH_SAFE(names, n, nx, m->link_servers)
                if (n->marked) {
                        server_name_free(n);
                        changed = true;
                }

        return changed;

clear:
        manager_flush_server_names(m, SERVER_LINK);
        return r;
}

static bool manager_is_connected(Manager *m) {
        /* Return true when the manager is sending a request, resolving a server name, or
         * in a poll interval. */
        return m->server_socket >= 0 || m->resolve_query || m->event_timer;
}

static int manager_network_event_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        bool changed, connected, online;
        int r;

        assert(m);

        sd_network_monitor_flush(m->network_monitor);

        /* When manager_network_read_link_servers() failed, we assume that the servers are changed. */
        changed = manager_network_read_link_servers(m);

        /* check if the machine is online */
        online = network_is_online();

        /* check if the client is currently connected */
        connected = manager_is_connected(m);

        if (connected && !online) {
                log_info("No network connectivity, watching for changes.");
                manager_disconnect(m);

        } else if ((!connected || changed) && online) {
                log_info("Network configuration changed, trying to establish connection.");

                if (m->current_server_address)
                        r = manager_begin(m);
                else
                        r = manager_connect(m);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int manager_network_monitor_listen(Manager *m) {
        int r, fd, events;

        assert(m);

        r = sd_network_monitor_new(&m->network_monitor, NULL);
        if (r == -ENOENT) {
                log_info("systemd does not appear to be running, not listening for systemd-networkd events.");
                return 0;
        }
        if (r < 0)
                return r;

        fd = sd_network_monitor_get_fd(m->network_monitor);
        if (fd < 0)
                return fd;

        events = sd_network_monitor_get_events(m->network_monitor);
        if (events < 0)
                return events;

        r = sd_event_add_io(m->event, &m->network_event_source, fd, events, manager_network_event_handler, m);
        if (r < 0)
                return r;

        return 0;
}

int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        m->max_root_distance_usec = NTP_MAX_ROOT_DISTANCE;
        m->poll_interval_min_usec = NTP_POLL_INTERVAL_MIN_USEC;
        m->poll_interval_max_usec = NTP_POLL_INTERVAL_MAX_USEC;

        m->server_socket = m->clock_watch_fd = -1;

        RATELIMIT_INIT(m->ratelimit, RATELIMIT_INTERVAL_USEC, RATELIMIT_BURST);

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        (void) sd_event_add_signal(m->event, NULL, SIGTERM, NULL,  NULL);
        (void) sd_event_add_signal(m->event, NULL, SIGINT, NULL, NULL);

        (void) sd_event_set_watchdog(m->event, true);

        r = sd_resolve_default(&m->resolve);
        if (r < 0)
                return r;

        r = sd_resolve_attach_event(m->resolve, m->event, 0);
        if (r < 0)
                return r;

        r = manager_network_monitor_listen(m);
        if (r < 0)
                return r;

        (void) manager_network_read_link_servers(m);

        *ret = TAKE_PTR(m);

        return 0;
}
