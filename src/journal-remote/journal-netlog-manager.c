/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Susant Sahani

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

#include "util.h"
#include "socket-util.h"
#include "conf-parser.h"
#include "sd-daemon.h"
#include "network-util.h"
#include "capability.h"
#include "signal-util.h"
#include "mkdir.h"
#include "fileio.h"
#include "journal-internal.h"
#include "journal-netlog-manager.h"

#define JOURNAL_SEND_POLL_TIMEOUT (10 * USEC_PER_SEC)

/* Default severity LOG_NOTICE */
#define JOURNAL_DEFAULT_SEVERITY LOG_PRI(LOG_NOTICE)

/* Default facility LOG_USER */
#define JOURNAL_DEFAULT_FACILITY LOG_FAC(LOG_USER)

static int parse_field(const void *data, size_t length, const char *field, char **target) {
        size_t fl, nl;
        void *buf;

        assert(data);
        assert(field);
        assert(target);

        fl = strlen(field);
        if (length < fl)
                return 0;

        if (memcmp(data, field, fl))
                return 0;

        nl = length - fl;
        buf = malloc(nl+1);
        if (!buf)
                return -ENOMEM;

        memcpy(buf, (const char*) data + fl, nl);
        ((char*)buf)[nl] = 0;

        free(*target);
        *target = buf;

        return 1;
}

static int manager_read_journal_input(Manager *m) {
        _cleanup_free_ char *facility = NULL, *identifier = NULL,
                *priority = NULL, *message = NULL, *pid = NULL,
                *hostname = NULL;
        unsigned sev = JOURNAL_DEFAULT_SEVERITY;
        unsigned fac = JOURNAL_DEFAULT_FACILITY;
        struct timeval tv;
        usec_t realtime;
        const void *data;
        size_t length;
        int r;

        assert(m);
        assert(m->journal);

        JOURNAL_FOREACH_DATA_RETVAL(m->journal, data, length, r) {

                r = parse_field(data, length, "PRIORITY=", &priority);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "SYSLOG_FACILITY=", &facility);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "_HOSTNAME=", &hostname);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "SYSLOG_IDENTIFIER=", &identifier);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "_PID=", &pid);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "MESSAGE=", &message);
                if (r < 0)
                        return r;
        }

        r = sd_journal_get_realtime_usec(m->journal, &realtime);
        if (r < 0)
                log_warning_errno(r, "Failed to rerieve realtime from journal: %m");
        else {
                tv.tv_sec = realtime / USEC_PER_SEC;
                tv.tv_usec = realtime % USEC_PER_SEC;
        }

        if (facility) {
                r = safe_atou(facility, &fac);
                if (r < 0)
                        log_debug("Failed to parse syslog facility: %s", facility);

                if (fac >= LOG_NFACILITIES)
                        fac = JOURNAL_DEFAULT_FACILITY;
        }

        if (priority) {
                r = safe_atou(priority, &sev);
                if (r < 0)
                        log_debug("Failed to parse syslog priority: %s", priority);

                if (sev > LOG_DEBUG)
                        sev = JOURNAL_DEFAULT_SEVERITY;
        }

        return manager_push_to_network(m, sev, fac, identifier,
                                       message, hostname, pid, r >= 0 ? &tv : NULL);
}

static int update_cursor_state(Manager *m) {
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(m);

        if (!m->state_file || !m->last_cursor)
                return 0;

        r = fopen_temporary(m->state_file, &f, &temp_path);
        if (r < 0)
                goto finish;

        fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "LAST_CURSOR=%s\n",
                m->last_cursor);

        r = fflush_and_check(f);
        if (r < 0)
                goto finish;

        if (rename(temp_path, m->state_file) < 0) {
                r = -errno;
                goto finish;
        }

 finish:
        if (r < 0)
                log_error_errno(r, "Failed to save state %s: %m", m->state_file);

        if (temp_path)
                (void) unlink(temp_path);

        return r;
}

static int load_cursor_state(Manager *m) {
        int r;

        assert(m);

        if (!m->state_file)
                return 0;

        r = parse_env_file(m->state_file, NEWLINE, "LAST_CURSOR", &m->last_cursor, NULL);
        if (r < 0 && r != -ENOENT)
                return r;

        log_debug("Last cursor was %s.", m->last_cursor ? m->last_cursor : "not available");

        return 0;
}

static int process_journal_input(Manager *m) {
        int r;

        assert(m);
        assert(m->journal);

        while (true) {
                r = sd_journal_next(m->journal);
                if (r < 0) {
                        log_error_errno(r, "Failed to get next entry: %m");
                        return r;
                }

                if (r == 0)
                        break;

                r = manager_read_journal_input(m);
                if (r < 0) {
                        /* Can't send the message. Seek one entry back. */
                        r = sd_journal_previous(m->journal);
                        if (r < 0)
                                log_error_errno(r, "Failed to iterate through journal: %m");

                        break;
                }
        }

        r = sd_journal_get_cursor(m->journal, &m->current_cursor);
        if (r < 0)
                return log_error_errno(r, "Failed to get cursor: %m");

        free(m->last_cursor);
        m->last_cursor = m->current_cursor;
        m->current_cursor = NULL;

        return update_cursor_state(m);
}

static int manager_journal_event_handler(sd_event_source *event, int fd, uint32_t revents, void *userp) {
        Manager *m = userp;
        int r;

        if (revents & EPOLLHUP) {
                log_debug("Received HUP");
                return 0;
        }

        if (!(revents & EPOLLIN)) {
                log_warning("Unexpected poll event %"PRIu32".", revents);
                return -EINVAL;
        }

        r = sd_journal_process(m->journal);
        if (r < 0) {
                log_error_errno(r, "Failed to process journal: %m");
                manager_disconnect(m);
                return r;
        }

        if (r == SD_JOURNAL_NOP)
                return 0;

        return process_journal_input(m);
}

static void close_journal_input(Manager *m) {
        assert(m);

        if (m->journal) {
                log_debug("Closing journal input.");

                sd_journal_close(m->journal);
                m->journal = NULL;
        }

        m->timeout = 0;
}

static int manager_signal_event_handler(sd_event_source *event, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = userdata;

        assert(m);

        log_received_signal(LOG_INFO, si);

        manager_disconnect(m);

        sd_event_exit(m->event, 0);

        return 0;
}

static int manager_journal_monitor_listen(Manager *m) {
        int r, events;

        assert(m);

        r = sd_journal_open(&m->journal, SD_JOURNAL_LOCAL_ONLY);
        if (r < 0) {
                log_error_errno(r, "Failed to open journal: %m");
                return r;
        }

        sd_journal_set_data_threshold(m->journal, 0);

        m->journal_watch_fd  = sd_journal_get_fd(m->journal);
        if (m->journal_watch_fd  < 0)
                return log_error_errno(m->journal_watch_fd, "sd_journal_get_fd failed: %m");

        events = sd_journal_get_events(m->journal);

        r = sd_journal_reliable_fd(m->journal);
        assert(r >= 0);
        if (r > 0)
                m->timeout = -1;
        else
                m->timeout = JOURNAL_SEND_POLL_TIMEOUT;

        r = sd_event_add_io(m->event, &m->event_journal_input, m->journal_watch_fd,
                            events, manager_journal_event_handler, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register input event: %m");

        /* ignore failure */
        if (!m->last_cursor)
                (void) load_cursor_state(m);

        if (m->last_cursor) {
                r = sd_journal_seek_cursor(m->journal, m->last_cursor);
                if (r < 0)
                        return log_error_errno(r, "Failed to seek to cursor %s: %m",
                                               m->last_cursor);
        }

        return 0;
}

int manager_connect(Manager *m) {
        int r;

        assert(m);

        manager_disconnect(m);

        r = manager_open_network_socket(m);
        if (r < 0)
                return r;

        r = manager_journal_monitor_listen(m);
        if (r < 0)
                return r;

        return 0;
}

void manager_disconnect(Manager *m) {
        assert(m);

        close_journal_input(m);

        manager_close_network_socket(m);

        m->event_journal_input = sd_event_source_unref(m->event_journal_input);

        sd_notifyf(false, "STATUS=Idle.");
}

static int manager_network_event_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        bool connected, online;
        int r;

        assert(m);

        sd_network_monitor_flush(m->network_monitor);

        /* check if the machine is online */
        online = network_is_online();

        /* check if the socket is currently open*/
        connected = m->socket >= 0;

        if (connected && !online) {
                log_info("No network connectivity, watching for changes.");
                manager_disconnect(m);

        } else if (!connected && online) {
                log_info("Network configuration changed, trying to establish connection.");

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

void manager_free(Manager *m) {
        if (!m)
                return;

        manager_disconnect(m);

        free(m->last_cursor);
        free(m->current_cursor);

        free(m->state_file);

        sd_event_source_unref(m->network_event_source);
        sd_network_monitor_unref(m->network_monitor);

        sd_event_source_unref(m->sigterm_event);
        sd_event_source_unref(m->sigint_event);

        sd_event_unref(m->event);

        free(m);
}

int manager_new(Manager **ret, const char *state_file, const char *cursor) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        m->socket = m->journal_watch_fd = -1;

        m->state_file = strdup(state_file);
        if (!m->state_file)
                return -ENOMEM;

        if (cursor) {
                m->last_cursor = strdup(cursor);
                if (!m->last_cursor)
                        return -ENOMEM;
        }

        r = sd_event_default(&m->event);
        if (r < 0)
                return log_error_errno(r, "sd_event_default failed: %m");

        assert_se(sigprocmask_many(SIG_BLOCK, SIGTERM, SIGINT, -1) == 0);

        r = sd_event_add_signal(m->event, NULL, SIGTERM, manager_signal_event_handler,  m);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, SIGINT, manager_signal_event_handler, m);
        if (r < 0)
                return r;

        sd_event_set_watchdog(m->event, true);

        r = manager_network_monitor_listen(m);
        if (r < 0)
                return r;

        *ret = m;
        m = NULL;

        return 0;
}
