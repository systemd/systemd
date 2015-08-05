/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <stdbool.h>
#include <sys/types.h>

#include "sd-event.h"
#include "journal-file.h"
#include "hashmap.h"
#include "audit.h"
#include "journald-rate-limit.h"
#include "list.h"

typedef enum Storage {
        STORAGE_AUTO,
        STORAGE_VOLATILE,
        STORAGE_PERSISTENT,
        STORAGE_NONE,
        _STORAGE_MAX,
        _STORAGE_INVALID = -1
} Storage;

typedef enum SplitMode {
        SPLIT_UID,
        SPLIT_LOGIN,
        SPLIT_NONE,
        _SPLIT_MAX,
        _SPLIT_INVALID = -1
} SplitMode;

typedef struct StdoutStream StdoutStream;

typedef struct Server {
        int syslog_fd;
        int native_fd;
        int stdout_fd;
        int dev_kmsg_fd;
        int audit_fd;
        int hostname_fd;

        sd_event *event;

        sd_event_source *syslog_event_source;
        sd_event_source *native_event_source;
        sd_event_source *stdout_event_source;
        sd_event_source *dev_kmsg_event_source;
        sd_event_source *audit_event_source;
        sd_event_source *sync_event_source;
        sd_event_source *sigusr1_event_source;
        sd_event_source *sigusr2_event_source;
        sd_event_source *sigterm_event_source;
        sd_event_source *sigint_event_source;
        sd_event_source *hostname_event_source;

        JournalFile *runtime_journal;
        JournalFile *system_journal;
        OrderedHashmap *user_journals;

        uint64_t seqnum;

        char *buffer;
        size_t buffer_size;

        JournalRateLimit *rate_limit;
        usec_t sync_interval_usec;
        usec_t rate_limit_interval;
        unsigned rate_limit_burst;

        JournalMetrics runtime_metrics;
        JournalMetrics system_metrics;

        bool compress;
        bool seal;

        bool forward_to_kmsg;
        bool forward_to_syslog;
        bool forward_to_console;
        bool forward_to_wall;

        unsigned n_forward_syslog_missed;
        usec_t last_warn_forward_syslog_missed;

        uint64_t cached_available_space;
        usec_t cached_available_space_timestamp;

        uint64_t var_available_timestamp;

        usec_t max_retention_usec;
        usec_t max_file_usec;
        usec_t oldest_file_usec;

        LIST_HEAD(StdoutStream, stdout_streams);
        unsigned n_stdout_streams;

        char *tty_path;

        int max_level_store;
        int max_level_syslog;
        int max_level_kmsg;
        int max_level_console;
        int max_level_wall;

        Storage storage;
        SplitMode split_mode;

        MMapCache *mmap;

        bool dev_kmsg_readable;

        uint64_t *kernel_seqnum;

        struct udev *udev;

        bool sync_scheduled;

        char machine_id_field[sizeof("_MACHINE_ID=") + 32];
        char boot_id_field[sizeof("_BOOT_ID=") + 32];
        char *hostname_field;

        /* Cached cgroup root, so that we don't have to query that all the time */
        char *cgroup_root;
} Server;

#define N_IOVEC_META_FIELDS 20
#define N_IOVEC_KERNEL_FIELDS 64
#define N_IOVEC_UDEV_FIELDS 32
#define N_IOVEC_OBJECT_FIELDS 12

void server_dispatch_message(Server *s, struct iovec *iovec, unsigned n, unsigned m, const struct ucred *ucred, const struct timeval *tv, const char *label, size_t label_len, const char *unit_id, int priority, pid_t object_pid);
void server_driver_message(Server *s, sd_id128_t message_id, const char *format, ...) _printf_(3,4);

/* gperf lookup function */
const struct ConfigPerfItem* journald_gperf_lookup(const char *key, unsigned length);

int config_parse_storage(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

const char *storage_to_string(Storage s) _const_;
Storage storage_from_string(const char *s) _pure_;

int config_parse_split_mode(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

const char *split_mode_to_string(SplitMode s) _const_;
SplitMode split_mode_from_string(const char *s) _pure_;

void server_fix_perms(Server *s, JournalFile *f, uid_t uid);
int server_init(Server *s);
void server_done(Server *s);
void server_sync(Server *s);
void server_vacuum(Server *s);
void server_rotate(Server *s);
int server_schedule_sync(Server *s, int priority);
int server_flush_to_var(Server *s);
void server_maybe_append_tags(Server *s);
int server_process_datagram(sd_event_source *es, int fd, uint32_t revents, void *userdata);
