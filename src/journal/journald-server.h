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

#include <inttypes.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "journal-file.h"
#include "hashmap.h"
#include "util.h"
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
        SPLIT_LOGIN,
        SPLIT_UID,
        SPLIT_NONE,
        _SPLIT_MAX,
        _SPLIT_INVALID = -1
} SplitMode;

typedef struct StdoutStream StdoutStream;

typedef struct Server {
        int epoll_fd;
        int signal_fd;
        int syslog_fd;
        int native_fd;
        int stdout_fd;
        int dev_kmsg_fd;

        JournalFile *runtime_journal;
        JournalFile *system_journal;
        Hashmap *user_journals;

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

        Storage storage;
        SplitMode split_mode;

        MMapCache *mmap;

        bool dev_kmsg_readable;

        uint64_t *kernel_seqnum;

        struct udev *udev;

        int sync_timer_fd;
        bool sync_scheduled;
} Server;

#define N_IOVEC_META_FIELDS 20
#define N_IOVEC_KERNEL_FIELDS 64
#define N_IOVEC_UDEV_FIELDS 32
#define N_IOVEC_OBJECT_FIELDS 11

void server_dispatch_message(Server *s, struct iovec *iovec, unsigned n, unsigned m, struct ucred *ucred, struct timeval *tv, const char *label, size_t label_len, const char *unit_id, int priority, pid_t object_pid);
void server_driver_message(Server *s, sd_id128_t message_id, const char *format, ...) _printf_attr_(3,4);

/* gperf lookup function */
const struct ConfigPerfItem* journald_gperf_lookup(const char *key, unsigned length);

int config_parse_storage(const char *unit, const char *filename, unsigned line, const char *section, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

const char *storage_to_string(Storage s) _const_;
Storage storage_from_string(const char *s) _pure_;

int config_parse_split_mode(const char *unit, const char *filename, unsigned line, const char *section, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

const char *split_mode_to_string(SplitMode s) _const_;
SplitMode split_mode_from_string(const char *s) _pure_;

void server_fix_perms(Server *s, JournalFile *f, uid_t uid);
bool shall_try_append_again(JournalFile *f, int r);
int server_init(Server *s);
void server_done(Server *s);
void server_sync(Server *s);
void server_vacuum(Server *s);
void server_rotate(Server *s);
int server_schedule_sync(Server *s, int priority);
int server_flush_to_var(Server *s);
int process_event(Server *s, struct epoll_event *ev);
void server_maybe_append_tags(Server *s);
