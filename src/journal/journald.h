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
#include <sys/types.h>
#include <stdbool.h>

#include "journal-file.h"
#include "hashmap.h"
#include "util.h"
#include "audit.h"
#include "journal-rate-limit.h"
#include "list.h"

typedef enum Storage {
        STORAGE_AUTO,
        STORAGE_VOLATILE,
        STORAGE_PERSISTENT,
        STORAGE_NONE,
        _STORAGE_MAX,
        _STORAGE_INVALID = -1
} Storage;

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
        usec_t rate_limit_interval;
        unsigned rate_limit_burst;

        JournalMetrics runtime_metrics;
        JournalMetrics system_metrics;

        bool compress;
        bool seal;

        bool forward_to_kmsg;
        bool forward_to_syslog;
        bool forward_to_console;

        uint64_t cached_available_space;
        usec_t cached_available_space_timestamp;

        uint64_t var_available_timestamp;

        gid_t file_gid;
        bool file_gid_valid;

        LIST_HEAD(StdoutStream, stdout_streams);
        unsigned n_stdout_streams;

        char *tty_path;

        int max_level_store;
        int max_level_syslog;
        int max_level_kmsg;
        int max_level_console;

        Storage storage;

        MMapCache *mmap;

        bool dev_kmsg_readable;

        uint64_t *kernel_seqnum;

        struct udev *udev;
} Server;

#define N_IOVEC_META_FIELDS 17
#define N_IOVEC_KERNEL_FIELDS 64
#define N_IOVEC_UDEV_FIELDS 32

void server_dispatch_message(Server *s, struct iovec *iovec, unsigned n, unsigned m, struct ucred *ucred, struct timeval *tv, const char *label, size_t label_len, const char *unit_id, int priority);

void server_driver_message(Server *s, sd_id128_t message_id, const char *format, ...);

/* gperf lookup function */
const struct ConfigPerfItem* journald_gperf_lookup(const char *key, unsigned length);

int config_parse_storage(const char *filename, unsigned line, const char *section, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

const char *storage_to_string(Storage s);
Storage storage_from_string(const char *s);

void server_forward_console(Server *s, int priority, const char *identifier, const char *message, struct ucred *ucred);
