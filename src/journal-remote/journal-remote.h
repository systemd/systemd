/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"

#include "hashmap.h"
#include "journal-remote-parse.h"
#include "journal-remote-write.h"
#include "journal-vacuum.h"

#if HAVE_MICROHTTPD
#include "microhttpd-util.h"

typedef struct MHDDaemonWrapper MHDDaemonWrapper;

struct MHDDaemonWrapper {
        uint64_t fd;
        struct MHD_Daemon *daemon;

        sd_event_source *io_event;
        sd_event_source *timer_event;
};

MHDDaemonWrapper *MHDDaemonWrapper_free(MHDDaemonWrapper *d);
DEFINE_TRIVIAL_CLEANUP_FUNC(MHDDaemonWrapper*, MHDDaemonWrapper_free);
#endif

struct RemoteServer {
        RemoteSource **sources;
        size_t active;

        sd_event *event;
        sd_event_source *listen_event;

        Hashmap *writers;
        Writer *_single_writer;
        uint64_t event_count;

#if HAVE_MICROHTTPD
        Hashmap *daemons;
#endif
        const char *output;                    /* either the output file or directory */

        JournalWriteSplitMode split_mode;
        JournalFileFlags file_flags;
        bool check_trust;
        JournalMetrics metrics;
};
extern RemoteServer *journal_remote_server_global;

/* Used for MHD_OPTION_CONNECTION_MEMORY_LIMIT and header parsing cap */
#define JOURNAL_SERVER_MEMORY_MAX 128U * 1024U

int journal_remote_server_init(
                RemoteServer *s,
                const char *output,
                JournalWriteSplitMode split_mode,
                JournalFileFlags file_flags);

int journal_remote_get_writer(RemoteServer *s, const char *host, Writer **writer);

int journal_remote_add_source(RemoteServer *s, int fd, char *name, bool own_name);
int journal_remote_add_raw_socket(RemoteServer *s, int fd);
int journal_remote_handle_raw_source(
                sd_event_source *event,
                int fd,
                uint32_t revents,
                RemoteServer *s);

void journal_remote_server_destroy(RemoteServer *s);
