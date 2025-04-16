/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct StdoutStream StdoutStream;

#include "fdset.h"
#include "journald-server.h"
#include "journald-sync.h"

typedef enum StdoutStreamState {
        STDOUT_STREAM_IDENTIFIER,
        STDOUT_STREAM_UNIT_ID,
        STDOUT_STREAM_PRIORITY,
        STDOUT_STREAM_LEVEL_PREFIX,
        STDOUT_STREAM_FORWARD_TO_SYSLOG,
        STDOUT_STREAM_FORWARD_TO_KMSG,
        STDOUT_STREAM_FORWARD_TO_CONSOLE,
        STDOUT_STREAM_RUNNING,
} StdoutStreamState;

struct StdoutStream {
        Server *server;
        StdoutStreamState state;

        int fd;

        struct ucred ucred;
        char *label;
        char *identifier;
        char *unit_id;
        int priority;
        bool level_prefix:1;
        bool forward_to_syslog:1;
        bool forward_to_kmsg:1;
        bool forward_to_console:1;

        bool fdstore:1;
        bool in_notify_queue:1;

        char *buffer;
        size_t length;

        sd_event_source *event_source;

        char *state_file;

        ClientContext *context;

        LIST_FIELDS(StdoutStream, stdout_stream);
        LIST_FIELDS(StdoutStream, stdout_stream_notify_queue);

        char id_field[STRLEN("_STREAM_ID=") + SD_ID128_STRING_MAX];

        LIST_HEAD(StreamSyncReq, stream_sync_reqs);
};

int server_open_stdout_socket(Server *s, const char *stdout_socket);
int server_restore_streams(Server *s, FDSet *fds);

StdoutStream* stdout_stream_free(StdoutStream *s);
int stdout_stream_install(Server *s, int fd, StdoutStream **ret);
void stdout_stream_terminate(StdoutStream *s);
void stdout_stream_send_notify(StdoutStream *s);
