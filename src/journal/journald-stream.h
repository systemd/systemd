/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

typedef struct StdoutStream StdoutStream;

#include "fdset.h"
#include "journald-server.h"

int server_open_stdout_socket(Server *s);
int server_restore_streams(Server *s, FDSet *fds);

void stdout_stream_free(StdoutStream *s);
void stdout_stream_send_notify(StdoutStream *s);
