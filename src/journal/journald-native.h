/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journald-server.h"

void server_process_native_message(
                Server *s,
                const char *buffer,
                size_t buffer_size,
                const struct ucred *ucred,
                const struct timeval *tv,
                const char *label,
                size_t label_len);

void server_process_native_file(
                Server *s,
                int fd,
                const struct ucred *ucred,
                const struct timeval *tv,
                const char *label,
                size_t label_len);

int server_open_native_socket(Server *s, const char *native_socket);
