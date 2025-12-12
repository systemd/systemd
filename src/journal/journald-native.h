/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journald-forward.h"

void manager_process_native_message(
                Manager *m,
                const char *buffer,
                size_t buffer_size,
                const struct ucred *ucred,
                const struct timeval *tv,
                const char *label,
                size_t label_len);

int manager_process_native_file(
                Manager *m,
                int fd,
                const struct ucred *ucred,
                const struct timeval *tv,
                const char *label,
                size_t label_len);

int manager_open_native_socket(Manager *m, const char *native_socket);
