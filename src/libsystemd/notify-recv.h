/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int notify_socket_prepare_full(
                sd_event *event,
                int64_t priority,
                sd_event_io_handler_t handler,
                void *userdata,
                bool accept_fds,
                char **ret_path,
                sd_event_source **ret_event_source);

static inline int notify_socket_prepare(
                sd_event *event,
                int64_t priority,
                sd_event_io_handler_t handler,
                void *userdata,
                char **ret_path) {

        return notify_socket_prepare_full(event, priority, handler, userdata, false, ret_path, NULL);
}

int notify_recv_with_fd_array(
                int fd,
                char **ret_text,
                struct ucred *ret_ucred,
                PidRef *ret_pidref,
                int **ret_fds,
                size_t *ret_n_fds);
int notify_recv(int fd, char **ret_text, struct ucred *ret_ucred, PidRef *ret_pidref);
int notify_socket_prepare_fd(const char *socket_path, bool accept_fds, char **ret_path);
