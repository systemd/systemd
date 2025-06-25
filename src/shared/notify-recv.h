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

int notify_recv_with_fds(
                int fd,
                char **ret_text,
                struct ucred *ret_ucred,
                PidRef *ret_pidref,
                FDSet **ret_fds);

static inline int notify_recv(int fd, char **ret_text, struct ucred *ret_ucred, PidRef *ret_pidref) {
        return notify_recv_with_fds(fd, ret_text, ret_ucred, ret_pidref, NULL);
}

int notify_recv_with_fds_strv(
                int fd,
                char ***ret_list,
                struct ucred *ret_ucred,
                PidRef *ret_pidref,
                FDSet **ret_fds);

static inline int notify_recv_strv(int fd, char ***ret_list, struct ucred *ret_ucred, PidRef *ret_pidref) {
        return notify_recv_with_fds_strv(fd, ret_list, ret_ucred, ret_pidref, NULL);
}
