/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "../libsystemd/notify-recv.h" /* IWYU pragma: export */

int notify_recv_with_fds(
                int fd,
                char **ret_text,
                struct ucred *ret_ucred,
                PidRef *ret_pidref,
                FDSet **ret_fds);

int notify_recv_with_fds_strv(
                int fd,
                char ***ret_list,
                struct ucred *ret_ucred,
                PidRef *ret_pidref,
                FDSet **ret_fds);

static inline int notify_recv_strv(int fd, char ***ret_list, struct ucred *ret_ucred, PidRef *ret_pidref) {
        return notify_recv_with_fds_strv(fd, ret_list, ret_ucred, ret_pidref, NULL);
}
