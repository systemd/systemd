/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/quota.h>        /* IWYU pragma: export */
#include <sys/quota.h>          /* IWYU pragma: export */

#include "forward.h"

/* Wrapper around the QCMD() macro of linux/quota.h that removes some undefined behaviour. A typical quota
 * command such as QCMD(Q_GETQUOTA, USRQUOTA) cannot be resolved on platforms where "int" is 32-bit, as it is
 * larger than INT_MAX. Yikes, because that are basically all platforms Linux supports. Let's add a wrapper
 * that explicitly takes its arguments as unsigned 32-bit, and then converts the shift result explicitly to
 * int, acknowledging the undefined behaviour of the kernel headers. This doesn't remove the undefined
 * behaviour, but it stops ubsan from complaining about it. */
static inline int QCMD_FIXED(uint32_t cmd, uint32_t type) {
        return (int) QCMD(cmd, type);
}

int quotactl_fd_with_fallback(int fd, int cmd, int id, void *addr);
int quota_query_proj_id(int fd, uint32_t proj_id, struct dqblk *ret_req);
int quota_proj_id_set_recursive(int fd, uint32_t proj_id, bool verify_exclusive);
bool quota_dqblk_is_populated(const struct dqblk *dqblk);
