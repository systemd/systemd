/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <sys/quota.h>
#include <sys/types.h>

/* Wrapper around the QCMD() macro of linux/quota.h that removes some undefined behaviour. A typical quota
 * command such as QCMD(Q_GETQUOTA, USRQUOTA) cannot be resolved on platforms where "int" is 32bit, as it is
 * larger than INT_MAX. Yikes, because that are basically all platforms Linux supports. Let's add a wrapper
 * that explicitly takes its arguments as unsigned 32bit, and then converts the shift result explicitly to
 * int, acknowledging the undefined behaviour of the kernel headers. This doesn't remove the undefined
 * behaviour, but it stops ubsan from complaining about it. */
static inline int QCMD_FIXED(uint32_t cmd, uint32_t type) {
        return (int) QCMD(cmd, type);
}

int quotactl_devnum(int cmd, dev_t devnum, int id, void *addr);
int quotactl_path(int cmd, const char *path, int id, void *addr);
