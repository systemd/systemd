/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

int namespace_open(pid_t pid, int *pidns_fd, int *mntns_fd, int *netns_fd, int *userns_fd, int *root_fd);
int namespace_enter(int pidns_fd, int mntns_fd, int netns_fd, int userns_fd, int root_fd);

int fd_is_ns(int fd, unsigned long nsflag);

int detach_mount_namespace(void);

static inline bool userns_shift_range_valid(uid_t shift, uid_t range) {
        /* Checks that the specified userns range makes sense, i.e. contains at least one UID, and the end
         * doesn't overflow uid_t. */

        assert_cc((uid_t) -1 > 0); /* verify that uid_t is unsigned */

        if (range <= 0)
                return false;

        if (shift > (uid_t) -1 - range)
                return false;

        return true;
}

int userns_acquire(const char *uid_map, const char *gid_map);
