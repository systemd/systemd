/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "pidref.h"

typedef enum NamespaceType {
        NAMESPACE_CGROUP,
        NAMESPACE_IPC,
        NAMESPACE_NET,
        NAMESPACE_MOUNT,
        NAMESPACE_PID,
        NAMESPACE_USER,
        NAMESPACE_UTS,
        NAMESPACE_TIME,
        _NAMESPACE_TYPE_MAX,
        _NAMESPACE_TYPE_INVALID = -EINVAL,
} NamespaceType;

extern const struct namespace_info {
        const char *proc_name;
        const char *proc_path;
        unsigned int clone_flag;
} namespace_info[_NAMESPACE_TYPE_MAX + 1];

int pidref_namespace_open(
                const PidRef *pidref,
                int *ret_pidns_fd,
                int *ret_mntns_fd,
                int *ret_netns_fd,
                int *ret_userns_fd,
                int *ret_root_fd);
int namespace_open(
                pid_t pid,
                int *ret_pidns_fd,
                int *ret_mntns_fd,
                int *ret_netns_fd,
                int *ret_userns_fd,
                int *ret_root_fd);
int namespace_enter(int pidns_fd, int mntns_fd, int netns_fd, int userns_fd, int root_fd);

int fd_is_ns(int fd, unsigned long nsflag);

int detach_mount_namespace(void);
int detach_mount_namespace_harder(uid_t target_uid, gid_t target_gid);
int detach_mount_namespace_userns(int userns_fd);

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

int userns_acquire_empty(void);
int userns_acquire(const char *uid_map, const char *gid_map);

int netns_acquire(void);

int in_same_namespace(pid_t pid1, pid_t pid2, NamespaceType type);

int parse_userns_uid_range(const char *s, uid_t *ret_uid_shift, uid_t *ret_uid_range);

int namespace_open_by_type(NamespaceType type);

int is_our_namespace(int fd, NamespaceType type);
