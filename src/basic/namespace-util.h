/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "basic-forward.h"

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
        unsigned long clone_flag;
        unsigned long pidfd_get_ns_ioctl_cmd;
        ino_t root_inode;
} namespace_info[_NAMESPACE_TYPE_MAX + 1];

NamespaceType clone_flag_to_namespace_type(unsigned long clone_flag);

bool namespace_type_supported(NamespaceType type);

int pidref_namespace_open_by_type(const PidRef *pidref, NamespaceType type);
int namespace_open_by_type(NamespaceType type);

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
int namespace_enter_delegated(int userns_fd, int pidns_fd, int mntns_fd, int netns_fd, int root_fd);

int fd_is_namespace(int fd, NamespaceType type);
int is_our_namespace(int fd, NamespaceType type);

int namespace_is_init(NamespaceType type);

int pidref_in_same_namespace(PidRef *pid1, PidRef *pid2, NamespaceType type);
int in_same_namespace(pid_t pid1, pid_t pid2, NamespaceType type);

int namespace_get_leader(PidRef *pidref, NamespaceType type, PidRef *ret);

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

int parse_userns_uid_range(const char *s, uid_t *ret_uid_shift, uid_t *ret_uid_range);

int userns_acquire_empty(void);
int userns_acquire(const char *uid_map, const char *gid_map, bool setgroups_deny);
int userns_acquire_self_root(void);
int userns_enter_and_pin(int userns_fd, PidRef *ret);
bool userns_supported(void);

int userns_get_base_uid(int userns_fd, uid_t *ret_uid, gid_t *ret_gid);

int process_is_owned_by_uid(const PidRef *pidref, uid_t uid);

int is_idmapping_supported(const char *path);

int netns_acquire(void);
