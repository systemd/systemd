/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

int userns_open_registry_fd(void);

typedef struct UserNamespaceInfo {
        uid_t start;
        char *name;
        uint32_t size;
        uid_t target;
        uint64_t userns_inode;
} UserNamespaceInfo;

UserNamespaceInfo* userns_info_free(UserNamespaceInfo *userns);

DEFINE_TRIVIAL_CLEANUP_FUNC(UserNamespaceInfo*, userns_info_free);

int userns_load_json_by_start_uid(int dir_fd, uid_t start, UserNamespaceInfo **ret);
int userns_load_json_by_userns_inode(int dir_fd, ino_t userns, UserNamespaceInfo **ret);
