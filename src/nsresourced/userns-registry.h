/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#define USER_NAMESPACE_CGROUPS_DELEGATE_MAX 16U
#define USER_NAMESPACE_NETIFS_DELEGATE_MAX 16U
#define USER_NAMESPACE_DELEGATIONS_MAX 16U

typedef struct DelegatedUserNamespaceInfo {
        uint64_t userns_inode;
        uid_t start_uid;
        gid_t start_gid;
        uint32_t size;
        /* We track all the previous owners of the delegation so we can restore the previous owner of each
         * delegated range when a user namespace with delegated ranges is freed. */
        uint64_t *ancestor_userns;
        size_t n_ancestor_userns;
} DelegatedUserNamespaceInfo;

#define DELEGATED_USER_NAMESPACE_INFO_NULL (DelegatedUserNamespaceInfo) {       \
        .start_uid = UID_INVALID,                                               \
        .start_gid = GID_INVALID,                                               \
}

void delegated_userns_info_done(DelegatedUserNamespaceInfo *info);
void delegated_userns_info_done_many(DelegatedUserNamespaceInfo infos[], size_t n);

typedef struct UserNamespaceInfo {
        uid_t owner;
        char *name;
        uint64_t userns_inode;
        uint32_t size;
        uid_t start_uid;
        uid_t target_uid;
        gid_t start_gid;
        gid_t target_gid;
        uint64_t *cgroups;
        size_t n_cgroups;
        char **netifs;
        DelegatedUserNamespaceInfo *delegates;
        size_t n_delegates;
} UserNamespaceInfo;

UserNamespaceInfo* userns_info_new(void);
UserNamespaceInfo* userns_info_free(UserNamespaceInfo *userns);

DEFINE_TRIVIAL_CLEANUP_FUNC(UserNamespaceInfo*, userns_info_free);

bool userns_info_has_cgroup(UserNamespaceInfo *userns, uint64_t cgroup_id);
int userns_info_add_cgroup(UserNamespaceInfo *userns, uint64_t cgroup_id);
int userns_info_remove_cgroups(UserNamespaceInfo *userns);

int userns_info_add_netif(UserNamespaceInfo *userns, const char *netif);
int userns_info_remove_netifs(UserNamespaceInfo *userns);

bool userns_name_is_valid(const char *name);

int userns_registry_open_fd(void);
int userns_registry_lock(int dir_fd);

int userns_registry_load_by_start_uid(int dir_fd, uid_t start, UserNamespaceInfo **ret);
int userns_registry_load_by_start_gid(int dir_fd, gid_t start, UserNamespaceInfo **ret);
int userns_registry_load_by_userns_inode(int dir_fd, uint64_t inode, UserNamespaceInfo **ret);
int userns_registry_load_by_name(int dir_fd, const char *name, UserNamespaceInfo **ret);

int userns_registry_store(int dir_fd, UserNamespaceInfo *info);
int userns_registry_remove(int dir_fd, UserNamespaceInfo *info);

int userns_registry_inode_exists(int dir_fd, uint64_t inode);
int userns_registry_name_exists(int dir_fd, const char *name);
int userns_registry_uid_exists(int dir_fd, uid_t start);
int userns_registry_gid_exists(int dir_fd, gid_t start);

int userns_registry_per_uid(int dir_fd, uid_t owner);

int userns_registry_delegation_uid_exists(int dir_fd, uid_t start);
int userns_registry_delegation_gid_exists(int dir_fd, gid_t start);
int userns_registry_load_delegation_by_uid(int dir_fd, uid_t start, DelegatedUserNamespaceInfo *ret);
int userns_registry_load_delegation_by_gid(int dir_fd, gid_t start, DelegatedUserNamespaceInfo *ret);
