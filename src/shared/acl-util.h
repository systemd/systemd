/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <unistd.h>

#if HAVE_ACL
#include <acl/libacl.h>
#include <stdbool.h>
#include <sys/acl.h>

#include "macro.h"

int acl_find_uid(acl_t acl, uid_t uid, acl_entry_t *entry);
int calc_acl_mask_if_needed(acl_t *acl_p);
int add_base_acls_if_needed(acl_t *acl_p, const char *path);
int acl_search_groups(const char* path, char ***ret_groups);
int parse_acl(const char *text, acl_t *acl_access, acl_t *acl_default, bool want_mask);
int acls_for_file(const char *path, acl_type_t type, acl_t new, acl_t *acl);
int fd_add_uid_acl_permission(int fd, uid_t uid, unsigned mask);

/* acl_free takes multiple argument types.
 * Multiple cleanup functions are necessary. */
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(acl_t, acl_free, NULL);
#define acl_free_charp acl_free
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(char*, acl_free_charp, NULL);
#define acl_free_uid_tp acl_free
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(uid_t*, acl_free_uid_tp, NULL);
#define acl_free_gid_tp acl_free
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(gid_t*, acl_free_gid_tp, NULL);

#else
#define ACL_READ    0x04
#define ACL_WRITE   0x02
#define ACL_EXECUTE 0x01

static inline int fd_add_uid_acl_permission(int fd, uid_t uid, unsigned mask) {
        return -EOPNOTSUPP;
}
#endif
