/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int fd_acl_make_read_only_fallback(int fd);
int fd_acl_make_writable_fallback(int fd);

#if HAVE_ACL
#include <acl/libacl.h> /* IWYU pragma: export */
#include <sys/acl.h>    /* IWYU pragma: export */

int devnode_acl(int fd, uid_t uid);

int calc_acl_mask_if_needed(acl_t *acl_p);
int add_base_acls_if_needed(acl_t *acl_p, const char *path);
int acl_search_groups(const char* path, char ***ret_groups);
int parse_acl(
                const char *text,
                acl_t *ret_acl_access,
                acl_t *ret_acl_access_exec,
                acl_t *ret_acl_default,
                bool want_mask);
int acls_for_file(const char *path, acl_type_t type, acl_t new, acl_t *ret);
int fd_add_uid_acl_permission(int fd, uid_t uid, unsigned mask);

int fd_acl_make_read_only(int fd);
int fd_acl_make_writable(int fd);

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

static inline int devnode_acl(int fd, uid_t uid) {
        return -EOPNOTSUPP;
}

static inline int fd_add_uid_acl_permission(int fd, uid_t uid, unsigned mask) {
        return -EOPNOTSUPP;
}

static inline int fd_acl_make_read_only(int fd) {
        return fd_acl_make_read_only_fallback(fd);
}

static inline int fd_acl_make_writable(int fd) {
        return fd_acl_make_writable_fallback(fd);
}

#endif
