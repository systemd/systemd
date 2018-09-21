/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

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
int add_acls_for_user(int fd, uid_t uid);

/* acl_free takes multiple argument types.
 * Multiple cleanup functions are necessary. */
DEFINE_TRIVIAL_CLEANUP_FUNC(acl_t, acl_free);
#define acl_free_charp acl_free
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, acl_free_charp);
#define acl_free_uid_tp acl_free
DEFINE_TRIVIAL_CLEANUP_FUNC(uid_t*, acl_free_uid_tp);
#define acl_free_gid_tp acl_free
DEFINE_TRIVIAL_CLEANUP_FUNC(gid_t*, acl_free_gid_tp);

#endif
