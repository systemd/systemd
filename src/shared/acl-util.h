/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#if HAVE_ACL
#include <acl/libacl.h> /* IWYU pragma: export */
#include <sys/acl.h>    /* IWYU pragma: export */

#include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(acl_add_perm);
extern DLSYM_PROTOTYPE(acl_calc_mask);
extern DLSYM_PROTOTYPE(acl_copy_entry);
extern DLSYM_PROTOTYPE(acl_create_entry);
extern DLSYM_PROTOTYPE(acl_delete_entry);
extern DLSYM_PROTOTYPE(acl_delete_perm);
extern DLSYM_PROTOTYPE(acl_dup);
extern DLSYM_PROTOTYPE(acl_entries);
extern DLSYM_PROTOTYPE(acl_extended_file);
extern DLSYM_PROTOTYPE(acl_free);
extern DLSYM_PROTOTYPE(acl_from_mode);
extern DLSYM_PROTOTYPE(acl_from_text);
extern DLSYM_PROTOTYPE(acl_get_entry);
extern DLSYM_PROTOTYPE(acl_get_fd);
extern DLSYM_PROTOTYPE(acl_get_file);
extern DLSYM_PROTOTYPE(acl_get_perm);
extern DLSYM_PROTOTYPE(acl_get_permset);
extern DLSYM_PROTOTYPE(acl_get_qualifier);
extern DLSYM_PROTOTYPE(acl_get_tag_type);
extern DLSYM_PROTOTYPE(acl_init);
extern DLSYM_PROTOTYPE(acl_set_fd);
extern DLSYM_PROTOTYPE(acl_set_file);
extern DLSYM_PROTOTYPE(acl_set_permset);
extern DLSYM_PROTOTYPE(acl_set_qualifier);
extern DLSYM_PROTOTYPE(acl_set_tag_type);
extern DLSYM_PROTOTYPE(acl_to_any_text);

int dlopen_libacl(void);

int devnode_acl(int fd, const Set *uids);

int calc_acl_mask_if_needed(acl_t *acl_p);
int add_base_acls_if_needed(acl_t *acl_p, const char *path);
int acl_search_groups(const char* path, char ***ret_groups);
int parse_acl(
                const char *text,
                acl_t *ret_acl_access,
                acl_t *ret_acl_access_exec,
                acl_t *ret_acl_default,
                bool want_mask);
int acls_for_file(const char *path, acl_type_t type, acl_t acl, acl_t *ret);
int fd_add_uid_acl_permission(int fd, uid_t uid, unsigned mask);

/* acl_free() takes multiple argument types. Multiple cleanup functions are necessary. */
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(acl_t, sym_acl_free, acl_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(char*, sym_acl_free, acl_free_charpp, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(uid_t*, sym_acl_free, acl_free_uid_tpp, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(gid_t*, sym_acl_free, acl_free_gid_tpp, NULL);

static inline int acl_set_perm(acl_permset_t ps, acl_perm_t p, bool b) {
        return (b ? sym_acl_add_perm : sym_acl_delete_perm)(ps, p);
}

#else

typedef void* acl_t;
typedef int acl_tag_t;
typedef unsigned acl_type_t;

#define ACL_READ    0x04
#define ACL_WRITE   0x02
#define ACL_EXECUTE 0x01

/* acl_tag_t */
#define ACL_UNDEFINED_TAG       (0x00)
#define ACL_USER_OBJ            (0x01)
#define ACL_USER                (0x02)
#define ACL_GROUP_OBJ           (0x04)
#define ACL_GROUP               (0x08)
#define ACL_MASK                (0x10)
#define ACL_OTHER               (0x20)

/* acl_type_t */
#define ACL_TYPE_ACCESS         (0x8000)
#define ACL_TYPE_DEFAULT        (0x4000)

static inline int dlopen_libacl(void) {
        return -EOPNOTSUPP;
}

static inline int devnode_acl(int fd, const Set *uids) {
        return -EOPNOTSUPP;
}

static inline int fd_add_uid_acl_permission(int fd, uid_t uid, unsigned mask) {
        return -EOPNOTSUPP;
}
#endif

int fd_acl_make_read_only(int fd);
int fd_acl_make_writable(int fd);

int inode_type_can_acl(mode_t mode);
