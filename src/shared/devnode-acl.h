/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

#if HAVE_ACL

int devnode_acl(const char *path,
                bool flush,
                bool del, uid_t old_uid,
                bool add, uid_t new_uid);

int devnode_acl_all(const char *seat,
                    bool flush,
                    bool del, uid_t old_uid,
                    bool add, uid_t new_uid);
#else

static inline int devnode_acl(const char *path,
                bool flush,
                bool del, uid_t old_uid,
                bool add, uid_t new_uid) {
        return 0;
}

static inline int devnode_acl_all(const char *seat,
                                  bool flush,
                                  bool del, uid_t old_uid,
                                  bool add, uid_t new_uid) {
        return 0;
}

#endif
