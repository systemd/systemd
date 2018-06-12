/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright 2011 Lennart Poettering
***/

#include <stdbool.h>
#include <sys/types.h>

#include "libudev.h"

#if HAVE_ACL

int devnode_acl(const char *path,
                bool flush,
                bool del, uid_t old_uid,
                bool add, uid_t new_uid);

int devnode_acl_all(struct udev *udev,
                    const char *seat,
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

static inline int devnode_acl_all(struct udev *udev,
                                  const char *seat,
                                  bool flush,
                                  bool del, uid_t old_uid,
                                  bool add, uid_t new_uid) {
        return 0;
}

#endif
