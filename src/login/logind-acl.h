/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/types.h>
#include <stdbool.h>

#include "libudev.h"

#ifdef HAVE_ACL

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
