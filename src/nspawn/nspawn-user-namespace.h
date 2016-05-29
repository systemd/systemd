#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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

typedef enum UserNamespaceMode {
        USER_NAMESPACE_NO,
        USER_NAMESPACE_FIXED,
        USER_NAMESPACE_PICK,
        _USER_NAMESPACE_MODE_MAX,
        _USER_NAMESPACE_MODE_INVALID = -1,
} UserNamespaceMode;

typedef struct UserNamespaceContext {
        uid_t			base_uid;
        gid_t			base_gid;
        uid_t			uid_shift;
        uid_t			uid_range;
        UserNamespaceMode	mode;
} UserNamespaceContext;

int fd_patch_uid(int fd, uid_t shift, uid_t range);
int path_patch_uid(const char *path, uid_t shift, uid_t range);
