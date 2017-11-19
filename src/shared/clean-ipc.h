/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include "user-util.h"

int clean_ipc_internal(uid_t uid, gid_t gid, bool rm);

/* Remove all IPC objects owned by the specified UID or GID */
int clean_ipc_by_uid(uid_t uid);
int clean_ipc_by_gid(gid_t gid);

/* Check if any IPC object owned by the specified UID or GID exists, returns > 0 if so, == 0 if not */
static inline int search_ipc(uid_t uid, gid_t gid) {
        return clean_ipc_internal(uid, gid, false);
}
