#pragma once

/***
  This file is part of systemd.

  Copyright 2017 Lennart Poettering

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

/* While we are chmod()ing a directory tree, we set the top-level UID base to this "busy" base, so that we can always
 * recognize trees we are were chmod()ing recursively and got interrupted in */
#define UID_BUSY_BASE ((uid_t) UINT32_C(0xFFFE0000))
#define UID_BUSY_MASK ((uid_t) UINT32_C(0xFFFF0000))
