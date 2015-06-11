/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2013 Kay Sievers

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

int mkdir_safe(const char *path, mode_t mode, uid_t uid, gid_t gid);
int mkdir_parents(const char *path, mode_t mode);
int mkdir_p(const char *path, mode_t mode);

/* mandatory access control(MAC) versions */
int mkdir_safe_label(const char *path, mode_t mode, uid_t uid, gid_t gid);
int mkdir_parents_label(const char *path, mode_t mode);
int mkdir_p_label(const char *path, mode_t mode);

/* internally used */
typedef int (*mkdir_func_t)(const char *pathname, mode_t mode);
int mkdir_safe_internal(const char *path, mode_t mode, uid_t uid, gid_t gid, mkdir_func_t _mkdir);
int mkdir_parents_internal(const char *prefix, const char *path, mode_t mode, mkdir_func_t _mkdir);
int mkdir_p_internal(const char *prefix, const char *path, mode_t mode, mkdir_func_t _mkdir);
