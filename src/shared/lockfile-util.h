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

#include "macro.h"
#include "missing.h"

typedef struct LockFile {
        char *path;
        int fd;
        int operation;
} LockFile;

int make_lock_file(const char *p, int operation, LockFile *ret);
int make_lock_file_for(const char *p, int operation, LockFile *ret);
void release_lock_file(LockFile *f);

#define _cleanup_release_lock_file_ _cleanup_(release_lock_file)

#define LOCK_FILE_INIT { .fd = -1, .path = NULL }
