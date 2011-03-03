/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef fooreadaheadcommonhfoo
#define fooreadaheadcommonhfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/stat.h>
#include <sys/types.h>

#include "macro.h"

#define READAHEAD_FILE_SIZE_MAX (128*1024*1024)

int file_verify(int fd, const char *fn, off_t file_size_max, struct stat *st);

int fs_on_ssd(const char *p);
int fs_on_read_only(const char *p);

bool enough_ram(void);

int open_inotify(void);

typedef struct ReadaheadShared {
        pid_t collect;
        pid_t replay;
} _packed_ ReadaheadShared;

ReadaheadShared *shared_get(void);

int bump_request_nr(const char *p);

#endif
