/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <sys/stat.h>
#include <sys/types.h>

#include "macro.h"
#include "util.h"

#define READAHEAD_FILE_SIZE_MAX (10*1024*1024)

#define READAHEAD_PACK_FILE_VERSION ";VERSION=2\n"

extern unsigned arg_files_max;
extern off_t arg_file_size_max;
extern usec_t arg_timeout;

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

int block_bump_request_nr(const char *p);

int block_get_readahead(const char *p, uint64_t *bytes);
int block_set_readahead(const char *p, uint64_t bytes);

int main_collect(const char *root);
int main_replay(const char *root);
int main_analyze(const char *pack_path);
