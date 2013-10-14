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

#include "set.h"
#include "util.h"

typedef struct FDSet FDSet;

FDSet* fdset_new(void);
void fdset_free(FDSet *s);

int fdset_put(FDSet *s, int fd);
int fdset_put_dup(FDSet *s, int fd);

bool fdset_contains(FDSet *s, int fd);
int fdset_remove(FDSet *s, int fd);

int fdset_new_fill(FDSet **_s);
int fdset_new_listen_fds(FDSet **_s, bool unset);

int fdset_cloexec(FDSet *fds, bool b);

int fdset_close_others(FDSet *fds);

unsigned fdset_size(FDSet *fds);

int fdset_iterate(FDSet *s, Iterator *i);

#define FDSET_FOREACH(fd, fds, i) \
        for ((i) = ITERATOR_FIRST, (fd) = fdset_iterate((fds), &(i)); (fd) >= 0; (fd) = fdset_iterate((fds), &(i)))

DEFINE_TRIVIAL_CLEANUP_FUNC(FDSet*, fdset_free);
#define _cleanup_fdset_free_ _cleanup_(fdset_freep)
