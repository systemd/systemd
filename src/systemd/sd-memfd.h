/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosdmemfdhfoo
#define foosdmemfdhfoo

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <inttypes.h>
#include <sys/types.h>
#include <stdio.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_memfd sd_memfd;

int sd_memfd_new(sd_memfd **m, const char *name);
int sd_memfd_new_from_fd(sd_memfd **m, int fd);
int sd_memfd_new_and_map(sd_memfd **m, const char *name, size_t sz, void **p);

void sd_memfd_free(sd_memfd *m);

int sd_memfd_get_fd(sd_memfd *m);
int sd_memfd_dup_fd(sd_memfd *n);
int sd_memfd_get_file(sd_memfd *m, FILE **f);

int sd_memfd_map(sd_memfd *m, uint64_t offset, size_t size, void **p);

int sd_memfd_set_sealed(sd_memfd *m, int b);
int sd_memfd_get_sealed(sd_memfd *m);

int sd_memfd_get_size(sd_memfd *m, uint64_t *sz);
int sd_memfd_set_size(sd_memfd *m, uint64_t sz);

int sd_memfd_get_name(sd_memfd *m, char **name);

_SD_END_DECLARATIONS;

#endif
