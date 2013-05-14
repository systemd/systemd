/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include "sd-bus.h"

#define MEMFD_CACHE_MAX 32
#define MEMFD_CACHE_ITEM_SIZE_MAX (128*1024)

struct memfd_cache {
        int fd;
        void *address;
        size_t size;
};

int bus_kernel_connect(sd_bus *b);
int bus_kernel_take_fd(sd_bus *b);

int bus_kernel_write_message(sd_bus *bus, sd_bus_message *m);
int bus_kernel_read_message(sd_bus *bus, sd_bus_message **m);

int bus_kernel_create(const char *name, char **s);

int bus_kernel_pop_memfd(sd_bus *bus, void **address, size_t *size);
void bus_kernel_push_memfd(sd_bus *bus, int fd, void *address, size_t size);

void bus_kernel_flush_memfd(sd_bus *bus);
