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

#include <stdbool.h>

#include "busname.h"
#include "sd-bus.h"

#define KDBUS_ITEM_NEXT(item) \
        (typeof(item))(((uint8_t *)item) + ALIGN8((item)->size))

#define KDBUS_ITEM_FOREACH(part, head, first)                           \
        for (part = (head)->first;                                      \
             ((uint8_t *)(part) < (uint8_t *)(head) + (head)->size) &&  \
                ((uint8_t *) part >= (uint8_t *) head);                 \
             part = KDBUS_ITEM_NEXT(part))

#define KDBUS_ITEM_HEADER_SIZE offsetof(struct kdbus_item, data)
#define KDBUS_ITEM_SIZE(s) ALIGN8((s) + KDBUS_ITEM_HEADER_SIZE)

#define MEMFD_CACHE_MAX 32

/* When we cache a memfd block for reuse, we will truncate blocks
 * longer than this in order not to keep too much data around. */
#define MEMFD_CACHE_ITEM_SIZE_MAX (128*1024)

/* This determines at which minimum size we prefer sending memfds over
 * sending vectors */
#define MEMFD_MIN_SIZE (512*1024)

/* The size of the per-connection memory pool that we set up and where
 * the kernel places our incoming messages */
#define KDBUS_POOL_SIZE (16*1024*1024)

struct memfd_cache {
        int fd;
        void *address;
        size_t mapped;
        size_t allocated;
};

int bus_kernel_connect(sd_bus *b);
int bus_kernel_take_fd(sd_bus *b);

int bus_kernel_write_message(sd_bus *bus, sd_bus_message *m, bool hint_sync_call);
int bus_kernel_read_message(sd_bus *bus, bool hint_priority, int64_t priority);

int bus_kernel_open_bus_fd(const char *bus);
int bus_kernel_make_starter(int fd, const char *name, bool activating, bool accept_fd, BusNamePolicy *policy, BusNamePolicyAccess world_policy);

int bus_kernel_create_bus(const char *name, bool world, char **s);
int bus_kernel_create_domain(const char *name, char **s);
int bus_kernel_create_monitor(const char *bus);

int bus_kernel_pop_memfd(sd_bus *bus, void **address, size_t *mapped, size_t *allocated);
void bus_kernel_push_memfd(sd_bus *bus, int fd, void *address, size_t mapped, size_t allocated);

void bus_kernel_flush_memfd(sd_bus *bus);

int bus_kernel_parse_unique_name(const char *s, uint64_t *id);

int kdbus_translate_request_name_flags(uint64_t sd_bus_flags, uint64_t *kdbus_flags);
int kdbus_translate_attach_flags(uint64_t sd_bus_flags, uint64_t *kdbus_flags);

int bus_kernel_try_close(sd_bus *bus);

int bus_kernel_drop_one(int fd);
