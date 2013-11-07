/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosdbusvtablehfoo
#define foosdbusvtablehfoo

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

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sd_bus_vtable sd_bus_vtable;

#include "sd-bus.h"

enum {
        _SD_BUS_VTABLE_START = '<',
        _SD_BUS_VTABLE_END = '>',
        _SD_BUS_VTABLE_METHOD = 'M',
        _SD_BUS_VTABLE_SIGNAL = 'S',
        _SD_BUS_VTABLE_PROPERTY = 'P',
        _SD_BUS_VTABLE_WRITABLE_PROPERTY = 'W',
        _SD_BUS_VTABLE_CHILDREN = 'C'
};

enum {
        SD_BUS_VTABLE_DEPRECATED = 1,
        SD_BUS_VTABLE_METHOD_NO_REPLY = 2,
        SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE = 4,
        SD_BUS_VTABLE_PROPERTY_INVALIDATE_ONLY = 8,
};

struct sd_bus_vtable {
        /* Please do not initialize this structure directly, use the
         * macros below instead */

        int type;
        int flags;
        union {
                struct {
                        size_t element_size;
                } start;
                struct {
                        const char *member;
                        const char *signature;
                        const char *result;
                        sd_bus_message_handler_t handler;
                } method;
                struct {
                        const char *member;
                        const char *signature;
                } signal;
                struct {
                        const char *member;
                        const char *signature;
                        sd_bus_property_get_t get;
                        sd_bus_property_set_t set;
                        size_t offset;
                } property;
        } x;
};

#define SD_BUS_VTABLE_START(_flags)                                     \
        {                                                               \
                .type = _SD_BUS_VTABLE_START,                           \
                .flags = _flags,                                        \
                .x.start.element_size = sizeof(sd_bus_vtable),          \
        }

#define SD_BUS_METHOD(_member, _signature, _result, _handler, _flags)   \
        {                                                               \
                .type = _SD_BUS_VTABLE_METHOD,                          \
                .flags = _flags,                                        \
                .x.method.member = _member,                             \
                .x.method.signature = _signature,                       \
                .x.method.result = _result,                             \
                .x.method.handler = _handler,                           \
        }

#define SD_BUS_SIGNAL(_member, _signature, _flags)                      \
        {                                                               \
                .type = _SD_BUS_VTABLE_SIGNAL,                          \
                .flags = _flags,                                        \
                .x.signal.member = _member,                             \
                .x.signal.signature = _signature,                       \
        }

#define SD_BUS_PROPERTY(_member, _signature, _get, _offset, _flags)     \
        {                                                               \
                .type = _SD_BUS_VTABLE_PROPERTY,                        \
                .flags = _flags,                                        \
                .x.property.member = _member,                           \
                .x.property.signature = _signature,                     \
                .x.property.get = _get,                                 \
                .x.property.offset = _offset,                           \
        }

#define SD_BUS_WRITABLE_PROPERTY(_member, _signature, _get, _set, _offset, _flags) \
        {                                                               \
                .type = _SD_BUS_VTABLE_WRITABLE_PROPERTY,               \
                .flags = _flags,                                        \
                .x.property.member = _member,                           \
                .x.property.signature = _signature,                     \
                .x.property.get = _get,                                 \
                .x.property.set = _set,                                 \
                .x.property.offset = _offset,                           \
        }

#define SD_BUS_VTABLE_END                                               \
        {                                                               \
                .type = _SD_BUS_VTABLE_END,                             \
        }

#ifdef __cplusplus
}
#endif

#endif
