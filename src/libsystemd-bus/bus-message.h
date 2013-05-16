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
#include <byteswap.h>
#include <sys/socket.h>

#include "macro.h"
#include "sd-bus.h"
#include "kdbus.h"
#include "time-util.h"

struct bus_container {
        char enclosing;

        unsigned index, saved_index;

        char *signature;

        uint32_t *array_size;
        size_t before, begin;
};

struct bus_header {
        uint8_t endian;
        uint8_t type;
        uint8_t flags;
        uint8_t version;
        uint32_t body_size;
        uint32_t serial;
        uint32_t fields_size;
} _packed_;

struct bus_body_part {
        struct bus_body_part *next;
        void *data;
        size_t size;
        size_t mapped;
        int memfd;
        bool free_this:1;
        bool munmap_this:1;
        bool sealed:1;
        bool is_zero:1;
};

struct sd_bus_message {
        unsigned n_ref;

        sd_bus *bus;

        uint32_t reply_serial;

        const char *path;
        const char *interface;
        const char *member;
        const char *destination;
        const char *sender;

        sd_bus_error error;

        uid_t uid;
        gid_t gid;
        pid_t pid;
        pid_t tid;
        usec_t pid_starttime;
        usec_t monotonic;
        usec_t realtime;

        bool sealed:1;
        bool dont_send:1;
        bool allow_fds:1;
        bool uid_valid:1;
        bool gid_valid:1;
        bool free_header:1;
        bool free_kdbus:1;
        bool free_fds:1;
        bool release_kdbus:1;
        bool poisoned:1;

        struct bus_header *header;
        struct bus_body_part body;
        struct bus_body_part *body_end;
        unsigned n_body_parts;

        char *label;

        size_t rindex;
        struct bus_body_part *cached_rindex_part;
        size_t cached_rindex_part_begin;

        uint32_t n_fds;
        int *fds;

        struct bus_container root_container, *containers;
        unsigned n_containers;

        struct iovec *iovec;
        struct iovec iovec_fixed[2];
        unsigned n_iovec;

        struct kdbus_msg *kdbus;

        char *peeked_signature;

        usec_t timeout;

        char sender_buffer[3 + DECIMAL_STR_MAX(uint64_t) + 1];
        char destination_buffer[3 + DECIMAL_STR_MAX(uint64_t) + 1];

        const char *exe;
        const char *comm;
        const char *tid_comm;
        const char *cgroup;

        const char *cmdline;
        size_t cmdline_length;
        char **cmdline_array;

        char *session;
        char *unit;
        char *user_unit;

        struct kdbus_audit *audit;

        uint8_t *capability;
        size_t capability_size;
};

#define BUS_MESSAGE_NEED_BSWAP(m) ((m)->header->endian != SD_BUS_NATIVE_ENDIAN)

static inline uint16_t BUS_MESSAGE_BSWAP16(sd_bus_message *m, uint16_t u) {
        return BUS_MESSAGE_NEED_BSWAP(m) ? bswap_16(u) : u;
}

static inline uint32_t BUS_MESSAGE_BSWAP32(sd_bus_message *m, uint32_t u) {
        return BUS_MESSAGE_NEED_BSWAP(m) ? bswap_32(u) : u;
}

static inline uint64_t BUS_MESSAGE_BSWAP64(sd_bus_message *m, uint64_t u) {
        return BUS_MESSAGE_NEED_BSWAP(m) ? bswap_64(u) : u;
}

static inline uint32_t BUS_MESSAGE_SERIAL(sd_bus_message *m) {
        return BUS_MESSAGE_BSWAP32(m, m->header->serial);
}

static inline uint32_t BUS_MESSAGE_BODY_SIZE(sd_bus_message *m) {
        return BUS_MESSAGE_BSWAP32(m, m->header->body_size);
}

static inline uint32_t BUS_MESSAGE_FIELDS_SIZE(sd_bus_message *m) {
        return BUS_MESSAGE_BSWAP32(m, m->header->fields_size);
}

static inline uint32_t BUS_MESSAGE_SIZE(sd_bus_message *m) {
        return
                sizeof(struct bus_header) +
                ALIGN8(BUS_MESSAGE_FIELDS_SIZE(m)) +
                BUS_MESSAGE_BODY_SIZE(m);
}

static inline uint32_t BUS_MESSAGE_BODY_BEGIN(sd_bus_message *m) {
        return
                sizeof(struct bus_header) +
                ALIGN8(BUS_MESSAGE_FIELDS_SIZE(m));
}

static inline void* BUS_MESSAGE_FIELDS(sd_bus_message *m) {
        return (uint8_t*) m->header + sizeof(struct bus_header);
}

static inline void bus_message_unrefp(sd_bus_message **m) {
        sd_bus_message_unref(*m);
}

#define _cleanup_bus_message_unref_ __attribute__((cleanup(bus_message_unrefp)))

int bus_message_seal(sd_bus_message *m, uint64_t serial);
int bus_message_dump(sd_bus_message *m);
int bus_message_get_blob(sd_bus_message *m, void **buffer, size_t *sz);
int bus_message_read_strv_extend(sd_bus_message *m, char ***l);

int bus_message_from_header(
                void *header,
                size_t length,
                int *fds,
                unsigned n_fds,
                const struct ucred *ucred,
                const char *label,
                size_t extra,
                sd_bus_message **ret);

int bus_message_from_malloc(
                void *buffer,
                size_t length,
                int *fds,
                unsigned n_fds,
                const struct ucred *ucred,
                const char *label,
                sd_bus_message **ret);

const char* bus_message_get_arg(sd_bus_message *m, unsigned i);

int bus_message_append_ap(sd_bus_message *m, const char *types, va_list ap);

int bus_message_parse_fields(sd_bus_message *m);

bool bus_header_is_complete(struct bus_header *h, size_t size);
int bus_header_message_size(struct bus_header *h, size_t *sum);

struct bus_body_part *message_append_part(sd_bus_message *m);

#define MESSAGE_FOREACH_PART(part, i, m) \
        for ((i) = 0, (part) = &(m)->body; (i) < (m)->n_body_parts; (i)++, (part) = (part)->next)

int bus_body_part_map(struct bus_body_part *part);
void bus_body_part_unmap(struct bus_body_part *part);

int bus_message_to_errno(sd_bus_message *m);

int bus_message_new_synthetic_error(sd_bus *bus, uint64_t serial, const sd_bus_error *e, sd_bus_message **m);
