/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <byteswap.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "sd-bus.h"

#include "bus-creds.h"
#include "bus-protocol.h"
#include "macro.h"
#include "time-util.h"

struct bus_container {
        char enclosing;

        /* Indexes into the signature string */
        unsigned index, saved_index;
        char *signature;

        size_t before, begin, end;

        /* pointer to the array size value, if this is a value */
        uint32_t *array_size;

        char *peeked_signature;
};

struct bus_body_part {
        struct bus_body_part *next;
        void *data;
        void *mmap_begin;
        size_t size;
        size_t mapped;
        size_t allocated;
        uint64_t memfd_offset;
        int memfd;
        bool free_this:1;
        bool munmap_this:1;
        bool sealed:1;
        bool is_zero:1;
};

struct sd_bus_message {
        /* Caveat: a message can be referenced in two different ways: the main (user-facing) way will also
         * pin the bus connection object the message is associated with. The secondary way ("queued") is used
         * when a message is in the read or write queues of the bus connection object, which will not pin the
         * bus connection object. This is necessary so that we don't have to have a pair of cyclic references
         * between a message that is queued and its connection: as soon as a message is only referenced by
         * the connection (by means of being queued) and the connection itself has no other references it
         * will be freed. */

        unsigned n_ref;     /* Counter of references that pin the connection */
        unsigned n_queued;  /* Counter of references that do not pin the connection */

        sd_bus *bus;

        uint64_t reply_cookie;

        const char *path;
        const char *interface;
        const char *member;
        const char *destination;
        const char *sender;

        sd_bus_error error;

        sd_bus_creds creds;

        usec_t monotonic;
        usec_t realtime;
        uint64_t seqnum;
        uint64_t verify_destination_id;

        bool sealed:1;
        bool dont_send:1;
        bool allow_fds:1;
        bool free_header:1;
        bool free_fds:1;
        bool poisoned:1;
        bool sensitive:1;

        /* The first bytes of the message */
        struct bus_header *header;

        size_t fields_size;
        size_t body_size;
        size_t user_body_size;

        struct bus_body_part body;
        struct bus_body_part *body_end;
        unsigned n_body_parts;

        size_t rindex;
        struct bus_body_part *cached_rindex_part;
        size_t cached_rindex_part_begin;

        uint32_t n_fds;
        int *fds;

        struct bus_container root_container, *containers;
        size_t n_containers;

        struct iovec *iovec;
        struct iovec iovec_fixed[2];
        unsigned n_iovec;

        char *peeked_signature;

        /* If set replies to this message must carry the signature
         * specified here to successfully seal. This is initialized
         * from the vtable data */
        const char *enforced_reply_signature;

        usec_t timeout;

        size_t header_offsets[_BUS_MESSAGE_HEADER_MAX];
        unsigned n_header_offsets;

        uint64_t read_counter;
};

static inline bool BUS_MESSAGE_NEED_BSWAP(sd_bus_message *m) {
        return m->header->endian != BUS_NATIVE_ENDIAN;
}

static inline uint16_t BUS_MESSAGE_BSWAP16(sd_bus_message *m, uint16_t u) {
        return BUS_MESSAGE_NEED_BSWAP(m) ? __builtin_bswap16(u) : u;
}

static inline uint32_t BUS_MESSAGE_BSWAP32(sd_bus_message *m, uint32_t u) {
        return BUS_MESSAGE_NEED_BSWAP(m) ? __builtin_bswap32(u) : u;
}

static inline uint64_t BUS_MESSAGE_BSWAP64(sd_bus_message *m, uint64_t u) {
        return BUS_MESSAGE_NEED_BSWAP(m) ? __builtin_bswap64(u) : u;
}

static inline uint64_t BUS_MESSAGE_COOKIE(sd_bus_message *m) {
        return BUS_MESSAGE_BSWAP32(m, m->header->serial);
}

static inline size_t BUS_MESSAGE_SIZE(sd_bus_message *m) {
        return
                sizeof(struct bus_header) +
                ALIGN8(m->fields_size) +
                m->body_size;
}

static inline size_t BUS_MESSAGE_BODY_BEGIN(sd_bus_message *m) {
        return
                sizeof(struct bus_header) +
                ALIGN8(m->fields_size);
}

static inline void* BUS_MESSAGE_FIELDS(sd_bus_message *m) {
        return (uint8_t*) m->header + sizeof(struct bus_header);
}

int bus_message_get_blob(sd_bus_message *m, void **buffer, size_t *sz);

int bus_message_from_malloc(
                sd_bus *bus,
                void *buffer,
                size_t length,
                int *fds,
                size_t n_fds,
                const char *label,
                sd_bus_message **ret);

int bus_message_get_arg(sd_bus_message *m, unsigned i, const char **str);
int bus_message_get_arg_strv(sd_bus_message *m, unsigned i, char ***strv);

#define MESSAGE_FOREACH_PART(part, i, m) \
        for ((i) = 0, (part) = &(m)->body; (i) < (m)->n_body_parts; (i)++, (part) = (part)->next)

int bus_body_part_map(struct bus_body_part *part);
void bus_body_part_unmap(struct bus_body_part *part);

int bus_message_new_synthetic_error(sd_bus *bus, uint64_t serial, const sd_bus_error *e, sd_bus_message **m);

int bus_message_remarshal(sd_bus *bus, sd_bus_message **m);

void bus_message_set_sender_driver(sd_bus *bus, sd_bus_message *m);
void bus_message_set_sender_local(sd_bus *bus, sd_bus_message *m);

sd_bus_message* bus_message_ref_queued(sd_bus_message *m, sd_bus *bus);
sd_bus_message* bus_message_unref_queued(sd_bus_message *m, sd_bus *bus);

char** bus_message_make_log_fields(sd_bus_message *m);
