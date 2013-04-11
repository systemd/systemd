/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <fcntl.h>

#include "util.h"

#include "bus-internal.h"
#include "bus-message.h"
#include "bus-kernel.h"

#define KDBUS_MSG_FOREACH_DATA(d, k)                                    \
        for ((d) = (k)->data;                                           \
             (uint8_t*) (d) < (uint8_t*) (k) + (k)->size;               \
             (d) = (struct kdbus_msg_data*) ((uint8_t*) (d) + ALIGN8((d)->size)))



static int parse_unique_name(const char *s, uint64_t *id) {
        int r;

        assert(s);
        assert(id);

        if (!startswith(s, ":1."))
                return 0;

        r = safe_atou64(s + 3, id);
        if (r < 0)
                return r;

        return 1;
}

static void append_payload_vec(struct kdbus_msg_data **d, const void *p, size_t sz) {
        assert(d);
        assert(p);
        assert(sz > 0);

        (*d)->size = offsetof(struct kdbus_msg_data, vec) + sizeof(struct kdbus_vec);
        (*d)->type = KDBUS_MSG_PAYLOAD_VEC;
        (*d)->vec.address = (uint64_t) p;
        (*d)->vec.size = sz;

        *d = (struct kdbus_msg_data*) ((uint8_t*) *d + ALIGN8((*d)->size));
}

static void append_destination(struct kdbus_msg_data **d, const char *s, size_t length) {
        assert(d);
        assert(d);

        (*d)->size = offsetof(struct kdbus_msg_data, data) + length + 1;
        (*d)->type = KDBUS_MSG_DST_NAME;
        memcpy((*d)->data, s, length + 1);

        *d = (struct kdbus_msg_data*) ((uint8_t*) *d + ALIGN8((*d)->size));
}

static int bus_message_setup_kmsg(sd_bus_message *m) {
        struct kdbus_msg_data *d;
        bool well_known;
        uint64_t unique;
        size_t sz, dl;
        int r;

        assert(m);
        assert(m->sealed);
        assert(!m->kdbus);

        if (m->destination) {
                r = parse_unique_name(m->destination, &unique);
                if (r < 0)
                        return r;

                well_known = r == 0;
        } else
                well_known = false;

        sz = offsetof(struct kdbus_msg, data);

        /* Add in fixed header, fields header, fields header padding and payload */
        sz += 4 * ALIGN8(offsetof(struct kdbus_msg_data, vec) + sizeof(struct kdbus_vec));

        /* Add in well-known destination header */
        if (well_known) {
                dl = strlen(m->destination);
                sz += ALIGN8(offsetof(struct kdbus_msg, data) + dl + 1);
        }

        m->kdbus = malloc0(sz);
        if (!m->kdbus)
                return -ENOMEM;

        m->kdbus->flags =
                ((m->header->flags & SD_BUS_MESSAGE_NO_REPLY_EXPECTED) ? 0 : KDBUS_MSG_FLAGS_EXPECT_REPLY) |
                ((m->header->flags & SD_BUS_MESSAGE_NO_AUTO_START) ? KDBUS_MSG_FLAGS_NO_AUTO_START : 0);
        m->kdbus->dst_id =
                well_known ? 0 :
                m->destination ? unique : (uint64_t) -1;
        m->kdbus->payload_type = KDBUS_PAYLOAD_DBUS1;
        m->kdbus->cookie = m->header->serial;

        m->kdbus->timeout_ns = m->timeout * NSEC_PER_USEC;

        d = m->kdbus->data;

        if (well_known)
                append_destination(&d, m->destination, dl);

        append_payload_vec(&d, m->header, sizeof(*m->header));

        if (m->fields) {
                append_payload_vec(&d, m->fields, m->header->fields_size);

                if (m->header->fields_size % 8 != 0) {
                        static const uint8_t padding[7] = {};

                        append_payload_vec(&d, padding, 8 - (m->header->fields_size % 8));
                }
        }

        if (m->body)
                append_payload_vec(&d, m->body, m->header->body_size);

        m->kdbus->size = (uint8_t*) m - (uint8_t*) m->kdbus;
        assert(m->kdbus->size <= sz);

        return 0;
}

int bus_kernel_take_fd(sd_bus *b) {
        struct kdbus_cmd_hello hello = {};
        int r;

        assert(b);

        r = ioctl(b->input_fd, KDBUS_CMD_HELLO, &hello);
        if (r < 0)
                return -errno;

        if (asprintf(&b->unique_name, ":1.%llu", (unsigned long long) hello.id) < 0)
                return -ENOMEM;

        b->is_kernel = true;

        r = bus_start_running(b);
        if (r < 0)
                return r;

        return 1;
}

int bus_kernel_connect(sd_bus *b) {
        assert(b);
        assert(b->input_fd < 0);
        assert(b->output_fd < 0);
        assert(b->kernel);

        b->input_fd = open(b->kernel, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (b->input_fd)
                return -errno;

        b->output_fd = b->input_fd;

        return bus_kernel_take_fd(b);
}

int bus_kernel_write_message(sd_bus *bus, sd_bus_message *m) {
        int r;

        assert(bus);
        assert(m);
        assert(bus->state == BUS_RUNNING);

        r = bus_message_setup_kmsg(m);
        if (r < 0)
                return r;

        r = ioctl(bus->output_fd, KDBUS_CMD_MSG_SEND, m->kdbus);
        if (r < 0)
                return errno == EAGAIN ? 0 : -errno;

        return 0;
}

static void close_kdbus_msg(struct kdbus_msg *k) {
        struct kdbus_msg_data *d;

        KDBUS_MSG_FOREACH_DATA(d, k) {

                if (d->type != KDBUS_MSG_UNIX_FDS)
                        continue;

                close_many(d->fds, (d->size - offsetof(struct kdbus_msg_data, fds)) / sizeof(int));
        }
}

static int bus_kernel_make_message(sd_bus *bus, struct kdbus_msg *k, sd_bus_message **ret) {
        sd_bus_message *m = NULL;
        struct kdbus_msg_data *d;
        unsigned n_payload = 0, n_fds = 0;
        _cleanup_free_ int *fds = NULL;
        struct bus_header *h = NULL;
        size_t total, n_bytes = 0, idx = 0;
        int r;

        assert(bus);
        assert(k);
        assert(ret);

        if (k->payload_type != KDBUS_PAYLOAD_DBUS1)
                return 0;

        KDBUS_MSG_FOREACH_DATA(d, k) {
                size_t l;

                l = d->size - offsetof(struct kdbus_msg_data, data);

                if (d->type == KDBUS_MSG_PAYLOAD) {

                        if (!h) {
                                if (l < sizeof(struct bus_header))
                                        return -EBADMSG;

                                h = (struct bus_header*) d->data;
                        }

                        n_payload++;
                        n_bytes += l;

                } else if (d->type == KDBUS_MSG_UNIX_FDS) {
                        int *f;
                        unsigned j;

                        j = l / sizeof(int);
                        f = realloc(fds, sizeof(int) * (n_fds + j));
                        if (!f)
                                return -ENOMEM;

                        fds = f;
                        memcpy(fds + n_fds, d->fds, j);
                        n_fds += j;
                }
        }

        if (!h)
                return -EBADMSG;

        r = bus_header_size(h, &total);
        if (r < 0)
                return r;

        if (n_bytes != total)
                return -EBADMSG;

        r = bus_message_from_header(h, sizeof(struct bus_header), fds, n_fds, NULL, NULL, 0, &m);
        if (r < 0)
                return r;

        KDBUS_MSG_FOREACH_DATA(d, k) {
                size_t l;

                if (d->type != KDBUS_MSG_PAYLOAD)
                        continue;

                l = d->size - offsetof(struct kdbus_msg_data, data);

                if (idx == sizeof(struct bus_header) &&
                    l == BUS_MESSAGE_FIELDS_SIZE(m))
                        m->fields = d->data;
                else if (idx == sizeof(struct bus_header) + ALIGN8(BUS_MESSAGE_FIELDS_SIZE(m)) &&
                         l == BUS_MESSAGE_BODY_SIZE(m))
                        m->body = d->data;
                else {
                        sd_bus_message_unref(m);
                        return -EBADMSG;
                }

                idx += l;
        }

        r = bus_message_parse_fields(m);
        if (r < 0) {
                sd_bus_message_unref(m);
                return r;
        }

        /* We take possession of the kmsg struct now */
        m->kdbus = k;
        m->free_kdbus = true;
        m->free_fds = true;

        fds = NULL;

        *ret = m;
        return 1;
}

int bus_kernel_read_message(sd_bus *bus, sd_bus_message **m) {
        struct kdbus_msg *k;
        size_t sz = 128;
        int r;

        assert(bus);
        assert(m);

        for (;;) {
                void *q;

                q = realloc(bus->rbuffer, sz);
                if (!q)
                        return -errno;

                k = bus->rbuffer = q;
                k->size = sz;

                r = ioctl(bus->input_fd, KDBUS_CMD_MSG_RECV, bus->rbuffer);
                if (r >= 0)
                        break;

                if (errno == EAGAIN)
                        return 0;

                if (errno != -EMSGSIZE)
                        return -errno;

                sz *= 2;
        }

        r = bus_kernel_make_message(bus, k, m);
        if (r > 0)
                bus->rbuffer = NULL;
        else
                close_kdbus_msg(k);

        return r;
}

int bus_kernel_create(const char *name, char **s) {
        struct kdbus_cmd_fname *fname;
        size_t l;
        int fd;
        char *p;

        assert(name);
        assert(s);

        fd = open("/dev/kdbus/control", O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        l = strlen(name);
        fname = alloca(offsetof(struct kdbus_cmd_fname, name) + DECIMAL_STR_MAX(uid_t) + 1 + l + 1);
        sprintf(fname->name, "%lu-%s", (unsigned long) getuid(), name);
        fname->size = offsetof(struct kdbus_cmd_fname, name) + strlen(fname->name) + 1;
        fname->kernel_flags = KDBUS_CMD_FNAME_ACCESS_WORLD;
        fname->user_flags = 0;

        p = strjoin("/dev/kdbus/", fname->name, "/bus", NULL);
        if (!p)
                return -ENOMEM;

        if (ioctl(fd, KDBUS_CMD_BUS_MAKE, &fname) < 0) {
                close_nointr_nofail(fd);
                free(p);
                return -errno;
        }

        if (s)
                *s = p;

        return fd;
}
