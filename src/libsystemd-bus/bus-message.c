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

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "util.h"
#include "utf8.h"
#include "strv.h"
#include "time-util.h"
#include "cgroup-util.h"

#include "sd-bus.h"
#include "bus-message.h"
#include "bus-internal.h"
#include "bus-type.h"
#include "bus-signature.h"

static int message_append_basic(sd_bus_message *m, char type, const void *p, const void **stored);

static void *adjust_pointer(const void *p, void *old_base, size_t sz, void *new_base) {

        if (p == NULL)
                return NULL;

        if (old_base == new_base)
                return (void*) p;

        if ((uint8_t*) p < (uint8_t*) old_base)
                return (void*) p;

        if ((uint8_t*) p >= (uint8_t*) old_base + sz)
                return (void*) p;

        return (uint8_t*) new_base + ((uint8_t*) p - (uint8_t*) old_base);
}

static void message_free_part(sd_bus_message *m, struct bus_body_part *part) {
        assert(m);
        assert(part);

        if (part->memfd >= 0) {
                /* If we can reuse the memfd, try that. For that it
                 * can't be sealed yet. */

                if (!part->sealed)
                        bus_kernel_push_memfd(m->bus, part->memfd, part->data, part->mapped);
                else {
                        if (part->mapped > 0)
                                assert_se(munmap(part->data, part->mapped) == 0);

                        close_nointr_nofail(part->memfd);
                }

        } else if (part->munmap_this)
                munmap(part->data, part->mapped);
        else if (part->free_this)
                free(part->data);

        if (part != &m->body)
                free(part);
}

static void message_reset_parts(sd_bus_message *m) {
        struct bus_body_part *part;

        assert(m);

        part = &m->body;
        while (m->n_body_parts > 0) {
                struct bus_body_part *next = part->next;
                message_free_part(m, part);
                part = next;
                m->n_body_parts--;
        }

        m->body_end = NULL;

        m->cached_rindex_part = NULL;
        m->cached_rindex_part_begin = 0;
}

static void message_reset_containers(sd_bus_message *m) {
        unsigned i;

        assert(m);

        for (i = 0; i < m->n_containers; i++)
                free(m->containers[i].signature);

        free(m->containers);
        m->containers = NULL;

        m->n_containers = 0;
        m->root_container.index = 0;
}

static void message_free(sd_bus_message *m) {
        assert(m);

        if (m->free_header)
                free(m->header);

        message_reset_parts(m);

        if (m->free_kdbus)
                free(m->kdbus);

        if (m->release_kdbus) {
                uint64_t off;

                off = (uint8_t *)m->kdbus - (uint8_t *)m->bus->kdbus_buffer;
                ioctl(m->bus->input_fd, KDBUS_CMD_MSG_RELEASE, &off);
        }

        if (m->bus)
                sd_bus_unref(m->bus);

        if (m->free_fds) {
                close_many(m->fds, m->n_fds);
                free(m->fds);
        }

        if (m->iovec != m->iovec_fixed)
                free(m->iovec);

        free(m->cmdline_array);

        message_reset_containers(m);
        free(m->root_container.signature);

        free(m->peeked_signature);

        free(m->unit);
        free(m->user_unit);
        free(m->session);
        free(m);
}

static void *message_extend_fields(sd_bus_message *m, size_t align, size_t sz) {
        void *op, *np;
        size_t old_size, new_size, start;

        assert(m);

        if (m->poisoned)
                return NULL;

        old_size = sizeof(struct bus_header) + m->header->fields_size;
        start = ALIGN_TO(old_size, align);
        new_size = start + sz;

        if (old_size == new_size)
                return (uint8_t*) m->header + old_size;

        if (new_size > (size_t) ((uint32_t) -1))
                goto poison;

        if (m->free_header) {
                np = realloc(m->header, ALIGN8(new_size));
                if (!np)
                        goto poison;
        } else {
                /* Initially, the header is allocated as part of of
                 * the sd_bus_message itself, let's replace it by
                 * dynamic data */

                np = malloc(ALIGN8(new_size));
                if (!np)
                        goto poison;

                memcpy(np, m->header, sizeof(struct bus_header));
        }

        /* Zero out padding */
        if (start > old_size)
                memset((uint8_t*) np + old_size, 0, start - old_size);

        op = m->header;
        m->header = np;
        m->header->fields_size = new_size - sizeof(struct bus_header);

        /* Adjust quick access pointers */
        m->path = adjust_pointer(m->path, op, old_size, m->header);
        m->interface = adjust_pointer(m->interface, op, old_size, m->header);
        m->member = adjust_pointer(m->member, op, old_size, m->header);
        m->destination = adjust_pointer(m->destination, op, old_size, m->header);
        m->sender = adjust_pointer(m->sender, op, old_size, m->header);
        m->error.name = adjust_pointer(m->error.name, op, old_size, m->header);

        m->free_header = true;

        return (uint8_t*) np + start;

poison:
        m->poisoned = true;
        return NULL;
}

static int message_append_field_string(
                sd_bus_message *m,
                uint8_t h,
                char type,
                const char *s,
                const char **ret) {

        size_t l;
        uint8_t *p;

        assert(m);

        l = strlen(s);
        if (l > (size_t) (uint32_t) -1)
                return -EINVAL;

        /* field id byte + signature length + signature 's' + NUL + string length + string + NUL */
        p = message_extend_fields(m, 8, 4 + 4 + l + 1);
        if (!p)
                return -ENOMEM;

        p[0] = h;
        p[1] = 1;
        p[2] = type;
        p[3] = 0;

        ((uint32_t*) p)[1] = l;
        memcpy(p + 8, s, l + 1);

        if (ret)
                *ret = (char*) p + 8;

        return 0;
}

static int message_append_field_signature(
                sd_bus_message *m,
                uint8_t h,
                const char *s,
                const char **ret) {

        size_t l;
        uint8_t *p;

        assert(m);

        l = strlen(s);
        if (l > 255)
                return -EINVAL;

        /* field id byte + signature length + signature 'g' + NUL + string length + string + NUL */
        p = message_extend_fields(m, 8, 4 + 1 + l + 1);
        if (!p)
                return -ENOMEM;

        p[0] = h;
        p[1] = 1;
        p[2] = SD_BUS_TYPE_SIGNATURE;
        p[3] = 0;
        p[4] = l;
        memcpy(p + 5, s, l + 1);

        if (ret)
                *ret = (const char*) p + 5;

        return 0;
}

static int message_append_field_uint32(sd_bus_message *m, uint8_t h, uint32_t x) {
        uint8_t *p;

        assert(m);

        /* field id byte + signature length + signature 'u' + NUL + value */
        p = message_extend_fields(m, 8, 4 + 4);
        if (!p)
                return -ENOMEM;

        p[0] = h;
        p[1] = 1;
        p[2] = SD_BUS_TYPE_UINT32;
        p[3] = 0;

        ((uint32_t*) p)[1] = x;

        return 0;
}

int bus_message_from_header(
                void *buffer,
                size_t length,
                int *fds,
                unsigned n_fds,
                const struct ucred *ucred,
                const char *label,
                size_t extra,
                sd_bus_message **ret) {

        sd_bus_message *m;
        struct bus_header *h;
        size_t a, label_sz;

        assert(buffer || length <= 0);
        assert(fds || n_fds <= 0);
        assert(ret);

        if (length < sizeof(struct bus_header))
                return -EBADMSG;

        h = buffer;
        if (h->version != 1)
                return -EBADMSG;

        if (h->serial == 0)
                return -EBADMSG;

        if (h->type == _SD_BUS_MESSAGE_TYPE_INVALID)
                return -EBADMSG;

        if (h->endian != SD_BUS_LITTLE_ENDIAN &&
            h->endian != SD_BUS_BIG_ENDIAN)
                return -EBADMSG;

        a = ALIGN(sizeof(sd_bus_message)) + ALIGN(extra);

        if (label) {
                label_sz = strlen(label);
                a += label_sz + 1;
        }

        m = malloc0(a);
        if (!m)
                return -ENOMEM;

        m->n_ref = 1;
        m->sealed = true;
        m->header = h;
        m->fds = fds;
        m->n_fds = n_fds;

        if (ucred) {
                m->uid = ucred->uid;
                m->pid = ucred->pid;
                m->gid = ucred->gid;
                m->uid_valid = m->gid_valid = true;
        }

        if (label) {
                m->label = (char*) m + ALIGN(sizeof(sd_bus_message)) + ALIGN(extra);
                memcpy(m->label, label, label_sz + 1);
        }

        *ret = m;
        return 0;
}

int bus_message_from_malloc(
                void *buffer,
                size_t length,
                int *fds,
                unsigned n_fds,
                const struct ucred *ucred,
                const char *label,
                sd_bus_message **ret) {

        sd_bus_message *m;
        int r;

        r = bus_message_from_header(buffer, length, fds, n_fds, ucred, label, 0, &m);
        if (r < 0)
                return r;

        if (length != BUS_MESSAGE_SIZE(m)) {
                r = -EBADMSG;
                goto fail;
        }

        m->n_body_parts = 1;
        m->body.data = (uint8_t*) buffer + sizeof(struct bus_header) + ALIGN8(BUS_MESSAGE_FIELDS_SIZE(m));
        m->body.size = length - sizeof(struct bus_header) - ALIGN8(BUS_MESSAGE_FIELDS_SIZE(m));
        m->body.sealed = true;
        m->body.memfd = -1;

        m->n_iovec = 1;
        m->iovec = m->iovec_fixed;
        m->iovec[0].iov_base = buffer;
        m->iovec[0].iov_len = length;

        r = bus_message_parse_fields(m);
        if (r < 0)
                goto fail;

        /* We take possession of the memory and fds now */
        m->free_header = true;
        m->free_fds = true;

        *ret = m;
        return 0;

fail:
        message_free(m);
        return r;
}

static sd_bus_message *message_new(sd_bus *bus, uint8_t type) {
        sd_bus_message *m;

        m = malloc0(ALIGN(sizeof(sd_bus_message)) + sizeof(struct bus_header));
        if (!m)
                return NULL;

        m->n_ref = 1;
        m->header = (struct bus_header*) ((uint8_t*) m + ALIGN(sizeof(struct sd_bus_message)));
        m->header->endian = SD_BUS_NATIVE_ENDIAN;
        m->header->type = type;
        m->header->version = bus ? bus->message_version : 1;
        m->allow_fds = !bus || bus->can_fds || (bus->state != BUS_HELLO && bus->state != BUS_RUNNING);

        if (bus)
                m->bus = sd_bus_ref(bus);

        return m;
}

int sd_bus_message_new_signal(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_message **m) {

        sd_bus_message *t;
        int r;

        if (!path)
                return -EINVAL;
        if (!interface)
                return -EINVAL;
        if (!member)
                return -EINVAL;
        if (!m)
                return -EINVAL;
        if (bus && bus->state == BUS_UNSET)
                return -ENOTCONN;

        t = message_new(bus, SD_BUS_MESSAGE_TYPE_SIGNAL);
        if (!t)
                return -ENOMEM;

        t->header->flags |= SD_BUS_MESSAGE_NO_REPLY_EXPECTED;

        r = message_append_field_string(t, SD_BUS_MESSAGE_HEADER_PATH, SD_BUS_TYPE_OBJECT_PATH, path, &t->path);
        if (r < 0)
                goto fail;
        r = message_append_field_string(t, SD_BUS_MESSAGE_HEADER_INTERFACE, SD_BUS_TYPE_STRING, interface, &t->interface);
        if (r < 0)
                goto fail;
        r = message_append_field_string(t, SD_BUS_MESSAGE_HEADER_MEMBER, SD_BUS_TYPE_STRING, member, &t->member);
        if (r < 0)
                goto fail;

        *m = t;
        return 0;

fail:
        sd_bus_message_unref(t);
        return r;
}

int sd_bus_message_new_method_call(
                sd_bus *bus,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_message **m) {

        sd_bus_message *t;
        int r;

        if (!path)
                return -EINVAL;
        if (!member)
                return -EINVAL;
        if (!m)
                return -EINVAL;
        if (bus && bus->state == BUS_UNSET)
                return -ENOTCONN;

        t = message_new(bus, SD_BUS_MESSAGE_TYPE_METHOD_CALL);
        if (!t)
                return -ENOMEM;

        r = message_append_field_string(t, SD_BUS_MESSAGE_HEADER_PATH, SD_BUS_TYPE_OBJECT_PATH, path, &t->path);
        if (r < 0)
                goto fail;
        r = message_append_field_string(t, SD_BUS_MESSAGE_HEADER_MEMBER, SD_BUS_TYPE_STRING, member, &t->member);
        if (r < 0)
                goto fail;

        if (interface) {
                r = message_append_field_string(t, SD_BUS_MESSAGE_HEADER_INTERFACE, SD_BUS_TYPE_STRING, interface, &t->interface);
                if (r < 0)
                        goto fail;
        }

        if (destination) {
                r = message_append_field_string(t, SD_BUS_MESSAGE_HEADER_DESTINATION, SD_BUS_TYPE_STRING, destination, &t->destination);
                if (r < 0)
                        goto fail;
        }

        *m = t;
        return 0;

fail:
        message_free(t);
        return r;
}

static int message_new_reply(
                sd_bus *bus,
                sd_bus_message *call,
                uint8_t type,
                sd_bus_message **m) {

        sd_bus_message *t;
        int r;

        if (!call)
                return -EINVAL;
        if (!call->sealed)
                return -EPERM;
        if (call->header->type != SD_BUS_MESSAGE_TYPE_METHOD_CALL)
                return -EINVAL;
        if (!m)
                return -EINVAL;
        if (bus && bus->state == BUS_UNSET)
                return -ENOTCONN;

        t = message_new(bus, type);
        if (!t)
                return -ENOMEM;

        t->header->flags |= SD_BUS_MESSAGE_NO_REPLY_EXPECTED;
        t->reply_serial = BUS_MESSAGE_SERIAL(call);

        r = message_append_field_uint32(t, SD_BUS_MESSAGE_HEADER_REPLY_SERIAL, t->reply_serial);
        if (r < 0)
                goto fail;

        if (call->sender) {
                r = message_append_field_string(t, SD_BUS_MESSAGE_HEADER_DESTINATION, SD_BUS_TYPE_STRING, call->sender, &t->destination);
                if (r < 0)
                        goto fail;
        }

        t->dont_send = !!(call->header->flags & SD_BUS_MESSAGE_NO_REPLY_EXPECTED);

        *m = t;
        return 0;

fail:
        message_free(t);
        return r;
}

int sd_bus_message_new_method_return(
                sd_bus *bus,
                sd_bus_message *call,
                sd_bus_message **m) {

        return message_new_reply(bus, call, SD_BUS_MESSAGE_TYPE_METHOD_RETURN, m);
}

int sd_bus_message_new_method_error(
                sd_bus *bus,
                sd_bus_message *call,
                const sd_bus_error *e,
                sd_bus_message **m) {

        sd_bus_message *t;
        int r;

        if (!sd_bus_error_is_set(e))
                return -EINVAL;
        if (!m)
                return -EINVAL;

        r = message_new_reply(bus, call, SD_BUS_MESSAGE_TYPE_METHOD_ERROR, &t);
        if (r < 0)
                return r;

        r = message_append_field_string(t, SD_BUS_MESSAGE_HEADER_ERROR_NAME, SD_BUS_TYPE_STRING, e->name, &t->error.name);
        if (r < 0)
                goto fail;

        if (e->message) {
                r = message_append_basic(t, SD_BUS_TYPE_STRING, e->message, (const void**) &t->error.message);
                if (r < 0)
                        goto fail;
        }

        *m = t;
        return 0;

fail:
        message_free(t);
        return r;
}

int bus_message_new_synthetic_error(
                sd_bus *bus,
                uint64_t serial,
                const sd_bus_error *e,
                sd_bus_message **m) {

        sd_bus_message *t;
        int r;

        assert(sd_bus_error_is_set(e));
        assert(m);

        t = message_new(bus, SD_BUS_MESSAGE_TYPE_METHOD_ERROR);
        if (!t)
                return -ENOMEM;

        t->header->flags |= SD_BUS_MESSAGE_NO_REPLY_EXPECTED;
        t->reply_serial = serial;

        r = message_append_field_uint32(t, SD_BUS_MESSAGE_HEADER_REPLY_SERIAL, t->reply_serial);
        if (r < 0)
                goto fail;

        if (bus && bus->unique_name) {
                r = message_append_field_string(t, SD_BUS_MESSAGE_HEADER_DESTINATION, SD_BUS_TYPE_STRING, bus->unique_name, &t->destination);
                if (r < 0)
                        goto fail;
        }

        *m = t;
        return 0;

fail:
        message_free(t);
        return r;
}

sd_bus_message* sd_bus_message_ref(sd_bus_message *m) {
        if (!m)
                return NULL;

        assert(m->n_ref > 0);
        m->n_ref++;

        return m;
}

sd_bus_message* sd_bus_message_unref(sd_bus_message *m) {
        if (!m)
                return NULL;

        assert(m->n_ref > 0);
        m->n_ref--;

        if (m->n_ref <= 0)
                message_free(m);

        return NULL;
}

int sd_bus_message_get_type(sd_bus_message *m, uint8_t *type) {
        if (!m)
                return -EINVAL;
        if (!type)
                return -EINVAL;

        *type = m->header->type;
        return 0;
}

int sd_bus_message_get_serial(sd_bus_message *m, uint64_t *serial) {
        if (!m)
                return -EINVAL;
        if (!serial)
                return -EINVAL;
        if (m->header->serial == 0)
                return -ENOENT;

        *serial = BUS_MESSAGE_SERIAL(m);
        return 0;
}

int sd_bus_message_get_reply_serial(sd_bus_message *m, uint64_t *serial) {
        if (!m)
                return -EINVAL;
        if (!serial)
                return -EINVAL;
        if (m->reply_serial == 0)
                return -ENOENT;

        *serial = m->reply_serial;
        return 0;
}

int sd_bus_message_get_no_reply(sd_bus_message *m) {
        if (!m)
                return -EINVAL;

        return m->header->type == SD_BUS_MESSAGE_TYPE_METHOD_CALL ? !!(m->header->flags & SD_BUS_MESSAGE_NO_REPLY_EXPECTED) : 0;
}

const char *sd_bus_message_get_path(sd_bus_message *m) {
        if (!m)
                return NULL;

        return m->path;
}

const char *sd_bus_message_get_interface(sd_bus_message *m) {
        if (!m)
                return NULL;

        return m->interface;
}

const char *sd_bus_message_get_member(sd_bus_message *m) {
        if (!m)
                return NULL;

        return m->member;
}
const char *sd_bus_message_get_destination(sd_bus_message *m) {
        if (!m)
                return NULL;

        return m->destination;
}

const char *sd_bus_message_get_sender(sd_bus_message *m) {
        if (!m)
                return NULL;

        return m->sender;
}

const sd_bus_error *sd_bus_message_get_error(sd_bus_message *m) {
        if (!m)
                return NULL;

        if (!sd_bus_error_is_set(&m->error))
                return NULL;

        return &m->error;
}

int sd_bus_message_get_uid(sd_bus_message *m, uid_t *uid) {
        if (!m)
                return -EINVAL;
        if (!uid)
                return -EINVAL;
        if (!m->uid_valid)
                return -ESRCH;

        *uid = m->uid;
        return 0;
}

int sd_bus_message_get_gid(sd_bus_message *m, gid_t *gid) {
        if (!m)
                return -EINVAL;
        if (!gid)
                return -EINVAL;
        if (!m->gid_valid)
                return -ESRCH;

        *gid = m->gid;
        return 0;
}

int sd_bus_message_get_pid(sd_bus_message *m, pid_t *pid) {
        if (!m)
                return -EINVAL;
        if (!pid)
                return -EINVAL;
        if (m->pid <= 0)
                return -ESRCH;

        *pid = m->pid;
        return 0;
}

int sd_bus_message_get_tid(sd_bus_message *m, pid_t *tid) {
        if (!m)
                return -EINVAL;
        if (!tid)
                return -EINVAL;
        if (m->tid <= 0)
                return -ESRCH;

        *tid = m->tid;
        return 0;
}

int sd_bus_message_get_pid_starttime(sd_bus_message *m, uint64_t *usec) {
        if (!m)
                return -EINVAL;
        if (!usec)
                return -EINVAL;
        if (m->pid_starttime <= 0)
                return -ESRCH;

        *usec = m->pid_starttime;
        return 0;
}

int sd_bus_message_get_selinux_context(sd_bus_message *m, const char **ret) {
        if (!m)
                return -EINVAL;
        if (!m->label)
                return -ESRCH;

        *ret = m->label;
        return 0;
}

int sd_bus_message_get_monotonic_timestamp(sd_bus_message *m, uint64_t *usec) {
        if (!m)
                return -EINVAL;
        if (!usec)
                return -EINVAL;
        if (m->monotonic <= 0)
                return -ESRCH;

        *usec = m->monotonic;
        return 0;
}

int sd_bus_message_get_realtime_timestamp(sd_bus_message *m, uint64_t *usec) {
        if (!m)
                return -EINVAL;
        if (!usec)
                return -EINVAL;
        if (m->realtime <= 0)
                return -ESRCH;

        *usec = m->realtime;
        return 0;
}

int sd_bus_message_get_comm(sd_bus_message *m, const char **ret) {
        if (!m)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (!m->comm)
                return -ESRCH;

        *ret = m->comm;
        return 0;
}

int sd_bus_message_get_tid_comm(sd_bus_message *m, const char **ret) {
        if (!m)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (!m->tid_comm)
                return -ESRCH;

        *ret = m->tid_comm;
        return 0;
}

int sd_bus_message_get_exe(sd_bus_message *m, const char **ret) {
        if (!m)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (!m->exe)
                return -ESRCH;

        *ret = m->exe;
        return 0;
}

int sd_bus_message_get_cgroup(sd_bus_message *m, const char **ret) {
        if (!m)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (!m->cgroup)
                return -ESRCH;

        *ret = m->cgroup;
        return 0;
}

int sd_bus_message_get_unit(sd_bus_message *m, const char **ret) {
        int r;

        if (!m)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (!m->cgroup)
                return -ESRCH;

        if (!m->unit) {
                r = cg_path_get_unit(m->cgroup, &m->unit);
                if (r < 0)
                        return r;
        }

        *ret = m->unit;
        return 0;
}

int sd_bus_message_get_user_unit(sd_bus_message *m, const char **ret) {
        int r;

        if (!m)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (!m->cgroup)
                return -ESRCH;

        if (!m->user_unit) {
                r = cg_path_get_user_unit(m->cgroup, &m->user_unit);
                if (r < 0)
                        return r;
        }

        *ret = m->user_unit;
        return 0;
}

int sd_bus_message_get_session(sd_bus_message *m, const char **ret) {
        int r;

        if (!m)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (!m->cgroup)
                return -ESRCH;

        if (!m->session) {
                r = cg_path_get_session(m->cgroup, &m->session);
                if (r < 0)
                        return r;
        }

        *ret = m->session;
        return 0;
}

int sd_bus_message_get_owner_uid(sd_bus_message *m, uid_t *uid) {
        if (!m)
                return -EINVAL;
        if (!uid)
                return -EINVAL;
        if (!m->cgroup)
                return -ESRCH;

        return cg_path_get_owner_uid(m->cgroup, uid);
}

int sd_bus_message_get_cmdline(sd_bus_message *m, char ***cmdline) {
        size_t n, i;
        const char *p;
        bool first;

        if (!m)
                return -EINVAL;

        if (!m->cmdline)
                return -ENOENT;

        for (p = m->cmdline, n = 0; p < m->cmdline + m->cmdline_length; p++)
                if (*p == 0)
                        n++;

        m->cmdline_array = new(char*, n + 1);
        if (!m->cmdline_array)
                return -ENOMEM;

        for (p = m->cmdline, i = 0, first = true; p < m->cmdline + m->cmdline_length; p++) {
                if (first)
                        m->cmdline_array[i++] = (char*) p;

                first = *p == 0;
        }

        m->cmdline_array[i] = NULL;
        *cmdline = m->cmdline_array;

        return 0;
}

int sd_bus_message_get_audit_sessionid(sd_bus_message *m, uint32_t *sessionid) {
        if (!m)
                return -EINVAL;
        if (!sessionid)
                return -EINVAL;
        if (!m->audit)
                return -ESRCH;

        *sessionid = m->audit->sessionid;
        return 0;
}

int sd_bus_message_get_audit_loginuid(sd_bus_message *m, uid_t *uid) {
        if (!m)
                return -EINVAL;
        if (!uid)
                return -EINVAL;
        if (!m->audit)
                return -ESRCH;

        *uid = m->audit->loginuid;
        return 0;
}

int sd_bus_message_has_effective_cap(sd_bus_message *m, int capability) {
        unsigned sz;

        if (!m)
                return -EINVAL;
        if (capability < 0)
                return -EINVAL;
        if (!m->capability)
                return -ESRCH;

        sz = m->capability_size / 4;
        if ((unsigned) capability >= sz*8)
                return 0;

        return !!(m->capability[2 * sz + (capability / 8)] & (1 << (capability % 8)));
}

int sd_bus_message_is_signal(sd_bus_message *m, const char *interface, const char *member) {
        if (!m)
                return -EINVAL;

        if (m->header->type != SD_BUS_MESSAGE_TYPE_SIGNAL)
                return 0;

        if (interface && (!m->interface || !streq(m->interface, interface)))
                return 0;

        if (member &&  (!m->member || !streq(m->member, member)))
                return 0;

        return 1;
}

int sd_bus_message_is_method_call(sd_bus_message *m, const char *interface, const char *member) {
        if (!m)
                return -EINVAL;

        if (m->header->type != SD_BUS_MESSAGE_TYPE_METHOD_CALL)
                return 0;

        if (interface && (!m->interface || !streq(m->interface, interface)))
                return 0;

        if (member &&  (!m->member || !streq(m->member, member)))
                return 0;

        return 1;
}

int sd_bus_message_is_method_error(sd_bus_message *m, const char *name) {
        if (!m)
                return -EINVAL;

        if (m->header->type != SD_BUS_MESSAGE_TYPE_METHOD_ERROR)
                return 0;

        if (name && (!m->error.name || !streq(m->error.name, name)))
                return 0;

        return 1;
}

int sd_bus_message_set_no_reply(sd_bus_message *m, int b) {
        if (!m)
                return -EINVAL;
        if (m->sealed)
                return -EPERM;
        if (m->header->type != SD_BUS_MESSAGE_TYPE_METHOD_CALL)
                return -EPERM;

        if (b)
                m->header->flags |= SD_BUS_MESSAGE_NO_REPLY_EXPECTED;
        else
                m->header->flags &= ~SD_BUS_MESSAGE_NO_REPLY_EXPECTED;

        return 0;
}

static struct bus_container *message_get_container(sd_bus_message *m) {
        assert(m);

        if (m->n_containers == 0)
                return &m->root_container;

        assert(m->containers);
        return m->containers + m->n_containers - 1;
}

struct bus_body_part *message_append_part(sd_bus_message *m) {
        struct bus_body_part *part;

        assert(m);

        if (m->poisoned)
                return NULL;

        if (m->n_body_parts <= 0) {
                part = &m->body;
                zero(*part);
        } else {
                assert(m->body_end);

                part = new0(struct bus_body_part, 1);
                if (!part) {
                        m->poisoned = true;
                        return NULL;
                }

                m->body_end->next = part;
        }

        part->memfd = -1;
        m->body_end = part;
        m->n_body_parts ++;

        return part;
}

static void part_zero(struct bus_body_part *part, size_t sz) {
        assert(part);
        assert(sz > 0);
        assert(sz < 8);

        /* All other fields can be left in their defaults */
        assert(!part->data);
        assert(part->memfd < 0);

        part->size = sz;
        part->is_zero = true;
        part->sealed = true;
}

static int part_make_space(
                struct sd_bus_message *m,
                struct bus_body_part *part,
                size_t sz,
                void **q) {

        void *n;
        int r;

        assert(m);
        assert(part);
        assert(!part->sealed);

        if (m->poisoned)
                return -ENOMEM;

        if (!part->data && part->memfd < 0)
                part->memfd = bus_kernel_pop_memfd(m->bus, &part->data, &part->mapped);

        if (part->memfd >= 0) {
                uint64_t u = sz;

                r = ioctl(part->memfd, KDBUS_CMD_MEMFD_SIZE_SET, &u);
                if (r < 0) {
                        m->poisoned = true;
                        return -errno;
                }

                if (!part->data || sz > part->mapped) {
                        size_t psz = PAGE_ALIGN(sz > 0 ? sz : 1);

                        if (part->mapped <= 0)
                                n = mmap(NULL, psz, PROT_READ|PROT_WRITE, MAP_SHARED, part->memfd, 0);
                        else
                                n = mremap(part->data, part->mapped, psz, MREMAP_MAYMOVE);

                        if (n == MAP_FAILED) {
                                m->poisoned = true;
                                return -errno;
                        }

                        part->mapped = psz;
                        part->data = n;
                }

                part->munmap_this = true;
        } else {
                n = realloc(part->data, sz);
                if (!n) {
                        m->poisoned = true;
                        return -ENOMEM;
                }

                part->data = n;
                part->free_this = true;
        }

        if (q)
                *q = part->data ? (uint8_t*) part->data + part->size : NULL;

        part->size = sz;
        return 0;
}

static void message_extend_containers(sd_bus_message *m, size_t expand) {
        struct bus_container *c;

        assert(m);

        if (expand <= 0)
                return;

        /* Update counters */
        for (c = m->containers; c < m->containers + m->n_containers; c++)
                if (c->array_size)
                        *c->array_size += expand;
}

static void *message_extend_body(sd_bus_message *m, size_t align, size_t sz) {
        struct bus_body_part *part = NULL;
        size_t start_body, end_body, padding, start_part, end_part, added;
        bool add_new_part;
        void *p;
        int r;

        assert(m);
        assert(align > 0);
        assert(!m->sealed);

        if (m->poisoned)
                return NULL;

        start_body = ALIGN_TO((size_t) m->header->body_size, align);
        end_body = start_body + sz;

        padding = start_body - m->header->body_size;
        added = padding + sz;

        /* Check for 32bit overflows */
        if (end_body > (size_t) ((uint32_t) -1)) {
                m->poisoned = true;
                return NULL;
        }

        add_new_part =
                m->n_body_parts <= 0 ||
                m->body_end->sealed ||
                padding != ALIGN_TO(m->body_end->size, align) - m->body_end->size;

        if (add_new_part) {
                if (padding > 0) {
                        part = message_append_part(m);
                        if (!part)
                                return NULL;

                        part_zero(part, padding);
                }

                part = message_append_part(m);
                if (!part)
                        return NULL;

                r = part_make_space(m, part, sz, &p);
                if (r < 0)
                        return NULL;
        } else {
                struct bus_container *c;
                void *op;
                size_t os;

                part = m->body_end;
                op = part->data;
                os = part->size;

                start_part = ALIGN_TO(part->size, align);
                end_part = start_part + sz;

                r = part_make_space(m, part, end_part, &p);
                if (r < 0)
                        return NULL;

                if (padding > 0) {
                        memset(p, 0, padding);
                        p = (uint8_t*) p + padding;
                }

                /* Readjust pointers */
                for (c = m->containers; c < m->containers + m->n_containers; c++)
                        c->array_size = adjust_pointer(c->array_size, op, os, part->data);

                m->error.message = (const char*) adjust_pointer(m->error.message, op, os, part->data);
        }

        m->header->body_size = end_body;
        message_extend_containers(m, added);

        return p;
}

int message_append_basic(sd_bus_message *m, char type, const void *p, const void **stored) {
        struct bus_container *c;
        ssize_t align, sz;
        uint32_t k;
        void *a;
        int fd = -1;
        uint32_t fdi = 0;
        int r;

        if (!m)
                return -EINVAL;
        if (!p)
                return -EINVAL;
        if (m->sealed)
                return -EPERM;
        if (!bus_type_is_basic(type))
                return -EINVAL;
        if (m->poisoned)
                return -ESTALE;

        c = message_get_container(m);

        if (c->signature && c->signature[c->index]) {
                /* Container signature is already set */

                if (c->signature[c->index] != type)
                        return -ENXIO;
        } else {
                char *e;

                /* Maybe we can append to the signature? But only if this is the top-level container*/
                if (c->enclosing != 0)
                        return -ENXIO;

                e = strextend(&c->signature, CHAR_TO_STR(type), NULL);
                if (!e) {
                        m->poisoned = true;
                        return -ENOMEM;
                }
        }

        switch (type) {

        case SD_BUS_TYPE_STRING:
        case SD_BUS_TYPE_OBJECT_PATH:

                align = 4;
                sz = 4 + strlen(p) + 1;
                break;

        case SD_BUS_TYPE_SIGNATURE:

                align = 1;
                sz = 1 + strlen(p) + 1;
                break;

        case SD_BUS_TYPE_BOOLEAN:
                align = sz = 4;

                assert_cc(sizeof(int) == sizeof(uint32_t));
                memcpy(&k, p, 4);
                k = !!k;
                p = &k;
                break;

        case SD_BUS_TYPE_UNIX_FD: {
                int z, *f;

                if (!m->allow_fds) {
                        r = -ENOTSUP;
                        goto fail;
                }

                align = sz = 4;

                z = *(int*) p;
                if (z < 0) {
                        r = -EINVAL;
                        goto fail;
                }

                fd = fcntl(z, F_DUPFD_CLOEXEC, 3);
                if (fd < 0) {
                        r = -errno;
                        goto fail;
                }

                f = realloc(m->fds, sizeof(int) * (m->n_fds + 1));
                if (!f) {
                        m->poisoned = true;
                        r = -ENOMEM;
                        goto fail;
                }

                fdi = m->n_fds;
                f[fdi] = fd;
                m->fds = f;
                m->free_fds = true;
                break;
        }

        default:
                align = bus_type_get_alignment(type);
                sz = bus_type_get_size(type);
                break;
        }

        assert(align > 0);
        assert(sz > 0);

        a = message_extend_body(m, align, sz);
        if (!a) {
                r = -ENOMEM;
                goto fail;
        }

        if (type == SD_BUS_TYPE_STRING || type == SD_BUS_TYPE_OBJECT_PATH) {
                *(uint32_t*) a = sz - 5;
                memcpy((uint8_t*) a + 4, p, sz - 4);

                if (stored)
                        *stored = (const uint8_t*) a + 4;

        } else if (type == SD_BUS_TYPE_SIGNATURE) {
                *(uint8_t*) a = sz - 1;
                memcpy((uint8_t*) a + 1, p, sz - 1);

                if (stored)
                        *stored = (const uint8_t*) a + 1;
        } else if (type == SD_BUS_TYPE_UNIX_FD) {
                *(uint32_t*) a = fdi;

                if (stored)
                        *stored = a;

                m->n_fds ++;

        } else {
                memcpy(a, p, sz);

                if (stored)
                        *stored = a;
        }

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index++;

        return 0;

fail:
        if (fd >= 0)
                close_nointr_nofail(fd);

        return r;
}

int sd_bus_message_append_basic(sd_bus_message *m, char type, const void *p) {
        return message_append_basic(m, type, p, NULL);
}

int sd_bus_message_append_string_space(sd_bus_message *m, size_t size, char **s) {
        struct bus_container *c;
        void *a;

        if (!m)
                return -EINVAL;
        if (!s)
                return -EINVAL;
        if (m->sealed)
                return -EPERM;
        if (m->poisoned)
                return -ESTALE;

        c = message_get_container(m);

        if (c->signature && c->signature[c->index]) {
                /* Container signature is already set */

                if (c->signature[c->index] != SD_BUS_TYPE_STRING)
                        return -ENXIO;
        } else {
                char *e;

                /* Maybe we can append to the signature? But only if this is the top-level container*/
                if (c->enclosing != 0)
                        return -ENXIO;

                e = strextend(&c->signature, CHAR_TO_STR(SD_BUS_TYPE_STRING), NULL);
                if (!e) {
                        m->poisoned = true;
                        return -ENOMEM;
                }
        }

        a = message_extend_body(m, 4, 4 + size + 1);
        if (!a)
                return -ENOMEM;

        *(uint32_t*) a = size;
        *s = (char*) a + 4;

        (*s)[size] = 0;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index++;

        return 0;
}

static int bus_message_open_array(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents,
                uint32_t **array_size) {

        unsigned nindex;
        void *a, *op;
        int alignment;
        size_t os;
        struct bus_body_part *o;

        assert(m);
        assert(c);
        assert(contents);
        assert(array_size);

        if (!signature_is_single(contents))
                return -EINVAL;

        alignment = bus_type_get_alignment(contents[0]);
        if (alignment < 0)
                return alignment;

        if (c->signature && c->signature[c->index]) {

                /* Verify the existing signature */

                if (c->signature[c->index] != SD_BUS_TYPE_ARRAY)
                        return -ENXIO;

                if (!startswith(c->signature + c->index + 1, contents))
                        return -ENXIO;

                nindex = c->index + 1 + strlen(contents);
        } else {
                char *e;

                if (c->enclosing != 0)
                        return -ENXIO;

                /* Extend the existing signature */

                e = strextend(&c->signature, CHAR_TO_STR(SD_BUS_TYPE_ARRAY), contents, NULL);
                if (!e) {
                        m->poisoned = true;
                        return -ENOMEM;
                }

                nindex = e - c->signature;
        }

        a = message_extend_body(m, 4, 4);
        if (!a)
                return -ENOMEM;

        o = m->body_end;
        op = m->body_end->data;
        os = m->body_end->size;

        /* Add alignment between size and first element */
        if (!message_extend_body(m, alignment, 0))
                return -ENOMEM;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index = nindex;

        /* location of array size might have changed so let's readjust a */
        if (o == m->body_end)
                a = adjust_pointer(a, op, os, m->body_end->data);

        *(uint32_t*) a = 0;
        *array_size = a;
        return 0;
}

static int bus_message_open_variant(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents) {

        size_t l;
        void *a;

        assert(m);
        assert(c);
        assert(contents);

        if (!signature_is_single(contents))
                return -EINVAL;

        if (*contents == SD_BUS_TYPE_DICT_ENTRY_BEGIN)
                return -EINVAL;

        if (c->signature && c->signature[c->index]) {

                if (c->signature[c->index] != SD_BUS_TYPE_VARIANT)
                        return -ENXIO;

        } else {
                char *e;

                if (c->enclosing != 0)
                        return -ENXIO;

                e = strextend(&c->signature, CHAR_TO_STR(SD_BUS_TYPE_VARIANT), NULL);
                if (!e) {
                        m->poisoned = true;
                        return -ENOMEM;
                }
        }

        l = strlen(contents);
        a = message_extend_body(m, 1, 1 + l + 1);
        if (!a)
                return -ENOMEM;

        *(uint8_t*) a = l;
        memcpy((uint8_t*) a + 1, contents, l + 1);

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index++;

        return 0;
}

static int bus_message_open_struct(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents) {

        size_t nindex;

        assert(m);
        assert(c);
        assert(contents);

        if (!signature_is_valid(contents, false))
                return -EINVAL;

        if (c->signature && c->signature[c->index]) {
                size_t l;

                l = strlen(contents);

                if (c->signature[c->index] != SD_BUS_TYPE_STRUCT_BEGIN ||
                    !startswith(c->signature + c->index + 1, contents) ||
                    c->signature[c->index + 1 + l] != SD_BUS_TYPE_STRUCT_END)
                        return -ENXIO;

                nindex = c->index + 1 + l + 1;
        } else {
                char *e;

                if (c->enclosing != 0)
                        return -ENXIO;

                e = strextend(&c->signature, CHAR_TO_STR(SD_BUS_TYPE_STRUCT_BEGIN), contents, CHAR_TO_STR(SD_BUS_TYPE_STRUCT_END), NULL);
                if (!e) {
                        m->poisoned = true;
                        return -ENOMEM;
                }

                nindex = e - c->signature;
        }

        /* Align contents to 8 byte boundary */
        if (!message_extend_body(m, 8, 0))
                return -ENOMEM;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index = nindex;

        return 0;
}

static int bus_message_open_dict_entry(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents) {

        size_t nindex;

        assert(m);
        assert(c);
        assert(contents);

        if (!signature_is_pair(contents))
                return -EINVAL;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                return -ENXIO;

        if (c->signature && c->signature[c->index]) {
                size_t l;

                l = strlen(contents);

                if (c->signature[c->index] != SD_BUS_TYPE_DICT_ENTRY_BEGIN ||
                    !startswith(c->signature + c->index + 1, contents) ||
                    c->signature[c->index + 1 + l] != SD_BUS_TYPE_DICT_ENTRY_END)
                        return -ENXIO;

                nindex = c->index + 1 + l + 1;
        } else
                return -ENXIO;

        /* Align contents to 8 byte boundary */
        if (!message_extend_body(m, 8, 0))
                return -ENOMEM;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index = nindex;

        return 0;
}

int sd_bus_message_open_container(
                sd_bus_message *m,
                char type,
                const char *contents) {

        struct bus_container *c, *w;
        uint32_t *array_size = NULL;
        char *signature;
        size_t before;
        int r;

        if (!m)
                return -EINVAL;
        if (m->sealed)
                return -EPERM;
        if (!contents)
                return -EINVAL;
        if (m->poisoned)
                return -ESTALE;

        /* Make sure we have space for one more container */
        w = realloc(m->containers, sizeof(struct bus_container) * (m->n_containers + 1));
        if (!w) {
                m->poisoned = true;
                return -ENOMEM;
        }

        m->containers = w;

        c = message_get_container(m);

        signature = strdup(contents);
        if (!signature) {
                m->poisoned = true;
                return -ENOMEM;
        }

        /* Save old index in the parent container, in case we have to
         * abort this container */
        c->saved_index = c->index;
        before = m->header->body_size;

        if (type == SD_BUS_TYPE_ARRAY)
                r = bus_message_open_array(m, c, contents, &array_size);
        else if (type == SD_BUS_TYPE_VARIANT)
                r = bus_message_open_variant(m, c, contents);
        else if (type == SD_BUS_TYPE_STRUCT)
                r = bus_message_open_struct(m, c, contents);
        else if (type == SD_BUS_TYPE_DICT_ENTRY)
                r = bus_message_open_dict_entry(m, c, contents);
        else
                r = -EINVAL;

        if (r < 0) {
                free(signature);
                return r;
        }

        /* OK, let's fill it in */
        w += m->n_containers++;
        w->enclosing = type;
        w->signature = signature;
        w->index = 0;
        w->array_size = array_size;
        w->before = before;
        w->begin = m->rindex;

        return 0;
}

int sd_bus_message_close_container(sd_bus_message *m) {
        struct bus_container *c;

        if (!m)
                return -EINVAL;
        if (m->sealed)
                return -EPERM;
        if (m->n_containers <= 0)
                return -EINVAL;
        if (m->poisoned)
                return -ESTALE;

        c = message_get_container(m);
        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                if (c->signature && c->signature[c->index] != 0)
                        return -EINVAL;

        free(c->signature);
        m->n_containers--;

        return 0;
}

typedef struct {
        const char *types;
        unsigned n_struct;
        unsigned n_array;
} TypeStack;

static int type_stack_push(TypeStack *stack, unsigned max, unsigned *i, const char *types, unsigned n_struct, unsigned n_array) {
        assert(stack);
        assert(max > 0);

        if (*i >= max)
                return -EINVAL;

        stack[*i].types = types;
        stack[*i].n_struct = n_struct;
        stack[*i].n_array = n_array;
        (*i)++;

        return 0;
}

static int type_stack_pop(TypeStack *stack, unsigned max, unsigned *i, const char **types, unsigned *n_struct, unsigned *n_array) {
        assert(stack);
        assert(max > 0);
        assert(types);
        assert(n_struct);
        assert(n_array);

        if (*i <= 0)
                return 0;

        (*i)--;
        *types = stack[*i].types;
        *n_struct = stack[*i].n_struct;
        *n_array = stack[*i].n_array;

        return 1;
}

int bus_message_append_ap(
                sd_bus_message *m,
                const char *types,
                va_list ap) {

        unsigned n_array, n_struct;
        TypeStack stack[BUS_CONTAINER_DEPTH];
        unsigned stack_ptr = 0;
        int r;

        assert(m);

        if (!types)
                return 0;

        n_array = (unsigned) -1;
        n_struct = strlen(types);

        for (;;) {
                const char *t;

                if (n_array == 0 || (n_array == (unsigned) -1 && n_struct == 0)) {
                        r = type_stack_pop(stack, ELEMENTSOF(stack), &stack_ptr, &types, &n_struct, &n_array);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        r = sd_bus_message_close_container(m);
                        if (r < 0)
                                return r;

                        continue;
                }

                t = types;
                if (n_array != (unsigned) -1)
                        n_array --;
                else {
                        types ++;
                        n_struct--;
                }

                switch (*t) {

                case SD_BUS_TYPE_BYTE: {
                        uint8_t x;

                        x = (uint8_t) va_arg(ap, int);
                        r = sd_bus_message_append_basic(m, *t, &x);
                        break;
                }

                case SD_BUS_TYPE_BOOLEAN:
                case SD_BUS_TYPE_INT32:
                case SD_BUS_TYPE_UINT32:
                case SD_BUS_TYPE_UNIX_FD: {
                        uint32_t x;

                        /* We assume a boolean is the same as int32_t */
                        assert_cc(sizeof(int32_t) == sizeof(int));

                        x = va_arg(ap, uint32_t);
                        r = sd_bus_message_append_basic(m, *t, &x);
                        break;
                }

                case SD_BUS_TYPE_INT16:
                case SD_BUS_TYPE_UINT16: {
                        uint16_t x;

                        x = (uint16_t) va_arg(ap, int);
                        r = sd_bus_message_append_basic(m, *t, &x);
                        break;
                }

                case SD_BUS_TYPE_INT64:
                case SD_BUS_TYPE_UINT64:
                case SD_BUS_TYPE_DOUBLE: {
                        uint64_t x;

                        x = va_arg(ap, uint64_t);
                        r = sd_bus_message_append_basic(m, *t, &x);
                        break;
                }

                case SD_BUS_TYPE_STRING:
                case SD_BUS_TYPE_OBJECT_PATH:
                case SD_BUS_TYPE_SIGNATURE: {
                        const char *x;

                        x = va_arg(ap, const char*);
                        r = sd_bus_message_append_basic(m, *t, x);
                        break;
                }

                case SD_BUS_TYPE_ARRAY: {
                        size_t k;

                        r = signature_element_length(t + 1, &k);
                        if (r < 0)
                                return r;

                        {
                                char s[k + 1];
                                memcpy(s, t + 1, k);
                                s[k] = 0;

                                r = sd_bus_message_open_container(m, SD_BUS_TYPE_ARRAY, s);
                                if (r < 0)
                                        return r;
                        }

                        if (n_array == (unsigned) -1) {
                                types += k;
                                n_struct -= k;
                        }

                        r = type_stack_push(stack, ELEMENTSOF(stack), &stack_ptr, types, n_struct, n_array);
                        if (r < 0)
                                return r;

                        types = t + 1;
                        n_struct = k;
                        n_array = va_arg(ap, unsigned);

                        break;
                }

                case SD_BUS_TYPE_VARIANT: {
                        const char *s;

                        s = va_arg(ap, const char*);
                        if (!s)
                                return -EINVAL;

                        r = sd_bus_message_open_container(m, SD_BUS_TYPE_VARIANT, s);
                        if (r < 0)
                                return r;

                        r = type_stack_push(stack, ELEMENTSOF(stack), &stack_ptr, types, n_struct, n_array);
                        if (r < 0)
                                return r;

                        types = s;
                        n_struct = strlen(s);
                        n_array = (unsigned) -1;

                        break;
                }

                case SD_BUS_TYPE_STRUCT_BEGIN:
                case SD_BUS_TYPE_DICT_ENTRY_BEGIN: {
                        size_t k;

                        r = signature_element_length(t, &k);
                        if (r < 0)
                                return r;

                        {
                                char s[k - 1];

                                memcpy(s, t + 1, k - 2);
                                s[k - 2] = 0;

                                r = sd_bus_message_open_container(m, *t == SD_BUS_TYPE_STRUCT_BEGIN ? SD_BUS_TYPE_STRUCT : SD_BUS_TYPE_DICT_ENTRY, s);
                                if (r < 0)
                                        return r;
                        }

                        if (n_array == (unsigned) -1) {
                                types += k - 1;
                                n_struct -= k - 1;
                        }

                        r = type_stack_push(stack, ELEMENTSOF(stack), &stack_ptr, types, n_struct, n_array);
                        if (r < 0)
                                return r;

                        types = t + 1;
                        n_struct = k - 2;
                        n_array = (unsigned) -1;

                        break;
                }

                default:
                        r = -EINVAL;
                }

                if (r < 0)
                        return r;
        }

        return 0;
}

int sd_bus_message_append(sd_bus_message *m, const char *types, ...) {
        va_list ap;
        int r;

        if (!m)
                return -EINVAL;
        if (m->sealed)
                return -EPERM;
        if (m->poisoned)
                return -ESTALE;
        if (!types)
                return 0;

        va_start(ap, types);
        r = bus_message_append_ap(m, types, ap);
        va_end(ap);

        return r;
}

int sd_bus_message_append_array_space(sd_bus_message *m, char type, size_t size, void **ptr) {
        ssize_t align, sz;
        void *a;
        int r;

        if (!m)
                return -EINVAL;
        if (m->sealed)
                return -EPERM;
        if (!bus_type_is_trivial(type))
                return -EINVAL;
        if (!ptr && size > 0)
                return -EINVAL;
        if (m->poisoned)
                return -ESTALE;

        align = bus_type_get_alignment(type);
        sz = bus_type_get_size(type);

        assert_se(align > 0);
        assert_se(sz > 0);

        if (size % sz != 0)
                return -EINVAL;

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_ARRAY, CHAR_TO_STR(type));
        if (r < 0)
                return r;

        a = message_extend_body(m, align, size);
        if (!a)
                return -ENOMEM;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        *ptr = a;
        return 0;
}

int sd_bus_message_append_array(sd_bus_message *m, char type, const void *ptr, size_t size) {
        int r;
        void *p;

        if (!ptr && size > 0)
                return -EINVAL;

        r = sd_bus_message_append_array_space(m, type, size, &p);
        if (r < 0)
                return r;

        if (size > 0)
                memcpy(p, ptr, size);

        return 0;
}

int sd_bus_message_append_array_memfd(sd_bus_message *m, char type, sd_memfd *memfd) {
        _cleanup_close_ int copy_fd = -1;
        struct bus_body_part *part;
        ssize_t align, sz;
        uint64_t size;
        void *a;
        int r;

        if (!m)
                return -EINVAL;
        if (!memfd)
                return -EINVAL;
        if (m->sealed)
                return -EPERM;
        if (!bus_type_is_trivial(type))
                return -EINVAL;
        if (m->poisoned)
                return -ESTALE;

        r = sd_memfd_set_sealed(memfd, true);
        if (r < 0)
                return r;

        copy_fd = sd_memfd_dup_fd(memfd);
        if (copy_fd < 0)
                return copy_fd;

        r = sd_memfd_get_size(memfd, &size);
        if (r < 0)
                return r;

        align = bus_type_get_alignment(type);
        sz = bus_type_get_size(type);

        assert_se(align > 0);
        assert_se(sz > 0);

        if (size % sz != 0)
                return -EINVAL;

        if (size > (uint64_t) (uint32_t) -1)
                return -EINVAL;

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_ARRAY, CHAR_TO_STR(type));
        if (r < 0)
                return r;

        a = message_extend_body(m, align, 0);
        if (!a)
                return -ENOMEM;

        part = message_append_part(m);
        if (!part)
                return -ENOMEM;

        part->memfd = copy_fd;
        part->sealed = true;
        part->size = size;
        copy_fd = -1;

        message_extend_containers(m, size);
        m->header->body_size += size;

        return sd_bus_message_close_container(m);
}

int sd_bus_message_append_string_memfd(sd_bus_message *m, sd_memfd *memfd) {
        _cleanup_close_ int copy_fd = -1;
        struct bus_body_part *part;
        struct bus_container *c;
        uint64_t size;
        void *a;
        int r;

        if (!m)
                return -EINVAL;
        if (!memfd)
                return -EINVAL;
        if (m->sealed)
                return -EPERM;
        if (m->poisoned)
                return -ESTALE;

        r = sd_memfd_set_sealed(memfd, true);
        if (r < 0)
                return r;

        copy_fd = sd_memfd_dup_fd(memfd);
        if (copy_fd < 0)
                return copy_fd;

        r = sd_memfd_get_size(memfd, &size);
        if (r < 0)
                return r;

        /* We require this to be NUL terminated */
        if (size == 0)
                return -EINVAL;

        if (size > (uint64_t) (uint32_t) -1)
                return -EINVAL;

        c = message_get_container(m);
        if (c->signature && c->signature[c->index]) {
                /* Container signature is already set */

                if (c->signature[c->index] != SD_BUS_TYPE_STRING)
                        return -ENXIO;
        } else {
                char *e;

                /* Maybe we can append to the signature? But only if this is the top-level container*/
                if (c->enclosing != 0)
                        return -ENXIO;

                e = strextend(&c->signature, CHAR_TO_STR(SD_BUS_TYPE_STRING), NULL);
                if (!e) {
                        m->poisoned = true;
                        return -ENOMEM;
                }
        }

        a = message_extend_body(m, 4, 4);
        if (!a)
                return -ENOMEM;

        *(uint32_t*) a = size - 1;

        part = message_append_part(m);
        if (!part)
                return -ENOMEM;

        part->memfd = copy_fd;
        part->sealed = true;
        part->size = size;
        copy_fd = -1;

        message_extend_containers(m, size);
        m->header->body_size += size;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index++;

        return 0;
}

int bus_body_part_map(struct bus_body_part *part) {
        void *p;
        size_t psz;

        assert_se(part);

        if (part->data)
                return 0;

        if (part->size <= 0)
                return 0;

        /* For smaller zero parts (as used for padding) we don't need to map anything... */
        if (part->memfd < 0 && part->is_zero && part->size < 8) {
                static const uint8_t zeroes[7] = { };
                part->data = (void*) zeroes;
                return 0;
        }

        psz = PAGE_ALIGN(part->size);

        if (part->memfd >= 0)
                p = mmap(NULL, psz, PROT_READ, MAP_SHARED, part->memfd, 0);
        else if (part->is_zero)
                p = mmap(NULL, psz, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        else
                return -EINVAL;

        if (p == MAP_FAILED)
                return -errno;

        part->mapped = psz;
        part->data = p;
        part->munmap_this = true;

        return 0;
}

void bus_body_part_unmap(struct bus_body_part *part) {

        assert_se(part);

        if (part->memfd < 0)
                return;

        if (!part->data)
                return;

        if (!part->munmap_this)
                return;

        assert_se(munmap(part->data, part->mapped) == 0);

        part->data = NULL;
        part->mapped = 0;
        part->munmap_this = false;

        return;
}

static int buffer_peek(const void *p, uint32_t sz, size_t *rindex, size_t align, size_t nbytes, void **r) {
        size_t k, start, end;

        assert(rindex);
        assert(align > 0);

        start = ALIGN_TO((size_t) *rindex, align);
        end = start + nbytes;

        if (end > sz)
                return -EBADMSG;

        /* Verify that padding is 0 */
        for (k = *rindex; k < start; k++)
                if (((const uint8_t*) p)[k] != 0)
                        return -EBADMSG;

        if (r)
                *r = (uint8_t*) p + start;

        *rindex = end;

        return 1;
}

static bool message_end_of_array(sd_bus_message *m, size_t index) {
        struct bus_container *c;

        assert(m);

        c = message_get_container(m);
        if (!c->array_size)
                return false;

        return index >= c->begin + BUS_MESSAGE_BSWAP32(m, *c->array_size);
}

static struct bus_body_part* find_part(sd_bus_message *m, size_t index, size_t sz, void **p) {
        struct bus_body_part *part;
        size_t begin;
        int r;

        assert(m);

        if (m->cached_rindex_part && index >= m->cached_rindex_part_begin) {
                part = m->cached_rindex_part;
                begin = m->cached_rindex_part_begin;
        } else {
                part = &m->body;
                begin = 0;
        }

        while (part) {
                if (index < begin)
                        return NULL;

                if (index + sz <= begin + part->size) {

                        r = bus_body_part_map(part);
                        if (r < 0)
                                return NULL;

                        if (p)
                                *p = (uint8_t*) part->data + index - begin;

                        m->cached_rindex_part = part;
                        m->cached_rindex_part_begin = begin;

                        return part;
                }

                begin += part->size;
                part = part->next;
        }

        return NULL;
}

static int message_peek_body(
                sd_bus_message *m,
                size_t *rindex,
                size_t align,
                size_t nbytes,
                void **ret) {

        size_t k, start, end, padding;
        struct bus_body_part *part;
        uint8_t *q;

        assert(m);
        assert(rindex);
        assert(align > 0);

        if (message_end_of_array(m, *rindex))
                return 0;

        start = ALIGN_TO((size_t) *rindex, align);
        padding = start - *rindex;
        end = start + nbytes;

        if (end > BUS_MESSAGE_BODY_SIZE(m))
                return -EBADMSG;

        part = find_part(m, *rindex, padding, (void**) &q);
        if (!part)
                return -EBADMSG;

        if (q) {
                /* Verify padding */
                for (k = 0; k < padding; k++)
                        if (q[k] != 0)
                                return -EBADMSG;
        }

        part = find_part(m, start, nbytes, (void**) &q);
        if (!part || !q)
                return -EBADMSG;

        *rindex = end;

        if (ret)
                *ret = q;

        return 1;
}

static bool validate_nul(const char *s, size_t l) {

        /* Check for NUL chars in the string */
        if (memchr(s, 0, l))
                return false;

        /* Check for NUL termination */
        if (s[l] != 0)
                return false;

        return true;
}

static bool validate_string(const char *s, size_t l) {

        if (!validate_nul(s, l))
                return false;

        /* Check if valid UTF8 */
        if (!utf8_is_valid(s))
                return false;

        return true;
}

static bool validate_signature(const char *s, size_t l) {

        if (!validate_nul(s, l))
                return false;

        /* Check if valid signature */
        if (!signature_is_valid(s, true))
                return false;

        return true;
}

static bool validate_object_path(const char *s, size_t l) {

        if (!validate_nul(s, l))
                return false;

        if (!object_path_is_valid(s))
                return false;

        return true;
}

int sd_bus_message_read_basic(sd_bus_message *m, char type, void *p) {
        struct bus_container *c;
        int r;
        void *q;

        if (!m)
                return -EINVAL;
        if (!m->sealed)
                return -EPERM;
        if (!bus_type_is_basic(type))
                return -EINVAL;
        if (!p)
                return -EINVAL;

        c = message_get_container(m);

        if (!c->signature || c->signature[c->index] == 0)
                return 0;

        if (c->signature[c->index] != type)
                return -ENXIO;

        switch (type) {

        case SD_BUS_TYPE_STRING:
        case SD_BUS_TYPE_OBJECT_PATH: {
                uint32_t l;
                size_t rindex;

                rindex = m->rindex;
                r = message_peek_body(m, &rindex, 4, 4, &q);
                if (r <= 0)
                        return r;

                l = BUS_MESSAGE_BSWAP32(m, *(uint32_t*) q);
                r = message_peek_body(m, &rindex, 1, l+1, &q);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EBADMSG;

                if (type == SD_BUS_TYPE_OBJECT_PATH) {
                        if (!validate_object_path(q, l))
                                return -EBADMSG;
                } else {
                        if (!validate_string(q, l))
                                return -EBADMSG;
                }

                m->rindex = rindex;
                *(const char**) p = q;
                break;
        }

        case SD_BUS_TYPE_SIGNATURE: {
                uint8_t l;
                size_t rindex;

                rindex = m->rindex;
                r = message_peek_body(m, &rindex, 1, 1, &q);
                if (r <= 0)
                        return r;

                l = *(uint8_t*) q;
                r = message_peek_body(m, &rindex, 1, l+1, &q);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EBADMSG;

                if (!validate_signature(q, l))
                        return -EBADMSG;

                m->rindex = rindex;
                *(const char**) p = q;
                break;
        }

        default: {
                ssize_t sz, align;
                size_t rindex;

                align = bus_type_get_alignment(type);
                sz = bus_type_get_size(type);
                assert(align > 0 && sz > 0);

                rindex = m->rindex;
                r = message_peek_body(m, &rindex, align, sz, &q);
                if (r <= 0)
                        return r;

                switch (type) {

                case SD_BUS_TYPE_BYTE:
                        *(uint8_t*) p = *(uint8_t*) q;
                        break;

                case SD_BUS_TYPE_BOOLEAN:
                        *(int*) p = !!*(uint32_t*) q;
                        break;

                case SD_BUS_TYPE_INT16:
                case SD_BUS_TYPE_UINT16:
                        *(uint16_t*) p = BUS_MESSAGE_BSWAP16(m, *(uint16_t*) q);
                        break;

                case SD_BUS_TYPE_INT32:
                case SD_BUS_TYPE_UINT32:
                        *(uint32_t*) p = BUS_MESSAGE_BSWAP32(m, *(uint32_t*) q);
                        break;

                case SD_BUS_TYPE_INT64:
                case SD_BUS_TYPE_UINT64:
                case SD_BUS_TYPE_DOUBLE:
                        *(uint64_t*) p = BUS_MESSAGE_BSWAP64(m, *(uint64_t*) q);
                        break;

                case SD_BUS_TYPE_UNIX_FD: {
                        uint32_t j;

                        j = BUS_MESSAGE_BSWAP32(m, *(uint32_t*) q);
                        if (j >= m->n_fds)
                                return -EBADMSG;

                        *(int*) p = m->fds[j];
                        break;
                }

                default:
                        assert_not_reached("Unknown basic type...");
                }

                m->rindex = rindex;

                break;
        }
        }

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index++;

        return 1;
}

static int bus_message_enter_array(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents,
                uint32_t **array_size) {

        size_t rindex;
        void *q;
        int r, alignment;

        assert(m);
        assert(c);
        assert(contents);
        assert(array_size);

        if (!signature_is_single(contents))
                return -EINVAL;

        alignment = bus_type_get_alignment(contents[0]);
        if (alignment < 0)
                return alignment;

        if (!c->signature || c->signature[c->index] == 0)
                return 0;

        if (c->signature[c->index] != SD_BUS_TYPE_ARRAY)
                return -ENXIO;

        if (!startswith(c->signature + c->index + 1, contents))
                return -ENXIO;

        rindex = m->rindex;
        r = message_peek_body(m, &rindex, 4, 4, &q);
        if (r <= 0)
                return r;

        if (BUS_MESSAGE_BSWAP32(m, *(uint32_t*) q) > BUS_ARRAY_MAX_SIZE)
                return -EBADMSG;

        r = message_peek_body(m, &rindex, alignment, 0, NULL);
        if (r < 0)
                return r;
        if (r == 0)
                return -EBADMSG;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index += 1 + strlen(contents);

        m->rindex = rindex;

        *array_size = (uint32_t*) q;

        return 1;
}

static int bus_message_enter_variant(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents) {

        size_t rindex;
        uint8_t l;
        void *q;
        int r;

        assert(m);
        assert(c);
        assert(contents);

        if (!signature_is_single(contents))
                return -EINVAL;

        if (*contents == SD_BUS_TYPE_DICT_ENTRY_BEGIN)
                return -EINVAL;

        if (!c->signature || c->signature[c->index] == 0)
                return 0;

        if (c->signature[c->index] != SD_BUS_TYPE_VARIANT)
                return -ENXIO;

        rindex = m->rindex;
        r = message_peek_body(m, &rindex, 1, 1, &q);
        if (r <= 0)
                return r;

        l = *(uint8_t*) q;
        r = message_peek_body(m, &rindex, 1, l+1, &q);
        if (r < 0)
                return r;
        if (r == 0)
                return -EBADMSG;

        if (!validate_signature(q, l))
                return -EBADMSG;

        if (!streq(q, contents))
                return -ENXIO;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index++;

        m->rindex = rindex;

        return 1;
}

static int bus_message_enter_struct(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents) {

        size_t l;
        int r;

        assert(m);
        assert(c);
        assert(contents);

        if (!signature_is_valid(contents, false))
                return -EINVAL;

        if (!c->signature || c->signature[c->index] == 0)
                return 0;

        l = strlen(contents);

        if (c->signature[c->index] != SD_BUS_TYPE_STRUCT_BEGIN ||
            !startswith(c->signature + c->index + 1, contents) ||
            c->signature[c->index + 1 + l] != SD_BUS_TYPE_STRUCT_END)
                return -ENXIO;

        r = message_peek_body(m, &m->rindex, 8, 0, NULL);
        if (r <= 0)
                return r;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index += 1 + l + 1;

        return 1;
}

static int bus_message_enter_dict_entry(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents) {

        size_t l;
        int r;

        assert(m);
        assert(c);
        assert(contents);

        if (!signature_is_pair(contents))
                return -EINVAL;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                return -ENXIO;

        if (!c->signature || c->signature[c->index] == 0)
                return 0;

        l = strlen(contents);

        if (c->signature[c->index] != SD_BUS_TYPE_DICT_ENTRY_BEGIN ||
            !startswith(c->signature + c->index + 1, contents) ||
            c->signature[c->index + 1 + l] != SD_BUS_TYPE_DICT_ENTRY_END)
                return -ENXIO;

        r = message_peek_body(m, &m->rindex, 8, 0, NULL);
        if (r <= 0)
                return r;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index += 1 + l + 1;

        return 1;
}

int sd_bus_message_enter_container(sd_bus_message *m, char type, const char *contents) {
        struct bus_container *c, *w;
        uint32_t *array_size = NULL;
        char *signature;
        size_t before;
        int r;

        if (!m)
                return -EINVAL;
        if (!m->sealed)
                return -EPERM;
        if (!contents)
                return -EINVAL;

        /*
         * We enforce a global limit on container depth, that is much
         * higher than the 32 structs and 32 arrays the specification
         * mandates. This is simpler to implement for us, and we need
         * this only to ensure our container array doesn't grow
         * without bounds. We are happy to return any data from a
         * message as long as the data itself is valid, even if the
         * overall message might be not.
         *
         * Note that the message signature is validated when
         * parsing the headers, and that validation does check the
         * 32/32 limit.
         *
         * Note that the specification defines no limits on the depth
         * of stacked variants, but we do.
         */
        if (m->n_containers >= BUS_CONTAINER_DEPTH)
                return -EBADMSG;

        w = realloc(m->containers, sizeof(struct bus_container) * (m->n_containers + 1));
        if (!w)
                return -ENOMEM;
        m->containers = w;

        c = message_get_container(m);

        if (!c->signature || c->signature[c->index] == 0)
                return 0;

        signature = strdup(contents);
        if (!signature)
                return -ENOMEM;

        c->saved_index = c->index;
        before = m->rindex;

        if (type == SD_BUS_TYPE_ARRAY)
                r = bus_message_enter_array(m, c, contents, &array_size);
        else if (type == SD_BUS_TYPE_VARIANT)
                r = bus_message_enter_variant(m, c, contents);
        else if (type == SD_BUS_TYPE_STRUCT)
                r = bus_message_enter_struct(m, c, contents);
        else if (type == SD_BUS_TYPE_DICT_ENTRY)
                r = bus_message_enter_dict_entry(m, c, contents);
        else
                r = -EINVAL;

        if (r <= 0) {
                free(signature);
                return r;
        }

        /* OK, let's fill it in */
        w += m->n_containers++;
        w->enclosing = type;
        w->signature = signature;
        w->index = 0;
        w->array_size = array_size;
        w->before = before;
        w->begin = m->rindex;

        return 1;
}

int sd_bus_message_exit_container(sd_bus_message *m) {
        struct bus_container *c;

        if (!m)
                return -EINVAL;
        if (!m->sealed)
                return -EPERM;
        if (m->n_containers <= 0)
                return -EINVAL;

        c = message_get_container(m);
        if (c->enclosing == SD_BUS_TYPE_ARRAY) {
                uint32_t l;

                l = BUS_MESSAGE_BSWAP32(m, *c->array_size);
                if (c->begin + l != m->rindex)
                        return -EBUSY;

        } else {
                if (c->signature && c->signature[c->index] != 0)
                        return -EINVAL;
        }

        free(c->signature);
        m->n_containers--;

        return 1;
}

static void message_quit_container(sd_bus_message *m) {
        struct bus_container *c;

        assert(m);
        assert(m->sealed);
        assert(m->n_containers > 0);

        c = message_get_container(m);

        /* Undo seeks */
        assert(m->rindex >= c->before);
        m->rindex = c->before;

        /* Free container */
        free(c->signature);
        m->n_containers--;

        /* Correct index of new top-level container */
        c = message_get_container(m);
        c->index = c->saved_index;
}

int sd_bus_message_peek_type(sd_bus_message *m, char *type, const char **contents) {
        struct bus_container *c;
        int r;

        if (!m)
                return -EINVAL;
        if (!m->sealed)
                return -EPERM;

        c = message_get_container(m);

        if (!c->signature || c->signature[c->index] == 0)
                goto eof;

        if (message_end_of_array(m, m->rindex))
                goto eof;

        if (bus_type_is_basic(c->signature[c->index])) {
                if (contents)
                        *contents = NULL;
                if (type)
                        *type = c->signature[c->index];
                return 1;
        }

        if (c->signature[c->index] == SD_BUS_TYPE_ARRAY) {

                if (contents) {
                        size_t l;
                        char *sig;

                        r = signature_element_length(c->signature+c->index+1, &l);
                        if (r < 0)
                                return r;

                        assert(l >= 1);

                        sig = strndup(c->signature + c->index + 1, l);
                        if (!sig)
                                return -ENOMEM;

                        free(m->peeked_signature);
                        m->peeked_signature = sig;

                        *contents = sig;
                }

                if (type)
                        *type = SD_BUS_TYPE_ARRAY;

                return 1;
        }

        if (c->signature[c->index] == SD_BUS_TYPE_STRUCT_BEGIN ||
            c->signature[c->index] == SD_BUS_TYPE_DICT_ENTRY_BEGIN) {

                if (contents) {
                        size_t l;
                        char *sig;

                        r = signature_element_length(c->signature+c->index, &l);
                        if (r < 0)
                                return r;

                        assert(l >= 2);
                        sig = strndup(c->signature + c->index + 1, l - 2);
                        if (!sig)
                                return -ENOMEM;

                        free(m->peeked_signature);
                        m->peeked_signature = sig;

                        *contents = sig;
                }

                if (type)
                        *type = c->signature[c->index] == SD_BUS_TYPE_STRUCT_BEGIN ? SD_BUS_TYPE_STRUCT : SD_BUS_TYPE_DICT_ENTRY;

                return 1;
        }

        if (c->signature[c->index] == SD_BUS_TYPE_VARIANT) {
                if (contents) {
                        size_t rindex, l;
                        void *q;

                        rindex = m->rindex;
                        r = message_peek_body(m, &rindex, 1, 1, &q);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                goto eof;

                        l = *(uint8_t*) q;
                        r = message_peek_body(m, &rindex, 1, l+1, &q);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -EBADMSG;

                        if (!validate_signature(q, l))
                                return -EBADMSG;

                        *contents = q;
                }

                if (type)
                        *type = SD_BUS_TYPE_VARIANT;

                return 1;
        }

        return -EINVAL;

eof:
        if (type)
                *type = c->enclosing;
        if (contents)
                *contents = NULL;
        return 0;
}

int sd_bus_message_rewind(sd_bus_message *m, int complete) {
        struct bus_container *c;

        if (!m)
                return -EINVAL;
        if (!m->sealed)
                return -EPERM;

        if (complete) {
                message_reset_containers(m);
                m->rindex = 0;
                m->root_container.index = 0;

                c = message_get_container(m);
        } else {
                c = message_get_container(m);

                c->index = 0;
                m->rindex = c->begin;
        }

        return !isempty(c->signature);
}
static int message_read_ap(
                sd_bus_message *m,
                const char *types,
                va_list ap) {

        unsigned n_array, n_struct;
        TypeStack stack[BUS_CONTAINER_DEPTH];
        unsigned stack_ptr = 0;
        int r;

        assert(m);

        if (!types)
                return 0;

        /* Ideally, we'd just call ourselves recursively on every
         * complex type. However, the state of a va_list that is
         * passed to a function is undefined after that function
         * returns. This means we need to docode the va_list linearly
         * in a single stackframe. We hence implement our own
         * home-grown stack in an array. */

        n_array = (unsigned) -1;
        n_struct = strlen(types);

        for (;;) {
                const char *t;

                if (n_array == 0 || (n_array == (unsigned) -1 && n_struct == 0)) {
                        r = type_stack_pop(stack, ELEMENTSOF(stack), &stack_ptr, &types, &n_struct, &n_array);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return r;

                        continue;
                }

                t = types;
                if (n_array != (unsigned) -1)
                        n_array --;
                else {
                        types ++;
                        n_struct--;
                }

                switch (*t) {

                case SD_BUS_TYPE_BYTE:
                case SD_BUS_TYPE_BOOLEAN:
                case SD_BUS_TYPE_INT16:
                case SD_BUS_TYPE_UINT16:
                case SD_BUS_TYPE_INT32:
                case SD_BUS_TYPE_UINT32:
                case SD_BUS_TYPE_INT64:
                case SD_BUS_TYPE_UINT64:
                case SD_BUS_TYPE_DOUBLE:
                case SD_BUS_TYPE_STRING:
                case SD_BUS_TYPE_OBJECT_PATH:
                case SD_BUS_TYPE_SIGNATURE:
                case SD_BUS_TYPE_UNIX_FD: {
                        void *p;

                        p = va_arg(ap, void*);
                        r = sd_bus_message_read_basic(m, *t, p);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -ENXIO;

                        break;
                }

                case SD_BUS_TYPE_ARRAY: {
                        size_t k;

                        r = signature_element_length(t + 1, &k);
                        if (r < 0)
                                return r;

                        {
                                char s[k + 1];
                                memcpy(s, t + 1, k);
                                s[k] = 0;

                                r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, s);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        return -ENXIO;
                        }

                        if (n_array == (unsigned) -1) {
                                types += k;
                                n_struct -= k;
                        }

                        r = type_stack_push(stack, ELEMENTSOF(stack), &stack_ptr, types, n_struct, n_array);
                        if (r < 0)
                                return r;

                        types = t + 1;
                        n_struct = k;
                        n_array = va_arg(ap, unsigned);

                        break;
                }

                case SD_BUS_TYPE_VARIANT: {
                        const char *s;

                        s = va_arg(ap, const char *);
                        if (!s)
                                return -EINVAL;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, s);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -ENXIO;

                        r = type_stack_push(stack, ELEMENTSOF(stack), &stack_ptr, types, n_struct, n_array);
                        if (r < 0)
                                return r;

                        types = s;
                        n_struct = strlen(s);
                        n_array = (unsigned) -1;

                        break;
                }

                case SD_BUS_TYPE_STRUCT_BEGIN:
                case SD_BUS_TYPE_DICT_ENTRY_BEGIN: {
                        size_t k;

                        r = signature_element_length(t, &k);
                        if (r < 0)
                                return r;

                        {
                                char s[k - 1];
                                memcpy(s, t + 1, k - 2);
                                s[k - 2] = 0;

                                r = sd_bus_message_enter_container(m, *t == SD_BUS_TYPE_STRUCT_BEGIN ? SD_BUS_TYPE_STRUCT : SD_BUS_TYPE_DICT_ENTRY, s);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        return -ENXIO;
                        }

                        if (n_array == (unsigned) -1) {
                                types += k - 1;
                                n_struct -= k - 1;
                        }

                        r = type_stack_push(stack, ELEMENTSOF(stack), &stack_ptr, types, n_struct, n_array);
                        if (r < 0)
                                return r;

                        types = t + 1;
                        n_struct = k - 2;
                        n_array = (unsigned) -1;

                        break;
                }

                default:
                        return -EINVAL;
                }
        }

        return 1;
}

int sd_bus_message_read(sd_bus_message *m, const char *types, ...) {
        va_list ap;
        int r;

        if (!m)
                return -EINVAL;
        if (!m->sealed)
                return -EPERM;
        if (!types)
                return -EINVAL;

        va_start(ap, types);
        r = message_read_ap(m, types, ap);
        va_end(ap);

        return r;
}

int sd_bus_message_read_array(sd_bus_message *m, char type, const void **ptr, size_t *size) {
        struct bus_container *c;
        void *p;
        size_t sz;
        ssize_t align;
        int r;

        if (!m)
                return -EINVAL;
        if (!m->sealed)
                return -EPERM;
        if (!bus_type_is_trivial(type))
                return -EINVAL;
        if (!ptr)
                return -EINVAL;
        if (!size)
                return -EINVAL;
        if (BUS_MESSAGE_NEED_BSWAP(m))
                return -ENOTSUP;

        align = bus_type_get_alignment(type);
        if (align < 0)
                return align;

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, CHAR_TO_STR(type));
        if (r <= 0)
                return r;

        c = message_get_container(m);
        sz = BUS_MESSAGE_BSWAP32(m, *c->array_size);

        r = message_peek_body(m, &m->rindex, align, sz, &p);
        if (r < 0)
                goto fail;
        if (r == 0) {
                r = -EBADMSG;
                goto fail;
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                goto fail;

        *ptr = (const void*) p;
        *size = sz;

        return 1;

fail:
        message_quit_container(m);
        return r;
}

static int message_peek_fields(
                sd_bus_message *m,
                size_t *rindex,
                size_t align,
                size_t nbytes,
                void **ret) {

        assert(m);
        assert(rindex);
        assert(align > 0);

        return buffer_peek(BUS_MESSAGE_FIELDS(m), BUS_MESSAGE_FIELDS_SIZE(m), rindex, align, nbytes, ret);
}

static int message_peek_field_uint32(
                sd_bus_message *m,
                size_t *ri,
                uint32_t *ret) {

        int r;
        void *q;

        assert(m);
        assert(ri);

        r = message_peek_fields(m, ri, 4, 4, &q);
        if (r < 0)
                return r;

        if (ret)
                *ret = BUS_MESSAGE_BSWAP32(m, *(uint32_t*) q);

        return 0;
}

static int message_peek_field_string(
                sd_bus_message *m,
                bool (*validate)(const char *p),
                size_t *ri,
                const char **ret) {

        uint32_t l;
        int r;
        void *q;

        assert(m);
        assert(ri);

        r = message_peek_field_uint32(m, ri, &l);
        if (r < 0)
                return r;

        r = message_peek_fields(m, ri, 1, l+1, &q);
        if (r < 0)
                return r;

        if (validate) {
                if (!validate_nul(q, l))
                        return -EBADMSG;

                if (!validate(q))
                        return -EBADMSG;
        } else {
                if (!validate_string(q, l))
                        return -EBADMSG;
        }

        if (ret)
                *ret = q;

        return 0;
}

static int message_peek_field_signature(
                sd_bus_message *m,
                size_t *ri,
                const char **ret) {

        size_t l;
        int r;
        void *q;

        assert(m);
        assert(ri);

        r = message_peek_fields(m, ri, 1, 1, &q);
        if (r < 0)
                return r;

        l = *(uint8_t*) q;
        r = message_peek_fields(m, ri, 1, l+1, &q);
        if (r < 0)
                return r;

        if (!validate_signature(q, l))
                return -EBADMSG;

        if (ret)
                *ret = q;

        return 0;
}

static int message_skip_fields(
                sd_bus_message *m,
                size_t *ri,
                uint32_t array_size,
                const char **signature) {

        size_t original_index;
        int r;

        assert(m);
        assert(ri);
        assert(signature);

        original_index = *ri;

        for (;;) {
                char t;
                size_t l;

                if (array_size != (uint32_t) -1 &&
                    array_size <= *ri - original_index)
                        return 0;

                t = **signature;
                if (!t)
                        return 0;

                if (t == SD_BUS_TYPE_STRING) {

                        r = message_peek_field_string(m, NULL, ri, NULL);
                        if (r < 0)
                                return r;

                        (*signature)++;

                } else if (t == SD_BUS_TYPE_OBJECT_PATH) {

                        r = message_peek_field_string(m, object_path_is_valid, ri, NULL);
                        if (r < 0)
                                return r;

                        (*signature)++;

                } else if (t == SD_BUS_TYPE_SIGNATURE) {

                        r = message_peek_field_signature(m, ri, NULL);
                        if (r < 0)
                                return r;

                        (*signature)++;

                } else if (bus_type_is_basic(t)) {
                        ssize_t align, k;

                        align = bus_type_get_alignment(t);
                        k = bus_type_get_size(t);
                        assert(align > 0 && k > 0);

                        r = message_peek_fields(m, ri, align, k, NULL);
                        if (r < 0)
                                return r;

                        (*signature)++;

                } else if (t == SD_BUS_TYPE_ARRAY) {

                        r = signature_element_length(*signature+1, &l);
                        if (r < 0)
                                return r;

                        assert(l >= 1);
                        {
                                char sig[l-1], *s;
                                uint32_t nas;
                                int alignment;

                                strncpy(sig, *signature + 1, l-1);
                                s = sig;

                                alignment = bus_type_get_alignment(sig[0]);
                                if (alignment < 0)
                                        return alignment;

                                r = message_peek_field_uint32(m, ri, &nas);
                                if (r < 0)
                                        return r;
                                if (nas > BUS_ARRAY_MAX_SIZE)
                                        return -EBADMSG;

                                r = message_peek_fields(m, ri, alignment, 0, NULL);
                                if (r < 0)
                                        return r;

                                r = message_skip_fields(m, ri, nas, (const char**) &s);
                                if (r < 0)
                                        return r;
                        }

                        (*signature) += 1 + l;

                } else if (t == SD_BUS_TYPE_VARIANT) {
                        const char *s;

                        r = message_peek_field_signature(m, ri, &s);
                        if (r < 0)
                                return r;

                        r = message_skip_fields(m, ri, (uint32_t) -1, (const char**) &s);
                        if (r < 0)
                                return r;

                        (*signature)++;

                } else if (t == SD_BUS_TYPE_STRUCT ||
                           t == SD_BUS_TYPE_DICT_ENTRY) {

                        r = signature_element_length(*signature, &l);
                        if (r < 0)
                                return r;

                        assert(l >= 2);
                        {
                                char sig[l-1], *s;
                                strncpy(sig, *signature + 1, l-1);
                                s = sig;

                                r = message_skip_fields(m, ri, (uint32_t) -1, (const char**) &s);
                                if (r < 0)
                                        return r;
                        }

                        *signature += l;
                } else
                        return -EINVAL;
        }
}

int bus_message_parse_fields(sd_bus_message *m) {
        size_t ri;
        int r;
        uint32_t unix_fds = 0;

        assert(m);

        for (ri = 0; ri < BUS_MESSAGE_FIELDS_SIZE(m); ) {
                const char *signature;
                uint8_t *header;

                r = message_peek_fields(m, &ri, 8, 1, (void**) &header);
                if (r < 0)
                        return r;

                r = message_peek_field_signature(m, &ri, &signature);
                if (r < 0)
                        return r;

                switch (*header) {
                case _SD_BUS_MESSAGE_HEADER_INVALID:
                        return -EBADMSG;

                case SD_BUS_MESSAGE_HEADER_PATH:

                        if (m->path)
                                return -EBADMSG;

                        if (!streq(signature, "o"))
                                return -EBADMSG;

                        r = message_peek_field_string(m, object_path_is_valid, &ri, &m->path);
                        break;

                case SD_BUS_MESSAGE_HEADER_INTERFACE:

                        if (m->interface)
                                return -EBADMSG;

                        if (!streq(signature, "s"))
                                return -EBADMSG;

                        r = message_peek_field_string(m, interface_name_is_valid, &ri, &m->interface);
                        break;

                case SD_BUS_MESSAGE_HEADER_MEMBER:

                        if (m->member)
                                return -EBADMSG;

                        if (!streq(signature, "s"))
                                return -EBADMSG;

                        r = message_peek_field_string(m, member_name_is_valid, &ri, &m->member);
                        break;

                case SD_BUS_MESSAGE_HEADER_ERROR_NAME:

                        if (m->error.name)
                                return -EBADMSG;

                        if (!streq(signature, "s"))
                                return -EBADMSG;

                        r = message_peek_field_string(m, error_name_is_valid, &ri, &m->error.name);
                        break;

                case SD_BUS_MESSAGE_HEADER_DESTINATION:

                        if (m->destination)
                                return -EBADMSG;

                        if (!streq(signature, "s"))
                                return -EBADMSG;

                        r = message_peek_field_string(m, service_name_is_valid, &ri, &m->destination);
                        break;

                case SD_BUS_MESSAGE_HEADER_SENDER:

                        if (m->sender)
                                return -EBADMSG;

                        if (!streq(signature, "s"))
                                return -EBADMSG;

                        r = message_peek_field_string(m, service_name_is_valid, &ri, &m->sender);
                        break;


                case SD_BUS_MESSAGE_HEADER_SIGNATURE: {
                        const char *s;
                        char *c;

                        if (m->root_container.signature)
                                return -EBADMSG;

                        if (!streq(signature, "g"))
                                return -EBADMSG;

                        r = message_peek_field_signature(m, &ri, &s);
                        if (r < 0)
                                return r;

                        c = strdup(s);
                        if (!c)
                                return -ENOMEM;

                        free(m->root_container.signature);
                        m->root_container.signature = c;
                        break;
                }

                case SD_BUS_MESSAGE_HEADER_REPLY_SERIAL:
                        if (m->reply_serial != 0)
                                return -EBADMSG;

                        if (!streq(signature, "u"))
                                return -EBADMSG;

                        r = message_peek_field_uint32(m, &ri, &m->reply_serial);
                        if (r < 0)
                                return r;

                        if (m->reply_serial == 0)
                                return -EBADMSG;

                        break;

                case SD_BUS_MESSAGE_HEADER_UNIX_FDS:
                        if (unix_fds != 0)
                                return -EBADMSG;

                        if (!streq(signature, "u"))
                                return -EBADMSG;

                        r = message_peek_field_uint32(m, &ri, &unix_fds);
                        if (r < 0)
                                return -EBADMSG;

                        if (unix_fds == 0)
                                return -EBADMSG;

                        break;

                default:
                        r = message_skip_fields(m, &ri, (uint32_t) -1, (const char **) &signature);
                }

                if (r < 0)
                        return r;
        }

        if (m->n_fds != unix_fds)
                return -EBADMSG;

        if (isempty(m->root_container.signature) != (BUS_MESSAGE_BODY_SIZE(m) == 0))
                return -EBADMSG;

        switch (m->header->type) {

        case SD_BUS_MESSAGE_TYPE_SIGNAL:
                if (!m->path || !m->interface || !m->member)
                        return -EBADMSG;
                break;

        case SD_BUS_MESSAGE_TYPE_METHOD_CALL:

                if (!m->path || !m->member)
                        return -EBADMSG;

                break;

        case SD_BUS_MESSAGE_TYPE_METHOD_RETURN:

                if (m->reply_serial == 0)
                        return -EBADMSG;
                break;

        case SD_BUS_MESSAGE_TYPE_METHOD_ERROR:

                if (m->reply_serial == 0 || !m->error.name)
                        return -EBADMSG;
                break;
        }

        /* Try to read the error message, but if we can't it's a non-issue */
        if (m->header->type == SD_BUS_MESSAGE_TYPE_METHOD_ERROR)
                sd_bus_message_read(m, "s", &m->error.message);

        return 0;
}

int bus_message_seal(sd_bus_message *m, uint64_t serial) {
        struct bus_body_part *part;
        size_t l, a;
        unsigned i;
        int r;

        assert(m);

        if (m->sealed)
                return -EPERM;

        if (m->n_containers > 0)
                return -EBADMSG;

        if (m->poisoned)
                return -ESTALE;

        /* If there's a non-trivial signature set, then add it in here */
        if (!isempty(m->root_container.signature)) {
                r = message_append_field_signature(m, SD_BUS_MESSAGE_HEADER_SIGNATURE, m->root_container.signature, NULL);
                if (r < 0)
                        return r;
        }

        if (m->n_fds > 0) {
                r = message_append_field_uint32(m, SD_BUS_MESSAGE_HEADER_UNIX_FDS, m->n_fds);
                if (r < 0)
                        return r;
        }

        /* Add padding at the end of the fields part, since we know
         * the body needs to start at an 8 byte alignment. We made
         * sure we allocated enough space for this, so all we need to
         * do here is to zero it out. */
        l = BUS_MESSAGE_FIELDS_SIZE(m);
        a = ALIGN8(l) - l;
        if (a > 0)
                memset((uint8_t*) BUS_MESSAGE_FIELDS(m) + l, 0, a);

        /* If this is something we can send as memfd, then let's seal
        the memfd now. Note that we can send memfds as payload only
        for directed messages, and not for broadcasts. */
        if (m->destination && m->bus && m->bus->use_memfd) {
                MESSAGE_FOREACH_PART(part, i, m)
                        if (part->memfd >= 0 && !part->sealed && (part->size > MEMFD_MIN_SIZE || m->bus->use_memfd < 0)) {
                                bus_body_part_unmap(part);

                                if (ioctl(part->memfd, KDBUS_CMD_MEMFD_SEAL_SET, 1) >= 0)
                                        part->sealed = true;
                        }
        }

        m->header->serial = serial;
        m->sealed = true;

        return 0;
}

int sd_bus_message_set_destination(sd_bus_message *m, const char *destination) {
        if (!m)
                return -EINVAL;
        if (!destination)
                return -EINVAL;
        if (m->sealed)
                return -EPERM;
        if (m->destination)
                return -EEXIST;

        return message_append_field_string(m, SD_BUS_MESSAGE_HEADER_DESTINATION, SD_BUS_TYPE_STRING, destination, &m->destination);
}

int bus_message_dump(sd_bus_message *m) {
        const char *u = NULL, *uu = NULL, *s = NULL;
        char **cmdline = NULL;
        unsigned level = 1;
        int r;
        uid_t owner, audit_loginuid;
        uint32_t audit_sessionid;

        assert(m);

        printf("Message %p\n"
               "\tn_ref=%u\n"
               "\tendian=%c\n"
               "\ttype=%i\n"
               "\tflags=%u\n"
               "\tversion=%u\n"
               "\tserial=%u\n"
               "\tfields_size=%u\n"
               "\tbody_size=%u\n"
               "\tpath=%s\n"
               "\tinterface=%s\n"
               "\tmember=%s\n"
               "\tdestination=%s\n"
               "\tsender=%s\n"
               "\tsignature=%s\n"
               "\treply_serial=%u\n"
               "\terror.name=%s\n"
               "\terror.message=%s\n"
               "\tsealed=%s\n"
               "\tn_body_parts=%u\n",
               m,
               m->n_ref,
               m->header->endian,
               m->header->type,
               m->header->flags,
               m->header->version,
               BUS_MESSAGE_SERIAL(m),
               BUS_MESSAGE_FIELDS_SIZE(m),
               BUS_MESSAGE_BODY_SIZE(m),
               strna(m->path),
               strna(m->interface),
               strna(m->member),
               strna(m->destination),
               strna(m->sender),
               strna(m->root_container.signature),
               m->reply_serial,
               strna(m->error.name),
               strna(m->error.message),
               yes_no(m->sealed),
               m->n_body_parts);

        if (m->pid != 0)
                printf("\tpid=%lu\n", (unsigned long) m->pid);
        if (m->tid != 0)
                printf("\ttid=%lu\n", (unsigned long) m->tid);
        if (m->uid_valid)
                printf("\tuid=%lu\n", (unsigned long) m->uid);
        if (m->gid_valid)
                printf("\tgid=%lu\n", (unsigned long) m->gid);
        if (m->pid_starttime != 0)
                printf("\tpid_starttime=%llu\n", (unsigned long long) m->pid_starttime);
        if (m->monotonic != 0)
                printf("\tmonotonic=%llu\n", (unsigned long long) m->monotonic);
        if (m->realtime != 0)
                printf("\trealtime=%llu\n", (unsigned long long) m->realtime);
        if (m->exe)
                printf("\texe=[%s]\n", m->exe);
        if (m->comm)
                printf("\tcomm=[%s]\n", m->comm);
        if (m->tid_comm)
                printf("\ttid_comm=[%s]\n", m->tid_comm);
        if (m->label)
                printf("\tlabel=[%s]\n", m->label);
        if (m->cgroup)
                printf("\tcgroup=[%s]\n", m->cgroup);

        sd_bus_message_get_unit(m, &u);
        if (u)
                printf("\tunit=[%s]\n", u);
        sd_bus_message_get_user_unit(m, &uu);
        if (uu)
                printf("\tuser_unit=[%s]\n", uu);
        sd_bus_message_get_session(m, &s);
        if (s)
                printf("\tsession=[%s]\n", s);
        if (sd_bus_message_get_owner_uid(m, &owner) >= 0)
                printf("\towner_uid=%lu\n", (unsigned long) owner);
        if (sd_bus_message_get_audit_loginuid(m, &audit_loginuid) >= 0)
                printf("\taudit_loginuid=%lu\n", (unsigned long) audit_loginuid);
        if (sd_bus_message_get_audit_sessionid(m, &audit_sessionid) >= 0)
                printf("\taudit_sessionid=%lu\n", (unsigned long) audit_sessionid);

        printf("\tCAP_KILL=%i\n", sd_bus_message_has_effective_cap(m, 5));

        if (sd_bus_message_get_cmdline(m, &cmdline) >= 0) {
                char **c;

                fputs("\tcmdline=[", stdout);
                STRV_FOREACH(c, cmdline) {
                        if (c != cmdline)
                                putchar(' ');

                        fputs(*c, stdout);
                }

                fputs("]\n", stdout);
        }

        r = sd_bus_message_rewind(m, true);
        if (r < 0) {
                log_error("Failed to rewind: %s", strerror(-r));
                return r;
        }

        printf("BEGIN_MESSAGE \"%s\" {\n", strempty(m->root_container.signature));

        for(;;) {
                _cleanup_free_ char *prefix = NULL;
                const char *contents = NULL;
                char type;
                union {
                        uint8_t u8;
                        uint16_t u16;
                        int16_t s16;
                        uint32_t u32;
                        int32_t s32;
                        uint64_t u64;
                        int64_t s64;
                        double d64;
                        const char *string;
                        int i;
                } basic;

                r = sd_bus_message_peek_type(m, &type, &contents);
                if (r < 0) {
                        log_error("Failed to peek type: %s", strerror(-r));
                        return r;
                }
                if (r == 0) {
                        if (level <= 1)
                                break;

                        r = sd_bus_message_exit_container(m);
                        if (r < 0) {
                                log_error("Failed to exit container: %s", strerror(-r));
                                return r;
                        }

                        level--;

                        prefix = strrep("\t", level);
                        if (!prefix)
                                return log_oom();

                        if (type == SD_BUS_TYPE_ARRAY)
                                printf("%s} END_ARRAY \n", prefix);
                        else if (type == SD_BUS_TYPE_VARIANT)
                                printf("%s} END_VARIANT\n", prefix);
                        else if (type == SD_BUS_TYPE_STRUCT)
                                printf("%s} END_STRUCT\n", prefix);
                        else if (type == SD_BUS_TYPE_DICT_ENTRY)
                                printf("%s} END_DICT_ENTRY\n", prefix);

                        continue;
                }

                prefix = strrep("\t", level);
                if (!prefix)
                        return log_oom();

                if (bus_type_is_container(type) > 0) {
                        r = sd_bus_message_enter_container(m, type, contents);
                        if (r < 0) {
                                log_error("Failed to enter container: %s", strerror(-r));
                                return r;
                        }

                        if (type == SD_BUS_TYPE_ARRAY)
                                printf("%sBEGIN_ARRAY \"%s\" {\n", prefix, contents);
                        else if (type == SD_BUS_TYPE_VARIANT)
                                printf("%sBEGIN_VARIANT \"%s\" {\n", prefix, contents);
                        else if (type == SD_BUS_TYPE_STRUCT)
                                printf("%sBEGIN_STRUCT \"%s\" {\n", prefix, contents);
                        else if (type == SD_BUS_TYPE_DICT_ENTRY)
                                printf("%sBEGIN_DICT_ENTRY \"%s\" {\n", prefix, contents);

                        level ++;

                        continue;
                }

                r = sd_bus_message_read_basic(m, type, &basic);
                if (r < 0) {
                        log_error("Failed to get basic: %s", strerror(-r));
                        return r;
                }

                switch (type) {

                case SD_BUS_TYPE_BYTE:
                        printf("%sBYTE: %u\n", prefix, basic.u8);
                        break;

                case SD_BUS_TYPE_BOOLEAN:
                        printf("%sBOOLEAN: %s\n", prefix, yes_no(basic.i));
                        break;

                case SD_BUS_TYPE_INT16:
                        printf("%sINT16: %i\n", prefix, basic.s16);
                        break;

                case SD_BUS_TYPE_UINT16:
                        printf("%sUINT16: %u\n", prefix, basic.u16);
                        break;

                case SD_BUS_TYPE_INT32:
                        printf("%sINT32: %i\n", prefix, basic.s32);
                        break;

                case SD_BUS_TYPE_UINT32:
                        printf("%sUINT32: %u\n", prefix, basic.u32);
                        break;

                case SD_BUS_TYPE_INT64:
                        printf("%sINT64: %lli\n", prefix, (long long) basic.s64);
                        break;

                case SD_BUS_TYPE_UINT64:
                        printf("%sUINT64: %llu\n", prefix, (unsigned long long) basic.u64);
                        break;

                case SD_BUS_TYPE_DOUBLE:
                        printf("%sDOUBLE: %g\n", prefix, basic.d64);
                        break;

                case SD_BUS_TYPE_STRING:
                        printf("%sSTRING: \"%s\"\n", prefix, basic.string);
                        break;

                case SD_BUS_TYPE_OBJECT_PATH:
                        printf("%sOBJECT_PATH: \"%s\"\n", prefix, basic.string);
                        break;

                case SD_BUS_TYPE_SIGNATURE:
                        printf("%sSIGNATURE: \"%s\"\n", prefix, basic.string);
                        break;

                case SD_BUS_TYPE_UNIX_FD:
                        printf("%sUNIX_FD: %i\n", prefix, basic.i);
                        break;

                default:
                        assert_not_reached("Unknown basic type.");
                }
        }

        printf("} END_MESSAGE\n");
        return 0;
}

int bus_message_get_blob(sd_bus_message *m, void **buffer, size_t *sz) {
        size_t total;
        void *p, *e;
        unsigned i;
        struct bus_body_part *part;

        assert(m);
        assert(buffer);
        assert(sz);

        total = BUS_MESSAGE_SIZE(m);

        p = malloc(total);
        if (!p)
                return -ENOMEM;

        e = mempcpy(p, m->header, BUS_MESSAGE_BODY_BEGIN(m));
        MESSAGE_FOREACH_PART(part, i, m)
                e = mempcpy(e, part->data, part->size);

        assert(total == (size_t) ((uint8_t*) e - (uint8_t*) p));

        *buffer = p;
        *sz = total;

        return 0;
}

int bus_message_read_strv_extend(sd_bus_message *m, char ***l) {
        int r;

        assert(m);
        assert(l);

        r = sd_bus_message_enter_container(m, 'a', "s");
        if (r < 0)
                return r;

        for (;;) {
                const char *s;

                r = sd_bus_message_read_basic(m, 's', &s);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = strv_extend(l, s);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        return 0;
}

const char* bus_message_get_arg(sd_bus_message *m, unsigned i) {
        int r;
        const char *t = NULL;
        unsigned j;

        assert(m);

        r = sd_bus_message_rewind(m, true);
        if (r < 0)
                return NULL;

        for (j = 0; j <= i; j++) {
                char type;

                r = sd_bus_message_peek_type(m, &type, NULL);
                if (r < 0)
                        return NULL;

                if (type != SD_BUS_TYPE_STRING &&
                    type != SD_BUS_TYPE_OBJECT_PATH &&
                    type != SD_BUS_TYPE_SIGNATURE)
                        return NULL;

                r = sd_bus_message_read_basic(m, type, &t);
                if (r < 0)
                        return NULL;
        }

        return t;
}

bool bus_header_is_complete(struct bus_header *h, size_t size) {
        size_t full;

        assert(h);
        assert(size);

        if (size < sizeof(struct bus_header))
                return false;

        full = sizeof(struct bus_header) +
                (h->endian == SD_BUS_NATIVE_ENDIAN ? h->fields_size : bswap_32(h->fields_size));

        return size >= full;
}

int bus_header_message_size(struct bus_header *h, size_t *sum) {
        size_t fs, bs;

        assert(h);
        assert(sum);

        if (h->endian == SD_BUS_NATIVE_ENDIAN) {
                fs = h->fields_size;
                bs = h->body_size;
        } else if (h->endian == SD_BUS_REVERSE_ENDIAN) {
                fs = bswap_32(h->fields_size);
                bs = bswap_32(h->body_size);
        } else
                return -EBADMSG;

        *sum = sizeof(struct bus_header) + ALIGN8(fs) + bs;
        return 0;
}

int bus_message_to_errno(sd_bus_message *m) {
        assert(m);

        if (m->header->type != SD_BUS_MESSAGE_TYPE_METHOD_ERROR)
                return 0;

        return bus_error_to_errno(&m->error);
}
