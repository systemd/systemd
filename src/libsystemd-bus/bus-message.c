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

#include "util.h"

#include "bus-message.h"
#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-type.h"
#include "bus-signature.h"

int message_append_basic(sd_bus_message *m, char type, const void *p, const void **stored);

static void message_free(sd_bus_message *m) {
        unsigned i;

        assert(m);

        if (m->free_header)
                free(m->header);

        if (m->free_fields)
                free(m->fields);

        if (m->free_body)
                free(m->body);

        for (i = 0; i < m->n_fds; i++)
                close_nointr_nofail(m->fds[i]);

        for (i = 0; i < m->n_containers; i++)
                free(m->sub_containers[i].signature);

        free(m->sub_containers);
        free(m);
}

static void* buffer_extend(void **p, uint32_t *sz, size_t align, size_t extend) {
        size_t start, n;
        void *k;

        assert(p);
        assert(sz);
        assert(align > 0);

        start = ALIGN_TO((size_t) *sz, align);
        n = start + extend;

        if (n == *sz)
                return (uint8_t*) *p + start;

        if (n > (size_t) ((uint32_t) -1))
                return NULL;

        k = realloc(*p, n);
        if (!k)
                return NULL;

        /* Zero out padding */
        if (start > *sz)
                memset((uint8_t*) k + *sz, 0, start - *sz);

        *p = k;
        *sz = n;

        return (uint8_t*) k + start;
}

static void *message_extend_fields(sd_bus_message *m, size_t align, size_t sz) {
        void *p, *o;

        assert(m);

        o = m->fields;
        p = buffer_extend(&m->fields, &m->header->fields_size, align, sz);
        if (!p)
                return NULL;

        if (o != m->fields) {
                /* Adjust quick access pointers */

                if (m->path)
                        m->path = (const char*) m->fields + (m->path - (const char*) o);
                if (m->interface)
                        m->interface = (const char*) m->fields + (m->interface - (const char*) o);
                if (m->member)
                        m->member = (const char*) m->fields + (m->member - (const char*) o);
                if (m->destination)
                        m->destination = (const char*) m->fields + (m->destination - (const char*) o);
                if (m->sender)
                        m->sender = (const char*) m->fields + (m->sender - (const char*) o);
                if (m->signature)
                        m->signature = (const char*) m->fields + (m->signature - (const char*) o);
                if (m->error.name)
                        m->error.name = (const char*) m->fields + (m->error.name - (const char*) o);
        }

        m->free_fields = true;

        return p;
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
                *ret = (const char*) p + 8;

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

static sd_bus_message *message_new(sd_bus *bus, uint8_t type) {
        sd_bus_message *m;

        m = malloc0(ALIGN(sizeof(struct sd_bus_message)) + sizeof(struct bus_header));
        if (!m)
                return NULL;

        m->n_ref = 1;
        m->header = (struct bus_header*) ((uint8_t*) m + ALIGN(sizeof(struct sd_bus_message)));

#if __BYTE_ORDER == __BIG_ENDIAN
        m->header->endian = SD_BUS_BIG_ENDIAN;
#else
        m->header->endian = SD_BUS_LITTLE_ENDIAN;
#endif
        m->header->type = type;
        m->header->version = bus ? bus->message_version : 1;

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

        t = message_new(bus, SD_BUS_MESSAGE_TYPE_SIGNAL);
        if (!t)
                return -ENOMEM;

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
        if (call->header->type != SD_BUS_MESSAGE_TYPE_METHOD_CALL)
                return -EINVAL;
        if (!m)
                return -EINVAL;

        t = message_new(bus, type);
        if (!t)
                return -ENOMEM;

        t->reply_serial = BUS_MESSAGE_SERIAL(call);

        r = message_append_field_uint32(t, SD_BUS_MESSAGE_HEADER_REPLY_SERIAL, t->reply_serial);
        if (r < 0)
                goto fail;

        if (call->sender) {
                r = message_append_field_string(t, SD_BUS_MESSAGE_HEADER_DESTINATION, SD_BUS_TYPE_STRING, call->sender, &t->sender);
                if (r < 0)
                        goto fail;
        }

        t->dont_send = !!(call->header->flags & SD_BUS_MESSAGE_NO_REPLY_EXPECTED);

        *m = t;

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

        if (!e)
                return -EINVAL;
        if (!e->name)
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
        if (!m->uid_valid)
                return -ENOENT;

        *uid = m->uid;
        return 0;
}

int sd_bus_message_get_gid(sd_bus_message *m, gid_t *gid) {
        if (!m)
                return -EINVAL;
        if (!m->gid_valid)
                return -ENOENT;

        *gid = m->gid;
        return 0;
}

int sd_bus_message_get_pid(sd_bus_message *m, pid_t *pid) {
        if (!m)
                return -EINVAL;
        if (m->pid <= 0)
                return -ENOENT;

        *pid = m->pid;
        return 0;
}

int sd_bus_message_get_tid(sd_bus_message *m, pid_t *tid) {
        if (!m)
                return -EINVAL;
        if (m->tid <= 0)
                return -ENOENT;

        *tid = m->tid;
        return 0;
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

        assert(m->sub_containers);
        return m->sub_containers + m->n_containers - 1;
}

static void *message_extend_body(sd_bus_message *m, size_t align, size_t sz) {
        void *p, *o;
        size_t added;
        struct bus_container *c;

        assert(m);

        o = m->body;
        added = m->header->body_size;

        p = buffer_extend(&m->body, &m->header->body_size, align, sz);
        if (!p)
                return NULL;

        added = m->header->body_size - added;

        for (c = m->sub_containers; c < m->sub_containers + m->n_containers; c++)
                if (c->array_size) {
                        c->array_size = (uint32_t*) ((uint8_t*) m->body + ((uint8_t*) c->array_size - (uint8_t*) o));
                        *c->array_size += added;
                }

        if (o != m->body) {
                if (m->error.message)
                        m->error.message = (const char*) m->body + (m->error.message - (const char*) o);
        }

        m->free_body = true;

        return p;
}

int message_append_basic(sd_bus_message *m, char type, const void *p, const void **stored) {
        struct bus_container *c;
        size_t sz, align, nindex;
        uint32_t k;
        void *a;
        char *e = NULL;

        if (!m)
                return -EINVAL;
        if (m->sealed)
                return -EPERM;
        if (!bus_type_is_basic(type))
                return -EINVAL;

        c = message_get_container(m);

        if (c->signature && c->signature[c->index]) {
                /* Container signature is already set */

                if (c->signature[c->index] != type)
                        return -EINVAL;
        } else {
                /* Maybe we can append to the signature? But only if this is the top-level container*/
                if (c->enclosing != 0)
                        return -EINVAL;

                e = strextend(&c->signature, CHAR_TO_STR(type), NULL);
                if (!e)
                        return -ENOMEM;
        }

        nindex = c->index + 1;

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

        default:
                align = bus_type_get_alignment(type);
                sz = bus_type_get_size(type);
                break;
        }

        assert(align > 0);
        assert(sz > 0);

        a = message_extend_body(m, align, sz);
        if (!a) {
                /* Truncate extended signature again */
                if (e)
                        c->signature[c->index] = 0;

                return -ENOMEM;
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

        } else {
                memcpy(a, p, sz);

                if (stored)
                        *stored = a;
        }

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index = nindex;

        return 0;
}

int sd_bus_message_append_basic(sd_bus_message *m, char type, const void *p) {
        return message_append_basic(m, type, p, NULL);
}

static int bus_message_open_array(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents,
                uint32_t **array_size) {

        char *e = NULL;
        size_t nindex;
        void *a, *b;
        int alignment;
        size_t saved;

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
                        return -EINVAL;

                if (!startswith(c->signature + c->index + 1, contents))
                        return -EINVAL;

                nindex = c->index + 1 + strlen(contents);
        } else {
                if (c->enclosing != 0)
                        return -EINVAL;

                /* Extend the existing signature */

                e = strextend(&c->signature, CHAR_TO_STR(SD_BUS_TYPE_ARRAY), contents, NULL);
                if (!e)
                        return -ENOMEM;

                nindex = e - c->signature;
        }

        saved = m->header->body_size;
        a = message_extend_body(m, 4, 4);
        if (!a) {
                /* Truncate extended signature again */
                if (e)
                        c->signature[c->index] = 0;

                return -ENOMEM;
        }
        b = m->body;

        if (!message_extend_body(m, alignment, 0)) {
                /* Add alignment between size and first element */
                if (e)
                        c->signature[c->index] = 0;

                m->header->body_size = saved;
                return -ENOMEM;
        }

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index = nindex;

        /* m->body might have changed so let's readjust a */
        a = (uint8_t*) m->body + ((uint8_t*) a - (uint8_t*) b);
        *(uint32_t*) a = 0;

        *array_size = a;
        return 0;
}

static int bus_message_open_variant(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents) {

        char *e = NULL;
        size_t l, nindex;
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
                        return -EINVAL;

        } else {
                if (c->enclosing != 0)
                        return -EINVAL;

                e = strextend(&c->signature, CHAR_TO_STR(SD_BUS_TYPE_VARIANT), NULL);
                if (!e)
                        return -ENOMEM;
        }

        nindex = c->index + 1;

        l = strlen(contents);
        a = message_extend_body(m, 1, 1 + l + 1);
        if (!a) {
                /* Truncate extended signature again */
                if (e)
                        c->signature[c->index] = 0;

                return -ENOMEM;
        }

        *(uint8_t*) a = l;
        memcpy((uint8_t*) a + 1, contents, l + 1);

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index = nindex;

        return 0;
}

static int bus_message_open_struct(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents) {

        size_t nindex;
        char *e = NULL;

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
                        return -EINVAL;

                nindex = c->index + 1 + l + 1;
        } else {
                if (c->enclosing != 0)
                        return -EINVAL;

                e = strextend(&c->signature, CHAR_TO_STR(SD_BUS_TYPE_STRUCT_BEGIN), contents, CHAR_TO_STR(SD_BUS_TYPE_STRUCT_END), NULL);
                if (!e)
                        return -ENOMEM;

                nindex = e - c->signature;
        }

        /* Align contents to 8 byte boundary */
        if (!message_extend_body(m, 8, 0)) {
                if (e)
                        c->signature[c->index] = 0;

                return -ENOMEM;
        }

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
                return -EINVAL;

        if (c->signature && c->signature[c->index]) {
                size_t l;

                l = strlen(contents);

                if (c->signature[c->index] != SD_BUS_TYPE_DICT_ENTRY_BEGIN ||
                    !startswith(c->signature + c->index + 1, contents) ||
                    c->signature[c->index + 1 + l] != SD_BUS_TYPE_DICT_ENTRY_END)
                        return -EINVAL;

                nindex = c->index + 1 + l + 1;
        } else
                return -EINVAL;

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

        struct bus_container *c, *sub;
        char *signature;
        uint32_t *array_size = NULL;
        int r;

        if (!m)
                return -EINVAL;
        if (m->sealed)
                return -EPERM;
        if (!contents)
                return -EINVAL;

        /* Make sure we have space for one more container */
        sub = realloc(m->sub_containers, sizeof(struct bus_container) * (m->n_containers + 1));
        if (!sub)
                return -ENOMEM;

        m->sub_containers = sub;

        c = message_get_container(m);

        signature = strdup(contents);
        if (!signature)
                return -ENOMEM;

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
        sub += m->n_containers++;

        sub->enclosing = type;
        sub->signature = signature;
        sub->index = 0;
        sub->array_size = array_size;

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

        c = message_get_container(m);

        if (!c->signature)
                return -EINVAL;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                if (c->signature[c->index] != 0)
                        return -EINVAL;

        free(c->signature);
        m->n_containers--;

        return 0;
}

static int message_append_ap(
                sd_bus_message *m,
                const char *types,
                va_list ap) {

        const char *t;
        int r;

        assert(m);
        assert(types);

        for (t = types; *t; t++) {
                switch (*t) {

                case SD_BUS_TYPE_BYTE: {
                        uint8_t x;

                        x = (uint8_t) va_arg(ap, int);
                        r = sd_bus_message_append_basic(m, *t, &x);
                        break;
                }

                case SD_BUS_TYPE_BOOLEAN:
                case SD_BUS_TYPE_INT32:
                case SD_BUS_TYPE_UINT32: {
                        uint32_t x;

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

                case SD_BUS_TYPE_UNIX_FD: {
                        int x;

                        x = va_arg(ap, int);
                        r = sd_bus_message_append_basic(m, *t, &x);
                        break;
                }

                case SD_BUS_TYPE_ARRAY: {
                        unsigned i, n;
                        size_t k;

                        r = signature_element_length(t + 1, &k);
                        if (r < 0)
                                return r;

                        {
                                char s[k + 1];

                                memcpy(s, t + 1, k);
                                s[k] = 0;
                                t += k;

                                r = sd_bus_message_open_container(m, SD_BUS_TYPE_ARRAY, s);
                                if (r < 0)
                                        return r;

                                n = va_arg(ap, unsigned);

                                for (i = 0; i < n; i++) {
                                        r = message_append_ap(m, s, ap);
                                        if (r < 0)
                                                return r;
                                }

                                r = sd_bus_message_close_container(m);
                        }

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

                        r = message_append_ap(m, s, ap);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_close_container(m);
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

                                t += k - 1;

                                r = message_append_ap(m, s, ap);
                                if (r < 0)
                                        return r;

                                r = sd_bus_message_close_container(m);
                        }

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
        if (!types)
                return -EINVAL;

        va_start(ap, types);
        r = message_append_ap(m, types, ap);
        va_end(ap);

        return r;
}

int sd_bus_message_read_type(sd_bus_message *m, char *type, char *element, size_t *length) {
        return -ENOTSUP;
}

int sd_bus_message_read_basic(sd_bus_message *m, char type, char element, const void **p, size_t *length) {
        return -ENOTSUP;
}

int sd_bus_message_read(sd_bus_message *m, const char *types, ...) {
        return -ENOTSUP;
}

int message_parse(sd_bus_message *m) {
        assert(m);

        if (m->header->version != 1)
                return -EIO;

        if (m->header->endian != SD_BUS_BIG_ENDIAN &&
            m->header->endian != SD_BUS_LITTLE_ENDIAN)
                return -EIO;

        return 0;
}

static void setup_iovec(sd_bus_message *m) {
        assert(m);
        assert(m->sealed);

        m->n_iovec = 0;

        m->iovec[m->n_iovec].iov_base = m->header;
        m->iovec[m->n_iovec].iov_len = sizeof(*m->header);
        m->n_iovec++;

        if (m->fields) {
                m->iovec[m->n_iovec].iov_base = m->fields;
                m->iovec[m->n_iovec].iov_len = m->header->fields_size;
                m->n_iovec++;

                if (m->header->fields_size % 8 != 0) {
                        static const uint8_t padding[7] = { 0, 0, 0, 0, 0, 0, 0 };

                        m->iovec[m->n_iovec].iov_base = (void*) padding;
                        m->iovec[m->n_iovec].iov_len = 8 - m->header->fields_size % 8;
                        m->n_iovec++;
                }
        }

        if (m->body) {
                m->iovec[m->n_iovec].iov_base = m->body;
                m->iovec[m->n_iovec].iov_len = m->header->body_size;
                m->n_iovec++;
        }
}

int message_seal(sd_bus_message *m, uint64_t serial) {
        int r;

        assert(m);

        if (m->sealed)
                return -EPERM;

        if (m->n_containers > 0)
                return -EBADMSG;

        /* If there's a non-trivial signature set, then add it in here */
        if (!isempty(m->root_container.signature)) {
                r = message_append_field_signature(m, SD_BUS_MESSAGE_HEADER_SIGNATURE, m->root_container.signature, &m->signature);
                if (r < 0)
                        return r;
        }

        if (m->n_fds > 0) {
                r = message_append_field_uint32(m, SD_BUS_MESSAGE_HEADER_UNIX_FDS, m->n_fds);
                if (r < 0)
                        return r;
        }

        m->header->serial = serial;
        m->sealed = true;

        setup_iovec(m);

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

void message_dump(sd_bus_message *m) {

        log_info("Message %p\n"
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
                 "\tsealed=%s\n",
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
                 strna(m->signature),
                 m->reply_serial,
                 strna(m->error.name),
                 strna(m->error.message),
                 yes_no(m->sealed));
}

int bus_message_get_blob(sd_bus_message *m, void **buffer, size_t *sz) {
        size_t total;
        unsigned i;
        void *p, *e;

        assert(m);
        assert(buffer);
        assert(sz);

        for (i = 0, total = 0; i < m->n_iovec; i++)
                total += m->iovec[i].iov_len;

        p = malloc(total);
        if (!p)
                return -ENOMEM;

        for (i = 0, e = p; i < m->n_iovec; i++)
                e = mempcpy(e, m->iovec[i].iov_base, m->iovec[i].iov_len);

        *buffer = p;
        *sz = total;

        return 0;
}
