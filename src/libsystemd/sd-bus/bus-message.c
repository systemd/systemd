/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-gvariant.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-signature.h"
#include "bus-type.h"
#include "bus-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "memfd-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "utf8.h"
#include "util.h"

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

        if (part->memfd >= 0)
                close_and_munmap(part->memfd, part->mmap_begin, part->mapped);
        else if (part->munmap_this)
                munmap(part->mmap_begin, part->mapped);
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

static struct bus_container *message_get_last_container(sd_bus_message *m) {
        assert(m);

        if (m->n_containers == 0)
                return &m->root_container;

        assert(m->containers);
        return m->containers + m->n_containers - 1;
}

static void message_free_last_container(sd_bus_message *m) {
        struct bus_container *c;

        c = message_get_last_container(m);

        free(c->signature);
        free(c->peeked_signature);
        free(c->offsets);

        /* Move to previous container, but not if we are on root container */
        if (m->n_containers > 0)
                m->n_containers--;
}

static void message_reset_containers(sd_bus_message *m) {
        assert(m);

        while (m->n_containers > 0)
                message_free_last_container(m);

        m->containers = mfree(m->containers);
        m->containers_allocated = 0;
        m->root_container.index = 0;
}

static sd_bus_message* message_free(sd_bus_message *m) {
        assert(m);

        if (m->free_header)
                free(m->header);

        message_reset_parts(m);

        sd_bus_unref(m->bus);

        if (m->free_fds) {
                close_many(m->fds, m->n_fds);
                free(m->fds);
        }

        if (m->iovec != m->iovec_fixed)
                free(m->iovec);

        message_reset_containers(m);
        assert(m->n_containers == 0);
        message_free_last_container(m);

        bus_creds_done(&m->creds);
        return mfree(m);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_bus_message*, message_free);

static void *message_extend_fields(sd_bus_message *m, size_t align, size_t sz, bool add_offset) {
        void *op, *np;
        size_t old_size, new_size, start;

        assert(m);

        if (m->poisoned)
                return NULL;

        old_size = sizeof(struct bus_header) + m->fields_size;
        start = ALIGN_TO(old_size, align);
        new_size = start + sz;

        if (new_size < start ||
            new_size > (size_t) ((uint32_t) -1))
                goto poison;

        if (old_size == new_size)
                return (uint8_t*) m->header + old_size;

        if (m->free_header) {
                np = realloc(m->header, ALIGN8(new_size));
                if (!np)
                        goto poison;
        } else {
                /* Initially, the header is allocated as part of
                 * the sd_bus_message itself, let's replace it by
                 * dynamic data */

                np = malloc(ALIGN8(new_size));
                if (!np)
                        goto poison;

                memcpy(np, m->header, sizeof(struct bus_header));
        }

        /* Zero out padding */
        if (start > old_size)
                memzero((uint8_t*) np + old_size, start - old_size);

        op = m->header;
        m->header = np;
        m->fields_size = new_size - sizeof(struct bus_header);

        /* Adjust quick access pointers */
        m->path = adjust_pointer(m->path, op, old_size, m->header);
        m->interface = adjust_pointer(m->interface, op, old_size, m->header);
        m->member = adjust_pointer(m->member, op, old_size, m->header);
        m->destination = adjust_pointer(m->destination, op, old_size, m->header);
        m->sender = adjust_pointer(m->sender, op, old_size, m->header);
        m->error.name = adjust_pointer(m->error.name, op, old_size, m->header);

        m->free_header = true;

        if (add_offset) {
                if (m->n_header_offsets >= ELEMENTSOF(m->header_offsets))
                        goto poison;

                m->header_offsets[m->n_header_offsets++] = new_size - sizeof(struct bus_header);
        }

        return (uint8_t*) np + start;

poison:
        m->poisoned = true;
        return NULL;
}

static int message_append_field_string(
                sd_bus_message *m,
                uint64_t h,
                char type,
                const char *s,
                const char **ret) {

        size_t l;
        uint8_t *p;

        assert(m);

        /* dbus1 only allows 8bit header field ids */
        if (h > 0xFF)
                return -EINVAL;

        /* dbus1 doesn't allow strings over 32bit, let's enforce this
         * globally, to not risk convertability */
        l = strlen(s);
        if (l > UINT32_MAX)
                return -EINVAL;

        /* Signature "(yv)" where the variant contains "s" */

        if (BUS_MESSAGE_IS_GVARIANT(m)) {

                /* (field id 64bit, ((string + NUL) + NUL + signature string 's') */
                p = message_extend_fields(m, 8, 8 + l + 1 + 1 + 1, true);
                if (!p)
                        return -ENOMEM;

                *((uint64_t*) p) = h;
                memcpy(p+8, s, l);
                p[8+l] = 0;
                p[8+l+1] = 0;
                p[8+l+2] = type;

                if (ret)
                        *ret = (char*) p + 8;

        } else {
                /* (field id byte + (signature length + signature 's' + NUL) + (string length + string + NUL)) */
                p = message_extend_fields(m, 8, 4 + 4 + l + 1, false);
                if (!p)
                        return -ENOMEM;

                p[0] = (uint8_t) h;
                p[1] = 1;
                p[2] = type;
                p[3] = 0;

                ((uint32_t*) p)[1] = l;
                memcpy(p + 8, s, l + 1);

                if (ret)
                        *ret = (char*) p + 8;
        }

        return 0;
}

static int message_append_field_signature(
                sd_bus_message *m,
                uint64_t h,
                const char *s,
                const char **ret) {

        size_t l;
        uint8_t *p;

        assert(m);

        /* dbus1 only allows 8bit header field ids */
        if (h > 0xFF)
                return -EINVAL;

        /* dbus1 doesn't allow signatures over 8bit, let's enforce
         * this globally, to not risk convertability */
        l = strlen(s);
        if (l > 255)
                return -EINVAL;

        /* Signature "(yv)" where the variant contains "g" */

        if (BUS_MESSAGE_IS_GVARIANT(m))
                /* For gvariant the serialization is the same as for normal strings */
                return message_append_field_string(m, h, 'g', s, ret);
        else {
                /* (field id byte + (signature length + signature 'g' + NUL) + (string length + string + NUL)) */
                p = message_extend_fields(m, 8, 4 + 1 + l + 1, false);
                if (!p)
                        return -ENOMEM;

                p[0] = (uint8_t) h;
                p[1] = 1;
                p[2] = SD_BUS_TYPE_SIGNATURE;
                p[3] = 0;
                p[4] = l;
                memcpy(p + 5, s, l + 1);

                if (ret)
                        *ret = (const char*) p + 5;
        }

        return 0;
}

static int message_append_field_uint32(sd_bus_message *m, uint64_t h, uint32_t x) {
        uint8_t *p;

        assert(m);

        /* dbus1 only allows 8bit header field ids */
        if (h > 0xFF)
                return -EINVAL;

        if (BUS_MESSAGE_IS_GVARIANT(m)) {
                /* (field id 64bit + ((value + NUL + signature string 'u') */

                p = message_extend_fields(m, 8, 8 + 4 + 1 + 1, true);
                if (!p)
                        return -ENOMEM;

                *((uint64_t*) p) = h;
                *((uint32_t*) (p + 8)) = x;
                p[12] = 0;
                p[13] = 'u';
        } else {
                /* (field id byte + (signature length + signature 'u' + NUL) + value) */
                p = message_extend_fields(m, 8, 4 + 4, false);
                if (!p)
                        return -ENOMEM;

                p[0] = (uint8_t) h;
                p[1] = 1;
                p[2] = 'u';
                p[3] = 0;

                ((uint32_t*) p)[1] = x;
        }

        return 0;
}

static int message_append_field_uint64(sd_bus_message *m, uint64_t h, uint64_t x) {
        uint8_t *p;

        assert(m);

        /* dbus1 only allows 8bit header field ids */
        if (h > 0xFF)
                return -EINVAL;

        if (BUS_MESSAGE_IS_GVARIANT(m)) {
                /* (field id 64bit + ((value + NUL + signature string 't') */

                p = message_extend_fields(m, 8, 8 + 8 + 1 + 1, true);
                if (!p)
                        return -ENOMEM;

                *((uint64_t*) p) = h;
                *((uint64_t*) (p + 8)) = x;
                p[16] = 0;
                p[17] = 't';
        } else {
                /* (field id byte + (signature length + signature 't' + NUL) + 4 byte padding + value) */
                p = message_extend_fields(m, 8, 4 + 4 + 8, false);
                if (!p)
                        return -ENOMEM;

                p[0] = (uint8_t) h;
                p[1] = 1;
                p[2] = 't';
                p[3] = 0;
                p[4] = 0;
                p[5] = 0;
                p[6] = 0;
                p[7] = 0;

                ((uint64_t*) p)[1] = x;
        }

        return 0;
}

static int message_append_reply_cookie(sd_bus_message *m, uint64_t cookie) {
        assert(m);

        if (BUS_MESSAGE_IS_GVARIANT(m))
                return message_append_field_uint64(m, BUS_MESSAGE_HEADER_REPLY_SERIAL, cookie);
        else {
                /* 64bit cookies are not supported on dbus1 */
                if (cookie > 0xffffffffUL)
                        return -EOPNOTSUPP;

                return message_append_field_uint32(m, BUS_MESSAGE_HEADER_REPLY_SERIAL, (uint32_t) cookie);
        }
}

int bus_message_from_header(
                sd_bus *bus,
                void *header,
                size_t header_accessible,
                void *footer,
                size_t footer_accessible,
                size_t message_size,
                int *fds,
                size_t n_fds,
                const char *label,
                size_t extra,
                sd_bus_message **ret) {

        _cleanup_free_ sd_bus_message *m = NULL;
        struct bus_header *h;
        size_t a, label_sz;

        assert(bus);
        assert(header || header_accessible <= 0);
        assert(footer || footer_accessible <= 0);
        assert(fds || n_fds <= 0);
        assert(ret);

        if (header_accessible < sizeof(struct bus_header))
                return -EBADMSG;

        if (header_accessible > message_size)
                return -EBADMSG;
        if (footer_accessible > message_size)
                return -EBADMSG;

        h = header;
        if (!IN_SET(h->version, 1, 2))
                return -EBADMSG;

        if (h->type == _SD_BUS_MESSAGE_TYPE_INVALID)
                return -EBADMSG;

        if (!IN_SET(h->endian, BUS_LITTLE_ENDIAN, BUS_BIG_ENDIAN))
                return -EBADMSG;

        /* Note that we are happy with unknown flags in the flags header! */

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
        m->header = header;
        m->header_accessible = header_accessible;
        m->footer = footer;
        m->footer_accessible = footer_accessible;

        if (BUS_MESSAGE_IS_GVARIANT(m)) {
                size_t ws;

                if (h->dbus2.cookie == 0)
                        return -EBADMSG;

                /* dbus2 derives the sizes from the message size and
                the offset table at the end, since it is formatted as
                gvariant "yyyyuta{tv}v". Since the message itself is a
                structure with precisely to variable sized entries,
                there's only one offset in the table, which marks the
                end of the fields array. */

                ws = bus_gvariant_determine_word_size(message_size, 0);
                if (footer_accessible < ws)
                        return -EBADMSG;

                m->fields_size = bus_gvariant_read_word_le((uint8_t*) footer + footer_accessible - ws, ws);
                if (ALIGN8(m->fields_size) > message_size - ws)
                        return -EBADMSG;
                if (m->fields_size < sizeof(struct bus_header))
                        return -EBADMSG;

                m->fields_size -= sizeof(struct bus_header);
                m->body_size = message_size - (sizeof(struct bus_header) + ALIGN8(m->fields_size));
        } else {
                if (h->dbus1.serial == 0)
                        return -EBADMSG;

                /* dbus1 has the sizes in the header */
                m->fields_size = BUS_MESSAGE_BSWAP32(m, h->dbus1.fields_size);
                m->body_size = BUS_MESSAGE_BSWAP32(m, h->dbus1.body_size);

                if (sizeof(struct bus_header) + ALIGN8(m->fields_size) + m->body_size != message_size)
                        return -EBADMSG;
        }

        m->fds = fds;
        m->n_fds = n_fds;

        if (label) {
                m->creds.label = (char*) m + ALIGN(sizeof(sd_bus_message)) + ALIGN(extra);
                memcpy(m->creds.label, label, label_sz + 1);

                m->creds.mask |= SD_BUS_CREDS_SELINUX_CONTEXT;
        }

        m->bus = sd_bus_ref(bus);
        *ret = TAKE_PTR(m);

        return 0;
}

int bus_message_from_malloc(
                sd_bus *bus,
                void *buffer,
                size_t length,
                int *fds,
                size_t n_fds,
                const char *label,
                sd_bus_message **ret) {

        _cleanup_(message_freep) sd_bus_message *m = NULL;
        size_t sz;
        int r;

        r = bus_message_from_header(
                        bus,
                        buffer, length, /* in this case the initial bytes and the final bytes are the same */
                        buffer, length,
                        length,
                        fds, n_fds,
                        label,
                        0, &m);
        if (r < 0)
                return r;

        sz = length - sizeof(struct bus_header) - ALIGN8(m->fields_size);
        if (sz > 0) {
                m->n_body_parts = 1;
                m->body.data = (uint8_t*) buffer + sizeof(struct bus_header) + ALIGN8(m->fields_size);
                m->body.size = sz;
                m->body.sealed = true;
                m->body.memfd = -1;
        }

        m->n_iovec = 1;
        m->iovec = m->iovec_fixed;
        m->iovec[0].iov_base = buffer;
        m->iovec[0].iov_len = length;

        r = bus_message_parse_fields(m);
        if (r < 0)
                return r;

        /* We take possession of the memory and fds now */
        m->free_header = true;
        m->free_fds = true;

        *ret = TAKE_PTR(m);
        return 0;
}

_public_ int sd_bus_message_new(
                sd_bus *bus,
                sd_bus_message **m,
                uint8_t type) {

        sd_bus_message *t;

        assert_return(bus, -ENOTCONN);
        assert_return(bus->state != BUS_UNSET, -ENOTCONN);
        assert_return(m, -EINVAL);
        assert_return(type < _SD_BUS_MESSAGE_TYPE_MAX, -EINVAL);

        t = malloc0(ALIGN(sizeof(sd_bus_message)) + sizeof(struct bus_header));
        if (!t)
                return -ENOMEM;

        t->n_ref = 1;
        t->header = (struct bus_header*) ((uint8_t*) t + ALIGN(sizeof(struct sd_bus_message)));
        t->header->endian = BUS_NATIVE_ENDIAN;
        t->header->type = type;
        t->header->version = bus->message_version;
        t->allow_fds = bus->can_fds || !IN_SET(bus->state, BUS_HELLO, BUS_RUNNING);
        t->root_container.need_offsets = BUS_MESSAGE_IS_GVARIANT(t);
        t->bus = sd_bus_ref(bus);

        if (bus->allow_interactive_authorization)
                t->header->flags |= BUS_MESSAGE_ALLOW_INTERACTIVE_AUTHORIZATION;

        *m = t;
        return 0;
}

_public_ int sd_bus_message_new_signal(
                sd_bus *bus,
                sd_bus_message **m,
                const char *path,
                const char *interface,
                const char *member) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *t = NULL;
        int r;

        assert_return(bus, -ENOTCONN);
        assert_return(bus->state != BUS_UNSET, -ENOTCONN);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(interface_name_is_valid(interface), -EINVAL);
        assert_return(member_name_is_valid(member), -EINVAL);
        assert_return(m, -EINVAL);

        r = sd_bus_message_new(bus, &t, SD_BUS_MESSAGE_SIGNAL);
        if (r < 0)
                return -ENOMEM;

        assert(t);

        t->header->flags |= BUS_MESSAGE_NO_REPLY_EXPECTED;

        r = message_append_field_string(t, BUS_MESSAGE_HEADER_PATH, SD_BUS_TYPE_OBJECT_PATH, path, &t->path);
        if (r < 0)
                return r;
        r = message_append_field_string(t, BUS_MESSAGE_HEADER_INTERFACE, SD_BUS_TYPE_STRING, interface, &t->interface);
        if (r < 0)
                return r;
        r = message_append_field_string(t, BUS_MESSAGE_HEADER_MEMBER, SD_BUS_TYPE_STRING, member, &t->member);
        if (r < 0)
                return r;

        *m = TAKE_PTR(t);
        return 0;
}

_public_ int sd_bus_message_new_method_call(
                sd_bus *bus,
                sd_bus_message **m,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member) {

        _cleanup_(message_freep) sd_bus_message *t = NULL;
        int r;

        assert_return(bus, -ENOTCONN);
        assert_return(bus->state != BUS_UNSET, -ENOTCONN);
        assert_return(!destination || service_name_is_valid(destination), -EINVAL);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(!interface || interface_name_is_valid(interface), -EINVAL);
        assert_return(member_name_is_valid(member), -EINVAL);
        assert_return(m, -EINVAL);

        r = sd_bus_message_new(bus, &t, SD_BUS_MESSAGE_METHOD_CALL);
        if (r < 0)
                return -ENOMEM;

        assert(t);

        r = message_append_field_string(t, BUS_MESSAGE_HEADER_PATH, SD_BUS_TYPE_OBJECT_PATH, path, &t->path);
        if (r < 0)
                return r;
        r = message_append_field_string(t, BUS_MESSAGE_HEADER_MEMBER, SD_BUS_TYPE_STRING, member, &t->member);
        if (r < 0)
                return r;

        if (interface) {
                r = message_append_field_string(t, BUS_MESSAGE_HEADER_INTERFACE, SD_BUS_TYPE_STRING, interface, &t->interface);
                if (r < 0)
                        return r;
        }

        if (destination) {
                r = message_append_field_string(t, BUS_MESSAGE_HEADER_DESTINATION, SD_BUS_TYPE_STRING, destination, &t->destination);
                if (r < 0)
                        return r;
        }

        *m = TAKE_PTR(t);
        return 0;
}

static int message_new_reply(
                sd_bus_message *call,
                uint8_t type,
                sd_bus_message **m) {

        _cleanup_(message_freep) sd_bus_message *t = NULL;
        uint64_t cookie;
        int r;

        assert_return(call, -EINVAL);
        assert_return(call->sealed, -EPERM);
        assert_return(call->header->type == SD_BUS_MESSAGE_METHOD_CALL, -EINVAL);
        assert_return(call->bus->state != BUS_UNSET, -ENOTCONN);
        assert_return(m, -EINVAL);

        cookie = BUS_MESSAGE_COOKIE(call);
        if (cookie == 0)
                return -EOPNOTSUPP;

        r = sd_bus_message_new(call->bus, &t, type);
        if (r < 0)
                return -ENOMEM;

        assert(t);

        t->header->flags |= BUS_MESSAGE_NO_REPLY_EXPECTED;
        t->reply_cookie = cookie;
        r = message_append_reply_cookie(t, t->reply_cookie);
        if (r < 0)
                return r;

        if (call->sender) {
                r = message_append_field_string(t, BUS_MESSAGE_HEADER_DESTINATION, SD_BUS_TYPE_STRING, call->sender, &t->destination);
                if (r < 0)
                        return r;
        }

        t->dont_send = !!(call->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED);
        t->enforced_reply_signature = call->enforced_reply_signature;

        *m = TAKE_PTR(t);
        return 0;
}

_public_ int sd_bus_message_new_method_return(
                sd_bus_message *call,
                sd_bus_message **m) {

        return message_new_reply(call, SD_BUS_MESSAGE_METHOD_RETURN, m);
}

_public_ int sd_bus_message_new_method_error(
                sd_bus_message *call,
                sd_bus_message **m,
                const sd_bus_error *e) {

        _cleanup_(message_freep) sd_bus_message *t = NULL;
        int r;

        assert_return(sd_bus_error_is_set(e), -EINVAL);
        assert_return(m, -EINVAL);

        r = message_new_reply(call, SD_BUS_MESSAGE_METHOD_ERROR, &t);
        if (r < 0)
                return r;

        r = message_append_field_string(t, BUS_MESSAGE_HEADER_ERROR_NAME, SD_BUS_TYPE_STRING, e->name, &t->error.name);
        if (r < 0)
                return r;

        if (e->message) {
                r = message_append_basic(t, SD_BUS_TYPE_STRING, e->message, (const void**) &t->error.message);
                if (r < 0)
                        return r;
        }

        t->error._need_free = -1;

        *m = TAKE_PTR(t);
        return 0;
}

_public_ int sd_bus_message_new_method_errorf(
                sd_bus_message *call,
                sd_bus_message **m,
                const char *name,
                const char *format,
                ...) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        va_list ap;

        assert_return(name, -EINVAL);
        assert_return(m, -EINVAL);

        va_start(ap, format);
        bus_error_setfv(&error, name, format, ap);
        va_end(ap);

        return sd_bus_message_new_method_error(call, m, &error);
}

_public_ int sd_bus_message_new_method_errno(
                sd_bus_message *call,
                sd_bus_message **m,
                int error,
                const sd_bus_error *p) {

        _cleanup_(sd_bus_error_free) sd_bus_error berror = SD_BUS_ERROR_NULL;

        if (sd_bus_error_is_set(p))
                return sd_bus_message_new_method_error(call, m, p);

        sd_bus_error_set_errno(&berror, error);

        return sd_bus_message_new_method_error(call, m, &berror);
}

_public_ int sd_bus_message_new_method_errnof(
                sd_bus_message *call,
                sd_bus_message **m,
                int error,
                const char *format,
                ...) {

        _cleanup_(sd_bus_error_free) sd_bus_error berror = SD_BUS_ERROR_NULL;
        va_list ap;

        va_start(ap, format);
        sd_bus_error_set_errnofv(&berror, error, format, ap);
        va_end(ap);

        return sd_bus_message_new_method_error(call, m, &berror);
}

void bus_message_set_sender_local(sd_bus *bus, sd_bus_message *m) {
        assert(bus);
        assert(m);

        m->sender = m->creds.unique_name = (char*) "org.freedesktop.DBus.Local";
        m->creds.well_known_names_local = true;
        m->creds.mask |= (SD_BUS_CREDS_UNIQUE_NAME|SD_BUS_CREDS_WELL_KNOWN_NAMES) & bus->creds_mask;
}

void bus_message_set_sender_driver(sd_bus *bus, sd_bus_message *m) {
        assert(bus);
        assert(m);

        m->sender = m->creds.unique_name = (char*) "org.freedesktop.DBus";
        m->creds.well_known_names_driver = true;
        m->creds.mask |= (SD_BUS_CREDS_UNIQUE_NAME|SD_BUS_CREDS_WELL_KNOWN_NAMES) & bus->creds_mask;
}

int bus_message_new_synthetic_error(
                sd_bus *bus,
                uint64_t cookie,
                const sd_bus_error *e,
                sd_bus_message **m) {

        _cleanup_(message_freep) sd_bus_message *t = NULL;
        int r;

        assert(bus);
        assert(sd_bus_error_is_set(e));
        assert(m);

        r = sd_bus_message_new(bus, &t, SD_BUS_MESSAGE_METHOD_ERROR);
        if (r < 0)
                return -ENOMEM;

        assert(t);

        t->header->flags |= BUS_MESSAGE_NO_REPLY_EXPECTED;
        t->reply_cookie = cookie;

        r = message_append_reply_cookie(t, t->reply_cookie);
        if (r < 0)
                return r;

        if (bus && bus->unique_name) {
                r = message_append_field_string(t, BUS_MESSAGE_HEADER_DESTINATION, SD_BUS_TYPE_STRING, bus->unique_name, &t->destination);
                if (r < 0)
                        return r;
        }

        r = message_append_field_string(t, BUS_MESSAGE_HEADER_ERROR_NAME, SD_BUS_TYPE_STRING, e->name, &t->error.name);
        if (r < 0)
                return r;

        if (e->message) {
                r = message_append_basic(t, SD_BUS_TYPE_STRING, e->message, (const void**) &t->error.message);
                if (r < 0)
                        return r;
        }

        t->error._need_free = -1;

        bus_message_set_sender_driver(bus, t);

        *m = TAKE_PTR(t);
        return 0;
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_bus_message, sd_bus_message, message_free);

_public_ int sd_bus_message_get_type(sd_bus_message *m, uint8_t *type) {
        assert_return(m, -EINVAL);
        assert_return(type, -EINVAL);

        *type = m->header->type;
        return 0;
}

_public_ int sd_bus_message_get_cookie(sd_bus_message *m, uint64_t *cookie) {
        uint64_t c;

        assert_return(m, -EINVAL);
        assert_return(cookie, -EINVAL);

        c = BUS_MESSAGE_COOKIE(m);
        if (c == 0)
                return -ENODATA;

        *cookie = BUS_MESSAGE_COOKIE(m);
        return 0;
}

_public_ int sd_bus_message_get_reply_cookie(sd_bus_message *m, uint64_t *cookie) {
        assert_return(m, -EINVAL);
        assert_return(cookie, -EINVAL);

        if (m->reply_cookie == 0)
                return -ENODATA;

        *cookie = m->reply_cookie;
        return 0;
}

_public_ int sd_bus_message_get_expect_reply(sd_bus_message *m) {
        assert_return(m, -EINVAL);

        return m->header->type == SD_BUS_MESSAGE_METHOD_CALL &&
                !(m->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED);
}

_public_ int sd_bus_message_get_auto_start(sd_bus_message *m) {
        assert_return(m, -EINVAL);

        return !(m->header->flags & BUS_MESSAGE_NO_AUTO_START);
}

_public_ int sd_bus_message_get_allow_interactive_authorization(sd_bus_message *m) {
        assert_return(m, -EINVAL);

        return m->header->type == SD_BUS_MESSAGE_METHOD_CALL &&
                (m->header->flags & BUS_MESSAGE_ALLOW_INTERACTIVE_AUTHORIZATION);
}

_public_ const char *sd_bus_message_get_path(sd_bus_message *m) {
        assert_return(m, NULL);

        return m->path;
}

_public_ const char *sd_bus_message_get_interface(sd_bus_message *m) {
        assert_return(m, NULL);

        return m->interface;
}

_public_ const char *sd_bus_message_get_member(sd_bus_message *m) {
        assert_return(m, NULL);

        return m->member;
}

_public_ const char *sd_bus_message_get_destination(sd_bus_message *m) {
        assert_return(m, NULL);

        return m->destination;
}

_public_ const char *sd_bus_message_get_sender(sd_bus_message *m) {
        assert_return(m, NULL);

        return m->sender;
}

_public_ const sd_bus_error *sd_bus_message_get_error(sd_bus_message *m) {
        assert_return(m, NULL);

        if (!sd_bus_error_is_set(&m->error))
                return NULL;

        return &m->error;
}

_public_ int sd_bus_message_get_monotonic_usec(sd_bus_message *m, uint64_t *usec) {
        assert_return(m, -EINVAL);
        assert_return(usec, -EINVAL);

        if (m->monotonic <= 0)
                return -ENODATA;

        *usec = m->monotonic;
        return 0;
}

_public_ int sd_bus_message_get_realtime_usec(sd_bus_message *m, uint64_t *usec) {
        assert_return(m, -EINVAL);
        assert_return(usec, -EINVAL);

        if (m->realtime <= 0)
                return -ENODATA;

        *usec = m->realtime;
        return 0;
}

_public_ int sd_bus_message_get_seqnum(sd_bus_message *m, uint64_t *seqnum) {
        assert_return(m, -EINVAL);
        assert_return(seqnum, -EINVAL);

        if (m->seqnum <= 0)
                return -ENODATA;

        *seqnum = m->seqnum;
        return 0;
}

_public_ sd_bus_creds *sd_bus_message_get_creds(sd_bus_message *m) {
        assert_return(m, NULL);

        if (m->creds.mask == 0)
                return NULL;

        return &m->creds;
}

_public_ int sd_bus_message_is_signal(
                sd_bus_message *m,
                const char *interface,
                const char *member) {

        assert_return(m, -EINVAL);

        if (m->header->type != SD_BUS_MESSAGE_SIGNAL)
                return 0;

        if (interface && !streq_ptr(m->interface, interface))
                return 0;

        if (member && !streq_ptr(m->member, member))
                return 0;

        return 1;
}

_public_ int sd_bus_message_is_method_call(
                sd_bus_message *m,
                const char *interface,
                const char *member) {

        assert_return(m, -EINVAL);

        if (m->header->type != SD_BUS_MESSAGE_METHOD_CALL)
                return 0;

        if (interface && !streq_ptr(m->interface, interface))
                return 0;

        if (member && !streq_ptr(m->member, member))
                return 0;

        return 1;
}

_public_ int sd_bus_message_is_method_error(sd_bus_message *m, const char *name) {
        assert_return(m, -EINVAL);

        if (m->header->type != SD_BUS_MESSAGE_METHOD_ERROR)
                return 0;

        if (name && !streq_ptr(m->error.name, name))
                return 0;

        return 1;
}

_public_ int sd_bus_message_set_expect_reply(sd_bus_message *m, int b) {
        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(m->header->type == SD_BUS_MESSAGE_METHOD_CALL, -EPERM);

        SET_FLAG(m->header->flags, BUS_MESSAGE_NO_REPLY_EXPECTED, !b);

        return 0;
}

_public_ int sd_bus_message_set_auto_start(sd_bus_message *m, int b) {
        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        SET_FLAG(m->header->flags, BUS_MESSAGE_NO_AUTO_START, !b);

        return 0;
}

_public_ int sd_bus_message_set_allow_interactive_authorization(sd_bus_message *m, int b) {
        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        SET_FLAG(m->header->flags, BUS_MESSAGE_ALLOW_INTERACTIVE_AUTHORIZATION, b);

        return 0;
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
        m->n_body_parts++;

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

        assert(m);
        assert(part);
        assert(!part->sealed);

        if (m->poisoned)
                return -ENOMEM;

        if (part->allocated == 0 || sz > part->allocated) {
                size_t new_allocated;

                new_allocated = sz > 0 ? 2 * sz : 64;
                n = realloc(part->data, new_allocated);
                if (!n) {
                        m->poisoned = true;
                        return -ENOMEM;
                }

                part->data = n;
                part->allocated = new_allocated;
                part->free_this = true;
        }

        if (q)
                *q = part->data ? (uint8_t*) part->data + part->size : NULL;

        part->size = sz;
        return 0;
}

static int message_add_offset(sd_bus_message *m, size_t offset) {
        struct bus_container *c;

        assert(m);
        assert(BUS_MESSAGE_IS_GVARIANT(m));

        /* Add offset to current container, unless this is the first
         * item in it, which will have the 0 offset, which we can
         * ignore. */
        c = message_get_last_container(m);

        if (!c->need_offsets)
                return 0;

        if (!GREEDY_REALLOC(c->offsets, c->offsets_allocated, c->n_offsets + 1))
                return -ENOMEM;

        c->offsets[c->n_offsets++] = offset;
        return 0;
}

static void message_extend_containers(sd_bus_message *m, size_t expand) {
        struct bus_container *c;

        assert(m);

        if (expand <= 0)
                return;

        /* Update counters */
        for (c = m->containers; c < m->containers + m->n_containers; c++) {

                if (c->array_size)
                        *c->array_size += expand;
        }
}

static void *message_extend_body(
                sd_bus_message *m,
                size_t align,
                size_t sz,
                bool add_offset,
                bool force_inline) {

        size_t start_body, end_body, padding, added;
        void *p;
        int r;

        assert(m);
        assert(align > 0);
        assert(!m->sealed);

        if (m->poisoned)
                return NULL;

        start_body = ALIGN_TO((size_t) m->body_size, align);
        end_body = start_body + sz;

        padding = start_body - m->body_size;
        added = padding + sz;

        /* Check for 32bit overflows */
        if (end_body > (size_t) ((uint32_t) -1) ||
            end_body < start_body) {
                m->poisoned = true;
                return NULL;
        }

        if (added > 0) {
                struct bus_body_part *part = NULL;
                bool add_new_part;

                add_new_part =
                        m->n_body_parts <= 0 ||
                        m->body_end->sealed ||
                        (padding != ALIGN_TO(m->body_end->size, align) - m->body_end->size) ||
                        (force_inline && m->body_end->size > MEMFD_MIN_SIZE);
                        /* If this must be an inlined extension, let's create a new part if
                         * the previous part is large enough to be inlined. */

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
                        size_t os, start_part, end_part;

                        part = m->body_end;
                        op = part->data;
                        os = part->size;

                        start_part = ALIGN_TO(part->size, align);
                        end_part = start_part + sz;

                        r = part_make_space(m, part, end_part, &p);
                        if (r < 0)
                                return NULL;

                        if (padding > 0) {
                                memzero(p, padding);
                                p = (uint8_t*) p + padding;
                        }

                        /* Readjust pointers */
                        for (c = m->containers; c < m->containers + m->n_containers; c++)
                                c->array_size = adjust_pointer(c->array_size, op, os, part->data);

                        m->error.message = (const char*) adjust_pointer(m->error.message, op, os, part->data);
                }
        } else
                /* Return something that is not NULL and is aligned */
                p = (uint8_t*) align;

        m->body_size = end_body;
        message_extend_containers(m, added);

        if (add_offset) {
                r = message_add_offset(m, end_body);
                if (r < 0) {
                        m->poisoned = true;
                        return NULL;
                }
        }

        return p;
}

static int message_push_fd(sd_bus_message *m, int fd) {
        int *f, copy;

        assert(m);

        if (fd < 0)
                return -EINVAL;

        if (!m->allow_fds)
                return -EOPNOTSUPP;

        copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (copy < 0)
                return -errno;

        f = reallocarray(m->fds, sizeof(int), m->n_fds + 1);
        if (!f) {
                m->poisoned = true;
                safe_close(copy);
                return -ENOMEM;
        }

        m->fds = f;
        m->fds[m->n_fds] = copy;
        m->free_fds = true;

        return copy;
}

int message_append_basic(sd_bus_message *m, char type, const void *p, const void **stored) {
        _cleanup_close_ int fd = -1;
        struct bus_container *c;
        ssize_t align, sz;
        void *a;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(bus_type_is_basic(type), -EINVAL);
        assert_return(!m->poisoned, -ESTALE);

        c = message_get_last_container(m);

        if (c->signature && c->signature[c->index]) {
                /* Container signature is already set */

                if (c->signature[c->index] != type)
                        return -ENXIO;
        } else {
                char *e;

                /* Maybe we can append to the signature? But only if this is the top-level container */
                if (c->enclosing != 0)
                        return -ENXIO;

                e = strextend(&c->signature, CHAR_TO_STR(type), NULL);
                if (!e) {
                        m->poisoned = true;
                        return -ENOMEM;
                }
        }

        if (BUS_MESSAGE_IS_GVARIANT(m)) {
                uint8_t u8;
                uint32_t u32;

                switch (type) {

                case SD_BUS_TYPE_SIGNATURE:
                case SD_BUS_TYPE_STRING:
                        p = strempty(p);

                        _fallthrough_;
                case SD_BUS_TYPE_OBJECT_PATH:
                        if (!p)
                                return -EINVAL;

                        align = 1;
                        sz = strlen(p) + 1;
                        break;

                case SD_BUS_TYPE_BOOLEAN:

                        u8 = p && *(int*) p;
                        p = &u8;

                        align = sz = 1;
                        break;

                case SD_BUS_TYPE_UNIX_FD:

                        if (!p)
                                return -EINVAL;

                        fd = message_push_fd(m, *(int*) p);
                        if (fd < 0)
                                return fd;

                        u32 = m->n_fds;
                        p = &u32;

                        align = sz = 4;
                        break;

                default:
                        align = bus_gvariant_get_alignment(CHAR_TO_STR(type));
                        sz = bus_gvariant_get_size(CHAR_TO_STR(type));
                        break;
                }

                assert(align > 0);
                assert(sz > 0);

                a = message_extend_body(m, align, sz, true, false);
                if (!a)
                        return -ENOMEM;

                memcpy(a, p, sz);

                if (stored)
                        *stored = (const uint8_t*) a;

        } else {
                uint32_t u32;

                switch (type) {

                case SD_BUS_TYPE_STRING:
                        /* To make things easy we'll serialize a NULL string
                         * into the empty string */
                        p = strempty(p);

                        _fallthrough_;
                case SD_BUS_TYPE_OBJECT_PATH:

                        if (!p)
                                return -EINVAL;

                        align = 4;
                        sz = 4 + strlen(p) + 1;
                        break;

                case SD_BUS_TYPE_SIGNATURE:

                        p = strempty(p);

                        align = 1;
                        sz = 1 + strlen(p) + 1;
                        break;

                case SD_BUS_TYPE_BOOLEAN:

                        u32 = p && *(int*) p;
                        p = &u32;

                        align = sz = 4;
                        break;

                case SD_BUS_TYPE_UNIX_FD:

                        if (!p)
                                return -EINVAL;

                        fd = message_push_fd(m, *(int*) p);
                        if (fd < 0)
                                return fd;

                        u32 = m->n_fds;
                        p = &u32;

                        align = sz = 4;
                        break;

                default:
                        align = bus_type_get_alignment(type);
                        sz = bus_type_get_size(type);
                        break;
                }

                assert(align > 0);
                assert(sz > 0);

                a = message_extend_body(m, align, sz, false, false);
                if (!a)
                        return -ENOMEM;

                if (IN_SET(type, SD_BUS_TYPE_STRING, SD_BUS_TYPE_OBJECT_PATH)) {
                        *(uint32_t*) a = sz - 5;
                        memcpy((uint8_t*) a + 4, p, sz - 4);

                        if (stored)
                                *stored = (const uint8_t*) a + 4;

                } else if (type == SD_BUS_TYPE_SIGNATURE) {
                        *(uint8_t*) a = sz - 2;
                        memcpy((uint8_t*) a + 1, p, sz - 1);

                        if (stored)
                                *stored = (const uint8_t*) a + 1;
                } else {
                        memcpy(a, p, sz);

                        if (stored)
                                *stored = a;
                }
        }

        if (type == SD_BUS_TYPE_UNIX_FD)
                m->n_fds++;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index++;

        fd = -1;
        return 0;
}

_public_ int sd_bus_message_append_basic(sd_bus_message *m, char type, const void *p) {
        return message_append_basic(m, type, p, NULL);
}

_public_ int sd_bus_message_append_string_space(
                sd_bus_message *m,
                size_t size,
                char **s) {

        struct bus_container *c;
        void *a;

        assert_return(m, -EINVAL);
        assert_return(s, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(!m->poisoned, -ESTALE);

        c = message_get_last_container(m);

        if (c->signature && c->signature[c->index]) {
                /* Container signature is already set */

                if (c->signature[c->index] != SD_BUS_TYPE_STRING)
                        return -ENXIO;
        } else {
                char *e;

                /* Maybe we can append to the signature? But only if this is the top-level container */
                if (c->enclosing != 0)
                        return -ENXIO;

                e = strextend(&c->signature, CHAR_TO_STR(SD_BUS_TYPE_STRING), NULL);
                if (!e) {
                        m->poisoned = true;
                        return -ENOMEM;
                }
        }

        if (BUS_MESSAGE_IS_GVARIANT(m)) {
                a = message_extend_body(m, 1, size + 1, true, false);
                if (!a)
                        return -ENOMEM;

                *s = a;
        } else {
                a = message_extend_body(m, 4, 4 + size + 1, false, false);
                if (!a)
                        return -ENOMEM;

                *(uint32_t*) a = size;
                *s = (char*) a + 4;
        }

        (*s)[size] = 0;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index++;

        return 0;
}

_public_ int sd_bus_message_append_string_iovec(
                sd_bus_message *m,
                const struct iovec *iov,
                unsigned n /* should be size_t, but is API now… 😞 */) {

        size_t size;
        unsigned i;
        char *p;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(iov || n == 0, -EINVAL);
        assert_return(!m->poisoned, -ESTALE);

        size = IOVEC_TOTAL_SIZE(iov, n);

        r = sd_bus_message_append_string_space(m, size, &p);
        if (r < 0)
                return r;

        for (i = 0; i < n; i++) {

                if (iov[i].iov_base)
                        memcpy(p, iov[i].iov_base, iov[i].iov_len);
                else
                        memset(p, ' ', iov[i].iov_len);

                p += iov[i].iov_len;
        }

        return 0;
}

static int bus_message_open_array(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents,
                uint32_t **array_size,
                size_t *begin,
                bool *need_offsets) {

        unsigned nindex;
        int alignment, r;

        assert(m);
        assert(c);
        assert(contents);
        assert(array_size);
        assert(begin);
        assert(need_offsets);

        if (!signature_is_single(contents, true))
                return -EINVAL;

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

        if (BUS_MESSAGE_IS_GVARIANT(m)) {
                alignment = bus_gvariant_get_alignment(contents);
                if (alignment < 0)
                        return alignment;

                /* Add alignment padding and add to offset list */
                if (!message_extend_body(m, alignment, 0, false, false))
                        return -ENOMEM;

                r = bus_gvariant_is_fixed_size(contents);
                if (r < 0)
                        return r;

                *begin = m->body_size;
                *need_offsets = r == 0;
        } else {
                void *a, *op;
                size_t os;
                struct bus_body_part *o;

                alignment = bus_type_get_alignment(contents[0]);
                if (alignment < 0)
                        return alignment;

                a = message_extend_body(m, 4, 4, false, false);
                if (!a)
                        return -ENOMEM;

                o = m->body_end;
                op = m->body_end->data;
                os = m->body_end->size;

                /* Add alignment between size and first element */
                if (!message_extend_body(m, alignment, 0, false, false))
                        return -ENOMEM;

                /* location of array size might have changed so let's readjust a */
                if (o == m->body_end)
                        a = adjust_pointer(a, op, os, m->body_end->data);

                *(uint32_t*) a = 0;
                *array_size = a;
        }

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index = nindex;

        return 0;
}

static int bus_message_open_variant(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents) {

        assert(m);
        assert(c);
        assert(contents);

        if (!signature_is_single(contents, false))
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

        if (BUS_MESSAGE_IS_GVARIANT(m)) {
                /* Variants are always aligned to 8 */

                if (!message_extend_body(m, 8, 0, false, false))
                        return -ENOMEM;

        } else {
                size_t l;
                void *a;

                l = strlen(contents);
                a = message_extend_body(m, 1, 1 + l + 1, false, false);
                if (!a)
                        return -ENOMEM;

                *(uint8_t*) a = l;
                memcpy((uint8_t*) a + 1, contents, l + 1);
        }

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index++;

        return 0;
}

static int bus_message_open_struct(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents,
                size_t *begin,
                bool *need_offsets) {

        size_t nindex;
        int r;

        assert(m);
        assert(c);
        assert(contents);
        assert(begin);
        assert(need_offsets);

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

        if (BUS_MESSAGE_IS_GVARIANT(m)) {
                int alignment;

                alignment = bus_gvariant_get_alignment(contents);
                if (alignment < 0)
                        return alignment;

                if (!message_extend_body(m, alignment, 0, false, false))
                        return -ENOMEM;

                r = bus_gvariant_is_fixed_size(contents);
                if (r < 0)
                        return r;

                *begin = m->body_size;
                *need_offsets = r == 0;
        } else {
                /* Align contents to 8 byte boundary */
                if (!message_extend_body(m, 8, 0, false, false))
                        return -ENOMEM;
        }

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index = nindex;

        return 0;
}

static int bus_message_open_dict_entry(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents,
                size_t *begin,
                bool *need_offsets) {

        int r;

        assert(m);
        assert(c);
        assert(contents);
        assert(begin);
        assert(need_offsets);

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
        } else
                return -ENXIO;

        if (BUS_MESSAGE_IS_GVARIANT(m)) {
                int alignment;

                alignment = bus_gvariant_get_alignment(contents);
                if (alignment < 0)
                        return alignment;

                if (!message_extend_body(m, alignment, 0, false, false))
                        return -ENOMEM;

                r = bus_gvariant_is_fixed_size(contents);
                if (r < 0)
                        return r;

                *begin = m->body_size;
                *need_offsets = r == 0;
        } else {
                /* Align contents to 8 byte boundary */
                if (!message_extend_body(m, 8, 0, false, false))
                        return -ENOMEM;
        }

        return 0;
}

_public_ int sd_bus_message_open_container(
                sd_bus_message *m,
                char type,
                const char *contents) {

        struct bus_container *c;
        uint32_t *array_size = NULL;
        _cleanup_free_ char *signature = NULL;
        size_t before, begin = 0;
        bool need_offsets = false;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(contents, -EINVAL);
        assert_return(!m->poisoned, -ESTALE);

        /* Make sure we have space for one more container */
        if (!GREEDY_REALLOC(m->containers, m->containers_allocated, m->n_containers + 1)) {
                m->poisoned = true;
                return -ENOMEM;
        }

        c = message_get_last_container(m);

        signature = strdup(contents);
        if (!signature) {
                m->poisoned = true;
                return -ENOMEM;
        }

        /* Save old index in the parent container, in case we have to
         * abort this container */
        c->saved_index = c->index;
        before = m->body_size;

        if (type == SD_BUS_TYPE_ARRAY)
                r = bus_message_open_array(m, c, contents, &array_size, &begin, &need_offsets);
        else if (type == SD_BUS_TYPE_VARIANT)
                r = bus_message_open_variant(m, c, contents);
        else if (type == SD_BUS_TYPE_STRUCT)
                r = bus_message_open_struct(m, c, contents, &begin, &need_offsets);
        else if (type == SD_BUS_TYPE_DICT_ENTRY)
                r = bus_message_open_dict_entry(m, c, contents, &begin, &need_offsets);
        else
                r = -EINVAL;
        if (r < 0)
                return r;

        /* OK, let's fill it in */
        m->containers[m->n_containers++] = (struct bus_container) {
                .enclosing = type,
                .signature = TAKE_PTR(signature),
                .array_size = array_size,
                .before = before,
                .begin = begin,
                .need_offsets = need_offsets,
        };

        return 0;
}

static int bus_message_close_array(sd_bus_message *m, struct bus_container *c) {

        assert(m);
        assert(c);

        if (!BUS_MESSAGE_IS_GVARIANT(m))
                return 0;

        if (c->need_offsets) {
                size_t payload, sz, i;
                uint8_t *a;

                /* Variable-width arrays */

                payload = c->n_offsets > 0 ? c->offsets[c->n_offsets-1] - c->begin : 0;
                sz = bus_gvariant_determine_word_size(payload, c->n_offsets);

                a = message_extend_body(m, 1, sz * c->n_offsets, true, false);
                if (!a)
                        return -ENOMEM;

                for (i = 0; i < c->n_offsets; i++)
                        bus_gvariant_write_word_le(a + sz*i, sz, c->offsets[i] - c->begin);
        } else {
                void *a;

                /* Fixed-width or empty arrays */

                a = message_extend_body(m, 1, 0, true, false); /* let's add offset to parent */
                if (!a)
                        return -ENOMEM;
        }

        return 0;
}

static int bus_message_close_variant(sd_bus_message *m, struct bus_container *c) {
        uint8_t *a;
        size_t l;

        assert(m);
        assert(c);
        assert(c->signature);

        if (!BUS_MESSAGE_IS_GVARIANT(m))
                return 0;

        l = strlen(c->signature);

        a = message_extend_body(m, 1, 1 + l, true, false);
        if (!a)
                return -ENOMEM;

        a[0] = 0;
        memcpy(a+1, c->signature, l);

        return 0;
}

static int bus_message_close_struct(sd_bus_message *m, struct bus_container *c, bool add_offset) {
        bool fixed_size = true;
        size_t n_variable = 0;
        unsigned i = 0;
        const char *p;
        uint8_t *a;
        int r;

        assert(m);
        assert(c);

        if (!BUS_MESSAGE_IS_GVARIANT(m))
                return 0;

        p = strempty(c->signature);
        while (*p != 0) {
                size_t n;

                r = signature_element_length(p, &n);
                if (r < 0)
                        return r;
                else {
                        char t[n+1];

                        memcpy(t, p, n);
                        t[n] = 0;

                        r = bus_gvariant_is_fixed_size(t);
                        if (r < 0)
                                return r;
                }

                assert(!c->need_offsets || i <= c->n_offsets);

                /* We need to add an offset for each item that has a
                 * variable size and that is not the last one in the
                 * list */
                if (r == 0)
                        fixed_size = false;
                if (r == 0 && p[n] != 0)
                        n_variable++;

                i++;
                p += n;
        }

        assert(!c->need_offsets || i == c->n_offsets);
        assert(c->need_offsets || n_variable == 0);

        if (isempty(c->signature)) {
                /* The unary type is encoded as fixed 1 byte padding */
                a = message_extend_body(m, 1, 1, add_offset, false);
                if (!a)
                        return -ENOMEM;

                *a = 0;
        } else if (n_variable <= 0) {
                int alignment = 1;

                /* Structures with fixed-size members only have to be
                 * fixed-size themselves. But gvariant requires all fixed-size
                 * elements to be sized a multiple of their alignment. Hence,
                 * we must *always* add final padding after the last member so
                 * the overall size of the structure is properly aligned. */
                if (fixed_size)
                        alignment = bus_gvariant_get_alignment(strempty(c->signature));

                assert(alignment > 0);

                a = message_extend_body(m, alignment, 0, add_offset, false);
                if (!a)
                        return -ENOMEM;
        } else {
                size_t sz;
                unsigned j;

                assert(c->offsets[c->n_offsets-1] == m->body_size);

                sz = bus_gvariant_determine_word_size(m->body_size - c->begin, n_variable);

                a = message_extend_body(m, 1, sz * n_variable, add_offset, false);
                if (!a)
                        return -ENOMEM;

                p = strempty(c->signature);
                for (i = 0, j = 0; i < c->n_offsets; i++) {
                        unsigned k;
                        size_t n;

                        r = signature_element_length(p, &n);
                        if (r < 0)
                                return r;
                        else {
                                char t[n+1];

                                memcpy(t, p, n);
                                t[n] = 0;

                                p += n;

                                r = bus_gvariant_is_fixed_size(t);
                                if (r < 0)
                                        return r;
                                if (r > 0 || p[0] == 0)
                                        continue;
                        }

                        k = n_variable - 1 - j;

                        bus_gvariant_write_word_le(a + k * sz, sz, c->offsets[i] - c->begin);

                        j++;
                }
        }

        return 0;
}

_public_ int sd_bus_message_close_container(sd_bus_message *m) {
        struct bus_container *c;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(m->n_containers > 0, -EINVAL);
        assert_return(!m->poisoned, -ESTALE);

        c = message_get_last_container(m);

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                if (c->signature && c->signature[c->index] != 0)
                        return -EINVAL;

        m->n_containers--;

        if (c->enclosing == SD_BUS_TYPE_ARRAY)
                r = bus_message_close_array(m, c);
        else if (c->enclosing == SD_BUS_TYPE_VARIANT)
                r = bus_message_close_variant(m, c);
        else if (IN_SET(c->enclosing, SD_BUS_TYPE_STRUCT, SD_BUS_TYPE_DICT_ENTRY))
                r = bus_message_close_struct(m, c, true);
        else
                assert_not_reached("Unknown container type");

        free(c->signature);
        free(c->offsets);

        return r;
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

_public_ int sd_bus_message_appendv(
                sd_bus_message *m,
                const char *types,
                va_list ap) {

        unsigned n_array, n_struct;
        TypeStack stack[BUS_CONTAINER_DEPTH];
        unsigned stack_ptr = 0;
        int r;

        assert_return(m, -EINVAL);
        assert_return(types, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(!m->poisoned, -ESTALE);

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
                        n_array--;
                else {
                        types++;
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
                case SD_BUS_TYPE_UINT64: {
                        uint64_t x;

                        x = va_arg(ap, uint64_t);
                        r = sd_bus_message_append_basic(m, *t, &x);
                        break;
                }

                case SD_BUS_TYPE_DOUBLE: {
                        double x;

                        x = va_arg(ap, double);
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

        return 1;
}

_public_ int sd_bus_message_append(sd_bus_message *m, const char *types, ...) {
        va_list ap;
        int r;

        va_start(ap, types);
        r = sd_bus_message_appendv(m, types, ap);
        va_end(ap);

        return r;
}

_public_ int sd_bus_message_append_array_space(
                sd_bus_message *m,
                char type,
                size_t size,
                void **ptr) {

        ssize_t align, sz;
        void *a;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(bus_type_is_trivial(type) && type != SD_BUS_TYPE_BOOLEAN, -EINVAL);
        assert_return(ptr || size == 0, -EINVAL);
        assert_return(!m->poisoned, -ESTALE);

        /* alignment and size of the trivial types (except bool) is
         * identical for gvariant and dbus1 marshalling */
        align = bus_type_get_alignment(type);
        sz = bus_type_get_size(type);

        assert_se(align > 0);
        assert_se(sz > 0);

        if (size % sz != 0)
                return -EINVAL;

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_ARRAY, CHAR_TO_STR(type));
        if (r < 0)
                return r;

        a = message_extend_body(m, align, size, false, false);
        if (!a)
                return -ENOMEM;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        *ptr = a;
        return 0;
}

_public_ int sd_bus_message_append_array(
                sd_bus_message *m,
                char type,
                const void *ptr,
                size_t size) {
        int r;
        void *p;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(bus_type_is_trivial(type), -EINVAL);
        assert_return(ptr || size == 0, -EINVAL);
        assert_return(!m->poisoned, -ESTALE);

        r = sd_bus_message_append_array_space(m, type, size, &p);
        if (r < 0)
                return r;

        memcpy_safe(p, ptr, size);

        return 0;
}

_public_ int sd_bus_message_append_array_iovec(
                sd_bus_message *m,
                char type,
                const struct iovec *iov,
                unsigned n /* should be size_t, but is API now… 😞 */) {

        size_t size;
        unsigned i;
        void *p;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(bus_type_is_trivial(type), -EINVAL);
        assert_return(iov || n == 0, -EINVAL);
        assert_return(!m->poisoned, -ESTALE);

        size = IOVEC_TOTAL_SIZE(iov, n);

        r = sd_bus_message_append_array_space(m, type, size, &p);
        if (r < 0)
                return r;

        for (i = 0; i < n; i++) {

                if (iov[i].iov_base)
                        memcpy(p, iov[i].iov_base, iov[i].iov_len);
                else
                        memzero(p, iov[i].iov_len);

                p = (uint8_t*) p + iov[i].iov_len;
        }

        return 0;
}

_public_ int sd_bus_message_append_array_memfd(
                sd_bus_message *m,
                char type,
                int memfd,
                uint64_t offset,
                uint64_t size) {

        _cleanup_close_ int copy_fd = -1;
        struct bus_body_part *part;
        ssize_t align, sz;
        uint64_t real_size;
        void *a;
        int r;

        assert_return(m, -EINVAL);
        assert_return(memfd >= 0, -EBADF);
        assert_return(bus_type_is_trivial(type), -EINVAL);
        assert_return(size > 0, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(!m->poisoned, -ESTALE);

        r = memfd_set_sealed(memfd);
        if (r < 0)
                return r;

        copy_fd = fcntl(memfd, F_DUPFD_CLOEXEC, 3);
        if (copy_fd < 0)
                return copy_fd;

        r = memfd_get_size(memfd, &real_size);
        if (r < 0)
                return r;

        if (offset == 0 && size == (uint64_t) -1)
                size = real_size;
        else if (offset + size > real_size)
                return -EMSGSIZE;

        align = bus_type_get_alignment(type);
        sz = bus_type_get_size(type);

        assert_se(align > 0);
        assert_se(sz > 0);

        if (offset % align != 0)
                return -EINVAL;

        if (size % sz != 0)
                return -EINVAL;

        if (size > (uint64_t) (uint32_t) -1)
                return -EINVAL;

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_ARRAY, CHAR_TO_STR(type));
        if (r < 0)
                return r;

        a = message_extend_body(m, align, 0, false, false);
        if (!a)
                return -ENOMEM;

        part = message_append_part(m);
        if (!part)
                return -ENOMEM;

        part->memfd = copy_fd;
        part->memfd_offset = offset;
        part->sealed = true;
        part->size = size;
        copy_fd = -1;

        m->body_size += size;
        message_extend_containers(m, size);

        return sd_bus_message_close_container(m);
}

_public_ int sd_bus_message_append_string_memfd(
                sd_bus_message *m,
                int memfd,
                uint64_t offset,
                uint64_t size) {

        _cleanup_close_ int copy_fd = -1;
        struct bus_body_part *part;
        struct bus_container *c;
        uint64_t real_size;
        void *a;
        int r;

        assert_return(m, -EINVAL);
        assert_return(memfd >= 0, -EBADF);
        assert_return(size > 0, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(!m->poisoned, -ESTALE);

        r = memfd_set_sealed(memfd);
        if (r < 0)
                return r;

        copy_fd = fcntl(memfd, FD_CLOEXEC, 3);
        if (copy_fd < 0)
                return copy_fd;

        r = memfd_get_size(memfd, &real_size);
        if (r < 0)
                return r;

        if (offset == 0 && size == (uint64_t) -1)
                size = real_size;
        else if (offset + size > real_size)
                return -EMSGSIZE;

        /* We require this to be NUL terminated */
        if (size == 0)
                return -EINVAL;

        if (size > (uint64_t) (uint32_t) -1)
                return -EINVAL;

        c = message_get_last_container(m);
        if (c->signature && c->signature[c->index]) {
                /* Container signature is already set */

                if (c->signature[c->index] != SD_BUS_TYPE_STRING)
                        return -ENXIO;
        } else {
                char *e;

                /* Maybe we can append to the signature? But only if this is the top-level container */
                if (c->enclosing != 0)
                        return -ENXIO;

                e = strextend(&c->signature, CHAR_TO_STR(SD_BUS_TYPE_STRING), NULL);
                if (!e) {
                        m->poisoned = true;
                        return -ENOMEM;
                }
        }

        if (!BUS_MESSAGE_IS_GVARIANT(m)) {
                a = message_extend_body(m, 4, 4, false, false);
                if (!a)
                        return -ENOMEM;

                *(uint32_t*) a = size - 1;
        }

        part = message_append_part(m);
        if (!part)
                return -ENOMEM;

        part->memfd = copy_fd;
        part->memfd_offset = offset;
        part->sealed = true;
        part->size = size;
        copy_fd = -1;

        m->body_size += size;
        message_extend_containers(m, size);

        if (BUS_MESSAGE_IS_GVARIANT(m)) {
                r = message_add_offset(m, m->body_size);
                if (r < 0) {
                        m->poisoned = true;
                        return -ENOMEM;
                }
        }

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index++;

        return 0;
}

_public_ int sd_bus_message_append_strv(sd_bus_message *m, char **l) {
        char **i;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(!m->poisoned, -ESTALE);

        r = sd_bus_message_open_container(m, 'a', "s");
        if (r < 0)
                return r;

        STRV_FOREACH(i, l) {
                r = sd_bus_message_append_basic(m, 's', *i);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(m);
}

static int bus_message_close_header(sd_bus_message *m) {

        assert(m);

        /* The actual user data is finished now, we just complete the
           variant and struct now (at least on gvariant). Remember
           this position, so that during parsing we know where to
           put the outer container end. */
        m->user_body_size = m->body_size;

        if (BUS_MESSAGE_IS_GVARIANT(m)) {
                const char *signature;
                size_t sz, l;
                void *d;

                /* Add offset table to end of fields array */
                if (m->n_header_offsets >= 1) {
                        uint8_t *a;
                        unsigned i;

                        assert(m->fields_size == m->header_offsets[m->n_header_offsets-1]);

                        sz = bus_gvariant_determine_word_size(m->fields_size, m->n_header_offsets);
                        a = message_extend_fields(m, 1, sz * m->n_header_offsets, false);
                        if (!a)
                                return -ENOMEM;

                        for (i = 0; i < m->n_header_offsets; i++)
                                bus_gvariant_write_word_le(a + sz*i, sz, m->header_offsets[i]);
                }

                /* Add gvariant NUL byte plus signature to the end of
                 * the body, followed by the final offset pointing to
                 * the end of the fields array */

                signature = strempty(m->root_container.signature);
                l = strlen(signature);

                sz = bus_gvariant_determine_word_size(sizeof(struct bus_header) + ALIGN8(m->fields_size) + m->body_size + 1 + l + 2, 1);
                d = message_extend_body(m, 1, 1 + l + 2 + sz, false, true);
                if (!d)
                        return -ENOMEM;

                *(uint8_t*) d = 0;
                *((uint8_t*) d + 1) = SD_BUS_TYPE_STRUCT_BEGIN;
                memcpy((uint8_t*) d + 2, signature, l);
                *((uint8_t*) d + 1 + l + 1) = SD_BUS_TYPE_STRUCT_END;

                bus_gvariant_write_word_le((uint8_t*) d + 1 + l + 2, sz, sizeof(struct bus_header) + m->fields_size);

                m->footer = d;
                m->footer_accessible = 1 + l + 2 + sz;
        } else {
                m->header->dbus1.fields_size = m->fields_size;
                m->header->dbus1.body_size = m->body_size;
        }

        return 0;
}

_public_ int sd_bus_message_seal(sd_bus_message *m, uint64_t cookie, uint64_t timeout_usec) {
        struct bus_body_part *part;
        size_t a;
        unsigned i;
        int r;

        assert_return(m, -EINVAL);

        if (m->sealed)
                return -EPERM;

        if (m->n_containers > 0)
                return -EBADMSG;

        if (m->poisoned)
                return -ESTALE;

        if (cookie > 0xffffffffULL &&
            !BUS_MESSAGE_IS_GVARIANT(m))
                return -EOPNOTSUPP;

        /* In vtables the return signature of method calls is listed,
         * let's check if they match if this is a response */
        if (m->header->type == SD_BUS_MESSAGE_METHOD_RETURN &&
            m->enforced_reply_signature &&
            !streq(strempty(m->root_container.signature), m->enforced_reply_signature))
                return -ENOMSG;

        /* If gvariant marshalling is used we need to close the body structure */
        r = bus_message_close_struct(m, &m->root_container, false);
        if (r < 0)
                return r;

        /* If there's a non-trivial signature set, then add it in
         * here, but only on dbus1 */
        if (!isempty(m->root_container.signature) && !BUS_MESSAGE_IS_GVARIANT(m)) {
                r = message_append_field_signature(m, BUS_MESSAGE_HEADER_SIGNATURE, m->root_container.signature, NULL);
                if (r < 0)
                        return r;
        }

        if (m->n_fds > 0) {
                r = message_append_field_uint32(m, BUS_MESSAGE_HEADER_UNIX_FDS, m->n_fds);
                if (r < 0)
                        return r;
        }

        r = bus_message_close_header(m);
        if (r < 0)
                return r;

        if (BUS_MESSAGE_IS_GVARIANT(m))
                m->header->dbus2.cookie = cookie;
        else
                m->header->dbus1.serial = (uint32_t) cookie;

        m->timeout = m->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED ? 0 : timeout_usec;

        /* Add padding at the end of the fields part, since we know
         * the body needs to start at an 8 byte alignment. We made
         * sure we allocated enough space for this, so all we need to
         * do here is to zero it out. */
        a = ALIGN8(m->fields_size) - m->fields_size;
        if (a > 0)
                memzero((uint8_t*) BUS_MESSAGE_FIELDS(m) + m->fields_size, a);

        /* If this is something we can send as memfd, then let's seal
        the memfd now. Note that we can send memfds as payload only
        for directed messages, and not for broadcasts. */
        if (m->destination && m->bus->use_memfd) {
                MESSAGE_FOREACH_PART(part, i, m)
                        if (part->memfd >= 0 &&
                            !part->sealed &&
                            (part->size > MEMFD_MIN_SIZE || m->bus->use_memfd < 0) &&
                            part != m->body_end) { /* The last part may never be sent as memfd */
                                uint64_t sz;

                                /* Try to seal it if that makes
                                 * sense. First, unmap our own map to
                                 * make sure we don't keep it busy. */
                                bus_body_part_unmap(part);

                                /* Then, sync up real memfd size */
                                sz = part->size;
                                r = memfd_set_size(part->memfd, sz);
                                if (r < 0)
                                        return r;

                                /* Finally, try to seal */
                                if (memfd_set_sealed(part->memfd) >= 0)
                                        part->sealed = true;
                        }
        }

        m->root_container.end = m->user_body_size;
        m->root_container.index = 0;
        m->root_container.offset_index = 0;
        m->root_container.item_size = m->root_container.n_offsets > 0 ? m->root_container.offsets[0] : 0;

        m->sealed = true;

        return 0;
}

int bus_body_part_map(struct bus_body_part *part) {
        void *p;
        size_t psz, shift;

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

        shift = part->memfd_offset - ((part->memfd_offset / page_size()) * page_size());
        psz = PAGE_ALIGN(part->size + shift);

        if (part->memfd >= 0)
                p = mmap(NULL, psz, PROT_READ, MAP_PRIVATE, part->memfd, part->memfd_offset - shift);
        else if (part->is_zero)
                p = mmap(NULL, psz, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        else
                return -EINVAL;

        if (p == MAP_FAILED)
                return -errno;

        part->mapped = psz;
        part->mmap_begin = p;
        part->data = (uint8_t*) p + shift;
        part->munmap_this = true;

        return 0;
}

void bus_body_part_unmap(struct bus_body_part *part) {

        assert_se(part);

        if (part->memfd < 0)
                return;

        if (!part->mmap_begin)
                return;

        if (!part->munmap_this)
                return;

        assert_se(munmap(part->mmap_begin, part->mapped) == 0);

        part->mmap_begin = NULL;
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

static bool message_end_of_signature(sd_bus_message *m) {
        struct bus_container *c;

        assert(m);

        c = message_get_last_container(m);
        return !c->signature || c->signature[c->index] == 0;
}

static bool message_end_of_array(sd_bus_message *m, size_t index) {
        struct bus_container *c;

        assert(m);

        c = message_get_last_container(m);
        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                return false;

        if (BUS_MESSAGE_IS_GVARIANT(m))
                return index >= c->end;
        else {
                assert(c->array_size);
                return index >= c->begin + BUS_MESSAGE_BSWAP32(m, *c->array_size);
        }
}

_public_ int sd_bus_message_at_end(sd_bus_message *m, int complete) {
        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);

        if (complete && m->n_containers > 0)
                return false;

        if (message_end_of_signature(m))
                return true;

        if (message_end_of_array(m, m->rindex))
                return true;

        return false;
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

static int container_next_item(sd_bus_message *m, struct bus_container *c, size_t *rindex) {
        int r;

        assert(m);
        assert(c);
        assert(rindex);

        if (!BUS_MESSAGE_IS_GVARIANT(m))
                return 0;

        if (c->enclosing == SD_BUS_TYPE_ARRAY) {
                int sz;

                sz = bus_gvariant_get_size(c->signature);
                if (sz < 0) {
                        int alignment;

                        if (c->offset_index+1 >= c->n_offsets)
                                goto end;

                        /* Variable-size array */

                        alignment = bus_gvariant_get_alignment(c->signature);
                        assert(alignment > 0);

                        *rindex = ALIGN_TO(c->offsets[c->offset_index], alignment);
                        assert(c->offsets[c->offset_index+1] >= *rindex);
                        c->item_size = c->offsets[c->offset_index+1] - *rindex;
                } else {

                        if (c->offset_index+1 >= (c->end-c->begin)/sz)
                                goto end;

                        /* Fixed-size array */
                        *rindex = c->begin + (c->offset_index+1) * sz;
                        c->item_size = sz;
                }

                c->offset_index++;

        } else if (IN_SET(c->enclosing, 0, SD_BUS_TYPE_STRUCT, SD_BUS_TYPE_DICT_ENTRY)) {

                int alignment;
                size_t n, j;

                if (c->offset_index+1 >= c->n_offsets)
                        goto end;

                r = signature_element_length(c->signature + c->index, &n);
                if (r < 0)
                        return r;

                r = signature_element_length(c->signature + c->index + n, &j);
                if (r < 0)
                        return r;
                else {
                        char t[j+1];
                        memcpy(t, c->signature + c->index + n, j);
                        t[j] = 0;

                        alignment = bus_gvariant_get_alignment(t);
                }

                assert(alignment > 0);

                *rindex = ALIGN_TO(c->offsets[c->offset_index], alignment);
                assert(c->offsets[c->offset_index+1] >= *rindex);
                c->item_size = c->offsets[c->offset_index+1] - *rindex;

                c->offset_index++;

        } else if (c->enclosing == SD_BUS_TYPE_VARIANT)
                goto end;
        else
                assert_not_reached("Unknown container type");

        return 0;

end:
        /* Reached the end */
        *rindex = c->end;
        c->item_size = 0;
        return 0;
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

        start = ALIGN_TO((size_t) *rindex, align);
        padding = start - *rindex;
        end = start + nbytes;

        if (end > m->user_body_size)
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
        if (!part || (nbytes > 0 && !q))
                return -EBADMSG;

        *rindex = end;

        if (ret)
                *ret = q;

        return 0;
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

_public_ int sd_bus_message_read_basic(sd_bus_message *m, char type, void *p) {
        struct bus_container *c;
        size_t rindex;
        void *q;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);
        assert_return(bus_type_is_basic(type), -EINVAL);

        if (message_end_of_signature(m))
                return -ENXIO;

        if (message_end_of_array(m, m->rindex))
                return 0;

        c = message_get_last_container(m);
        if (c->signature[c->index] != type)
                return -ENXIO;

        rindex = m->rindex;

        if (BUS_MESSAGE_IS_GVARIANT(m)) {

                if (IN_SET(type, SD_BUS_TYPE_STRING, SD_BUS_TYPE_OBJECT_PATH, SD_BUS_TYPE_SIGNATURE)) {
                        bool ok;

                        /* D-Bus spec: The marshalling formats for the string-like types all end
                         * with a single zero (NUL) byte, but that byte is not considered to be part
                         * of the text. */
                        if (c->item_size == 0)
                                return -EBADMSG;

                        r = message_peek_body(m, &rindex, 1, c->item_size, &q);
                        if (r < 0)
                                return r;

                        if (type == SD_BUS_TYPE_STRING)
                                ok = validate_string(q, c->item_size-1);
                        else if (type == SD_BUS_TYPE_OBJECT_PATH)
                                ok = validate_object_path(q, c->item_size-1);
                        else
                                ok = validate_signature(q, c->item_size-1);

                        if (!ok)
                                return -EBADMSG;

                        if (p)
                                *(const char**) p = q;
                } else {
                        int sz, align;

                        sz = bus_gvariant_get_size(CHAR_TO_STR(type));
                        assert(sz > 0);
                        if ((size_t) sz != c->item_size)
                                return -EBADMSG;

                        align = bus_gvariant_get_alignment(CHAR_TO_STR(type));
                        assert(align > 0);

                        r = message_peek_body(m, &rindex, align, c->item_size, &q);
                        if (r < 0)
                                return r;

                        switch (type) {

                        case SD_BUS_TYPE_BYTE:
                                if (p)
                                        *(uint8_t*) p = *(uint8_t*) q;
                                break;

                        case SD_BUS_TYPE_BOOLEAN:
                                if (p)
                                        *(int*) p = !!*(uint8_t*) q;
                                break;

                        case SD_BUS_TYPE_INT16:
                        case SD_BUS_TYPE_UINT16:
                                if (p)
                                        *(uint16_t*) p = BUS_MESSAGE_BSWAP16(m, *(uint16_t*) q);
                                break;

                        case SD_BUS_TYPE_INT32:
                        case SD_BUS_TYPE_UINT32:
                                if (p)
                                        *(uint32_t*) p = BUS_MESSAGE_BSWAP32(m, *(uint32_t*) q);
                                break;

                        case SD_BUS_TYPE_INT64:
                        case SD_BUS_TYPE_UINT64:
                        case SD_BUS_TYPE_DOUBLE:
                                if (p)
                                        *(uint64_t*) p = BUS_MESSAGE_BSWAP64(m, *(uint64_t*) q);
                                break;

                        case SD_BUS_TYPE_UNIX_FD: {
                                uint32_t j;

                                j = BUS_MESSAGE_BSWAP32(m, *(uint32_t*) q);
                                if (j >= m->n_fds)
                                        return -EBADMSG;

                                if (p)
                                        *(int*) p = m->fds[j];

                                break;
                        }

                        default:
                                assert_not_reached("unexpected type");
                        }
                }

                r = container_next_item(m, c, &rindex);
                if (r < 0)
                        return r;
        } else {

                if (IN_SET(type, SD_BUS_TYPE_STRING, SD_BUS_TYPE_OBJECT_PATH)) {
                        uint32_t l;
                        bool ok;

                        r = message_peek_body(m, &rindex, 4, 4, &q);
                        if (r < 0)
                                return r;

                        l = BUS_MESSAGE_BSWAP32(m, *(uint32_t*) q);
                        if (l == UINT32_MAX)
                                /* avoid overflow right below */
                                return -EBADMSG;

                        r = message_peek_body(m, &rindex, 1, l+1, &q);
                        if (r < 0)
                                return r;

                        if (type == SD_BUS_TYPE_OBJECT_PATH)
                                ok = validate_object_path(q, l);
                        else
                                ok = validate_string(q, l);
                        if (!ok)
                                return -EBADMSG;

                        if (p)
                                *(const char**) p = q;

                } else if (type == SD_BUS_TYPE_SIGNATURE) {
                        uint8_t l;

                        r = message_peek_body(m, &rindex, 1, 1, &q);
                        if (r < 0)
                                return r;

                        l = *(uint8_t*) q;
                        if (l == UINT8_MAX)
                                /* avoid overflow right below */
                                return -EBADMSG;

                        r = message_peek_body(m, &rindex, 1, l+1, &q);
                        if (r < 0)
                                return r;

                        if (!validate_signature(q, l))
                                return -EBADMSG;

                        if (p)
                                *(const char**) p = q;

                } else {
                        ssize_t sz, align;

                        align = bus_type_get_alignment(type);
                        assert(align > 0);

                        sz = bus_type_get_size(type);
                        assert(sz > 0);

                        r = message_peek_body(m, &rindex, align, sz, &q);
                        if (r < 0)
                                return r;

                        switch (type) {

                        case SD_BUS_TYPE_BYTE:
                                if (p)
                                        *(uint8_t*) p = *(uint8_t*) q;
                                break;

                        case SD_BUS_TYPE_BOOLEAN:
                                if (p)
                                        *(int*) p = !!*(uint32_t*) q;
                                break;

                        case SD_BUS_TYPE_INT16:
                        case SD_BUS_TYPE_UINT16:
                                if (p)
                                        *(uint16_t*) p = BUS_MESSAGE_BSWAP16(m, *(uint16_t*) q);
                                break;

                        case SD_BUS_TYPE_INT32:
                        case SD_BUS_TYPE_UINT32:
                                if (p)
                                        *(uint32_t*) p = BUS_MESSAGE_BSWAP32(m, *(uint32_t*) q);
                                break;

                        case SD_BUS_TYPE_INT64:
                        case SD_BUS_TYPE_UINT64:
                        case SD_BUS_TYPE_DOUBLE:
                                if (p)
                                        *(uint64_t*) p = BUS_MESSAGE_BSWAP64(m, *(uint64_t*) q);
                                break;

                        case SD_BUS_TYPE_UNIX_FD: {
                                uint32_t j;

                                j = BUS_MESSAGE_BSWAP32(m, *(uint32_t*) q);
                                if (j >= m->n_fds)
                                        return -EBADMSG;

                                if (p)
                                        *(int*) p = m->fds[j];
                                break;
                        }

                        default:
                                assert_not_reached("Unknown basic type...");
                        }
                }
        }

        m->rindex = rindex;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index++;

        return 1;
}

static int bus_message_enter_array(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents,
                uint32_t **array_size,
                size_t *item_size,
                size_t **offsets,
                size_t *n_offsets) {

        size_t rindex;
        void *q;
        int r;

        assert(m);
        assert(c);
        assert(contents);
        assert(array_size);
        assert(item_size);
        assert(offsets);
        assert(n_offsets);

        if (!signature_is_single(contents, true))
                return -EINVAL;

        if (!c->signature || c->signature[c->index] == 0)
                return -ENXIO;

        if (c->signature[c->index] != SD_BUS_TYPE_ARRAY)
                return -ENXIO;

        if (!startswith(c->signature + c->index + 1, contents))
                return -ENXIO;

        rindex = m->rindex;

        if (!BUS_MESSAGE_IS_GVARIANT(m)) {
                /* dbus1 */
                int alignment;

                r = message_peek_body(m, &rindex, 4, 4, &q);
                if (r < 0)
                        return r;

                if (BUS_MESSAGE_BSWAP32(m, *(uint32_t*) q) > BUS_ARRAY_MAX_SIZE)
                        return -EBADMSG;

                alignment = bus_type_get_alignment(contents[0]);
                if (alignment < 0)
                        return alignment;

                r = message_peek_body(m, &rindex, alignment, 0, NULL);
                if (r < 0)
                        return r;

                *array_size = (uint32_t*) q;

        } else if (c->item_size <= 0) {

                /* gvariant: empty array */
                *item_size = 0;
                *offsets = NULL;
                *n_offsets = 0;

        } else if (bus_gvariant_is_fixed_size(contents)) {

                /* gvariant: fixed length array */
                *item_size = bus_gvariant_get_size(contents);
                *offsets = NULL;
                *n_offsets = 0;

        } else {
                size_t where, previous = 0, framing, sz;
                int alignment;
                unsigned i;

                /* gvariant: variable length array */
                sz = bus_gvariant_determine_word_size(c->item_size, 0);

                where = rindex + c->item_size - sz;
                r = message_peek_body(m, &where, 1, sz, &q);
                if (r < 0)
                        return r;

                framing = bus_gvariant_read_word_le(q, sz);
                if (framing > c->item_size - sz)
                        return -EBADMSG;
                if ((c->item_size - framing) % sz != 0)
                        return -EBADMSG;

                *n_offsets = (c->item_size - framing) / sz;

                where = rindex + framing;
                r = message_peek_body(m, &where, 1, *n_offsets * sz, &q);
                if (r < 0)
                        return r;

                *offsets = new(size_t, *n_offsets);
                if (!*offsets)
                        return -ENOMEM;

                alignment = bus_gvariant_get_alignment(c->signature);
                assert(alignment > 0);

                for (i = 0; i < *n_offsets; i++) {
                        size_t x, start;

                        start = ALIGN_TO(previous, alignment);

                        x = bus_gvariant_read_word_le((uint8_t*) q + i * sz, sz);
                        if (x > c->item_size - sz)
                                return -EBADMSG;
                        if (x < start)
                                return -EBADMSG;

                        (*offsets)[i] = rindex + x;
                        previous = x;
                }

                *item_size = (*offsets)[0] - rindex;
        }

        m->rindex = rindex;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index += 1 + strlen(contents);

        return 1;
}

static int bus_message_enter_variant(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents,
                size_t *item_size) {

        size_t rindex;
        uint8_t l;
        void *q;
        int r;

        assert(m);
        assert(c);
        assert(contents);
        assert(item_size);

        if (!signature_is_single(contents, false))
                return -EINVAL;

        if (*contents == SD_BUS_TYPE_DICT_ENTRY_BEGIN)
                return -EINVAL;

        if (!c->signature || c->signature[c->index] == 0)
                return -ENXIO;

        if (c->signature[c->index] != SD_BUS_TYPE_VARIANT)
                return -ENXIO;

        rindex = m->rindex;

        if (BUS_MESSAGE_IS_GVARIANT(m)) {
                size_t k, where;

                k = strlen(contents);
                if (1+k > c->item_size)
                        return -EBADMSG;

                where = rindex + c->item_size - (1+k);
                r = message_peek_body(m, &where, 1, 1+k, &q);
                if (r < 0)
                        return r;

                if (*(char*) q != 0)
                        return -EBADMSG;

                if (memcmp((uint8_t*) q+1, contents, k))
                        return -ENXIO;

                *item_size = c->item_size - (1+k);

        } else {
                r = message_peek_body(m, &rindex, 1, 1, &q);
                if (r < 0)
                        return r;

                l = *(uint8_t*) q;
                if (l == UINT8_MAX)
                        /* avoid overflow right below */
                        return -EBADMSG;

                r = message_peek_body(m, &rindex, 1, l+1, &q);
                if (r < 0)
                        return r;

                if (!validate_signature(q, l))
                        return -EBADMSG;

                if (!streq(q, contents))
                        return -ENXIO;
        }

        m->rindex = rindex;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index++;

        return 1;
}

static int build_struct_offsets(
                sd_bus_message *m,
                const char *signature,
                size_t size,
                size_t *item_size,
                size_t **offsets,
                size_t *n_offsets) {

        unsigned n_variable = 0, n_total = 0, v;
        size_t previous, where;
        const char *p;
        size_t sz;
        void *q;
        int r;

        assert(m);
        assert(item_size);
        assert(offsets);
        assert(n_offsets);

        if (isempty(signature)) {
                /* Unary type is encoded as *fixed* 1 byte padding */
                r = message_peek_body(m, &m->rindex, 1, 1, &q);
                if (r < 0)
                        return r;

                if (*(uint8_t *) q != 0)
                        return -EBADMSG;

                *item_size = 0;
                *offsets = NULL;
                *n_offsets = 0;
                return 0;
        }

        sz = bus_gvariant_determine_word_size(size, 0);
        if (sz <= 0)
                return -EBADMSG;

        /* First, loop over signature and count variable elements and
         * elements in general. We use this to know how large the
         * offset array is at the end of the structure. Note that
         * GVariant only stores offsets for all variable size elements
         * that are not the last item. */

        p = signature;
        while (*p != 0) {
                size_t n;

                r = signature_element_length(p, &n);
                if (r < 0)
                        return r;
                else {
                        char t[n+1];

                        memcpy(t, p, n);
                        t[n] = 0;

                        r = bus_gvariant_is_fixed_size(t);
                }

                if (r < 0)
                        return r;
                if (r == 0 && p[n] != 0) /* except the last item */
                        n_variable++;
                n_total++;

                p += n;
        }

        if (size < n_variable * sz)
                return -EBADMSG;

        where = m->rindex + size - (n_variable * sz);
        r = message_peek_body(m, &where, 1, n_variable * sz, &q);
        if (r < 0)
                return r;

        v = n_variable;

        *offsets = new(size_t, n_total);
        if (!*offsets)
                return -ENOMEM;

        *n_offsets = 0;

        /* Second, loop again and build an offset table */
        p = signature;
        previous = m->rindex;
        while (*p != 0) {
                size_t n, offset;
                int k;

                r = signature_element_length(p, &n);
                if (r < 0)
                        return r;
                else {
                        char t[n+1];

                        memcpy(t, p, n);
                        t[n] = 0;

                        size_t align = bus_gvariant_get_alignment(t);
                        assert(align > 0);

                        /* The possible start of this member after including alignment */
                        size_t start = ALIGN_TO(previous, align);

                        k = bus_gvariant_get_size(t);
                        if (k < 0) {
                                size_t x;

                                /* Variable size */
                                if (v > 0) {
                                        v--;

                                        x = bus_gvariant_read_word_le((uint8_t*) q + v*sz, sz);
                                        if (x >= size)
                                                return -EBADMSG;
                                } else
                                        /* The last item's end is determined
                                         * from the start of the offset array */
                                        x = size - (n_variable * sz);

                                offset = m->rindex + x;
                                if (offset < start) {
                                        log_debug("For type %s with alignment %zu, message specifies offset %zu which is smaller than previous end %zu + alignment = %zu",
                                                  t, align, offset, previous, start);
                                        return -EBADMSG;
                                }
                        } else
                                /* Fixed size */
                                offset = start + k;
                }

                previous = (*offsets)[(*n_offsets)++] = offset;
                p += n;
        }

        assert(v == 0);
        assert(*n_offsets == n_total);

        *item_size = (*offsets)[0] - m->rindex;
        return 0;
}

static int enter_struct_or_dict_entry(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents,
                size_t *item_size,
                size_t **offsets,
                size_t *n_offsets) {

        int r;

        assert(m);
        assert(c);
        assert(contents);
        assert(item_size);
        assert(offsets);
        assert(n_offsets);

        if (!BUS_MESSAGE_IS_GVARIANT(m)) {

                /* dbus1 */
                r = message_peek_body(m, &m->rindex, 8, 0, NULL);
                if (r < 0)
                        return r;

        } else
                /* gvariant with contents */
                return build_struct_offsets(m, contents, c->item_size, item_size, offsets, n_offsets);

        return 0;
}

static int bus_message_enter_struct(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents,
                size_t *item_size,
                size_t **offsets,
                size_t *n_offsets) {

        size_t l;
        int r;

        assert(m);
        assert(c);
        assert(contents);
        assert(item_size);
        assert(offsets);
        assert(n_offsets);

        if (!signature_is_valid(contents, false))
                return -EINVAL;

        if (!c->signature || c->signature[c->index] == 0)
                return -ENXIO;

        l = strlen(contents);

        if (c->signature[c->index] != SD_BUS_TYPE_STRUCT_BEGIN ||
            !startswith(c->signature + c->index + 1, contents) ||
            c->signature[c->index + 1 + l] != SD_BUS_TYPE_STRUCT_END)
                return -ENXIO;

        r = enter_struct_or_dict_entry(m, c, contents, item_size, offsets, n_offsets);
        if (r < 0)
                return r;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index += 1 + l + 1;

        return 1;
}

static int bus_message_enter_dict_entry(
                sd_bus_message *m,
                struct bus_container *c,
                const char *contents,
                size_t *item_size,
                size_t **offsets,
                size_t *n_offsets) {

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

        r = enter_struct_or_dict_entry(m, c, contents, item_size, offsets, n_offsets);
        if (r < 0)
                return r;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index += 1 + l + 1;

        return 1;
}

_public_ int sd_bus_message_enter_container(sd_bus_message *m,
                                            char type,
                                            const char *contents) {
        struct bus_container *c;
        uint32_t *array_size = NULL;
        _cleanup_free_ char *signature = NULL;
        size_t before, end;
        _cleanup_free_ size_t *offsets = NULL;
        size_t n_offsets = 0, item_size = 0;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);
        assert_return(type != 0 || !contents, -EINVAL);

        if (type == 0 || !contents) {
                const char *cc;
                char tt;

                /* Allow entering into anonymous containers */
                r = sd_bus_message_peek_type(m, &tt, &cc);
                if (r < 0)
                        return r;

                if (type != 0 && type != tt)
                        return -ENXIO;

                if (contents && !streq(contents, cc))
                        return -ENXIO;

                type = tt;
                contents = cc;
        }

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

        if (!GREEDY_REALLOC(m->containers, m->containers_allocated, m->n_containers + 1))
                return -ENOMEM;

        if (message_end_of_signature(m))
                return -ENXIO;

        if (message_end_of_array(m, m->rindex))
                return 0;

        c = message_get_last_container(m);

        signature = strdup(contents);
        if (!signature)
                return -ENOMEM;

        c->saved_index = c->index;
        before = m->rindex;

        if (type == SD_BUS_TYPE_ARRAY)
                r = bus_message_enter_array(m, c, contents, &array_size, &item_size, &offsets, &n_offsets);
        else if (type == SD_BUS_TYPE_VARIANT)
                r = bus_message_enter_variant(m, c, contents, &item_size);
        else if (type == SD_BUS_TYPE_STRUCT)
                r = bus_message_enter_struct(m, c, contents, &item_size, &offsets, &n_offsets);
        else if (type == SD_BUS_TYPE_DICT_ENTRY)
                r = bus_message_enter_dict_entry(m, c, contents, &item_size, &offsets, &n_offsets);
        else
                r = -EINVAL;
        if (r <= 0)
                return r;

        /* OK, let's fill it in */
        if (BUS_MESSAGE_IS_GVARIANT(m) &&
            type == SD_BUS_TYPE_STRUCT &&
            isempty(signature))
                end = m->rindex + 0;
        else
                end = m->rindex + c->item_size;
        
        m->containers[m->n_containers++] = (struct bus_container) {
                 .enclosing = type,
                 .signature = TAKE_PTR(signature),

                 .before = before,
                 .begin = m->rindex,
                 /* Unary type has fixed size of 1, but virtual size of 0 */
                 .end = end,
                 .array_size = array_size,
                 .item_size = item_size,
                 .offsets = TAKE_PTR(offsets),
                 .n_offsets = n_offsets,
        };

        return 1;
}

_public_ int sd_bus_message_exit_container(sd_bus_message *m) {
        struct bus_container *c;
        unsigned saved;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);
        assert_return(m->n_containers > 0, -ENXIO);

        c = message_get_last_container(m);

        if (c->enclosing != SD_BUS_TYPE_ARRAY) {
                if (c->signature && c->signature[c->index] != 0)
                        return -EBUSY;
        }

        if (BUS_MESSAGE_IS_GVARIANT(m)) {
                if (m->rindex < c->end)
                        return -EBUSY;

        } else if (c->enclosing == SD_BUS_TYPE_ARRAY) {
                uint32_t l;

                l = BUS_MESSAGE_BSWAP32(m, *c->array_size);
                if (c->begin + l != m->rindex)
                        return -EBUSY;
        }

        message_free_last_container(m);

        c = message_get_last_container(m);
        saved = c->index;
        c->index = c->saved_index;
        r = container_next_item(m, c, &m->rindex);
        c->index = saved;
        if (r < 0)
                return r;

        return 1;
}

static void message_quit_container(sd_bus_message *m) {
        struct bus_container *c;

        assert(m);
        assert(m->sealed);
        assert(m->n_containers > 0);

        /* Undo seeks */
        c = message_get_last_container(m);
        assert(m->rindex >= c->before);
        m->rindex = c->before;

        /* Free container */
        message_free_last_container(m);

        /* Correct index of new top-level container */
        c = message_get_last_container(m);
        c->index = c->saved_index;
}

_public_ int sd_bus_message_peek_type(sd_bus_message *m, char *type, const char **contents) {
        struct bus_container *c;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);

        if (message_end_of_signature(m))
                goto eof;

        if (message_end_of_array(m, m->rindex))
                goto eof;

        c = message_get_last_container(m);

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

                        r = signature_element_length(c->signature+c->index+1, &l);
                        if (r < 0)
                                return r;

                        /* signature_element_length does verification internally */

                        /* The array element must not be empty */
                        assert(l >= 1);
                        if (free_and_strndup(&c->peeked_signature,
                                             c->signature + c->index + 1, l) < 0)
                                return -ENOMEM;

                        *contents = c->peeked_signature;
                }

                if (type)
                        *type = SD_BUS_TYPE_ARRAY;

                return 1;
        }

        if (IN_SET(c->signature[c->index], SD_BUS_TYPE_STRUCT_BEGIN, SD_BUS_TYPE_DICT_ENTRY_BEGIN)) {

                if (contents) {
                        size_t l;

                        r = signature_element_length(c->signature+c->index, &l);
                        if (r < 0)
                                return r;

                        assert(l >= 3);
                        if (free_and_strndup(&c->peeked_signature,
                                             c->signature + c->index + 1, l - 2) < 0)
                                return -ENOMEM;

                        *contents = c->peeked_signature;
                }

                if (type)
                        *type = c->signature[c->index] == SD_BUS_TYPE_STRUCT_BEGIN ? SD_BUS_TYPE_STRUCT : SD_BUS_TYPE_DICT_ENTRY;

                return 1;
        }

        if (c->signature[c->index] == SD_BUS_TYPE_VARIANT) {
                if (contents) {
                        void *q;

                        if (BUS_MESSAGE_IS_GVARIANT(m)) {
                                size_t k;

                                if (c->item_size < 2)
                                        return -EBADMSG;

                                /* Look for the NUL delimiter that
                                   separates the payload from the
                                   signature. Since the body might be
                                   in a different part that then the
                                   signature we map byte by byte. */

                                for (k = 2; k <= c->item_size; k++) {
                                        size_t where;

                                        where = m->rindex + c->item_size - k;
                                        r = message_peek_body(m, &where, 1, k, &q);
                                        if (r < 0)
                                                return r;

                                        if (*(char*) q == 0)
                                                break;
                                }

                                if (k > c->item_size)
                                        return -EBADMSG;

                                if (free_and_strndup(&c->peeked_signature,
                                                     (char*) q + 1, k - 1) < 0)
                                        return -ENOMEM;

                                if (!signature_is_valid(c->peeked_signature, true))
                                        return -EBADMSG;

                                *contents = c->peeked_signature;
                        } else {
                                size_t rindex, l;

                                rindex = m->rindex;
                                r = message_peek_body(m, &rindex, 1, 1, &q);
                                if (r < 0)
                                        return r;

                                l = *(uint8_t*) q;
                                if (l == UINT8_MAX)
                                        /* avoid overflow right below */
                                        return -EBADMSG;

                                r = message_peek_body(m, &rindex, 1, l+1, &q);
                                if (r < 0)
                                        return r;

                                if (!validate_signature(q, l))
                                        return -EBADMSG;

                                *contents = q;
                        }
                }

                if (type)
                        *type = SD_BUS_TYPE_VARIANT;

                return 1;
        }

        return -EINVAL;

eof:
        if (type)
                *type = 0;
        if (contents)
                *contents = NULL;
        return 0;
}

_public_ int sd_bus_message_rewind(sd_bus_message *m, int complete) {
        struct bus_container *c;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);

        if (complete) {
                message_reset_containers(m);
                m->rindex = 0;

                c = message_get_last_container(m);
        } else {
                c = message_get_last_container(m);

                c->index = 0;
                m->rindex = c->begin;
        }

        c->offset_index = 0;
        c->item_size = (c->n_offsets > 0 ? c->offsets[0] : c->end) - c->begin;

        return !isempty(c->signature);
}

_public_ int sd_bus_message_readv(
                sd_bus_message *m,
                const char *types,
                va_list ap) {

        unsigned n_array, n_struct;
        TypeStack stack[BUS_CONTAINER_DEPTH];
        unsigned stack_ptr = 0;
        unsigned n_loop = 0;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);
        assert_return(types, -EINVAL);

        if (isempty(types))
                return 0;

        /* Ideally, we'd just call ourselves recursively on every
         * complex type. However, the state of a va_list that is
         * passed to a function is undefined after that function
         * returns. This means we need to decode the va_list linearly
         * in a single stackframe. We hence implement our own
         * home-grown stack in an array. */

        n_array = (unsigned) -1; /* length of current array entries */
        n_struct = strlen(types); /* length of current struct contents signature */

        for (;;) {
                const char *t;

                n_loop++;

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
                        n_array--;
                else {
                        types++;
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
                        if (r == 0) {
                                if (n_loop <= 1)
                                        return 0;

                                return -ENXIO;
                        }

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
                                if (r == 0) {
                                        if (n_loop <= 1)
                                                return 0;

                                        return -ENXIO;
                                }
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
                        if (r == 0) {
                                if (n_loop <= 1)
                                        return 0;

                                return -ENXIO;
                        }

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
                                if (r == 0) {
                                        if (n_loop <= 1)
                                                return 0;
                                        return -ENXIO;
                                }
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

_public_ int sd_bus_message_read(sd_bus_message *m, const char *types, ...) {
        va_list ap;
        int r;

        va_start(ap, types);
        r = sd_bus_message_readv(m, types, ap);
        va_end(ap);

        return r;
}

_public_ int sd_bus_message_skip(sd_bus_message *m, const char *types) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);

        /* If types is NULL, read exactly one element */
        if (!types) {
                struct bus_container *c;
                size_t l;

                if (message_end_of_signature(m))
                        return -ENXIO;

                if (message_end_of_array(m, m->rindex))
                        return 0;

                c = message_get_last_container(m);

                r = signature_element_length(c->signature + c->index, &l);
                if (r < 0)
                        return r;

                types = strndupa(c->signature + c->index, l);
        }

        switch (*types) {

        case 0: /* Nothing to drop */
                return 0;

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
        case SD_BUS_TYPE_UNIX_FD:

                r = sd_bus_message_read_basic(m, *types, NULL);
                if (r <= 0)
                        return r;

                r = sd_bus_message_skip(m, types + 1);
                if (r < 0)
                        return r;

                return 1;

        case SD_BUS_TYPE_ARRAY: {
                size_t k;

                r = signature_element_length(types + 1, &k);
                if (r < 0)
                        return r;

                {
                        char s[k+1];
                        memcpy(s, types+1, k);
                        s[k] = 0;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, s);
                        if (r <= 0)
                                return r;

                        for (;;) {
                                r = sd_bus_message_skip(m, s);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        break;
                        }

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return r;
                }

                r = sd_bus_message_skip(m, types + 1 + k);
                if (r < 0)
                        return r;

                return 1;
        }

        case SD_BUS_TYPE_VARIANT: {
                const char *contents;
                char x;

                r = sd_bus_message_peek_type(m, &x, &contents);
                if (r <= 0)
                        return r;

                if (x != SD_BUS_TYPE_VARIANT)
                        return -ENXIO;

                r = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, contents);
                if (r <= 0)
                        return r;

                r = sd_bus_message_skip(m, contents);
                if (r < 0)
                        return r;
                assert(r != 0);

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return r;

                r = sd_bus_message_skip(m, types + 1);
                if (r < 0)
                        return r;

                return 1;
        }

        case SD_BUS_TYPE_STRUCT_BEGIN:
        case SD_BUS_TYPE_DICT_ENTRY_BEGIN: {
                size_t k;

                r = signature_element_length(types, &k);
                if (r < 0)
                        return r;

                {
                        char s[k-1];
                        memcpy(s, types+1, k-2);
                        s[k-2] = 0;

                        r = sd_bus_message_enter_container(m, *types == SD_BUS_TYPE_STRUCT_BEGIN ? SD_BUS_TYPE_STRUCT : SD_BUS_TYPE_DICT_ENTRY, s);
                        if (r <= 0)
                                return r;

                        r = sd_bus_message_skip(m, s);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return r;
                }

                r = sd_bus_message_skip(m, types + k);
                if (r < 0)
                        return r;

                return 1;
        }

        default:
                return -EINVAL;
        }
}

_public_ int sd_bus_message_read_array(
                sd_bus_message *m,
                char type,
                const void **ptr,
                size_t *size) {

        struct bus_container *c;
        void *p;
        size_t sz;
        ssize_t align;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);
        assert_return(bus_type_is_trivial(type), -EINVAL);
        assert_return(ptr, -EINVAL);
        assert_return(size, -EINVAL);
        assert_return(!BUS_MESSAGE_NEED_BSWAP(m), -EOPNOTSUPP);

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, CHAR_TO_STR(type));
        if (r <= 0)
                return r;

        c = message_get_last_container(m);

        if (BUS_MESSAGE_IS_GVARIANT(m)) {
                align = bus_gvariant_get_alignment(CHAR_TO_STR(type));
                if (align < 0)
                        return align;

                sz = c->end - c->begin;
        } else {
                align = bus_type_get_alignment(type);
                if (align < 0)
                        return align;

                sz = BUS_MESSAGE_BSWAP32(m, *c->array_size);
        }

        if (sz == 0)
                /* Zero length array, let's return some aligned
                 * pointer that is not NULL */
                p = (uint8_t*) align;
        else {
                r = message_peek_body(m, &m->rindex, align, sz, &p);
                if (r < 0)
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

        return buffer_peek(BUS_MESSAGE_FIELDS(m), m->fields_size, rindex, align, nbytes, ret);
}

static int message_peek_field_uint32(
                sd_bus_message *m,
                size_t *ri,
                size_t item_size,
                uint32_t *ret) {

        int r;
        void *q;

        assert(m);
        assert(ri);

        if (BUS_MESSAGE_IS_GVARIANT(m) && item_size != 4)
                return -EBADMSG;

        /* identical for gvariant and dbus1 */

        r = message_peek_fields(m, ri, 4, 4, &q);
        if (r < 0)
                return r;

        if (ret)
                *ret = BUS_MESSAGE_BSWAP32(m, *(uint32_t*) q);

        return 0;
}

static int message_peek_field_uint64(
                sd_bus_message *m,
                size_t *ri,
                size_t item_size,
                uint64_t *ret) {

        int r;
        void *q;

        assert(m);
        assert(ri);

        if (BUS_MESSAGE_IS_GVARIANT(m) && item_size != 8)
                return -EBADMSG;

        /* identical for gvariant and dbus1 */

        r = message_peek_fields(m, ri, 8, 8, &q);
        if (r < 0)
                return r;

        if (ret)
                *ret = BUS_MESSAGE_BSWAP64(m, *(uint64_t*) q);

        return 0;
}

static int message_peek_field_string(
                sd_bus_message *m,
                bool (*validate)(const char *p),
                size_t *ri,
                size_t item_size,
                const char **ret) {

        uint32_t l;
        int r;
        void *q;

        assert(m);
        assert(ri);

        if (BUS_MESSAGE_IS_GVARIANT(m)) {

                if (item_size <= 0)
                        return -EBADMSG;

                r = message_peek_fields(m, ri, 1, item_size, &q);
                if (r < 0)
                        return r;

                l = item_size - 1;
        } else {
                r = message_peek_field_uint32(m, ri, 4, &l);
                if (r < 0)
                        return r;

                if (l == UINT32_MAX)
                        /* avoid overflow right below */
                        return -EBADMSG;

                r = message_peek_fields(m, ri, 1, l+1, &q);
                if (r < 0)
                        return r;
        }

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
                size_t item_size,
                const char **ret) {

        size_t l;
        int r;
        void *q;

        assert(m);
        assert(ri);

        if (BUS_MESSAGE_IS_GVARIANT(m)) {

                if (item_size <= 0)
                        return -EBADMSG;

                r = message_peek_fields(m, ri, 1, item_size, &q);
                if (r < 0)
                        return r;

                l = item_size - 1;
        } else {
                r = message_peek_fields(m, ri, 1, 1, &q);
                if (r < 0)
                        return r;

                l = *(uint8_t*) q;
                if (l == UINT8_MAX)
                        /* avoid overflow right below */
                        return -EBADMSG;

                r = message_peek_fields(m, ri, 1, l+1, &q);
                if (r < 0)
                        return r;
        }

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
        assert(!BUS_MESSAGE_IS_GVARIANT(m));

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

                        r = message_peek_field_string(m, NULL, ri, 0, NULL);
                        if (r < 0)
                                return r;

                        (*signature)++;

                } else if (t == SD_BUS_TYPE_OBJECT_PATH) {

                        r = message_peek_field_string(m, object_path_is_valid, ri, 0, NULL);
                        if (r < 0)
                                return r;

                        (*signature)++;

                } else if (t == SD_BUS_TYPE_SIGNATURE) {

                        r = message_peek_field_signature(m, ri, 0, NULL);
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

                        r = signature_element_length(*signature + 1, &l);
                        if (r < 0)
                                return r;

                        assert(l >= 1);
                        {
                                char sig[l + 1], *s = sig;
                                uint32_t nas;
                                int alignment;

                                strncpy(sig, *signature + 1, l);
                                sig[l] = '\0';

                                alignment = bus_type_get_alignment(sig[0]);
                                if (alignment < 0)
                                        return alignment;

                                r = message_peek_field_uint32(m, ri, 0, &nas);
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

                        r = message_peek_field_signature(m, ri, 0, &s);
                        if (r < 0)
                                return r;

                        r = message_skip_fields(m, ri, (uint32_t) -1, (const char**) &s);
                        if (r < 0)
                                return r;

                        (*signature)++;

                } else if (IN_SET(t, SD_BUS_TYPE_STRUCT, SD_BUS_TYPE_DICT_ENTRY)) {

                        r = signature_element_length(*signature, &l);
                        if (r < 0)
                                return r;

                        assert(l >= 2);
                        {
                                char sig[l + 1], *s = sig;
                                strncpy(sig, *signature + 1, l);
                                sig[l] = '\0';

                                r = message_skip_fields(m, ri, (uint32_t) -1, (const char**) &s);
                                if (r < 0)
                                        return r;
                        }

                        *signature += l;
                } else
                        return -EBADMSG;
        }
}

int bus_message_parse_fields(sd_bus_message *m) {
        size_t ri;
        int r;
        uint32_t unix_fds = 0;
        bool unix_fds_set = false;
        void *offsets = NULL;
        unsigned n_offsets = 0;
        size_t sz = 0;
        unsigned i = 0;

        assert(m);

        if (BUS_MESSAGE_IS_GVARIANT(m)) {
                char *p;

                /* Read the signature from the end of the body variant first */
                sz = bus_gvariant_determine_word_size(BUS_MESSAGE_SIZE(m), 0);
                if (m->footer_accessible < 1 + sz)
                        return -EBADMSG;

                p = (char*) m->footer + m->footer_accessible - (1 + sz);
                for (;;) {
                        if (p < (char*) m->footer)
                                return -EBADMSG;

                        if (*p == 0) {
                                size_t l;

                                /* We found the beginning of the signature
                                 * string, yay! We require the body to be a
                                 * structure, so verify it and then strip the
                                 * opening/closing brackets. */

                                l = (char*) m->footer + m->footer_accessible - p - (1 + sz);
                                if (l < 2 ||
                                    p[1] != SD_BUS_TYPE_STRUCT_BEGIN ||
                                    p[1 + l - 1] != SD_BUS_TYPE_STRUCT_END)
                                        return -EBADMSG;

                                if (free_and_strndup(&m->root_container.signature,
                                                     p + 1 + 1, l - 2) < 0)
                                        return -ENOMEM;
                                break;
                        }

                        p--;
                }

                /* Calculate the actual user body size, by removing
                 * the trailing variant signature and struct offset
                 * table */
                m->user_body_size = m->body_size - ((char*) m->footer + m->footer_accessible - p);

                /* Pull out the offset table for the fields array */
                sz = bus_gvariant_determine_word_size(m->fields_size, 0);
                if (sz > 0) {
                        size_t framing;
                        void *q;

                        ri = m->fields_size - sz;
                        r = message_peek_fields(m, &ri, 1, sz, &q);
                        if (r < 0)
                                return r;

                        framing = bus_gvariant_read_word_le(q, sz);
                        if (framing >= m->fields_size - sz)
                                return -EBADMSG;
                        if ((m->fields_size - framing) % sz != 0)
                                return -EBADMSG;

                        ri = framing;
                        r = message_peek_fields(m, &ri, 1, m->fields_size - framing, &offsets);
                        if (r < 0)
                                return r;

                        n_offsets = (m->fields_size - framing) / sz;
                }
        } else
                m->user_body_size = m->body_size;

        ri = 0;
        while (ri < m->fields_size) {
                _cleanup_free_ char *sig = NULL;
                const char *signature;
                uint64_t field_type;
                size_t item_size = (size_t) -1;

                if (BUS_MESSAGE_IS_GVARIANT(m)) {
                        uint64_t *u64;

                        if (i >= n_offsets)
                                break;

                        if (i == 0)
                                ri = 0;
                        else
                                ri = ALIGN_TO(bus_gvariant_read_word_le((uint8_t*) offsets + (i-1)*sz, sz), 8);

                        r = message_peek_fields(m, &ri, 8, 8, (void**) &u64);
                        if (r < 0)
                                return r;

                        field_type = BUS_MESSAGE_BSWAP64(m, *u64);
                } else {
                        uint8_t *u8;

                        r = message_peek_fields(m, &ri, 8, 1, (void**) &u8);
                        if (r < 0)
                                return r;

                        field_type = *u8;
                }

                if (BUS_MESSAGE_IS_GVARIANT(m)) {
                        size_t where, end;
                        char *b;
                        void *q;

                        end = bus_gvariant_read_word_le((uint8_t*) offsets + i*sz, sz);

                        if (end < ri)
                                return -EBADMSG;

                        where = ri = ALIGN_TO(ri, 8);
                        item_size = end - ri;
                        r = message_peek_fields(m, &where, 1, item_size, &q);
                        if (r < 0)
                                return r;

                        b = memrchr(q, 0, item_size);
                        if (!b)
                                return -EBADMSG;

                        sig = strndup(b+1, item_size - (b+1-(char*) q));
                        if (!sig)
                                return -ENOMEM;

                        signature = sig;
                        item_size = b - (char*) q;
                } else {
                        r = message_peek_field_signature(m, &ri, 0, &signature);
                        if (r < 0)
                                return r;
                }

                switch (field_type) {

                case _BUS_MESSAGE_HEADER_INVALID:
                        return -EBADMSG;

                case BUS_MESSAGE_HEADER_PATH:

                        if (m->path)
                                return -EBADMSG;

                        if (!streq(signature, "o"))
                                return -EBADMSG;

                        r = message_peek_field_string(m, object_path_is_valid, &ri, item_size, &m->path);
                        break;

                case BUS_MESSAGE_HEADER_INTERFACE:

                        if (m->interface)
                                return -EBADMSG;

                        if (!streq(signature, "s"))
                                return -EBADMSG;

                        r = message_peek_field_string(m, interface_name_is_valid, &ri, item_size, &m->interface);
                        break;

                case BUS_MESSAGE_HEADER_MEMBER:

                        if (m->member)
                                return -EBADMSG;

                        if (!streq(signature, "s"))
                                return -EBADMSG;

                        r = message_peek_field_string(m, member_name_is_valid, &ri, item_size, &m->member);
                        break;

                case BUS_MESSAGE_HEADER_ERROR_NAME:

                        if (m->error.name)
                                return -EBADMSG;

                        if (!streq(signature, "s"))
                                return -EBADMSG;

                        r = message_peek_field_string(m, error_name_is_valid, &ri, item_size, &m->error.name);
                        if (r >= 0)
                                m->error._need_free = -1;

                        break;

                case BUS_MESSAGE_HEADER_DESTINATION:

                        if (m->destination)
                                return -EBADMSG;

                        if (!streq(signature, "s"))
                                return -EBADMSG;

                        r = message_peek_field_string(m, service_name_is_valid, &ri, item_size, &m->destination);
                        break;

                case BUS_MESSAGE_HEADER_SENDER:

                        if (m->sender)
                                return -EBADMSG;

                        if (!streq(signature, "s"))
                                return -EBADMSG;

                        r = message_peek_field_string(m, service_name_is_valid, &ri, item_size, &m->sender);

                        if (r >= 0 && m->sender[0] == ':' && m->bus->bus_client) {
                                m->creds.unique_name = (char*) m->sender;
                                m->creds.mask |= SD_BUS_CREDS_UNIQUE_NAME & m->bus->creds_mask;
                        }

                        break;

                case BUS_MESSAGE_HEADER_SIGNATURE: {
                        const char *s;
                        char *c;

                        if (BUS_MESSAGE_IS_GVARIANT(m)) /* only applies to dbus1 */
                                return -EBADMSG;

                        if (m->root_container.signature)
                                return -EBADMSG;

                        if (!streq(signature, "g"))
                                return -EBADMSG;

                        r = message_peek_field_signature(m, &ri, item_size, &s);
                        if (r < 0)
                                return r;

                        c = strdup(s);
                        if (!c)
                                return -ENOMEM;

                        free_and_replace(m->root_container.signature, c);
                        break;
                }

                case BUS_MESSAGE_HEADER_REPLY_SERIAL:

                        if (m->reply_cookie != 0)
                                return -EBADMSG;

                        if (BUS_MESSAGE_IS_GVARIANT(m)) {
                                /* 64bit on dbus2 */

                                if (!streq(signature, "t"))
                                        return -EBADMSG;

                                r = message_peek_field_uint64(m, &ri, item_size, &m->reply_cookie);
                                if (r < 0)
                                        return r;
                        } else {
                                /* 32bit on dbus1 */
                                uint32_t serial;

                                if (!streq(signature, "u"))
                                        return -EBADMSG;

                                r = message_peek_field_uint32(m, &ri, item_size, &serial);
                                if (r < 0)
                                        return r;

                                m->reply_cookie = serial;
                        }

                        if (m->reply_cookie == 0)
                                return -EBADMSG;

                        break;

                case BUS_MESSAGE_HEADER_UNIX_FDS:
                        if (unix_fds_set)
                                return -EBADMSG;

                        if (!streq(signature, "u"))
                                return -EBADMSG;

                        r = message_peek_field_uint32(m, &ri, item_size, &unix_fds);
                        if (r < 0)
                                return -EBADMSG;

                        unix_fds_set = true;
                        break;

                default:
                        if (!BUS_MESSAGE_IS_GVARIANT(m))
                                r = message_skip_fields(m, &ri, (uint32_t) -1, (const char **) &signature);
                }

                if (r < 0)
                        return r;

                i++;
        }

        if (m->n_fds != unix_fds)
                return -EBADMSG;

        switch (m->header->type) {

        case SD_BUS_MESSAGE_SIGNAL:
                if (!m->path || !m->interface || !m->member)
                        return -EBADMSG;

                if (m->reply_cookie != 0)
                        return -EBADMSG;

                break;

        case SD_BUS_MESSAGE_METHOD_CALL:

                if (!m->path || !m->member)
                        return -EBADMSG;

                if (m->reply_cookie != 0)
                        return -EBADMSG;

                break;

        case SD_BUS_MESSAGE_METHOD_RETURN:

                if (m->reply_cookie == 0)
                        return -EBADMSG;
                break;

        case SD_BUS_MESSAGE_METHOD_ERROR:

                if (m->reply_cookie == 0 || !m->error.name)
                        return -EBADMSG;
                break;
        }

        /* Refuse non-local messages that claim they are local */
        if (streq_ptr(m->path, "/org/freedesktop/DBus/Local"))
                return -EBADMSG;
        if (streq_ptr(m->interface, "org.freedesktop.DBus.Local"))
                return -EBADMSG;
        if (streq_ptr(m->sender, "org.freedesktop.DBus.Local"))
                return -EBADMSG;

        m->root_container.end = m->user_body_size;

        if (BUS_MESSAGE_IS_GVARIANT(m)) {
                r = build_struct_offsets(
                                m,
                                m->root_container.signature,
                                m->user_body_size,
                                &m->root_container.item_size,
                                &m->root_container.offsets,
                                &m->root_container.n_offsets);
                if (r == -EINVAL)
                        return -EBADMSG;
                if (r < 0)
                        return r;
        }

        /* Try to read the error message, but if we can't it's a non-issue */
        if (m->header->type == SD_BUS_MESSAGE_METHOD_ERROR)
                (void) sd_bus_message_read(m, "s", &m->error.message);

        return 0;
}

_public_ int sd_bus_message_set_destination(sd_bus_message *m, const char *destination) {
        assert_return(m, -EINVAL);
        assert_return(destination, -EINVAL);
        assert_return(service_name_is_valid(destination), -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(!m->destination, -EEXIST);

        return message_append_field_string(m, BUS_MESSAGE_HEADER_DESTINATION, SD_BUS_TYPE_STRING, destination, &m->destination);
}

_public_ int sd_bus_message_set_sender(sd_bus_message *m, const char *sender) {
        assert_return(m, -EINVAL);
        assert_return(sender, -EINVAL);
        assert_return(service_name_is_valid(sender), -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(!m->sender, -EEXIST);

        return message_append_field_string(m, BUS_MESSAGE_HEADER_SENDER, SD_BUS_TYPE_STRING, sender, &m->sender);
}

int bus_message_get_blob(sd_bus_message *m, void **buffer, size_t *sz) {
        size_t total;
        void *p, *e;
        size_t i;
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
        const char *s;
        int r;

        assert(m);
        assert(l);

        r = sd_bus_message_enter_container(m, 'a', "s");
        if (r <= 0)
                return r;

        while ((r = sd_bus_message_read_basic(m, 's', &s)) > 0) {
                r = strv_extend(l, s);
                if (r < 0)
                        return r;
        }
        if (r < 0)
                return r;

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        return 1;
}

_public_ int sd_bus_message_read_strv(sd_bus_message *m, char ***l) {
        _cleanup_strv_free_ char **strv = NULL;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);
        assert_return(l, -EINVAL);

        r = bus_message_read_strv_extend(m, &strv);
        if (r <= 0)
                return r;

        *l = TAKE_PTR(strv);
        return 1;
}

static int bus_message_get_arg_skip(
                sd_bus_message *m,
                unsigned i,
                char *_type,
                const char **_contents) {

        unsigned j;
        int r;

        r = sd_bus_message_rewind(m, true);
        if (r < 0)
                return r;

        for (j = 0;; j++) {
                const char *contents;
                char type;

                r = sd_bus_message_peek_type(m, &type, &contents);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENXIO;

                /* Don't match against arguments after the first one we don't understand */
                if (!IN_SET(type, SD_BUS_TYPE_STRING, SD_BUS_TYPE_OBJECT_PATH, SD_BUS_TYPE_SIGNATURE) &&
                    !(type == SD_BUS_TYPE_ARRAY && STR_IN_SET(contents, "s", "o", "g")))
                        return -ENXIO;

                if (j >= i) {
                        if (_contents)
                                *_contents = contents;
                        if (_type)
                                *_type = type;
                        return 0;
                }

                r = sd_bus_message_skip(m, NULL);
                if (r < 0)
                        return r;
        }

}

int bus_message_get_arg(sd_bus_message *m, unsigned i, const char **str) {
        char type;
        int r;

        assert(m);
        assert(str);

        r = bus_message_get_arg_skip(m, i, &type, NULL);
        if (r < 0)
                return r;

        if (!IN_SET(type, SD_BUS_TYPE_STRING, SD_BUS_TYPE_OBJECT_PATH, SD_BUS_TYPE_SIGNATURE))
                return -ENXIO;

        return sd_bus_message_read_basic(m, type, str);
}

int bus_message_get_arg_strv(sd_bus_message *m, unsigned i, char ***strv) {
        const char *contents;
        char type;
        int r;

        assert(m);
        assert(strv);

        r = bus_message_get_arg_skip(m, i, &type, &contents);
        if (r < 0)
                return r;

        if (type != SD_BUS_TYPE_ARRAY)
                return -ENXIO;
        if (!STR_IN_SET(contents, "s", "o", "g"))
                return -ENXIO;

        return sd_bus_message_read_strv(m, strv);
}

_public_ int sd_bus_message_get_errno(sd_bus_message *m) {
        assert_return(m, EINVAL);

        if (m->header->type != SD_BUS_MESSAGE_METHOD_ERROR)
                return 0;

        return sd_bus_error_get_errno(&m->error);
}

_public_ const char* sd_bus_message_get_signature(sd_bus_message *m, int complete) {
        struct bus_container *c;

        assert_return(m, NULL);

        c = complete ? &m->root_container : message_get_last_container(m);
        return strempty(c->signature);
}

_public_ int sd_bus_message_is_empty(sd_bus_message *m) {
        assert_return(m, -EINVAL);

        return isempty(m->root_container.signature);
}

_public_ int sd_bus_message_has_signature(sd_bus_message *m, const char *signature) {
        assert_return(m, -EINVAL);

        return streq(strempty(m->root_container.signature), strempty(signature));
}

_public_ int sd_bus_message_copy(sd_bus_message *m, sd_bus_message *source, int all) {
        bool done_something = false;
        int r;

        assert_return(m, -EINVAL);
        assert_return(source, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(source->sealed, -EPERM);

        do {
                const char *contents;
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

                r = sd_bus_message_peek_type(source, &type, &contents);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                done_something = true;

                if (bus_type_is_container(type) > 0) {

                        r = sd_bus_message_enter_container(source, type, contents);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_open_container(m, type, contents);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_copy(m, source, true);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_close_container(m);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_exit_container(source);
                        if (r < 0)
                                return r;

                        continue;
                }

                r = sd_bus_message_read_basic(source, type, &basic);
                if (r < 0)
                        return r;

                assert(r > 0);

                if (IN_SET(type, SD_BUS_TYPE_OBJECT_PATH, SD_BUS_TYPE_SIGNATURE, SD_BUS_TYPE_STRING))
                        r = sd_bus_message_append_basic(m, type, basic.string);
                else
                        r = sd_bus_message_append_basic(m, type, &basic);

                if (r < 0)
                        return r;

        } while (all);

        return done_something;
}

_public_ int sd_bus_message_verify_type(sd_bus_message *m, char type, const char *contents) {
        const char *c;
        char t;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);
        assert_return(!type || bus_type_is_valid(type), -EINVAL);
        assert_return(!contents || signature_is_valid(contents, true), -EINVAL);
        assert_return(type || contents, -EINVAL);
        assert_return(!contents || !type || bus_type_is_container(type), -EINVAL);

        r = sd_bus_message_peek_type(m, &t, &c);
        if (r <= 0)
                return r;

        if (type != 0 && type != t)
                return 0;

        if (contents && !streq_ptr(contents, c))
                return 0;

        return 1;
}

_public_ sd_bus *sd_bus_message_get_bus(sd_bus_message *m) {
        assert_return(m, NULL);

        return m->bus;
}

int bus_message_remarshal(sd_bus *bus, sd_bus_message **m) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *n = NULL;
        usec_t timeout;
        int r;

        assert(bus);
        assert(m);
        assert(*m);

        switch ((*m)->header->type) {

        case SD_BUS_MESSAGE_SIGNAL:
                r = sd_bus_message_new_signal(bus, &n, (*m)->path, (*m)->interface, (*m)->member);
                if (r < 0)
                        return r;

                break;

        case SD_BUS_MESSAGE_METHOD_CALL:
                r = sd_bus_message_new_method_call(bus, &n, (*m)->destination, (*m)->path, (*m)->interface, (*m)->member);
                if (r < 0)
                        return r;

                break;

        case SD_BUS_MESSAGE_METHOD_RETURN:
        case SD_BUS_MESSAGE_METHOD_ERROR:

                r = sd_bus_message_new(bus, &n, (*m)->header->type);
                if (r < 0)
                        return -ENOMEM;

                assert(n);

                n->reply_cookie = (*m)->reply_cookie;

                r = message_append_reply_cookie(n, n->reply_cookie);
                if (r < 0)
                        return r;

                if ((*m)->header->type == SD_BUS_MESSAGE_METHOD_ERROR && (*m)->error.name) {
                        r = message_append_field_string(n, BUS_MESSAGE_HEADER_ERROR_NAME, SD_BUS_TYPE_STRING, (*m)->error.name, &n->error.message);
                        if (r < 0)
                                return r;

                        n->error._need_free = -1;
                }

                break;

        default:
                return -EINVAL;
        }

        if ((*m)->destination && !n->destination) {
                r = message_append_field_string(n, BUS_MESSAGE_HEADER_DESTINATION, SD_BUS_TYPE_STRING, (*m)->destination, &n->destination);
                if (r < 0)
                        return r;
        }

        if ((*m)->sender && !n->sender) {
                r = message_append_field_string(n, BUS_MESSAGE_HEADER_SENDER, SD_BUS_TYPE_STRING, (*m)->sender, &n->sender);
                if (r < 0)
                        return r;
        }

        n->header->flags |= (*m)->header->flags & (BUS_MESSAGE_NO_REPLY_EXPECTED|BUS_MESSAGE_NO_AUTO_START);

        r = sd_bus_message_copy(n, *m, true);
        if (r < 0)
                return r;

        timeout = (*m)->timeout;
        if (timeout == 0 && !((*m)->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)) {
                r = sd_bus_get_method_call_timeout(bus, &timeout);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_seal(n, BUS_MESSAGE_COOKIE(*m), timeout);
        if (r < 0)
                return r;

        sd_bus_message_unref(*m);
        *m = TAKE_PTR(n);

        return 0;
}

int bus_message_append_sender(sd_bus_message *m, const char *sender) {
        assert(m);
        assert(sender);

        assert_return(!m->sealed, -EPERM);
        assert_return(!m->sender, -EPERM);

        return message_append_field_string(m, BUS_MESSAGE_HEADER_SENDER, SD_BUS_TYPE_STRING, sender, &m->sender);
}

_public_ int sd_bus_message_get_priority(sd_bus_message *m, int64_t *priority) {
        assert_return(m, -EINVAL);
        assert_return(priority, -EINVAL);

        *priority = m->priority;
        return 0;
}

_public_ int sd_bus_message_set_priority(sd_bus_message *m, int64_t priority) {
        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        m->priority = priority;
        return 0;
}
