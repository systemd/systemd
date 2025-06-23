/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-signature.h"
#include "bus-type.h"
#include "fd-util.h"
#include "iovec-util.h"
#include "log.h"
#include "memfd-util.h"
#include "memory-util.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

static int message_append_basic(sd_bus_message *m, char type, const void *p, const void **stored);
static int message_parse_fields(sd_bus_message *m);

static void* adjust_pointer(const void *p, void *old_base, size_t sz, void *new_base) {

        if (!p)
                return NULL;

        if (old_base == new_base)
                return (void*) p;

        if ((uint8_t*) p < (uint8_t*) old_base)
                return (void*) p;

        if ((uint8_t*) p >= (uint8_t*) old_base + sz)
                return (void*) p;

        return (uint8_t*) new_base + ((uint8_t*) p - (uint8_t*) old_base);
}

static void message_free_part(sd_bus_message *m, BusMessageBodyPart *part) {
        assert(m);
        assert(part);

        if (part->memfd >= 0) {
                /* erase if requested, but only if the memfd is not sealed yet, i.e. is writable */
                if (m->sensitive && !m->sealed)
                        explicit_bzero_safe(part->data, part->size);

                close_and_munmap(part->memfd, part->mmap_begin, part->mapped);
        } else if (part->munmap_this)
                /* We don't erase sensitive data here, since the data is memory mapped from someone else, and
                 * we just don't know if it's OK to write to it */
                munmap(part->mmap_begin, part->mapped);
        else {
                /* Erase this if that is requested. Since this is regular memory we know we can write it. */
                if (m->sensitive)
                        explicit_bzero_safe(part->data, part->size);

                if (part->free_this)
                        free(part->data);
        }

        if (part != &m->body)
                free(part);
}

static void message_reset_parts(sd_bus_message *m) {
        BusMessageBodyPart *part;

        assert(m);

        part = &m->body;
        while (m->n_body_parts > 0) {
                BusMessageBodyPart *next = part->next;
                message_free_part(m, part);
                part = next;
                m->n_body_parts--;
        }

        m->body_end = NULL;

        m->cached_rindex_part = NULL;
        m->cached_rindex_part_begin = 0;
}

static BusMessageContainer* message_get_last_container(sd_bus_message *m) {
        assert(m);

        if (m->n_containers == 0)
                return &m->root_container;

        assert(m->containers);
        return m->containers + m->n_containers - 1;
}

static void message_free_last_container(sd_bus_message *m) {
        BusMessageContainer *c;

        c = message_get_last_container(m);

        free(c->signature);
        free(c->peeked_signature);

        /* Move to previous container, but not if we are on root container */
        if (m->n_containers > 0)
                m->n_containers--;
}

static void message_reset_containers(sd_bus_message *m) {
        assert(m);

        while (m->n_containers > 0)
                message_free_last_container(m);

        m->containers = mfree(m->containers);
        m->root_container.index = 0;
}

static sd_bus_message* message_free(sd_bus_message *m) {
        assert(m);

        message_reset_parts(m);

        if (m->free_header)
                free(m->header);

        /* Note that we don't unref m->bus here. That's already done by sd_bus_message_unref() as each user
         * reference to the bus message also is considered a reference to the bus connection itself. */

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

static void* message_extend_fields(sd_bus_message *m, size_t sz, bool add_offset) {
        void *op, *np;
        size_t old_size, new_size, start;

        assert(m);

        if (m->poisoned)
                return NULL;

        old_size = sizeof(BusMessageHeader) + m->fields_size;
        start = ALIGN8(old_size);
        new_size = start + sz;

        if (new_size < start || new_size > UINT32_MAX)
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

                memcpy(np, m->header, sizeof(BusMessageHeader));
        }

        /* Zero out padding */
        if (start > old_size)
                memzero((uint8_t*) np + old_size, start - old_size);

        op = m->header;
        m->header = np;
        m->fields_size = new_size - sizeof(BusMessageHeader);

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

                m->header_offsets[m->n_header_offsets++] = new_size - sizeof(BusMessageHeader);
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

        /* dbus only allows 8-bit header field ids */
        if (h > 0xFF)
                return -EINVAL;

        /* dbus doesn't allow strings over 32-bit */
        l = strlen(s);
        if (l > UINT32_MAX)
                return -EINVAL;

        /* Signature "(yv)" where the variant contains "s" */

        /* (field id byte + (signature length + signature 's' + NUL) + (string length + string + NUL)) */
        p = message_extend_fields(m, 4 + 4 + l + 1, false);
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

        /* dbus only allows 8-bit header field ids */
        if (h > 0xFF)
                return -EINVAL;

        /* dbus doesn't allow signatures over 8-bit */
        l = strlen(s);
        if (l > SD_BUS_MAXIMUM_SIGNATURE_LENGTH)
                return -EINVAL;

        /* Signature "(yv)" where the variant contains "g" */

        /* (field id byte + (signature length + signature 'g' + NUL) + (string length + string + NUL)) */
        p = message_extend_fields(m, 4 + 1 + l + 1, false);
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

        return 0;
}

static int message_append_field_uint32(sd_bus_message *m, uint64_t h, uint32_t x) {
        uint8_t *p;

        assert(m);

        /* dbus only allows 8-bit header field ids */
        if (h > 0xFF)
                return -EINVAL;

        /* (field id byte + (signature length + signature 'u' + NUL) + value) */
        p = message_extend_fields(m, 4 + 4, false);
        if (!p)
                return -ENOMEM;

        p[0] = (uint8_t) h;
        p[1] = 1;
        p[2] = 'u';
        p[3] = 0;

        ((uint32_t*) p)[1] = x;

        return 0;
}

static int message_append_reply_cookie(sd_bus_message *m, uint64_t cookie) {
        assert(m);

        /* 64-bit cookies are not supported */
        if (cookie > UINT32_MAX)
                return -EOPNOTSUPP;

        return message_append_field_uint32(m, BUS_MESSAGE_HEADER_REPLY_SERIAL, (uint32_t) cookie);
}

static int message_from_header(
                sd_bus *bus,
                void *buffer,
                size_t message_size,
                int *fds,
                size_t n_fds,
                const char *label,
                sd_bus_message **ret) {

        _cleanup_free_ sd_bus_message *m = NULL;
        BusMessageHeader *h;
        size_t a, label_sz = 0; /* avoid false maybe-uninitialized warning */

        assert(bus);
        assert(buffer || message_size <= 0);
        assert(fds || n_fds <= 0);
        assert(ret);

        if (message_size < sizeof(BusMessageHeader))
                return -EBADMSG;

        h = buffer;
        if (!IN_SET(h->version, 1, 2))
                return -EBADMSG;

        if (h->type == _SD_BUS_MESSAGE_TYPE_INVALID)
                return -EBADMSG;

        if (!IN_SET(h->endian, BUS_LITTLE_ENDIAN, BUS_BIG_ENDIAN))
                return -EBADMSG;

        /* Note that we are happy with unknown flags in the flags header! */

        a = ALIGN(sizeof(sd_bus_message));

        if (label) {
                label_sz = strlen(label);
                a += label_sz + 1;
        }

        m = malloc0(a);
        if (!m)
                return -ENOMEM;

        m->creds = (sd_bus_creds) { SD_BUS_CREDS_INIT_FIELDS };
        m->sealed = true;
        m->header = buffer;

        if (h->serial == 0)
                return -EBADMSG;

        m->fields_size = BUS_MESSAGE_BSWAP32(m, h->fields_size);
        m->body_size = BUS_MESSAGE_BSWAP32(m, h->body_size);

        assert(message_size >= sizeof(BusMessageHeader));
        if (ALIGN8(m->fields_size) > message_size - sizeof(BusMessageHeader) ||
            m->body_size != message_size - sizeof(BusMessageHeader) - ALIGN8(m->fields_size))
                return -EBADMSG;

        m->fds = fds;
        m->n_fds = n_fds;

        if (label) {
                m->creds.label = (char*) m + ALIGN(sizeof(sd_bus_message));
                memcpy(m->creds.label, label, label_sz + 1);

                m->creds.mask |= SD_BUS_CREDS_SELINUX_CONTEXT;
        }

        m->n_ref = 1;
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

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        size_t sz;
        int r;

        r = message_from_header(
                        bus,
                        buffer, length,
                        fds, n_fds,
                        label,
                        &m);
        if (r < 0)
                return r;

        sz = length - sizeof(BusMessageHeader) - ALIGN8(m->fields_size);
        if (sz > 0) {
                m->n_body_parts = 1;
                m->body.data = (uint8_t*) buffer + sizeof(BusMessageHeader) + ALIGN8(m->fields_size);
                m->body.size = sz;
                m->body.sealed = true;
                m->body.memfd = -EBADF;
        }

        m->n_iovec = 1;
        m->iovec = m->iovec_fixed;
        m->iovec[0] = IOVEC_MAKE(buffer, length);

        r = message_parse_fields(m);
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
                sd_bus_message **ret,
                uint8_t type) {

        assert_return(bus, -ENOTCONN);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(bus->state != BUS_UNSET, -ENOTCONN);
        assert_return(ret, -EINVAL);
        /* Creation of messages with _SD_BUS_MESSAGE_TYPE_INVALID is allowed. */
        assert_return(type < _SD_BUS_MESSAGE_TYPE_MAX, -EINVAL);

        sd_bus_message *t = malloc0(ALIGN(sizeof(sd_bus_message)) + sizeof(BusMessageHeader));
        if (!t)
                return -ENOMEM;

        t->n_ref = 1;
        t->creds = (sd_bus_creds) { SD_BUS_CREDS_INIT_FIELDS };
        t->bus = sd_bus_ref(bus);
        t->header = (BusMessageHeader*) ((uint8_t*) t + ALIGN(sizeof(struct sd_bus_message)));
        t->header->endian = BUS_NATIVE_ENDIAN;
        t->header->type = type;
        t->header->version = bus->message_version;
        t->allow_fds = bus->can_fds || !IN_SET(bus->state, BUS_HELLO, BUS_RUNNING);

        if (bus->allow_interactive_authorization)
                t->header->flags |= BUS_MESSAGE_ALLOW_INTERACTIVE_AUTHORIZATION;

        *ret = t;
        return 0;
}

_public_ int sd_bus_message_new_signal_to(
                sd_bus *bus,
                sd_bus_message **ret,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *t = NULL;
        int r;

        assert_return(bus, -ENOTCONN);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(bus->state != BUS_UNSET, -ENOTCONN);
        assert_return(!destination || service_name_is_valid(destination), -EINVAL);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(interface_name_is_valid(interface), -EINVAL);
        assert_return(member_name_is_valid(member), -EINVAL);
        assert_return(ret, -EINVAL);

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

        if (destination) {
                r = message_append_field_string(t, BUS_MESSAGE_HEADER_DESTINATION, SD_BUS_TYPE_STRING, destination, &t->destination);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(t);
        return 0;
}

_public_ int sd_bus_message_new_signal(
                sd_bus *bus,
                sd_bus_message **ret,
                const char *path,
                const char *interface,
                const char *member) {

        return sd_bus_message_new_signal_to(bus, ret, NULL, path, interface, member);
}

_public_ int sd_bus_message_new_method_call(
                sd_bus *bus,
                sd_bus_message **ret,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *t = NULL;
        int r;

        assert_return(bus, -ENOTCONN);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(bus->state != BUS_UNSET, -ENOTCONN);
        assert_return(!destination || service_name_is_valid(destination), -EINVAL);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(!interface || interface_name_is_valid(interface), -EINVAL);
        assert_return(member_name_is_valid(member), -EINVAL);
        assert_return(ret, -EINVAL);

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

        *ret = TAKE_PTR(t);
        return 0;
}

static int message_new_reply(
                sd_bus_message *call,
                uint8_t type,
                sd_bus_message **ret) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *t = NULL;
        uint64_t cookie;
        int r;

        assert_return(call, -EINVAL);
        assert_return(call->sealed, -EPERM);
        assert_return(call->header->type == SD_BUS_MESSAGE_METHOD_CALL, -EINVAL);
        assert_return(call->bus->state != BUS_UNSET, -ENOTCONN);
        assert_return(ret, -EINVAL);

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

        t->dont_send = FLAGS_SET(call->header->flags, BUS_MESSAGE_NO_REPLY_EXPECTED);
        t->enforced_reply_signature = call->enforced_reply_signature;

        /* let's copy the sensitive flag over. Let's do that as a safety precaution to keep a transaction
         * wholly sensitive if already the incoming message was sensitive. This is particularly useful when a
         * vtable record sets the SD_BUS_VTABLE_SENSITIVE flag on a method call, since this means it applies
         * to both the message call and the reply. */
        t->sensitive = call->sensitive;

        *ret = TAKE_PTR(t);
        return 0;
}

_public_ int sd_bus_message_new_method_return(
                sd_bus_message *call,
                sd_bus_message **ret) {

        return message_new_reply(call, SD_BUS_MESSAGE_METHOD_RETURN, ret);
}

_public_ int sd_bus_message_new_method_error(
                sd_bus_message *call,
                sd_bus_message **ret,
                const sd_bus_error *e) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *t = NULL;
        int r;

        assert_return(sd_bus_error_is_set(e), -EINVAL);
        assert_return(ret, -EINVAL);

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

        *ret = TAKE_PTR(t);
        return 0;
}

_public_ int sd_bus_message_new_method_errorf(
                sd_bus_message *call,
                sd_bus_message **ret,
                const char *name,
                const char *format,
                ...) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        va_list ap;

        assert_return(name, -EINVAL);
        assert_return(ret, -EINVAL);

        va_start(ap, format);
        sd_bus_error_setfv(&error, name, format, ap);
        va_end(ap);

        return sd_bus_message_new_method_error(call, ret, &error);
}

_public_ int sd_bus_message_new_method_errno(
                sd_bus_message *call,
                sd_bus_message **ret,
                int error,
                const sd_bus_error *p) {

        _cleanup_(sd_bus_error_free) sd_bus_error berror = SD_BUS_ERROR_NULL;

        if (sd_bus_error_is_set(p))
                return sd_bus_message_new_method_error(call, ret, p);

        sd_bus_error_set_errno(&berror, error);

        return sd_bus_message_new_method_error(call, ret, &berror);
}

_public_ int sd_bus_message_new_method_errnof(
                sd_bus_message *call,
                sd_bus_message **ret,
                int error,
                const char *format,
                ...) {

        _cleanup_(sd_bus_error_free) sd_bus_error berror = SD_BUS_ERROR_NULL;
        va_list ap;

        va_start(ap, format);
        sd_bus_error_set_errnofv(&berror, error, format, ap);
        va_end(ap);

        return sd_bus_message_new_method_error(call, ret, &berror);
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

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *t = NULL;
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

_public_ sd_bus_message* sd_bus_message_ref(sd_bus_message *m) {
        if (!m)
                return NULL;

        /* We are fine if this message so far was either explicitly reffed or not reffed but queued into at
         * least one bus connection object. */
        assert(m->n_ref > 0 || m->n_queued > 0);

        m->n_ref++;

        /* Each user reference to a bus message shall also be considered a ref on the bus */
        sd_bus_ref(m->bus);
        return m;
}

_public_ sd_bus_message* sd_bus_message_unref(sd_bus_message *m) {
        if (!m)
                return NULL;

        assert(m->n_ref > 0);

        sd_bus_unref(m->bus); /* Each regular ref is also a ref on the bus connection. Let's hence drop it
                               * here. Note we have to do this before decrementing our own n_ref here, since
                               * otherwise, if this message is currently queued sd_bus_unref() might call
                               * bus_message_unref_queued() for this which might then destroy the message
                               * while we are still processing it. */
        m->n_ref--;

        if (m->n_ref > 0 || m->n_queued > 0)
                return NULL;

        /* Unset the bus field if neither the user has a reference nor this message is queued. We are careful
         * to reset the field only after the last reference to the bus is dropped, after all we might keep
         * multiple references to the bus, once for each reference kept on ourselves. */
        m->bus = NULL;

        return message_free(m);
}

sd_bus_message* bus_message_ref_queued(sd_bus_message *m, sd_bus *bus) {
        if (!m)
                return NULL;

        /* If this is a different bus than the message is associated with, then implicitly turn this into a
         * regular reference. This means that you can create a memory leak by enqueuing a message generated
         * on one bus onto another at the same time as enqueueing a message from the second one on the first,
         * as we'll not detect the cyclic references there. */
        if (bus != m->bus)
                return sd_bus_message_ref(m);

        assert(m->n_ref > 0 || m->n_queued > 0);
        m->n_queued++;

        return m;
}

sd_bus_message* bus_message_unref_queued(sd_bus_message *m, sd_bus *bus) {
        if (!m)
                return NULL;

        if (bus != m->bus)
                return sd_bus_message_unref(m);

        assert(m->n_queued > 0);
        m->n_queued--;

        if (m->n_ref > 0 || m->n_queued > 0)
                return NULL;

        m->bus = NULL;

        return message_free(m);
}

_public_ int sd_bus_message_get_type(sd_bus_message *m, uint8_t *ret) {
        assert_return(m, -EINVAL);
        assert_return(ret, -EINVAL);

        *ret = m->header->type;
        return 0;
}

_public_ int sd_bus_message_get_cookie(sd_bus_message *m, uint64_t *ret) {
        uint64_t c;

        assert_return(m, -EINVAL);
        assert_return(ret, -EINVAL);

        c = BUS_MESSAGE_COOKIE(m);
        if (c == 0)
                return -ENODATA;

        *ret = BUS_MESSAGE_COOKIE(m);
        return 0;
}

_public_ int sd_bus_message_get_reply_cookie(sd_bus_message *m, uint64_t *ret) {
        assert_return(m, -EINVAL);
        assert_return(ret, -EINVAL);

        if (m->reply_cookie == 0)
                return -ENODATA;

        *ret = m->reply_cookie;
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

_public_ const char* sd_bus_message_get_path(sd_bus_message *m) {
        assert_return(m, NULL);

        return m->path;
}

_public_ const char* sd_bus_message_get_interface(sd_bus_message *m) {
        assert_return(m, NULL);

        return m->interface;
}

_public_ const char* sd_bus_message_get_member(sd_bus_message *m) {
        assert_return(m, NULL);

        return m->member;
}

_public_ const char* sd_bus_message_get_destination(sd_bus_message *m) {
        assert_return(m, NULL);

        return m->destination;
}

_public_ const char* sd_bus_message_get_sender(sd_bus_message *m) {
        assert_return(m, NULL);

        return m->sender;
}

_public_ const sd_bus_error* sd_bus_message_get_error(sd_bus_message *m) {
        assert_return(m, NULL);

        if (!sd_bus_error_is_set(&m->error))
                return NULL;

        return &m->error;
}

_public_ int sd_bus_message_get_monotonic_usec(sd_bus_message *m, uint64_t *ret) {
        assert_return(m, -EINVAL);
        assert_return(ret, -EINVAL);

        if (m->monotonic <= 0)
                return -ENODATA;

        *ret = m->monotonic;
        return 0;
}

_public_ int sd_bus_message_get_realtime_usec(sd_bus_message *m, uint64_t *ret) {
        assert_return(m, -EINVAL);
        assert_return(ret, -EINVAL);

        if (m->realtime <= 0)
                return -ENODATA;

        *ret = m->realtime;
        return 0;
}

_public_ int sd_bus_message_get_seqnum(sd_bus_message *m, uint64_t *ret) {
        assert_return(m, -EINVAL);
        assert_return(ret, -EINVAL);

        if (m->seqnum <= 0)
                return -ENODATA;

        *ret = m->seqnum;
        return 0;
}

_public_ sd_bus_creds* sd_bus_message_get_creds(sd_bus_message *m) {
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

static BusMessageBodyPart* message_append_part(sd_bus_message *m) {
        BusMessageBodyPart *part;

        assert(m);

        if (m->poisoned)
                return NULL;

        if (m->n_body_parts <= 0) {
                part = &m->body;
                zero(*part);
        } else {
                assert(m->body_end);

                part = new0(BusMessageBodyPart, 1);
                if (!part) {
                        m->poisoned = true;
                        return NULL;
                }

                m->body_end->next = part;
        }

        part->memfd = -EBADF;
        m->body_end = part;
        m->n_body_parts++;

        return part;
}

static void part_zero(BusMessageBodyPart *part, size_t sz) {
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
                BusMessageBodyPart *part,
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

static void message_extend_containers(sd_bus_message *m, size_t expand) {
        assert(m);

        if (expand <= 0)
                return;

        if (m->n_containers <= 0)
                return;

        /* Update counters */
        for (BusMessageContainer *c = m->containers; c < m->containers + m->n_containers; c++)
                if (c->array_size)
                        *c->array_size += expand;
}

static void* message_extend_body(
                sd_bus_message *m,
                size_t align,
                size_t sz) {

        size_t start_body, end_body, padding, added;
        void *p;
        int r;

        assert(m);
        assert(align > 0);
        assert(!m->sealed);

        if (m->poisoned)
                return NULL;

        start_body = ALIGN_TO(m->body_size, align);
        end_body = start_body + sz;

        padding = start_body - m->body_size;
        added = padding + sz;

        /* Check for 32-bit overflows */
        if (end_body < start_body || end_body > UINT32_MAX) {
                m->poisoned = true;
                return NULL;
        }

        if (added > 0) {
                BusMessageBodyPart *part = NULL;
                bool add_new_part;

                add_new_part =
                        m->n_body_parts <= 0 ||
                        m->body_end->sealed ||
                        (padding != ALIGN_TO(m->body_end->size, align) - m->body_end->size);
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
                        if (m->n_containers > 0)
                                for (BusMessageContainer *c = m->containers; c < m->containers + m->n_containers; c++)
                                        c->array_size = adjust_pointer(c->array_size, op, os, part->data);

                        m->error.message = (const char*) adjust_pointer(m->error.message, op, os, part->data);
                }
        } else
                /* Return something that is not NULL and is aligned */
                p = (uint8_t*) align;

        m->body_size = end_body;
        message_extend_containers(m, added);

        return p;
}

static int message_push_fd(sd_bus_message *m, int fd) {
        int copy;

        assert(m);

        if (fd < 0)
                return -EINVAL;

        if (!m->allow_fds)
                return -EOPNOTSUPP;

        copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (copy < 0)
                return -errno;

        if (!GREEDY_REALLOC(m->fds, m->n_fds + 1)) {
                m->poisoned = true;
                safe_close(copy);
                return -ENOMEM;
        }

        m->fds[m->n_fds] = copy; /* m->n_fds will be incremented by the caller later */
        m->free_fds = true;

        return copy;
}

int message_append_basic(sd_bus_message *m, char type, const void *p, const void **stored) {
        _cleanup_close_ int fd = -EBADF;
        BusMessageContainer *c;
        ssize_t align, sz;
        uint32_t u32;
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

                e = strextend(&c->signature, CHAR_TO_STR(type));
                if (!e) {
                        m->poisoned = true;
                        return -ENOMEM;
                }
        }

        switch (type) {

        case SD_BUS_TYPE_STRING:
                /* To make things easy we'll serialize a NULL string
                 * into the empty string */
                p = strempty(p);

                if (!utf8_is_valid(p))
                        return -EINVAL;

                align = 4;
                sz = 4 + strlen(p) + 1;
                break;

        case SD_BUS_TYPE_OBJECT_PATH:

                if (!p)
                        return -EINVAL;

                if (!object_path_is_valid(p))
                        return -EINVAL;

                align = 4;
                sz = 4 + strlen(p) + 1;
                break;

        case SD_BUS_TYPE_SIGNATURE:

                p = strempty(p);

                if (!signature_is_valid(p, /* allow_dict_entry = */ true))
                        return -EINVAL;

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
        }

        assert(align > 0);
        assert(sz > 0);

        a = message_extend_body(m, align, sz);
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

        if (type == SD_BUS_TYPE_UNIX_FD)
                m->n_fds++;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index++;

        fd = -EBADF;
        return 0;
}

_public_ int sd_bus_message_append_basic(sd_bus_message *m, char type, const void *p) {
        return message_append_basic(m, type, p, NULL);
}

_public_ int sd_bus_message_append_string_space(
                sd_bus_message *m,
                size_t size,
                char **ret) {

        BusMessageContainer *c;
        void *a;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(!m->poisoned, -ESTALE);
        assert_return(ret, -EINVAL);

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

                e = strextend(&c->signature, CHAR_TO_STR(SD_BUS_TYPE_STRING));
                if (!e) {
                        m->poisoned = true;
                        return -ENOMEM;
                }
        }

        a = message_extend_body(m, 4, 4 + size + 1);
        if (!a)
                return -ENOMEM;

        *(uint32_t*) a = size;
        *ret = (char*) a + 4;

        (*ret)[size] = 0;

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

        size = iovec_total_size(iov, n);

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
                BusMessageContainer *c,
                const char *contents,
                uint32_t **ret_array_size) {

        unsigned nindex;
        int alignment;
        void *a, *op;
        size_t os;
        BusMessageBodyPart *o;

        assert(m);
        assert(c);
        assert(contents);
        assert(ret_array_size);

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

                e = strextend(&c->signature, CHAR_TO_STR(SD_BUS_TYPE_ARRAY), contents);
                if (!e) {
                        m->poisoned = true;
                        return -ENOMEM;
                }

                nindex = e - c->signature;
        }

        alignment = bus_type_get_alignment(contents[0]);
        if (alignment < 0)
                return alignment;

        a = message_extend_body(m, 4, 4);
        if (!a)
                return -ENOMEM;

        o = m->body_end;
        op = m->body_end->data;
        os = m->body_end->size;

        /* Add alignment between size and first element */
        if (!message_extend_body(m, alignment, 0))
                return -ENOMEM;

        /* location of array size might have changed so let's readjust a */
        if (o == m->body_end)
                a = adjust_pointer(a, op, os, m->body_end->data);

        *(uint32_t*) a = 0;
        *ret_array_size = a;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index = nindex;

        return 0;
}

static int bus_message_open_variant(
                sd_bus_message *m,
                BusMessageContainer *c,
                const char *contents) {

        size_t l;
        void *a;

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

                e = strextend(&c->signature, CHAR_TO_STR(SD_BUS_TYPE_VARIANT));
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
                BusMessageContainer *c,
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

                e = strextend(&c->signature, CHAR_TO_STR(SD_BUS_TYPE_STRUCT_BEGIN), contents, CHAR_TO_STR(SD_BUS_TYPE_STRUCT_END));
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
                BusMessageContainer *c,
                const char *contents) {

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
        } else
                return -ENXIO;

        /* Align contents to 8 byte boundary */
        if (!message_extend_body(m, 8, 0))
                return -ENOMEM;

        return 0;
}

_public_ int sd_bus_message_open_container(
                sd_bus_message *m,
                char type,
                const char *contents) {

        BusMessageContainer *c;
        uint32_t *array_size = NULL;
        _cleanup_free_ char *signature = NULL;
        size_t before;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(contents, -EINVAL);
        assert_return(!m->poisoned, -ESTALE);

        /* Make sure we have space for one more container */
        if (!GREEDY_REALLOC(m->containers, m->n_containers + 1)) {
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
                r = bus_message_open_array(m, c, contents, &array_size);
        else if (type == SD_BUS_TYPE_VARIANT)
                r = bus_message_open_variant(m, c, contents);
        else if (type == SD_BUS_TYPE_STRUCT)
                r = bus_message_open_struct(m, c, contents);
        else if (type == SD_BUS_TYPE_DICT_ENTRY)
                r = bus_message_open_dict_entry(m, c, contents);
        else
                r = -EINVAL;
        if (r < 0)
                return r;

        /* OK, let's fill it in */
        m->containers[m->n_containers++] = (BusMessageContainer) {
                .enclosing = type,
                .signature = TAKE_PTR(signature),
                .array_size = array_size,
                .before = before,
        };

        return 0;
}

_public_ int sd_bus_message_close_container(sd_bus_message *m) {
        BusMessageContainer *c;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(m->n_containers > 0, -EINVAL);
        assert_return(!m->poisoned, -ESTALE);

        c = message_get_last_container(m);

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                if (c->signature && c->signature[c->index] != 0)
                        return -EINVAL;

        m->n_containers--;

        free(c->signature);

        return 0;
}

typedef struct BusTypeStack {
        const char *types;
        unsigned n_struct;
        unsigned n_array;
} BusTypeStack;

static int type_stack_push(
                BusTypeStack *stack,
                unsigned max,
                unsigned *i,
                const char *types,
                unsigned n_struct,
                unsigned n_array) {

        assert(stack);
        assert(max > 0);
        assert(i);

        if (*i >= max)
                return -EINVAL;

        stack[*i].types = types;
        stack[*i].n_struct = n_struct;
        stack[*i].n_array = n_array;
        (*i)++;

        return 0;
}

static int type_stack_pop(
                BusTypeStack *stack,
                unsigned max,
                unsigned *i,
                const char **ret_types,
                unsigned *ret_n_struct,
                unsigned *ret_n_array) {

        assert(stack);
        assert(max > 0);
        assert(i);
        assert(ret_types);
        assert(ret_n_struct);
        assert(ret_n_array);

        if (*i <= 0)
                return 0;

        (*i)--;
        *ret_types = stack[*i].types;
        *ret_n_struct = stack[*i].n_struct;
        *ret_n_array = stack[*i].n_array;

        return 1;
}

_public_ int sd_bus_message_appendv(
                sd_bus_message *m,
                const char *types,
                va_list ap) {

        unsigned n_array, n_struct;
        BusTypeStack stack[BUS_CONTAINER_DEPTH];
        unsigned stack_ptr = 0;
        int r;

        assert_return(m, -EINVAL);
        assert_return(types, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(!m->poisoned, -ESTALE);

        n_array = UINT_MAX;
        n_struct = strlen(types);

        for (;;) {
                const char *t;

                if (n_array == 0 || (n_array == UINT_MAX && n_struct == 0)) {
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
                if (n_array != UINT_MAX)
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

                        if (n_array == UINT_MAX) {
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
                        n_array = UINT_MAX;

                        break;
                }

                case SD_BUS_TYPE_STRUCT_BEGIN:
                case SD_BUS_TYPE_DICT_ENTRY_BEGIN: {
                        size_t k;

                        r = signature_element_length(t, &k);
                        if (r < 0)
                                return r;
                        if (k < 2)
                                return -ERANGE;

                        {
                                char s[k - 1];

                                memcpy(s, t + 1, k - 2);
                                s[k - 2] = 0;

                                r = sd_bus_message_open_container(m, *t == SD_BUS_TYPE_STRUCT_BEGIN ? SD_BUS_TYPE_STRUCT : SD_BUS_TYPE_DICT_ENTRY, s);
                                if (r < 0)
                                        return r;
                        }

                        if (n_array == UINT_MAX) {
                                types += k - 1;
                                n_struct -= k - 1;
                        }

                        r = type_stack_push(stack, ELEMENTSOF(stack), &stack_ptr, types, n_struct, n_array);
                        if (r < 0)
                                return r;

                        types = t + 1;
                        n_struct = k - 2;
                        n_array = UINT_MAX;

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
                void **ret) {

        ssize_t align, sz;
        void *a;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(bus_type_is_trivial(type) && type != SD_BUS_TYPE_BOOLEAN, -EINVAL);
        assert_return(ret || size == 0, -EINVAL);
        assert_return(!m->poisoned, -ESTALE);

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

        *ret = a;
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

        size = iovec_total_size(iov, n);

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

        _cleanup_close_ int copy_fd = -EBADF;
        BusMessageBodyPart *part;
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

        if (offset == 0 && size == UINT64_MAX)
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

        if (size > (uint64_t) UINT32_MAX)
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
        part->memfd_offset = offset;
        part->sealed = true;
        part->size = size;
        copy_fd = -EBADF;

        m->body_size += size;
        message_extend_containers(m, size);

        return sd_bus_message_close_container(m);
}

_public_ int sd_bus_message_append_string_memfd(
                sd_bus_message *m,
                int memfd,
                uint64_t offset,
                uint64_t size) {

        _cleanup_close_ int copy_fd = -EBADF;
        BusMessageBodyPart *part;
        BusMessageContainer *c;
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

        if (offset == 0 && size == UINT64_MAX)
                size = real_size;
        else if (offset + size > real_size)
                return -EMSGSIZE;

        /* We require this to be NUL terminated */
        if (size == 0)
                return -EINVAL;

        if (size > (uint64_t) UINT32_MAX)
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

                e = strextend(&c->signature, CHAR_TO_STR(SD_BUS_TYPE_STRING));
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
        part->memfd_offset = offset;
        part->sealed = true;
        part->size = size;
        copy_fd = -EBADF;

        m->body_size += size;
        message_extend_containers(m, size);

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index++;

        return 0;
}

_public_ int sd_bus_message_append_strv(sd_bus_message *m, char **l) {
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

        /* The actual user data is finished now, we just complete the variant and struct now. Remember
         * this position, so that during parsing we know where to put the outer container end. */
        m->user_body_size = m->body_size;

        m->header->fields_size = m->fields_size;
        m->header->body_size = m->body_size;

        return 0;
}

_public_ int sd_bus_message_seal(sd_bus_message *m, uint64_t cookie, uint64_t timeout_usec) {
        BusMessageBodyPart *part;
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

        if (cookie > UINT32_MAX)
                return -EOPNOTSUPP;

        /* In vtables the return signature of method calls is listed,
         * let's check if they match if this is a response */
        if (m->header->type == SD_BUS_MESSAGE_METHOD_RETURN &&
            m->enforced_reply_signature &&
            !streq(strempty(m->root_container.signature), m->enforced_reply_signature))
                return -ENOMSG;

        /* If there's a non-trivial signature set, then add it in here */
        if (!isempty(m->root_container.signature)) {
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

        m->header->serial = (uint32_t) cookie;

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

        m->sealed = true;

        return 0;
}

int bus_body_part_map(BusMessageBodyPart *part) {
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

        shift = PAGE_OFFSET(part->memfd_offset);
        psz = PAGE_ALIGN(part->size + shift);
        if (psz >= SIZE_MAX)
                return -EFBIG;

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

void bus_body_part_unmap(BusMessageBodyPart *part) {

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

static bool message_end_of_signature(sd_bus_message *m) {
        BusMessageContainer *c;

        assert(m);

        c = message_get_last_container(m);
        return !c->signature || c->signature[c->index] == 0;
}

static bool message_end_of_array(sd_bus_message *m, size_t index) {
        BusMessageContainer *c;

        assert(m);

        c = message_get_last_container(m);
        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                return false;

        assert(c->array_size);
        return index >= c->begin + BUS_MESSAGE_BSWAP32(m, *c->array_size);
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

static BusMessageBodyPart* find_part(sd_bus_message *m, size_t index, size_t sz, void **ret) {
        BusMessageBodyPart *part;
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

                        if (ret)
                                *ret = part->data ? (uint8_t*) part->data + index - begin
                                        : NULL; /* Avoid dereferencing a NULL pointer. */

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
        BusMessageBodyPart *part;
        uint8_t *q;

        assert(m);
        assert(rindex);
        assert(align > 0);

        start = ALIGN_TO(*rindex, align);
        if (start > m->user_body_size)
                return -EBADMSG;

        padding = start - *rindex;

        /* Avoid overflow below */
        if (nbytes > SIZE_MAX - start)
                return -EBADMSG;

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

_public_ int sd_bus_message_read_basic(sd_bus_message *m, char type, void *ret) {
        BusMessageContainer *c;
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

                if (ret)
                        *(const char**) ret = q;

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

                if (ret)
                        *(const char**) ret = q;

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
                        if (ret)
                                *(uint8_t*) ret = *(uint8_t*) q;
                        break;

                case SD_BUS_TYPE_BOOLEAN:
                        if (ret)
                                *(int*) ret = !!*(uint32_t*) q;
                        break;

                case SD_BUS_TYPE_INT16:
                case SD_BUS_TYPE_UINT16:
                        if (ret)
                                *(uint16_t*) ret = BUS_MESSAGE_BSWAP16(m, *(uint16_t*) q);
                        break;

                case SD_BUS_TYPE_INT32:
                case SD_BUS_TYPE_UINT32:
                        if (ret)
                                *(uint32_t*) ret = BUS_MESSAGE_BSWAP32(m, *(uint32_t*) q);
                        break;

                case SD_BUS_TYPE_INT64:
                case SD_BUS_TYPE_UINT64:
                case SD_BUS_TYPE_DOUBLE:
                        if (ret)
                                *(uint64_t*) ret = BUS_MESSAGE_BSWAP64(m, *(uint64_t*) q);
                        break;

                case SD_BUS_TYPE_UNIX_FD: {
                        uint32_t j;

                        j = BUS_MESSAGE_BSWAP32(m, *(uint32_t*) q);
                        if (j >= m->n_fds)
                                return -EBADMSG;

                        if (ret)
                                *(int*) ret = m->fds[j];
                        break;
                }

                default:
                        assert_not_reached();
                }
        }

        m->rindex = rindex;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index++;

        return 1;
}

static int bus_message_enter_array(
                sd_bus_message *m,
                BusMessageContainer *c,
                const char *contents,
                uint32_t **ret_array_size) {

        size_t rindex;
        void *q;
        int alignment, r;

        assert(m);
        assert(c);
        assert(contents);
        assert(ret_array_size);

        if (!signature_is_single(contents, true))
                return -EINVAL;

        if (!c->signature || c->signature[c->index] == 0)
                return -ENXIO;

        if (c->signature[c->index] != SD_BUS_TYPE_ARRAY)
                return -ENXIO;

        if (!startswith(c->signature + c->index + 1, contents))
                return -ENXIO;

        rindex = m->rindex;

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

        *ret_array_size = (uint32_t*) q;

        m->rindex = rindex;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index += 1 + strlen(contents);

        return 1;
}

static int bus_message_enter_variant(
                sd_bus_message *m,
                BusMessageContainer *c,
                const char *contents) {

        size_t rindex;
        uint8_t l;
        void *q;
        int r;

        assert(m);
        assert(c);
        assert(contents);

        if (!signature_is_single(contents, false))
                return -EINVAL;

        if (*contents == SD_BUS_TYPE_DICT_ENTRY_BEGIN)
                return -EINVAL;

        if (!c->signature || c->signature[c->index] == 0)
                return -ENXIO;

        if (c->signature[c->index] != SD_BUS_TYPE_VARIANT)
                return -ENXIO;

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

        if (!streq(q, contents))
                return -ENXIO;

        m->rindex = rindex;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index++;

        return 1;
}

static int bus_message_enter_struct(
                sd_bus_message *m,
                BusMessageContainer *c,
                const char *contents) {

        size_t l;
        int r;

        assert(m);
        assert(c);
        assert(contents);

        if (!signature_is_valid(contents, false))
                return -EINVAL;

        if (!c->signature || c->signature[c->index] == 0)
                return -ENXIO;

        l = strlen(contents);

        if (c->signature[c->index] != SD_BUS_TYPE_STRUCT_BEGIN ||
            !startswith(c->signature + c->index + 1, contents) ||
            c->signature[c->index + 1 + l] != SD_BUS_TYPE_STRUCT_END)
                return -ENXIO;

        r = message_peek_body(m, &m->rindex, 8, 0, NULL);
        if (r < 0)
                return r;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index += 1 + l + 1;

        return 1;
}

static int bus_message_enter_dict_entry(
                sd_bus_message *m,
                BusMessageContainer *c,
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
        if (r < 0)
                return r;

        if (c->enclosing != SD_BUS_TYPE_ARRAY)
                c->index += 1 + l + 1;

        return 1;
}

_public_ int sd_bus_message_enter_container(
                sd_bus_message *m,
                char type,
                const char *contents) {

        BusMessageContainer *c;
        uint32_t *array_size = NULL;
        _cleanup_free_ char *signature = NULL;
        size_t before;
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

        if (!GREEDY_REALLOC(m->containers, m->n_containers + 1))
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
                r = bus_message_enter_array(m, c, contents, &array_size);
        else if (type == SD_BUS_TYPE_VARIANT)
                r = bus_message_enter_variant(m, c, contents);
        else if (type == SD_BUS_TYPE_STRUCT)
                r = bus_message_enter_struct(m, c, contents);
        else if (type == SD_BUS_TYPE_DICT_ENTRY)
                r = bus_message_enter_dict_entry(m, c, contents);
        else
                r = -EINVAL;
        if (r <= 0)
                return r;

        /* OK, let's fill it in */
        m->containers[m->n_containers++] = (BusMessageContainer) {
                 .enclosing = type,
                 .signature = TAKE_PTR(signature),

                 .before = before,
                 .begin = m->rindex,
                 /* Unary type has fixed size of 1, but virtual size of 0 */
                 .end = m->rindex,
                 .array_size = array_size,
        };

        return 1;
}

_public_ int sd_bus_message_exit_container(sd_bus_message *m) {
        BusMessageContainer *c;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);
        assert_return(m->n_containers > 0, -ENXIO);

        c = message_get_last_container(m);

        if (c->enclosing != SD_BUS_TYPE_ARRAY) {
                if (c->signature && c->signature[c->index] != 0)
                        return -EBUSY;
        }

        if (c->enclosing == SD_BUS_TYPE_ARRAY) {
                uint32_t l;

                l = BUS_MESSAGE_BSWAP32(m, *c->array_size);
                if (c->begin + l != m->rindex)
                        return -EBUSY;
        }

        message_free_last_container(m);

        return 1;
}

static void message_quit_container(sd_bus_message *m) {
        BusMessageContainer *c;

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

_public_ int sd_bus_message_peek_type(sd_bus_message *m, char *ret_type, const char **ret_contents) {
        BusMessageContainer *c;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);

        if (message_end_of_signature(m))
                goto eof;

        if (message_end_of_array(m, m->rindex))
                goto eof;

        c = message_get_last_container(m);

        if (bus_type_is_basic(c->signature[c->index])) {
                if (ret_contents)
                        *ret_contents = NULL;
                if (ret_type)
                        *ret_type = c->signature[c->index];
                return 1;
        }

        if (c->signature[c->index] == SD_BUS_TYPE_ARRAY) {

                if (ret_contents) {
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

                        *ret_contents = c->peeked_signature;
                }

                if (ret_type)
                        *ret_type = SD_BUS_TYPE_ARRAY;

                return 1;
        }

        if (IN_SET(c->signature[c->index], SD_BUS_TYPE_STRUCT_BEGIN, SD_BUS_TYPE_DICT_ENTRY_BEGIN)) {

                if (ret_contents) {
                        size_t l;

                        r = signature_element_length(c->signature+c->index, &l);
                        if (r < 0)
                                return r;

                        assert(l >= 3);
                        if (free_and_strndup(&c->peeked_signature,
                                             c->signature + c->index + 1, l - 2) < 0)
                                return -ENOMEM;

                        *ret_contents = c->peeked_signature;
                }

                if (ret_type)
                        *ret_type = c->signature[c->index] == SD_BUS_TYPE_STRUCT_BEGIN ? SD_BUS_TYPE_STRUCT : SD_BUS_TYPE_DICT_ENTRY;

                return 1;
        }

        if (c->signature[c->index] == SD_BUS_TYPE_VARIANT) {
                if (ret_contents) {
                        size_t rindex, l;
                        void *q;

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

                        *ret_contents = q;
                }

                if (ret_type)
                        *ret_type = SD_BUS_TYPE_VARIANT;

                return 1;
        }

        return -EINVAL;

eof:
        if (ret_type)
                *ret_type = 0;
        if (ret_contents)
                *ret_contents = NULL;
        return 0;
}

_public_ int sd_bus_message_rewind(sd_bus_message *m, int complete) {
        BusMessageContainer *c;

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

        return !isempty(c->signature);
}

_public_ int sd_bus_message_readv(
                sd_bus_message *m,
                const char *types,
                va_list ap) {

        unsigned n_array, n_struct;
        BusTypeStack stack[BUS_CONTAINER_DEPTH];
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

        n_array = UINT_MAX; /* length of current array entries */
        n_struct = strlen(types); /* length of current struct contents signature */

        for (;;) {
                const char *t;

                n_loop++;

                if (n_array == 0 || (n_array == UINT_MAX && n_struct == 0)) {
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
                if (n_array != UINT_MAX)
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

                        if (n_array == UINT_MAX) {
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
                        n_array = UINT_MAX;

                        break;
                }

                case SD_BUS_TYPE_STRUCT_BEGIN:
                case SD_BUS_TYPE_DICT_ENTRY_BEGIN: {
                        size_t k;

                        r = signature_element_length(t, &k);
                        if (r < 0)
                                return r;
                        if (k < 2)
                                return -ERANGE;

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

                        if (n_array == UINT_MAX) {
                                types += k - 1;
                                n_struct -= k - 1;
                        }

                        r = type_stack_push(stack, ELEMENTSOF(stack), &stack_ptr, types, n_struct, n_array);
                        if (r < 0)
                                return r;

                        types = t + 1;
                        n_struct = k - 2;
                        n_array = UINT_MAX;

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
                BusMessageContainer *c;
                size_t l;

                if (message_end_of_signature(m))
                        return -ENXIO;

                if (message_end_of_array(m, m->rindex))
                        return 0;

                c = message_get_last_container(m);

                r = signature_element_length(c->signature + c->index, &l);
                if (r < 0)
                        return r;

                types = strndupa_safe(c->signature + c->index, l);
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
                if (k < 2)
                        return -ERANGE;

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
                const void **ret_ptr,
                size_t *ret_size) {

        BusMessageContainer *c;
        void *p;
        size_t sz;
        ssize_t align;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);
        assert_return(bus_type_is_trivial(type), -EINVAL);
        assert_return(ret_ptr, -EINVAL);
        assert_return(ret_size, -EINVAL);
        assert_return(!BUS_MESSAGE_NEED_BSWAP(m), -EOPNOTSUPP);

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, CHAR_TO_STR(type));
        if (r < 0)
                return r;
        if (r == 0) {
                *ret_ptr = NULL;
                *ret_size = 0;
                return 0;
        }

        c = message_get_last_container(m);

        align = bus_type_get_alignment(type);
        if (align < 0)
                return align;

        sz = BUS_MESSAGE_BSWAP32(m, *c->array_size);

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

        *ret_ptr = (const void*) p;
        *ret_size = sz;

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

        size_t start, end;

        assert(m);
        assert(rindex);
        assert(align > 0);

        start = ALIGN_TO(*rindex, align);
        if (start > m->fields_size)
                return -EBADMSG;

        /* Avoid overflow below */
        if (nbytes > SIZE_MAX - start)
                return -EBADMSG;

        end = start + nbytes;
        if (end > m->fields_size)
                return -EBADMSG;

        /* Verify that padding is 0 */
        uint8_t *p = BUS_MESSAGE_FIELDS(m);
        for (size_t k = *rindex; k < start; k++)
                if (p[k] != 0)
                        return -EBADMSG;

        if (ret)
                *ret = p + start;

        *rindex = end;
        return 1;
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
                size_t item_size,
                const char **ret) {

        uint32_t l;
        int r;
        void *q;

        assert(m);
        assert(ri);

        r = message_peek_field_uint32(m, ri, 4, &l);
        if (r < 0)
                return r;

        if (l == UINT32_MAX)
                /* avoid overflow right below */
                return -EBADMSG;

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
                size_t item_size,
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
        if (l == UINT8_MAX)
                /* avoid overflow right below */
                return -EBADMSG;

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

                if (array_size != UINT32_MAX &&
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

                        r = message_skip_fields(m, ri, UINT32_MAX, (const char**) &s);
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

                                r = message_skip_fields(m, ri, UINT32_MAX, (const char**) &s);
                                if (r < 0)
                                        return r;
                        }

                        *signature += l;
                } else
                        return -EBADMSG;
        }
}

static int message_parse_fields(sd_bus_message *m) {
        uint32_t unix_fds = 0;
        bool unix_fds_set = false;
        int r;

        assert(m);

        m->user_body_size = m->body_size;

        for (size_t ri = 0; ri < m->fields_size; ) {
                const char *signature;
                uint64_t field_type;
                size_t item_size = SIZE_MAX;
                uint8_t *u8;

                r = message_peek_fields(m, &ri, 8, 1, (void**) &u8);
                if (r < 0)
                        return r;

                field_type = *u8;

                r = message_peek_field_signature(m, &ri, 0, &signature);
                if (r < 0)
                        return r;

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

                case BUS_MESSAGE_HEADER_REPLY_SERIAL: {
                        uint32_t serial;

                        if (m->reply_cookie != 0)
                                return -EBADMSG;

                        if (!streq(signature, "u"))
                                return -EBADMSG;

                        r = message_peek_field_uint32(m, &ri, item_size, &serial);
                        if (r < 0)
                                return r;

                        m->reply_cookie = serial;

                        if (m->reply_cookie == 0)
                                return -EBADMSG;

                        break;
                }
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
                        r = message_skip_fields(m, &ri, UINT32_MAX, (const char **) &signature);
                }
                if (r < 0)
                        return r;
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
        BusMessageBodyPart *part;

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

_public_ int sd_bus_message_read_strv_extend(sd_bus_message *m, char ***l) {
        char type;
        const char *contents, *s;
        int r;

        assert(m);
        assert(l);

        r = sd_bus_message_peek_type(m, &type, &contents);
        if (r < 0)
                return r;

        if (type != SD_BUS_TYPE_ARRAY || !STR_IN_SET(contents, "s", "o", "g"))
                return -ENXIO;

        r = sd_bus_message_enter_container(m, 'a', NULL);
        if (r <= 0)
                return r;

        /* sd_bus_message_read_basic() does content validation for us. */
        while ((r = sd_bus_message_read_basic(m, *contents, &s)) > 0) {
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

_public_ int sd_bus_message_read_strv(sd_bus_message *m, char ***ret) {
        _cleanup_strv_free_ char **strv = NULL;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);
        assert_return(ret, -EINVAL);

        r = sd_bus_message_read_strv_extend(m, &strv);
        if (r <= 0)
                return r;

        *ret = TAKE_PTR(strv);
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
        BusMessageContainer *c;

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

_public_ sd_bus* sd_bus_message_get_bus(sd_bus_message *m) {
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

_public_ int sd_bus_message_get_priority(sd_bus_message *m, int64_t *ret) {
        static bool warned = false;

        assert_return(m, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!warned) {
                log_debug("sd_bus_message_get_priority() is deprecated and always returns 0.");
                warned = true;
        }

        *ret = 0;
        return 0;
}

_public_ int sd_bus_message_set_priority(sd_bus_message *m, int64_t priority) {
        static bool warned = false;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        if (!warned) {
                log_debug("sd_bus_message_set_priority() is deprecated and does nothing.");
                warned = true;
        }

        return 0;
}

_public_ int sd_bus_message_sensitive(sd_bus_message *m) {
        assert_return(m, -EINVAL);

        m->sensitive = true;
        return 0;
}

char** bus_message_make_log_fields(sd_bus_message *m) {
        _cleanup_strv_free_ char **strv = NULL;

        assert(m);

        (void) strv_extend_assignment(&strv, "DBUS_MESSAGE_TYPE", bus_message_type_to_string(m->header->type));
        (void) strv_extend_assignment(&strv, "DBUS_SENDER", sd_bus_message_get_sender(m));
        (void) strv_extend_assignment(&strv, "DBUS_DESTINATION", sd_bus_message_get_destination(m));
        (void) strv_extend_assignment(&strv, "DBUS_PATH", sd_bus_message_get_path(m));
        (void) strv_extend_assignment(&strv, "DBUS_INTERFACE", sd_bus_message_get_interface(m));
        (void) strv_extend_assignment(&strv, "DBUS_MEMBER", sd_bus_message_get_member(m));

        (void) strv_extendf(&strv, "DBUS_MESSAGE_COOKIE=%" PRIu64, BUS_MESSAGE_COOKIE(m));
        if (m->reply_cookie != 0)
                (void) strv_extendf(&strv, "DBUS_MESSAGE_REPLY_COOKIE=%" PRIu64, m->reply_cookie);

        (void) strv_extend_assignment(&strv, "DBUS_SIGNATURE", m->root_container.signature);
        (void) strv_extend_assignment(&strv, "DBUS_ERROR_NAME", m->error.name);
        (void) strv_extend_assignment(&strv, "DBUS_ERROR_MESSAGE", m->error.message);

        return TAKE_PTR(strv);
}
