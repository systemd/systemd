/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-error-util.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-signature.h"
#include "bus-type.h"
#include "escape.h"
#include "hexdecoct.h"
#include "io-util.h"
#include "string-util.h"
#include "strv.h"

bool object_path_is_valid(const char *p) {
        const char *q;
        bool slash;

        if (!p)
                return false;

        if (p[0] != '/')
                return false;

        if (p[1] == 0)
                return true;

        for (slash = true, q = p+1; *q; q++)
                if (*q == '/') {
                        if (slash)
                                return false;

                        slash = true;
                } else {
                        bool good;

                        good =
                                (*q >= 'a' && *q <= 'z') ||
                                (*q >= 'A' && *q <= 'Z') ||
                                (*q >= '0' && *q <= '9') ||
                                *q == '_';

                        if (!good)
                                return false;

                        slash = false;
                }

        if (slash)
                return false;

        return (q - p) <= BUS_PATH_SIZE_MAX;
}

char* object_path_startswith(const char *a, const char *b) {
        const char *p;

        if (!object_path_is_valid(a) ||
            !object_path_is_valid(b))
                return NULL;

        if (streq(b, "/"))
                return (char*) a + 1;

        p = startswith(a, b);
        if (!p)
                return NULL;

        if (*p == 0)
                return (char*) p;

        if (*p == '/')
                return (char*) p + 1;

        return NULL;
}

bool interface_name_is_valid(const char *p) {
        const char *q;
        bool dot, found_dot = false;

        if (isempty(p))
                return false;

        for (dot = true, q = p; *q; q++)
                if (*q == '.') {
                        if (dot)
                                return false;

                        found_dot = dot = true;
                } else {
                        bool good;

                        good =
                                (*q >= 'a' && *q <= 'z') ||
                                (*q >= 'A' && *q <= 'Z') ||
                                (!dot && *q >= '0' && *q <= '9') ||
                                *q == '_';

                        if (!good) {
                                if (DEBUG_LOGGING) {
                                        _cleanup_free_ char *iface = cescape(p);
                                        log_debug("The interface %s is invalid as it contains special character", strnull(iface));
                                }
                                return false;
                        }

                        dot = false;
                }

        if (q - p > SD_BUS_MAXIMUM_NAME_LENGTH)
                return false;

        if (dot)
                return false;

        if (!found_dot)
                return false;

        return true;
}

bool service_name_is_valid(const char *p) {
        const char *q;
        bool dot, found_dot = false, unique;

        if (isempty(p))
                return false;

        unique = p[0] == ':';

        for (dot = true, q = unique ? p+1 : p; *q; q++)
                if (*q == '.') {
                        if (dot)
                                return false;

                        found_dot = dot = true;
                } else {
                        bool good;

                        good =
                                (*q >= 'a' && *q <= 'z') ||
                                (*q >= 'A' && *q <= 'Z') ||
                                ((!dot || unique) && *q >= '0' && *q <= '9') ||
                                IN_SET(*q, '_', '-');

                        if (!good)
                                return false;

                        dot = false;
                }

        if (q - p > SD_BUS_MAXIMUM_NAME_LENGTH)
                return false;

        if (dot)
                return false;

        if (!found_dot)
                return false;

        return true;
}

bool member_name_is_valid(const char *p) {
        const char *q;

        if (isempty(p))
                return false;

        for (q = p; *q; q++) {
                bool good;

                good =
                        (*q >= 'a' && *q <= 'z') ||
                        (*q >= 'A' && *q <= 'Z') ||
                        (*q >= '0' && *q <= '9') ||
                        *q == '_';

                if (!good)
                        return false;
        }

        if (q - p > SD_BUS_MAXIMUM_NAME_LENGTH)
                return false;

        return true;
}

/*
 * Complex pattern match
 * This checks whether @a is a 'complex-prefix' of @b, or @b is a
 * 'complex-prefix' of @a, based on strings that consist of labels with @c as
 * separator. This function returns true if:
 *   - both strings are equal
 *   - either is a prefix of the other and ends with @c
 * The second rule makes sure that either string needs to be fully included in
 * the other, and the string which is considered the prefix needs to end with a
 * separator.
 */
static bool complex_pattern_check(char c, const char *a, const char *b) {
        bool separator = false;

        if (!a && !b)
                return true;

        if (!a || !b)
                return false;

        for (;;) {
                if (*a != *b)
                        return (separator && (*a == 0 || *b == 0));

                if (*a == 0)
                        return true;

                separator = *a == c;

                a++, b++;
        }
}

bool namespace_complex_pattern(const char *pattern, const char *value) {
        return complex_pattern_check('.', pattern, value);
}

bool path_complex_pattern(const char *pattern, const char *value) {
        return complex_pattern_check('/', pattern, value);
}

/*
 * Simple pattern match
 * This checks whether @a is a 'simple-prefix' of @b, based on strings that
 * consist of labels with @c as separator. This function returns true, if:
 *   - if @a and @b are equal
 *   - if @a is a prefix of @b, and the first following character in @b (or the
 *     last character in @a) is @c
 * The second rule basically makes sure that if @a is a prefix of @b, then @b
 * must follow with a new label separated by @c. It cannot extend the label.
 */
static bool simple_pattern_check(char c, const char *a, const char *b) {
        bool separator = false;

        if (!a && !b)
                return true;

        if (!a || !b)
                return false;

        for (;;) {
                if (*a != *b)
                        return *a == 0 && (*b == c || separator);

                if (*a == 0)
                        return true;

                separator = *a == c;

                a++, b++;
        }
}

bool namespace_simple_pattern(const char *pattern, const char *value) {
        return simple_pattern_check('.', pattern, value);
}

bool path_simple_pattern(const char *pattern, const char *value) {
        return simple_pattern_check('/', pattern, value);
}

int bus_message_type_from_string(const char *s, uint8_t *u) {
        if (streq(s, "signal"))
                *u = SD_BUS_MESSAGE_SIGNAL;
        else if (streq(s, "method_call"))
                *u = SD_BUS_MESSAGE_METHOD_CALL;
        else if (streq(s, "error"))
                *u = SD_BUS_MESSAGE_METHOD_ERROR;
        else if (streq(s, "method_return"))
                *u = SD_BUS_MESSAGE_METHOD_RETURN;
        else
                return -EINVAL;

        return 0;
}

const char *bus_message_type_to_string(uint8_t u) {
        if (u == SD_BUS_MESSAGE_SIGNAL)
                return "signal";
        else if (u == SD_BUS_MESSAGE_METHOD_CALL)
                return "method_call";
        else if (u == SD_BUS_MESSAGE_METHOD_ERROR)
                return "error";
        else if (u == SD_BUS_MESSAGE_METHOD_RETURN)
                 return "method_return";
        else
                return NULL;
}

int bus_maybe_reply_error(sd_bus_message *m, int r, sd_bus_error *error) {
        assert(m);

        if (sd_bus_error_is_set(error) || r < 0) {
                if (m->header->type == SD_BUS_MESSAGE_METHOD_CALL)
                        sd_bus_reply_method_errno(m, r, error);
        } else
                return r;

        log_debug("Failed to process message type=%s sender=%s destination=%s path=%s interface=%s member=%s cookie=%" PRIu64 " reply_cookie=%" PRIu64 " signature=%s error-name=%s error-message=%s: %s",
                  bus_message_type_to_string(m->header->type),
                  strna(sd_bus_message_get_sender(m)),
                  strna(sd_bus_message_get_destination(m)),
                  strna(sd_bus_message_get_path(m)),
                  strna(sd_bus_message_get_interface(m)),
                  strna(sd_bus_message_get_member(m)),
                  BUS_MESSAGE_COOKIE(m),
                  m->reply_cookie,
                  strna(m->root_container.signature),
                  strna(m->error.name),
                  strna(m->error.message),
                  bus_error_message(error, r));

        return 1;
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
                if (!message_validate_nul(q, l))
                        return -EBADMSG;

                if (!validate(q))
                        return -EBADMSG;
        } else {
                if (!message_validate_string(q, l))
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

        if (!message_validate_signature(q, l))
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

static int message_from_header(
                sd_bus *bus,
                void *buffer,
                size_t message_size,
                int *fds,
                size_t n_fds,
                const char *label,
                sd_bus_message **ret) {

        _cleanup_free_ sd_bus_message *m = NULL;
        struct bus_header *h;
        size_t a, label_sz = 0; /* avoid false maybe-uninitialized warning */

        assert(bus);
        assert(buffer || message_size <= 0);
        assert(fds || n_fds <= 0);
        assert(ret);

        if (message_size < sizeof(struct bus_header))
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

        m->sealed = true;
        m->header = buffer;

        if (h->serial == 0)
                return -EBADMSG;

        m->fields_size = BUS_MESSAGE_BSWAP32(m, h->fields_size);
        m->body_size = BUS_MESSAGE_BSWAP32(m, h->body_size);

        assert(message_size >= sizeof(struct bus_header));
        if (ALIGN8(m->fields_size) > message_size - sizeof(struct bus_header) ||
            m->body_size != message_size - sizeof(struct bus_header) - ALIGN8(m->fields_size))
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
