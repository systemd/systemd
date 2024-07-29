/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "escape.h"
#include "hexdecoct.h"
#include "string-util.h"

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

                        good = ascii_isalpha(*q) ||
                                ascii_isdigit(*q) ||
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
                                ascii_isalpha(*q) ||
                                (!dot && ascii_isdigit(*q)) ||
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
                                ascii_isalpha(*q) ||
                                ((!dot || unique) && ascii_isdigit(*q)) ||
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
                        ascii_isalpha(*q) ||
                        ascii_isdigit(*q) ||
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

const char* bus_message_type_to_string(uint8_t u) {
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

char* bus_address_escape(const char *v) {
        const char *a;
        char *r, *b;

        r = new(char, strlen(v)*3+1);
        if (!r)
                return NULL;

        for (a = v, b = r; *a; a++) {

                if (ascii_isdigit(*a) ||
                    ascii_isalpha(*a) ||
                    strchr("_-/.", *a))
                        *(b++) = *a;
                else {
                        *(b++) = '%';
                        *(b++) = hexchar(*a >> 4);
                        *(b++) = hexchar(*a & 0xF);
                }
        }

        *b = 0;
        return r;
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
