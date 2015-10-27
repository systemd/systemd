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

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-message.h"
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

        return true;
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

                        if (!good)
                                return false;

                        dot = false;
                }

        if (q - p > 255)
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
                                *q == '_' || *q == '-';

                        if (!good)
                                return false;

                        dot = false;
                }

        if (q - p > 255)
                return false;

        if (dot)
                return false;

        if (!found_dot)
                return false;

        return true;
}

char* service_name_startswith(const char *a, const char *b) {
        const char *p;

        if (!service_name_is_valid(a) ||
            !service_name_is_valid(b))
                return NULL;

        p = startswith(a, b);
        if (!p)
                return NULL;

        if (*p == 0)
                return (char*) p;

        if (*p == '.')
                return (char*) p + 1;

        return NULL;
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

        if (q - p > 255)
                return false;

        return true;
}

/*
 * Complex pattern match
 * This checks whether @a is a 'complex-prefix' of @b, or @b is a
 * 'complex-prefix' of @a, based on strings that consist of labels with @c as
 * spearator. This function returns true if:
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

char *bus_address_escape(const char *v) {
        const char *a;
        char *r, *b;

        r = new(char, strlen(v)*3+1);
        if (!r)
                return NULL;

        for (a = v, b = r; *a; a++) {

                if ((*a >= '0' && *a <= '9') ||
                    (*a >= 'a' && *a <= 'z') ||
                    (*a >= 'A' && *a <= 'Z') ||
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

        if (r < 0) {
                if (m->header->type == SD_BUS_MESSAGE_METHOD_CALL)
                        sd_bus_reply_method_errno(m, r, error);

        } else if (sd_bus_error_is_set(error)) {
                if (m->header->type == SD_BUS_MESSAGE_METHOD_CALL)
                        sd_bus_reply_method_error(m, error);
        } else
                return r;

        log_debug("Failed to process message [type=%s sender=%s path=%s interface=%s member=%s signature=%s]: %s",
                  bus_message_type_to_string(m->header->type),
                  strna(m->sender),
                  strna(m->path),
                  strna(m->interface),
                  strna(m->member),
                  strna(m->root_container.signature),
                  bus_error_message(error, r));

        return 1;
}
