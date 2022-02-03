/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Concatenates/copies strings. In any case, terminates in all cases
 * with '\0' and moves the @dest pointer forward to the added '\0'.
 * Returns the remaining size, and 0 if the string was truncated.
 *
 * Due to the intended usage, these helpers silently noop invocations
 * having zero size.  This is technically an exception to the above
 * statement "terminates in all cases".  It's unexpected for such calls to
 * occur outside of a loop where this is the preferred behavior.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "string-util.h"
#include "strxcpyx.h"

size_t strnpcpy_full(char **dest, size_t size, const char *src, size_t len, bool *ret_truncated) {
        bool truncated = false;

        assert(dest);
        assert(src);

        if (size == 0) {
                if (ret_truncated)
                        *ret_truncated = len > 0;
                return 0;
        }

        if (len >= size) {
                if (size > 1)
                        *dest = mempcpy(*dest, src, size-1);
                size = 0;
                truncated = true;
        } else if (len > 0) {
                *dest = mempcpy(*dest, src, len);
                size -= len;
        }

        if (ret_truncated)
                *ret_truncated = truncated;

        *dest[0] = '\0';
        return size;
}

size_t strpcpy_full(char **dest, size_t size, const char *src, bool *ret_truncated) {
        assert(dest);
        assert(src);

        return strnpcpy_full(dest, size, src, strlen(src), ret_truncated);
}

size_t strpcpyf_full(char **dest, size_t size, bool *ret_truncated, const char *src, ...) {
        bool truncated = false;
        va_list va;
        int i;

        assert(dest);
        assert(src);

        va_start(va, src);
        i = vsnprintf(*dest, size, src, va);
        va_end(va);

        if (i < (int) size) {
                *dest += i;
                size -= i;
        } else {
                size = 0;
                truncated = i > 0;
        }

        if (ret_truncated)
                *ret_truncated = truncated;

        return size;
}

size_t strpcpyl_full(char **dest, size_t size, bool *ret_truncated, const char *src, ...) {
        bool truncated = false;
        va_list va;

        assert(dest);
        assert(src);

        va_start(va, src);
        do {
                bool t;

                size = strpcpy_full(dest, size, src, &t);
                truncated = truncated || t;
                src = va_arg(va, char *);
        } while (src);
        va_end(va);

        if (ret_truncated)
                *ret_truncated = truncated;
        return size;
}

size_t strnscpy_full(char *dest, size_t size, const char *src, size_t len, bool *ret_truncated) {
        char *s;

        assert(dest);
        assert(src);

        s = dest;
        return strnpcpy_full(&s, size, src, len, ret_truncated);
}

size_t strscpy_full(char *dest, size_t size, const char *src, bool *ret_truncated) {
        assert(dest);
        assert(src);

        return strnscpy_full(dest, size, src, strlen(src), ret_truncated);
}

size_t strscpyl_full(char *dest, size_t size, bool *ret_truncated, const char *src, ...) {
        bool truncated = false;
        va_list va;
        char *s;

        assert(dest);
        assert(src);

        va_start(va, src);
        s = dest;
        do {
                bool t;

                size = strpcpy_full(&s, size, src, &t);
                truncated = truncated || t;
                src = va_arg(va, char *);
        } while (src);
        va_end(va);

        if (ret_truncated)
                *ret_truncated = truncated;

        return size;
}
