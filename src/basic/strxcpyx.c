/***
  This file is part of systemd.

  Copyright 2013 Kay Sievers

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

#include "strxcpyx.h"

size_t strpcpy(char **dest, size_t size, const char *src) {
        size_t len;

        assert(dest);
        assert(src);

        if (size == 0)
                return 0;

        len = strlen(src);
        if (len >= size) {
                if (size > 1)
                        *dest = mempcpy(*dest, src, size-1);
                size = 0;
        } else {
                if (len > 0) {
                        *dest = mempcpy(*dest, src, len);
                        size -= len;
                }
        }
        *dest[0] = '\0';
        return size;
}

size_t strpcpyf(char **dest, size_t size, const char *src, ...) {
        va_list va;
        int i;

        assert(dest);
        assert(src);

        if (size == 0)
                return 0;

        va_start(va, src);
        i = vsnprintf(*dest, size, src, va);
        if (i < (int)size) {
                *dest += i;
                size -= i;
        } else {
                size = 0;
        }
        va_end(va);
        return size;
}

size_t strpcpyl(char **dest, size_t size, const char *src, ...) {
        va_list va;

        assert(dest);
        assert(src);

        va_start(va, src);
        do {
                size = strpcpy(dest, size, src);
                src = va_arg(va, char *);
        } while (src != NULL);
        va_end(va);
        return size;
}

size_t strscpy(char *dest, size_t size, const char *src) {
        char *s;

        assert(dest);
        assert(src);

        s = dest;
        return strpcpy(&s, size, src);
}

size_t strscpyl(char *dest, size_t size, const char *src, ...) {
        va_list va;
        char *s;

        assert(dest);
        assert(src);

        va_start(va, src);
        s = dest;
        do {
                size = strpcpy(&s, size, src);
                src = va_arg(va, char *);
        } while (src != NULL);
        va_end(va);

        return size;
}
