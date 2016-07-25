/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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
#include <unistd.h>

#include "fd-util.h"
#include "hexdecoct.h"
#include "id128-util.h"
#include "io-util.h"
#include "stdio-util.h"

char *id128_to_uuid_string(sd_id128_t id, char s[37]) {
        unsigned n, k = 0;

        assert(s);

        /* Similar to sd_id128_to_string() but formats the result as UUID instead of plain hex chars */

        for (n = 0; n < 16; n++) {

                if (IN_SET(n, 4, 6, 8, 10))
                        s[k++] = '-';

                s[k++] = hexchar(id.bytes[n] >> 4);
                s[k++] = hexchar(id.bytes[n] & 0xF);
        }

        assert(k == 36);

        s[k] = 0;

        return s;
}

bool id128_is_valid(const char *s) {
        size_t i, l;

        assert(s);

        l = strlen(s);
        if (l == 32) {

                /* Plain formatted 128bit hex string */

                for (i = 0; i < l; i++) {
                        char c = s[i];

                        if (!(c >= '0' && c <= '9') &&
                            !(c >= 'a' && c <= 'z') &&
                            !(c >= 'A' && c <= 'Z'))
                                return false;
                }

        } else if (l == 36) {

                /* Formatted UUID */

                for (i = 0; i < l; i++) {
                        char c = s[i];

                        if ((i == 8 || i == 13 || i == 18 || i == 23)) {
                                if (c != '-')
                                        return false;
                        } else {
                                if (!(c >= '0' && c <= '9') &&
                                    !(c >= 'a' && c <= 'z') &&
                                    !(c >= 'A' && c <= 'Z'))
                                        return false;
                        }
                }

        } else
                return false;

        return true;
}

int id128_read_fd(int fd, Id128Format f, sd_id128_t *ret) {
        char buffer[36 + 2];
        ssize_t l;

        assert(fd >= 0);
        assert(f < _ID128_FORMAT_MAX);

        /* Reads an 128bit ID from a file, which may either be in plain format (32 hex digits), or in UUID format, both
         * optionally followed by a newline and nothing else. ID files should really be newline terminated, but if they
         * aren't that's OK too, following the rule of "Be conservative in what you send, be liberal in what you
         * accept". */

        l = loop_read(fd, buffer, sizeof(buffer), false); /* we expect a short read of either 32/33 or 36/37 chars */
        if (l < 0)
                return (int) l;
        if (l == 0) /* empty? */
                return -ENOMEDIUM;

        switch (l) {

        case 33: /* plain UUID with trailing newline */
                if (buffer[32] != '\n')
                        return -EINVAL;

                /* fall through */
        case 32: /* plain UUID without trailing newline */
                if (f == ID128_UUID)
                        return -EINVAL;

                buffer[32] = 0;
                break;

        case 37: /* RFC UUID with trailing newline */
                if (buffer[36] != '\n')
                        return -EINVAL;

                /* fall through */
        case 36: /* RFC UUID without trailing newline */
                if (f == ID128_PLAIN)
                        return -EINVAL;

                buffer[36] = 0;
                break;

        default:
                return -EINVAL;
        }

        return sd_id128_from_string(buffer, ret);
}

int id128_read(const char *p, Id128Format f, sd_id128_t *ret) {
        _cleanup_close_ int fd = -1;

        fd = open(p, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return -errno;

        return id128_read_fd(fd, f, ret);
}

int id128_write_fd(int fd, Id128Format f, sd_id128_t id, bool do_sync) {
        char buffer[36 + 2];
        size_t sz;
        int r;

        assert(fd >= 0);
        assert(f < _ID128_FORMAT_MAX);

        if (f != ID128_UUID) {
                sd_id128_to_string(id, buffer);
                buffer[32] = '\n';
                sz = 33;
        } else {
                id128_to_uuid_string(id, buffer);
                buffer[36] = '\n';
                sz = 37;
        }

        r = loop_write(fd, buffer, sz, false);
        if (r < 0)
                return r;

        if (do_sync) {
                if (fsync(fd) < 0)
                        return -errno;
        }

        return r;
}

int id128_write(const char *p, Id128Format f, sd_id128_t id, bool do_sync) {
        _cleanup_close_ int fd = -1;

        fd = open(p, O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY, 0444);
        if (fd < 0)
                return -errno;

        return id128_write_fd(fd, f, id, do_sync);
}
