/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "fd-util.h"
#include "hexdecoct.h"
#include "id128-util.h"
#include "io-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "sync-util.h"

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

                        if (IN_SET(i, 8, 13, 18, 23)) {
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

        case 13:
        case 14:
                /* Treat an "uninitialized" id file like an empty one */
                return f == ID128_PLAIN_OR_UNINIT && strneq(buffer, "uninitialized\n", l) ? -ENOMEDIUM : -EINVAL;

        case 33: /* plain UUID with trailing newline */
                if (buffer[32] != '\n')
                        return -EINVAL;

                _fallthrough_;
        case 32: /* plain UUID without trailing newline */
                if (f == ID128_UUID)
                        return -EINVAL;

                buffer[32] = 0;
                break;

        case 37: /* RFC UUID with trailing newline */
                if (buffer[36] != '\n')
                        return -EINVAL;

                _fallthrough_;
        case 36: /* RFC UUID without trailing newline */
                if (IN_SET(f, ID128_PLAIN, ID128_PLAIN_OR_UNINIT))
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
                assert_se(sd_id128_to_string(id, buffer));
                buffer[SD_ID128_STRING_MAX - 1] = '\n';
                sz = SD_ID128_STRING_MAX;
        } else {
                assert_se(sd_id128_to_uuid_string(id, buffer));
                buffer[SD_ID128_UUID_STRING_MAX - 1] = '\n';
                sz = SD_ID128_UUID_STRING_MAX;
        }

        r = loop_write(fd, buffer, sz, false);
        if (r < 0)
                return r;

        if (do_sync) {
                r = fsync_full(fd);
                if (r < 0)
                        return r;
        }

        return 0;
}

int id128_write(const char *p, Id128Format f, sd_id128_t id, bool do_sync) {
        _cleanup_close_ int fd = -1;

        fd = open(p, O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY|O_TRUNC, 0444);
        if (fd < 0)
                return -errno;

        return id128_write_fd(fd, f, id, do_sync);
}

void id128_hash_func(const sd_id128_t *p, struct siphash *state) {
        siphash24_compress(p, sizeof(sd_id128_t), state);
}

int id128_compare_func(const sd_id128_t *a, const sd_id128_t *b) {
        return memcmp(a, b, 16);
}

sd_id128_t id128_make_v4_uuid(sd_id128_t id) {
        /* Stolen from generate_random_uuid() of drivers/char/random.c
         * in the kernel sources */

        /* Set UUID version to 4 --- truly random generation */
        id.bytes[6] = (id.bytes[6] & 0x0F) | 0x40;

        /* Set the UUID variant to DCE */
        id.bytes[8] = (id.bytes[8] & 0x3F) | 0x80;

        return id;
}

DEFINE_HASH_OPS(id128_hash_ops, sd_id128_t, id128_hash_func, id128_compare_func);

int id128_get_product(sd_id128_t *ret) {
        sd_id128_t uuid;
        int r;

        assert(ret);

        /* Reads the systems product UUID from DMI or devicetree (where it is located on POWER). This is
         * particularly relevant in VM environments, where VM managers typically place a VM uuid there. */

        r = id128_read("/sys/class/dmi/id/product_uuid", ID128_UUID, &uuid);
        if (r == -ENOENT)
                r = id128_read("/proc/device-tree/vm,uuid", ID128_UUID, &uuid);
        if (r < 0)
                return r;

        if (sd_id128_is_null(uuid) || sd_id128_is_allf(uuid))
                return -EADDRNOTAVAIL; /* Recognizable error */

        *ret = uuid;
        return 0;
}

int id128_equal_string(const char *s, sd_id128_t id) {
        sd_id128_t parsed;
        int r;

        if (!s)
                return false;

        /* Checks if the specified string matches a valid string representation of the specified 128 bit ID/uuid */

        r = sd_id128_from_string(s, &parsed);
        if (r < 0)
                return r;

        return sd_id128_equal(parsed, id);
}
