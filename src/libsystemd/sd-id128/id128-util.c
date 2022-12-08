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
        size_t l;

        assert(s);

        l = strlen(s);

        if (l == SD_ID128_STRING_MAX - 1)
                /* Plain formatted 128bit hex string */
                return in_charset(s, HEXDIGITS);

        if (l == SD_ID128_UUID_STRING_MAX - 1) {
                /* Formatted UUID */
                for (size_t i = 0; i < l; i++) {
                        char c = s[i];

                        if (IN_SET(i, 8, 13, 18, 23)) {
                                if (c != '-')
                                        return false;
                        } else if (!ascii_ishex(c))
                                return false;
                }
                return true;
        }

        return false;
}

int id128_read_fd(int fd, Id128FormatFlag f, sd_id128_t *ret) {
        char buffer[SD_ID128_UUID_STRING_MAX + 1]; /* +1 is for trailing newline */
        ssize_t l;

        assert(fd >= 0);

        /* Reads an 128bit ID from a file, which may either be in plain format (32 hex digits), or in UUID format, both
         * optionally followed by a newline and nothing else. ID files should really be newline terminated, but if they
         * aren't that's OK too, following the rule of "Be conservative in what you send, be liberal in what you
         * accept".
         *
         * This returns the following:
         *     -ENOMEDIUM: an empty string,
         *     -ENOPKG:    "uninitialized" or "uninitialized\n",
         *     -EINVAL:    other invalid strings. */

        l = loop_read(fd, buffer, sizeof(buffer), false); /* we expect a short read of either 32/33 or 36/37 chars */
        if (l < 0)
                return (int) l;
        if (l == 0) /* empty? */
                return -ENOMEDIUM;

        switch (l) {

        case STRLEN("uninitialized"):
        case STRLEN("uninitialized\n"):
                return strneq(buffer, "uninitialized\n", l) ? -ENOPKG : -EINVAL;

        case SD_ID128_STRING_MAX: /* plain UUID with trailing newline */
                if (buffer[SD_ID128_STRING_MAX-1] != '\n')
                        return -EINVAL;

                _fallthrough_;
        case SD_ID128_STRING_MAX-1: /* plain UUID without trailing newline */
                if (!FLAGS_SET(f, ID128_FORMAT_PLAIN))
                        return -EINVAL;

                buffer[SD_ID128_STRING_MAX-1] = 0;
                break;

        case SD_ID128_UUID_STRING_MAX: /* RFC UUID with trailing newline */
                if (buffer[SD_ID128_UUID_STRING_MAX-1] != '\n')
                        return -EINVAL;

                _fallthrough_;
        case SD_ID128_UUID_STRING_MAX-1: /* RFC UUID without trailing newline */
                if (!FLAGS_SET(f, ID128_FORMAT_UUID))
                        return -EINVAL;

                buffer[SD_ID128_UUID_STRING_MAX-1] = 0;
                break;

        default:
                return -EINVAL;
        }

        return sd_id128_from_string(buffer, ret);
}

int id128_read(const char *p, Id128FormatFlag f, sd_id128_t *ret) {
        _cleanup_close_ int fd = -1;

        fd = open(p, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return -errno;

        return id128_read_fd(fd, f, ret);
}

int id128_write_fd(int fd, Id128FormatFlag f, sd_id128_t id, bool do_sync) {
        char buffer[SD_ID128_UUID_STRING_MAX + 1]; /* +1 is for trailing newline */
        size_t sz;
        int r;

        assert(fd >= 0);
        assert(IN_SET((f & ID128_FORMAT_ANY), ID128_FORMAT_PLAIN, ID128_FORMAT_UUID));

        if (FLAGS_SET(f, ID128_FORMAT_PLAIN)) {
                assert_se(sd_id128_to_string(id, buffer));
                sz = SD_ID128_STRING_MAX;
        } else {
                assert_se(sd_id128_to_uuid_string(id, buffer));
                sz = SD_ID128_UUID_STRING_MAX;
        }

        buffer[sz - 1] = '\n';
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

int id128_write(const char *p, Id128FormatFlag f, sd_id128_t id, bool do_sync) {
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

        r = id128_read("/sys/class/dmi/id/product_uuid", ID128_FORMAT_UUID, &uuid);
        if (r == -ENOENT)
                r = id128_read("/proc/device-tree/vm,uuid", ID128_FORMAT_UUID, &uuid);
        if (r < 0)
                return r;

        if (sd_id128_is_null(uuid) || sd_id128_is_allf(uuid))
                return -EADDRNOTAVAIL; /* Recognizable error */

        *ret = uuid;
        return 0;
}
