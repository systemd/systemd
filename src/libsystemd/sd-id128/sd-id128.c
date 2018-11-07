/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "id128-util.h"
#include "io-util.h"
#include "khash.h"
#include "macro.h"
#include "missing.h"
#include "random-util.h"
#include "user-util.h"
#include "util.h"

_public_ char *sd_id128_to_string(sd_id128_t id, char s[SD_ID128_STRING_MAX]) {
        unsigned n;

        assert_return(s, NULL);

        for (n = 0; n < 16; n++) {
                s[n*2] = hexchar(id.bytes[n] >> 4);
                s[n*2+1] = hexchar(id.bytes[n] & 0xF);
        }

        s[32] = 0;

        return s;
}

_public_ int sd_id128_from_string(const char s[], sd_id128_t *ret) {
        unsigned n, i;
        sd_id128_t t;
        bool is_guid = false;

        assert_return(s, -EINVAL);

        for (n = 0, i = 0; n < 16;) {
                int a, b;

                if (s[i] == '-') {
                        /* Is this a GUID? Then be nice, and skip over
                         * the dashes */

                        if (i == 8)
                                is_guid = true;
                        else if (IN_SET(i, 13, 18, 23)) {
                                if (!is_guid)
                                        return -EINVAL;
                        } else
                                return -EINVAL;

                        i++;
                        continue;
                }

                a = unhexchar(s[i++]);
                if (a < 0)
                        return -EINVAL;

                b = unhexchar(s[i++]);
                if (b < 0)
                        return -EINVAL;

                t.bytes[n++] = (a << 4) | b;
        }

        if (i != (is_guid ? 36 : 32))
                return -EINVAL;

        if (s[i] != 0)
                return -EINVAL;

        if (ret)
                *ret = t;
        return 0;
}

_public_ int sd_id128_get_machine(sd_id128_t *ret) {
        static thread_local sd_id128_t saved_machine_id = {};
        int r;

        assert_return(ret, -EINVAL);

        if (sd_id128_is_null(saved_machine_id)) {
                r = id128_read("/etc/machine-id", ID128_PLAIN, &saved_machine_id);
                if (r < 0)
                        return r;

                if (sd_id128_is_null(saved_machine_id))
                        return -ENOMEDIUM;
        }

        *ret = saved_machine_id;
        return 0;
}

_public_ int sd_id128_get_boot(sd_id128_t *ret) {
        static thread_local sd_id128_t saved_boot_id = {};
        int r;

        assert_return(ret, -EINVAL);

        if (sd_id128_is_null(saved_boot_id)) {
                r = id128_read("/proc/sys/kernel/random/boot_id", ID128_UUID, &saved_boot_id);
                if (r < 0)
                        return r;
        }

        *ret = saved_boot_id;
        return 0;
}

static int get_invocation_from_keyring(sd_id128_t *ret) {

        _cleanup_free_ char *description = NULL;
        char *d, *p, *g, *u, *e;
        unsigned long perms;
        key_serial_t key;
        size_t sz = 256;
        uid_t uid;
        gid_t gid;
        int r, c;

#define MAX_PERMS ((unsigned long) (KEY_POS_VIEW|KEY_POS_READ|KEY_POS_SEARCH| \
                                    KEY_USR_VIEW|KEY_USR_READ|KEY_USR_SEARCH))

        assert(ret);

        key = request_key("user", "invocation_id", NULL, 0);
        if (key == -1) {
                /* Keyring support not available? No invocation key stored? */
                if (IN_SET(errno, ENOSYS, ENOKEY))
                        return 0;

                return -errno;
        }

        for (;;) {
                description = new(char, sz);
                if (!description)
                        return -ENOMEM;

                c = keyctl(KEYCTL_DESCRIBE, key, (unsigned long) description, sz, 0);
                if (c < 0)
                        return -errno;

                if ((size_t) c <= sz)
                        break;

                sz = c;
                free(description);
        }

        /* The kernel returns a final NUL in the string, verify that. */
        assert(description[c-1] == 0);

        /* Chop off the final description string */
        d = strrchr(description, ';');
        if (!d)
                return -EIO;
        *d = 0;

        /* Look for the permissions */
        p = strrchr(description, ';');
        if (!p)
                return -EIO;

        errno = 0;
        perms = strtoul(p + 1, &e, 16);
        if (errno > 0)
                return -errno;
        if (e == p + 1) /* Read at least one character */
                return -EIO;
        if (e != d) /* Must reached the end */
                return -EIO;

        if ((perms & ~MAX_PERMS) != 0)
                return -EPERM;

        *p = 0;

        /* Look for the group ID */
        g = strrchr(description, ';');
        if (!g)
                return -EIO;
        r = parse_gid(g + 1, &gid);
        if (r < 0)
                return r;
        if (gid != 0)
                return -EPERM;
        *g = 0;

        /* Look for the user ID */
        u = strrchr(description, ';');
        if (!u)
                return -EIO;
        r = parse_uid(u + 1, &uid);
        if (r < 0)
                return r;
        if (uid != 0)
                return -EPERM;

        c = keyctl(KEYCTL_READ, key, (unsigned long) ret, sizeof(sd_id128_t), 0);
        if (c < 0)
                return -errno;
        if (c != sizeof(sd_id128_t))
                return -EIO;

        return 1;
}

_public_ int sd_id128_get_invocation(sd_id128_t *ret) {
        static thread_local sd_id128_t saved_invocation_id = {};
        int r;

        assert_return(ret, -EINVAL);

        if (sd_id128_is_null(saved_invocation_id)) {

                /* We first try to read the invocation ID from the kernel keyring. This has the benefit that it is not
                 * fakeable by unprivileged code. If the information is not available in the keyring, we use
                 * $INVOCATION_ID but ignore the data if our process was called by less privileged code
                 * (i.e. secure_getenv() instead of getenv()).
                 *
                 * The kernel keyring is only relevant for system services (as for user services we don't store the
                 * invocation ID in the keyring, as there'd be no trust benefit in that). The environment variable is
                 * primarily relevant for user services, and sufficiently safe as no privilege boundary is involved. */

                r = get_invocation_from_keyring(&saved_invocation_id);
                if (r < 0)
                        return r;

                if (r == 0) {
                        const char *e;

                        e = secure_getenv("INVOCATION_ID");
                        if (!e)
                                return -ENXIO;

                        r = sd_id128_from_string(e, &saved_invocation_id);
                        if (r < 0)
                                return r;
                }
        }

        *ret = saved_invocation_id;
        return 0;
}

static sd_id128_t make_v4_uuid(sd_id128_t id) {
        /* Stolen from generate_random_uuid() of drivers/char/random.c
         * in the kernel sources */

        /* Set UUID version to 4 --- truly random generation */
        id.bytes[6] = (id.bytes[6] & 0x0F) | 0x40;

        /* Set the UUID variant to DCE */
        id.bytes[8] = (id.bytes[8] & 0x3F) | 0x80;

        return id;
}

_public_ int sd_id128_randomize(sd_id128_t *ret) {
        sd_id128_t t;
        int r;

        assert_return(ret, -EINVAL);

        /* We allow usage if x86-64 RDRAND here. It might not be trusted enough for keeping secrets, but it should be
         * fine for UUIDS. */
        r = genuine_random_bytes(&t, sizeof t, RANDOM_ALLOW_RDRAND);
        if (r < 0)
                return r;

        /* Turn this into a valid v4 UUID, to be nice. Note that we
         * only guarantee this for newly generated UUIDs, not for
         * pre-existing ones. */

        *ret = make_v4_uuid(t);
        return 0;
}

static int get_app_specific(sd_id128_t base, sd_id128_t app_id, sd_id128_t *ret) {
        _cleanup_(khash_unrefp) khash *h = NULL;
        sd_id128_t result;
        const void *p;
        int r;

        assert(ret);

        r = khash_new_with_key(&h, "hmac(sha256)", &base, sizeof(base));
        if (r < 0)
                return r;

        r = khash_put(h, &app_id, sizeof(app_id));
        if (r < 0)
                return r;

        r = khash_digest_data(h, &p);
        if (r < 0)
                return r;

        /* We chop off the trailing 16 bytes */
        memcpy(&result, p, MIN(khash_get_size(h), sizeof(result)));

        *ret = make_v4_uuid(result);
        return 0;
}

_public_ int sd_id128_get_machine_app_specific(sd_id128_t app_id, sd_id128_t *ret) {
        sd_id128_t id;
        int r;

        assert_return(ret, -EINVAL);

        r = sd_id128_get_machine(&id);
        if (r < 0)
                return r;

        return get_app_specific(id, app_id, ret);
}

_public_ int sd_id128_get_boot_app_specific(sd_id128_t app_id, sd_id128_t *ret) {
        sd_id128_t id;
        int r;

        assert_return(ret, -EINVAL);

        r = sd_id128_get_boot(&id);
        if (r < 0)
                return r;

        return get_app_specific(id, app_id, ret);
}
