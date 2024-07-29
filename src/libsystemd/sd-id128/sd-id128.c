/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "chase.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "hmac.h"
#include "id128-util.h"
#include "io-util.h"
#include "keyring-util.h"
#include "macro.h"
#include "missing_syscall.h"
#include "missing_threads.h"
#include "path-util.h"
#include "random-util.h"
#include "stat-util.h"
#include "user-util.h"

_public_ char *sd_id128_to_string(sd_id128_t id, char s[_SD_ARRAY_STATIC SD_ID128_STRING_MAX]) {
        size_t k = 0;

        assert_return(s, NULL);

        for (size_t n = 0; n < sizeof(sd_id128_t); n++) {
                s[k++] = hexchar(id.bytes[n] >> 4);
                s[k++] = hexchar(id.bytes[n] & 0xF);
        }

        assert(k == SD_ID128_STRING_MAX - 1);
        s[k] = 0;

        return s;
}

_public_ char *sd_id128_to_uuid_string(sd_id128_t id, char s[_SD_ARRAY_STATIC SD_ID128_UUID_STRING_MAX]) {
        size_t k = 0;

        assert_return(s, NULL);

        /* Similar to sd_id128_to_string() but formats the result as UUID instead of plain hex chars */

        for (size_t n = 0; n < sizeof(sd_id128_t); n++) {

                if (IN_SET(n, 4, 6, 8, 10))
                        s[k++] = '-';

                s[k++] = hexchar(id.bytes[n] >> 4);
                s[k++] = hexchar(id.bytes[n] & 0xF);
        }

        assert(k == SD_ID128_UUID_STRING_MAX - 1);
        s[k] = 0;

        return s;
}

_public_ int sd_id128_from_string(const char *s, sd_id128_t *ret) {
        size_t n, i;
        sd_id128_t t;
        bool is_guid = false;

        assert_return(s, -EINVAL);

        for (n = 0, i = 0; n < sizeof(sd_id128_t);) {
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

        if (i != (is_guid ? SD_ID128_UUID_STRING_MAX : SD_ID128_STRING_MAX) - 1)
                return -EINVAL;

        if (s[i] != 0)
                return -EINVAL;

        if (ret)
                *ret = t;
        return 0;
}

_public_ int sd_id128_string_equal(const char *s, sd_id128_t id) {
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

_public_ int sd_id128_get_machine(sd_id128_t *ret) {
        static thread_local sd_id128_t saved_machine_id = {};
        int r;

        if (sd_id128_is_null(saved_machine_id)) {
                r = id128_read("/etc/machine-id", ID128_FORMAT_PLAIN | ID128_REFUSE_NULL, &saved_machine_id);
                if (r < 0)
                        return r;
        }

        if (ret)
                *ret = saved_machine_id;
        return 0;
}

int id128_get_machine_at(int rfd, sd_id128_t *ret) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(rfd >= 0 || rfd == AT_FDCWD);

        r = dir_fd_is_root_or_cwd(rfd);
        if (r < 0)
                return r;
        if (r > 0)
                return sd_id128_get_machine(ret);

        fd = chase_and_openat(rfd, "/etc/machine-id", CHASE_AT_RESOLVE_IN_ROOT, O_RDONLY|O_CLOEXEC|O_NOCTTY, NULL);
        if (fd < 0)
                return fd;

        return id128_read_fd(fd, ID128_FORMAT_PLAIN | ID128_REFUSE_NULL, ret);
}

int id128_get_machine(const char *root, sd_id128_t *ret) {
        _cleanup_close_ int fd = -EBADF;

        if (empty_or_root(root))
                return sd_id128_get_machine(ret);

        fd = chase_and_open("/etc/machine-id", root, CHASE_PREFIX_ROOT, O_RDONLY|O_CLOEXEC|O_NOCTTY, NULL);
        if (fd < 0)
                return fd;

        return id128_read_fd(fd, ID128_FORMAT_PLAIN | ID128_REFUSE_NULL, ret);
}

int id128_get_boot(sd_id128_t *ret) {
        int r;

        assert(ret);

        r = id128_read("/proc/sys/kernel/random/boot_id", ID128_FORMAT_UUID | ID128_REFUSE_NULL, ret);
        if (r == -ENOENT && proc_mounted() == 0)
                return -ENOSYS;

        return r;
}

_public_ int sd_id128_get_boot(sd_id128_t *ret) {
        static thread_local sd_id128_t saved_boot_id = {};
        int r;

        if (sd_id128_is_null(saved_boot_id)) {
                r = id128_get_boot(&saved_boot_id);
                if (r < 0)
                        return r;
        }

        if (ret)
                *ret = saved_boot_id;
        return 0;
}

static int get_invocation_from_keyring(sd_id128_t *ret) {
        _cleanup_free_ char *description = NULL;
        char *d, *p, *g, *u, *e;
        unsigned long perms;
        key_serial_t key;
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
                        return -ENXIO;

                return -errno;
        }

        r = keyring_describe(key, &description);
        if (r < 0)
                return r;

        /* Chop off the final description string */
        d = strrchr(description, ';');
        if (!d)
                return -EUCLEAN;
        *d = 0;

        /* Look for the permissions */
        p = strrchr(description, ';');
        if (!p)
                return -EUCLEAN;

        errno = 0;
        perms = strtoul(p + 1, &e, 16);
        if (errno > 0)
                return -errno;
        if (e == p + 1) /* Read at least one character */
                return -EUCLEAN;
        if (e != d) /* Must reached the end */
                return -EUCLEAN;

        if ((perms & ~MAX_PERMS) != 0)
                return -EPERM;

        *p = 0;

        /* Look for the group ID */
        g = strrchr(description, ';');
        if (!g)
                return -EUCLEAN;
        r = parse_gid(g + 1, &gid);
        if (r < 0)
                return r;
        if (gid != 0)
                return -EPERM;
        *g = 0;

        /* Look for the user ID */
        u = strrchr(description, ';');
        if (!u)
                return -EUCLEAN;
        r = parse_uid(u + 1, &uid);
        if (r < 0)
                return r;
        if (uid != 0)
                return -EPERM;

        c = keyctl(KEYCTL_READ, key, (unsigned long) ret, sizeof(sd_id128_t), 0);
        if (c < 0)
                return -errno;
        if (c != sizeof(sd_id128_t))
                return -EUCLEAN;

        return 0;
}

static int get_invocation_from_environment(sd_id128_t *ret) {
        const char *e;
        int r;

        assert(ret);

        e = secure_getenv("INVOCATION_ID");
        if (!e)
                return -ENXIO;

        r = sd_id128_from_string(e, ret);
        return r == -EINVAL ? -EUCLEAN : r;
}

_public_ int sd_id128_get_invocation(sd_id128_t *ret) {
        static thread_local sd_id128_t saved_invocation_id = {};
        int r;

        if (sd_id128_is_null(saved_invocation_id)) {
                /* We first check the environment. The environment variable is primarily relevant for user
                 * services, and sufficiently safe as long as no privilege boundary is involved. */
                r = get_invocation_from_environment(&saved_invocation_id);
                if (r == -ENXIO)
                        /* The kernel keyring is relevant for system services (as for user services we don't
                         * store the invocation ID in the keyring, as there'd be no trust benefit in that). */
                        r = get_invocation_from_keyring(&saved_invocation_id);
                if (r < 0)
                        return r;

                if (sd_id128_is_null(saved_invocation_id))
                        return -ENOMEDIUM;
        }

        if (ret)
                *ret = saved_invocation_id;
        return 0;
}

_public_ int sd_id128_randomize(sd_id128_t *ret) {
        sd_id128_t t;

        assert_return(ret, -EINVAL);

        random_bytes(&t, sizeof(t));

        /* Turn this into a valid v4 UUID, to be nice. Note that we
         * only guarantee this for newly generated UUIDs, not for
         * pre-existing ones. */

        *ret = id128_make_v4_uuid(t);
        return 0;
}

_public_ int sd_id128_get_app_specific(sd_id128_t base, sd_id128_t app_id, sd_id128_t *ret) {
        assert_cc(sizeof(sd_id128_t) < SHA256_DIGEST_SIZE); /* Check that we don't need to pad with zeros. */
        union {
                uint8_t hmac[SHA256_DIGEST_SIZE];
                sd_id128_t result;
        } buf;

        assert_return(ret, -EINVAL);
        assert_return(!sd_id128_is_null(app_id), -ENXIO);

        hmac_sha256(&base, sizeof(base), &app_id, sizeof(app_id), buf.hmac);

        /* Take only the first half. */
        *ret = id128_make_v4_uuid(buf.result);
        return 0;
}

_public_ int sd_id128_get_machine_app_specific(sd_id128_t app_id, sd_id128_t *ret) {
        sd_id128_t id;
        int r;

        assert_return(ret, -EINVAL);

        r = sd_id128_get_machine(&id);
        if (r < 0)
                return r;

        return sd_id128_get_app_specific(id, app_id, ret);
}

_public_ int sd_id128_get_boot_app_specific(sd_id128_t app_id, sd_id128_t *ret) {
        sd_id128_t id;
        int r;

        assert_return(ret, -EINVAL);

        r = sd_id128_get_boot(&id);
        if (r < 0)
                return r;

        return sd_id128_get_app_specific(id, app_id, ret);
}

_public_ int sd_id128_get_invocation_app_specific(sd_id128_t app_id, sd_id128_t *ret) {
        sd_id128_t id;
        int r;

        assert_return(ret, -EINVAL);

        r = sd_id128_get_invocation(&id);
        if (r < 0)
                return r;

        return sd_id128_get_app_specific(id, app_id, ret);
}
