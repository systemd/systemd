/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "keyring-util.h"
#include "log.h"
#include "parse-util.h"
#include "string-util.h"
#include "user-util.h"

int keyring_read(key_serial_t serial, void **ret, size_t *ret_size) {
        size_t bufsize = 100;

        for (;;) {
                _cleanup_(erase_and_freep) uint8_t *buf = NULL;
                long n;

                buf = new(uint8_t, bufsize + 1);
                if (!buf)
                        return -ENOMEM;

                n = keyctl(KEYCTL_READ, (unsigned long) serial, (unsigned long) buf, (unsigned long) bufsize, 0);
                if (n < 0)
                        return -errno;

                if ((size_t) n <= bufsize) {
                        buf[n] = 0; /* NUL terminate, just in case */

                        if (ret)
                                *ret = TAKE_PTR(buf);
                        if (ret_size)
                                *ret_size = n;

                        return 0;
                }

                bufsize = (size_t) n;
        }
}

int keyring_describe(key_serial_t serial, char **ret) {
        _cleanup_free_ char *tuple = NULL;
        size_t sz = 64;
        int c = -1; /* Workaround for maybe-uninitialized false positive due to missing_syscall indirection */

        assert(ret);

        for (;;) {
                tuple = new(char, sz);
                if (!tuple)
                        return log_oom_debug();

                c = keyctl(KEYCTL_DESCRIBE, serial, (unsigned long) tuple, sz, 0);
                if (c < 0)
                        return log_debug_errno(errno, "Failed to describe key id %d: %m", serial);

                if ((size_t) c <= sz)
                        break;

                sz = c;
                free(tuple);
        }

        /* The kernel returns a final NUL in the string, verify that. */
        assert(tuple[c-1] == 0);

        *ret = TAKE_PTR(tuple);

        return 0;
}

void proc_keys_entry_done(ProcKeysEntry *e) {
        assert(e);

        e->type = mfree(e->type);
        e->description = mfree(e->description);
}

int proc_keys_entry_parse(const char *line, ProcKeysEntry *ret) {
        _cleanup_(proc_keys_entry_done) ProcKeysEntry e = {};
        _cleanup_free_ char *serial = NULL, *flags = NULL, *usage = NULL, *timeout = NULL, *perm = NULL,
                *uid = NULL, *gid = NULL;
        const char *p = line;
        uint32_t u;
        int r;

        assert(line);
        assert(ret);

        /* "%08x %c%c%c%c%c%c%c %5d %4s %08x %5d %5d %-9.9s <description>" */

        r = extract_many_words(&p, WHITESPACE, 0, &serial, &flags, &usage, &timeout, &perm, &uid, &gid, &e.type);
        if (r < 0)
                return r;
        if (r < 8)
                return -EBADMSG;

        r = safe_atou32_full(serial, 16, &u);
        if (r < 0)
                return r;
        if (u > INT32_MAX)
                return -ERANGE;
        e.serial = u;

        if (strlen(flags) != sizeof(e.flags) - 1)
                return -EBADMSG;
        strcpy(e.flags, flags);

        r = safe_atou32_full(perm, 16, &e.perm);
        if (r < 0)
                return r;

        r = parse_uid(uid, &e.uid);
        if (r < 0)
                return r;

        r = parse_gid(gid, &e.gid);
        if (r < 0)
                return r;

        e.description = strdup(strempty(p));
        if (!e.description)
                return -ENOMEM;

        *ret = TAKE_STRUCT(e);
        return 0;
}

bool proc_keys_entry_is_keyring(const ProcKeysEntry *e, const char *name) {
        const char *p;

        assert(e);
        assert(name);

        if (!streq(e->type, "keyring"))
                return false;

        /* Revoked, dead or invalidated keyrings linger until the key GC runs */
        if (strpbrk(e->flags, "RDi"))
                return false;

        /* Instantiated keyrings carry a ": <n>" or ": empty" suffix, see keyring_describe() in the kernel */
        p = startswith(e->description, name);
        if (!p)
                return false;
        p = startswith(p, ": ");
        if (!p)
                return false;

        return streq(p, "empty") || in_charset(p, DIGITS);
}

int keyring_find_by_name(const char *name, key_serial_t *ret) {
        _cleanup_fclose_ FILE *f = NULL;
        key_serial_t found = 0;
        int r;

        assert(name);
        assert(ret);

        /* The kernel's own keyrings (.dm-verity, .fs-verity, …) are linked into no other keyring and
         * their names are not published, hence /proc/keys is the only way to find them. */

        f = fopen("/proc/keys", "re");
        if (!f)
                return -errno;

        for (;;) {
                _cleanup_(proc_keys_entry_done) ProcKeysEntry e = {};
                _cleanup_free_ char *line = NULL;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = proc_keys_entry_parse(line, &e);
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse /proc/keys line, ignoring: %s", line);
                        continue;
                }

                if (!proc_keys_entry_is_keyring(&e, name))
                        continue;

                if (found > 0)
                        return -ENOTUNIQ;

                found = e.serial;
        }

        if (found <= 0)
                return -ENOENT;

        *ret = found;
        return 0;
}

int keyring_list(key_serial_t keyring, key_serial_t **ret, size_t *ret_n) {
        _cleanup_free_ void *p = NULL;
        size_t n;
        int r;

        assert(ret);
        assert(ret_n);

        /* The payload of a keyring is the array of its direct members' serials */

        r = keyring_read(keyring, &p, &n);
        if (r < 0)
                return r;
        if (n % sizeof(key_serial_t) != 0)
                return -EBADMSG;

        *ret = TAKE_PTR(p);
        *ret_n = n / sizeof(key_serial_t);
        return 0;
}

int keyring_count(key_serial_t keyring, size_t *ret) {
        _cleanup_free_ key_serial_t *l = NULL;
        size_t n;
        int r;

        assert(ret);

        r = keyring_list(keyring, &l, &n);
        if (r < 0)
                return r;

        *ret = n;
        return 0;
}

/* KEYCTL_DESCRIBE needs only View permission, hence this works after the owner dropped SetAttr */
static int keyring_describe_parse(key_serial_t serial, uint32_t *ret_perm, char **ret_description) {
        _cleanup_free_ char *d = NULL, *type = NULL, *uid = NULL, *gid = NULL, *perm = NULL;
        const char *p;
        int r;

        r = keyring_describe(serial, &d);
        if (r < 0)
                return r;

        /* "type;uid;gid;perm;description" */
        p = d;
        r = extract_many_words(&p, ";", EXTRACT_RETAIN_ESCAPE|EXTRACT_DONT_COALESCE_SEPARATORS,
                               &type, &uid, &gid, &perm);
        if (r < 0)
                return r;
        if (r < 4)
                return -EBADMSG;

        if (ret_perm) {
                r = safe_atou32_full(perm, 16, ret_perm);
                if (r < 0)
                        return r;
        }

        if (ret_description) {
                r = strdup_to(ret_description, p);
                if (r < 0)
                        return r;
        }

        return 0;
}

int keyring_perm(key_serial_t serial, uint32_t *ret) {
        assert(ret);

        return keyring_describe_parse(serial, ret, /* ret_description= */ NULL);
}

int keyring_description(key_serial_t serial, char **ret) {
        assert(ret);

        return keyring_describe_parse(serial, /* ret_perm= */ NULL, ret);
}

int keyring_add_asymmetric(key_serial_t keyring, const char *description, const void *der, size_t size, key_serial_t *ret) {
        key_serial_t serial;

        assert(der || size == 0);

        /* With an empty description the kernel derives one from the certificate's subject and key identifier */

        serial = add_key("asymmetric", strempty(description), der, size, keyring);
        if (serial < 0)
                return -errno;

        if (ret)
                *ret = serial;
        return 0;
}

int keyring_restrict(key_serial_t keyring, const char *type, const char *restriction) {

        /* Without a type the kernel installs a restriction that rejects every further link */

        return RET_NERRNO(keyctl(KEYCTL_RESTRICT_KEYRING, keyring, (unsigned long) type, (unsigned long) restriction, 0));
}

int keyring_set_perm(key_serial_t serial, uint32_t perm) {
        return RET_NERRNO(keyctl(KEYCTL_SETPERM, serial, perm, 0, 0));
}
