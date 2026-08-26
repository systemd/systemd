/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/magic.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "keyring-util.h"
#include "log.h"
#include "parse-util.h"
#include "stat-util.h"
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
        int c;

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

        free(e->type);
        free(e->description);

        *e = (ProcKeysEntry) {};
}

/* The output struct must be unset, previous contents are not released */
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

        r = extract_many_words(&p, WHITESPACE, 0,
                               &serial, &flags, &usage, &timeout, &perm, &uid, &gid, &e.type);
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

        /* Flags the kernel might add later are ignored, the ones inspected come first */
        if (strlen(flags) < sizeof(e.flags) - 1)
                return -EBADMSG;
        memcpy(e.flags, flags, sizeof(e.flags) - 1);

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

/* KEYCTL_DESCRIBE only needs View permissions. So this helper will keep working even after SetAttr is
 * dropped. */
int keyring_describe_full(
                key_serial_t serial,
                char **ret_type,
                uid_t *ret_uid,
                uint32_t *ret_perm,
                char **ret_description) {

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

        uid_t u;
        r = parse_uid(uid, &u);
        if (r < 0)
                return r;

        uint32_t pm;
        r = safe_atou32_full(perm, 16, &pm);
        if (r < 0)
                return r;

        _cleanup_free_ char *description = NULL;
        if (ret_description) {
                description = strdup(strempty(p));
                if (!description)
                        return -ENOMEM;
        }

        if (ret_uid)
                *ret_uid = u;
        if (ret_perm)
                *ret_perm = pm;
        if (ret_description)
                *ret_description = TAKE_PTR(description);
        if (ret_type)
                *ret_type = TAKE_PTR(type);

        return 0;
}

/* A description may contain newlines and hence forge /proc/keys rows, KEYCTL_DESCRIBE is authoritative */
static int key_matches(key_serial_t serial, const char *name, uid_t owner) {
        _cleanup_free_ char *type = NULL, *description = NULL;
        uid_t uid;
        int r;

        r = keyring_describe_full(serial, &type, &uid, /* ret_perm= */ NULL, &description);
        if (r < 0)
                return r;

        return streq(type, "keyring") && streq(description, name) && (owner == UID_INVALID || uid == owner);
}

/* Various kernel keyring such as .dm-verity, .fs-verity, and the .bpf keyring are not visible to
 * request_key() and KEYCTL_SEARCH. So we can only learn their serial by parsing through /proc/keys.
 *
 * Note that anybody may create a keyring with the same name so only only care about keyrings owned by the
 * specified user. UID_INVALID can be passed to match any. Returns -ENOKEY if there is none, -ENOTUNIQ if
 * there is more than one, -ERFKILL if /proc/keys is masked. */
int keyring_find_by_name(const char *name, uid_t owner, key_serial_t *ret) {
        _cleanup_fclose_ FILE *f = NULL;
        key_serial_t found = 0;
        size_t n_lines = 0, n_parsed = 0;
        int r;

        assert(name);

        f = fopen("/proc/keys", "re");
        if (!f)
                return -errno;

        /* Containers mask it with an empty regular file, which root can still read */
        r = fd_is_fs_type(fileno(f), PROC_SUPER_MAGIC);
        if (r < 0)
                return r;
        if (r == 0)
                return -ERFKILL;

        for (;;) {
                _cleanup_(proc_keys_entry_done) ProcKeysEntry e = {};
                _cleanup_free_ char *line = NULL;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                n_lines++;

                r = proc_keys_entry_parse(line, &e);
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse /proc/keys line, ignoring: %s", line);
                        continue;
                }

                n_parsed++;

                if (!proc_keys_entry_is_keyring(&e, name))
                        continue;
                if (owner != UID_INVALID && e.uid != owner)
                        continue;

                r = key_matches(e.serial, name, owner);
                if (r == -ENOMEM)
                        return r;
                if (r < 0) {
                        log_debug_errno(r, "Failed to describe key %d, ignoring: %m", e.serial);
                        continue;
                }
                if (r == 0) {
                        log_debug("Key %d is not keyring %s, ignoring the /proc/keys row.", e.serial, name);
                        continue;
                }

                /* The same key listed twice can only be a forged row */
                if (found == e.serial)
                        continue;
                if (found > 0)
                        return -ENOTUNIQ;

                found = e.serial;
        }

        if (found <= 0)
                return n_lines > 0 && n_parsed == 0 ? -EBADMSG : -ENOKEY;

        if (ret)
                *ret = found;
        return 0;
}
