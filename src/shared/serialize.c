/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "alloc-util.h"
#include "env-util.h"
#include "escape.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "memfd-util.h"
#include "missing_mman.h"
#include "missing_syscall.h"
#include "parse-util.h"
#include "process-util.h"
#include "serialize.h"
#include "strv.h"
#include "tmpfile-util.h"

int serialize_item(FILE *f, const char *key, const char *value) {
        assert(f);
        assert(key);

        if (!value)
                return 0;

        /* Make sure that anything we serialize we can also read back again with read_line() with a maximum line size
         * of LONG_LINE_MAX. This is a safety net only. All code calling us should filter this out earlier anyway. */
        if (strlen(key) + 1 + strlen(value) + 1 > LONG_LINE_MAX)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Attempted to serialize overly long item '%s', refusing.", key);

        fputs(key, f);
        fputc('=', f);
        fputs(value, f);
        fputc('\n', f);

        return 1;
}

int serialize_item_escaped(FILE *f, const char *key, const char *value) {
        _cleanup_free_ char *c = NULL;

        assert(f);
        assert(key);

        if (!value)
                return 0;

        c = cescape(value);
        if (!c)
                return log_oom();

        return serialize_item(f, key, c);
}

int serialize_item_format(FILE *f, const char *key, const char *format, ...) {
        _cleanup_free_ char *allocated = NULL;
        char buf[256]; /* Something resonably short that fits nicely on any stack (i.e. is considerably less
                        * than LONG_LINE_MAX (1MiB!) */
        const char *b;
        va_list ap;
        int k;

        assert(f);
        assert(key);
        assert(format);

        /* First, let's try to format this into a stack buffer */
        va_start(ap, format);
        k = vsnprintf(buf, sizeof(buf), format, ap);
        va_end(ap);

        if (k < 0)
                return log_warning_errno(errno, "Failed to serialize item '%s', ignoring: %m", key);
        if (strlen(key) + 1 + k + 1 > LONG_LINE_MAX) /* See above */
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Attempted to serialize overly long item '%s', refusing.", key);

        if ((size_t) k < sizeof(buf))
                b = buf; /* Yay, it fit! */
        else {
                /* So the string didn't fit in the short buffer above, but was not above our total limit,
                 * hence let's format it via dynamic memory */

                va_start(ap, format);
                k = vasprintf(&allocated, format, ap);
                va_end(ap);

                if (k < 0)
                        return log_warning_errno(errno, "Failed to serialize item '%s', ignoring: %m", key);

                b = allocated;
        }

        fputs(key, f);
        fputc('=', f);
        fputs(b, f);
        fputc('\n', f);

        return 1;
}

int serialize_fd(FILE *f, FDSet *fds, const char *key, int fd) {
        int copy;

        assert(f);
        assert(key);

        if (fd < 0)
                return 0;

        copy = fdset_put_dup(fds, fd);
        if (copy < 0)
                return log_error_errno(copy, "Failed to add file descriptor to serialization set: %m");

        return serialize_item_format(f, key, "%i", copy);
}

int serialize_usec(FILE *f, const char *key, usec_t usec) {
        assert(f);
        assert(key);

        if (usec == USEC_INFINITY)
                return 0;

        return serialize_item_format(f, key, USEC_FMT, usec);
}

int serialize_dual_timestamp(FILE *f, const char *name, const dual_timestamp *t) {
        assert(f);
        assert(name);
        assert(t);

        if (!dual_timestamp_is_set(t))
                return 0;

        return serialize_item_format(f, name, USEC_FMT " " USEC_FMT, t->realtime, t->monotonic);
}

int serialize_strv(FILE *f, const char *key, char **l) {
        int ret = 0, r;

        /* Returns the first error, or positive if anything was serialized, 0 otherwise. */

        STRV_FOREACH(i, l) {
                r = serialize_item_escaped(f, key, *i);
                if ((ret >= 0 && r < 0) ||
                    (ret == 0 && r > 0))
                        ret = r;
        }

        return ret;
}

int serialize_item_hexmem(FILE *f, const char *key, const void *p, size_t l) {
        _cleanup_free_ char *encoded = NULL;
        int r;

        assert(f);
        assert(key);
        assert(p || l == 0);

        if (l == 0)
                return 0;

        encoded = hexmem(p, l);
        if (!encoded)
                return log_oom_debug();

        r = serialize_item(f, key, encoded);
        if (r < 0)
                return r;

        return 1;
}

int serialize_item_base64mem(FILE *f, const char *key, const void *p, size_t l) {
        _cleanup_free_ char *encoded = NULL;
        ssize_t len;
        int r;

        assert(f);
        assert(key);
        assert(p || l == 0);

        if (l == 0)
                return 0;

        len = base64mem(p, l, &encoded);
        if (len <= 0)
                return log_oom_debug();

        r = serialize_item(f, key, encoded);
        if (r < 0)
                return r;

        return 1;
}

int deserialize_read_line(FILE *f, char **ret) {
        _cleanup_free_ char *line = NULL;
        int r;

        assert(f);
        assert(ret);

        r = read_line(f, LONG_LINE_MAX, &line);
        if (r < 0)
                return log_error_errno(r, "Failed to read serialization line: %m");
        if (r == 0) { /* eof */
                *ret = NULL;
                return 0;
        }

        const char *l = strstrip(line);
        if (isempty(l)) { /* End marker */
                *ret = NULL;
                return 0;
        }

        if (free_and_strdup(&line, l) < 0)
                return log_oom();

        *ret = TAKE_PTR(line);
        return 1;
}

int deserialize_strv(char ***l, const char *value) {
        ssize_t unescaped_len;
        char *unescaped;

        assert(l);
        assert(value);

        unescaped_len = cunescape(value, 0, &unescaped);
        if (unescaped_len < 0)
                return unescaped_len;

        return strv_consume(l, unescaped);
}

int deserialize_usec(const char *value, usec_t *ret) {
        int r;

        assert(value);

        r = safe_atou64(value, ret);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse usec value \"%s\": %m", value);

        return 0;
}

int deserialize_dual_timestamp(const char *value, dual_timestamp *t) {
        uint64_t a, b;
        int r, pos;

        assert(value);
        assert(t);

        pos = strspn(value, WHITESPACE);
        if (value[pos] == '-')
                return -EINVAL;
        pos += strspn(value + pos, DIGITS);
        pos += strspn(value + pos, WHITESPACE);
        if (value[pos] == '-')
                return -EINVAL;

        r = sscanf(value, "%" PRIu64 "%" PRIu64 "%n", &a, &b, &pos);
        if (r != 2)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Failed to parse dual timestamp value \"%s\".",
                                       value);

        if (value[pos] != '\0')
                /* trailing garbage */
                return -EINVAL;

        t->realtime = a;
        t->monotonic = b;

        return 0;
}

int deserialize_environment(const char *value, char ***list) {
        _cleanup_free_ char *unescaped = NULL;
        ssize_t l;
        int r;

        assert(value);
        assert(list);

        /* Changes the *environment strv inline. */

        l = cunescape(value, 0, &unescaped);
        if (l < 0)
                return log_error_errno(l, "Failed to unescape: %m");

        r = strv_env_replace_consume(list, TAKE_PTR(unescaped));
        if (r < 0)
                return log_error_errno(r, "Failed to append environment variable: %m");

        return 0;
}

int open_serialization_fd(const char *ident) {
        int fd;

        fd = memfd_create_wrapper(ident, MFD_CLOEXEC | MFD_NOEXEC_SEAL);
        if (fd < 0) {
                const char *path;

                path = getpid_cached() == 1 ? "/run/systemd" : "/tmp";
                fd = open_tmpfile_unlinkable(path, O_RDWR|O_CLOEXEC);
                if (fd < 0)
                        return fd;

                log_debug("Serializing %s to %s.", ident, path);
        } else
                log_debug("Serializing %s to memfd.", ident);

        return fd;
}
