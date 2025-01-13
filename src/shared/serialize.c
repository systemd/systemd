/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "alloc-util.h"
#include "env-util.h"
#include "escape.h"
#include "fd-util.h"
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

        c = xescape(value, " ");
        if (!c)
                return log_oom();

        return serialize_item(f, key, c);
}

int serialize_item_format(FILE *f, const char *key, const char *format, ...) {
        _cleanup_free_ char *allocated = NULL;
        char buf[256]; /* Something reasonably short that fits nicely on any stack (i.e. is considerably less
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
        assert(fds);
        assert(key);

        if (fd < 0)
                return 0;

        copy = fdset_put_dup(fds, fd);
        if (copy < 0)
                return log_error_errno(copy, "Failed to add file descriptor to serialization set: %m");

        return serialize_item_format(f, key, "%i", copy);
}

int serialize_fd_many(FILE *f, FDSet *fds, const char *key, const int fd_array[], size_t n_fd_array) {
        _cleanup_free_ char *t = NULL;

        assert(f);

        if (n_fd_array == 0)
                return 0;

        assert(fd_array);

        for (size_t i = 0; i < n_fd_array; i++) {
                int copy;

                if (fd_array[i] < 0)
                        return -EBADF;

                copy = fdset_put_dup(fds, fd_array[i]);
                if (copy < 0)
                        return log_error_errno(copy, "Failed to add file descriptor to serialization set: %m");

                if (strextendf_with_separator(&t, " ", "%i", copy) < 0)
                        return log_oom();
        }

        return serialize_item(f, key, t);
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

int serialize_strv(FILE *f, const char *key, char * const *l) {
        int ret = 0, r;

        /* Returns the first error, or positive if anything was serialized, 0 otherwise. */

        assert(f);
        assert(key);

        STRV_FOREACH(i, l) {
                r = serialize_item_escaped(f, key, *i);
                if ((ret >= 0 && r < 0) ||
                    (ret == 0 && r > 0))
                        ret = r;
        }

        return ret;
}

int serialize_id128(FILE *f, const char *key, sd_id128_t id) {
        assert(f);
        assert(key);

        if (sd_id128_is_null(id))
                return 0;

        return serialize_item_format(f, key, SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(id));
}

int serialize_pidref(FILE *f, FDSet *fds, const char *key, PidRef *pidref) {
        int r;

        assert(f);
        assert(fds);

        if (!pidref_is_set(pidref))
                return 0;

        /* We always serialize the pid separately, to keep downgrades mostly working (older versions will
         * deserialize the pid and silently fail to deserialize the pidfd). If we also have a pidfd, we
         * serialize both the pid and pidfd, so that we can construct the exact same pidref after
         * deserialization (this doesn't work with only the pidfd, as we can't retrieve the original pid
         * from the pidfd anymore if the process is reaped). */

        if (pidref->fd >= 0) {
                int copy = fdset_put_dup(fds, pidref->fd);
                if (copy < 0)
                        return log_error_errno(copy, "Failed to add file descriptor to serialization set: %m");

                r = serialize_item_format(f, key, "@%i:" PID_FMT, copy, pidref->pid);
                if (r < 0)
                        return r;
        }

        return serialize_item_format(f, key, PID_FMT, pidref->pid);
}

int serialize_ratelimit(FILE *f, const char *key, const RateLimit *rl) {
        assert(rl);

        return serialize_item_format(f, key,
                                     USEC_FMT " " USEC_FMT " %u %u",
                                     rl->begin,
                                     rl->interval,
                                     rl->num,
                                     rl->burst);
}

int serialize_item_hexmem(FILE *f, const char *key, const void *p, size_t l) {
        _cleanup_free_ char *encoded = NULL;
        int r;

        assert(f);
        assert(key);

        if (!p && l > 0)
                return -EINVAL;

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

        if (!p && l > 0)
                return -EINVAL;

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

int serialize_string_set(FILE *f, const char *key, const Set *s) {
        int r;

        assert(f);
        assert(key);

        if (set_isempty(s))
                return 0;

        /* Serialize as individual items, as each element might contain separators and escapes */

        const char *e;
        SET_FOREACH(e, s) {
                r = serialize_item(f, key, e);
                if (r < 0)
                        return r;
        }

        return 1;
}

int serialize_image_policy(FILE *f, const char *key, const ImagePolicy *p) {
        _cleanup_free_ char *policy = NULL;
        int r;

        assert(f);
        assert(key);

        if (!p)
                return 0;

        r = image_policy_to_string(p, /* simplify= */ false, &policy);
        if (r < 0)
                return r;

        r = serialize_item(f, key, policy);
        if (r < 0)
                return r;

        return 1;
}

int deserialize_read_line(FILE *f, char **ret) {
        _cleanup_free_ char *line = NULL;
        int r;

        assert(f);
        assert(ret);

        r = read_stripped_line(f, LONG_LINE_MAX, &line);
        if (r < 0)
                return log_error_errno(r, "Failed to read serialization line: %m");
        if (r == 0) { /* eof */
                *ret = NULL;
                return 0;
        }

        if (isempty(line)) { /* End marker */
                *ret = NULL;
                return 0;
        }

        *ret = TAKE_PTR(line);
        return 1;
}

int deserialize_fd(FDSet *fds, const char *value) {
        _cleanup_close_ int our_fd = -EBADF;
        int parsed_fd;

        assert(value);

        parsed_fd = parse_fd(value);
        if (parsed_fd < 0)
                return log_debug_errno(parsed_fd, "Failed to parse file descriptor serialization: %s", value);

        our_fd = fdset_remove(fds, parsed_fd); /* Take possession of the fd */
        if (our_fd < 0)
                return log_debug_errno(our_fd, "Failed to acquire fd from serialization fds: %m");

        return TAKE_FD(our_fd);
}

int deserialize_fd_many(FDSet *fds, const char *value, size_t n, int *ret) {
        int r, *fd_array = NULL;
        size_t m = 0;

        assert(value);

        fd_array = new(int, n);
        if (!fd_array)
                return -ENOMEM;

        CLEANUP_ARRAY(fd_array, m, close_many_and_free);

        for (;;) {
                _cleanup_free_ char *w = NULL;
                int fd;

                r = extract_first_word(&value, &w, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0) {
                        if (m < n) /* Too few */
                                return -EINVAL;

                        break;
                }

                if (m >= n) /* Too many */
                        return -EINVAL;

                fd = deserialize_fd(fds, w);
                if (fd < 0)
                        return fd;

                fd_array[m++] = fd;
        }

        memcpy(ret, fd_array, m * sizeof(int));
        fd_array = mfree(fd_array);

        return 0;
}

int deserialize_strv(const char *value, char ***l) {
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
        assert(ret);

        r = safe_atou64(value, ret);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse usec value \"%s\": %m", value);

        return 0;
}

int deserialize_dual_timestamp(const char *value, dual_timestamp *ret) {
        uint64_t a, b;
        int r, pos;

        assert(value);
        assert(ret);

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

        *ret = (dual_timestamp) {
                .realtime = a,
                .monotonic = b,
        };

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

int deserialize_pidref(FDSet *fds, const char *value, PidRef *ret) {
        const char *e;
        int r;

        assert(value);
        assert(ret);

        e = startswith(value, "@");
        if (e) {
                _cleanup_free_ char *fdstr = NULL, *pidstr = NULL;
                _cleanup_close_ int fd = -EBADF;

                r = extract_many_words(&e, ":", /* flags = */ 0, &fdstr, &pidstr);
                if (r < 0)
                        return log_debug_errno(r, "Failed to deserialize pidref '%s': %m", e);
                if (r == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot deserialize pidref from empty string.");

                assert(r <= 2);

                fd = deserialize_fd(fds, fdstr);
                if (fd < 0)
                        return fd;

                /* The serialization format changed after 255.4. In systemd <= 255.4 only pidfd is
                 * serialized, but that causes problems when reconstructing pidref (see serialize_pidref for
                 * details). After 255.4 the pid is serialized as well even if we have a pidfd, but we still
                 * need to support older format as we might be upgrading from a version that still uses the
                 * old format. */
                if (pidstr) {
                        pid_t pid;

                        r = parse_pid(pidstr, &pid);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to parse PID: %s", pidstr);

                        *ret = (PidRef) {
                                .pid = pid,
                                .fd = TAKE_FD(fd),
                        };
                } else
                        r = pidref_set_pidfd_consume(ret, TAKE_FD(fd));
        } else {
                pid_t pid;

                r = parse_pid(value, &pid);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse PID: %s", value);

                r = pidref_set_pid(ret, pid);
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to initialize pidref: %m");

        return 0;
}

void deserialize_ratelimit(RateLimit *rl, const char *name, const char *value) {
        usec_t begin, interval;
        unsigned num, burst;

        assert(rl);
        assert(name);
        assert(value);

        if (sscanf(value, USEC_FMT " " USEC_FMT " %u %u", &begin, &interval, &num, &burst) != 4)
                return log_notice("Failed to parse %s, ignoring: %s", name, value);

        /* Preserve the counter only if the configuration didn't change. */
        rl->num = (interval == rl->interval && burst == rl->burst) ? num : 0;
        rl->begin = begin;
}

int open_serialization_fd(const char *ident) {
        assert(ident);

        int fd = memfd_new_full(ident, MFD_ALLOW_SEALING);
        if (fd < 0)
                return fd;

        log_debug("Serializing %s to memfd.", ident);
        return fd;
}

int open_serialization_file(const char *ident, FILE **ret) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_close_ int fd;

        assert(ret);

        fd = open_serialization_fd(ident);
        if (fd < 0)
                return fd;

        f = take_fdopen(&fd, "w+");
        if (!f)
                return -errno;

        *ret = TAKE_PTR(f);
        return 0;
}

int finish_serialization_fd(int fd) {
        assert(fd >= 0);

        if (lseek(fd, 0, SEEK_SET) < 0)
                return -errno;

        return memfd_set_sealed(fd);
}

int finish_serialization_file(FILE *f) {
        int r;

        assert(f);

        r = fflush_and_check(f);
        if (r < 0)
                return r;

        if (fseeko(f, 0, SEEK_SET) < 0)
                return -errno;

        int fd = fileno(f);
        if (fd < 0)
                return -EBADF;

        return memfd_set_sealed(fd);
}
